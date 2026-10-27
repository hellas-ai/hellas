//! The offline two-Open handshake, as one artifact that is passed back
//! and forth.
//!
//! # Why a bundle at all
//!
//! Opening a work channel takes four signatures over two transactions,
//! made by two parties who do not share keys and, in this milestone, do
//! not share a network. Generic Open verifies both party authorizations
//! (`crates/kernel/src/tx/mod.rs`), so a provider-only bond signature is
//! not a transaction — somebody has to carry half-signed bytes between
//! the two processes, and "the parties exchange signatures out of band"
//! is not an implementation.
//!
//! [`WorkChannelSetupBundleV2`] is that carrier. It has exactly three
//! revisions, each one strictly extending the last:
//!
//! 1. `BondProposed` — P names the funding it will stake and the tag-4
//!    terms, and signs the bond open.
//! 2. `PaymentProposed` — C countersigns that exact bond, names the
//!    funding it will lock as capacity and the tag-2 terms over that
//!    bond, and signs the payment open.
//! 3. `Complete` — P countersigns that exact payment. Both transactions
//!    are now executable, and only P holds them both.
//!
//! # What it establishes
//!
//! [`WorkChannelSetupBundleV2::check`] verifies every signature the
//! revision carries against the open hash the kernel will compute, by
//! the party the terms name — so an endpoint countersigns a bond only
//! after checking the other side's signature over the same bytes, not
//! after being told it exists.
//!
//! It also establishes the two structural facts a signature cannot: the
//! payment terms embed *this* bond, by both witness and derived edge id,
//! and no coin funds both opens. A duplicated funding id would produce
//! two transactions that cannot both execute, after both parties have
//! signed both.
//!
//! # What it does not establish
//!
//! That the coins exist, are unspent, or are owned by the party
//! offering them. Nothing in a signed body says so, and only a
//! coherent finalized read does — which is the preflight P runs
//! immediately before broadcasting, not a property of these bytes.
//!
//! That any of this survives a crash. A bundle is a value; the journal
//! that fsyncs each revision before its next signature is exported is
//! durable endpoint state, and durable endpoint state is P3's.

use hellas_kernel::{
    EdgeId, Funding, NetworkId, PartyAuth, PayloadHash, SigVerifier, Terms, TermsProfile, Tx,
    WorkPaymentTerms, WorkStakeBondTerms, verify_party,
};
use hellas_xet::XetFileHasher;

use hellas_auth::Digest;

/// Domain of the bundle digest. An endpoint records the revision it
/// exported by this digest, so it must not collide with any other body
/// this crate hashes.
const SETUP_BUNDLE: &[u8] = b"hellas.work.channel-setup-bundle.v2";

/// First byte of every encoded bundle.
const FORMAT_VERSION: u8 = 2;

/// Why a setup bundle is not one this endpoint may act on.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupBundleError {
    /// The envelope's first byte was not the current format version.
    #[error("setup bundle format version {actual} is not {FORMAT_VERSION}")]
    UnknownFormatVersion {
        /// Version byte carried.
        actual: u8,
    },
    /// The revision byte is not one of the three this handshake has.
    #[error("setup bundle revision {actual} is not 1, 2, or 3")]
    UnknownRevision {
        /// Revision byte carried.
        actual: u8,
    },
    /// A nested kernel body did not decode, or bytes were left over.
    #[error("setup bundle is not canonical")]
    Malformed,
    /// A terms slot carried a body of the wrong shape.
    #[error("the {slot} slot does not carry {expected} terms")]
    WrongTermsShape {
        /// Which slot disagreed.
        slot: &'static str,
        /// Shape that slot must carry.
        expected: &'static str,
    },
    /// The payment terms embed a different bond than the one signed.
    #[error("the payment terms embed other bond terms than the bundle's own")]
    BondWitnessMismatch,
    /// The payment terms name a different bond edge than the signed
    /// bond funding and terms produce.
    #[error("the payment terms name bond edge {named:?}, not the derived {derived:?}")]
    BondEdgeMismatch {
        /// Edge id the payment terms name.
        named: EdgeId,
        /// Edge id the bond's own funding and terms derive.
        derived: EdgeId,
    },
    /// One coin id appears more than once across the two openings.
    #[error("coin {coin:?} funds more than one input of this setup")]
    DuplicateFunding {
        /// The repeated coin.
        coin: hellas_kernel::CoinId,
    },
    /// A carried signature is not this party's over these bytes.
    #[error("the {slot} authorization is not {party}'s signature over this open")]
    BadAuthorization {
        /// Which signature failed.
        slot: &'static str,
        /// Party the terms say must have made it.
        party: &'static str,
    },
    /// An imported revision does not extend the one this endpoint
    /// holds.
    #[error("the imported bundle is revision {actual}, not the expected {expected}")]
    NotTheNextRevision {
        /// Revision that must come next.
        expected: u8,
        /// Revision that arrived.
        actual: u8,
    },
    /// An imported revision changed a field an earlier revision fixed.
    #[error("the imported bundle changed bytes an earlier revision fixed")]
    Rewritten,
    /// A step was attempted from the wrong revision.
    #[error("revision {actual} cannot take this step")]
    WrongStage {
        /// Revision the bundle is at.
        actual: u8,
    },
}

/// One revision of the offline two-Open handshake.
///
/// The bond leg is present in every revision, so it is the struct; what
/// changes is how far the handshake has got, and that is the stage. The
/// stage carries the data its revision adds, so a bundle that claims to
/// be countersigned but has no countersignature is not a state this type
/// can be in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkChannelSetupBundleV2 {
    network: NetworkId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    // Store the initial witness on the heap like later-stage witnesses, so
    // retained bundle copies do not inflate composed async poll frames.
    provider_bond_auth: Box<PartyAuth>,
    stage: SetupStage,
}

/// How far the handshake has got, and what that revision added.
///
/// The payment leg is boxed because a `WebAuthn` authorization is
/// kilobytes wide, and an unboxed leg would make every revision-1
/// bundle as large as a revision-3 one.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SetupStage {
    /// Revision 1: the provider has signed the bond.
    BondProposed,
    /// Revision 2: the client has countersigned the bond and signed a
    /// payment open over it.
    PaymentProposed(Box<PaymentLeg>),
    /// Revision 3: the provider has countersigned that payment.
    Complete(Box<PaymentLeg>, Box<PartyAuth>),
}

/// What the client's revision adds.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PaymentLeg {
    client_bond_auth: PartyAuth,
    funding: Funding,
    terms: WorkPaymentTerms,
    client_auth: PartyAuth,
}

impl SetupStage {
    /// Returns the revision number this stage is.
    ///
    /// The one place the three numbers are written. The stage is what
    /// the number means, so a caller that has moved the stage out of a
    /// bundle can still name it.
    const fn revision(&self) -> u8 {
        match self {
            Self::BondProposed => 1,
            Self::PaymentProposed(_) => 2,
            Self::Complete(..) => 3,
        }
    }
}

impl WorkChannelSetupBundleV2 {
    /// Starts the handshake: the provider's staked funding, the bond
    /// terms, and the provider's signature over that open.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::DuplicateFunding`] when one coin appears
    /// twice among the bond's own inputs.
    pub fn propose_bond(
        network: NetworkId,
        bond_funding: Funding,
        bond_terms: WorkStakeBondTerms,
        provider_bond_auth: PartyAuth,
    ) -> Result<Self, SetupBundleError> {
        check_funding_disjoint(&bond_funding, None)?;
        Ok(Self {
            network,
            bond_funding,
            bond_terms,
            provider_bond_auth: Box::new(provider_bond_auth),
            stage: SetupStage::BondProposed,
        })
    }

    /// Countersigns the bond and proposes the payment channel over it.
    ///
    /// The client fixes both of its own choices here — which coins it
    /// locks and what the channel's terms are — in the same revision
    /// that releases its bond signature. It cannot be asked to stake a
    /// countersignature on a bond and only afterwards learn what channel
    /// it will be asked to fund over it.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::WrongStage`] from any revision but the
    /// first, [`SetupBundleError::BondWitnessMismatch`] or
    /// [`SetupBundleError::BondEdgeMismatch`] when the payment terms
    /// are over some other bond, and
    /// [`SetupBundleError::DuplicateFunding`] when a coin funds both.
    pub fn countersign_bond_and_propose_payment(
        mut self,
        client_bond_auth: PartyAuth,
        payment_funding: Funding,
        payment_terms: WorkPaymentTerms,
        client_payment_auth: PartyAuth,
    ) -> Result<Self, SetupBundleError> {
        if !matches!(self.stage, SetupStage::BondProposed) {
            return Err(SetupBundleError::WrongStage {
                actual: self.revision(),
            });
        }
        check_payment_over_bond(&self.bond_funding, &self.bond_terms, &payment_terms)?;
        check_funding_disjoint(&self.bond_funding, Some(&payment_funding))?;
        self.stage = SetupStage::PaymentProposed(Box::new(PaymentLeg {
            client_bond_auth,
            funding: payment_funding,
            terms: payment_terms,
            client_auth: client_payment_auth,
        }));
        Ok(self)
    }

    /// Countersigns the payment. Both opens become executable.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::WrongStage`] from any revision but the
    /// second.
    pub fn countersign_payment(
        mut self,
        provider_payment_auth: PartyAuth,
    ) -> Result<Self, SetupBundleError> {
        self.stage = match self.stage {
            SetupStage::PaymentProposed(payment) => {
                SetupStage::Complete(payment, Box::new(provider_payment_auth))
            }
            stage => {
                return Err(SetupBundleError::WrongStage {
                    actual: stage.revision(),
                });
            }
        };
        Ok(self)
    }

    /// Returns which of the three revisions this is.
    #[must_use]
    pub const fn revision(&self) -> u8 {
        self.stage.revision()
    }

    const fn payment(&self) -> Option<&PaymentLeg> {
        match &self.stage {
            SetupStage::BondProposed => None,
            SetupStage::PaymentProposed(leg) | SetupStage::Complete(leg, _) => Some(leg),
        }
    }

    const fn provider_payment_auth(&self) -> Option<&PartyAuth> {
        match &self.stage {
            SetupStage::Complete(_, auth) => Some(auth),
            _ => None,
        }
    }

    /// Returns the network both opens are bound to.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// Returns the bond edge this setup will create.
    #[must_use]
    pub fn bond_edge(&self) -> EdgeId {
        Tx::edge_id_of(
            &self.bond_funding,
            &Terms::work_stake_bond(self.bond_terms.clone()),
        )
    }

    /// Returns the stake-bond terms fixed by the provider's first revision.
    ///
    /// These terms are present at every revision. In particular, startup can
    /// verify a configured client's settlement key against their taker before
    /// that client has answered the offer and before a payment leg exists.
    #[must_use]
    pub const fn bond_terms(&self) -> &WorkStakeBondTerms {
        &self.bond_terms
    }

    /// Returns the funding the provider stakes, fixed by its first revision.
    ///
    /// Beside [`Self::bond_open`] rather than instead of it, and the two are
    /// reachable at different revisions. The Open is executable only once the
    /// client has countersigned; these coins are encumbered from the moment
    /// the provider signs, because the signature over that exact funding is
    /// already exported. A provider asking which coins its own retained
    /// proposals already promise therefore has to read them here — off the
    /// Open, an offer nobody has answered would look like it staked nothing.
    #[must_use]
    pub const fn bond_funding(&self) -> &Funding {
        &self.bond_funding
    }

    /// Returns the payment edge this setup will create, once the client
    /// has named its terms.
    #[must_use]
    pub fn payment_edge(&self) -> Option<EdgeId> {
        let payment = self.payment()?;
        Some(Tx::edge_id_of(
            &payment.funding,
            &Terms::work_payment(payment.terms.clone()),
        ))
    }

    /// Returns the payment terms the client has proposed, once it has
    /// proposed them.
    ///
    /// Reachable a revision earlier than [`Self::payment_open`], and
    /// that gap is the whole reason it exists: the provider has to
    /// decide whether it will work over these terms *before* it
    /// countersigns them, and the open they belong to is not executable
    /// until it has.
    #[must_use]
    pub fn payment_terms(&self) -> Option<&WorkPaymentTerms> {
        Some(&self.payment()?.terms)
    }

    pub fn payment_funding(&self) -> Option<&Funding> {
        Some(&self.payment()?.funding)
    }

    /// Returns the hash both parties sign to authorize the bond open.
    #[must_use]
    pub fn bond_open_hash(&self) -> PayloadHash {
        Tx::open_hash(
            self.network,
            &self.bond_funding,
            &Terms::work_stake_bond(self.bond_terms.clone()),
        )
    }

    /// Returns the hash both parties sign to authorize the payment
    /// open.
    #[must_use]
    pub fn payment_open_hash(&self) -> Option<PayloadHash> {
        Some(self.leg_open_hash(self.payment()?))
    }

    /// Returns the hash that authorizes `leg`'s payment open.
    ///
    /// Takes the leg rather than reading it back off `self`, so a caller
    /// that already holds one is not handed an `Option` whose `None` its
    /// own binding has already ruled out.
    fn leg_open_hash(&self, leg: &PaymentLeg) -> PayloadHash {
        Tx::open_hash(
            self.network,
            &leg.funding,
            &Terms::work_payment(leg.terms.clone()),
        )
    }

    /// Returns the executable bond open, once both parties have signed
    /// it.
    ///
    /// Maker is the provider: tag-4 terms name the stake funder first,
    /// and the transaction's two authorizations are in that order.
    #[must_use]
    pub fn bond_open(&self) -> Option<Tx> {
        let payment = self.payment()?;
        Some(Tx::open(
            self.bond_funding.clone(),
            Terms::work_stake_bond(self.bond_terms.clone()),
            self.provider_bond_auth.as_ref().clone(),
            payment.client_bond_auth.clone(),
        ))
    }

    /// Returns the executable payment open, once both parties have
    /// signed it.
    ///
    /// Maker is the client: the payment parties are the bond's
    /// mirrored, so the client funds and signs first.
    #[must_use]
    pub fn payment_open(&self) -> Option<Tx> {
        let SetupStage::Complete(payment, provider_auth) = &self.stage else {
            return None;
        };
        Some(Tx::open(
            payment.funding.clone(),
            Terms::work_payment(payment.terms.clone()),
            payment.client_auth.clone(),
            (**provider_auth).clone(),
        ))
    }

    /// Checks every signature and structural rule this revision
    /// carries.
    ///
    /// Run on import, before the receiving endpoint releases its own
    /// next signature. What it establishes is that the bytes in hand are
    /// a coherent proposal already signed by the other party — not that
    /// the coins behind it are live, which no signature can say.
    ///
    /// The party each signature is checked against comes from the
    /// terms, never from the bundle's shape: the bond's maker is the
    /// provider and the payment's maker is the client, and both are read
    /// out of the same `bond_terms.parties`.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::BadAuthorization`] for a signature that is
    /// not this party's over these bytes, plus the structural errors
    /// [`Self::countersign_bond_and_propose_payment`] raises — checked
    /// again here because an imported bundle was built somewhere else.
    pub fn check<V: SigVerifier>(&self, verifier: &V) -> Result<(), SetupBundleError> {
        // Every witness carries its authority; the kernel selects its committed key.
        let provider = self.bond_terms.parties.maker();
        let client = self.bond_terms.parties.taker();

        check_funding_disjoint(&self.bond_funding, self.payment().map(|leg| &leg.funding))?;

        let bond_hash = self.bond_open_hash();
        if !verify_party(verifier, &self.provider_bond_auth, provider, bond_hash) {
            return Err(SetupBundleError::BadAuthorization {
                slot: "bond open",
                party: "the provider",
            });
        }

        let Some(payment) = self.payment() else {
            return Ok(());
        };
        check_payment_over_bond(&self.bond_funding, &self.bond_terms, &payment.terms)?;
        if !verify_party(verifier, &payment.client_bond_auth, client, bond_hash) {
            return Err(SetupBundleError::BadAuthorization {
                slot: "bond open",
                party: "the client",
            });
        }

        let payment_hash = self.leg_open_hash(payment);
        if !verify_party(verifier, &payment.client_auth, client, payment_hash) {
            return Err(SetupBundleError::BadAuthorization {
                slot: "payment open",
                party: "the client",
            });
        }
        if let Some(provider_auth) = self.provider_payment_auth()
            && !verify_party(verifier, provider_auth, provider, payment_hash)
        {
            return Err(SetupBundleError::BadAuthorization {
                slot: "payment open",
                party: "the provider",
            });
        }
        Ok(())
    }

    /// Checks that `self` is the next revision of `previous`, changing
    /// nothing `previous` fixed.
    ///
    /// This is what makes a bundle a conversation rather than a
    /// suggestion. The comparison is over the encoding of the shared
    /// prefix, so a field silently retyped or reordered is a
    /// disagreement and not a coincidence.
    ///
    /// A replayed stale revision fails on the revision number; an
    /// altered body fails on the prefix; and a bundle that skips a
    /// revision fails on the number too, so no endpoint can be handed a
    /// complete setup it never took part in.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::NotTheNextRevision`] and
    /// [`SetupBundleError::Rewritten`].
    pub fn check_extends(&self, previous: &Self) -> Result<(), SetupBundleError> {
        let expected = previous.revision().saturating_add(1);
        if self.revision() != expected {
            return Err(SetupBundleError::NotTheNextRevision {
                expected,
                actual: self.revision(),
            });
        }
        // Both encodings are `version || revision || body`. The version
        // byte is written by `encode` and is the same constant on both
        // sides, and the revision byte is the one that legally differs
        // and has just been checked — so the body is what is left to
        // compare.
        const HEAD: usize = 2;
        let held = previous.encode();
        let arrived = self.encode();
        if !arrived[HEAD..].starts_with(&held[HEAD..]) {
            return Err(SetupBundleError::Rewritten);
        }
        Ok(())
    }

    /// Returns the canonical bytes of this revision.
    ///
    /// The nested bodies are the kernel's own encodings, so the bytes a
    /// party hashes here contain the bytes it will sign and submit.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION, self.revision()];
        push(&mut out, &self.network);
        push(&mut out, &self.bond_funding);
        push(&mut out, &Terms::work_stake_bond(self.bond_terms.clone()));
        push(&mut out, self.provider_bond_auth.as_ref());
        if let Some(payment) = self.payment() {
            push(&mut out, &payment.client_bond_auth);
            push(&mut out, &payment.funding);
            push(&mut out, &Terms::work_payment(payment.terms.clone()));
            push(&mut out, &payment.client_auth);
        }
        if let Some(provider_auth) = self.provider_payment_auth() {
            push(&mut out, provider_auth);
        }
        out
    }

    /// Reads one revision from its canonical bytes.
    ///
    /// Exact: trailing bytes are refused rather than ignored, because
    /// the digest an endpoint records covers every byte it was handed.
    ///
    /// # Errors
    ///
    /// [`SetupBundleError::UnknownFormatVersion`],
    /// [`SetupBundleError::UnknownRevision`],
    /// [`SetupBundleError::Malformed`],
    /// [`SetupBundleError::WrongTermsShape`], and the structural errors
    /// the revision's own constructor raises.
    pub fn decode(bytes: &[u8]) -> Result<Self, SetupBundleError> {
        let mut cursor = hellas_kernel::Cursor::new(bytes);
        match cursor.byte().ok_or(SetupBundleError::Malformed)? {
            FORMAT_VERSION => {}
            actual => return Err(SetupBundleError::UnknownFormatVersion { actual }),
        }
        let revision = cursor.byte().ok_or(SetupBundleError::Malformed)?;
        if !matches!(revision, 1..=3) {
            return Err(SetupBundleError::UnknownRevision { actual: revision });
        }

        let network = cursor.network().ok_or(SetupBundleError::Malformed)?;
        let bond_funding: Funding = cursor.field().ok_or(SetupBundleError::Malformed)?;
        let bond_terms = match cursor
            .field::<Terms>()
            .ok_or(SetupBundleError::Malformed)?
            .profile()
        {
            TermsProfile::WorkStakeBond(terms) => terms.clone(),
            _ => {
                return Err(SetupBundleError::WrongTermsShape {
                    slot: "bond",
                    expected: "work-stake bond",
                });
            }
        };
        let provider_bond_auth: PartyAuth = cursor.field().ok_or(SetupBundleError::Malformed)?;

        let bundle = if revision == 1 {
            Self::propose_bond(network, bond_funding, bond_terms, provider_bond_auth)?
        } else {
            let client_bond_auth: PartyAuth = cursor.field().ok_or(SetupBundleError::Malformed)?;
            let payment_funding: Funding = cursor.field().ok_or(SetupBundleError::Malformed)?;
            let payment_terms = match cursor
                .field::<Terms>()
                .ok_or(SetupBundleError::Malformed)?
                .profile()
            {
                TermsProfile::WorkPayment(terms) => terms.clone(),
                _ => {
                    return Err(SetupBundleError::WrongTermsShape {
                        slot: "payment",
                        expected: "work-payment",
                    });
                }
            };
            let client_payment_auth: PartyAuth =
                cursor.field().ok_or(SetupBundleError::Malformed)?;
            let proposed =
                Self::propose_bond(network, bond_funding, bond_terms, provider_bond_auth)?
                    .countersign_bond_and_propose_payment(
                        client_bond_auth,
                        payment_funding,
                        payment_terms,
                        client_payment_auth,
                    )?;
            if revision == 2 {
                proposed
            } else {
                proposed.countersign_payment(cursor.field().ok_or(SetupBundleError::Malformed)?)?
            }
        };

        if cursor.is_empty() {
            Ok(bundle)
        } else {
            Err(SetupBundleError::Malformed)
        }
    }

    /// Returns the digest of this exact revision.
    ///
    /// Streamed, because a bundle carries two fundings, two terms
    /// bodies, and up to four authorizations — a `WebAuthn` assertion
    /// alone can be kilobytes — and the single-chunk hasher panics
    /// rather than errors past its limit.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut hasher = XetFileHasher::new();
        hasher.update(SETUP_BUNDLE);
        hasher.update(&self.encode());
        hasher.finalize()
    }
}

/// Checks that the payment terms are over exactly this bundle's bond.
///
/// Two checks, not one. The embedded witness is what the payment's own
/// terms hash covers; the derived edge id is what the kernel will look
/// the bond up by, and it is a function of the *funding* as well as the
/// terms. Equal witnesses with different funding are two different
/// bonds, and only the second check sees that.
fn check_payment_over_bond(
    bond_funding: &Funding,
    bond_terms: &WorkStakeBondTerms,
    payment_terms: &WorkPaymentTerms,
) -> Result<(), SetupBundleError> {
    if &payment_terms.bond_terms != bond_terms {
        return Err(SetupBundleError::BondWitnessMismatch);
    }
    let derived = Tx::edge_id_of(bond_funding, &Terms::work_stake_bond(bond_terms.clone()));
    if payment_terms.bond_edge != derived {
        return Err(SetupBundleError::BondEdgeMismatch {
            named: payment_terms.bond_edge,
            derived,
        });
    }
    Ok(())
}

/// Checks that no coin funds two inputs of this setup.
///
/// Across both openings and both sides of each: a coin spent by the bond
/// cannot also fund the payment, and the kernel would refuse the second
/// transaction after all four signatures had been exchanged.
fn check_funding_disjoint(
    bond: &Funding,
    payment: Option<&Funding>,
) -> Result<(), SetupBundleError> {
    let mut seen = std::collections::BTreeSet::new();
    for funding in core::iter::once(bond).chain(payment) {
        for coin in funding.maker().iter().chain(funding.taker().iter()) {
            if !seen.insert(*coin) {
                return Err(SetupBundleError::DuplicateFunding { coin: *coin });
            }
        }
    }
    Ok(())
}

fn push<E: hellas_kernel::Encode>(out: &mut Vec<u8>, value: &E) {
    out.extend_from_slice(&crate::model::work::encode_kernel(value));
}
