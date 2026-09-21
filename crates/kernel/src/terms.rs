//! Concrete edge terms and their deterministic commitment.
//!
//! No direct abstract counterpart — the L1 model treats terms as opaque
//! constants (`TimeoutHeight`, `MakerPayout`, `TakerPayout` in
//! `models/types.qnt`). The Rust kernel commits to a structured [`Terms`]
//! body and binds it via [`TermsHash`] so closes can carry only the
//! commitment, not the full payload.
//!
//! [`Terms`] computes its [`TermsHash`] at construction and stores it
//! alongside the body. Callers that need the hash get a field load; no
//! type that contains a `Terms` ever needs to cache `terms_hash`
//! separately.
//!
//! # Shapes
//!
//! Three shapes: `Basic` (tag 0), [`WorkPaymentTerms`] (tag 2), and
//! [`WorkStakeBondTerms`] (tag 4). Tags 1 and 3 decode to a rejection
//! and carry no promise. [`Terms::profile`] is the one classification,
//! and it is exhaustive, so a shape added later is a compile error at
//! every site that decides policy from the shape.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::{HASH_LENGTH, MAX_EDGE_OUTPUTS},
    context::BlockHeight,
    list::List,
    object::Parties,
    primitive::{EdgeId, ProtocolCode, TermsHash},
    tx::{CloseKindSet, Payout},
};

/// Concrete open terms committed by an edge.
///
/// `Terms` is the *body* + a precomputed [`TermsHash`] that binds it.
/// The two cannot drift because the only constructor computes the hash
/// once and stores it, and the body is immutable thereafter.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Terms {
    body: TermsBody,
    hash: TermsHash,
}

/// Body of a [`Terms`] commitment. Variants enumerate the supported
/// protocol-mode shapes; the wrapping [`Terms`] adds the canonical
/// commitment over the body.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
enum TermsBody {
    /// Degenerate bilateral terms used until protocol-specific terms land.
    Basic {
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    },

    /// Work-payment channel: the client (maker) funds capacity the
    /// provider (taker) earns against off-chain.
    WorkPayment(WorkPaymentTerms),

    /// Work-stake bond: the provider-funded stake a work channel leases.
    WorkStakeBond(WorkStakeBondTerms),
}

// Variant numbers are consensus assignments, not positions in this
// enum. 1 was the deleted legacy stake bond and 3 was never assigned;
// both decode to a rejection, and neither is reserved for anything.
const BASIC_TAG: u8 = 0;
const WORK_PAYMENT_TAG: u8 = 2;
const WORK_STAKE_BOND_TAG: u8 = 4;

/// Stake a work channel leases.
///
/// The maker is the provider funding the stake; the taker is the client
/// the channel serves. The bond admits only `Timeout`: unleased it
/// returns the stake immediately and permissionlessly to the provider,
/// leased it returns at `timeout`, which is also the channel's
/// admission horizon.
///
/// The stake is the edge's own locked value. There is deliberately no
/// second `stake` scalar to disagree with it.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WorkStakeBondTerms {
    /// Maker = provider (stake funder), taker = client.
    pub parties: Parties,
    /// Bond expiry, and the admission horizon of the channel it
    /// insures.
    pub timeout: BlockHeight,
    /// Committed timeout payout shape. Checked at open to pay the
    /// provider and nobody else.
    pub timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    /// Largest job price this bond may cover. At least 1 — a bond that
    /// can cover no job is not a bond.
    pub max_job_price: u64,
}

/// Terms of the payment edge of a work channel.
///
/// The client is the maker and funds the capacity; the provider is the
/// taker and earns against it off-chain. The body embeds the complete
/// canonical bytes of the bond it names, so the kernel can bind a
/// payment to one exact bond policy without a second state read at
/// signing time.
///
/// The parties and the admission horizon are *derived* from that
/// embedded bond, not spelled out beside it. A second spelling could
/// only ever disagree with the first, and the rule that rejected the
/// disagreement was carrying both spellings to justify itself.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct WorkPaymentTerms {
    /// Edge holding the bond that insures this channel's work.
    ///
    /// Naming an edge id from inside terms looks circular, because an
    /// edge id is `H(funding, terms_hash)` of the edge it names. It is
    /// not: this is a *different* edge. The bond is opened first, by the
    /// provider, from its own funding under its own
    /// [`WorkStakeBondTerms`]; only then can a payment name it. The
    /// reference points backwards in time, so the two ids form a chain,
    /// never a cycle.
    ///
    /// What the field adds over [`Self::bond_terms`] is narrower than it
    /// looks, and worth stating so nobody deletes it as redundant. The
    /// embedded body already yields the bond's terms hash, so of the two
    /// inputs to the bond's id — its funding and its terms hash — only
    /// the funding is new information here. This field is therefore not
    /// "which policy", which the body already fixes; it is "which
    /// *instantiation* of that policy", i.e. the exact coins the
    /// provider staked. Carrying the funding instead would be larger and
    /// would still need the id derived at every lookup, and the id is
    /// what the store is keyed by.
    ///
    /// The useful consequence: this payment's own id commits to
    /// `bond_edge`, which commits to the bond's funding and terms, so a
    /// payment edge transitively commits to the whole bond. It cannot be
    /// re-pointed at a different bond without becoming a different edge.
    /// That is why leasing the bond at open (see
    /// `tx::work::open_bond_lease`) is enough on its own, with no
    /// separate proof binding the two objects together.
    pub bond_edge: EdgeId,
    /// Complete bond terms the payment commits to. Their commitment is
    /// derived, not carried twice: see [`Self::bond_terms_hash`].
    pub bond_terms: WorkStakeBondTerms,
    /// Salted commitment to the bilateral risk and credit policy. The
    /// body stays private until a game reveals it.
    pub private_policy_commitment: [u8; HASH_LENGTH],
    /// Blocks the client has to answer a provider's close start before
    /// the provider's stated amount is taken as uncontested.
    pub omit_response_blocks: u64,
    /// Blocks a signed close start stays valid for inclusion.
    pub start_validity_blocks: u64,
    /// Amount the client forfeits to the provider when a close reveals
    /// the client understated the earned scalar.
    pub omission_bond: u64,
}

impl WorkPaymentTerms {
    /// Returns the commitment to the embedded bond terms.
    ///
    /// Derived, not stored: the body already carries the bond's
    /// complete canonical bytes.
    #[must_use]
    pub fn bond_terms_hash(&self) -> TermsHash {
        work_stake_bond_terms_hash(&self.bond_terms)
    }

    /// Returns the payment edge's parties: the bond's, mirrored.
    ///
    /// The client funds this edge and is the bond's taker; the provider
    /// stakes the bond and earns here. One source, so the two edges
    /// cannot describe different pairings.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        let bond = self.bond_terms.parties;
        Parties::new(bond.taker(), bond.maker())
    }

    /// Returns the last height at which a job may be admitted, and the
    /// rent horizon the edge pays for.
    ///
    /// It is the bond's timeout, because a job admitted with no live
    /// bond left to insure it is exactly what one horizon prevents. It
    /// is not a refund deadline: this shape has no timeout close.
    /// Passing this height retires the channel's capacity to admit work
    /// and nothing else — it does not release the edge, does not pay
    /// anyone, and does not start a clock that will. An abandoned
    /// payment edge is settled by a co-signed `Freeze` or by the
    /// unilateral `Adjudicated` route, and by nothing else, however long
    /// it is left.
    #[must_use]
    pub const fn admission_horizon(&self) -> BlockHeight {
        self.bond_terms.timeout
    }
}

/// Borrowed profile-specific body of a [`Terms`] value.
///
/// This is the only classification of a terms shape the kernel has.
/// Guards match on it exhaustively, so adding a shape is a compile
/// error at every site that decides policy from the shape, instead of a
/// silently skipped check.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum TermsProfile<'a> {
    /// Basic bilateral terms. Every field is reachable through the
    /// shape-independent accessors, so this arm carries no body.
    Basic,
    /// Work-channel payment edge.
    WorkPayment(&'a WorkPaymentTerms),
    /// Work-channel stake bond.
    WorkStakeBond(&'a WorkStakeBondTerms),
}

impl Terms {
    /// Creates basic terms.
    #[must_use]
    pub fn basic(
        protocol: ProtocolCode,
        parties: Parties,
        timeout: BlockHeight,
        timeout_outputs: List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> Self {
        Self::commit(TermsBody::Basic {
            protocol,
            parties,
            timeout,
            timeout_outputs,
        })
    }

    /// Creates work-payment terms.
    #[must_use]
    pub fn work_payment(payment: WorkPaymentTerms) -> Self {
        Self::commit(TermsBody::WorkPayment(payment))
    }

    /// Creates work-stake-bond terms.
    #[must_use]
    pub fn work_stake_bond(bond: WorkStakeBondTerms) -> Self {
        Self::commit(TermsBody::WorkStakeBond(bond))
    }

    fn commit(body: TermsBody) -> Self {
        let hash = body.compute_hash();
        Self { body, hash }
    }

    /// Returns the canonical Xet commitment for these terms.
    ///
    /// Computed once at construction; this is a field load.
    #[must_use]
    pub const fn hash(&self) -> TermsHash {
        self.hash
    }

    /// Returns the borrowed profile-specific body.
    #[must_use]
    pub const fn profile(&self) -> TermsProfile<'_> {
        match &self.body {
            TermsBody::Basic { .. } => TermsProfile::Basic,
            TermsBody::WorkPayment(payment) => TermsProfile::WorkPayment(payment),
            TermsBody::WorkStakeBond(bond) => TermsProfile::WorkStakeBond(bond),
        }
    }

    /// Returns the protocol code committed by basic bilateral terms.
    #[must_use]
    pub const fn basic_protocol(&self) -> Option<ProtocolCode> {
        match &self.body {
            TermsBody::Basic { protocol, .. } => Some(*protocol),
            TermsBody::WorkPayment(_) | TermsBody::WorkStakeBond(_) => None,
        }
    }

    /// Returns the committed parties.
    #[must_use]
    pub const fn parties(&self) -> Parties {
        match &self.body {
            TermsBody::Basic { parties, .. } => *parties,
            TermsBody::WorkPayment(payment) => payment.parties(),
            TermsBody::WorkStakeBond(bond) => bond.parties,
        }
    }

    /// Returns the committed lifetime horizon.
    ///
    /// For every shape but work payment this is the height a `Timeout`
    /// close becomes available. Work payment commits the same field as
    /// an admission and rent horizon with no refund attached.
    #[must_use]
    pub const fn timeout(&self) -> BlockHeight {
        match &self.body {
            TermsBody::Basic { timeout, .. } => *timeout,
            TermsBody::WorkPayment(payment) => payment.admission_horizon(),
            TermsBody::WorkStakeBond(bond) => bond.timeout,
        }
    }

    /// Returns the deterministic timeout payout shape, including any reserve
    /// surplus left after the open-time committed timeout close fee.
    ///
    /// `None` for work payment, the one shape with no timeout close: a
    /// fixed refund payable after the provider has earned against the
    /// channel would pay the wrong party. Callers that need a payout
    /// must handle the absence; none may substitute an empty list,
    /// which is a different commitment (pay nobody everything).
    #[must_use]
    pub const fn timeout_outputs(&self) -> Option<&List<Payout, MAX_EDGE_OUTPUTS>> {
        match &self.body {
            TermsBody::Basic {
                timeout_outputs, ..
            } => Some(timeout_outputs),
            TermsBody::WorkPayment(_) => None,
            TermsBody::WorkStakeBond(bond) => Some(&bond.timeout_outputs),
        }
    }

    /// Returns the close kinds this terms shape admits.
    ///
    /// Fixed structurally per shape — no field to misconfigure. Each
    /// shape names its set explicitly, so a newly assigned close kind
    /// joins a shape only when someone decides it should.
    #[must_use]
    pub const fn allowed_closes(&self) -> CloseKindSet {
        match &self.body {
            TermsBody::Basic { .. } => CloseKindSet::BASIC,
            TermsBody::WorkPayment(_) => CloseKindSet::WORK_PAYMENT,
            TermsBody::WorkStakeBond(_) => CloseKindSet::WORK_STAKE_BOND,
        }
    }
}

/// Returns the commitment a tag-4 bond body carries.
///
/// The preimage is the bond's standalone `Terms` encoding, which is
/// exactly the witness a work-payment body embeds; a payment can
/// therefore name its bond by the same hash the bond edge stores.
fn work_stake_bond_terms_hash(bond: &WorkStakeBondTerms) -> TermsHash {
    let mut hasher = hellas_xet::SingleChunkHasher::new();
    hasher.update(crate::consts::TERMS_WORK_STAKE_BOND);
    encode_work_stake_bond_witness(&mut hasher, bond);
    TermsHash::from_bytes(hasher.finalize().into_bytes())
}

/// Writes the complete tag-4 `Terms` bytes for `bond`.
///
/// Deliberately not a nested owned `Terms`: the payment body carries a
/// bond's canonical bytes, and nothing in the decoder recurses into a
/// second terms object.
fn encode_work_stake_bond_witness<W: Writer + ?Sized>(writer: &mut W, bond: &WorkStakeBondTerms) {
    encode_envelope(writer, tag::TERMS);
    WORK_STAKE_BOND_TAG.encode_to(writer);
    bond.encode_to(writer);
}

fn decode_work_stake_bond_witness(buf: &[u8]) -> Result<(WorkStakeBondTerms, usize), DecodeError> {
    let mut consumed = decode_envelope(buf, tag::TERMS)?;
    let variant = decode_field::<u8>(buf, &mut consumed)?;
    if variant != WORK_STAKE_BOND_TAG {
        return Err(DecodeError::InvalidTag { tag: variant });
    }
    let bond = decode_field(buf, &mut consumed)?;
    Ok((bond, consumed))
}

const WORK_STAKE_BOND_WITNESS_MAX_SIZE: usize =
    ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + WorkStakeBondTerms::MAX_ENCODED_SIZE;

fn work_stake_bond_witness_size(bond: &WorkStakeBondTerms) -> usize {
    ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + bond.encoded_size()
}

impl TermsBody {
    fn compute_hash(&self) -> TermsHash {
        // The hash domain is the structural tag for this body shape:
        // different semantics can never share the same canonical bytes.
        let domain = match self {
            Self::Basic { .. } => crate::consts::TERMS_BASIC,
            Self::WorkPayment(_) => crate::consts::TERMS_WORK_PAYMENT,
            Self::WorkStakeBond(_) => crate::consts::TERMS_WORK_STAKE_BOND,
        };
        TermsHash::from_bytes(crate::canonical::hash(domain, self).into_bytes())
    }
}

impl Encode for Terms {
    const MAX_ENCODED_SIZE: usize = TermsBody::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        self.body.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.body.encode_to(writer);
    }
}

impl Decode for Terms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let (body, consumed) = TermsBody::decode(buf)?;
        let hash = body.compute_hash();
        Ok((Self { body, hash }, consumed))
    }
}

const BASIC_BODY_SIZE: usize = ProtocolCode::MAX_ENCODED_SIZE
    + Parties::MAX_ENCODED_SIZE
    + BlockHeight::MAX_ENCODED_SIZE
    + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE;

impl Encode for WorkStakeBondTerms {
    const MAX_ENCODED_SIZE: usize = Parties::MAX_ENCODED_SIZE
        + BlockHeight::MAX_ENCODED_SIZE
        + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE
        + u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Parties::MAX_ENCODED_SIZE
            + BlockHeight::MAX_ENCODED_SIZE
            + self.timeout_outputs.encoded_size()
            + u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.parties.encode_to(writer);
        self.timeout.encode_to(writer);
        self.timeout_outputs.encode_to(writer);
        self.max_job_price.encode_to(writer);
    }
}

impl Decode for WorkStakeBondTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let parties = decode_field(buf, &mut consumed)?;
        let timeout = decode_field(buf, &mut consumed)?;
        let timeout_outputs = decode_field(buf, &mut consumed)?;
        let max_job_price = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                parties,
                timeout,
                timeout_outputs,
                max_job_price,
            },
            consumed,
        ))
    }
}

impl Encode for WorkPaymentTerms {
    const MAX_ENCODED_SIZE: usize = EdgeId::MAX_ENCODED_SIZE
        + WORK_STAKE_BOND_WITNESS_MAX_SIZE
        + HASH_LENGTH
        + 3 * u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        EdgeId::MAX_ENCODED_SIZE
            + work_stake_bond_witness_size(&self.bond_terms)
            + HASH_LENGTH
            + 3 * u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.bond_edge.encode_to(writer);
        encode_work_stake_bond_witness(writer, &self.bond_terms);
        self.private_policy_commitment.encode_to(writer);
        self.omit_response_blocks.encode_to(writer);
        self.start_validity_blocks.encode_to(writer);
        self.omission_bond.encode_to(writer);
    }
}

impl Decode for WorkPaymentTerms {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let bond_edge = decode_field(buf, &mut consumed)?;
        let rest = buf.get(consumed..).ok_or(DecodeError::InvalidConsumption {
            consumed,
            available: buf.len(),
        })?;
        let (bond_terms, witness_size) = decode_work_stake_bond_witness(rest)?;
        consumed += witness_size;
        let private_policy_commitment = decode_field(buf, &mut consumed)?;
        let omit_response_blocks = decode_field(buf, &mut consumed)?;
        let start_validity_blocks = decode_field(buf, &mut consumed)?;
        let omission_bond = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                bond_edge,
                bond_terms,
                private_policy_commitment,
                omit_response_blocks,
                start_validity_blocks,
                omission_bond,
            },
            consumed,
        ))
    }
}

impl Encode for TermsBody {
    const MAX_ENCODED_SIZE: usize = {
        // The widest body decides every buffer that holds a `Terms`,
        // and through `Tx` every chain transaction buffer.
        let mut max_body = BASIC_BODY_SIZE;
        if WorkStakeBondTerms::MAX_ENCODED_SIZE > max_body {
            max_body = WorkStakeBondTerms::MAX_ENCODED_SIZE;
        }
        if WorkPaymentTerms::MAX_ENCODED_SIZE > max_body {
            max_body = WorkPaymentTerms::MAX_ENCODED_SIZE;
        }
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Basic {
                    protocol,
                    parties,
                    timeout,
                    timeout_outputs,
                } => {
                    protocol.encoded_size()
                        + parties.encoded_size()
                        + timeout.encoded_size()
                        + timeout_outputs.encoded_size()
                }
                Self::WorkPayment(payment) => payment.encoded_size(),
                Self::WorkStakeBond(bond) => bond.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::TERMS);
        match self {
            Self::Basic {
                protocol,
                parties,
                timeout,
                timeout_outputs,
            } => {
                BASIC_TAG.encode_to(writer);
                protocol.encode_to(writer);
                parties.encode_to(writer);
                timeout.encode_to(writer);
                timeout_outputs.encode_to(writer);
            }
            Self::WorkPayment(payment) => {
                WORK_PAYMENT_TAG.encode_to(writer);
                payment.encode_to(writer);
            }
            Self::WorkStakeBond(bond) => {
                WORK_STAKE_BOND_TAG.encode_to(writer);
                bond.encode_to(writer);
            }
        }
    }
}

impl Decode for TermsBody {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::TERMS)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            BASIC_TAG => {
                let protocol = decode_field(buf, &mut consumed)?;
                let parties = decode_field(buf, &mut consumed)?;
                let timeout = decode_field(buf, &mut consumed)?;
                let timeout_outputs = decode_field(buf, &mut consumed)?;
                Ok((
                    Self::Basic {
                        protocol,
                        parties,
                        timeout,
                        timeout_outputs,
                    },
                    consumed,
                ))
            }
            WORK_PAYMENT_TAG => {
                let payment = decode_field(buf, &mut consumed)?;
                Ok((Self::WorkPayment(payment), consumed))
            }
            WORK_STAKE_BOND_TAG => {
                let bond = decode_field(buf, &mut consumed)?;
                Ok((Self::WorkStakeBond(bond), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;
    use crate::{
        canonical::{BufferWriter, hash},
        consts::{TERMS_BASIC, TERMS_WORK_PAYMENT, TERMS_WORK_STAKE_BOND},
        primitive::Key,
        tx::CloseKind,
    };

    fn sample_work_bond() -> WorkStakeBondTerms {
        let provider = Key::from_bytes([1; Key::LENGTH]);
        let client = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(provider, 12);
        WorkStakeBondTerms {
            parties: Parties::new(provider, client),
            timeout: BlockHeight::new(77),
            timeout_outputs: List::take(outputs, 1),
            max_job_price: 4,
        }
    }

    fn sample_payment() -> WorkPaymentTerms {
        WorkPaymentTerms {
            bond_edge: EdgeId::from_bytes([5; EdgeId::LENGTH]),
            bond_terms: sample_work_bond(),
            private_policy_commitment: [6; HASH_LENGTH],
            omit_response_blocks: 64,
            start_validity_blocks: 8,
            omission_bond: 3,
        }
    }

    fn round_trip(terms: &Terms) {
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let written = terms.write_to(&mut buf);
        assert_eq!(written, terms.encoded_size());
        let Ok((decoded, consumed)) = Terms::decode(&buf[..written]) else {
            panic!("terms decode");
        };
        assert_eq!(consumed, written);
        assert_eq!(&decoded, terms);
    }

    #[test]
    fn work_stake_bond_terms_round_trip_under_their_own_domain() {
        let bond = sample_work_bond();
        let terms = Terms::work_stake_bond(bond.clone());

        let expected = TermsHash::from_bytes(hash(TERMS_WORK_STAKE_BOND, &terms.body).into_bytes());
        assert_eq!(terms.hash(), expected);
        assert_eq!(terms.parties(), bond.parties);
        assert_eq!(terms.timeout(), bond.timeout);
        assert_eq!(terms.timeout_outputs(), Some(&bond.timeout_outputs));
        round_trip(&terms);
    }

    #[test]
    fn work_payment_terms_round_trip_under_their_own_domain() {
        let payment = sample_payment();
        let terms = Terms::work_payment(payment.clone());

        let expected = TermsHash::from_bytes(hash(TERMS_WORK_PAYMENT, &terms.body).into_bytes());
        assert_eq!(terms.hash(), expected);
        // Every one of these is derived from the embedded bond: there
        // is no second spelling to disagree with.
        let bond = &payment.bond_terms;
        assert_eq!(
            terms.parties(),
            Parties::new(bond.parties.taker(), bond.parties.maker()),
        );
        assert_eq!(terms.timeout(), bond.timeout);
        assert_eq!(payment.admission_horizon(), bond.timeout);
        assert_eq!(
            payment.bond_terms_hash(),
            Terms::work_stake_bond(bond.clone()).hash()
        );
        assert_eq!(terms.timeout_outputs(), None);
        round_trip(&terms);
    }

    /// The embedded witness is the bond's own canonical `Terms` bytes,
    /// so a payment names its bond by the hash the bond edge stores.
    #[test]
    fn embedded_bond_witness_hashes_as_a_standalone_bond() {
        let payment = sample_payment();
        let standalone = Terms::work_stake_bond(payment.bond_terms.clone());

        assert_eq!(payment.bond_terms_hash(), standalone.hash());

        let mut witness = [0; WORK_STAKE_BOND_WITNESS_MAX_SIZE];
        let mut writer = BufferWriter::new(&mut witness);
        encode_work_stake_bond_witness(&mut writer, &payment.bond_terms);
        let written = writer.position();
        let mut standalone_bytes = [0; TermsBody::MAX_ENCODED_SIZE];
        let standalone_written = standalone.write_to(&mut standalone_bytes);
        assert_eq!(written, standalone_written);
        assert_eq!(&witness[..written], &standalone_bytes[..standalone_written]);
    }

    /// Tags 1 and 3 are unassigned: 1 held the deleted legacy stake
    /// bond, 3 never held anything. Both are ordinary rejections, and
    /// neither is a promise about a future body.
    #[test]
    fn unassigned_terms_variants_are_rejected() {
        for tag in [1_u8, 3, 5, 255] {
            let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
            let terms = Terms::work_stake_bond(sample_work_bond());
            let written = terms.write_to(&mut buf);
            buf[ENVELOPE_SIZE] = tag;

            assert_eq!(
                Terms::decode(&buf[..written]).map(|(_, consumed)| consumed),
                Err(DecodeError::InvalidTag { tag }),
            );
        }
    }

    #[test]
    fn close_kind_sets_are_fixed_per_terms_shape() {
        let work_bond = Terms::work_stake_bond(sample_work_bond());
        assert!(!work_bond.allowed_closes().contains(CloseKind::Mutual));
        assert!(work_bond.allowed_closes().contains(CloseKind::Timeout));
        assert!(!work_bond.allowed_closes().contains(CloseKind::Freeze));
        assert!(!work_bond.allowed_closes().contains(CloseKind::Adjudicated));

        let payment = Terms::work_payment(sample_payment());
        assert!(payment.allowed_closes().contains(CloseKind::Freeze));
        assert!(payment.allowed_closes().contains(CloseKind::Adjudicated));
        assert!(!payment.allowed_closes().contains(CloseKind::Timeout));

        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let basic = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
        );
        for kind in [CloseKind::Mutual, CloseKind::Timeout] {
            assert!(basic.allowed_closes().contains(kind));
        }
        assert!(!basic.allowed_closes().contains(CloseKind::Freeze));
        assert!(!basic.allowed_closes().contains(CloseKind::Adjudicated));
    }

    /// Every shape is classified once, and exactly one of them — the
    /// payment edge — has no committed timeout payout. A shape added
    /// without an arm here fails to compile.
    #[test]
    fn every_shape_is_classified_once() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let basic = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
        );
        let cases = [
            basic,
            Terms::work_payment(sample_payment()),
            Terms::work_stake_bond(sample_work_bond()),
        ];

        let mut seen = [false; 3];
        for terms in &cases {
            let index = match terms.profile() {
                TermsProfile::Basic => 0,
                TermsProfile::WorkPayment(_) => 1,
                TermsProfile::WorkStakeBond(_) => 2,
            };
            seen[index] = true;
            assert_eq!(terms.timeout_outputs().is_none(), index == 1);
        }
        assert_eq!(seen, [true; 3]);
    }

    #[test]
    fn basic_terms_hash_is_bound_to_basic_terms_domain() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
        outputs[0] = Payout::new(maker, 7);
        outputs[1] = Payout::new(taker, 8);
        let outputs = List::take(outputs, 2);
        let terms = Terms::basic(
            ProtocolCode::new(1),
            Parties::new(maker, taker),
            BlockHeight::new(99),
            outputs,
        );

        let expected = TermsHash::from_bytes(hash(TERMS_BASIC, &terms.body).into_bytes());
        assert_eq!(terms.hash(), expected);
    }

    #[test]
    fn basic_terms_body_size_matches_canonical_encoding() {
        let maker = Key::from_bytes([1; Key::LENGTH]);
        let taker = Key::from_bytes([2; Key::LENGTH]);
        let outputs = List::all([Payout::new(maker, 7); MAX_EDGE_OUTPUTS]);
        let body = TermsBody::Basic {
            protocol: ProtocolCode::new(1),
            parties: Parties::new(maker, taker),
            timeout: BlockHeight::new(99),
            timeout_outputs: outputs,
        };
        let mut buf = [0; TermsBody::MAX_ENCODED_SIZE];
        let mut writer = BufferWriter::new(&mut buf);

        body.encode_to(&mut writer);

        assert_eq!(body.encoded_size(), writer.position());
        assert!(body.encoded_size() <= TermsBody::MAX_ENCODED_SIZE);
        let maker_start =
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + ProtocolCode::MAX_ENCODED_SIZE + ENVELOPE_SIZE;
        let taker_start = maker_start + Key::LENGTH;
        let parties_end = taker_start + Key::LENGTH;

        assert_eq!(&buf[..4], &[1, tag::TERMS, BASIC_TAG, 1]);
        assert_eq!(&buf[4..maker_start], &[1, tag::PARTIES]);
        assert_eq!(&buf[maker_start..taker_start], maker.as_bytes());
        assert_eq!(&buf[taker_start..parties_end], taker.as_bytes());
    }

    /// The widest body is the work payment, and it is what every buffer
    /// sized by `Terms::MAX_ENCODED_SIZE` must hold.
    #[test]
    fn declared_body_bounds_match_the_widest_encoding() {
        assert_eq!(
            Parties::MAX_ENCODED_SIZE
                + BlockHeight::MAX_ENCODED_SIZE
                + <List<Payout, MAX_EDGE_OUTPUTS> as Encode>::MAX_ENCODED_SIZE
                + u64::MAX_ENCODED_SIZE,
            WorkStakeBondTerms::MAX_ENCODED_SIZE,
        );
        assert_eq!(
            TermsBody::MAX_ENCODED_SIZE,
            ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + WorkPaymentTerms::MAX_ENCODED_SIZE,
        );

        let maker = Key::from_bytes([1; Key::LENGTH]);
        let mut widest = sample_payment();
        widest.bond_terms.timeout_outputs = List::all([Payout::new(maker, 7); MAX_EDGE_OUTPUTS]);
        let terms = Terms::work_payment(widest);
        assert_eq!(terms.encoded_size(), Terms::MAX_ENCODED_SIZE);
        round_trip(&terms);
    }
}
