//! Transaction vocabulary, events, and the validate-then-fold transition machinery.
//!
//! Abstract counterpart: the actions in `models/l1.qnt` (`openEdge`,
//! `closeEdge`, `tick`, `idle`) and `models/delegation.qnt` (`reshape`,
//! the authority-classified opens and closes), and the `step` relations
//! that dispatch over them. `apply` here implements the same
//! validate-then-fold discipline the models capture by primed-variable
//! assignments inside an `action` block.

mod auth;
mod funding;
mod open;
mod payout;
mod proof;
mod reshape;
mod work;

use hellas_xet::SingleChunkHasher;

pub use self::{
    auth::{Auth, Authority, PartyAuth, WebAuthnAssertion, WebAuthnData},
    funding::Funding,
    open::{OpenFunding, OpenProjection, open_projection},
    payout::Payout,
    proof::{CloseKind, CloseKindSet, PaymentContestCommitment, Proof},
    reshape::Reshape,
    work::check_response,
};

use self::open::{
    FundingShape, check_timeout_payout, check_work_profile_open, open_cost, open_debits,
};
use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, peek_envelope_tag, tag,
    },
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS},
    context::{Context, Cost},
    error::{ApplyError, InvalidCloseReason, InvalidOpenReason, InvalidProofReason, KernelResult},
    event::Change,
    list::List,
    network::NetworkId,
    object::{Coin, PartyKeys},
    primitive::{CoinId, EdgeId, PayloadHash, TermsHash},
    registry::{RegistryDiff, RegistryMutation},
    store::Batch,
    terms::{Terms, TermsProfile},
    verifier::SigVerifier,
    work::{PaymentCloseResponse, PaymentCloseStart, work_payment_close_cost},
};

const OPEN_TAG: u8 = 0;
const CLOSE_TAG: u8 = 1;
const MOVE_TAG: u8 = 2;
const OWNER_TAG: u8 = 3;

type PartyCoins = List<CoinId, MAX_PARTY_INPUTS>;
type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type Payouts = List<Payout, MAX_EDGE_OUTPUTS>;
type CloseCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;

/// A protocol transaction submitted to the Hellas kernel.
#[allow(
    clippy::large_enum_variant,
    reason = "Opens and mutual closes may carry two inline WebAuthn assertions in this no-alloc kernel"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Tx {
    /// Open one edge by locking bounded bilateral funding under both
    /// parties' authorization.
    Open {
        /// Bilateral funding consumed by the open. Each list's coins
        /// must be owned by the matching party's committed owner from
        /// `terms.parties()`.
        funding: Funding,
        /// Concrete terms committing the produced edge.
        terms: Terms,
        /// Maker's authorization over [`Tx::open_hash`]. Required even when
        /// the maker funding list is empty — opening an edge that names
        /// the maker as a party requires the maker's consent.
        maker_auth: PartyAuth,
        /// Taker's authorization over [`Tx::open_hash`]. Same
        /// authorization rule as `maker_auth`.
        taker_auth: PartyAuth,
    },

    /// Close one edge into bounded coin payouts.
    Close {
        /// Edge consumed by the close.
        input: EdgeId,
        /// Close proof witness.
        proof: Proof,
        /// Coin payouts produced by the close.
        outputs: Payouts,
    },

    /// Advance the consensus state of a live edge without consuming it.
    ///
    /// The third shape, and the one that owns no coin: a move settles
    /// nothing and produces nothing spendable. It stages the registry
    /// state a later close reads — which is why it announces no public
    /// event, and why the whole of it is bounded by the registry diff a
    /// single operation may write.
    Move {
        /// The action this move performs.
        action: Move,
    },

    /// An owner reshapes coins it owns: the one transaction that sets or
    /// clears a coin's delegate, and the one that pays a third party.
    Owner(Reshape),
}

/// One action under [`Tx::Move`].
///
/// Dispatched on the nested envelope tag rather than on a variant byte:
/// each action body is already a complete tagged composite, and a second
/// discriminant beside its tag would be a redundant encoding with two
/// ways to disagree.
#[allow(
    clippy::large_enum_variant,
    reason = "a close start carries the revealed payment terms inline in this no-alloc kernel"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Move {
    /// Opens the bounded payment-close contest.
    StartPaymentClose(PaymentCloseStart),

    /// The beneficiary's one bounded answer to an open contest.
    RespondPaymentClose(PaymentCloseResponse),
}

impl Move {
    /// Returns the deterministic resource cost of this action.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        match self {
            Self::StartPaymentClose(start) => start.cost(),
            Self::RespondPaymentClose(response) => response.cost(),
        }
    }

    fn apply<B, V>(&self, context: Context, verifier: &V, batch: &B) -> KernelResult<Change>
    where
        B: Batch,
        V: SigVerifier + ?Sized,
    {
        match self {
            Self::StartPaymentClose(start) => work::apply_start(start, context, verifier, batch),
            Self::RespondPaymentClose(response) => {
                work::apply_response(response, context, verifier, batch)
            }
        }
    }
}

impl Encode for Move {
    const MAX_ENCODED_SIZE: usize = {
        let start = PaymentCloseStart::MAX_ENCODED_SIZE;
        let response = PaymentCloseResponse::MAX_ENCODED_SIZE;
        if start > response { start } else { response }
    };

    fn encoded_size(&self) -> usize {
        match self {
            Self::StartPaymentClose(start) => start.encoded_size(),
            Self::RespondPaymentClose(response) => response.encoded_size(),
        }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        match self {
            Self::StartPaymentClose(start) => start.encode_to(writer),
            Self::RespondPaymentClose(response) => response.encode_to(writer),
        }
    }
}

impl Decode for Move {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        match peek_envelope_tag(buf)? {
            tag::PAYMENT_CLOSE_START => {
                let (start, consumed) = PaymentCloseStart::decode(buf)?;
                Ok((Self::StartPaymentClose(start), consumed))
            }
            tag::PAYMENT_CLOSE_RESPONSE => {
                let (response, consumed) = PaymentCloseResponse::decode(buf)?;
                Ok((Self::RespondPaymentClose(response), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

impl Tx {
    /// Creates an open transaction from concrete terms and party-key
    /// authorization witnesses.
    ///
    /// `maker_auth` and `taker_auth` are each checked against the one key
    /// their [`Authority`] names among that party's committed keys, even
    /// when that party contributes no funding input.
    #[must_use]
    pub const fn open(
        funding: Funding,
        terms: Terms,
        maker_auth: PartyAuth,
        taker_auth: PartyAuth,
    ) -> Self {
        Self::Open {
            funding,
            terms,
            maker_auth,
            taker_auth,
        }
    }

    /// Creates a close transaction.
    #[must_use]
    pub const fn close(input: EdgeId, proof: Proof, outputs: Payouts) -> Self {
        Self::Close {
            input,
            proof,
            outputs,
        }
    }

    /// Creates a move transaction.
    #[must_use]
    pub const fn move_action(action: Move) -> Self {
        Self::Move { action }
    }

    /// Creates the unilateral timeout close of `edge` under `terms`:
    /// a `Timeout` proof paying the terms' own committed
    /// `timeout_outputs`.
    ///
    /// The only close whose payload is fixed at open, so it is the one
    /// close that needs no negotiation and no signature — either party
    /// may submit it once the committed height has passed.
    ///
    /// `None` for a terms shape that commits no timeout payout: there
    /// is no payload to construct, and inventing one (an empty payout
    /// list, say) would burn the edge's whole value.
    #[must_use]
    pub fn timeout_close(edge: EdgeId, terms: &Terms) -> Option<Self> {
        let outputs = terms.timeout_outputs()?.clone();
        Some(Self::close(
            edge,
            Proof::timeout(terms.clone(), None),
            outputs,
        ))
    }

    /// Predicts the edge id that [`Tx::open`] would produce for `funding` and
    /// `terms`.
    ///
    /// Useful when callers need to know the id before constructing or
    /// applying the transaction.
    #[must_use]
    pub fn edge_id_of(funding: &Funding, terms: &Terms) -> EdgeId {
        edge_id(funding, terms.hash())
    }

    /// Returns the canonical hash both parties must sign to authorize an
    /// open of the edge that `funding` + `terms` would produce on
    /// `network`.
    ///
    /// Bound to the canonical [`EdgeId`] derived from the open inputs
    /// under a distinct domain separator, so an open signature can never
    /// be replayed as anything else (a close signature, a different
    /// edge's open, etc.) — and bound to [`NetworkId`], so it can never
    /// be replayed as the same open on another network. The id alone
    /// does not carry that: nothing stops two deployments deriving
    /// identical coin ids from identical genesis allocations, and then
    /// identical edge ids from them.
    #[must_use]
    pub fn open_hash(network: NetworkId, funding: &Funding, terms: &Terms) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::OPEN);
        network.encode_to(&mut hasher);
        Self::edge_id_of(funding, terms).encode_to(&mut hasher);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
    }

    /// Returns the canonical ids of the payout coins a close would produce.
    #[must_use]
    pub fn close_output_ids(
        edge: EdgeId,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> List<CoinId, MAX_EDGE_OUTPUTS> {
        let mut ids = [CoinId::ZERO; MAX_EDGE_OUTPUTS];

        for (index, (slot, payout)) in ids.iter_mut().zip(outputs).enumerate() {
            *slot = payout.id(edge, index);
        }

        List::take(ids, outputs.len())
    }

    /// Returns the commitment signed or proven by a close witness on
    /// `network`.
    ///
    /// Network-bound for the same reason as [`Self::open_hash`]: a
    /// mutual close is a signature over a payout, and a payout that is
    /// legitimate on one network must not authorize the identical
    /// payout on another.
    #[must_use]
    pub fn payload_hash(
        network: NetworkId,
        input: EdgeId,
        kind: CloseKind,
        terms: TermsHash,
        outputs: &List<Payout, MAX_EDGE_OUTPUTS>,
    ) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        hasher.update(crate::consts::CLOSE);
        network.encode_to(&mut hasher);
        input.encode_to(&mut hasher);
        kind.tag().encode_to(&mut hasher);
        terms.encode_to(&mut hasher);
        outputs.encode_to(&mut hasher);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
    }

    /// Returns the deterministic resource cost of this transaction.
    #[must_use]
    pub fn cost(&self) -> Cost {
        match self {
            Self::Open { funding, terms, .. } => open_cost(funding.len(), terms),
            Self::Close { proof, outputs, .. } => close_cost(outputs.len(), proof),
            Self::Move { action } => action.cost(),
            Self::Owner(reshape) => reshape.cost(),
        }
    }

    pub(crate) fn apply<B, V>(
        &self,
        context: Context,
        verifier: &V,
        batch: &B,
    ) -> KernelResult<Change>
    where
        B: Batch,
        V: SigVerifier + ?Sized,
    {
        match self {
            Self::Open {
                funding,
                terms,
                maker_auth,
                taker_auth,
            } => apply_open(
                funding, terms, maker_auth, taker_auth, context, verifier, batch,
            ),
            Self::Close {
                input,
                proof,
                outputs,
            } => apply_close(*input, proof, outputs, context, verifier, batch),
            Self::Move { action } => action.apply(context, verifier, batch),
            Self::Owner(reshape) => reshape.apply(context, verifier, batch),
        }
    }
}

impl Encode for Tx {
    const MAX_ENCODED_SIZE: usize = {
        let open =
            Funding::MAX_ENCODED_SIZE + Terms::MAX_ENCODED_SIZE + 2 * PartyAuth::MAX_ENCODED_SIZE;
        let close = EdgeId::MAX_ENCODED_SIZE + Proof::MAX_ENCODED_SIZE + Payouts::MAX_ENCODED_SIZE;
        let mut max_body = if open > close { open } else { close };
        if Move::MAX_ENCODED_SIZE > max_body {
            max_body = Move::MAX_ENCODED_SIZE;
        }
        if Reshape::MAX_ENCODED_SIZE > max_body {
            max_body = Reshape::MAX_ENCODED_SIZE;
        }
        ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + max_body
    };

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Open {
                    funding,
                    terms,
                    maker_auth,
                    taker_auth,
                } => {
                    funding.encoded_size()
                        + terms.encoded_size()
                        + maker_auth.encoded_size()
                        + taker_auth.encoded_size()
                }
                Self::Close {
                    input,
                    proof,
                    outputs,
                } => input.encoded_size() + proof.encoded_size() + outputs.encoded_size(),
                Self::Move { action } => action.encoded_size(),
                Self::Owner(reshape) => reshape.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::TX);
        match self {
            Self::Open {
                funding,
                terms,
                maker_auth,
                taker_auth,
            } => {
                OPEN_TAG.encode_to(writer);
                funding.encode_to(writer);
                terms.encode_to(writer);
                maker_auth.encode_to(writer);
                taker_auth.encode_to(writer);
            }
            Self::Close {
                input,
                proof,
                outputs,
            } => {
                CLOSE_TAG.encode_to(writer);
                input.encode_to(writer);
                proof.encode_to(writer);
                outputs.encode_to(writer);
            }
            Self::Move { action } => {
                MOVE_TAG.encode_to(writer);
                action.encode_to(writer);
            }
            Self::Owner(reshape) => {
                OWNER_TAG.encode_to(writer);
                reshape.encode_to(writer);
            }
        }
    }
}

impl Decode for Tx {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::TX)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            OPEN_TAG => {
                let funding = decode_field(buf, &mut consumed)?;
                let terms = decode_field(buf, &mut consumed)?;
                let maker_auth = decode_field(buf, &mut consumed)?;
                let taker_auth = decode_field(buf, &mut consumed)?;
                Ok((Self::open(funding, terms, maker_auth, taker_auth), consumed))
            }
            CLOSE_TAG => {
                let input = decode_field(buf, &mut consumed)?;
                let proof = decode_field(buf, &mut consumed)?;
                let outputs = decode_field(buf, &mut consumed)?;
                Ok((Self::close(input, proof, outputs), consumed))
            }
            MOVE_TAG => {
                let action = decode_field(buf, &mut consumed)?;
                Ok((Self::move_action(action), consumed))
            }
            OWNER_TAG => {
                let reshape = decode_field(buf, &mut consumed)?;
                Ok((Self::Owner(reshape), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

/// Slots a tag-4 timeout touches beyond its payouts: the edge it
/// consumes, both lease chunks, and the payment edge a present lease
/// names. Every tag-4 timeout reads the lease — that read, and whether
/// the channel it names still exists, is what decides whether the
/// immediate exit is open — so the price does not depend on what it
/// finds.
const WORK_BOND_TIMEOUT_EXTRA_SLOTS: u64 = 4;

/// One slot per payout output plus one for the consumed edge — except
/// for the work-payment exits, whose slot count is fixed by profile.
///
/// The close kind is what selects between them, and it can: `Freeze` and
/// `Adjudicated` are members of exactly one committed close-kind set, so
/// a proof of either kind names a work-payment edge structurally. The
/// fixed count is what lets an open commit a capacity every close route
/// honours.
fn close_cost(outputs: usize, proof: &Proof) -> Cost {
    match proof {
        // Only the timeout's price depends on the profile, and only a
        // timeout reveals the terms that name one. Every other kind is
        // priced by its kind alone.
        Proof::Timeout { terms, .. } => timeout_close_cost(outputs, is_work_bond(terms)),
        Proof::Mutual { .. } | Proof::Freeze { .. } | Proof::Adjudicated { .. } => {
            kind_close_cost(outputs, proof.kind())
        }
    }
}

/// True when `terms` are a tag-4 work bond, whose timeout reads lease
/// state no other shape has.
const fn is_work_bond(terms: &Terms) -> bool {
    matches!(terms.profile(), TermsProfile::WorkStakeBond(_))
}

/// A timeout's slots: its payouts, the edge it consumes, and — for a
/// tag-4 bond — both chunks of the lease it has to read before it can
/// know which height rule governs it.
fn timeout_close_cost(outputs: usize, work_bond: bool) -> Cost {
    let extra = if work_bond {
        WORK_BOND_TIMEOUT_EXTRA_SLOTS
    } else {
        1
    };
    Cost::new(
        1,
        units(outputs).saturating_add(extra),
        CloseKind::Timeout.proofs(),
    )
}

fn kind_close_cost(outputs: usize, kind: CloseKind) -> Cost {
    match kind {
        CloseKind::Freeze | CloseKind::Adjudicated => work_payment_close_cost(kind),
        CloseKind::Mutual | CloseKind::Timeout => {
            Cost::new(1, units(outputs).saturating_add(1), kind.proofs())
        }
    }
}

fn apply_open<B, V>(
    funding: &Funding,
    terms: &Terms,
    maker_auth: &PartyAuth,
    taker_auth: &PartyAuth,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let output = edge_id(funding, terms.hash());

    if let Some(id) = duplicate(open_inputs(funding).as_slice()) {
        return Err(ApplyError::DuplicateInput { id });
    }
    if batch.edge(output).is_some() {
        return Err(ApplyError::EdgeExists { id: output });
    }

    let coins = open_coins(funding, batch)?;
    let parties = terms.parties();
    // Run every cheap structural / arithmetic check before the
    // signature verifier. The verifier is the most expensive piece of
    // the open path (Xet hash + two SigVerifier calls, potentially real
    // ECDSA); under DoS pressure we don't want a tx that fails
    // cheaply on owner-match or insufficient funding to also pay for
    // crypto.
    check_funding_ownership(output, &coins, funding.maker_len(), parties)?;
    // The same arithmetic `open_projection` performs for an endpoint
    // holding no store, and the only implementation of it.
    let debits = open_debits(
        context.block_height(),
        context.fees(),
        funding.len(),
        coins.checked_sum(|(_, coin)| coin.value()),
        terms,
    )
    .map_err(|reason| invalid_open(output, reason))?;
    let edge = debits.edge;
    check_timeout_payout(&debits, terms).map_err(|reason| invalid_open(output, reason))?;
    check_open_authority(terms, (&coins, funding.maker_len()), maker_auth, taker_auth)
        .map_err(|reason| invalid_open(output, reason))?;
    check_work_profile_open(&edge, FundingShape::of(funding), terms)
        .map_err(|reason| invalid_open(output, reason))?;
    // Before the verifier, like every other structural check: a payment
    // naming a bond that is absent, wrong, or already leased must not
    // also pay for signature verification.
    let registry = work::open_bond_lease(output, terms, context, batch)?;
    check_open_auth(
        context.network(),
        output,
        funding,
        terms,
        maker_auth,
        taker_auth,
        verifier,
    )?;
    // One `Change`, so the edge and the lease it takes out commit or
    // fail together. A block that persisted the payment edge without
    // its lease would have created exactly the unbonded channel this
    // path exists to refuse.
    Ok(Change::open(&coins, &(output, edge)).with_registry(&registry))
}

/// Every coin in `funding.maker` must be owned by the maker's committed
/// owner; same for the taker. The kernel reads each coin's `owner()` from
/// the staged batch and compares against the matching party's owner —
/// the authentication check that complements the open signatures. A
/// party's coins therefore share one owner, whichever of its keys signs.
fn check_funding_ownership(
    output: EdgeId,
    coins: &OpenCoins,
    maker_len: usize,
    parties: crate::object::Parties,
) -> KernelResult<()> {
    for (index, (_, coin)) in coins.as_slice().iter().enumerate() {
        let expected = if index < maker_len {
            parties.maker()
        } else {
            parties.taker()
        };
        if coin.owner() != expected.owner() {
            return Err(invalid_open(output, InvalidOpenReason::FundingUnauthorized));
        }
    }
    Ok(())
}

/// What each party's witness class permits it to commit.
///
/// A basic edge admits owners only. Its committed timeout outputs pay
/// with no signature at all, so a delegate able to open one could park
/// its owner's coins until a height of its choosing with no exit the
/// owner controls; every work shape, by contrast, leaves the owner a
/// bounded exit (a payment's contest, a bond's timeout once its channel
/// is gone).
///
/// A signer-authorized party may spend only coins delegated to that
/// signer, and may commit only itself or nobody as its payout delegate.
/// An owner may spend any of its coins whatever they are delegated to,
/// and commit any payout delegate. The destination's owner is not a
/// choice for either: it is the party's owner by construction.
fn check_open_authority(
    terms: &Terms,
    funding: (&OpenCoins, usize),
    maker_auth: &PartyAuth,
    taker_auth: &PartyAuth,
) -> Result<(), InvalidOpenReason> {
    let (coins, maker_len) = funding;
    if matches!(terms.profile(), TermsProfile::Basic)
        && !(maker_auth.is_owner() && taker_auth.is_owner())
    {
        return Err(InvalidOpenReason::BasicAuthNotOwner);
    }
    let parties = terms.parties();
    let (maker_coins, taker_coins) = coins.as_slice().split_at(maker_len.min(coins.len()));
    check_party_authority(parties.maker(), maker_auth, maker_coins)?;
    check_party_authority(parties.taker(), taker_auth, taker_coins)
}

fn check_party_authority(
    party: PartyKeys,
    auth: &PartyAuth,
    coins: &[(CoinId, Coin)],
) -> Result<(), InvalidOpenReason> {
    if auth.is_owner() {
        return Ok(());
    }
    let signer = Some(party.signer());
    if coins.iter().any(|(_, coin)| coin.delegate() != signer) {
        return Err(InvalidOpenReason::FundingNotDelegated);
    }
    if party.payout_delegate().is_some() && party.payout_delegate() != signer {
        return Err(InvalidOpenReason::PayoutDelegateNotSigner);
    }
    Ok(())
}

fn check_open_auth<V: SigVerifier + ?Sized>(
    network: NetworkId,
    output: EdgeId,
    funding: &Funding,
    terms: &Terms,
    maker_auth: &PartyAuth,
    taker_auth: &PartyAuth,
    verifier: &V,
) -> KernelResult<()> {
    let hash = Tx::open_hash(network, funding, terms);
    let parties = terms.parties();
    if !verify_party(verifier, maker_auth, parties.maker(), hash)
        || !verify_party(verifier, taker_auth, parties.taker(), hash)
    {
        return Err(invalid_open(output, InvalidOpenReason::BadSignature));
    }
    Ok(())
}

/// Verifies `auth` against exactly the one key its authority names
/// among `party`'s committed keys.
pub fn verify_party<V: SigVerifier + ?Sized>(
    verifier: &V,
    auth: &PartyAuth,
    party: PartyKeys,
    hash: PayloadHash,
) -> bool {
    verifier.verify_auth(auth.auth(), party.key(auth.authority()), hash)
}

fn apply_close<B, V>(
    input: EdgeId,
    proof: &Proof,
    outputs: &Payouts,
    context: Context,
    verifier: &V,
    batch: &B,
) -> KernelResult<Change>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    check_close_outputs(input, outputs, batch)?;

    let coins = close_coins(input, outputs);
    let edge = batch
        .edge(input)
        .ok_or(ApplyError::MissingEdge { id: input })?;
    if !edge.allows(proof.kind()) {
        return Err(invalid_close(input, InvalidCloseReason::KindForbidden));
    }
    // Cheap structural checks first: output freshness and value conservation.
    // Close has no marginal monetary fee: the reserve was committed when the
    // edge opened, while `Tx::cost()` still counts close resources for block
    // admission. Signature verification comes last so a close that fails a
    // trivial check never pays for it.
    let total = edge
        .closes(&coins, close_cost(outputs.len(), proof))
        .map_err(|reason| invalid_close(input, reason))?;
    let subject = work::CloseSubject {
        input,
        edge: &edge,
        total,
        outputs,
    };
    let staged = check_proof(subject, proof, context, verifier, batch)
        .map_err(|reason| ApplyError::InvalidProof { input, reason })?;

    // Every close that touches registry state retires state belonging
    // to the edge it just consumed: the work-payment exits retire the
    // contest they settled, and a leased bond's timeout retires the
    // lease. Anything left behind would be a record about an edge that
    // no longer exists.
    let mut registry = RegistryDiff::empty();
    for mutation in staged.into_iter().flatten() {
        registry
            .push(mutation)
            .map_err(|reason| ApplyError::RegistryDiffRejected { reason })?;
    }
    Ok(Change::close(&(input, edge), &coins).with_registry(&registry))
}

/// Registry writes one close stages.
///
/// Two is the widest any close in this kernel makes: a leased tag-4
/// bond's timeout deletes both chunks of the lease. The work-payment
/// exits stage one, and the rest stage none.
type StagedCloseRegistry = [Option<RegistryMutation>; 2];

fn check_timeout<B: Batch, V: SigVerifier + ?Sized>(
    close: work::CloseSubject<'_>,
    terms: &Terms,
    owner: Option<&PartyAuth>,
    context: Context,
    verifier: &V,
    batch: &B,
) -> Result<StagedCloseRegistry, InvalidProofReason> {
    let work::CloseSubject {
        input,
        edge,
        outputs,
        ..
    } = close;
    if terms.hash() != edge.terms() {
        return Err(InvalidProofReason::TermsMismatch);
    }
    // Only a tag-4 bond has lease state, so only a tag-4 bond
    // pays to read it. Both slots are consulted, and anything
    // that is not exactly a whole lease or exactly nothing is a
    // rejection: reading a half-written record as "unleased"
    // would open the immediate exit under a live channel's
    // recourse.
    let lease = if is_work_bond(terms) {
        crate::lease::read_bond_lease(batch, context.network(), input)
            .map_err(|fault| InvalidProofReason::BondLeaseFault { fault })?
    } else {
        None
    };
    // A lease whose payment edge is gone insures nothing. The
    // channel it backed has settled, so nobody holds recourse
    // through it, and holding the stake to the horizon would only
    // let whoever opened that channel lock the bond for as long
    // as it chose — at the cost of the channel's dust. The lease
    // is created in the same change as its payment edge, so a
    // present lease naming an absent edge always means "closed",
    // never "not yet opened".
    let live_lease = lease.filter(|lease| batch.edge(lease.payment_edge()).is_some());
    // An unleased bond is the one shape whose timeout does not
    // wait. Nobody holds recourse against it, so there is
    // nothing for the horizon to protect — and consuming it is
    // what makes a delayed payment open fail its live-bond
    // check instead of leasing stake the provider has already
    // given up on. Every other shape, this one leased by a live
    // channel and every edge that is not a tag-4 bond at all,
    // waits.
    if !(is_work_bond(terms) && live_lease.is_none()) && context.block_height() < edge.timeout() {
        return Err(InvalidProofReason::TimeoutNotReached);
    }
    // Shapes with no committed timeout payout do not admit this
    // close at all, so this is unreachable through a live edge;
    // it stays a rejection rather than a payout of the caller's
    // choosing.
    let Some(committed) = terms.timeout_outputs() else {
        return Err(InvalidProofReason::PayoutMismatch);
    };
    if let Some(auth) = owner {
        if !is_work_bond(terms) || !auth.is_owner() {
            return Err(InvalidProofReason::BadSignature);
        }
        let hash = Tx::payload_hash(
            context.network(),
            input,
            CloseKind::Timeout,
            edge.terms(),
            outputs,
        );
        if !verify_party(verifier, auth, edge.parties().maker(), hash) {
            return Err(InvalidProofReason::BadSignature);
        }
    }
    if committed.len() != outputs.len()
        || committed.iter().zip(outputs).any(|(expected, actual)| {
            let expected = if owner.is_some() {
                Payout::new(expected.owner(), expected.value())
            } else {
                *expected
            };
            expected != *actual
        })
    {
        return Err(InvalidProofReason::PayoutMismatch);
    }
    // A leased bond's timeout takes the lease with it, live or
    // stale. The channel it insured keeps its own exits — a
    // payment edge outlives the admission horizon — but nothing
    // may still be reached through a bond that no longer exists.
    Ok(lease.map_or(NO_STAGED_REGISTRY, |_| {
        crate::lease::delete_mutations(context.network(), input).map(Some)
    }))
}

/// Checks the close witness and returns the registry slots the close
/// writes, if it writes any.
///
/// Timeout checks terms binding, height and payout shape, plus the optional
/// bond-owner witness through the shared party verifier. It reads
/// the staged batch for one profile: a tag-4 bond's height rule is
/// decided by whether a lease exists. The two work-payment kinds read it
/// too — their payout is derived from the contest record, not carried by
/// the transaction.
fn check_proof<B, V>(
    close: work::CloseSubject<'_>,
    proof: &Proof,
    context: Context,
    verifier: &V,
    batch: &B,
) -> Result<StagedCloseRegistry, InvalidProofReason>
where
    B: Batch,
    V: SigVerifier + ?Sized,
{
    let work::CloseSubject {
        input,
        edge,
        outputs,
        ..
    } = close;
    match proof {
        Proof::Mutual { maker, taker } => {
            if context.block_height() >= edge.timeout() {
                return Err(InvalidProofReason::ProofExpired);
            }
            let parties = edge.parties();
            // Both parties sign these outputs, but a cooperative close
            // is not a way to pay anyone the terms did not name: that is
            // a reshape's job, and a delegate co-signing with a colluding
            // counterparty must not get a third destination out of it.
            if !outputs.iter().all(|payout| {
                parties.maker().is_destination(*payout, maker.is_owner())
                    || parties.taker().is_destination(*payout, taker.is_owner())
            }) {
                return Err(InvalidProofReason::PayoutNotCommitted);
            }
            let hash = Tx::payload_hash(
                context.network(),
                input,
                CloseKind::Mutual,
                edge.terms(),
                outputs,
            );
            if verify_party(verifier, maker, parties.maker(), hash)
                && verify_party(verifier, taker, parties.taker(), hash)
            {
                Ok(NO_STAGED_REGISTRY)
            } else {
                Err(InvalidProofReason::BadSignature)
            }
        }
        Proof::Timeout { terms, owner } => {
            check_timeout(close, terms, owner.as_ref(), context, verifier, batch)
        }
        // Neither work-payment exit expires at the admission horizon. That
        // horizon buys admission and rent, not a refund, and a channel
        // that stopped being settleable once it stopped admitting jobs
        // would strand every amount already earned against it.
        Proof::Freeze {
            earned,
            valid_from_height,
            valid_through_height,
            maker,
            taker,
        } => work::check_freeze(
            close,
            (
                *earned,
                (*valid_from_height, *valid_through_height),
                maker,
                taker,
            ),
            context,
            verifier,
            batch,
        )
        .map(one_staged),
        Proof::Adjudicated { contest_commitment } => {
            work::check_adjudicated(close, *contest_commitment, context, batch).map(one_staged)
        }
    }
}

/// A close that stages nothing.
const NO_STAGED_REGISTRY: StagedCloseRegistry = [None, None];

/// Widens the one mutation a work-payment exit stages, or none.
const fn one_staged(mutation: Option<RegistryMutation>) -> StagedCloseRegistry {
    [mutation, None]
}

fn open_inputs(funding: &Funding) -> List<CoinId, MAX_EDGE_INPUTS> {
    let mut ids = [CoinId::ZERO; MAX_EDGE_INPUTS];

    for (slot, id) in ids.iter_mut().zip(funding.iter()) {
        *slot = id;
    }

    List::take(ids, funding.len())
}

fn open_coins<B: Batch>(funding: &Funding, batch: &B) -> KernelResult<OpenCoins> {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
    for (slot, id) in coins.iter_mut().zip(funding.iter()) {
        let coin = batch.coin(id).ok_or(ApplyError::MissingCoin { id })?;
        *slot = (id, coin);
    }
    Ok(List::take(coins, funding.len()))
}

fn check_close_outputs<B: Batch>(input: EdgeId, outputs: &Payouts, batch: &B) -> KernelResult<()> {
    for (index, output) in outputs.iter().enumerate() {
        let id = output.id(input, index);
        if batch.coin(id).is_some() {
            return Err(ApplyError::OutputExists { id });
        }
    }
    Ok(())
}

fn close_coins(input: EdgeId, outputs: &Payouts) -> CloseCoins {
    let mut coins = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
    for (index, (slot, output)) in coins.iter_mut().zip(outputs).enumerate() {
        *slot = output.close_coin(input, index);
    }
    List::take(coins, outputs.len())
}

fn edge_id(funding: &Funding, terms_hash: TermsHash) -> EdgeId {
    let mut hasher = SingleChunkHasher::new();
    hasher.update(crate::consts::EDGE_OPEN);
    terms_hash.encode_to(&mut hasher);
    funding.maker().encode_to(&mut hasher);
    funding.taker().encode_to(&mut hasher);
    EdgeId::from_bytes(hasher.finalize().into_bytes())
}

const fn invalid_open(output: EdgeId, reason: InvalidOpenReason) -> ApplyError {
    ApplyError::InvalidOpen { output, reason }
}

const fn invalid_close(input: EdgeId, reason: InvalidCloseReason) -> ApplyError {
    ApplyError::InvalidClose { input, reason }
}

fn units(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn duplicate<T: Copy + Eq>(items: &[T]) -> Option<T> {
    let mut rest = items;
    while let Some((head, tail)) = rest.split_first() {
        if tail.contains(head) {
            return Some(*head);
        }
        rest = tail;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::open::open_reserve_cost;
    use super::*;
    use crate::{object::Parties, primitive::Key, terms::WorkStakeBondTerms};

    /// A profile's reserve has to cover every close its *own* set
    /// admits, at every fanout. A kind an edge can admit but its reserve
    /// cannot pay for is a stranded edge (`ReserveTooSmall`); fail here
    /// instead.
    ///
    /// Enumerated from [`CloseKind::ALL`] against each profile's set
    /// rather than from a list written here: a kind added to a set
    /// without being priced is exactly the kind that would strand one.
    /// The `work_bond` flag is carried alongside the set because one
    /// kind — `Timeout` — costs a different number of slots on a tag-4
    /// bond than on any other shape, and a reserve checked against the
    /// cheaper spelling would pass while the edge stranded.
    #[test]
    fn every_profile_reserve_covers_its_own_close_set_at_every_fanout() {
        let profiles = [
            (
                CloseKindSet::BASIC,
                kind_close_cost(MAX_EDGE_OUTPUTS, CloseKind::Mutual),
                false,
            ),
            (
                CloseKindSet::WORK_STAKE_BOND,
                open_reserve_cost(&work_bond_terms()),
                true,
            ),
            (
                CloseKindSet::WORK_PAYMENT,
                crate::work::work_payment_reserve_cost(),
                false,
            ),
        ];

        for (set, reserve, work_bond) in profiles {
            for kind in CloseKind::ALL {
                if !set.contains(kind) {
                    continue;
                }
                for outputs in 0..=MAX_EDGE_OUTPUTS {
                    let cost = if matches!(kind, CloseKind::Timeout) {
                        timeout_close_cost(outputs, work_bond)
                    } else {
                        kind_close_cost(outputs, kind)
                    };
                    assert!(
                        cost.fits(reserve),
                        "close_cost({outputs}, {kind:?}) exceeds the {set:?} reserve",
                    );
                }
            }
        }
    }

    /// Basic keeps the generic maximum. The two work profiles each
    /// reserve their own — the payment its fixed four-slot exits, the
    /// bond its lease-reading timeout.
    #[test]
    fn each_profile_reserves_its_own_worst_close() {
        let generic = kind_close_cost(MAX_EDGE_OUTPUTS, CloseKind::Mutual);
        assert_eq!(generic, Cost::new(1, 5, 2));
        assert_eq!(open_reserve_cost(&work_bond_terms()), Cost::new(1, 8, 2));
        assert_eq!(crate::work::work_payment_reserve_cost(), Cost::new(1, 4, 2));
    }

    /// A tag-4 bond, in the least interesting shape that is one: these
    /// tests read only its profile, and the reserve rule they check is
    /// the profile's, not this bond's.
    fn work_bond_terms() -> Terms {
        Terms::work_stake_bond(WorkStakeBondTerms {
            parties: Parties::new(
                PartyKeys::sole(Key::from_bytes([1; Key::LENGTH])),
                PartyKeys::sole(Key::from_bytes([2; Key::LENGTH])),
            ),
            timeout: crate::context::BlockHeight::new(10),
            timeout_outputs: List::take([Payout::default(); MAX_EDGE_OUTPUTS], 0),
            max_job_price: 1,
        })
    }
}
