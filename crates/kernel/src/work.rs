#![allow(clippy::redundant_pub_crate)]

//! Work-payment close vocabulary: the earned certificate, the two Move
//! bodies, the pending record they write, and every digest that binds
//! them.
//!
//! # What the close contests
//!
//! One scalar. A work channel's adjudicable state is the greatest valid
//! client-signed cumulative earned amount the provider durably admitted
//! before its terminal cutoff — not a work set, not a lane tip, not a
//! membership root. Everything here exists to move that one number onto
//! L1 and to make omitting it unprofitable.
//!
//! A unilateral close is therefore three transactions: a
//! [`PaymentCloseStart`] that stakes a claim and opens a bounded window,
//! at most one [`PaymentCloseResponse`] that raises it, and a
//! `Proof::Adjudicated` close that pays the result out. The window is
//! information-theoretically necessary: an immediate close cannot
//! distinguish a world where no greater certificate exists from one where
//! the counterparty holds it privately, so the holder is given exactly
//! one chance to speak.
//!
//! # What this module is not
//!
//! It is the vocabulary, not the rules and not the insurance. The four
//! transitions that read and write these values live in
//! [`crate::tx::work`]; the exclusive lease that makes a provider's stake
//! back this channel and no other lives in [`crate::lease`], and is taken
//! at payment open rather than at close, so nothing here consults it. The
//! close kinds an edge admits — `Freeze` and `Adjudicated`, and
//! deliberately not `Timeout` — are fixed by [`crate::Terms`], which is
//! also where the admission horizon's meaning is written down.
//!
//! Abstract counterpart: none. The pending record is registry state, and
//! `models/registry.md` lists which properties of this close — the
//! scalar's monotonicity, the bond's conservation, the one-contest and
//! one-response rules, absence-versus-fault — are therefore established
//! by Rust tests alone.
//!
//! # Bounded preimages
//!
//! Every digest below is a [`SingleChunkHasher`] result, and that hasher
//! *asserts* rather than errors once a preimage reaches
//! [`hellas_xet::MIN_CHUNK_SIZE`]. These run on the apply path, where a
//! panic is a node halt and not a rejected transaction, so each preimage
//! is written by a `*_preimage` function whose compile-time maximum is
//! asserted below. The split also lets the tests count the exact bytes
//! each preimage emits instead of trusting the arithmetic here.

use hellas_xet::SingleChunkHasher;

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::{HASH_LENGTH, ID_LENGTH},
    context::Cost,
    error::{InvalidProofReason, PendingCloseFault},
    network::NetworkId,
    object::{Edge, EdgeValues, Parties},
    primitive::{EdgeId, Party, PayloadHash, TermsHash},
    registry::{RegistryChunk, RegistryChunkId, RegistryNamespace, RegistryRecordTag},
    store::Batch,
    terms::Terms,
    tx::{CloseKind, PartyAuth, PaymentContestCommitment, Payout},
};

/// Version byte every work-payment v3 body carries. Decode rejects any
/// other value, so one body shape has exactly one meaning.
const WORK_CLOSE_VERSION: u8 = 3;
const WORK_PENDING_VERSION: u8 = 4;

/// Physical store slots a work-payment close touches: the payment edge,
/// its two payout coins, and the pending-close registry slot.
///
/// Fixed, and charged whether or not the pending slot holds a record: a
/// close whose price depended on the contest having happened would let
/// the cheaper route pay out more than the edge reserved for the dearer
/// one. It is also why the payout fanout is fixed at two rather than
/// carried by the transaction.
const WORK_PAYMENT_CLOSE_SLOTS: u64 = 4;

/// Returns the exact cost of the work-payment close `kind`.
///
/// Both routes are priced from the same fixed slot count, so the capacity
/// an open commits is the capacity every close honours.
pub(crate) const fn work_payment_close_cost(kind: CloseKind) -> Cost {
    Cost::new(1, WORK_PAYMENT_CLOSE_SLOTS, kind.proofs())
}

/// Returns the reserve a work-payment open locks.
///
/// The dearer of its two exits: `Freeze` verifies two signatures where
/// `Adjudicated` verifies none, and both touch the same four slots.
pub(crate) const fn work_payment_reserve_cost() -> Cost {
    work_payment_close_cost(CloseKind::Freeze)
}

/// Returns the largest cumulative amount a certificate on this edge may
/// name, or `None` when the edge cannot fund both close routes plus the
/// omission bond.
///
/// `min(close_total(Freeze), close_total(Adjudicated)) - omission_bond`.
/// The minimum is what makes the subtraction at close total: a
/// certificate admitted against the cheaper route would not fit the
/// dearer one. Reserving the bond on top is what leaves a proved
/// understatement something to forfeit.
pub(crate) fn payment_capacity(edge: &Edge, omission_bond: u64) -> Option<u64> {
    Some(work_payment_settlement(edge.values(), omission_bond)?.capacity)
}

/// Returns the smaller of the two values a work-payment close can
/// distribute, or `None` when the edge's reserve does not price both
/// routes.
///
/// Separate from [`payment_capacity`] so an open can tell an edge that
/// cannot afford its own exits from one whose omission bond is larger
/// than everything it distributes. They are different mistakes and they
/// have different fixes.
pub(crate) fn close_route_minimum(edge: &Edge) -> Option<u64> {
    route_minimum(edge.values())
}

fn route_minimum(edge: EdgeValues) -> Option<u64> {
    let freeze = edge.close_value(work_payment_close_cost(CloseKind::Freeze))?;
    let adjudicated = edge.close_value(work_payment_close_cost(CloseKind::Adjudicated))?;
    Some(if freeze < adjudicated {
        freeze
    } else {
        adjudicated
    })
}

/// What one payment edge's two exits distribute, and the most a
/// certificate against it may name.
///
/// The endpoints need this arithmetic as badly as consensus does — a
/// client that signs a certificate above capacity has signed something
/// no close will pay, and a watcher that builds payouts from
/// `EdgeState.value` builds a close consensus refuses. It is one
/// calculation, exported, rather than three implementations that agree
/// until a fee schedule moves.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct WorkPaymentSettlement {
    freeze_total: u64,
    adjudicated_total: u64,
    capacity: u64,
    omission_bond: u64,
}

impl WorkPaymentSettlement {
    /// Returns the value a cooperative `Freeze` distributes.
    #[must_use]
    pub const fn freeze_total(&self) -> u64 {
        self.freeze_total
    }

    /// Returns the value a unilateral `Adjudicated` close distributes.
    #[must_use]
    pub const fn adjudicated_total(&self) -> u64 {
        self.adjudicated_total
    }

    /// Returns the largest cumulative amount a certificate may name.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Returns the funded omission bond a proved understatement
    /// forfeits.
    ///
    /// Carried rather than derived from the difference between the
    /// route minimum and the capacity: the payout functions need the
    /// exact amount, and recovering it by subtraction would be a second
    /// way to say the same thing.
    #[must_use]
    pub const fn omission_bond(&self) -> u64 {
        self.omission_bond
    }
}

/// Returns what a work-payment edge can settle, or `None` when its
/// reserve does not price both exits or its bond exceeds everything
/// they distribute.
///
/// Takes values rather than an [`Edge`] because the party that most
/// needs this arithmetic cannot hold one: an endpoint reads a finalized
/// edge from a light client, not from the kernel's store.
#[must_use]
pub fn work_payment_settlement(
    edge: EdgeValues,
    omission_bond: u64,
) -> Option<WorkPaymentSettlement> {
    let freeze_total = edge.close_value(work_payment_close_cost(CloseKind::Freeze))?;
    let adjudicated_total = edge.close_value(work_payment_close_cost(CloseKind::Adjudicated))?;
    let capacity = route_minimum(edge)?.checked_sub(omission_bond)?;
    Some(WorkPaymentSettlement {
        freeze_total,
        adjudicated_total,
        capacity,
        omission_bond,
    })
}

/// Returns the exact two payouts an `Adjudicated` close must carry.
///
/// `final_cumulative` is the scalar the contest ended at, `penalty_due`
/// is whether that contest proved an understatement, and `owner_signed`
/// records owner actions separately as `[maker, taker]` — see
/// [`PendingPaymentClose::owner_signed`]. There is no route argument: a
/// work-payment edge admits two exits, and the two functions that build
/// them are the two exits.
///
/// # Errors
///
/// [`InvalidProofReason::PayoutOverCapacity`] when the provider's total
/// exceeds what this route distributes, or when adding the forfeited
/// bond would wrap.
pub fn adjudicated_payouts(
    settlement: WorkPaymentSettlement,
    parties: Parties,
    final_cumulative: u64,
    penalty_due: bool,
    owner_signed: [bool; 2],
) -> Result<[Payout; 2], InvalidProofReason> {
    let penalty = if penalty_due {
        settlement.omission_bond
    } else {
        0
    };
    let provider = final_cumulative
        .checked_add(penalty)
        .ok_or(InvalidProofReason::PayoutOverCapacity)?;
    split_payouts(
        parties,
        settlement.adjudicated_total,
        provider,
        owner_signed,
    )
}

/// Returns the exact two payouts a cooperative `Freeze` must carry.
///
/// `penalty` is an amount and not a flag because a freeze's penalty is
/// whatever the contest it ends had already proved, which is zero for
/// the uncontested close both parties are agreeing to. `owner_signed` is
/// `[maker, taker]`: each flag combines that party's freeze witness with its
/// retained owner actions in the contest.
///
/// # Errors
///
/// [`InvalidProofReason::PayoutOverCapacity`] when the provider's total
/// exceeds what this route distributes, or when adding the penalty
/// would wrap.
pub fn freeze_payouts(
    settlement: WorkPaymentSettlement,
    parties: Parties,
    earned: u64,
    penalty: u64,
    owner_signed: [bool; 2],
) -> Result<[Payout; 2], InvalidProofReason> {
    let provider = earned
        .checked_add(penalty)
        .ok_or(InvalidProofReason::PayoutOverCapacity)?;
    split_payouts(parties, settlement.freeze_total, provider, owner_signed)
}

/// The fixed shape of every work-payment payout: provider first, client
/// second, each at its party's committed destination, summing to exactly
/// what the route distributes.
///
/// The one implementation. Consensus compares a close's outputs against
/// it and the endpoints construct closes from it, so a payout an
/// endpoint builds and a payout consensus expects cannot be two
/// different opinions about who is owed what.
///
/// `owner_signed` records maker and taker independently. An owner exits only
/// its own delegation; the counterparty keeps its committed destination.
pub(crate) fn split_payouts(
    parties: Parties,
    total: u64,
    provider_total: u64,
    owner_signed: [bool; 2],
) -> Result<[Payout; 2], InvalidProofReason> {
    let client_total = total
        .checked_sub(provider_total)
        .ok_or(InvalidProofReason::PayoutOverCapacity)?;
    Ok([
        parties.taker().payout(provider_total, owner_signed[1]),
        parties.maker().payout(client_total, owner_signed[0]),
    ])
}

// ── The certificate ───────────────────────────────────────────────────

/// A client's signed statement of everything the provider has earned on
/// one payment edge, ever.
///
/// Cumulative, not incremental, which is the whole design: maximum is
/// associative, commutative, and idempotent, so two endpoints that
/// admitted the same certificates in different orders hold the same
/// settlement state and neither has to prove it saw a complete history.
/// Only the client signs; there is no counter-acknowledgement that could
/// cap it.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct EarnedCertificate {
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    earned_cumulative: u64,
}

impl EarnedCertificate {
    /// Canonical encoded length, envelope included.
    pub const ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + EdgeId::MAX_ENCODED_SIZE
        + TermsHash::MAX_ENCODED_SIZE
        + u64::MAX_ENCODED_SIZE;

    /// Creates a certificate for one payment edge.
    #[must_use]
    pub const fn new(
        payment_edge: EdgeId,
        payment_terms_hash: TermsHash,
        earned_cumulative: u64,
    ) -> Self {
        Self {
            payment_edge,
            payment_terms_hash,
            earned_cumulative,
        }
    }

    /// Returns the payment edge this certificate settles.
    #[must_use]
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the payment terms this certificate is bound to.
    #[must_use]
    pub const fn payment_terms_hash(&self) -> TermsHash {
        self.payment_terms_hash
    }

    /// Returns the cumulative amount earned.
    #[must_use]
    pub const fn earned_cumulative(&self) -> u64 {
        self.earned_cumulative
    }

    /// Returns the digest the client signs.
    #[must_use]
    pub fn digest(&self, network: NetworkId) -> PayloadHash {
        let mut hasher = SingleChunkHasher::new();
        earned_preimage(&mut hasher, network, self);
        PayloadHash::from_bytes(hasher.finalize().into_bytes())
    }
}

fn earned_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    certificate: &EarnedCertificate,
) {
    writer.write(crate::consts::WORK_EARNED_CERTIFICATE);
    network.encode_to(writer);
    certificate.payment_edge.encode_to(writer);
    certificate.payment_terms_hash.encode_to(writer);
    certificate.encode_to(writer);
}

const EARNED_PREIMAGE_MAX: usize = crate::consts::WORK_EARNED_CERTIFICATE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + EarnedCertificate::ENCODED_SIZE;

impl Encode for EarnedCertificate {
    const MAX_ENCODED_SIZE: usize = Self::ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::EARNED_CERTIFICATE);
        WORK_CLOSE_VERSION.encode_to(writer);
        self.payment_edge.encode_to(writer);
        self.payment_terms_hash.encode_to(writer);
        self.earned_cumulative.encode_to(writer);
    }
}

impl Decode for EarnedCertificate {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::EARNED_CERTIFICATE)?;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != WORK_CLOSE_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let payment_edge = decode_field(buf, &mut consumed)?;
        let payment_terms_hash = decode_field(buf, &mut consumed)?;
        let earned_cumulative = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(payment_edge, payment_terms_hash, earned_cumulative),
            consumed,
        ))
    }
}

/// Returns the constant a close start signs in place of a certificate.
///
/// Zero is the implicit certificate, so an opener claiming nothing signs
/// this rather than an all-zero body: two spellings of one state would
/// let a start be re-encoded without breaking its signature.
#[must_use]
pub fn no_earned_digest(payment_edge: EdgeId, payment_terms_hash: TermsHash) -> PayloadHash {
    let mut hasher = SingleChunkHasher::new();
    no_earned_preimage(&mut hasher, payment_edge, payment_terms_hash);
    PayloadHash::from_bytes(hasher.finalize().into_bytes())
}

fn no_earned_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
) {
    writer.write(crate::consts::WORK_NO_EARNED_CERTIFICATE);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
}

const NO_EARNED_PREIMAGE_MAX: usize = crate::consts::WORK_NO_EARNED_CERTIFICATE.len()
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE;

/// Returns the canonical 32-byte settlement state for `amount`.
///
/// The state a cooperative freeze signs over. It carries the amount and
/// nothing else — no signature, no invoice sequence, no arrival order —
/// because none of those change who is paid what.
#[must_use]
pub fn settlement_commitment(
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    amount: u64,
) -> [u8; HASH_LENGTH] {
    let mut hasher = SingleChunkHasher::new();
    settlement_preimage(
        &mut hasher,
        network,
        payment_edge,
        payment_terms_hash,
        amount,
    );
    hasher.finalize().into_bytes()
}

fn settlement_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    amount: u64,
) {
    writer.write(crate::consts::WORK_SETTLEMENT_STATE);
    network.encode_to(writer);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
    amount.encode_to(writer);
}

const SETTLEMENT_PREIMAGE_MAX: usize = crate::consts::WORK_SETTLEMENT_STATE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + u64::MAX_ENCODED_SIZE;

// ── Start ─────────────────────────────────────────────────────────────

/// Identifier of one accepted close contest.
///
/// Derived from the signed start digest *and* the height that accepted
/// it, so a start signature that stays includable across its validity
/// window still names exactly one contest — and a racing responder can
/// bind its answer to the one that won.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StartId([u8; Self::LENGTH]);

impl StartId {
    /// Encoded length of a start identifier.
    pub const LENGTH: usize = ID_LENGTH;

    /// Reconstructs a start id from canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical byte representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl Encode for StartId {
    const MAX_ENCODED_SIZE: usize = Self::LENGTH;

    fn encoded_size(&self) -> usize {
        Self::LENGTH
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&self.0);
    }
}

impl Decode for StartId {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        crate::canonical::decode_fixed::<{ Self::LENGTH }>(buf)
            .map(|(bytes, consumed)| (Self::from_bytes(bytes), consumed))
    }
}

/// Opens the bounded payment-close contest on one payment edge.
///
/// Either role may open. The opener reveals the edge's complete terms —
/// the kernel needs the omission bond and the two window widths, and a
/// close that could not name them would have to read policy the edge does
/// not store. It states the amount it is willing to settle at, which is
/// either a client-signed certificate it holds or nothing at all.
///
/// # The write-ahead cutoff
///
/// Before releasing this signature an endpoint closes its own certificate
/// gate and records the exact signed body: the opener must not still be
/// admitting (or issuing) certificates it is about to leave out. Retiring
/// a cutoff whose signature never landed is an endpoint's decision, taken
/// against a finalized view, and it belongs to the endpoint that took it;
/// no kernel rule reads it, so no kernel type states it.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PaymentCloseStart {
    payment_edge: EdgeId,
    terms: Terms,
    opener_role: Party,
    valid_from_height: u64,
    valid_through_height: u64,
    certificate: Option<(EarnedCertificate, PartyAuth)>,
    action: PartyAuth,
}

/// Presence byte for the optional certificate. Exactly zero or one:
/// absence encodes neither conditional field, so an absent certificate is
/// never an all-zero composite that could also be read as a present one.
const CERTIFICATE_ABSENT: u8 = 0;
const CERTIFICATE_PRESENT: u8 = 1;

impl PaymentCloseStart {
    /// Creates a close start.
    #[must_use]
    pub const fn new(
        payment_edge: EdgeId,
        terms: Terms,
        opener_role: Party,
        validity: (u64, u64),
        certificate: Option<(EarnedCertificate, PartyAuth)>,
        action: PartyAuth,
    ) -> Self {
        let (valid_from_height, valid_through_height) = validity;
        Self {
            payment_edge,
            terms,
            opener_role,
            valid_from_height,
            valid_through_height,
            certificate,
            action,
        }
    }

    /// Returns the payment edge this start contests.
    #[must_use]
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the revealed payment terms.
    #[must_use]
    pub const fn terms(&self) -> &Terms {
        &self.terms
    }

    /// Returns the role that signed this start.
    #[must_use]
    pub const fn opener_role(&self) -> Party {
        self.opener_role
    }

    /// Returns the first height this start may be included at.
    #[must_use]
    pub const fn valid_from_height(&self) -> u64 {
        self.valid_from_height
    }

    /// Returns the last height this start may be included at.
    #[must_use]
    pub const fn valid_through_height(&self) -> u64 {
        self.valid_through_height
    }

    /// Returns the certificate this start claims, and the client
    /// authorization over it, if any.
    #[must_use]
    pub const fn certificate(&self) -> Option<&(EarnedCertificate, PartyAuth)> {
        self.certificate.as_ref()
    }

    /// Returns the opener's authorization of this start.
    #[must_use]
    pub const fn action(&self) -> &PartyAuth {
        &self.action
    }

    /// Returns the digest authorized by the opener.
    #[must_use]
    pub fn digest(&self, network: NetworkId) -> PayloadHash {
        let terms = self.terms.hash();
        let earned = self.certificate.as_ref().map_or_else(
            || no_earned_digest(self.payment_edge, terms),
            |(certificate, _)| certificate.digest(network),
        );
        start_digest(
            network,
            self.payment_edge,
            terms,
            self.opener_role,
            (self.valid_from_height, self.valid_through_height),
            earned,
        )
    }

    /// Returns the deterministic cost of applying this start.
    ///
    /// Two slots — the payment edge and the pending slot it creates — and
    /// one signature check per signature actually carried.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        let proofs = match &self.certificate {
            Some(_) => 2,
            None => 1,
        };
        Cost::new(1, 2, proofs)
    }
}

/// Returns the digest a close opener signs.
#[must_use]
pub fn start_digest(
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    opener_role: Party,
    validity: (u64, u64),
    earned_digest_or_none: PayloadHash,
) -> PayloadHash {
    let mut hasher = SingleChunkHasher::new();
    start_preimage(
        &mut hasher,
        network,
        payment_edge,
        payment_terms_hash,
        opener_role,
        validity,
        earned_digest_or_none,
    );
    PayloadHash::from_bytes(hasher.finalize().into_bytes())
}

fn start_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    opener_role: Party,
    validity: (u64, u64),
    earned_digest_or_none: PayloadHash,
) {
    writer.write(crate::consts::WORK_START_PAYMENT_CLOSE);
    network.encode_to(writer);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
    opener_role.encode_to(writer);
    validity.0.encode_to(writer);
    validity.1.encode_to(writer);
    earned_digest_or_none.encode_to(writer);
}

const START_PREIMAGE_MAX: usize = crate::consts::WORK_START_PAYMENT_CLOSE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + Party::MAX_ENCODED_SIZE
    + 2 * u64::MAX_ENCODED_SIZE
    + PayloadHash::MAX_ENCODED_SIZE;

/// Returns the identifier of the contest `start_digest` opens at
/// `inclusion_height`.
#[must_use]
pub fn start_id(start_digest: PayloadHash, inclusion_height: u64) -> StartId {
    let mut hasher = SingleChunkHasher::new();
    start_id_preimage(&mut hasher, start_digest, inclusion_height);
    StartId::from_bytes(hasher.finalize().into_bytes())
}

fn start_id_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    start_digest: PayloadHash,
    inclusion_height: u64,
) {
    writer.write(crate::consts::WORK_START_PAYMENT_CLOSE_ID);
    start_digest.encode_to(writer);
    inclusion_height.encode_to(writer);
}

const START_ID_PREIMAGE_MAX: usize = crate::consts::WORK_START_PAYMENT_CLOSE_ID.len()
    + PayloadHash::MAX_ENCODED_SIZE
    + u64::MAX_ENCODED_SIZE;

impl Encode for PaymentCloseStart {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + EdgeId::MAX_ENCODED_SIZE
        + Terms::MAX_ENCODED_SIZE
        + Party::MAX_ENCODED_SIZE
        + 2 * u64::MAX_ENCODED_SIZE
        + u8::MAX_ENCODED_SIZE
        + EarnedCertificate::ENCODED_SIZE
        + 2 * PartyAuth::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        let certificate = match &self.certificate {
            Some((certificate, auth)) => certificate.encoded_size() + auth.encoded_size(),
            None => 0,
        };
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + EdgeId::MAX_ENCODED_SIZE
            + self.terms.encoded_size()
            + Party::MAX_ENCODED_SIZE
            + 2 * u64::MAX_ENCODED_SIZE
            + u8::MAX_ENCODED_SIZE
            + certificate
            + self.action.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PAYMENT_CLOSE_START);
        WORK_CLOSE_VERSION.encode_to(writer);
        self.payment_edge.encode_to(writer);
        self.terms.encode_to(writer);
        self.opener_role.encode_to(writer);
        self.valid_from_height.encode_to(writer);
        self.valid_through_height.encode_to(writer);
        match &self.certificate {
            Some((certificate, auth)) => {
                CERTIFICATE_PRESENT.encode_to(writer);
                certificate.encode_to(writer);
                auth.encode_to(writer);
            }
            None => CERTIFICATE_ABSENT.encode_to(writer),
        }
        self.action.encode_to(writer);
    }
}

impl Decode for PaymentCloseStart {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PAYMENT_CLOSE_START)?;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != WORK_CLOSE_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let payment_edge = decode_field(buf, &mut consumed)?;
        let terms = decode_field(buf, &mut consumed)?;
        let opener_role = decode_field(buf, &mut consumed)?;
        let valid_from_height = decode_field(buf, &mut consumed)?;
        let valid_through_height = decode_field(buf, &mut consumed)?;
        let certificate = match decode_field::<u8>(buf, &mut consumed)? {
            CERTIFICATE_ABSENT => None,
            CERTIFICATE_PRESENT => {
                let certificate = decode_field(buf, &mut consumed)?;
                let auth = decode_field(buf, &mut consumed)?;
                Some((certificate, auth))
            }
            tag => return Err(DecodeError::InvalidTag { tag }),
        };
        let action = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(
                payment_edge,
                terms,
                opener_role,
                (valid_from_height, valid_through_height),
                certificate,
                action,
            ),
            consumed,
        ))
    }
}

// ── Response ──────────────────────────────────────────────────────────

/// The provider's one bounded answer to an accepted close start.
///
/// Only the certificate's beneficiary may respond, exactly once, and only
/// with a strictly greater client-signed amount. It reveals no terms: the
/// pending record the start wrote already carries the funded omission
/// bond, so the answer needs nothing the chain does not already hold.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PaymentCloseResponse {
    payment_edge: EdgeId,
    start_id: StartId,
    responder_role: Party,
    certificate: EarnedCertificate,
    certificate_auth: PartyAuth,
    action: PartyAuth,
}

impl PaymentCloseResponse {
    /// Creates a close response.
    #[must_use]
    pub const fn new(
        payment_edge: EdgeId,
        start_id: StartId,
        responder_role: Party,
        certificate: (EarnedCertificate, PartyAuth),
        action: PartyAuth,
    ) -> Self {
        let (certificate, certificate_auth) = certificate;
        Self {
            payment_edge,
            start_id,
            responder_role,
            certificate,
            certificate_auth,
            action,
        }
    }

    /// Returns the payment edge this response answers on.
    #[must_use]
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the contest this response is bound to.
    #[must_use]
    pub const fn start_id(&self) -> StartId {
        self.start_id
    }

    /// Returns the role that signed this response.
    #[must_use]
    pub const fn responder_role(&self) -> Party {
        self.responder_role
    }

    /// Returns the certificate this response supplies.
    #[must_use]
    pub const fn certificate(&self) -> &EarnedCertificate {
        &self.certificate
    }

    /// Returns the client authorization over that certificate.
    #[must_use]
    pub const fn certificate_auth(&self) -> &PartyAuth {
        &self.certificate_auth
    }

    /// Returns the responder's authorization of this response.
    #[must_use]
    pub const fn action(&self) -> &PartyAuth {
        &self.action
    }

    /// Returns the deterministic cost of applying this response.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        Cost::new(1, 2, 2)
    }
}

/// Returns the digest a responder signs.
#[must_use]
pub fn response_digest(
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    start_id: StartId,
    responder_role: Party,
    earned_digest: PayloadHash,
) -> PayloadHash {
    let mut hasher = SingleChunkHasher::new();
    response_preimage(
        &mut hasher,
        network,
        payment_edge,
        payment_terms_hash,
        start_id,
        responder_role,
        earned_digest,
    );
    PayloadHash::from_bytes(hasher.finalize().into_bytes())
}

fn response_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    start_id: StartId,
    responder_role: Party,
    earned_digest: PayloadHash,
) {
    writer.write(crate::consts::WORK_RESPOND_PAYMENT_CLOSE);
    network.encode_to(writer);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
    start_id.encode_to(writer);
    responder_role.encode_to(writer);
    earned_digest.encode_to(writer);
}

const RESPONSE_PREIMAGE_MAX: usize = crate::consts::WORK_RESPOND_PAYMENT_CLOSE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + StartId::MAX_ENCODED_SIZE
    + Party::MAX_ENCODED_SIZE
    + PayloadHash::MAX_ENCODED_SIZE;

impl Encode for PaymentCloseResponse {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + EdgeId::MAX_ENCODED_SIZE
        + StartId::MAX_ENCODED_SIZE
        + Party::MAX_ENCODED_SIZE
        + EarnedCertificate::ENCODED_SIZE
        + 2 * PartyAuth::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE - 2 * PartyAuth::MAX_ENCODED_SIZE
            + self.certificate_auth.encoded_size()
            + self.action.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PAYMENT_CLOSE_RESPONSE);
        WORK_CLOSE_VERSION.encode_to(writer);
        self.payment_edge.encode_to(writer);
        self.start_id.encode_to(writer);
        self.responder_role.encode_to(writer);
        self.certificate.encode_to(writer);
        self.certificate_auth.encode_to(writer);
        self.action.encode_to(writer);
    }
}

impl Decode for PaymentCloseResponse {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PAYMENT_CLOSE_RESPONSE)?;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != WORK_CLOSE_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let payment_edge = decode_field(buf, &mut consumed)?;
        let start_id = decode_field(buf, &mut consumed)?;
        let responder_role = decode_field(buf, &mut consumed)?;
        let certificate = decode_field(buf, &mut consumed)?;
        let certificate_auth = decode_field(buf, &mut consumed)?;
        let action = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(
                payment_edge,
                start_id,
                responder_role,
                (certificate, certificate_auth),
                action,
            ),
            consumed,
        ))
    }
}

// ── The pending record ────────────────────────────────────────────────

/// The live state of one payment-close contest.
///
/// Everything a later Response, Adjudicated, or Freeze needs, and nothing
/// else: the deadline, the two amounts, the penalty the contest has
/// proved so far, and whether an owner has acted on it. It publishes no work count, no lane length, no
/// reservation total and no dependency root — the earned amount is
/// already revealed by the payout, and nothing else about the session has
/// to be.
///
/// It fits one [`RegistryChunk`], which is why every read and write of it
/// is a single charged slot.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct PendingPaymentClose {
    payment_edge: EdgeId,
    opener_role: Party,
    start_id: StartId,
    response_deadline: u64,
    start_cumulative: u64,
    final_cumulative: u64,
    responded: bool,
    penalty_due: bool,
    penalty_amount: u64,
    owner_signed: [bool; 2],
}

const FLAG_CLEAR: u8 = 0;
const FLAG_SET: u8 = 1;

impl PendingPaymentClose {
    /// Reconstructs the state written by an accepted start.
    ///
    /// This is the shared state transition used after kernel validation and
    /// when replaying authenticated finalized transactions. It does not
    /// validate signatures, funding, or inclusion; callers must establish
    /// acceptance first. Returns `None` for non-payment terms or overflow.
    #[must_use]
    pub fn from_accepted_start(
        network: NetworkId,
        height: u64,
        start: &PaymentCloseStart,
    ) -> Option<Self> {
        let crate::TermsProfile::WorkPayment(payment) = start.terms().profile() else {
            return None;
        };
        Some(Self::opened(
            start.payment_edge(),
            start.opener_role(),
            start_id(start.digest(network), height),
            height.checked_add(payment.omit_response_blocks)?,
            (
                start
                    .certificate()
                    .map_or(0, |(certificate, _)| certificate.earned_cumulative()),
                payment.omission_bond,
            ),
            start.action().is_owner(),
        ))
    }

    /// Applies an accepted response using the kernel's state transition.
    ///
    /// Call only after kernel validation or with an authenticated finalized
    /// response to this contest. This does not establish acceptance itself.
    #[must_use]
    pub const fn with_accepted_response(self, response: &PaymentCloseResponse) -> Self {
        self.responded_at(
            response.certificate().earned_cumulative(),
            response.action().is_owner(),
        )
    }

    /// Canonical encoded length, envelope included.
    pub const ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + EdgeId::MAX_ENCODED_SIZE
        + Party::MAX_ENCODED_SIZE
        + StartId::MAX_ENCODED_SIZE
        + 3 * u64::MAX_ENCODED_SIZE
        + 2 * u8::MAX_ENCODED_SIZE
        + u64::MAX_ENCODED_SIZE
        + 2 * u8::MAX_ENCODED_SIZE;

    /// Creates the record an accepted start writes.
    ///
    /// Both cumulative fields start at the amount the start claimed, so a
    /// response is an advance over the opener's own number rather than
    /// over a separately tracked floor. The omission bond is copied in
    /// here so a later response can apply the penalty without the terms
    /// being revealed a second time.
    #[must_use]
    pub(crate) const fn opened(
        payment_edge: EdgeId,
        opener_role: Party,
        start_id: StartId,
        response_deadline: u64,
        claim: (u64, u64),
        owner_signed: bool,
    ) -> Self {
        let owner_signed = match opener_role {
            Party::Maker => [owner_signed, false],
            Party::Taker => [false, owner_signed],
        };
        let (claimed, omission_bond) = claim;
        Self {
            payment_edge,
            opener_role,
            start_id,
            response_deadline,
            start_cumulative: claimed,
            final_cumulative: claimed,
            responded: false,
            penalty_due: false,
            penalty_amount: omission_bond,
            owner_signed,
        }
    }

    /// Returns the payment edge this contest settles.
    #[must_use]
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the role that opened the contest.
    #[must_use]
    pub const fn opener_role(&self) -> Party {
        self.opener_role
    }

    /// Returns the contest identifier a response must name.
    #[must_use]
    pub const fn start_id(&self) -> StartId {
        self.start_id
    }

    /// Returns the height at which the response window shuts.
    #[must_use]
    pub const fn response_deadline(&self) -> u64 {
        self.response_deadline
    }

    /// Returns the amount the opener claimed.
    #[must_use]
    pub const fn start_cumulative(&self) -> u64 {
        self.start_cumulative
    }

    /// Returns the amount the contest currently settles at.
    #[must_use]
    pub const fn final_cumulative(&self) -> u64 {
        self.final_cumulative
    }

    /// Returns true once the one legal response has landed.
    #[must_use]
    pub const fn responded(&self) -> bool {
        self.responded
    }

    /// Returns true once an understatement has been proved.
    #[must_use]
    pub const fn penalty_due(&self) -> bool {
        self.penalty_due
    }

    /// Returns the funded omission bond this contest can forfeit.
    #[must_use]
    pub const fn penalty_amount(&self) -> u64 {
        self.penalty_amount
    }

    /// Returns which parties acted as owner rather than signer in this contest.
    ///
    /// Ordered `[maker, taker]`, sticky, and read by both exits. Only the
    /// acting owner's payout loses delegation. A later freeze signed by
    /// that party's node cannot restore its delegation.
    #[must_use]
    pub const fn owner_signed(&self) -> [bool; 2] {
        self.owner_signed
    }

    /// Returns the penalty this contest actually pays: the funded bond
    /// when an understatement was proved, zero otherwise.
    #[must_use]
    pub const fn penalty(&self) -> u64 {
        if self.penalty_due {
            self.penalty_amount
        } else {
            0
        }
    }

    /// Returns this record advanced to `amount` by the one legal
    /// response.
    ///
    /// A client opener whose own later signature exceeds its start has
    /// contradicted itself, which is exactly the proved understatement
    /// the bond funds. A provider opener that is merely raised has proved
    /// nothing about the client.
    ///
    /// The first disjunct cannot fire on any record this runs on, and is
    /// kept for the same reason as [`Self::freeze_penalty`]'s. Nothing
    /// but this method ever sets `penalty_due`, this method also sets
    /// `responded`, and [`crate::tx::work::apply_response`] refuses a
    /// second response — so `penalty_due` is always clear on arrival. It
    /// is written anyway because it states the rule that belongs to the
    /// record — a proved penalty is never erased — rather than relying on
    /// the caller that happens to guarantee it. No test isolates it, and
    /// none claims to.
    #[must_use]
    pub(crate) const fn responded_at(self, amount: u64, owner_signed: bool) -> Self {
        Self {
            final_cumulative: amount,
            responded: true,
            penalty_due: self.penalty_due || matches!(self.opener_role, Party::Maker),
            owner_signed: [self.owner_signed[0], self.owner_signed[1] || owner_signed],
            ..self
        }
    }

    /// Returns whether a cooperative freeze at `earned` forfeits the
    /// bond.
    ///
    /// A freeze can never erase a penalty the contest already proved, and
    /// it cannot escape one it demonstrates itself: a client opener
    /// co-signing a higher amount than it started at has understated just
    /// as visibly as one caught by a response.
    ///
    /// The two disjuncts overlap completely on reachable state, and that
    /// is not an accident to be tidied away. `penalty_due` is only ever
    /// set by a response to a client opener, and a response strictly
    /// increases, so a freeze at or above the settled amount already
    /// exceeds that opener's claim. The first disjunct is therefore
    /// implied by the second today; it is kept because it states the
    /// rule that actually matters — a proved penalty is never erased —
    /// and the implication is a property of the response rule, not of
    /// this one.
    #[must_use]
    pub(crate) const fn freeze_penalty(&self, earned: u64) -> u64 {
        if self.penalty_due
            || (matches!(self.opener_role, Party::Maker) && earned > self.start_cumulative)
        {
            self.penalty_amount
        } else {
            0
        }
    }

    /// Returns the commitment an adjudicated close of this contest
    /// carries.
    #[must_use]
    pub fn contest_commitment(
        &self,
        network: NetworkId,
        payment_edge: EdgeId,
        payment_terms_hash: TermsHash,
    ) -> PaymentContestCommitment {
        let mut hasher = SingleChunkHasher::new();
        adjudicated_preimage(&mut hasher, network, payment_edge, payment_terms_hash, self);
        PaymentContestCommitment::from_bytes(hasher.finalize().into_bytes())
    }

    /// Returns this record packed into its single registry chunk.
    ///
    /// `None` is unreachable for a record of this fixed width — the
    /// encoding is 104 bytes and one chunk carries 120 — and is kept a
    /// rejection rather than a panic because this runs on the apply path.
    #[must_use]
    pub(crate) fn to_chunk(self) -> Option<RegistryChunk> {
        let mut buf = [0_u8; Self::ENCODED_SIZE];
        let written = self.write_to(&mut buf);
        RegistryChunk::split(
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            buf.get(..written)?,
            0,
        )
    }

    /// Reads the record a stored chunk holds.
    ///
    /// Every way a present chunk can fail to be this edge's record is a
    /// fault, never absence: a wrong-kind, partial, or noncanonical
    /// value is an invalid transaction, and reading it as "no contest is
    /// live" would hand a fresh start to whichever party corrupted it.
    fn from_chunk(chunk: RegistryChunk, payment_edge: EdgeId) -> Result<Self, PendingCloseFault> {
        // A pending record is one chunk by construction, and the length
        // check below is what decides that: `RegistryChunk` derives its
        // own count from its own length, so `value_len == ENCODED_SIZE`
        // already implies `chunk_count == 1`, which already implies
        // `chunk_index == 0`. The two are spelled out anyway because a
        // reader of this function should not have to know the chunk
        // decoder's derivation to trust the record it gets back — but
        // neither can be isolated by a test, and no test here claims to.
        if chunk.namespace() != RegistryNamespace::PaymentClose
            || chunk.record_tag() != RegistryRecordTag::PaymentPending
            || chunk.chunk_count() != 1
            || chunk.chunk_index() != 0
            || usize::from(chunk.value_len()) != Self::ENCODED_SIZE
        {
            return Err(PendingCloseFault::Shape);
        }
        let record = Self::decode_exact(chunk.data()).map_err(|_| PendingCloseFault::Body)?;
        if record.payment_edge != payment_edge {
            return Err(PendingCloseFault::Edge);
        }
        Ok(record)
    }
}

/// Returns the registry slot the pending record of `payment_edge` lives
/// in.
///
/// One derivation, used by the kernel transitions and by the host that
/// preloads the slot for them. A host that derived its own would preload
/// a slot the kernel never reads.
#[must_use]
pub fn pending_payment_close_slot(network: NetworkId, payment_edge: EdgeId) -> RegistryChunkId {
    RegistryChunkId::derive(
        network,
        RegistryNamespace::PaymentClose,
        payment_edge.to_bytes(),
        0,
    )
}

/// Reads the pending contest on `payment_edge` from the staged batch.
///
/// Exactly one charged slot read. A second slot is not consulted because
/// a pending record is a one-chunk value and its chunk says so: a stray
/// chunk at index one can never be part of it, and charging for a read
/// that can change no answer would price every close for a state that
/// cannot exist.
pub(crate) fn read_pending_close<B: Batch>(
    batch: &B,
    network: NetworkId,
    payment_edge: EdgeId,
) -> Result<Option<PendingPaymentClose>, PendingCloseFault> {
    match parse_pending_close(
        batch.registry_chunk(pending_payment_close_slot(network, payment_edge)),
        payment_edge,
    ) {
        PendingSlot::Absent => Ok(None),
        PendingSlot::Present(record) => Ok(Some(record)),
        PendingSlot::Faulty(fault) => Err(fault),
    }
}

/// Reads the contest on `payment_edge` out of whatever its derived slot
/// holds.
///
/// Pure, and public, because an endpoint deciding whether a channel may
/// admit new work asks exactly the question a close asks, and two
/// answers to it is one answer too many. Callers off the apply path
/// supply the chunk from wherever they read it;
/// [`pending_payment_close_slot`] is the one derivation of which slot
/// that is.
#[must_use]
pub fn parse_pending_close(chunk: Option<RegistryChunk>, payment_edge: EdgeId) -> PendingSlot {
    chunk.map_or(
        PendingSlot::Absent,
        |chunk| match PendingPaymentClose::from_chunk(chunk, payment_edge) {
            Ok(record) => PendingSlot::Present(record),
            Err(fault) => PendingSlot::Faulty(fault),
        },
    )
}

/// The contest-commitment preimage, field for field as §4.6 of the concurrency design
/// fixes it.
///
/// Two fields of the record are deliberately not here: `opener_role` and
/// `responded`. The commitment names the state a close settles, and what a
/// close does with that state is `final_cumulative + penalty`, paid to
/// destinations whose delegates `owner_signed` decides — every term of
/// which is committed above. Two records differing only in who
/// opened the contest, or only in whether the window was answered rather
/// than merely spent, pay out the same two coins, so a commitment that
/// separated them would name a difference the close cannot act on.
///
/// Nor is the omission a way past the guards those two fields drive. The
/// commitment is not a capability: the kernel recomputes it from the one
/// record stored for this edge and compares bytes, and the response
/// window is then decided from that same stored record. A close built
/// for an unresponded contest cannot borrow a responded one's window,
/// because a response also raises `final_cumulative` — strictly, or it
/// is refused — and that field is committed here.
fn adjudicated_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    record: &PendingPaymentClose,
) {
    writer.write(crate::consts::WORK_ADJUDICATED_PAYMENT_CLOSE);
    network.encode_to(writer);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
    record.start_id.encode_to(writer);
    record.response_deadline.encode_to(writer);
    record.start_cumulative.encode_to(writer);
    record.final_cumulative.encode_to(writer);
    flag(record.penalty_due).encode_to(writer);
    record.penalty_amount.encode_to(writer);
    flag(record.owner_signed[0]).encode_to(writer);
    flag(record.owner_signed[1]).encode_to(writer);
}

const ADJUDICATED_PREIMAGE_MAX: usize = crate::consts::WORK_ADJUDICATED_PAYMENT_CLOSE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + StartId::MAX_ENCODED_SIZE
    + 3 * u64::MAX_ENCODED_SIZE
    + u8::MAX_ENCODED_SIZE
    + u64::MAX_ENCODED_SIZE
    + 2 * u8::MAX_ENCODED_SIZE;

/// Returns the digest both parties sign to freeze a payment channel.
#[must_use]
pub fn freeze_digest(
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    earned: u64,
    validity: (u64, u64),
) -> PayloadHash {
    let mut hasher = SingleChunkHasher::new();
    freeze_preimage(
        &mut hasher,
        network,
        payment_edge,
        payment_terms_hash,
        earned,
        validity,
    );
    PayloadHash::from_bytes(hasher.finalize().into_bytes())
}

fn freeze_preimage<W: Writer + ?Sized>(
    writer: &mut W,
    network: NetworkId,
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    earned: u64,
    validity: (u64, u64),
) {
    writer.write(crate::consts::WORK_FREEZE_CLOSE);
    network.encode_to(writer);
    payment_edge.encode_to(writer);
    payment_terms_hash.encode_to(writer);
    settlement_commitment(network, payment_edge, payment_terms_hash, earned).encode_to(writer);
    validity.0.encode_to(writer);
    validity.1.encode_to(writer);
}

const FREEZE_PREIMAGE_MAX: usize = crate::consts::WORK_FREEZE_CLOSE.len()
    + NetworkId::MAX_ENCODED_SIZE
    + EdgeId::MAX_ENCODED_SIZE
    + TermsHash::MAX_ENCODED_SIZE
    + HASH_LENGTH
    + 2 * u64::MAX_ENCODED_SIZE;

/// Every preimage this module hands [`SingleChunkHasher`] must be
/// strictly under one Xet chunk. The hasher asserts past that bound, and
/// these all run on the apply path where an assert is a node halt rather
/// than a rejected transaction. Every term is a compile-time maximum, so
/// this is decided by the compiler and not by the values a caller passes.
macro_rules! assert_fits_one_chunk {
    ($($bound:ident),+ $(,)?) => {
        $(const _: () = assert!(
            $bound < hellas_xet::MIN_CHUNK_SIZE,
            "a work-payment hash preimage must fit one Xet chunk",
        );)+
    };
}

assert_fits_one_chunk!(
    EARNED_PREIMAGE_MAX,
    NO_EARNED_PREIMAGE_MAX,
    SETTLEMENT_PREIMAGE_MAX,
    START_PREIMAGE_MAX,
    START_ID_PREIMAGE_MAX,
    RESPONSE_PREIMAGE_MAX,
    ADJUDICATED_PREIMAGE_MAX,
    FREEZE_PREIMAGE_MAX,
);

const fn flag(value: bool) -> u8 {
    if value { FLAG_SET } else { FLAG_CLEAR }
}

fn decode_flag(buf: &[u8], consumed: &mut usize, field: &'static str) -> Result<bool, DecodeError> {
    match decode_field::<u8>(buf, consumed)? {
        FLAG_CLEAR => Ok(false),
        FLAG_SET => Ok(true),
        // Any other byte is a second spelling of one of these two
        // states, and a stored record with two spellings is a stored
        // record with two hashes.
        _ => Err(DecodeError::NonCanonical { field }),
    }
}

impl Encode for PendingPaymentClose {
    const MAX_ENCODED_SIZE: usize = Self::ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PAYMENT_CLOSE_PENDING);
        WORK_PENDING_VERSION.encode_to(writer);
        self.payment_edge.encode_to(writer);
        self.opener_role.encode_to(writer);
        self.start_id.encode_to(writer);
        self.response_deadline.encode_to(writer);
        self.start_cumulative.encode_to(writer);
        self.final_cumulative.encode_to(writer);
        flag(self.responded).encode_to(writer);
        flag(self.penalty_due).encode_to(writer);
        self.penalty_amount.encode_to(writer);
        flag(self.owner_signed[0]).encode_to(writer);
        flag(self.owner_signed[1]).encode_to(writer);
    }
}

impl Decode for PendingPaymentClose {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PAYMENT_CLOSE_PENDING)?;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != WORK_PENDING_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let payment_edge = decode_field(buf, &mut consumed)?;
        let opener_role = decode_field(buf, &mut consumed)?;
        let start_id = decode_field(buf, &mut consumed)?;
        let response_deadline = decode_field(buf, &mut consumed)?;
        let start_cumulative = decode_field(buf, &mut consumed)?;
        let final_cumulative = decode_field(buf, &mut consumed)?;
        let responded = decode_flag(buf, &mut consumed, "PendingPaymentClose.responded")?;
        let penalty_due = decode_flag(buf, &mut consumed, "PendingPaymentClose.penalty_due")?;
        let penalty_amount = decode_field(buf, &mut consumed)?;
        let owner_signed = [
            decode_flag(buf, &mut consumed, "PendingPaymentClose.maker_owner_signed")?,
            decode_flag(buf, &mut consumed, "PendingPaymentClose.taker_owner_signed")?,
        ];
        Ok((
            Self {
                payment_edge,
                opener_role,
                start_id,
                response_deadline,
                start_cumulative,
                final_cumulative,
                responded,
                penalty_due,
                penalty_amount,
                owner_signed,
            },
            consumed,
        ))
    }
}

/// What was found in the slot that holds one payment edge's contest.
///
/// Three states, not two. A malformed present chunk is its own answer
/// precisely because reading it as absence is the mistake this type
/// exists to make unrepresentable. Absence is a permission: it is what
/// lets a channel admit new work at all.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum PendingSlot {
    /// The derived slot is empty.
    Absent,
    /// The derived slot holds a readable record.
    Present(PendingPaymentClose),
    /// The derived slot holds something that is not this edge's record.
    Faulty(PendingCloseFault),
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    reason = "the preimage tests build fixed, statically bounded values"
)]
mod tests {
    use super::*;
    use crate::{
        context::{BlockHeight, Fees},
        network::MAX_NETWORK_ID_LENGTH,
        object::{Parties, PartyKeys},
        primitive::Key,
        tx::CloseKindSet,
    };

    /// Counts the bytes a preimage actually emits.
    ///
    /// The compile-time asserts above prove the declared bounds are
    /// under one Xet chunk. This proves the *encoders* stay inside those
    /// bounds — the two are different claims, and only the second would
    /// catch a field added to a preimage without its bound moving.
    struct CountingWriter(usize);

    impl Writer for CountingWriter {
        fn write(&mut self, bytes: &[u8]) {
            self.0 += bytes.len();
        }
    }

    fn count(build: impl FnOnce(&mut CountingWriter)) -> usize {
        let mut writer = CountingWriter(0);
        build(&mut writer);
        writer.0
    }

    /// The widest network id a deployment may carry, so each measured
    /// preimage is its own maximum rather than one sample of it.
    fn widest_network() -> NetworkId {
        let filled = [b'n'; MAX_NETWORK_ID_LENGTH];
        let Ok(id) = core::str::from_utf8(&filled) else {
            panic!("ascii is utf-8");
        };
        let Some(network) = NetworkId::new(id) else {
            panic!("the longest legal id is legal");
        };
        network
    }

    fn edge() -> EdgeId {
        EdgeId::from_bytes([0x11; EdgeId::LENGTH])
    }

    fn terms_hash() -> TermsHash {
        TermsHash::from_bytes([0x22; TermsHash::LENGTH])
    }

    fn sample_record() -> PendingPaymentClose {
        PendingPaymentClose::opened(
            edge(),
            Party::Maker,
            StartId::from_bytes([0x33; StartId::LENGTH]),
            77,
            (5, 2),
            false,
        )
    }

    /// Every preimage this module hands the hasher, measured at its
    /// widest, equals its declared bound and stays inside one Xet chunk.
    ///
    /// `SingleChunkHasher::update` asserts at `MIN_CHUNK_SIZE` and the
    /// kernel cannot unwind, so an overrun here is a node halt rather
    /// than a rejected transaction.
    #[test]
    fn every_hash_preimage_is_its_declared_width_and_fits_one_chunk() {
        let network = widest_network();
        let certificate = EarnedCertificate::new(edge(), terms_hash(), u64::MAX);
        let digest = PayloadHash::from_bytes([0x44; PayloadHash::LENGTH]);
        let record = sample_record();

        let measured = [
            (
                "earned",
                count(|w| earned_preimage(w, network, &certificate)),
                EARNED_PREIMAGE_MAX,
            ),
            (
                "no-earned",
                count(|w| no_earned_preimage(w, edge(), terms_hash())),
                NO_EARNED_PREIMAGE_MAX,
            ),
            (
                "settlement",
                count(|w| settlement_preimage(w, network, edge(), terms_hash(), u64::MAX)),
                SETTLEMENT_PREIMAGE_MAX,
            ),
            (
                "start",
                count(|w| {
                    start_preimage(
                        w,
                        network,
                        edge(),
                        terms_hash(),
                        Party::Taker,
                        (u64::MAX, u64::MAX),
                        digest,
                    );
                }),
                START_PREIMAGE_MAX,
            ),
            (
                "start-id",
                count(|w| start_id_preimage(w, digest, u64::MAX)),
                START_ID_PREIMAGE_MAX,
            ),
            (
                "response",
                count(|w| {
                    response_preimage(
                        w,
                        network,
                        edge(),
                        terms_hash(),
                        StartId::from_bytes([0x55; StartId::LENGTH]),
                        Party::Taker,
                        digest,
                    );
                }),
                RESPONSE_PREIMAGE_MAX,
            ),
            (
                "adjudicated",
                count(|w| adjudicated_preimage(w, network, edge(), terms_hash(), &record)),
                ADJUDICATED_PREIMAGE_MAX,
            ),
            (
                "freeze",
                count(|w| {
                    freeze_preimage(w, network, edge(), terms_hash(), u64::MAX, (u64::MAX, 0));
                }),
                FREEZE_PREIMAGE_MAX,
            ),
        ];

        for (name, actual, declared) in measured {
            assert_eq!(actual, declared, "{name} preimage width");
            assert!(
                actual < hellas_xet::MIN_CHUNK_SIZE,
                "{name} preimage reaches the single-chunk assert",
            );
        }
    }

    /// Asserts every digest in `digests` differs from every other.
    ///
    /// Each entry varies exactly one field of a common base, so a field
    /// that never reached the preimage collides with the base and is
    /// named here. Pairwise rather than base-versus-each: two fields
    /// that were swapped into each other's positions would both differ
    /// from the base and still be indistinguishable from each other.
    fn assert_all_distinct(digests: &[(&str, [u8; HASH_LENGTH])]) {
        let mut rest = digests;
        while let Some(((left_name, left), tail)) = rest.split_first() {
            for (right_name, right) in tail {
                assert_ne!(left, right, "{left_name} and {right_name} collide");
            }
            rest = tail;
        }
    }

    /// Every field the preimage carries moves the commitment.
    ///
    /// The commitment is what a close names to say which contest state it is
    /// settling, so a carried field that did not move it would be a
    /// field a racing submitter could change without invalidating the
    /// commitment. Each variant below moves exactly one field, which is what
    /// stops a neighbouring field's change from standing in for it.
    ///
    /// Not every field of the record is a field of the preimage:
    /// `opener_role` and `responded` are omitted by design, and
    /// [`adjudicated_preimage`] says why. This test is about what the
    /// preimage carries, not about what the record holds.
    #[test]
    fn every_field_in_the_contest_preimage_moves_the_commitment() {
        let network = widest_network();
        let base = sample_record();
        let commitment_of = |record: &PendingPaymentClose| {
            record
                .contest_commitment(network, edge(), terms_hash())
                .to_bytes()
        };

        let mut other_start = base;
        other_start.start_id = StartId::from_bytes([0x99; StartId::LENGTH]);
        let mut other_deadline = base;
        other_deadline.response_deadline = base.response_deadline + 1;
        let mut other_claim = base;
        other_claim.start_cumulative = base.start_cumulative + 1;
        let mut other_final = base;
        other_final.final_cumulative = base.final_cumulative + 1;
        let mut other_due = base;
        other_due.penalty_due = !base.penalty_due;
        let mut other_bond = base;
        other_bond.penalty_amount = base.penalty_amount + 1;
        let mut other_owner = base;
        other_owner.owner_signed[0] = !base.owner_signed[0];
        let mut other_taker_owner = base;
        other_taker_owner.owner_signed[1] = !base.owner_signed[1];

        assert_all_distinct(&[
            ("base", commitment_of(&base)),
            ("start_id", commitment_of(&other_start)),
            ("response_deadline", commitment_of(&other_deadline)),
            ("start_cumulative", commitment_of(&other_claim)),
            ("final_cumulative", commitment_of(&other_final)),
            ("penalty_due", commitment_of(&other_due)),
            ("penalty_amount", commitment_of(&other_bond)),
            ("maker_owner_signed", commitment_of(&other_owner)),
            ("taker_owner_signed", commitment_of(&other_taker_owner)),
        ]);

        // The edge and terms the commitment is derived against are the close's,
        // not the record's, and both are committed too.
        assert_all_distinct(&[
            ("base", commitment_of(&base)),
            (
                "payment_edge",
                base.contest_commitment(
                    network,
                    EdgeId::from_bytes([0x88; EdgeId::LENGTH]),
                    terms_hash(),
                )
                .to_bytes(),
            ),
            (
                "payment_terms_hash",
                base.contest_commitment(
                    network,
                    edge(),
                    TermsHash::from_bytes([0x88; TermsHash::LENGTH]),
                )
                .to_bytes(),
            ),
        ]);
    }

    fn other_edge() -> EdgeId {
        EdgeId::from_bytes([0x88; EdgeId::LENGTH])
    }

    fn other_terms() -> TermsHash {
        TermsHash::from_bytes([0x88; TermsHash::LENGTH])
    }

    /// Every field of the client's certificate digest is committed.
    #[test]
    fn every_certificate_digest_field_is_committed() {
        let network = widest_network();
        let other_edge = other_edge();
        let other_terms = other_terms();

        let certificate = |edge, terms, amount| {
            EarnedCertificate::new(edge, terms, amount)
                .digest(network)
                .to_bytes()
        };
        assert_all_distinct(&[
            ("base", certificate(edge(), terms_hash(), 5)),
            ("payment_edge", certificate(other_edge, terms_hash(), 5)),
            ("payment_terms_hash", certificate(edge(), other_terms, 5)),
            ("earned_cumulative", certificate(edge(), terms_hash(), 6)),
        ]);

        // The absent-certificate constant is not any certificate: a
        // start claiming nothing must not be re-readable as a start
        // claiming something.
        assert_ne!(
            no_earned_digest(edge(), terms_hash()).to_bytes(),
            certificate(edge(), terms_hash(), 0),
        );
        assert_all_distinct(&[
            ("base", no_earned_digest(edge(), terms_hash()).to_bytes()),
            (
                "payment_edge",
                no_earned_digest(other_edge, terms_hash()).to_bytes(),
            ),
            (
                "payment_terms_hash",
                no_earned_digest(edge(), other_terms).to_bytes(),
            ),
            (
                "swapped",
                no_earned_digest(
                    EdgeId::from_bytes(terms_hash().to_bytes()),
                    TermsHash::from_bytes(edge().to_bytes()),
                )
                .to_bytes(),
            ),
        ]);
    }

    /// Every field of the opener's start digest is committed.
    #[test]
    fn every_start_digest_field_is_committed() {
        let network = widest_network();
        let other_edge = other_edge();
        let other_terms = other_terms();
        let earned = PayloadHash::from_bytes([0x44; PayloadHash::LENGTH]);
        let other_earned = PayloadHash::from_bytes([0x45; PayloadHash::LENGTH]);

        let start_of = |edge, terms, role, validity, digest| {
            start_digest(network, edge, terms, role, validity, digest).to_bytes()
        };
        assert_all_distinct(&[
            (
                "base",
                start_of(edge(), terms_hash(), Party::Taker, (3, 9), earned),
            ),
            (
                "payment_edge",
                start_of(other_edge, terms_hash(), Party::Taker, (3, 9), earned),
            ),
            (
                "payment_terms_hash",
                start_of(edge(), other_terms, Party::Taker, (3, 9), earned),
            ),
            (
                "opener_role",
                start_of(edge(), terms_hash(), Party::Maker, (3, 9), earned),
            ),
            (
                "valid_from_height",
                start_of(edge(), terms_hash(), Party::Taker, (4, 9), earned),
            ),
            (
                "valid_through_height",
                start_of(edge(), terms_hash(), Party::Taker, (3, 8), earned),
            ),
            (
                "swapped bounds",
                start_of(edge(), terms_hash(), Party::Taker, (9, 3), earned),
            ),
            (
                "earned_digest",
                start_of(edge(), terms_hash(), Party::Taker, (3, 9), other_earned),
            ),
        ]);
    }

    /// Every field of the responder's digest is committed.
    #[test]
    fn every_response_digest_field_is_committed() {
        let network = widest_network();
        let other_edge = other_edge();
        let other_terms = other_terms();
        let earned = PayloadHash::from_bytes([0x44; PayloadHash::LENGTH]);
        let other_earned = PayloadHash::from_bytes([0x45; PayloadHash::LENGTH]);
        let start = StartId::from_bytes([0x33; StartId::LENGTH]);
        let other_start = StartId::from_bytes([0x34; StartId::LENGTH]);

        let response_of = |edge, terms, id, role, digest| {
            response_digest(network, edge, terms, id, role, digest).to_bytes()
        };
        assert_all_distinct(&[
            (
                "base",
                response_of(edge(), terms_hash(), start, Party::Taker, earned),
            ),
            (
                "payment_edge",
                response_of(other_edge, terms_hash(), start, Party::Taker, earned),
            ),
            (
                "payment_terms_hash",
                response_of(edge(), other_terms, start, Party::Taker, earned),
            ),
            (
                "start_id",
                response_of(edge(), terms_hash(), other_start, Party::Taker, earned),
            ),
            (
                "responder_role",
                response_of(edge(), terms_hash(), start, Party::Maker, earned),
            ),
            (
                "earned_digest",
                response_of(edge(), terms_hash(), start, Party::Taker, other_earned),
            ),
        ]);
    }

    /// Every field of the cooperative freeze digest is committed.
    #[test]
    fn every_freeze_digest_field_is_committed() {
        let network = widest_network();
        let other_edge = other_edge();
        let other_terms = other_terms();

        let freeze_of = |edge, terms, amount, validity| {
            freeze_digest(network, edge, terms, amount, validity).to_bytes()
        };
        assert_all_distinct(&[
            ("base", freeze_of(edge(), terms_hash(), 4, (3, 9))),
            (
                "payment_edge",
                freeze_of(other_edge, terms_hash(), 4, (3, 9)),
            ),
            (
                "payment_terms_hash",
                freeze_of(edge(), other_terms, 4, (3, 9)),
            ),
            ("earned", freeze_of(edge(), terms_hash(), 5, (3, 9))),
            (
                "valid_from_height",
                freeze_of(edge(), terms_hash(), 4, (4, 9)),
            ),
            (
                "valid_through_height",
                freeze_of(edge(), terms_hash(), 4, (3, 8)),
            ),
            ("swapped bounds", freeze_of(edge(), terms_hash(), 4, (9, 3))),
        ]);
    }

    /// Two same-typed neighbours are not interchangeable values.
    ///
    /// A preimage that fed a pair through one order-blind step — a sum,
    /// an unordered pair, a set — would return the same digest with the
    /// two exchanged. Each case below exchanges two values and requires
    /// the digest to move, which rules that out.
    ///
    /// It does not pin the field order, and cannot: both digests here
    /// come from the same encoder, so an encoder whose fields changed
    /// places moves both sides together and stays invisible. The hex
    /// goldens in `tests/canonical.rs` are what fix the order, against
    /// bytes that no edit to this file can move.
    #[test]
    fn adjacent_same_typed_fields_are_distinguished() {
        let network = widest_network();

        // The two validity bounds of a start.
        assert_ne!(
            start_digest(
                network,
                edge(),
                terms_hash(),
                Party::Taker,
                (3, 9),
                PayloadHash::from_bytes([0; 32])
            ),
            start_digest(
                network,
                edge(),
                terms_hash(),
                Party::Taker,
                (9, 3),
                PayloadHash::from_bytes([0; 32])
            ),
        );
        // The two validity bounds of a freeze.
        assert_ne!(
            freeze_digest(network, edge(), terms_hash(), 4, (3, 9)),
            freeze_digest(network, edge(), terms_hash(), 4, (9, 3)),
        );
        // The edge and the terms hash are both 32 bytes and adjacent.
        let swapped = TermsHash::from_bytes(edge().to_bytes());
        let as_edge = EdgeId::from_bytes(terms_hash().to_bytes());
        assert_ne!(
            no_earned_digest(edge(), terms_hash()),
            no_earned_digest(as_edge, swapped),
        );
        // The commitment's three amounts: deadline, start, and final.
        let record = sample_record();
        let advanced = record.responded_at(9, false);
        assert_ne!(
            record.contest_commitment(network, edge(), terms_hash()),
            advanced.contest_commitment(network, edge(), terms_hash()),
        );
    }

    /// The record is exactly one chunk wide, which is what makes every
    /// read and write of a contest a single charged slot.
    #[test]
    fn the_pending_record_is_one_registry_chunk() {
        assert_eq!(PendingPaymentClose::ENCODED_SIZE, 104);
        assert_eq!(
            PendingPaymentClose::ENCODED_SIZE.min(crate::consts::REGISTRY_CHUNK_DATA_CAPACITY),
            PendingPaymentClose::ENCODED_SIZE,
            "the record has to fit one chunk's data capacity",
        );

        let record = sample_record();
        let Some(chunk) = record.to_chunk() else {
            panic!("the record splits into one chunk");
        };
        assert_eq!(chunk.chunk_count(), 1);
        assert_eq!(chunk.chunk_index(), 0);
        assert_eq!(
            usize::from(chunk.value_len()),
            PendingPaymentClose::ENCODED_SIZE,
        );
        assert_eq!(chunk.namespace(), RegistryNamespace::PaymentClose);
        assert_eq!(chunk.record_tag(), RegistryRecordTag::PaymentPending);

        let mut buf = [0_u8; PendingPaymentClose::ENCODED_SIZE];
        let written = record.write_to(&mut buf);
        assert_eq!(written, PendingPaymentClose::ENCODED_SIZE);
        assert_eq!(chunk.data(), &buf[..written]);
        assert_eq!(PendingPaymentClose::decode_exact(chunk.data()), Ok(record));
    }

    /// The one answer both a close and an endpoint's readiness gate
    /// take, over every shape the derived slot can be in.
    ///
    /// Each case differs from the accepted one in exactly one way, so no
    /// case is satisfied by a neighbour's reason for failing.
    #[test]
    fn parse_pending_close_separates_absence_from_every_fault() {
        let record = sample_record();
        let Some(chunk) = record.to_chunk() else {
            panic!("the record splits into one chunk");
        };

        assert_eq!(parse_pending_close(None, edge()), PendingSlot::Absent);
        assert_eq!(
            parse_pending_close(Some(chunk), edge()),
            PendingSlot::Present(record),
        );

        // A whole readable record, over another payment edge.
        assert_eq!(
            parse_pending_close(Some(chunk), EdgeId::from_bytes([0x99; EdgeId::LENGTH])),
            PendingSlot::Faulty(PendingCloseFault::Edge),
        );

        // The exact bytes of this record, keyed under the other live
        // namespace. Only the namespace moves.
        let mut buf = [0_u8; PendingPaymentClose::ENCODED_SIZE];
        let written = record.write_to(&mut buf);
        let Some(value) = buf.get(..written) else {
            panic!("the record writes its own width");
        };
        let Some(misfiled) = RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::PaymentPending,
            value,
            0,
        ) else {
            panic!("a fixed-width value always splits");
        };
        assert_eq!(
            parse_pending_close(Some(misfiled), edge()),
            PendingSlot::Faulty(PendingCloseFault::Shape),
        );

        // Right namespace, right kind, right width: only the body's
        // version byte moves, which is what separates `Body` from
        // `Shape`.
        let mut corrupt = buf;
        let version = crate::canonical::ENVELOPE_SIZE;
        let Some(byte) = corrupt.get_mut(version) else {
            panic!("the version byte follows the envelope");
        };
        assert_eq!(*byte, WORK_PENDING_VERSION);
        *byte = WORK_PENDING_VERSION.wrapping_add(1);
        let Some(corrupt_chunk) = RegistryChunk::split(
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            &corrupt,
            0,
        ) else {
            panic!("a fixed-width value always splits");
        };
        assert_eq!(
            parse_pending_close(Some(corrupt_chunk), edge()),
            PendingSlot::Faulty(PendingCloseFault::Body),
        );
    }

    /// The three boolean fields have exactly two spellings each. A third
    /// byte would give one stored state two encodings, and therefore two
    /// adjudicated commitments.
    #[test]
    fn record_flags_decode_only_as_zero_or_one() {
        // Offsets of `responded`, `penalty_due` and `owner_signed` inside
        // the body.
        const RESPONDED: usize = PendingPaymentClose::ENCODED_SIZE - 12;
        const PENALTY_DUE: usize = PendingPaymentClose::ENCODED_SIZE - 11;
        const OWNER_SIGNED: usize = PendingPaymentClose::ENCODED_SIZE - 2;
        const TAKER_OWNER_SIGNED: usize = PendingPaymentClose::ENCODED_SIZE - 1;

        let mut buf = [0_u8; PendingPaymentClose::ENCODED_SIZE];
        let written = sample_record().write_to(&mut buf);
        assert_eq!(buf[RESPONDED], 0);
        assert_eq!(buf[PENALTY_DUE], 0);
        assert_eq!(buf[OWNER_SIGNED], 0);

        for (offset, field) in [
            (RESPONDED, "PendingPaymentClose.responded"),
            (PENALTY_DUE, "PendingPaymentClose.penalty_due"),
            (OWNER_SIGNED, "PendingPaymentClose.maker_owner_signed"),
            (TAKER_OWNER_SIGNED, "PendingPaymentClose.taker_owner_signed"),
        ] {
            let mut corrupt = buf;
            corrupt[offset] = 2;
            assert_eq!(
                PendingPaymentClose::decode_exact(&corrupt[..written]),
                Err(DecodeError::NonCanonical { field }),
            );
            // Both legal spellings still decode.
            for value in [0, 1] {
                let mut legal = buf;
                legal[offset] = value;
                assert!(PendingPaymentClose::decode_exact(&legal[..written]).is_ok());
            }
        }
    }

    /// Capacity is the smaller close route less the funded bond, and the
    /// two routes differ only by the proof units they verify.
    #[test]
    fn capacity_is_the_cheaper_route_less_the_bond() {
        let parties = Parties::new(
            PartyKeys::sole(Key::from_bytes([1; Key::LENGTH])),
            PartyKeys::sole(Key::from_bytes([2; Key::LENGTH])),
        );
        // 110 funded, no open or lifetime fee, 10 reserved: principal
        // 100 with a 10-unit reserve, priced at one per slot and proof.
        let fees = Fees::new(0, 1, 1, 0);
        let Ok(edge) = Edge::open(
            110,
            parties,
            terms_hash(),
            (0, 0, 10, fees),
            BlockHeight::new(50),
            CloseKindSet::WORK_PAYMENT,
        ) else {
            panic!("the fixture edge opens");
        };

        // Freeze verifies two signatures, Adjudicated none, and both
        // touch four slots: 100 + 10 − (4 + 2) and 100 + 10 − (4 + 1).
        assert_eq!(
            edge.close_value(work_payment_close_cost(CloseKind::Freeze)),
            Some(104),
        );
        assert_eq!(
            edge.close_value(work_payment_close_cost(CloseKind::Adjudicated)),
            Some(105),
        );
        assert_eq!(close_route_minimum(&edge), Some(104));
        assert_eq!(payment_capacity(&edge, 4), Some(100));
        assert_eq!(payment_capacity(&edge, 104), Some(0));
        assert_eq!(payment_capacity(&edge, 105), None);
    }
}
