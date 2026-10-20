//! Close witnesses.
//!
//! A [`Proof`] is the kernel-visible *shape* of why an edge should
//! close. Each variant maps to exactly one validation kind: `Mutual` and
//! `Freeze` and owner-signed `Timeout` → [`crate::SigVerifier`]; unsigned
//! `Timeout` and `Adjudicated` →
//! kernel inline structural checks against committed terms and staged
//! registry state. No close consults an external verifier.
//!
//! Abstract counterpart: `models/types.qnt::Proof` (witness ADT) and
//! `models/verifier.qnt` (`proofOk`, `payoutsBound`). The Quint module
//! treats these as pure predicates over opaque verifiers; the kernel
//! defers the same checks by routing each variant to the matching
//! verifier impl (or to its own inline check for Timeout).

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::HASH_LENGTH,
    context::Cost,
    terms::Terms,
    tx::PartyAuth,
};

// Tag numbers are fixed consensus assignments, not positions. 2 and 5
// were the external-violation and work-stake-mutual closes; both are
// deleted, and both bytes are ordinary rejections with no promise
// attached.
const MUTUAL_TAG: u8 = 0;
const TIMEOUT_TAG: u8 = 1;
const FREEZE_TAG: u8 = 3;
const ADJUDICATED_TAG: u8 = 4;

/// Universal close witness kind.
///
/// The tag numbers are consensus assignments: they are the [`Proof`]
/// variant numbers and, as bit positions, the membership bits of a
/// [`CloseKindSet`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum CloseKind {
    /// Cooperative close agreed by both parties.
    Mutual,

    /// Timeout close under the committed terms.
    Timeout,

    /// Cooperative close of a work-payment channel at a jointly signed
    /// settlement amount.
    Freeze,

    /// Unilateral close of a work-payment channel decided by the staged
    /// close contest rather than by a fresh bilateral signature.
    Adjudicated,
}

impl CloseKind {
    /// Every close kind. [`CloseKindSet`] members and the resource
    /// bounds that must hold for *every* close path enumerate this, so
    /// a kind that is absent here is a kind nothing checks.
    pub const ALL: [Self; 4] = [Self::Mutual, Self::Timeout, Self::Freeze, Self::Adjudicated];

    /// Returns the canonical one-byte close witness tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Mutual => MUTUAL_TAG,
            Self::Timeout => TIMEOUT_TAG,
            Self::Freeze => FREEZE_TAG,
            Self::Adjudicated => ADJUDICATED_TAG,
        }
    }

    pub(crate) const fn proofs(self) -> u64 {
        match self {
            Self::Timeout | Self::Adjudicated => 1,
            Self::Mutual | Self::Freeze => 2,
        }
    }

    const fn bit(self) -> u8 {
        1 << self.tag()
    }
}

/// Committed set of close kinds an edge admits.
///
/// Derived from the open terms (each [`crate::Terms`] shape fixes its
/// set structurally) and persisted on the [`crate::Edge`], so every
/// close — including `Mutual`, which reveals no terms body — is checked
/// against the committed policy. Every set the kernel constructs leaves
/// its edge at least one exit that no counterparty can withhold; which
/// exit that is depends on the shape.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct CloseKindSet(u8);

impl CloseKindSet {
    /// Basic terms: cooperative or timeout close.
    pub(crate) const BASIC: Self = Self::empty()
        .with(CloseKind::Mutual)
        .with(CloseKind::Timeout);

    /// Work-stake bond: `Timeout` alone. There is no cooperative exit,
    /// so the provider cannot co-sign its way out from under a lease,
    /// and no terminal bond proof exists to admit anything else.
    pub(crate) const WORK_STAKE_BOND: Self = Self::empty().with(CloseKind::Timeout);

    /// Work payment: cooperative `Freeze` or contested `Adjudicated`.
    /// Deliberately no `Timeout` — see the decoder below.
    pub(crate) const WORK_PAYMENT: Self = Self::empty()
        .with(CloseKind::Freeze)
        .with(CloseKind::Adjudicated);

    /// The exact sets an edge may carry, one per terms shape.
    ///
    /// One per shape and no more, so this table is exactly what
    /// [`crate::Terms::allowed_closes`] can return.
    const PERMITTED: [Self; 3] = [Self::BASIC, Self::WORK_STAKE_BOND, Self::WORK_PAYMENT];
}

/// A response reveals no terms, so [`crate::tx::work::apply_response`]
/// identifies a payment channel by the one exit only a payment channel
/// commits: `Adjudicated`. That is an inference about this table, so the
/// table is what checks it — a later set that admitted an adjudicated
/// close would otherwise make responses legal on an edge that is not a
/// payment channel, silently and with no test to notice.
///
/// The destructuring is the load-bearing part: a fourth permitted set
/// stops compiling here, which is the point at which someone has to
/// decide what it means rather than discover it later.
const _: () = {
    let [basic, work_stake_bond, work_payment] = CloseKindSet::PERMITTED;
    assert!(
        !basic.contains(CloseKind::Adjudicated)
            && !work_stake_bond.contains(CloseKind::Adjudicated),
        "only a work-payment edge may commit an adjudicated close",
    );
    assert!(
        work_payment.contains(CloseKind::Adjudicated),
        "the work-payment set is what that inference reads",
    );
};

impl CloseKindSet {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns this set with `kind` added.
    #[must_use]
    pub const fn with(self, kind: CloseKind) -> Self {
        Self(self.0 | kind.bit())
    }

    /// Returns true when `kind` is a member of this set.
    #[must_use]
    pub const fn contains(self, kind: CloseKind) -> bool {
        self.0 & kind.bit() != 0
    }
}

impl Encode for CloseKindSet {
    const MAX_ENCODED_SIZE: usize = u8::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.0.encode_to(writer);
    }
}

impl Decode for CloseKindSet {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let bits = decode_field::<u8>(buf, &mut consumed)?;
        let set = Self(bits);
        // Only the sets the kernel itself constructs decode: anything
        // else is corrupt state, not data. This replaced a blanket
        // "every set must contain Timeout" rule, and the amendment is
        // deliberate — do not restore it. Work payment has no Timeout
        // on purpose: its horizon is an admission deadline, and a fixed
        // refund payable after the provider has earned against the
        // channel would pay the wrong party. Freeze and Adjudicated are
        // its exits, and Adjudicated needs no counterparty.
        if !Self::PERMITTED.contains(&set) {
            return Err(DecodeError::InvalidTag { tag: bits });
        }
        Ok((set, consumed))
    }
}

/// Commitment to the staged close contest an adjudicated close settles.
///
/// Not a verifier input and not a capability: the kernel recomputes
/// these bytes from the edge and the live pending record and compares
/// them. It is carried so the transaction names exactly the contest
/// state it expects to settle, and a submitter racing a response
/// cannot pay out the wrong one.
///
/// Encoded as its raw bytes. There is no standalone envelope, because
/// the value never appears outside the one proof body that carries it.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct PaymentContestCommitment([u8; Self::LENGTH]);

impl PaymentContestCommitment {
    /// Encoded length of a contest commitment.
    pub const LENGTH: usize = HASH_LENGTH;

    /// Creates a contest commitment from its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the commitment bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; Self::LENGTH] {
        self.0
    }

    /// Borrows the commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl Encode for PaymentContestCommitment {
    const MAX_ENCODED_SIZE: usize = <[u8; Self::LENGTH] as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.0.encode_to(writer);
    }
}

impl Decode for PaymentContestCommitment {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let bytes = decode_field(buf, &mut consumed)?;
        Ok((Self::from_bytes(bytes), consumed))
    }
}

/// Bounded close witness.
///
/// Each variant maps to one check: `Mutual` and `Freeze` are checked by
/// [`crate::SigVerifier`], as is a timeout's optional owner witness.
/// Unsigned timeout and adjudicated closes use structural kernel checks.
#[allow(
    clippy::large_enum_variant,
    reason = "Mutual auth is stored inline so the no-alloc kernel can verify WebAuthn bytes directly"
)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Proof {
    /// Cooperative close authorized by both edge parties. The authorized
    /// payload is `Tx::payload_hash(edge_id, Mutual, edge.terms(),
    /// payouts)`; the terms commitment is read from the edge itself, so
    /// no terms reveal is needed here.
    Mutual {
        /// Maker authorization.
        maker: PartyAuth,
        /// Taker authorization.
        taker: PartyAuth,
    },

    /// Timeout close under committed terms.
    Timeout {
        /// Concrete terms revealed to check the timeout.
        terms: Terms,
        /// Optional bond-owner authorization to reclaim undelegated stake.
        owner: Option<PartyAuth>,
    },

    /// Cooperative close of a work-payment channel at a jointly signed
    /// settlement amount.
    ///
    /// Carries no terms: the amount, not the policy, is what the parties
    /// are agreeing to, and the edge already commits the policy. The
    /// signed height interval bounds how long the agreement stays
    /// spendable, which is what keeps an old session's freeze from
    /// settling a channel that has moved on.
    Freeze {
        /// Cumulative amount both parties agree the provider earned.
        earned: u64,
        /// First height this freeze may be included at.
        valid_from_height: u64,
        /// Last height this freeze may be included at.
        valid_through_height: u64,
        /// Client (maker) authorization over the freeze digest.
        maker: PartyAuth,
        /// Provider (taker) authorization over the freeze digest.
        taker: PartyAuth,
    },

    /// Unilateral close of a work-payment channel at the amount its
    /// staged close contest ended on.
    ///
    /// The commitment is not verified by any external verifier: the
    /// kernel recomputes it from the edge and the live pending record
    /// and compares bytes.
    Adjudicated {
        /// Commitment to the contest state this close settles.
        contest_commitment: PaymentContestCommitment,
    },
}

impl Proof {
    /// Creates a cooperative close witness.
    #[must_use]
    pub const fn mutual(maker: PartyAuth, taker: PartyAuth) -> Self {
        Self::Mutual { maker, taker }
    }

    /// Creates a timeout close witness.
    #[must_use]
    pub const fn timeout(terms: Terms, owner: Option<PartyAuth>) -> Self {
        Self::Timeout { terms, owner }
    }

    /// Creates a cooperative work-payment freeze witness.
    #[must_use]
    pub const fn freeze(
        earned: u64,
        validity: (u64, u64),
        maker: PartyAuth,
        taker: PartyAuth,
    ) -> Self {
        let (valid_from_height, valid_through_height) = validity;
        Self::Freeze {
            earned,
            valid_from_height,
            valid_through_height,
            maker,
            taker,
        }
    }

    /// Creates an adjudicated work-payment close witness.
    #[must_use]
    pub const fn adjudicated(contest_commitment: PaymentContestCommitment) -> Self {
        Self::Adjudicated { contest_commitment }
    }

    /// Returns the close witness kind.
    #[must_use]
    pub const fn kind(&self) -> CloseKind {
        match self {
            Self::Mutual { .. } => CloseKind::Mutual,
            Self::Timeout { .. } => CloseKind::Timeout,
            Self::Freeze { .. } => CloseKind::Freeze,
            Self::Adjudicated { .. } => CloseKind::Adjudicated,
        }
    }

    /// Returns the deterministic resource cost of checking this proof.
    #[must_use]
    pub const fn cost(&self) -> Cost {
        Cost::new(0, 0, self.kind().proofs())
    }
}

/// Body bytes of the widest [`Proof`] variant.
const MAX_PROOF_BODY: usize = {
    let mut max = 2 * PartyAuth::MAX_ENCODED_SIZE;
    if Terms::MAX_ENCODED_SIZE + <Option<PartyAuth>>::MAX_ENCODED_SIZE > max {
        max = Terms::MAX_ENCODED_SIZE + <Option<PartyAuth>>::MAX_ENCODED_SIZE;
    }
    if FREEZE_BODY_SIZE > max {
        max = FREEZE_BODY_SIZE;
    }
    if PaymentContestCommitment::MAX_ENCODED_SIZE > max {
        max = PaymentContestCommitment::MAX_ENCODED_SIZE;
    }
    max
};

const FREEZE_BODY_SIZE: usize = 3 * u64::MAX_ENCODED_SIZE + 2 * PartyAuth::MAX_ENCODED_SIZE;

impl Encode for Proof {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + u8::MAX_ENCODED_SIZE + MAX_PROOF_BODY;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE
            + u8::MAX_ENCODED_SIZE
            + match self {
                Self::Mutual { maker, taker } => maker.encoded_size() + taker.encoded_size(),
                Self::Timeout { terms, owner } => terms.encoded_size() + owner.encoded_size(),
                Self::Freeze { maker, taker, .. } => {
                    3 * u64::MAX_ENCODED_SIZE + maker.encoded_size() + taker.encoded_size()
                }
                Self::Adjudicated { contest_commitment } => contest_commitment.encoded_size(),
            }
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PROOF);
        match self {
            Self::Mutual { maker, taker } => {
                MUTUAL_TAG.encode_to(writer);
                maker.encode_to(writer);
                taker.encode_to(writer);
            }
            Self::Timeout { terms, owner } => {
                TIMEOUT_TAG.encode_to(writer);
                terms.encode_to(writer);
                owner.encode_to(writer);
            }
            Self::Freeze {
                earned,
                valid_from_height,
                valid_through_height,
                maker,
                taker,
            } => {
                FREEZE_TAG.encode_to(writer);
                earned.encode_to(writer);
                valid_from_height.encode_to(writer);
                valid_through_height.encode_to(writer);
                maker.encode_to(writer);
                taker.encode_to(writer);
            }
            Self::Adjudicated { contest_commitment } => {
                ADJUDICATED_TAG.encode_to(writer);
                contest_commitment.encode_to(writer);
            }
        }
    }
}

impl Decode for Proof {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PROOF)?;
        let variant = decode_field::<u8>(buf, &mut consumed)?;
        match variant {
            MUTUAL_TAG => {
                let maker = decode_field(buf, &mut consumed)?;
                let taker = decode_field(buf, &mut consumed)?;
                Ok((Self::mutual(maker, taker), consumed))
            }
            TIMEOUT_TAG => {
                let terms = decode_field(buf, &mut consumed)?;
                let owner = decode_field(buf, &mut consumed)?;
                Ok((Self::timeout(terms, owner), consumed))
            }
            FREEZE_TAG => {
                let earned = decode_field(buf, &mut consumed)?;
                let valid_from_height = decode_field(buf, &mut consumed)?;
                let valid_through_height = decode_field(buf, &mut consumed)?;
                let maker = decode_field(buf, &mut consumed)?;
                let taker = decode_field(buf, &mut consumed)?;
                Ok((
                    Self::freeze(
                        earned,
                        (valid_from_height, valid_through_height),
                        maker,
                        taker,
                    ),
                    consumed,
                ))
            }
            ADJUDICATED_TAG => {
                let contest_commitment = decode_field(buf, &mut consumed)?;
                Ok((Self::adjudicated(contest_commitment), consumed))
            }
            tag => Err(DecodeError::InvalidTag { tag }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, reason = "test constants are in-bounds")]
mod tests {
    use super::*;

    /// Consensus assignments. A close kind's tag is its `Proof` variant
    /// number and its set bit position; all three move together or the
    /// wire breaks. Tags are not positions: 2 and 5 were deleted with
    /// their subjects and are not reassigned.
    #[test]
    fn close_kind_tags_are_the_assigned_numbers() {
        assert_eq!(
            CloseKind::ALL.map(CloseKind::tag),
            [MUTUAL_TAG, TIMEOUT_TAG, FREEZE_TAG, ADJUDICATED_TAG],
        );
        assert_eq!(CloseKind::ALL.map(CloseKind::tag), [0, 1, 3, 4]);
    }

    #[test]
    fn permitted_sets_are_the_assigned_bit_patterns() {
        assert_eq!(CloseKindSet::BASIC.0, 0b000_011);
        assert_eq!(CloseKindSet::WORK_STAKE_BOND.0, 0b000_010);
        assert_eq!(CloseKindSet::WORK_PAYMENT.0, 0b011_000);
        // The empty pattern belongs to no shape, so the decoder refuses
        // it like any other unassigned byte.
        assert!(CloseKindSet::decode(&[0b000_000]).is_err());
        // Bits 2 and 5 carried the deleted external-violation and
        // work-stake-mutual closes. Setting either on an otherwise
        // permitted set rejects: they are invalid, not reserved.
        assert!(CloseKindSet::decode(&[0b000_111]).is_err());
        assert!(CloseKindSet::decode(&[0b100_010]).is_err());
    }

    /// The whitelist is exact: every other byte, including supersets of
    /// a permitted set and every unassigned bit, is refused.
    #[test]
    fn only_the_permitted_patterns_decode() {
        for bits in 0..=u8::MAX {
            let permitted = CloseKindSet::PERMITTED.iter().any(|set| set.0 == bits);
            let decoded = CloseKindSet::decode(&[bits]);
            assert_eq!(
                decoded.is_ok(),
                permitted,
                "close-kind set {bits:#010b} decoded as {decoded:?}",
            );
            if let Ok((set, consumed)) = decoded {
                assert_eq!(set.0, bits);
                assert_eq!(consumed, CloseKindSet::MAX_ENCODED_SIZE);
            }
        }
    }

    /// Timeout survives as the unilateral exit of every shape that has
    /// no other one. Work payment is the deliberate exception: its
    /// `Adjudicated` exit needs no counterparty either.
    #[test]
    fn every_permitted_set_keeps_an_exit_that_needs_no_counterparty() {
        for set in [CloseKindSet::BASIC, CloseKindSet::WORK_STAKE_BOND] {
            assert!(set.contains(CloseKind::Timeout));
        }
        assert!(!CloseKindSet::WORK_PAYMENT.contains(CloseKind::Timeout));
        assert!(CloseKindSet::WORK_PAYMENT.contains(CloseKind::Adjudicated));
    }
}
