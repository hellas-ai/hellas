//! Kernel error vocabulary.

use crate::primitive::{CoinId, EdgeId};
use crate::registry::{RegistryChunkId, RegistryDiffError};

/// Public kernel result type.
pub type KernelResult<T, E = ApplyError> = core::result::Result<T, E>;

/// Error returned when an ordered operation batch fails.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct BatchError {
    index: usize,
    source: ApplyError,
}

impl BatchError {
    pub(crate) const fn new(index: usize, source: ApplyError) -> Self {
        Self { index, source }
    }

    /// Returns the index of the failed operation.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the operation error.
    #[must_use]
    pub const fn source(self) -> ApplyError {
        self.source
    }
}

/// Reason an insert into a [`crate::Batch`] failed.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InsertError {
    /// The target slot is already occupied.
    Exists,

    /// The store cannot accept the requested identifier.
    Unavailable,
}

/// Error returned when a [`crate::Tx`] cannot be applied.
///
/// Most variants describe ordinary user-input rejections — bad funding,
/// unknown ids, mismatched payouts. The [`Self::CoinChanged`],
/// [`Self::EdgeChanged`], and fold-phase [`Self::MissingCoin`] /
/// [`Self::MissingEdge`] paths instead signal a [`crate::Batch`] contract
/// violation: the kernel reads a slot during validation, then the same
/// slot returns different bytes (or nothing) during fold without any
/// intervening kernel write. The kernel surfaces these as recoverable
/// errors rather than panicking so a misbehaving store can be rolled
/// back, but seeing them in production means the store implementation
/// is broken, not the operation payload.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ApplyError {
    /// A required coin does not exist. During validation this is an
    /// ordinary rejection (the user named a coin id that is not live);
    /// during fold it is a [`crate::Batch`] contract violation (the slot
    /// disappeared between validation and fold without a kernel write).
    MissingCoin {
        /// Missing coin id.
        id: CoinId,
    },

    /// A coin changed between validation and fold. Indicates a
    /// [`crate::Batch`] contract violation — the kernel does not write to
    /// a slot between reading it and folding the corresponding effect,
    /// so any divergence is the store's fault.
    CoinChanged {
        /// Changed coin id.
        id: CoinId,
    },

    /// A required edge does not exist. Same dual interpretation as
    /// [`Self::MissingCoin`]: validation = user error, fold = store bug.
    MissingEdge {
        /// Missing edge id.
        id: EdgeId,
    },

    /// An edge changed between validation and fold. Same interpretation
    /// as [`Self::CoinChanged`]: a [`crate::Batch`] contract violation.
    EdgeChanged {
        /// Changed edge id.
        id: EdgeId,
    },

    /// A required registry chunk does not exist. Same dual
    /// interpretation as [`Self::MissingCoin`]: validation = the named
    /// registry value is not live, fold = store bug.
    MissingRegistryChunk {
        /// Missing chunk id.
        id: RegistryChunkId,
    },

    /// A registry chunk changed between validation and fold. Same
    /// interpretation as [`Self::CoinChanged`]: a [`crate::Batch`]
    /// contract violation.
    RegistryChunkChanged {
        /// Changed chunk id.
        id: RegistryChunkId,
    },

    /// An output id is already occupied.
    OutputExists {
        /// Occupied output coin id.
        id: CoinId,
    },

    /// An output edge id is already occupied.
    EdgeExists {
        /// Occupied output edge id.
        id: EdgeId,
    },

    /// An operation attempts to consume the same input twice.
    DuplicateInput {
        /// Duplicated input coin id.
        id: CoinId,
    },

    /// The requested funding cannot open an edge.
    InvalidOpen {
        /// Edge requested for open.
        output: EdgeId,
        /// Specific reason the open was rejected.
        reason: InvalidOpenReason,
    },

    /// An edge cannot close into the requested payouts.
    InvalidClose {
        /// Edge requested for close.
        input: EdgeId,
        /// Specific reason the close was rejected.
        reason: InvalidCloseReason,
    },

    /// A close proof is unsupported or does not match the edge being closed.
    InvalidProof {
        /// Edge requested for close.
        input: EdgeId,
        /// Specific reason the proof was rejected.
        reason: InvalidProofReason,
    },

    /// A move does not advance the edge it names.
    InvalidMove {
        /// Edge the move addresses.
        input: EdgeId,
        /// Specific reason the move was rejected.
        reason: InvalidMoveReason,
    },

    /// An owner's reshape is not admissible.
    InvalidReshape {
        /// Specific reason the reshape was rejected.
        reason: InvalidReshapeReason,
    },

    /// A transition produced a registry diff its own bound refuses.
    ///
    /// A transition bug, not user input: an operation decides which slots
    /// it writes before it writes any of them, so neither a duplicate nor
    /// an overflow is reachable from a payload.
    RegistryDiffRejected {
        /// Reason the mutation could not join the diff.
        reason: RegistryDiffError,
    },

    /// The backing store rejected a coin insertion.
    CoinInsertRejected {
        /// Coin id that could not be inserted.
        id: CoinId,
        /// Reason the store rejected the insertion.
        reason: InsertError,
    },

    /// The backing store rejected an edge insertion.
    EdgeInsertRejected {
        /// Edge id that could not be inserted.
        id: EdgeId,
        /// Reason the store rejected the insertion.
        reason: InsertError,
    },

    /// The backing store rejected a registry chunk insertion.
    RegistryChunkInsertRejected {
        /// Chunk id that could not be inserted.
        id: RegistryChunkId,
        /// Reason the store rejected the insertion.
        reason: InsertError,
    },
}

/// Specific reason an [`ApplyError::InvalidOpen`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidOpenReason {
    /// `context.fee(open.cost())` overflowed.
    FeeOverflow,
    /// `context.fee(open.reserve_cost())` overflowed.
    ReserveOverflow,
    /// Sum of funding coin values overflowed `u64`.
    FundingOverflow,
    /// Sum of funding coin values is less than open fee + lifetime fee +
    /// locked reserve.
    FundingInsufficient,
    /// The committed timeout height is not strictly after the open block.
    TimeoutNotFuture,
    /// `context.fees().lifetime() * paid_lifetime_blocks` overflowed.
    LifetimeFeeOverflow,
    /// Sum of deterministic payouts committed by the open terms overflowed.
    TermsPayoutOverflow,
    /// Deterministic timeout payouts committed by the open terms do not equal
    /// edge principal plus timeout reserve surplus under the open-time close
    /// fee schedule.
    TermsValueMismatch,
    /// A funding coin's owner is not its party's committed owner. The
    /// maker funding list must contain coins owned by
    /// `terms.parties().maker().owner()`; the taker funding list, by the
    /// taker's.
    FundingUnauthorized,
    /// A signer-authorized party spends a coin not delegated to that
    /// signer. A delegate reaches exactly the coins its owner delegated
    /// to it, and no others of the same owner.
    FundingNotDelegated,
    /// A signer-authorized party commits a payout delegate other than
    /// itself or none. A delegate may keep its earnings spendable by
    /// itself, but may never hand them to another key.
    PayoutDelegateNotSigner,
    /// A basic open carries a signer-authorized party. A basic edge
    /// pays its committed timeout outputs with no signature at all, so a
    /// delegate that could open one could park its owner's coins until a
    /// height of its choosing with no exit for the owner; only the work
    /// profiles, whose every shape leaves the owner a bounded exit, admit
    /// a delegate.
    BasicAuthNotOwner,
    /// A committed timeout payout lands somewhere other than exactly one
    /// of the two parties' committed destinations.
    TimeoutPayoutNotCommitted,
    /// One of the open signatures was rejected by the configured
    /// `SigVerifier`. Both maker and taker must sign the canonical open
    /// hash for the produced edge.
    BadSignature,
    /// A work-stake-bond open locks no value. The edge's value is the
    /// stake, so a zero-value object is not a stake bond.
    WorkStakeValueZero,
    /// Work-stake-bond terms commit a zero `max_job_price`: the bond
    /// covers no job (a price is at least 1), so it insures nothing.
    JobPriceCapZero,
    /// Work-stake-bond timeout payouts are empty or pay a key other
    /// than the provider. An unleased bond times out permissionlessly,
    /// so any other routing would let the stake return to the wrong
    /// party.
    WorkStakeReturnRouting,
    /// A work-stake-bond open carries no maker funding. The bond is the
    /// provider's stake, and its owner is proved by the coins that fund
    /// it.
    WorkStakeMakerUnfunded,
    /// A work-stake-bond open carries taker funding. The bond is the
    /// provider's stake alone; a client contribution would be
    /// transferred to the provider by a permissionless unleased
    /// timeout.
    WorkStakeTakerFunded,
    /// A work-payment open carries taker funding. The client funds the
    /// channel; the provider's stake is the bond.
    WorkPaymentTakerFunded,
    /// A work-payment open carries no maker funding. The client's
    /// owner is proved by the coins that fund the channel.
    WorkPaymentMakerUnfunded,
    /// Work-payment terms commit a zero or over-long response window.
    WorkResponseWindowOutOfRange,
    /// Work-payment terms commit a zero or over-long start validity
    /// window.
    WorkStartValidityOutOfRange,
    /// A work-payment open locks a reserve that does not cover both of
    /// its close routes, so one of its two exits could never be taken.
    WorkPaymentReserveTooSmall,
    /// A work-payment open leaves no capacity: the omission bond meets
    /// or exceeds the value the cheaper close route distributes, so no
    /// certificate could ever be admitted against it.
    WorkPaymentCapacityUnfunded,
    /// The live edge named as the bond does not commit the terms the
    /// payment embeds. The embedded witness is the bond's own canonical
    /// bytes, so a mismatch means the payment named some other edge —
    /// a legacy bond, a different bond, or an unrelated channel.
    WorkBondTermsMismatch,
    /// The named bond is already leased. A bond insures one payment
    /// channel at a time: a second channel would be priced against
    /// stake the first can still consume.
    WorkBondAlreadyLeased,
    /// The named bond's lease slots hold something that is not a lease.
    WorkBondLeaseFault {
        /// How the stored value failed to be a lease.
        fault: BondLeaseFault,
    },
}

/// Why a present bond-lease registry slot pair is not a readable lease.
///
/// Every variant is an invalid transaction, never absence. Absence is a
/// permission — it lets a payment open take the lease and lets a bond
/// take its immediate timeout — so anything that could be mistaken for
/// it has to be refused.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum BondLeaseFault {
    /// Exactly one of the two derived slots is occupied. A lease is
    /// written whole, so this is state no kernel transition produced.
    Partial,
    /// A stored chunk is not its half of a whole lease: wrong
    /// namespace, wrong record kind, wrong chunk count or index, or a
    /// value length that is not this record's width.
    Shape,
    /// The reassembled bytes are not a canonical lease record.
    Body,
    /// The lease names a different bond than the slots it was read
    /// from.
    Edge,
}

/// Why a present pending-close registry slot is not a readable record.
///
/// Every variant is an invalid transaction, never absence. A close that
/// read a corrupted record as "no contest is live" would hand a fresh
/// start to whoever corrupted it.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum PendingCloseFault {
    /// The stored chunk is not a whole single-chunk pending record: wrong
    /// namespace, wrong record kind, wrong chunk count or index, or a
    /// value length that is not this record's width.
    Shape,
    /// The chunk's bytes are not a canonical pending record.
    Body,
    /// The record names a different payment edge than the slot it was
    /// read from.
    Edge,
}

/// Specific reason an [`ApplyError::InvalidMove`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidMoveReason {
    /// The revealed terms do not commit the edge the move names.
    TermsMismatch,
    /// The edge is not a work-payment channel, so it has no close
    /// contest to open or answer.
    NotAPaymentChannel,
    /// The move's inclusion height is outside the signed validity
    /// window.
    OutsideValidityWindow,
    /// The signed validity window is wider than the terms allow, so the
    /// authorization would stay includable longer than the channel
    /// agreed to.
    ValiditySpanTooWide,
    /// A contest is already live on this edge. A second start by either
    /// role is refused without mutation: the first start's deadline is
    /// the one the response is bound to, and extending it is exactly the
    /// attack the window exists to stop.
    ClosePending,
    /// No contest is live on this edge, so there is nothing to answer.
    ClosePendingMissing,
    /// The pending slot holds something that is not this edge's record.
    ClosePendingFault {
        /// How the stored value failed to be a record.
        fault: PendingCloseFault,
    },
    /// The response names a contest other than the live one. A racing
    /// party must answer the start that won, not the one it submitted.
    StartIdMismatch,
    /// The response was signed by a role other than the certificate's
    /// beneficiary.
    ResponderNotBeneficiary,
    /// The one legal response has already landed.
    AlreadyResponded,
    /// The response window has shut.
    ResponseWindowClosed,
    /// A certificate names a different payment edge or terms than the
    /// move that carries it.
    CertificateNotBound,
    /// A start encodes a present certificate for zero. Zero has only the
    /// implicit absent encoding.
    CertificateNotPositive,
    /// A response certificate does not strictly exceed the amount the
    /// contest already settles at.
    CertificateNotIncreasing,
    /// A certificate names more than the channel's payment capacity.
    CertificateOverCapacity,
    /// The edge's reserve does not price its close routes, so no
    /// capacity can be derived.
    ReserveTooSmall,
    /// Adding the committed response window to the current height
    /// overflowed. The work profile is disabled this close to the height
    /// ceiling rather than wrapping a deadline into the past.
    DeadlineOverflow,
    /// A signature on the move payload was rejected.
    BadSignature,
    /// A client certificate signature was rejected.
    BadCertificateSignature,
}

/// Specific reason an [`ApplyError::InvalidClose`] was raised.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidCloseReason {
    /// Sum of payout values overflowed `u64`.
    PayoutOverflow,
    /// The edge's open-time reserve does not cover this close path's
    /// open-time committed fee. Edges opened by this kernel reserve the
    /// worst-case close path, so this indicates corrupted preloaded state or
    /// an incompatible future cost rule rather than current fee repricing.
    ReserveTooSmall,
    /// Sum of payout values does not equal principal plus reserve surplus for
    /// the selected close path.
    ValueMismatch,
    /// The close kind is not in the edge's committed [`crate::CloseKindSet`].
    /// Raised before any witness check — e.g. a `Mutual` close of a stake
    /// bond is rejected even with both parties' valid signatures.
    KindForbidden,
}

/// Specific reason an [`ApplyError::InvalidProof`] was raised.
///
/// `BadSignature` comes from the wired [`crate::SigVerifier`];
/// every other variant comes from one of the kernel's own inline
/// structural checks.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidProofReason {
    /// The proof's terms commitment does not match the edge's `TermsHash`.
    TermsMismatch,
    /// A signature on the close payload was rejected.
    BadSignature,
    /// A pre-expiry close proof (`Mutual`) was submitted at or after
    /// the committed timeout height.
    ProofExpired,
    /// A `Proof::Timeout` was submitted before the committed timeout height.
    TimeoutNotReached,
    /// A `Proof::Timeout` carries payouts that do not equal
    /// `Terms::timeout_outputs`, or a work-payment exit carries payouts
    /// other than the exact split its contest or freeze settles.
    PayoutMismatch,
    /// A mutual close pays somewhere other than exactly one of the two
    /// committed destinations, with the delegate stripped when either
    /// party signed as its owner.
    PayoutNotCommitted,
    /// An adjudicated close names an edge with no live contest. The
    /// contest *is* the proof, so its absence leaves nothing adjudicated.
    ClosePendingMissing,
    /// The pending slot holds something that is not this edge's record.
    ClosePendingFault {
        /// How the stored value failed to be a record.
        fault: PendingCloseFault,
    },
    /// An adjudicated close was submitted while the response window is
    /// still open and no response has landed.
    ResponseWindowOpen,
    /// An adjudicated close carries a contest commitment that is not
    /// the one this contest's record derives.
    ContestMismatch,
    /// A freeze's inclusion height is outside its signed validity
    /// window, or that window is wider than consensus allows.
    FreezeOutsideValidityWindow,
    /// A freeze settles below the amount its edge's live contest has
    /// already reached.
    FreezeBelowSettled,
    /// A tag-4 bond close read lease slots holding something that is
    /// not a lease. Never read as "unleased": that answer is what
    /// decides whether the immediate timeout exit is open.
    BondLeaseFault {
        /// How the stored value failed to be a lease.
        fault: BondLeaseFault,
    },
    /// The provider's total exceeds the value the close distributes.
    /// Unreachable for amounts admitted under the open-time capacity
    /// rule, and a rejection rather than a wrapping subtraction because
    /// the alternative is paying the client from nothing.
    PayoutOverCapacity,
}

/// Specific reason [`ApplyError::InvalidReshape`] refused a reshape.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum InvalidReshapeReason {
    /// Reshape outputs must carry positive value.
    ZeroOutput,
    /// A transfer to another owner cannot choose that owner's delegate.
    ForeignDelegation,
    /// The reshape consumes no coin, so there is no owner to authorize it.
    NoInputs,
    /// The inputs are not all owned by one key.
    OwnerMismatch,
    /// The input or output values overflowed when summed.
    ValueOverflow,
    /// The outputs do not carry exactly the value the inputs held.
    ValueMismatch,
    /// The owner's authorization did not verify over the reshape's
    /// payload hash.
    BadSignature,
}
