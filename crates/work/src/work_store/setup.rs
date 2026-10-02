//! Durable state for the channel-opening handshake.
//!
//! Each signed revision is fsynced before export; recovery resumes from the
//! retained revision and decides from one coherent observed chain state.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, NetworkId, SigVerifier, Tx};
use hellas_xet::XetFileHasher;

use crate::work_store::journal::{
    Journal, JournalError, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, Role, journal_name_parts,
};
use crate::work_store::{
    Applied, WorkStoreError, cursor::Cursor, hex, put_bytes, put_option, put_u64, take_bool,
    take_bytes, take_option,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work_bundle::{SetupBundleError, WorkChannelSetupBundleV1};
use hellas_rpc::protocol::work_setup::{CloseDescriptor, WorkSetupError};

mod codec;
mod state;
mod store;

use codec::describes_bundle;
use store::check_bundle_signatures;
pub use store::{
    DiscoveredSetup, SetupDiscovery, SetupDiscoveryError, SetupStore, UnidentifiedSetup,
    discover_setups, setup_key,
};

/// Domain of the setup journal's key.
const SETUP_KEY: &[u8] = b"hellas.work.setup-journal-key.v1";

/// Why a setup record is not one this journal may hold.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupStateError {
    /// The bundle did not decode, or is not the next revision of the
    /// one held.
    #[error(transparent)]
    Bundle(#[from] SetupBundleError),
    /// The bundle is over another network, or another bond, than this
    /// journal is keyed to.
    #[error("the bundle's {field} is not the one this journal is keyed to")]
    WrongChannel {
        /// Which field disagreed.
        field: &'static str,
    },
    /// A step was recorded from a stage that cannot take it.
    #[error("{step} cannot be recorded at revision {revision:?}")]
    WrongStage {
        /// Step that was attempted.
        step: &'static str,
        /// Revision the journal holds, if any.
        revision: Option<u8>,
    },
    /// Setup has already ended, one way or the other.
    #[error("setup has already ended: {0}")]
    Ended(SetupEnd),
    /// A record naming an edge the retained bundle does not produce.
    #[error("the record names payment edge {named:?}, not the retained {retained:?}")]
    WrongPaymentEdge {
        /// Edge the record named.
        named: EdgeId,
        /// Edge the retained bundle derives.
        retained: Option<EdgeId>,
    },
    /// Only a provider holds both transactions and submits them.
    #[error("{step} is a provider step, and this journal is a client's")]
    WrongRole {
        /// Step that was attempted.
        step: &'static str,
    },
    /// A record's bytes were not canonical.
    #[error("setup record is not canonical")]
    Malformed,
    /// An armed descriptor is not for the bundle stored beside it.
    #[error("the armed close descriptor does not describe its setup bundle")]
    DescriptorMismatch,
    /// The persisted or proposed close descriptor failed its structural
    /// policy checks.
    #[error(transparent)]
    Descriptor(#[from] WorkSetupError),
    /// An abort or fault cannot discard an Open that may still finalize.
    #[error("setup cannot end while a submitted Open is unresolved")]
    SubmittedOpenUnresolved,
}

/// How setup ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupEnd {
    /// Both edges and the lease are live. This is the only end that
    /// produces a channel.
    #[error("complete")]
    Complete,
    /// Setup stopped without spending the provider's stake, and without
    /// anything to reconcile.
    #[error("aborted: {0}")]
    Aborted(SetupAbort),
    /// Setup stopped in a state no automatic step can leave.
    #[error("faulted: {0}")]
    Faulted(SetupFault),
}

/// Why setup stopped cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupAbort {
    /// The retained bond Open can no longer be included: its own
    /// timeout is at or before the finalized height. Its funding is
    /// unspent and stays that way.
    #[error("the retained bond open expired before it was included")]
    BondOpenExpired,
    /// A coin funding the client's payment Open was spent before the
    /// bond was posted, so the channel it would insure cannot be
    /// funded.
    #[error("a coin funding the payment open was spent before the bond was posted")]
    PaymentFundingSpent,
    /// The provider's own finalized bond Timeout consumed the stake and
    /// returned it. Contiguous history holds the bond Open and the Close
    /// that spent it, so the absent bond and spent funding are this
    /// endpoint's own reclaim rather than a theft: there is no channel and
    /// nothing to reconcile.
    #[error("the provider's own bond timeout reclaimed the stake")]
    BondReclaimed,
}

/// Why setup cannot continue without reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupFault {
    /// The bond is absent and a coin that funded it is gone: something
    /// else spent the provider's stake input.
    #[error("the bond is absent and a coin funding it has been spent")]
    BondFundingSpent,
    /// The bond's lease slots hold something that is not a readable
    /// lease.
    #[error("the bond's lease slots are not a readable lease")]
    LeaseMalformed,
    /// The bond is leased to another payment edge.
    #[error("the bond is leased to another payment channel")]
    LeasedElsewhere,
    /// A live object contradicts another: a payment edge without its
    /// bond, a lease without its payment edge, or a payment edge with
    /// no lease at all.
    #[error("the finalized objects contradict each other")]
    UnexplainedState,
}

/// What one restart, or one first submission, should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupDecision {
    /// Both edges and this channel's lease are live: record completion.
    Complete,
    /// A payment Open finalized, so close recovery must be mounted even
    /// though the admission bond or payment edge is no longer live.
    CloseOnly,
    /// Nothing to do here: the other party has not produced the next
    /// revision, or the transaction this endpoint is waiting on is not
    /// its own to send.
    AwaitingCounterparty,
    /// Submit the retained bond Open. This is both the first
    /// submission and every resubmission, and reaching it means the
    /// payment-funding preflight passed at the height decided from.
    SubmitBond,
    /// Submit the retained payment Open over the live unleased bond.
    SubmitPayment,
    /// Take the unleased bond's immediate Timeout back.
    TimeoutBond,
    /// Stop, with the provider's coins unspent.
    Abort(SetupAbort),
    /// Stop, and reconcile by hand.
    Fault(SetupFault),
}

/// One finalized read the setup decision is made from.
///
/// A struct rather than five arguments, for the same reason
/// `work_setup::ObservedChannel` is: two of its fields are
/// `Option<&Edge>` and would otherwise be silently swappable. Coherence
/// is the caller's: every field must come from one database snapshot at
/// `height`, and `live_funding` in particular must be read at that same
/// snapshot, because a coin read later than the edges is a preflight
/// that answers about a different state than the one it is protecting.
#[derive(Clone, Copy, Debug)]
pub struct ObservedSetup<'a> {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<&'a Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<&'a Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// Every coin of the two Opens' funding that is still live at that
    /// snapshot. A coin absent from this set is a coin that is gone.
    pub live_funding: &'a BTreeSet<CoinId>,
}

/// The immutable finalized observation floor retained before an executable
/// authorization can leave an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupScan {
    /// Finalized height already observed when the setup was armed.
    pub height: u64,
    /// Payload digest at `height`; the first history block must name it as
    /// parent.
    pub payload: [u8; 32],
}

/// A bounded observation of finalized blocks. Only `SetupState::observe` can
/// construct it; journals retain the cursor and outcomes, never transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupObservation {
    from: SetupScan,
    through: SetupScan,
    bond_finalized: bool,
    payment_finalized: bool,
    bond_closed: bool,
    payment_closed: bool,
    origin: Option<SetupOrigin>,
}

/// One durable step of the handshake.
///
/// Deliberately small. The two submission markers carry no transaction
/// bytes because the retained bundle already is both transactions —
/// a second copy could only ever be a different one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetupRecord {
    /// One revision of the handshake, written before the signature it
    /// carries is exported.
    Bundle {
        /// The revision's exact canonical bytes.
        bundle: Vec<u8>,
    },
    /// The immutable observation floor, written once before revision 1 (the
    /// provider) or revision 2 (the client) can be exported.
    ScanArmed {
        /// Finalized height already observed.
        height: u64,
        /// Payload digest at `height`.
        payload: [u8; 32],
    },
    /// An executable revision and everything close-only recovery needs,
    /// fsynced together before that revision is returned to the peer.
    ArmedBundle {
        /// The revision's exact canonical bytes.
        bundle: Vec<u8>,
        /// The admitted descriptor recovered without operator configuration.
        close_descriptor: Box<CloseDescriptor>,
    },
    /// The cursor and outcomes of a contiguous finalized scan.
    Observed(SetupObservation),
    /// The provider is about to submit the deterministic bond Timeout.
    BondTimeoutSubmitted,
    /// The retained bond Open is about to be broadcast.
    BondSubmitted,
    /// The retained payment Open is about to be broadcast.
    PaymentSubmitted,
    /// Both edges and the lease are finalized, at this block.
    Complete {
        /// The payment edge the retained bundle derives.
        payment_edge: EdgeId,
        /// Height of the block carrying the accepted payment Open.
        origin_height: u64,
        /// Payload digest of that block.
        origin_payload: [u8; 32],
        /// Payload digest of that block's parent, which is the watcher
        /// cursor immediately before the channel existed.
        origin_parent: [u8; 32],
    },
    /// Setup ended without a channel.
    Ended {
        /// Why.
        outcome: SetupEnd,
    },
}

mod tag {
    pub(super) const BUNDLE: u8 = 0;
    pub(super) const BOND_SUBMITTED: u8 = 1;
    pub(super) const PAYMENT_SUBMITTED: u8 = 2;
    pub(super) const COMPLETE: u8 = 3;
    pub(super) const ENDED: u8 = 4;
    pub(super) const SCAN_ARMED: u8 = 5;
    pub(super) const ARMED_BUNDLE: u8 = 6;
    pub(super) const OBSERVED: u8 = 7;
    pub(super) const BOND_TIMEOUT_SUBMITTED: u8 = 8;
}

mod end_code {
    pub(super) const COMPLETE: u8 = 0;
    pub(super) const ABORT_BOND_EXPIRED: u8 = 1;
    pub(super) const ABORT_PAYMENT_FUNDING_SPENT: u8 = 2;
    pub(super) const FAULT_BOND_FUNDING_SPENT: u8 = 3;
    pub(super) const FAULT_LEASE_MALFORMED: u8 = 4;
    pub(super) const FAULT_LEASED_ELSEWHERE: u8 = 5;
    pub(super) const FAULT_UNEXPLAINED: u8 = 6;
    pub(super) const ABORT_BOND_RECLAIMED: u8 = 7;
}

const fn end_to_code(end: SetupEnd) -> u8 {
    match end {
        SetupEnd::Complete => end_code::COMPLETE,
        SetupEnd::Aborted(SetupAbort::BondOpenExpired) => end_code::ABORT_BOND_EXPIRED,
        SetupEnd::Aborted(SetupAbort::PaymentFundingSpent) => end_code::ABORT_PAYMENT_FUNDING_SPENT,
        SetupEnd::Faulted(SetupFault::BondFundingSpent) => end_code::FAULT_BOND_FUNDING_SPENT,
        SetupEnd::Faulted(SetupFault::LeaseMalformed) => end_code::FAULT_LEASE_MALFORMED,
        SetupEnd::Faulted(SetupFault::LeasedElsewhere) => end_code::FAULT_LEASED_ELSEWHERE,
        SetupEnd::Faulted(SetupFault::UnexplainedState) => end_code::FAULT_UNEXPLAINED,
        SetupEnd::Aborted(SetupAbort::BondReclaimed) => end_code::ABORT_BOND_RECLAIMED,
    }
}

const fn end_from_code(code: u8) -> Option<SetupEnd> {
    Some(match code {
        end_code::COMPLETE => SetupEnd::Complete,
        end_code::ABORT_BOND_EXPIRED => SetupEnd::Aborted(SetupAbort::BondOpenExpired),
        end_code::ABORT_PAYMENT_FUNDING_SPENT => SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
        end_code::FAULT_BOND_FUNDING_SPENT => SetupEnd::Faulted(SetupFault::BondFundingSpent),
        end_code::FAULT_LEASE_MALFORMED => SetupEnd::Faulted(SetupFault::LeaseMalformed),
        end_code::FAULT_LEASED_ELSEWHERE => SetupEnd::Faulted(SetupFault::LeasedElsewhere),
        end_code::FAULT_UNEXPLAINED => SetupEnd::Faulted(SetupFault::UnexplainedState),
        end_code::ABORT_BOND_RECLAIMED => SetupEnd::Aborted(SetupAbort::BondReclaimed),
        _ => return None,
    })
}

/// Where the channel this journal opens is finalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupOrigin {
    /// The payment edge the handshake produced.
    pub payment_edge: EdgeId,
    /// Height of the block carrying the accepted payment Open.
    pub height: u64,
    /// Payload digest of that block.
    pub payload: [u8; 32],
    /// Payload digest of its parent: the watcher's starting cursor.
    pub parent: [u8; 32],
}

/// Everything the handshake has durably reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupState {
    network: NetworkId,
    bond_edge: EdgeId,
    role: Role,
    bundle: Option<WorkChannelSetupBundleV1>,
    bundle_bytes: Vec<u8>,
    scan_armed: Option<SetupScan>,
    close_descriptor: Option<CloseDescriptor>,
    unresolved_bond_open: bool,
    unresolved_payment_open: bool,
    scan_cursor: Option<SetupScan>,
    bond_finalized: bool,
    payment_finalized: bool,
    bond_closed: bool,
    payment_closed: bool,
    bond_timeout_submitted: bool,
    origin: Option<SetupOrigin>,
    end: Option<SetupEnd>,
}
