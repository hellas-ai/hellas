//! The paid-work wire: how a client proposes one job and a provider
//! accepts or refuses it.
//!
//! # What crosses the wire
//!
//! Canonical private records, and nothing else. `AcceptWorkRequest`
//! carries the exact bytes of a [`PaidJobAuthorizationV1`] and a
//! [`hellas_rpc::protocol::artifacts::PreparedPaidInputV1`], not a protobuf transcription of their
//! fields, because the two signatures on this exchange are over digests
//! of those bytes. A protobuf spelling beside them would be a second
//! definition of what both parties signed, agreeing with the first until
//! one of them gained a field.
//!
//! # The order
//!
//! Both endpoints obey the same rule, which is [`crate::work_store`]'s:
//! **the state that authorises a signature is fsynced before the
//! signature leaves the process.**
//!
//! The client reserves its nonce, builds and signs the authorization,
//! and journals the signature — all before the request is handed to a
//! transport. The provider journals the client's proposal, which is what
//! reserves its compute credit, then signs, then journals its own
//! signature, and only then answers. A crash anywhere in either sequence
//! costs a round trip and at most one burnt proposal nonce: the retry
//! finds the durable record, returns the retained bytes, and reserves no
//! credit twice.
//!
//! The one thing neither endpoint can promise is delivery. A provider
//! that crashes after its journal commits and before its reply reaches
//! the client has co-signed a job the client does not know is accepted;
//! the client's retry is what resolves that, and the acceptance deadline
//! is what bounds how long it may try.
//!
//! # Idempotence
//!
//! By `work_id`, which is the authorization's own digest. A retry of the
//! same proposal returns the retained co-signature without re-checking
//! deadlines — the answer was already given, and a deadline that passed
//! since cannot unsay it. A *different* proposal while one is in flight
//! is refused, never queued.
//!
//! # Running what was accepted
//!
//! [`run_accepted_work`] is the second half, and it obeys the same rule
//! in the one place it matters most: the running marker is fsynced
//! before the backend is called. It is not a wire exchange — there is no
//! Run RPC here — but it is the same journal, the same channel, and the
//! same `work_id`, so it lives beside the acceptance that authorised it.
//!
//! The property it exists for: **for one `work_id`, at most one call in
//! the lifetime of one journal ever invokes the backend.** Two durable
//! facts carry it, and neither alone does. The provider burns each
//! proposal nonce it sees, so one `work_id` opens at most one job, ever
//! — ending a job does not give its nonce back. And the journal takes a
//! running marker only from the accepted phase, so one job crosses into
//! running at most once; every later call reads that phase and answers
//! from it instead of invoking. Deleting the journal file forfeits both,
//! which is why the claim is scoped to one journal's life and not to one
//! `work_id`'s.
//!
//! A third durable fact is about the crash rather than the count. A
//! marker found on the disk by a process that did not write it makes the
//! state indeterminate, and that does not stop a second invocation — the
//! phase already does — it stops the *resolution*: a recovered process
//! may not sign a result for an invocation it cannot know it made.
//!
//! # Delivering the answer
//!
//! [`ProviderEndpoint::deliver`] and [`ClientEndpoint::receive`] are the
//! third exchange, and they obey the same rule at the one moment it is
//! irreversible: the release marker — which is what debits this client's
//! delivery credit — is fsynced before a byte of plaintext is returned.
//!
//! It is one unary call carrying the whole answer, and that is the
//! profile rather than a shortcut. Nothing is released before the
//! terminal result is durable and its price is reserved, so there is no
//! prefix to stream; what the client gets is the signed result and the
//! transcript the provider's own journal holds, and what it does with
//! them is rebuild one from the other before anything is stored.
//!
//! A lost response costs a round trip. The provider answers a second
//! call from the same spool and re-commits the same marker as a
//! redundant step, so one job's plaintext is debited once however many
//! times it is fetched.
//!
//! # Paying for it
//!
//! [`ClientEndpoint::pay`] is the fourth exchange, and it is where the
//! private evidence meets the one number consensus settles. There is no
//! invoice call in front of it and no provider signature over a price:
//! the provider has already co-signed the authorization that fixes the
//! price and signed the result that earns it, so what a third signature
//! could add is nothing, and what it could disagree with is everything.
//!
//! The client derives the amount itself — its own credited total plus
//! the price its own authorization fixed — signs the certificate and the
//! binding that says what that certificate bought, and fsyncs both
//! before either leaves the process, through the ledger that says this
//! job has not been paid for before.
//!
//! Then the provider fsyncs the same pair before it acknowledges
//! anything, deriving the same amount from its own ledger, and that same
//! record is what retires the job's compute and delivery credit. There
//! is no moment at which this client is owed service for a payment the
//! provider's disk does not hold.
//!
//! # Closing
//!
//! Both endpoints sign a close start, retain its exact bytes before
//! they leave, and hand them to consensus until a finalized block says
//! the contest opened or the window they were signed for has passed.
//! It is symmetric because the deadlock is: a provider that stops
//! answering leaves the client's funded edge locked, and a client that
//! stops paying leaves the provider's earnings unspendable.
//!
//! What neither endpoint does here is wait. `advance_close` is one
//! step, and the caller that owns a clock is the one that repeats it.

mod stream;
pub use stream::{PaidProgress, PaidResultStream, fetch_result_stream};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use hellas_kernel::{
    Decode as _, EarnedCertificate, Move, Party, PaymentCloseStart, PendingSlot, Secp256k1Signer,
    Secp256k1Verifier, Sig, SigVerifier as _, StartId, Tx,
};
use hellas_wire::{StreamTransport, TransportContext, WireStatus};

use prost::Message as _;

use crate::work_close::{
    CatchUpError, CloseChannel, CloseError, CloseProgress, FinalizedBlocks, FinalizedWork, TxSink,
    adjudicated_close, advance_close, catch_up, close_duty_present, close_response, close_start,
    observe, response_body_digest,
};
use crate::work_store::channel::encode_kernel;
use crate::work_store::journal::MAX_RECORD_BYTES;
use crate::work_store::{
    ChannelRecord, ChannelState, ChannelStateError, ChannelStore, JobPhase, JobState,
    PaidCertificate, Role, TerminalOutcome, WorkStoreError, hex,
};
use hellas_rpc::observe::{LEVEL, TARGET, Timing};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, WorkAccepted, WorkDelivered, WorkPaid,
    WorkRefusalCode, WorkRefused, accept_work_response::Outcome,
    admit_certificate_response::Outcome as AdmitOutcome,
    deliver_result_response::Outcome as DeliverOutcome,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::PreparedPaidInputParts;
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidJobAuthorizationV1, PaidJobResultV1, PaidWorkError, PaymentBindingV1,
    PrivateRecord as _, delivery_request_digest, encode_transcript, next_payment,
    payment_binding_digest, result_digest, signing_hash, work_id,
};
use hellas_rpc::protocol::work_fetch::{PaidFetchPolicyV1, PreparedPaidFetchInputParts};
use hellas_rpc::protocol::work_profile::{PaidWorkPolicy, PreparedPaidWorkInput};
use hellas_rpc::protocol::work_setup::{ObservedChannel, ReadyChannel, WorkSetupError};
use hellas_rpc::services::work::{WorkClientImpl, WorkHandler};
use hellas_rpc::{EvaluateRequest, OutputEventEnvelope, SubmitTxOutcome};

// ── Refusals ──────────────────────────────────────────────────────────

/// Why a provider did not accept a proposal.
///
/// Six answers, and the difference between them is what the caller may
/// do next: two are retryable unchanged, three are permanent for these
/// exact bytes, and one is permanent only while another job holds the
/// channel. A caller that cannot tell them apart either gives up on a
/// transient fault or retries an invalid proposal as a fresh paid job,
/// and the second of those is the expensive mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkRefusal {
    /// The provider cannot answer yet: it has not processed a finalized
    /// block it can admit work at, or the job it accepted has not
    /// finished. Retryable unchanged.
    NotReady,
    /// A deadline or the channel's admission horizon has passed.
    /// Permanent for these bytes; a fresh proposal may still be
    /// accepted.
    Expired,
    /// Not a well-formed proposal on this channel. Permanent, and never
    /// a reason to retry as a new paid job without changing it.
    Invalid,
    /// A different proposal already holds this key.
    Conflict,
    /// Well formed, and refused by the provider's own admission state:
    /// credit exhausted, an unallocated certificate gap, or a job
    /// already in flight.
    Declined,
    /// The provider could not make the state durable. Retryable, and
    /// nothing was released.
    Unavailable,
}

impl WorkRefusal {
    /// Returns the wire code for this refusal.
    #[must_use]
    pub const fn code(self) -> WorkRefusalCode {
        match self {
            Self::NotReady => WorkRefusalCode::NotReady,
            Self::Expired => WorkRefusalCode::Expired,
            Self::Invalid => WorkRefusalCode::Invalid,
            Self::Conflict => WorkRefusalCode::Conflict,
            Self::Declined => WorkRefusalCode::Declined,
            Self::Unavailable => WorkRefusalCode::Unavailable,
        }
    }

    /// Reads a refusal from its wire code.
    ///
    /// `WORK_REFUSAL_CODE_UNSPECIFIED` and every unassigned number
    /// return `None`: a refusal a peer cannot name is not a refusal this
    /// endpoint may act on, and proto3's open enums make the unassigned
    /// case reachable from any newer peer.
    #[must_use]
    pub const fn from_code(code: i32) -> Option<Self> {
        match code {
            c if c == WorkRefusalCode::NotReady as i32 => Some(Self::NotReady),
            c if c == WorkRefusalCode::Expired as i32 => Some(Self::Expired),
            c if c == WorkRefusalCode::Invalid as i32 => Some(Self::Invalid),
            c if c == WorkRefusalCode::Conflict as i32 => Some(Self::Conflict),
            c if c == WorkRefusalCode::Declined as i32 => Some(Self::Declined),
            c if c == WorkRefusalCode::Unavailable as i32 => Some(Self::Unavailable),
            _ => None,
        }
    }

    /// Whether retrying the identical request could succeed later.
    ///
    /// True only for the two faults that are about the provider's own
    /// progress. It says nothing about how long to wait, and nothing
    /// about whether the job's deadlines will still be met when the
    /// retry lands.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::NotReady | Self::Unavailable)
    }
}

impl core::fmt::Display for WorkRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotReady => "not ready",
            Self::Expired => "expired",
            Self::Invalid => "invalid",
            Self::Conflict => "conflict",
            Self::Declined => "declined",
            Self::Unavailable => "unavailable",
        })
    }
}

/// One refusal and the diagnostic text that goes with it.
///
/// The text is for an operator reading a log. Nothing decides on it, no
/// digest covers it, and no test asserts its wording.
pub(crate) struct Refusal {
    pub(crate) code: WorkRefusal,
    pub(crate) reason: String,
}

impl Refusal {
    pub(crate) fn new(code: WorkRefusal, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self::new(WorkRefusal::Invalid, reason)
    }
}

impl From<PaidWorkError> for Refusal {
    /// Only the acceptance deadline makes a record error a matter of
    /// timing. Everything else a record rule refuses is refused the same
    /// way at every height.
    fn from(error: PaidWorkError) -> Self {
        let code = match error {
            PaidWorkError::AcceptanceExpired { .. } => WorkRefusal::Expired,
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, error.to_string())
    }
}

impl From<WorkSetupError> for Refusal {
    /// `check_signable` and `check_releasable` are the two producers on
    /// this path. `CursorBehind` is the provider's own lag.
    /// `HorizonPassed`, `TerminalUnreachable`, and `DeliveryUnreachable`
    /// are height-dependent and one-way: no later height makes any of
    /// them pass again. `OracleGraceTooShort` compares two carried
    /// deadlines to each other and to no height at all, so it is wrong
    /// rather than late — and its overflow sibling, which the same
    /// arithmetic raises, is wrong for the same reason.
    ///
    /// The rest belong to `check_ready`, which runs before an endpoint is
    /// built and never here. They are mapped so the match is total; no
    /// test reaches them, and none claims to.
    fn from(error: WorkSetupError) -> Self {
        let code = match error {
            WorkSetupError::CursorBehind { .. } => WorkRefusal::NotReady,
            WorkSetupError::HorizonPassed { .. }
            | WorkSetupError::TerminalUnreachable { .. }
            | WorkSetupError::DeliveryUnreachable { .. } => WorkRefusal::Expired,
            WorkSetupError::OracleGraceTooShort { .. } | WorkSetupError::Record(_) => {
                WorkRefusal::Invalid
            }
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, error.to_string())
    }
}

impl From<WorkStoreError> for Refusal {
    /// A journal that will not take the record is the provider's own
    /// storage failing, and the proposal is untouched by it.
    fn from(error: WorkStoreError) -> Self {
        let code = match &error {
            WorkStoreError::Channel(channel) => channel_refusal(channel),
            WorkStoreError::Journal(_) | WorkStoreError::Setup(_) => WorkRefusal::Unavailable,
        };
        Self::new(code, error.to_string())
    }
}

/// Maps one channel-state refusal onto the wire's six answers.
///
/// Accepting a proposal reaches four of these through its two commits,
/// and each has a test: a nested record rule, a bad client signature, a
/// job already in flight, and a nonce this channel has already spent.
///
/// `OverCredit` is reachable but not from a test here. This profile
/// admits one job at a time, so the gate can only bite after earlier
/// jobs have been run and lost, which takes a journal rather than a
/// request. What it is on the wire — a decline, not a fault — is
/// decided here; that it bites at all is
/// `compute_credit_bounds_what_may_be_co_signed`'s, and that a channel
/// which has reached its limit still *opens* is
/// `a_journal_accepted_a_record_at_a_time_reopens_whole`'s.
///
/// The rest belong to steps this phase does not carry — a result, a
/// payment, a cursor, a job whose ending is already on the disk — and
/// are mapped so the match is total, not because a proposal can produce
/// them.
const fn channel_refusal(error: &ChannelStateError) -> WorkRefusal {
    match error {
        ChannelStateError::Terminated { .. } | ChannelStateError::Conflict { .. } => {
            WorkRefusal::Conflict
        }
        ChannelStateError::WrongPhase { .. }
        | ChannelStateError::OverCredit { .. }
        | ChannelStateError::Closing { .. }
        | ChannelStateError::Indeterminate => WorkRefusal::Declined,
        ChannelStateError::AcceptanceLate { .. }
        | ChannelStateError::DispatchLate { .. }
        | ChannelStateError::ReceiptLate { .. }
        | ChannelStateError::PaymentLate { .. } => WorkRefusal::Expired,
        ChannelStateError::Record(_)
        | ChannelStateError::BadSignature { .. }
        | ChannelStateError::WrongRole { .. }
        | ChannelStateError::WrongChannel { .. }
        | ChannelStateError::CursorNotNext { .. }
        | ChannelStateError::CursorNotContiguous { .. }
        | ChannelStateError::Malformed => WorkRefusal::Invalid,
    }
}

// ── Endpoint construction ─────────────────────────────────────────────

/// Why an endpoint could not be built over this channel, store, and key
/// — or, for [`Self::NotAdmitting`], why one that was built admits no
/// new work.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The journal is another channel's.
    #[error("the store's channel is not the one this readiness decided")]
    WrongChannel,
    /// The journal was opened at other funding than the readiness read
    /// found, so the two bound payments differently.
    #[error("the store's settlement is not the one this readiness read")]
    WrongSettlement,
    /// Paid Fetch providers must never persist customer payloads.
    #[error("paid fetch requires a provider journal containing metadata only")]
    PayloadRetention,
    /// The journal is the other role's.
    #[error("the store is the {found} journal, and this is the {expected} endpoint")]
    WrongRole {
        /// Role this endpoint is.
        expected: &'static str,
        /// Role the journal was opened as.
        found: &'static str,
    },
    /// The signer does not hold the settlement key this endpoint signs
    /// with.
    #[error("the signer is not the channel's {party} key")]
    WrongKey {
        /// Which party the endpoint signs as.
        party: &'static str,
    },
    /// No readiness decision is held, so this channel admits no new
    /// work. Its close duties are unaffected: they are the reason the
    /// channel is mounted at all.
    #[error("this channel holds no readiness decision, and admits no new work")]
    NotAdmitting,
    /// A handler panicked while holding the endpoint.
    #[error("the endpoint lock is poisoned")]
    Poisoned,
    /// Another lifecycle step currently owns this endpoint.
    #[error("another lifecycle step is still catching this endpoint up")]
    CatchingUp,
}

const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Client => "client",
        Role::Provider => "provider",
    }
}

/// Checks that a store, a readiness decision, and a signing key are
/// three views of the same half of the same channel.
///
/// All four disagreements are configuration mistakes rather than peer
/// behaviour, and every one of them would otherwise surface much later
/// as a signature nobody can verify or a payment bounded by the wrong
/// capacity.
fn bind(
    ready: &ReadyChannel,
    store: &ChannelStore,
    signer: &Secp256k1Signer,
    role: Role,
) -> Result<(), EndpointError> {
    if role == Role::Provider
        && matches!(ready.execution_policy(), PaidWorkPolicy::Fetch { .. })
        && !store.metadata_only()
    {
        return Err(EndpointError::PayloadRetention);
    }
    let state = store.state();
    if state.channel() != ready.channel() {
        return Err(EndpointError::WrongChannel);
    }
    if state.settlement() != ready.settlement() {
        return Err(EndpointError::WrongSettlement);
    }
    bind_store(store, signer, role)
}

/// Checks that a store and a signing key are two views of the same half
/// of the same channel.
///
/// The two disagreements a readiness decision has nothing to say about.
/// A journal carries the channel and the role it was opened at, so these
/// are answerable without one — which is what lets a close capability be
/// built for a channel no readiness decision could be made for.
fn bind_store(
    store: &ChannelStore,
    signer: &Secp256k1Signer,
    role: Role,
) -> Result<(), EndpointError> {
    let state = store.state();
    if state.role() != role {
        return Err(EndpointError::WrongRole {
            expected: role_name(role),
            found: role_name(state.role()),
        });
    }
    let party = match role {
        Role::Client => state.channel().client_key(),
        Role::Provider => state.channel().provider_key(),
    };
    if signer.party_key() != party {
        return Err(EndpointError::WrongKey {
            party: role_name(role),
        });
    }
    Ok(())
}

// ── The provider ──────────────────────────────────────────────────────

/// The provider half of the close, and nothing else.
///
/// Built from the journal and the key alone, because that is all a close
/// reads. A close driver exists *because* a channel is contested, or its
/// bond is gone, or its horizon has passed — and
/// [`WorkChannelDescriptor::check_ready`](hellas_rpc::protocol::work_setup::WorkChannelDescriptor::check_ready)
/// refuses every one of those. A close capability that needed a
/// [`ReadyChannel`] could therefore never be built for the channels it
/// exists for.
///
/// The two facts every method here reads are the *store's*: the channel
/// each signature is bound to, and what the funded edge settles. Both
/// were fixed when the journal was opened, and [`bind`] is what asserts
/// they are the same two a readiness decision carries — so nothing is
/// bypassed by reading them here, and there is no second copy to
/// disagree with. What a readiness decision adds beyond them — the
/// execution policy, the height it was decided at, and the admission
/// horizon — belongs to new work, and no close consults any of it.
///
/// Its public surface is the close core. Admission lives on
/// [`ProviderEndpoint`], which cannot be built without a readiness
/// decision, and on [`WorkService`], which refuses it until one arrives.
#[derive(Debug)]
pub struct CloseEndpoint {
    store: ChannelStore,
    signer: Secp256k1Signer,
    close_handoff: Option<(StartId, Handoff)>,
}

/// The provider half of the acceptance exchange.
///
/// It owns one channel's journal and answers proposals on that channel
/// alone. A proposal naming another channel is refused by
/// [`hellas_rpc::protocol::work::check_authorization`], never routed: routing many channels through
/// one endpoint is a later concern, and pretending to do it here would
/// mean an authorization whose `channel_id` selects its own validator.
///
/// It is a [`CloseEndpoint`] plus the readiness decision new work is
/// admitted under. [`Self::new`] takes one, so an endpoint that answers
/// proposals cannot exist without one; the close half underneath it
/// never reads it.
#[derive(Debug)]
pub struct ProviderEndpoint {
    close: CloseEndpoint,
    ready: Option<ReadyChannel>,
}

/// How far this process has got with the answer to a live contest.
///
/// Not journaled, and that is the whole point of it. A durable "handed
/// off" would be a claim about a submission that outlives the process
/// making it: the record would have to be written before the send, and a
/// crash in between would leave a disk saying consensus has an answer it
/// never received. What survives a restart is the answer itself —
/// `ChannelRecord::CloseResponded` — and a restarted endpoint offers it
/// again before it reads anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handoff {
    /// A sink took the call and did not enqueue it: [`SubmitTxOutcome::Full`]
    /// or [`SubmitTxOutcome::ValidationRejected`], both of which are
    /// successful `Result`s meaning *not enqueued*. The answer is still
    /// owed and is sent again on the next pass — over one further block
    /// and no more. A rejection can equally mean the answer is already on
    /// chain and only reading on can tell, so the cursor is not frozen;
    /// but a backlog read to its end would reach the deadline with the
    /// answer still unsent, which is the one thing this must not do.
    Offered,
    /// A sink holds the answer for inclusion: [`SubmitTxOutcome::Enqueued`]
    /// or [`SubmitTxOutcome::Duplicate`]. Nothing further is sent for
    /// this contest; what ends it now is the contest ending.
    Accepted,
}

impl CloseEndpoint {
    /// Builds the close half over one channel's journal and key.
    ///
    /// No readiness decision, and none is asked for. What is checked is
    /// what a journal can answer on its own: that it is the provider's,
    /// and that this key is the provider key its channel names.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when the store and the key are not both the
    /// provider's view of the same channel.
    pub fn new(store: ChannelStore, signer: Secp256k1Signer) -> Result<Self, EndpointError> {
        bind_store(&store, &signer, Role::Provider)?;
        Ok(Self {
            store,
            signer,
            close_handoff: None,
        })
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        self.store.state()
    }
}

impl ProviderEndpoint {
    /// Builds the provider endpoint for one ready channel.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when the store, the readiness decision, and the
    /// key are not all the provider's view of the same channel.
    pub fn new(
        ready: ReadyChannel,
        store: ChannelStore,
        signer: Secp256k1Signer,
    ) -> Result<Self, EndpointError> {
        bind(&ready, &store, &signer, Role::Provider)?;
        Ok(Self {
            close: CloseEndpoint {
                store,
                signer,
                close_handoff: None,
            },
            ready: Some(ready),
        })
    }

    /// Wraps a close half as an endpoint that admits no new work.
    ///
    /// Private, because a caller wanting exactly this already has it:
    /// [`CloseEndpoint`] is the close capability, whole. This is what
    /// [`WorkService::close_only`] serves it behind, where one type has
    /// to carry both halves because one handler answers the wire.
    const fn close_only(close: CloseEndpoint) -> Self {
        Self { close, ready: None }
    }

    /// The readiness this endpoint admits new work under, or the refusal
    /// that says it has none.
    ///
    /// # Errors
    ///
    /// [`EndpointError::NotAdmitting`] when no readiness decision is
    /// held. Nothing about a close reaches this.
    fn admitting(&self) -> Result<&ReadyChannel, EndpointError> {
        self.ready.as_ref().ok_or(EndpointError::NotAdmitting)
    }

    /// Takes a fresh readiness decision, and admits new work under it.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when it is not this journal's own channel, at
    /// this journal's own settlement.
    fn admit_new_work(&mut self, ready: ReadyChannel) -> Result<(), EndpointError> {
        bind(
            &ready,
            &self.close.store,
            &self.close.signer,
            Role::Provider,
        )?;
        self.ready = Some(ready);
        Ok(())
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        self.close.state()
    }

    /// Answers one proposal.
    ///
    /// Infallible by construction: every outcome an endpoint can have is
    /// one of the six refusal codes or a co-signature, so there is one
    /// channel for answers and not two. Transport faults stay the
    /// transport's.
    ///
    /// An authenticated retry returns its retained co-signature or terminal
    /// before readiness is consulted. An unaccepted proposal already past
    /// its acceptance deadline at the persisted cursor is permanently expired.
    /// Everything still requiring a new co-signature needs a readiness
    /// decision; without one it is retryable `NotReady`.
    ///
    /// On the accepting path the client's proposal is journaled — which
    /// is what reserves the compute credit — before the co-signature is
    /// produced, and the co-signature is journaled before this returns
    /// it. A crash before the first commit leaves nothing: the client
    /// retries into a fresh admission. A crash between the two leaves a
    /// half-signed job holding its credit, and the retry co-signs it if
    /// the deadlines still allow. A crash after the second commit and
    /// before the answer reaches the client leaves an accepted job, and
    /// the retry returns the retained signature.
    pub fn accept(&mut self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        acceptance_response(self.decide(request))
    }

    fn authenticate_proposal(
        &self,
        request: &AcceptWorkRequest,
    ) -> Result<(PaidJobAuthorizationV1, Sig, Digest), Refusal> {
        let authorization = PaidJobAuthorizationV1::decode(&request.authorization)?;
        let client_signature = signature(&request.client_signature)
            .ok_or_else(|| Refusal::invalid("the client signature is not 64 bytes"))?;
        let channel = self.state().channel();
        let work_id = work_id(channel, &authorization);
        if !Secp256k1Verifier::new().verify_sig(
            client_signature,
            channel.client_key(),
            signing_hash(work_id),
        ) {
            return Err(Refusal::invalid(
                "the client signature does not authorize this proposal",
            ));
        }
        Ok((authorization, client_signature, work_id))
    }

    fn prior_acceptance(
        &self,
        authorization: &PaidJobAuthorizationV1,
        work_id: Digest,
    ) -> Result<Option<Sig>, Refusal> {
        // A question already answered is answered again, with the same
        // bytes and without re-deciding it. The deadlines are not
        // rechecked here on purpose: this co-signature is already
        // durable and already the client's, and a height that has passed
        // since cannot unsay it.
        if let Some(retained) = self.retained_signature(work_id) {
            return Ok(Some(retained));
        }
        if let Some(terminal) = self.state().terminal_by_id(work_id) {
            return Err(Refusal::new(
                WorkRefusal::Conflict,
                format!("the job ended permanently as {}", terminal.outcome.name()),
            ));
        }
        let (finalized_height, _) = self.state().cursor();
        if finalized_height > authorization.acceptance_deadline {
            return Err(PaidWorkError::AcceptanceExpired {
                height: finalized_height,
                deadline: authorization.acceptance_deadline,
            }
            .into());
        }
        Ok(None)
    }

    fn decide(&mut self, request: &AcceptWorkRequest) -> Result<(Digest, Sig), Refusal> {
        let (authorization, client_signature, work_id) = self.authenticate_proposal(request)?;
        if let Some(retained) = self.prior_acceptance(&authorization, work_id)? {
            return Ok((work_id, retained));
        }
        let ready = self
            .admitting()
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))?
            .clone();
        let (cursor_height, _) = self.state().cursor();
        let policy = ready.execution_policy();
        policy.check_authorization(ready.channel(), &authorization, cursor_height)?;
        let bundle = PreparedPaidWorkInput::decode(&request.prepared_input, MAX_RECORD_BYTES)
            .map_err(|error| Refusal::invalid(error.to_string()))?;
        policy.check_input(ready.channel(), &authorization, &bundle)?;
        ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;

        // The client's signature, its bundle, and the credit this job
        // costs, on the disk before a co-signature exists to leak.
        self.close.store.commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature,
                prepared_input: request.prepared_input.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;

        let signature = self.close.signer.sign(signing_hash(work_id));
        self.close.store.commit(
            ChannelRecord::JobAccepted {
                work_id,
                provider_signature: signature,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok((work_id, signature))
    }

    /// Returns this endpoint's co-signature over `work_id`, if it has
    /// already given one.
    fn retained_signature(&self, work_id: Digest) -> Option<Sig> {
        self.state()
            .job_by_id(work_id)
            .and_then(JobState::provider_signature)
    }

    /// Decides whether the backend may be invoked for `work_id`, and
    /// makes that decision durable before it is returned.
    ///
    /// [`RunAdmission::Invoke`] is returned only when the job was
    /// accepted and not yet running, and only after the running marker
    /// is on the disk — so a crash between the marker and the answer
    /// costs the invocation, never a second one. Every other phase past
    /// acceptance answers with what it already is: a job this process is
    /// running, a job whose result is already signed, or a job whose
    /// marker was found by a process that did not write it. A job that
    /// was never co-signed is refused rather than answered.
    ///
    /// `ready` is a *fresh* readiness decision, and the freshness is the
    /// caller's to owe in exactly the sense [`ReadyChannel`] already
    /// documents: nothing on that type re-reads the chain, so a
    /// contest opened after it was built is invisible here. What is
    /// checked is that it is this endpoint's own channel, at this
    /// endpoint's own policy, that the channel still admits work at all,
    /// and that the margins the policy measured still fit before the
    /// terminal deadline — all at the height this endpoint has processed
    /// finalized blocks through, not at the height the readiness was
    /// decided at.
    ///
    /// The request and canonical manifest it hands back are rebuilt from the
    /// bundle the journal holds, never from a quote. That bundle is the one the
    /// authorization both parties signed commits to: its digest is checked
    /// before it is stored and again on every replay
    /// (`ChannelState::apply_proposed`), so a bundle altered on disk fails when
    /// the journal is opened rather than producing a job nobody agreed to.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this
    /// `work_id`, [`RunError::NotAccepted`] before the co-signature
    /// exists, [`RunError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`RunError::Policy`] when it carries another
    /// execution policy, [`RunError::Setup`] when the deadlines can no
    /// longer be met, [`RunError::Record`] when the stored bundle does
    /// not parse, and [`RunError::Store`] when the marker cannot be
    /// made durable.
    pub fn begin_run(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
    ) -> Result<RunAdmission, RunError> {
        let job = self.state().job_by_id(work_id).ok_or(RunError::NoSuchJob)?;
        // A signed result exists in exactly the three phases past it, so
        // this is the phase test as well as the answer.
        if let Some((result, signature)) = job.result() {
            return Ok(RunAdmission::Ready {
                result: *result,
                signature: *signature,
            });
        }
        match job.phase() {
            JobPhase::Running | JobPhase::Streaming
                if self.state().job_is_indeterminate(work_id) =>
            {
                return Ok(RunAdmission::Indeterminate);
            }
            JobPhase::Running | JobPhase::Streaming => return Ok(RunAdmission::Running),
            JobPhase::Accepted => {}
            phase => return Err(RunError::NotAccepted { phase }),
        }

        bind(ready, &self.close.store, &self.close.signer, Role::Provider)?;
        if ready.execution_policy() != self.admitting()?.execution_policy() {
            return Err(RunError::Policy);
        }
        let (cursor_height, _) = self.state().cursor();
        let authorization = *job.authorization();
        // The same arithmetic the co-signature was made under, asked
        // again at the height dispatch is happening at. It is the same
        // question both times — can the measured dispatch and delivery
        // margins still fit before the terminal deadline — so it is not
        // spelled a second way here.
        ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;

        if job.prepared_input().is_empty() {
            return Ok(RunAdmission::Indeterminate);
        }
        let bundle = PreparedPaidWorkInput::decode(job.prepared_input(), MAX_RECORD_BYTES)
            .map_err(PaidWorkError::from)?;
        ready
            .execution_policy()
            .check_input(ready.channel(), &authorization, &bundle)?;
        let admission = match (bundle, ready.execution_policy()) {
            (PreparedPaidWorkInput::Evaluate(bundle), PaidWorkPolicy::Evaluate(_)) => {
                RunAdmission::Invoke(Box::new(PreparedEvaluateInput {
                    parts: bundle.parts().map_err(PaidWorkError::from)?,
                }))
            }
            (PreparedPaidWorkInput::Fetch(bundle), PaidWorkPolicy::Fetch { policy, .. }) => {
                RunAdmission::InvokeFetch(Box::new(PreparedFetchInput {
                    parts: bundle.parts().map_err(PaidWorkError::from)?,
                    policy: *policy,
                }))
            }
            _ => return Err(RunError::Policy),
        };

        self.close.store.commit(
            ChannelRecord::JobRunning { work_id },
            &Secp256k1Verifier::new(),
        )?;
        Ok(admission)
    }

    /// Signs the result of the transcript this job's invocation
    /// produced, and returns it only once it is on the disk.
    ///
    /// The transcript is the provider's own: [`hellas_rpc::protocol::work::terminal_result`] refuses
    /// events that are not one verified chain for this authorization's
    /// request under the channel's provider key, and the journal refuses
    /// the record unless the job is running, is not indeterminate, and
    /// the result names it. Nothing here accepts a commitment chosen by
    /// anyone else, because nothing here takes one.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this `work_id`,
    /// [`RunError::Transcript`] when the events are not this job's
    /// terminal transcript, [`RunError::Record`] when the transcript is
    /// larger than the signed policy's spool or the delivery it would
    /// become is larger than the signed frame, and [`RunError::Store`]
    /// when the journal refuses the record — which is what it does for a
    /// job that is not running, or one left indeterminate by a crash.
    pub fn record_result(
        &mut self,
        work_id: Digest,
        transcript: &[OutputEventEnvelope],
    ) -> Result<(PaidJobResultV1, Sig), RunError> {
        let job = self.state().job_by_id(work_id).ok_or(RunError::NoSuchJob)?;
        let authorization = *job.authorization();
        let input = PreparedPaidWorkInput::decode(job.prepared_input(), MAX_RECORD_BYTES)
            .map_err(|e| RunError::Transcript(e.into()))?;
        let ready = self.admitting()?.clone();
        let channel = ready.channel();
        let result = ready
            .execution_policy()
            .terminal_result(channel, &authorization, &input, transcript)
            .map_err(RunError::Transcript)?;
        let spool = encode_transcript(transcript).map_err(RunError::Transcript)?;
        let spooled = u64::try_from(spool.len()).unwrap_or(u64::MAX);
        let limit = ready.execution_policy().max_spool_bytes();
        if spooled > limit {
            return Err(RunError::Record(PaidWorkError::OverEnvelope {
                field: "spooled transcript length",
                actual: spooled,
                limit,
            }));
        }
        let signature = self
            .close
            .signer
            .sign(signing_hash(result_digest(channel, &result)));
        // The delivery this result will become, measured before it is
        // recorded. The client refuses a frame over the bound both
        // parties signed, so a result that does not fit is one the
        // client cannot record a receipt for and therefore cannot pay
        // for — and recording it anyway would leave a job the ending
        // ledger charges this client for over an answer it was never
        // able to take. The client's own check is the other end of the
        // same bound, against a provider that does not apply this one.
        let delivered = WorkDelivered {
            result: result.encode(),
            provider_signature: signature.as_bytes().to_vec(),
            transcript: spool.clone(),
        };
        let frame = if matches!(ready.execution_policy(), PaidWorkPolicy::Fetch { .. }) {
            if spool.len() > hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES {
                return Err(RunError::Record(PaidWorkError::OverEnvelope {
                    field: "Fetch transcript",
                    actual: spool.len() as u64,
                    limit: hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES as u64,
                }));
            }
            stream::fetch_frames(
                &delivered,
                transcript,
                ready.execution_policy().max_encoded_result_frame(),
            )
            .try_fold(0, |size, frame| {
                Ok::<_, RunError>(size.max(frame?.encoded_len() as u64))
            })?
        } else {
            delivered.encoded_len() as u64
        };
        let frame_limit = u64::from(ready.execution_policy().max_encoded_result_frame())
            .min(hellas_wire::frame::MAX_FRAME_BYTES as u64);
        if frame > frame_limit {
            return Err(RunError::Record(PaidWorkError::OverEnvelope {
                field: "encoded result frame",
                actual: frame,
                limit: frame_limit,
            }));
        }
        self.close.store.commit(
            ChannelRecord::JobResult {
                work_id,
                result,
                provider_signature: signature,
                transcript: spool,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok((result, signature))
    }

    /// Releases the answer for a job whose result is signed and durable.
    ///
    /// The order is the module's rule applied to plaintext: the release
    /// is journaled — which is what debits this client's delivery
    /// credit — before a byte of the answer is returned. A crash between
    /// the two costs a round trip and no credit: the retry finds the job
    /// already delivered, re-commits the same marker as a redundant
    /// step, and hands back the same bytes.
    ///
    /// That is the whole of the idempotence claim, and it is worth being
    /// exact about its key. The marker is per open job, not per
    /// `(work_id, result_digest)` pair, because a job has at most one
    /// result: the journal refuses a second one for the same job
    /// outright. So a replay carrying a different result is not a
    /// conflict resolved here — it is a request this endpoint has no
    /// second answer to give.
    ///
    /// The deadline is checked on every call, including replays. A
    /// release begun too late to arrive is refused even though the
    /// plaintext already left on the first attempt, because the client's
    /// own journal refuses a receipt past the same deadline: bytes it
    /// may not record are bytes it cannot pay for.
    ///
    /// # Errors
    ///
    /// [`DeliverError::Malformed`] when a field is not the identifier
    /// or signature it must be, [`DeliverError::NoSuchJob`] when neither
    /// an open job nor a retained terminal carries this `work_id`,
    /// [`DeliverError::Terminated`] when the job has ended permanently,
    /// [`DeliverError::Unbound`] when
    /// the signature is not the channel's client's over this connection,
    /// [`DeliverError::NoResult`] before the result is
    /// signed, [`DeliverError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`DeliverError::Policy`] when it carries
    /// another execution policy, [`DeliverError::Setup`] when
    /// the delivery margin no longer fits, and [`DeliverError::Store`]
    /// when the release cannot be made durable — which is what happens
    /// when this client's delivery credit is exhausted.
    pub fn deliver(
        &mut self,
        request: &DeliverResultRequest,
        ready: &ReadyChannel,
        exporter: &[u8; 32],
    ) -> Result<Delivery, DeliverError> {
        self.deliver_with_readiness(request, Some(ready), exporter)
    }

    /// A retained terminal needs authentication, but no permission to admit
    /// new work. Actual delivery still uses this endpoint's readiness, or
    /// the explicitly supplied decision checked against it below.
    fn deliver_with_readiness(
        &mut self,
        request: &DeliverResultRequest,
        ready: Option<&ReadyChannel>,
        exporter: &[u8; 32],
    ) -> Result<Delivery, DeliverError> {
        let work_id = work_id_bytes(&request.work_id).ok_or(DeliverError::Malformed("work id"))?;
        let signature = signature(&request.client_signature)
            .ok_or(DeliverError::Malformed("client signature"))?;
        let channel = self.state().channel();
        // Who is asking, on this connection. A `work_id` says which job;
        // it says nothing about who may be handed it, and it travels —
        // so without this the plaintext goes to whoever learned one, and
        // the debit for it lands on the client that never asked.
        if !Secp256k1Verifier::new().verify_sig(
            signature,
            channel.client_key(),
            signing_hash(delivery_request_digest(channel, work_id, exporter)),
        ) {
            return Err(DeliverError::Unbound);
        }
        let job = self.state().job_by_id(work_id).ok_or_else(|| {
            self.state()
                .terminal_by_id(work_id)
                .map_or(DeliverError::NoSuchJob, |terminal| {
                    DeliverError::Terminated {
                        outcome: terminal.outcome.name(),
                    }
                })
        })?;
        let admitted = self.admitting()?.clone();
        let ready = ready.unwrap_or(&admitted);
        let Some((result, signature)) = job.result() else {
            return Err(DeliverError::NoResult { phase: job.phase() });
        };
        let (result, signature) = (*result, *signature);
        let transcript = job.transcript().to_vec();
        if transcript.is_empty() {
            return Err(DeliverError::NoResult { phase: job.phase() });
        }
        let terminal_deadline = job.authorization().terminal_deadline;

        bind(ready, &self.close.store, &self.close.signer, Role::Provider)?;
        if ready.execution_policy() != admitted.execution_policy() {
            return Err(DeliverError::Policy);
        }
        let (cursor_height, _) = self.state().cursor();
        ready.check_releasable(cursor_height, terminal_deadline)?;

        self.close.store.commit(
            ChannelRecord::PlaintextReleased { work_id },
            &Secp256k1Verifier::new(),
        )?;
        Ok(Delivery {
            result,
            signature,
            transcript,
        })
    }

    /// Admits one client payment, and returns what it credited only once
    /// that is on the disk.
    ///
    /// The record it commits is the one that retires this job's compute
    /// and delivery credit, so the credit is released in the same fsync
    /// that admits the certificate, and both happen before the caller
    /// has an answer to acknowledge with. A crash before the commit
    /// releases nothing and credits nothing: the client re-sends the
    /// bytes its own journal retained. A crash after it leaves the
    /// payment durable, and the re-send is recognised as the same
    /// payment and answered with the same number.
    ///
    /// A refused payment leaves nothing behind, certificate included.
    /// Every certificate on this channel is one half of a payment this
    /// provider's own ledger derived — the price from the authorization
    /// it co-signed, the cumulative from what it has already credited —
    /// so a certificate its binding does not account for is not money
    /// that was earned and mis-labelled, it is a client sending
    /// something no honest path produces. Banking it would also bank it
    /// for a job whose loss this endpoint may already have written to
    /// the client's ledger, and nothing takes a loss back: the client
    /// would then have been charged for the job *and* paid for it.
    ///
    /// # Errors
    ///
    /// [`PaymentError::Malformed`] when a field is not the record or
    /// signature it must be, [`PaymentError::Record`] when the
    /// certificate does not decode, and [`PaymentError::Store`] for
    /// every rule the journal applies — the client's two signatures, the
    /// binding and certificate against the ledger, and the phase this
    /// job is in.
    pub fn admit(&mut self, request: &AdmitCertificateRequest) -> Result<u64, PaymentError> {
        let certificate = earned_certificate(&request.certificate)
            .ok_or(PaymentError::Malformed("certificate"))?;
        let binding = PaymentBindingV1::decode(&request.binding)?;
        let work_id = binding.work_id;
        let binding_signature = signature(&request.binding_signature)
            .ok_or(PaymentError::Malformed("binding signature"))?;
        let certificate_signature = signature(&request.certificate_signature)
            .ok_or(PaymentError::Malformed("certificate signature"))?;

        let state = self.close.store.commit(
            ChannelRecord::JobTerminated {
                work_id,
                outcome: TerminalOutcome::Certified {
                    certificate,
                    binding: Box::new(binding),
                    binding_signature,
                    certificate_signature,
                },
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(state.ledger().credited_cumulative())
    }

    /// Ends the open job as this provider's own failure, releasing
    /// what it still holds.
    ///
    /// There is no reason to pass, and that is the point. The only
    /// ending a caller here can ask for is the one that charges this
    /// client nothing: a backend that faulted, or a transcript that is
    /// not this job's, is the provider's side going wrong. The ending
    /// that *does* charge a client — a deadline it signed and let pass
    /// — is decided from finalized heights by `work_close::observe`
    /// and nowhere else, so no local caller can reach it by choosing an
    /// argument.
    ///
    /// # Errors
    ///
    /// [`RunError::NoSuchJob`] when no open job carries this `work_id`,
    /// and [`RunError::Store`] when the ending cannot be made durable.
    pub fn end_run(&mut self, work_id: Digest) -> Result<(), RunError> {
        self.state().job_by_id(work_id).ok_or(RunError::NoSuchJob)?;
        self.close.store.commit(
            ChannelRecord::JobTerminated {
                work_id,
                outcome: TerminalOutcome::Failed {
                    code: PROVIDER_FAULT_CODE,
                },
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(())
    }
}

/// The failure code a provider records when it ends its own job — a
/// backend fault or a transcript that is not this job's. There is one
/// because [`ProviderEndpoint::end_run`] is the one provider-chosen
/// ending, and it is always the provider's own side going wrong.
const PROVIDER_FAULT_CODE: u32 = 1;

// ── Settling on chain ─────────────────────────────────────────────────

/// Retains one signed close start, and samples what making it durable
/// cost.
///
/// `close_prepared_fsync_ms`, as §4's `Wstart` names it: an endpoint
/// that wants a close on a chain waits for this before the bytes may
/// leave, so it is an addend of the wait a start is signed against.
/// Both endpoints prepare their own close and both go through here, so
/// there is one spelling of the record and one of the sample.
fn retain_close_start(
    store: &mut ChannelStore,
    start: &PaymentCloseStart,
) -> Result<(), WorkStoreError> {
    let fsynced = Timing::start();
    store.commit(
        ChannelRecord::ClosePrepared {
            start: Box::new(start.clone()),
        },
        &Secp256k1Verifier::new(),
    )?;
    if let Some(ms) = fsynced.ms() {
        tracing::event!(
            name: "close_prepared_fsync_ms",
            target: TARGET,
            LEVEL,
            edge = %hex(&start.payment_edge().to_bytes()),
            valid_through = start.valid_through_height(),
            ms,
        );
    }
    Ok(())
}

/// Everything a close is, and not one line of it reads a readiness
/// decision.
///
/// That is the whole of what makes "`check_ready` gates new work only"
/// true here rather than asserted in a comment: these methods are
/// defined on a type that has no [`ReadyChannel`] to read.
impl CloseEndpoint {
    /// Applies one finalized block: every transition it carries, then
    /// the cursor that says it was read.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError`] when the block is not the contiguous next one,
    /// or a transition it carries is refused.
    pub fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&ChannelState, WorkStoreError> {
        observe(&mut self.store, block, &Secp256k1Verifier::new())?;
        Ok(self.store.state())
    }

    /// Reads every finalized block this endpoint has not seen.
    ///
    /// # Errors
    ///
    /// [`CatchUpError`] when the source fails, a block in range cannot
    /// be read, or the journal refuses one.
    pub async fn catch_up<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<u64, CatchUpError> {
        catch_up(source, &mut self.store, &Secp256k1Verifier::new()).await
    }

    /// Signs the close start that spends this channel's certificate,
    /// and retains its exact bytes before returning them.
    ///
    /// This is the write-ahead cutoff. Committing first is what stops
    /// the provider admitting a certificate it has just decided to
    /// leave out; the caller gets the bytes only after the disk holds
    /// them, so a crash before the chain sees them costs a
    /// resubmission and nothing else.
    ///
    /// Called again it returns the retained start rather than signing a
    /// second one — until the cursor has passed the last height that
    /// signature could have been included at, when a start that can no
    /// longer land is replaced by one that can.
    ///
    /// # Errors
    ///
    /// [`CloseError::Store`] when a job is still open, a contest is
    /// already live, or the journal refuses the record, and the window
    /// errors [`close_start`] raises.
    pub fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
        let (height, _) = self.state().cursor();
        if let Some(retained) = self.state().includable_close_start(height) {
            return Ok(retained.clone());
        }
        let channel = self.state().channel().clone();
        let start = close_start(
            &channel,
            Party::Taker,
            height,
            self.state().executable_certificate(),
            &self.signer,
        )?;
        retain_close_start(&mut self.store, &start)?;
        Ok(start)
    }

    /// Reads to the tip, resubmits this endpoint's retained close start
    /// if it has not landed, and answers a contest opened below what it
    /// holds.
    ///
    /// The order is the one a crash has to survive. The read stops on
    /// the block that opens a contest — or, after a restart, before any
    /// block at all — so the answer is fixed on the disk and offered
    /// before this endpoint reads a successor. What ends the answering
    /// is not that write: a sink that *took* the answer
    /// ([`SubmitTxOutcome::Enqueued`] or [`SubmitTxOutcome::Duplicate`])
    /// ends it, a sink that did not ([`SubmitTxOutcome::Full`],
    /// [`SubmitTxOutcome::ValidationRejected`]) leaves it owed for the
    /// next pass — which reads one successor block and then owes it
    /// again — and the contest running out ends it either way.
    ///
    /// # Errors
    ///
    /// [`CatchUpError`] when the source fails, a block in range cannot
    /// be read, the journal refuses one, or the sink will not take the
    /// transaction.
    pub async fn advance_close<S, T>(
        &mut self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        advance_close(source, sink, self, &Secp256k1Verifier::new()).await
    }

    /// Fixes this endpoint's answer to `start_id` on the disk and
    /// returns the transaction that carries it.
    ///
    /// Durable before broadcast: the record is what refuses a second,
    /// different answer to this contest, and a record the state already
    /// holds is not written twice — so a resubmission after a failed
    /// hand-off costs no fsync and sends the same bytes.
    fn fix_close_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, WorkStoreError> {
        let Some((responded, response)) = self.close_duty(start_id) else {
            return Ok(None);
        };
        self.store.commit(responded, &Secp256k1Verifier::new())?;
        Ok(Some(response))
    }

    /// Records what a sink did with the answer to `start_id`.
    ///
    /// The two outcomes that mean *not enqueued* are the ones that leave
    /// the answer owed, and this is the one place that reading is made.
    const fn record_close_handoff(&mut self, start_id: StartId, outcome: SubmitTxOutcome) {
        let handoff = match outcome {
            SubmitTxOutcome::Enqueued | SubmitTxOutcome::Duplicate => Handoff::Accepted,
            SubmitTxOutcome::Full | SubmitTxOutcome::ValidationRejected => Handoff::Offered,
        };
        self.close_handoff = Some((start_id, handoff));
    }

    /// The contest whose answer a sink has taken, and so the one contest
    /// this endpoint's reads are excused from stopping for.
    ///
    /// [`Handoff::Offered`] is deliberately not one. The block it buys
    /// is bought inside one close step, where the retry that spends it
    /// is; a read that is not answering anything gets no such credit,
    /// and stops.
    const fn accepted_contest(&self) -> Option<StartId> {
        match self.close_handoff {
            Some((start_id, Handoff::Accepted)) => Some(start_id),
            _ => None,
        }
    }

    /// Builds this provider's answer to a journaled contest, and the
    /// record that must reach the disk before it is sent — or `None`
    /// when this endpoint owes no answer.
    ///
    /// Whether one is owed is
    /// [`ChannelState::answerable_contest`]'s judgement and no second
    /// spelling of it: the client is the opener, the response window is
    /// still open at the cursor, and this endpoint's certificate strictly
    /// exceeds the opener's claim. A contest failing any of those is not
    /// a duty this endpoint is waiting to discharge — all three were
    /// frozen by the block that recorded the contest — so nothing is
    /// built and nothing stops the cursor.
    ///
    /// It builds the same answer again while the answer is already
    /// journaled, and that is deliberate: the bytes are retained by
    /// being derivable from those same two frozen values, so an endpoint
    /// whose submission was refused offers them again, and the journal's
    /// own rule — one answer per contest — is what makes the second
    /// offer the first one rather than a new decision. What it will not
    /// do is offer them to a sink that already took them.
    fn close_duty(&self, start_id: StartId) -> Option<(ChannelRecord, Tx)> {
        if self.accepted_contest() == Some(start_id) {
            return None;
        }
        let (contest, certificate) = self.state().answerable_contest()?;
        if contest.start_id != start_id {
            return None;
        }
        let channel = self.state().channel();
        let response = close_response(channel, start_id, certificate, &self.signer);
        Some((
            ChannelRecord::CloseResponded {
                start_id,
                response_digest: response_body_digest(channel, start_id, &certificate.0),
            },
            Tx::move_action(Move::RespondPaymentClose(response)),
        ))
    }

    /// Builds the close that ends this endpoint's contest.
    ///
    /// `observed` is one coherent finalized read; the contest record it
    /// carries is what consensus itself holds, and the payouts are
    /// derived from it. Nothing durable is written, because nothing
    /// here is a decision: after any crash this is rebuilt from a fresh
    /// read and is the same transaction.
    ///
    /// The contest must be the one this endpoint's own watcher saw
    /// finalized. That is what makes a snapshot showing *some* contest
    /// insufficient: until the cursor has read the block that opened
    /// it, this endpoint does not know it is its own.
    ///
    /// # Errors
    ///
    /// [`CloseError::NoContest`] when no contest of this endpoint's is
    /// live at that read, [`CloseError::OtherContest`] when the live
    /// one is another, [`CloseError::ResponseWindowOpen`] when the
    /// provider's window has not run out, and [`CloseError::Unpayable`]
    /// when the settled total does not fit the route.
    pub fn adjudicated_close(&self, observed: &ObservedChannel<'_>) -> Result<Tx, CloseError> {
        let (held, _) = self.state().close_opened().ok_or(CloseError::NoContest)?;
        let PendingSlot::Present(record) = observed.pending else {
            return Err(CloseError::NoContest);
        };
        if record.start_id() != held {
            return Err(CloseError::OtherContest);
        }
        if !record.responded() && observed.height < record.response_deadline() {
            return Err(CloseError::ResponseWindowOpen {
                height: observed.height,
                deadline: record.response_deadline(),
            });
        }
        adjudicated_close(self.state().channel(), self.state().settlement(), &record)
    }

    /// Builds the one answer to a contest opened below what this
    /// provider holds.
    ///
    /// The contest may be either side's — this is the answer to a
    /// *client* that opened at less than it has already signed for, and
    /// it is the whole of what the funded omission bond deters. Only
    /// the certificate's beneficiary may answer, which is why there is
    /// no client counterpart to this.
    ///
    /// The answer is fixed on this endpoint's own disk before the bytes
    /// are returned, exactly as [`Self::advance_close`] fixes it before
    /// it sends them. That is not decoration: a caller given signed
    /// bytes over a journal that never recorded them could put an answer
    /// on chain this endpoint has no record of giving, and the journal
    /// would then owe — and refuse — that same answer.
    ///
    /// # Errors
    ///
    /// [`CloseError::NoContest`] and [`CloseError::OtherContest`] as
    /// above, [`CloseError::AlreadyResponded`] once the one answer has
    /// landed, [`CloseError::ResponseWindowClosed`] at or after the
    /// deadline — the kernel refuses an answer exactly there — and
    /// [`CloseError::NothingToAdd`] when this endpoint holds nothing
    /// the contest does not already settle. [`CloseError::Store`] when
    /// the journal refuses the answer, which is where the contest and
    /// the certificate the answer is derived from are re-checked.
    pub fn respond_to_close(&mut self, observed: &ObservedChannel<'_>) -> Result<Tx, CloseError> {
        let (held, _) = self.state().close_opened().ok_or(CloseError::NoContest)?;
        let PendingSlot::Present(record) = observed.pending else {
            return Err(CloseError::NoContest);
        };
        if record.start_id() != held {
            return Err(CloseError::OtherContest);
        }
        if record.responded() {
            return Err(CloseError::AlreadyResponded);
        }
        // Strictly below the deadline, which is the kernel's own rule:
        // an answer landing exactly at it is late.
        if observed.height >= record.response_deadline() {
            return Err(CloseError::ResponseWindowClosed {
                height: observed.height,
                deadline: record.response_deadline(),
            });
        }
        let certificate = self
            .state()
            .executable_certificate()
            .filter(|(certificate, _)| certificate.earned_cumulative() > record.final_cumulative())
            .ok_or(CloseError::NothingToAdd {
                held: self.state().max_executable_certificate(),
                settled: record.final_cumulative(),
            })?;
        let channel = self.state().channel().clone();
        let response = close_response(&channel, held, certificate, &self.signer);
        self.store.commit(
            ChannelRecord::CloseResponded {
                start_id: held,
                response_digest: response_body_digest(&channel, held, &certificate.0),
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(Tx::move_action(Move::RespondPaymentClose(response)))
    }
}

/// The close half is reachable through the whole endpoint, unchanged.
///
/// Forwarding rather than a second implementation: there is one close
/// sequence on this channel, and this is the same one, reached from the
/// endpoint that also admits work.
impl ProviderEndpoint {
    /// Applies one finalized block, as [`CloseEndpoint::observe_finalized`]
    /// does.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::observe_finalized`] raises.
    pub fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&ChannelState, WorkStoreError> {
        self.close.observe_finalized(block)
    }

    /// Reads every finalized block this endpoint has not seen.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::catch_up`] raises.
    pub async fn catch_up<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<u64, CatchUpError> {
        self.close.catch_up(source).await
    }

    /// Signs, or returns, this channel's retained close start.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::prepare_close`] raises.
    pub fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
        self.close.prepare_close()
    }

    /// Runs one close step.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::advance_close`] raises.
    pub async fn advance_close<S, T>(
        &mut self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        self.close.advance_close(source, sink).await
    }

    /// Builds the close that ends this endpoint's contest.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::adjudicated_close`] raises.
    pub fn adjudicated_close(&self, observed: &ObservedChannel<'_>) -> Result<Tx, CloseError> {
        self.close.adjudicated_close(observed)
    }

    /// Builds the one answer to a contest opened below what this
    /// provider holds.
    ///
    /// # Errors
    ///
    /// Whatever [`CloseEndpoint::respond_to_close`] raises.
    pub fn respond_to_close(&mut self, observed: &ObservedChannel<'_>) -> Result<Tx, CloseError> {
        self.close.respond_to_close(observed)
    }
}

/// A provider that owns its journal outright lends it directly, and owns
/// the answer it may have to give.
impl CloseChannel for CloseEndpoint {
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut ChannelStore) -> R,
    ) -> Result<R, CatchUpError> {
        Ok(step(&mut self.store))
    }

    fn handoff(&mut self) -> Result<Option<(StartId, Handoff)>, CatchUpError> {
        Ok(self.close_handoff)
    }

    fn fix_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, CatchUpError> {
        Ok(self.fix_close_answer(start_id)?)
    }

    fn record_handoff(
        &mut self,
        start_id: StartId,
        outcome: SubmitTxOutcome,
    ) -> Result<(), CatchUpError> {
        self.record_close_handoff(start_id, outcome);
        Ok(())
    }
}

/// A client lends its journal and nothing else: no contest is ever its
/// to answer, so the three defaulted answers are the true ones.
impl CloseChannel for ClientEndpoint {
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut ChannelStore) -> R,
    ) -> Result<R, CatchUpError> {
        Ok(step(&mut self.store))
    }
}

impl ClientEndpoint {
    /// Applies one finalized block: every transition it carries, then
    /// the cursor that says it was read.
    ///
    /// # Errors
    ///
    /// [`WorkStoreError`] when the block is not the contiguous next one,
    /// or a transition it carries is refused.
    pub fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&ChannelState, WorkStoreError> {
        observe(&mut self.store, block, &Secp256k1Verifier::new())?;
        Ok(self.store.state())
    }

    /// Reads every finalized block this endpoint has not seen.
    ///
    /// # Errors
    ///
    /// [`CatchUpError`] when the source fails, a block in range cannot
    /// be read, or the journal refuses one.
    pub async fn catch_up<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<u64, CatchUpError> {
        catch_up(source, &mut self.store, &Secp256k1Verifier::new()).await
    }
}

// ── Running an accepted job ───────────────────────────────────────────

/// Why the local execution backend produced no transcript.
///
/// Opaque on purpose. What the gate does about it — release the job and
/// charge the client nothing — is the same for every fault a backend can
/// have, so distinguishing them here would be a distinction nothing
/// reads.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the execution backend failed: {0}")]
pub struct BackendFault(String);

impl BackendFault {
    /// Records one backend fault, by its operator-facing text.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// The complete journaled input handed to a paid Evaluate backend.
///
/// All six bodies come from the same strictly decoded [`hellas_rpc::protocol::artifacts::PreparedPaidInputV1`]
/// whose digest the parties signed. Keeping the execution, tokens, policy, and
/// identity here is what lets a backend run after restart without depending on
/// transient Courtesy state. Environment bytes remain content-store data below
/// the manifest root and do not cross this seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedEvaluateInput {
    parts: PreparedPaidInputParts,
}

impl PreparedEvaluateInput {
    /// Returns the Evaluate request rebuilt from the journal.
    #[must_use]
    pub const fn evaluate_request(&self) -> &EvaluateRequest {
        &self.parts.evaluate_request
    }

    /// Returns the exact canonical ProgramManifest bytes from the journal.
    #[must_use]
    pub fn program_manifest(&self) -> Vec<u8> {
        self.parts.manifest.canonical_bytes()
    }

    /// Transfers all six strictly decoded bodies to the backend implementation.
    #[must_use]
    pub fn into_parts(self) -> PreparedPaidInputParts {
        self.parts
    }
}

/// A paid Fetch input admitted under a channel policy. It is held only in
/// memory on the provider, even while the job's accounting state is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFetchInput {
    parts: PreparedPaidFetchInputParts,
    policy: PaidFetchPolicyV1,
}

impl PreparedFetchInput {
    /// Returns the fixed output bounds the provider must enforce while running.
    pub const fn policy(&self) -> &PaidFetchPolicyV1 {
        &self.policy
    }

    /// Transfers the signed request and canonical manifest to the backend.
    pub fn into_parts(self) -> PreparedPaidFetchInputParts {
        self.parts
    }
}

/// The one seam a paid job crosses on its way to real execution.
///
/// The endpoint selects Evaluate or Fetch from the admitted profile and passes
/// the verified prepared input. Evaluate inputs survive journal recovery;
/// Fetch bodies exist only in this process's memory. Implement only the profiles
/// the backend serves; unsupported profiles fail without running work.
/// What comes back is the complete signed transcript of that invocation — not
/// a digest of one, because a digest is exactly what a backend that ran nothing
/// could also return.
///
/// Implementors must invoke once per call. That is not a property this
/// trait can check, and it is not the one the gate rests on: the gate
/// calls this at most once per `work_id` whatever the implementor does.
pub trait PaidWorkBackend: Sync {
    /// Runs an authorized Fetch without persisting request or response bodies.
    fn fetch(
        &self,
        _input: PreparedFetchInput,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async { Err(BackendFault::new("paid fetch backend is unavailable")) }
    }

    /// Runs once, exposing signed Fetch prefixes before terminal delivery.
    fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        progress: PaidProgress,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async move {
            let events = self.fetch(input).await?;
            for event in &events {
                if event.event().body().kind() == hellas_rpc::fetch::OUTPUT_EVENT_KIND {
                    progress(event.clone())?;
                }
            }
            Ok(events)
        }
    }
    /// Runs one journaled Evaluate input to its terminal.
    fn evaluate(
        &self,
        _input: PreparedEvaluateInput,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async { Err(BackendFault::new("paid evaluate backend is unavailable")) }
    }

    /// Run once, exposing authenticated token prefixes while retaining the
    /// complete transcript for durable terminal delivery.
    fn evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: PaidProgress,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async move {
            let events = self.evaluate(input).await?;
            for event in &events {
                if event.event().body().kind() == hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND {
                    progress(event.clone())?;
                }
            }
            Ok(events)
        }
    }
}

/// What [`ProviderEndpoint::begin_run`] found, and what may be done next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunAdmission {
    /// The marker is durable and the backend has not been called.
    /// Invoke exactly once, with this journaled input.
    Invoke(Box<PreparedEvaluateInput>),
    /// The fetch running marker is durable; invoke once with the in-memory input.
    InvokeFetch(Box<PreparedFetchInput>),
    /// This process marked the job and has not recorded its result.
    Running,
    /// A signed result already exists.
    Ready {
        /// The result.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// A prior process left a running marker, or an accepted Fetch lost its
    /// in-memory input. Neither case is automatically re-executed.
    Indeterminate,
}

/// What one run of an accepted job produced.
///
/// [`Self::Completed`] is returned by at most one call per `work_id`,
/// ever: it is the answer of the call that invoked the backend. It is
/// *at most* rather than exactly one because that call can still fault —
/// a backend that refuses, or a journal that will not take the result,
/// leaves a job whose `Completed` never comes.
///
/// Neither variant carries the transcript, and no caller needs one to:
/// the invocation's events are journaled beside the result, and
/// [`ProviderEndpoint::deliver`] is what serves them. Handing them back
/// here as well would put the answer in two places and make the second
/// one look authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    /// This call invoked the backend and recorded its terminal.
    Completed {
        /// The result, now durable.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// A signed result was already durable.
    Ready {
        /// The result.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        signature: Sig,
    },
    /// The job is running in this process. Ask again.
    Running,
    /// A crash left the invocation unresolved.
    Indeterminate,
}

/// Why one run of an accepted job did not produce a result.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The phase-boundary finalized-history catch-up did not complete.
    #[error("dispatch catch-up failed: {0}")]
    CatchUp(String),
    /// No open job on this channel carries this `work_id`.
    #[error("no open job on this channel carries this work id")]
    NoSuchJob,
    /// The job has no provider co-signature, so nothing authorises
    /// running it.
    #[error("a {phase} job has not been accepted, and may not run")]
    NotAccepted {
        /// How far the job has got.
        phase: JobPhase,
    },
    /// The readiness offered is not this endpoint's own channel.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The readiness offered carries another execution policy than the
    /// one this endpoint accepts work under.
    #[error("the readiness offered was decided under another execution policy")]
    Policy,
    /// The deadlines can no longer be met, or the endpoint is behind.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The stored bundle is not a readable prepared input.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// The events offered are not this job's terminal transcript.
    #[error(transparent)]
    Transcript(PaidWorkError),
    /// The backend produced no transcript.
    #[error(transparent)]
    Backend(BackendFault),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
}

/// Runs one accepted job on a real backend, at most once, ever.
///
/// The order, and the whole of why it is this order: the running marker
/// is journaled while the endpoint lock is held, the lock is then
/// released, and only then is the backend called. Releasing the lock is
/// deliberate — a synchronous journal must not be held across an
/// invocation that takes minutes — and it is safe because the marker on
/// the disk, not the lock, is what excludes a second call. A concurrent
/// call finds the job running; a call after a restart finds it
/// indeterminate.
///
/// A backend fault, or a transcript that is not this job's, ends the job
/// as failed. That releases the compute the co-signature reserved and
/// charges this client nothing, because neither is the client's doing.
///
/// # Errors
///
/// [`RunError::Backend`] for a backend fault and [`RunError::Transcript`]
/// for events that are not this job's terminal transcript — in both
/// cases after the job has been ended. If *that* ending cannot be
/// journaled, the journal's error is returned in place of the fault:
/// a job left running by a store that will not take its ending is the
/// more urgent fact, and it is the one an operator must see. Whatever
/// [`ProviderEndpoint::begin_run`] and [`ProviderEndpoint::record_result`]
/// raise otherwise.
pub async fn run_accepted_work<B>(
    service: &WorkService,
    ready: &ReadyChannel,
    backend: &B,
    work_id: Digest,
) -> Result<RunOutcome, RunError>
where
    B: PaidWorkBackend + Sync,
{
    let admission = service.begin_run(work_id, ready)?;
    let progress_service = service.clone();
    let progress: PaidProgress =
        Arc::new(move |event| progress_service.publish_progress(work_id, event));
    let invoked = match admission {
        RunAdmission::Invoke(input) => backend.evaluate_stream(*input, progress).await,
        RunAdmission::InvokeFetch(input) => backend.fetch_stream(*input, progress).await,
        RunAdmission::Running => return Ok(RunOutcome::Running),
        RunAdmission::Indeterminate => return Ok(RunOutcome::Indeterminate),
        RunAdmission::Ready { result, signature } => {
            return Ok(RunOutcome::Ready { result, signature });
        }
    };

    let transcript = match invoked {
        Ok(transcript) => transcript,
        Err(fault) => return Err(end_failed(service, work_id, RunError::Backend(fault))),
    };

    let recorded = service.record_result(work_id, &transcript);
    match recorded {
        Ok((result, signature)) => Ok(RunOutcome::Completed { result, signature }),
        // A transcript that is not this job's, and a result the signed
        // envelope would not carry, are the same kind of fault: the
        // backend produced something this provider cannot turn into a
        // delivery. Both end the job, and both charge the client
        // nothing.
        Err(fault @ (RunError::Transcript(_) | RunError::Record(_))) => {
            Err(end_failed(service, work_id, fault))
        }
        Err(error) => Err(error),
    }
}

/// Dispatch workflow with the post-boundary cursor rule: the endpoint is
/// released while finalized blocks are fetched, caught up contiguously, and
/// only then reacquired for `JobRunning`.
pub async fn run_accepted_work_after_catch_up<S, B>(
    service: &WorkService,
    source: &S,
    ready: &ReadyChannel,
    backend: &B,
    work_id: Digest,
) -> Result<RunOutcome, RunError>
where
    S: FinalizedBlocks + ?Sized,
    B: PaidWorkBackend + Sync,
{
    service
        .catch_up_job(source, work_id)
        .await
        .map_err(|error| RunError::CatchUp(error.to_string()))?;
    run_accepted_work(service, ready, backend, work_id).await
}

// ── Delivering the answer ─────────────────────────────────────────────

/// One whole delivery: the signed result and the transcript it
/// summarises.
///
/// The two travel together because neither is the answer alone. The
/// result is a pair of digests the provider stands behind; the
/// transcript is the signed events those digests are over, and the
/// tokens the client actually wanted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The provider's signature over its digest.
    pub signature: Sig,
    /// The encoded transcript, as [`decode_transcript`] reads it.
    pub transcript: Vec<u8>,
}

/// Why one delivery did not happen.
#[derive(Debug, thiserror::Error)]
pub enum DeliverError {
    /// No open job on this channel carries this `work_id`.
    #[error("no open job on this channel carries this work id")]
    NoSuchJob,
    /// The retained terminal records a permanent end to this job.
    #[error("the job ended permanently as {outcome}")]
    Terminated {
        /// The terminal's stable diagnostic name, without backend details.
        outcome: &'static str,
    },
    /// The job has no signed result, so there is nothing to deliver.
    #[error("a {phase} job has no result to deliver")]
    NoResult {
        /// How far the job has got.
        phase: JobPhase,
    },
    /// The readiness offered is not this endpoint's own channel.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The readiness offered carries another execution policy than the
    /// one this endpoint works under.
    #[error("the readiness offered was decided under another execution policy")]
    Policy,
    /// The delivery margin no longer fits, or the endpoint is behind.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The request is not this channel's client's, on this connection.
    #[error("the delivery request is not this channel's client's over this connection")]
    Unbound,
    /// The transport exposes no connection exporter, so nothing here
    /// can be bound to it.
    #[error("this transport exposes no connection exporter to bind a delivery request to")]
    Unbindable,
    /// The response is larger than the frame both parties authorized.
    #[error("the delivered frame is {actual} bytes, over the authorized {limit}")]
    OverFrame {
        /// Bytes the encoded delivery occupies.
        actual: u64,
        /// Bytes the signed execution policy allows.
        limit: u64,
    },
    /// A private-record rule refused the delivered bytes.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The provider refused to deliver.
    #[error("the provider refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The provider's diagnostic text, unchecked and uncovered by
        /// any digest.
        reason: String,
    },
    /// The response was not one of the shapes the service defines.
    #[error("the provider's response has no readable {0}")]
    Malformed(&'static str),
    /// The call did not complete.
    #[error("the work call failed: {0}")]
    Transport(#[from] WireStatus),
}

impl From<DeliverError> for Refusal {
    /// What a provider says on the wire when it will not deliver.
    ///
    /// The distinction the client's orchestration turns on is
    /// retryable-or-not. A job that has been accepted and has not
    /// finished is `NotReady` — asking again is exactly the right thing
    /// and is how a client learns the answer exists — while a job this
    /// channel does not have is `Declined`, because no wait produces
    /// one. A passed deadline is permanent, a cursor that has not caught
    /// up is the provider's own lag, and a journal that will not take
    /// the release is the provider's storage.
    ///
    /// The client-only arms are mapped so the match is total; a provider
    /// never builds one, and no test claims it does.
    fn from(error: DeliverError) -> Self {
        let reason = error.to_string();
        let code = match error {
            DeliverError::NoSuchJob | DeliverError::Terminated { .. } => WorkRefusal::Declined,
            DeliverError::NoResult { .. } => WorkRefusal::NotReady,
            DeliverError::Endpoint(EndpointError::CatchingUp) => WorkRefusal::NotReady,
            DeliverError::Endpoint(EndpointError::NotAdmitting) => WorkRefusal::Unavailable,
            DeliverError::Unbound => WorkRefusal::Invalid,
            DeliverError::Setup(setup) => return Refusal::from(setup),
            DeliverError::Store(store) => return Refusal::from(store),
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, reason)
    }
}

// ── Paying for the answer ─────────────────────────────────────────────

/// Why one payment did not happen.
///
/// Shared by both halves of the exchange, like [`DeliverError`], because
/// the two endpoints run the same rules over the same records; the arms
/// only one of them can raise are documented where they are mapped.
#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    /// No open job on this channel carries this `work_id`.
    #[error("no open job on this channel carries this work id")]
    NoSuchJob,
    /// The job has no signed result, so there is nothing to pay for.
    #[error("a {phase} job has no result to pay for")]
    NotPayable {
        /// How far the job has got.
        phase: JobPhase,
    },
    /// A private-record rule refused the bytes.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The peer refused.
    #[error("the provider refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The provider's diagnostic text, unchecked and uncovered by
        /// any digest.
        reason: String,
    },
    /// The message was not one of the shapes the service defines.
    #[error("the message has no readable {0}")]
    Malformed(&'static str),
    /// The provider acknowledged crediting an amount other than the one
    /// this client signed for.
    #[error("the provider acknowledged crediting {credited}, not the {signed} it was sent")]
    Acknowledged {
        /// Cumulative the client's certificate names.
        signed: u64,
        /// Cumulative the provider says it credited.
        credited: u64,
    },
    /// The call did not complete.
    #[error("the work call failed: {0}")]
    Transport(#[from] WireStatus),
}

impl From<PaymentError> for Refusal {
    /// What a provider says on the wire when it will not credit.
    ///
    /// A job this channel does not have is `Declined`: no wait produces
    /// one. A job with no result yet is `NotReady`, because that is the
    /// one answer asking again can change. Everything else about this
    /// call is a rule over bytes the caller sent, and the journal's own
    /// mapping is what grades those.
    ///
    /// Three arms are a client's own and no provider builds them: a
    /// refusal it read, a response it could not read, and an
    /// acknowledgement that did not match. They are mapped so the match
    /// is total, and no test claims a provider reaches them.
    fn from(error: PaymentError) -> Self {
        let reason = error.to_string();
        let code = match error {
            PaymentError::NoSuchJob => WorkRefusal::Declined,
            PaymentError::NotPayable { .. } => WorkRefusal::NotReady,
            PaymentError::Store(store) => return Refusal::from(store),
            _ => WorkRefusal::Invalid,
        };
        Self::new(code, reason)
    }
}

/// Reads one kernel certificate from exactly its canonical bytes.
fn earned_certificate(bytes: &[u8]) -> Option<EarnedCertificate> {
    let (certificate, consumed) = EarnedCertificate::decode(bytes).ok()?;
    (consumed == bytes.len()).then_some(certificate)
}

/// Returns the request that carries one retained payment.
fn admit_request(payment: &PaidCertificate) -> AdmitCertificateRequest {
    AdmitCertificateRequest {
        certificate: encode_kernel(&payment.certificate),
        binding: payment.binding.encode(),
        binding_signature: payment.binding_signature.as_bytes().to_vec(),
        certificate_signature: payment.certificate_signature.as_bytes().to_vec(),
    }
}

/// Ends the job as failed, and returns `fault` if that ending was
/// recorded.
fn end_failed(service: &WorkService, work_id: Digest, fault: RunError) -> RunError {
    match service.end_run(work_id) {
        Ok(()) => fault,
        Err(error) => error,
    }
}

/// The generated `Work` handler over one provider endpoint.
///
/// Cheap to clone and shared by every connection a node serves, because
/// one channel has one journal however many peers dial it.
///
/// The lock is the endpoint's, not the journal's: the journal already
/// refuses a second *process*, and this is what serialises the
/// concurrent calls of one. It is never held across an await, because
/// deciding a proposal — hashing, verifying, and two synchronous journal
/// appends — never awaits.
///
/// One type carries both halves because one handler answers the wire,
/// and the halves are not both always present: [`Self::close_only`]
/// serves a channel that admits no new work, and every admission method
/// on it answers [`EndpointError::NotAdmitting`] until
/// [`Self::admit_new_work`] is given a fresh readiness decision. Nothing
/// about a close consults that option.
#[derive(Clone, Debug)]
pub struct WorkService {
    endpoint: Arc<Mutex<ProviderEndpoint>>,
    driving: Arc<AtomicBool>,
    changed: Arc<tokio::sync::Notify>,
    progress: Arc<Mutex<std::collections::BTreeMap<Digest, stream::Progress>>>,
}

/// The authority to advance this channel's cursor, and the only thing
/// that has it.
///
/// Positive rather than absent: driving is not "whatever a caller can
/// still reach", it is this handle, and there is one of it. The
/// ownership is the *channel's*, not a job's, because the cursor is the
/// channel's — a driver naming some other digest is not a second
/// channel, it is a second driver of this one, and
/// [`WorkService::drive`] refuses it whatever it names.
///
/// Every read it does obeys §5's stop-before-successor rule, including
/// the one-block [`Self::observe_finalized`]: a caller stepping the
/// cursor by hand is stopped at exactly the block a loop would stop at,
/// so the rule holds on every path rather than on the path a caller
/// chose.
///
/// Known bound: the slot is returned by [`Drop`], which covers success,
/// error, unwind and a dropped future, but a safe
/// `std::mem::forget(driver)` leaks the handle and leaves the slot taken
/// for the life of the process. Every later [`WorkService::drive`] then
/// answers [`EndpointError::CatchingUp`]. That is a local denial of
/// service a caller can only do to itself, and it fails closed — no
/// cursor moves, and no second driver of this channel appears.
#[derive(Debug)]
pub struct ChannelDriver<'a> {
    service: &'a WorkService,
}

impl Drop for ChannelDriver<'_> {
    fn drop(&mut self) {
        self.service.driving.store(false, Ordering::Release);
    }
}

impl ChannelDriver<'_> {
    /// Refuses the read while this channel owes a close duty, and
    /// returns the cursor otherwise.
    ///
    /// The hand-off consulted is this endpoint's own, and only a sink
    /// that *took* the answer excuses the stop: a discharged duty is one
    /// there is nothing left to do about but watch, so the cursor may
    /// pass the contest it was stopped at. An answer nobody took is
    /// still owed, and this is not what retries it — so it stops here,
    /// and the deadline is not read past while the answer sits on the
    /// disk. [`Self::advance_close`] is what buys the one further block
    /// an unaccepted answer is worth, because it is what offers it
    /// again.
    fn readable_cursor(&self, endpoint: &ProviderEndpoint) -> Result<u64, CatchUpError> {
        let state = endpoint.state();
        let (height, _) = state.cursor();
        if close_duty_present(state, endpoint.close.accepted_contest()) {
            return Err(CatchUpError::CloseDuty { height });
        }
        Ok(height)
    }

    /// Reads to the tip, resubmits this channel's retained close start
    /// if it has not landed, and answers a contest opened below what
    /// this endpoint holds.
    ///
    /// The same one step [`ProviderEndpoint::advance_close`] is, in the
    /// borrow shape a served channel has: the journal is taken and given
    /// back for each apply, for the record that fixes the answer, and
    /// for the hand-off that says what a sink did with it — and it is
    /// held across neither the source's waits nor the sink's. So a
    /// close drives while this channel's requests keep being answered,
    /// and the two contend only for the moments the journal is actually
    /// being read or written.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when the endpoint is unreachable, and
    /// whatever [`crate::work_close::advance_close`] raises otherwise.
    pub async fn advance_close<S, T>(
        &mut self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        advance_close(source, sink, self, &Secp256k1Verifier::new()).await
    }

    /// Applies exactly one finalized block, under one brief borrow, and
    /// only while no close duty is outstanding.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::CloseDuty`] when a close duty stops the read,
    /// [`CatchUpError::Busy`] when the endpoint is unreachable, and
    /// [`CatchUpError::Store`] when the block is not the contiguous next
    /// one or a transition it carries is refused.
    pub fn observe_finalized(&mut self, block: &FinalizedWork) -> Result<(), CatchUpError> {
        let mut endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        self.readable_cursor(&endpoint)?;
        endpoint.observe_finalized(block)?;
        Ok(())
    }

    /// Reads contiguously to the tip, stopping on the first block that
    /// creates a duty.
    ///
    /// The entry check comes before [`FinalizedBlocks::latest_height`] is
    /// even called, which is the case a restart is: a duty already on the
    /// disk is refused before one successor block is read, so a backlog
    /// longer than the response window cannot be what loses it.
    ///
    /// The endpoint is borrowed for each apply and dropped again, never
    /// held across the source await, so the request path does not queue
    /// behind a slow chain.
    ///
    /// # Errors
    ///
    /// [`CatchUpError`] when a duty stops the read, the source fails, a
    /// block in range cannot be read, or the journal refuses one.
    pub async fn catch_up<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
    ) -> Result<u64, CatchUpError> {
        let mut cursor = self.cursor()?;
        let Some(latest) = source.latest_height().await? else {
            return Ok(cursor);
        };
        while cursor < latest {
            let next = cursor.saturating_add(1);
            let block = source
                .block_at(next)
                .await?
                .ok_or(CatchUpError::Missing { height: next })?;
            self.observe_finalized(&block)?;
            cursor = self.cursor()?;
        }
        Ok(cursor)
    }

    /// The cursor this driver may read on from, or the duty that stops
    /// it.
    fn cursor(&self) -> Result<u64, CatchUpError> {
        let endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        self.readable_cursor(&endpoint)
    }

    /// Refuses a driver that named a job this channel's journal does not
    /// hold.
    ///
    /// The open job and the permanent terminal both name it, and either
    /// one contradicts a stranger: ending a job clears the open one but
    /// keeps the terminal, so a check that read only the open job would
    /// stop refusing the moment the job was certified, expired, failed
    /// or refuted.
    ///
    /// A channel that has neither holds no job to contradict, which is
    /// the acceptance phase boundary's own case: the digest being caught
    /// up for is the proposal's, and the journal learns it from the
    /// acceptance this read precedes.
    fn for_job(&self, work_id: Digest) -> Result<(), CatchUpError> {
        let endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        let state = endpoint.state();
        if state.job_by_id(work_id).is_some() || state.terminal_by_id(work_id).is_some() {
            return Ok(());
        }
        if state.jobs().len() == 0 && state.terminals().len() == 0 {
            Ok(())
        } else {
            Err(CatchUpError::OtherJob)
        }
    }
}

/// The driver reaches the same journal and the same hand-off the
/// endpoint owns, one short borrow at a time.
///
/// Every method takes the endpoint lock and gives it back before it
/// returns, and none of them is async, so there is no shape in which a
/// borrow reaches a source or a sink wait. The endpoint's own methods
/// are what decide anything; this is only where the borrow begins and
/// ends.
impl CloseChannel for ChannelDriver<'_> {
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut ChannelStore) -> R,
    ) -> Result<R, CatchUpError> {
        let mut endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        Ok(step(&mut endpoint.close.store))
    }

    fn handoff(&mut self) -> Result<Option<(StartId, Handoff)>, CatchUpError> {
        let endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        Ok(endpoint.close.close_handoff)
    }

    fn fix_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, CatchUpError> {
        let mut endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        Ok(endpoint.close.fix_close_answer(start_id)?)
    }

    fn record_handoff(
        &mut self,
        start_id: StartId,
        outcome: SubmitTxOutcome,
    ) -> Result<(), CatchUpError> {
        let mut endpoint = self.service.endpoint().map_err(|_| CatchUpError::Busy)?;
        endpoint.close.record_close_handoff(start_id, outcome);
        Ok(())
    }
}

impl WorkService {
    /// Wraps one provider endpoint as a dispatchable service.
    #[must_use]
    pub fn new(endpoint: ProviderEndpoint) -> Self {
        Self {
            endpoint: Arc::new(Mutex::new(endpoint)),
            driving: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(tokio::sync::Notify::new()),
            progress: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    /// Wraps one close half as a service that drives closes and admits
    /// no new work.
    ///
    /// This is the mount a channel gets when
    /// [`WorkChannelDescriptor::check_ready`](hellas_rpc::protocol::work_setup::WorkChannelDescriptor::check_ready)
    /// has nothing to say: a contest is open, the bond edge is gone, or
    /// the admission horizon has passed. Every one of those is a state a
    /// close driver exists for, and none of them is a readiness
    /// decision, so there is none to pass.
    #[must_use]
    pub fn close_only(endpoint: CloseEndpoint) -> Self {
        Self::new(ProviderEndpoint::close_only(endpoint))
    }

    /// Admits new work under a fresh readiness decision.
    ///
    /// The one way an admitting service comes to exist after a close-only
    /// mount, and it takes the value only
    /// [`WorkChannelDescriptor::check_ready`](hellas_rpc::protocol::work_setup::WorkChannelDescriptor::check_ready)
    /// produces. Nothing here refreshes it afterwards: its freshness is
    /// the caller's in exactly the sense [`ReadyChannel`] documents.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Poisoned`] when the endpoint is unreachable, and
    /// the binding errors when the decision is not this journal's own
    /// channel at its own settlement.
    pub fn admit_new_work(&self, ready: ReadyChannel) -> Result<(), EndpointError> {
        self.endpoint()?.admit_new_work(ready)
    }

    /// Borrows the endpoint, privately.
    ///
    /// Private, and that is only half of the discipline. The other half
    /// is positive: everything that advances this channel's cursor goes
    /// through [`ChannelDriver`], and [`Self::drive`] hands out one of
    /// those at a time. So there is no borrow to hold across a chain or
    /// sink wait, no way to read on to the tip past a duty, and no
    /// second copy of a duty another driver already took — by the shape
    /// of the type, rather than by callers remembering to behave.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Poisoned`] after a handler panicked while
    /// holding it. The state is not recovered, because a panic mid-
    /// commit is a bug whose durable effect this type cannot know.
    fn endpoint(&self) -> Result<MutexGuard<'_, ProviderEndpoint>, EndpointError> {
        self.endpoint.lock().map_err(|_| EndpointError::Poisoned)
    }

    /// Reads what this endpoint durably knows, for exactly as long as
    /// `read` runs.
    ///
    /// The state is lent, not handed over. `read` is synchronous, so
    /// nothing can wait on a chain or a sink while this channel's
    /// journal is borrowed, and it is handed a shared reference, so a
    /// reader cannot become a driver.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Poisoned`], as [`Self::endpoint`] documents.
    pub fn with_state<R>(&self, read: impl FnOnce(&ChannelState) -> R) -> Result<R, EndpointError> {
        Ok(read(self.endpoint()?.state()))
    }

    /// Takes this channel's one cursor-driving authority, or says it is
    /// already taken.
    ///
    /// Channel-wide and service-owned: the slot is this service's own
    /// flag, so no caller-supplied name buys a second one. Ordinary brief
    /// journal operations do not contend on it, so a completed backend
    /// transcript waits for the endpoint lock and is never dropped merely
    /// because a watcher poll is running.
    ///
    /// # Errors
    ///
    /// [`EndpointError::CatchingUp`] while a driver is live.
    pub fn drive(&self) -> Result<ChannelDriver<'_>, EndpointError> {
        self.driving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| EndpointError::CatchingUp)?;
        Ok(ChannelDriver { service: self })
    }

    /// Advances this channel's cursor for `work_id`, without holding the
    /// endpoint across a chain await.
    ///
    /// `work_id` is checked against the job this journal holds rather
    /// than trusted: it names which job the read is *for*, and a caller
    /// naming another one is refused instead of being given a drive of
    /// its own.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] while another driver owns this channel,
    /// [`CatchUpError::OtherJob`] when the journal's job is not the one
    /// named, and whatever [`ChannelDriver::catch_up`] raises otherwise.
    pub async fn catch_up_job<S: FinalizedBlocks + ?Sized>(
        &self,
        source: &S,
        work_id: Digest,
    ) -> Result<u64, CatchUpError> {
        let mut driver = self.drive().map_err(|_| CatchUpError::Busy)?;
        driver.for_job(work_id)?;
        driver.catch_up(source).await
    }

    /// Signs, or returns, this channel's retained close start.
    ///
    /// # Errors
    ///
    /// [`CloseError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::prepare_close`] raises otherwise.
    pub fn prepare_close(&self) -> Result<PaymentCloseStart, CloseError> {
        self.endpoint()?.prepare_close()
    }

    /// Builds the close that ends this endpoint's contest, from one
    /// coherent finalized read.
    ///
    /// # Errors
    ///
    /// [`CloseError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::adjudicated_close`] raises otherwise.
    pub fn adjudicated_close(&self, observed: &ObservedChannel<'_>) -> Result<Tx, CloseError> {
        self.endpoint()?.adjudicated_close(observed)
    }

    /// Reads to the tip and services whatever close duty that read
    /// surfaced, under one driver.
    ///
    /// The whole of what a caller with a clock does to a live edge, and
    /// the reason this channel's requests are still answered while it
    /// runs: the endpoint is borrowed per apply and per record, never
    /// across the source's waits or the sink's.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] while another driver owns this channel,
    /// and whatever [`ChannelDriver::advance_close`] raises otherwise.
    pub async fn advance_close<S, T>(
        &self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        let mut driver = self.drive().map_err(|_| CatchUpError::Busy)?;
        driver.advance_close(source, sink).await
    }

    // There is deliberately no `respond_to_close` here.
    //
    // An answer to a contest is not bytes, it is a sequence: read to the
    // block that opened it, fix the answer on the disk, offer it to a
    // sink, and let what the sink did decide whether the cursor may move
    // past the duty. A service method returning the transaction would be
    // handing out a submittable duty that no hand-off state accounts
    // for, and two callers could take the same one.
    // [`ChannelDriver::advance_close`] owns source, sink and hand-off
    // together, is the only operation that couples the three, and there
    // is one driver of this channel at a time. A caller holding the
    // endpoint itself can still build a response with
    // [`ProviderEndpoint::respond_to_close`] — that is not the claim
    // here; the claim is that *this service* hands out no submittable
    // answer, only a driver that offers one and then records what
    // became of it.

    /// Workflow phase boundary for provider acceptance: catch up with short
    /// borrows, reacquire by this channel service, then let the durable
    /// acceptance transition compare against that same cursor.
    pub async fn accept_after_catch_up<S: FinalizedBlocks + ?Sized>(
        &self,
        source: &S,
        request: &AcceptWorkRequest,
    ) -> Result<AcceptWorkResponse, CatchUpError> {
        if let Some(response) = self.precheck_acceptance(request) {
            return Ok(response);
        }
        let work_id = {
            let endpoint = self.endpoint().map_err(|_| CatchUpError::Busy)?;
            let channel = endpoint.state().channel();
            PaidJobAuthorizationV1::decode(&request.authorization)
                .ok()
                .map(|authorization| work_id(channel, &authorization))
        };
        if let Some(work_id) = work_id {
            self.catch_up_job(source, work_id).await?;
        }
        Ok(self.accept(request))
    }

    /// Answers an authenticated proposal from retained state alone, when
    /// possible, without signing, writing the journal, or requiring readiness.
    ///
    /// A retained acceptance takes precedence over expiry: its acknowledgement
    /// may have been lost. Otherwise a retained terminal or an acceptance
    /// deadline already passed by the persisted cursor is permanent. Malformed
    /// or unauthenticated requests are refused before consulting job state.
    /// `None` means fresh readiness and the normal acceptance checks are needed.
    #[must_use]
    pub fn precheck_acceptance(&self, request: &AcceptWorkRequest) -> Option<AcceptWorkResponse> {
        let result = self
            .endpoint()
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))
            .and_then(|endpoint| {
                let (authorization, _, work_id) = endpoint.authenticate_proposal(request)?;
                Ok(endpoint
                    .prior_acceptance(&authorization, work_id)?
                    .map(|signature| (work_id, signature)))
            });
        result.transpose().map(acceptance_response)
    }

    /// Answers one proposal, or says the endpoint is unreachable.
    ///
    /// Synchronous, and that is the whole of why the lock above is a
    /// plain [`Mutex`]: nothing between taking it and dropping it can
    /// await.
    pub fn accept(&self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        match self.endpoint() {
            Ok(mut endpoint) => endpoint.accept(request),
            Err(error) => AcceptWorkResponse {
                outcome: Some(Outcome::Refused(WorkRefused {
                    code: endpoint_refusal(error).code() as i32,
                    reason: error.to_string(),
                })),
            },
        }
    }

    /// Admits one accepted job for a real invocation, and journals the
    /// running marker before it says so.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::begin_run`] raises otherwise.
    pub fn begin_run(
        &self,
        work_id: Digest,
        ready: &ReadyChannel,
    ) -> Result<RunAdmission, RunError> {
        let result = self.endpoint()?.begin_run(work_id, ready);
        self.changed.notify_waiters();
        result
    }

    /// Signs and journals the result of one invocation's transcript.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::record_result`] raises otherwise.
    pub fn record_result(
        &self,
        work_id: Digest,
        transcript: &[OutputEventEnvelope],
    ) -> Result<(PaidJobResultV1, Sig), RunError> {
        let result = self.endpoint()?.record_result(work_id, transcript);
        if result.is_ok() {
            self.progress
                .lock()
                .expect("paid progress poisoned")
                .remove(&work_id);
        }
        self.changed.notify_waiters();
        result
    }

    /// Ends the open job as this provider's own failure.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::end_run`] raises otherwise.
    pub fn end_run(&self, work_id: Digest) -> Result<(), RunError> {
        let result = self.endpoint()?.end_run(work_id);
        self.progress
            .lock()
            .expect("paid progress poisoned")
            .remove(&work_id);
        self.changed.notify_waiters();
        result
    }

    /// Releases one job's plaintext against this service's own
    /// readiness, to a request bound to `exporter`.
    ///
    /// The readiness is not a parameter, and that is deliberate: it is
    /// the endpoint's own, at the height this endpoint has actually
    /// processed finalized blocks through. A caller choosing one would
    /// be choosing the margins its own delivery is measured against.
    ///
    /// # Errors
    ///
    /// [`DeliverError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::deliver`] raises otherwise.
    pub fn deliver(
        &self,
        request: &DeliverResultRequest,
        exporter: &[u8; 32],
    ) -> Result<Delivery, DeliverError> {
        self.endpoint()?
            .deliver_with_readiness(request, None, exporter)
    }

    /// Releases one job's answer, or says why not.
    ///
    /// The exporter comes from `context`, which is the transport's own
    /// account of the connection this request arrived on. It is never
    /// read out of the request: a value the caller chooses proves
    /// nothing about where the caller is.
    ///
    /// The readiness it releases against is this service's own, which is
    /// the endpoint's — the one the channel was configured with, at the
    /// height it was decided at. Its freshness is the operator's in
    /// exactly the sense [`ReadyChannel`] documents; what is measured
    /// against it is the height this endpoint has actually processed
    /// finalized blocks through.
    fn release(
        &self,
        request: &DeliverResultRequest,
        context: &TransportContext,
    ) -> DeliverResultResponse {
        let outcome = match (self.endpoint(), context.open_exporter) {
            (Ok(mut endpoint), Some(exporter)) => endpoint
                .deliver_with_readiness(request, None, &exporter)
                .map_err(Refusal::from),
            (Ok(_), None) => Err(Refusal::from(DeliverError::Unbindable)),
            (Err(error), _) => Err(Refusal::new(endpoint_refusal(error), error.to_string())),
        };
        DeliverResultResponse {
            outcome: Some(match outcome {
                Ok(delivery) => DeliverOutcome::Delivered(WorkDelivered {
                    result: delivery.result.encode(),
                    provider_signature: delivery.signature.as_bytes().to_vec(),
                    transcript: delivery.transcript,
                }),
                Err(refusal) => DeliverOutcome::Refused(WorkRefused {
                    code: refusal.code.code() as i32,
                    reason: refusal.reason,
                }),
            }),
        }
    }

    /// Admits one payment, or says why not.
    ///
    /// The answer is produced after [`ProviderEndpoint::admit`] returns,
    /// which is after its record is fsynced. Nothing on this path can
    /// acknowledge a payment the disk does not hold.
    fn credit(&self, request: &AdmitCertificateRequest) -> AdmitCertificateResponse {
        let outcome = match self.endpoint() {
            Ok(mut endpoint) => endpoint.admit(request).map_err(Refusal::from),
            Err(error) => Err(Refusal::new(endpoint_refusal(error), error.to_string())),
        };
        AdmitCertificateResponse {
            outcome: Some(match outcome {
                Ok(credited_cumulative) => AdmitOutcome::Paid(WorkPaid {
                    credited_cumulative,
                }),
                Err(refusal) => AdmitOutcome::Refused(WorkRefused {
                    code: refusal.code.code() as i32,
                    reason: refusal.reason,
                }),
            }),
        }
    }
}

/// `NotAdmitting` is retryable for [`EndpointError::CatchingUp`]'s
/// reason and no other: a channel that admits no new work now may admit
/// it the moment a fresh readiness decision lands, and nothing about the
/// proposal is wrong.
const fn endpoint_refusal(error: EndpointError) -> WorkRefusal {
    match error {
        EndpointError::CatchingUp | EndpointError::NotAdmitting => WorkRefusal::NotReady,
        _ => WorkRefusal::Unavailable,
    }
}

impl WorkHandler for WorkService {
    fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(self.accept(&request)))
    }

    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send, WireStatus>
    {
        Ok(self.release(&request, &context))
    }

    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<PaidResultStream, WireStatus> {
        Ok(self.result_stream(request, context))
    }

    fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(self.credit(&request)))
    }
}

/// Reads a `work_id` from exactly its 32 bytes.
fn work_id_bytes(bytes: &[u8]) -> Option<Digest> {
    <[u8; Digest::LEN]>::try_from(bytes)
        .ok()
        .map(Digest::from_bytes)
}

// ── The client ────────────────────────────────────────────────────────

/// What a client wants done, before it is an authorization.
///
/// The two things a proposal actually chooses. Everything else in the
/// authorization is derived from the channel, the policy, and this
/// bundle by [`hellas_rpc::protocol::work::propose_authorization`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobProposal {
    /// The inputs the job runs on.
    pub prepared_input: PreparedPaidWorkInput,
    /// The three heights the job is bound by.
    pub deadlines: JobDeadlines,
}

/// Why a client could not complete one acceptance exchange.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    /// The provider refused.
    #[error("the provider refused as {refusal}: {reason}")]
    Refused {
        /// Which of the six answers came back.
        refusal: WorkRefusal,
        /// The provider's diagnostic text, unchecked and uncovered by
        /// any digest.
        reason: String,
    },
    /// The response was not one of the shapes the service defines.
    #[error("the provider's response has no readable {0}")]
    Malformed(&'static str),
    /// An acceptance was applied with no proposal outstanding.
    #[error("there is no proposal for this acceptance to answer")]
    NoOpenJob,
    /// A job is already past proposal, so the channel has no room for
    /// another.
    #[error("a job is already {phase} on this channel")]
    JobInFlight {
        /// How far the job in flight has got.
        phase: JobPhase,
    },
    /// A proposal is outstanding and this one is not it.
    #[error("a different proposal is already outstanding on this channel")]
    Conflict,
    /// A private-record rule refused the proposal.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// A readiness rule refused the proposal.
    #[error(transparent)]
    Setup(#[from] WorkSetupError),
    /// The journal refused the step, or could not take it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The call did not complete.
    #[error("the work call failed: {0}")]
    Transport(#[from] WireStatus),
}

/// The client half of the acceptance exchange.
///
/// It owns one channel's journal and proposes on that channel alone.
#[derive(Debug)]
pub struct ClientEndpoint {
    ready: ReadyChannel,
    store: ChannelStore,
    signer: Secp256k1Signer,
}

impl ClientEndpoint {
    /// Builds the client endpoint for one ready channel.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when the store, the readiness decision, and the
    /// key are not all the client's view of the same channel.
    pub fn new(
        ready: ReadyChannel,
        store: ChannelStore,
        signer: Secp256k1Signer,
    ) -> Result<Self, EndpointError> {
        bind(&ready, &store, &signer, Role::Client)?;
        Ok(Self {
            ready,
            store,
            signer,
        })
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &ChannelState {
        self.store.state()
    }

    /// Returns the request that proposes this job, making it durable
    /// first.
    ///
    /// The signature is journaled before this returns it — in the same
    /// record that burns the nonce carrying it — so a request in the
    /// caller's hand is a request the journal already accounts for. A
    /// crash before that commit leaves nothing: nothing was released,
    /// so the nonce was never spent, and the retry proposes the same
    /// job at the same number.
    ///
    /// A matching outstanding proposal returns its retained bytes. Use
    /// [`Self::resume_proposal`] to retry a known job after the configured
    /// execution policy has changed. Other proposals receive fresh nonces.
    ///
    /// # Errors
    ///
    /// [`ProposeError::JobInFlight`] once a job is past
    /// proposal, [`ProposeError::Conflict`] when a different proposal is
    /// outstanding, and the record, readiness, and journal errors the
    /// proposal itself raises.
    pub fn propose(&mut self, proposal: &JobProposal) -> Result<AcceptWorkRequest, ProposeError> {
        let (cursor_height, _) = self.state().cursor();
        let policy = self.ready.execution_policy();

        for job in self
            .state()
            .jobs()
            .filter(|job| job.phase() == JobPhase::HalfSigned)
        {
            let retained = *job.authorization();
            let rebuilt = policy.propose(
                self.ready.channel(),
                &proposal.prepared_input,
                retained.proposal_nonce,
                proposal.deadlines,
            )?;
            if rebuilt != retained {
                continue;
            }
            return Ok(wire_request(
                &retained,
                job.client_signature(),
                job.prepared_input().to_vec(),
            ));
        }

        // Nonces form a durable high-water mark. A second job does not
        // wait for the first, but no crash or reordered response can make
        // the sequence move backwards or reuse a number.
        let proposal_nonce = self.state().proposal_nonce_high_water().saturating_add(1);
        let authorization = policy.propose(
            self.ready.channel(),
            &proposal.prepared_input,
            proposal_nonce,
            proposal.deadlines,
        )?;
        policy.check_authorization(self.ready.channel(), &authorization, cursor_height)?;
        policy.check_input(
            self.ready.channel(),
            &authorization,
            &proposal.prepared_input,
        )?;
        self.ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        let prepared_input = proposal
            .prepared_input
            .encode()
            .map_err(PaidWorkError::from)?;
        let work_id = work_id(self.ready.channel(), &authorization);

        let signature = self.signer.sign(signing_hash(work_id));
        self.store.commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: signature,
                prepared_input: prepared_input.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(wire_request(&authorization, signature, prepared_input))
    }

    /// Resend a half-signed proposal exactly as journaled, including the
    /// original policy and deadlines. No nonce or new signature is created.
    ///
    /// # Errors
    /// Returns [`ProposeError::NoOpenJob`] for an unknown job and
    /// [`ProposeError::JobInFlight`] if the provider already co-signed it.
    pub fn resume_proposal(&self, work_id: Digest) -> Result<AcceptWorkRequest, ProposeError> {
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(ProposeError::NoOpenJob)?;
        if job.phase() != JobPhase::HalfSigned {
            return Err(ProposeError::JobInFlight { phase: job.phase() });
        }
        Ok(wire_request(
            job.authorization(),
            job.client_signature(),
            job.prepared_input().to_vec(),
        ))
    }

    /// Applies one provider answer, and returns the accepted `work_id`.
    ///
    /// The co-signature is journaled before this returns, and the store
    /// is what verifies it against the provider key over the retained
    /// job's own digest. A crash before that commit leaves the proposal
    /// half-signed and the client's retry re-sends the retained request;
    /// the provider's answer to the retry is the same signature.
    ///
    /// # Errors
    ///
    /// [`ProposeError::Refused`] for a refusal, [`ProposeError::NoOpenJob`]
    /// with nothing outstanding, [`ProposeError::Malformed`] for a
    /// response this service does not define, and
    /// [`ProposeError::Store`] when the signature is not the provider's
    /// or the journal will not take it.
    pub fn accepted(&mut self, response: &AcceptWorkResponse) -> Result<Digest, ProposeError> {
        let (work_id, signature) = match response.outcome.as_ref() {
            Some(Outcome::Accepted(accepted)) => (
                work_id_bytes(&accepted.work_id).ok_or(ProposeError::Malformed("work id"))?,
                signature(&accepted.provider_signature)
                    .ok_or(ProposeError::Malformed("provider signature"))?,
            ),
            Some(Outcome::Refused(refused)) => {
                return Err(ProposeError::Refused {
                    refusal: WorkRefusal::from_code(refused.code)
                        .ok_or(ProposeError::Malformed("refusal code"))?,
                    reason: refused.reason.clone(),
                });
            }
            None => return Err(ProposeError::Malformed("outcome")),
        };
        self.state()
            .job_by_id(work_id)
            .ok_or(ProposeError::NoOpenJob)?;
        self.store.commit(
            ChannelRecord::JobAccepted {
                work_id,
                provider_signature: signature,
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(work_id)
    }
}

impl ClientEndpoint {
    /// Signs the close start that spends this channel's certificate,
    /// and retains its exact bytes before returning them.
    ///
    /// The client's half of the same step, and it is not optional
    /// symmetry. A provider that stops answering leaves the client's
    /// funded payment edge locked up, and the only thing that unlocks
    /// it is a close this client opens itself. The certificate it
    /// carries is the client's own last payment, because opening below
    /// what one has already signed for is what the omission bond
    /// exists to punish — and the client is the party that would be
    /// punished for it.
    ///
    /// Everything else is [`ProviderEndpoint::prepare_close`]'s: the
    /// journal takes the bytes before they are returned, a start that
    /// can still be included is offered again rather than replaced,
    /// and the record is what shuts this channel to new work.
    ///
    /// # Errors
    ///
    /// [`CloseError::Store`] when a job is still open, a contest is
    /// already live, or the journal refuses the record, and the window
    /// errors [`close_start`] raises.
    pub fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
        let (height, _) = self.state().cursor();
        if let Some(retained) = self.state().includable_close_start(height) {
            return Ok(retained.clone());
        }
        let start = close_start(
            self.ready.channel(),
            Party::Maker,
            height,
            self.state().executable_certificate(),
            &self.signer,
        )?;
        retain_close_start(&mut self.store, &start)?;
        Ok(start)
    }

    /// Reads to the tip and resubmits this endpoint's retained close
    /// start if it has not landed.
    ///
    /// # Errors
    ///
    /// [`CatchUpError`] when the source fails, a block in range cannot
    /// be read, the journal refuses one, or the sink will not take the
    /// transaction.
    pub async fn advance_close<S, T>(
        &mut self,
        source: &S,
        sink: &T,
    ) -> Result<CloseProgress, CatchUpError>
    where
        S: FinalizedBlocks + ?Sized,
        T: TxSink + ?Sized,
    {
        // No contest is ever this endpoint's to answer — only a
        // certificate's beneficiary may spend it — so a client never
        // holds one back, and never stops reading over one.
        advance_close(source, sink, self, &Secp256k1Verifier::new()).await
    }

    /// Takes one delivered answer, and makes it durable before it is
    /// returned.
    ///
    /// What this establishes, and the order it establishes it in: the
    /// encoded delivery is inside the frame both parties signed a bound
    /// for; the result parses as this profile's record; and the store
    /// takes it, which is where the three rules that matter live —
    /// the transcript rebuilds exactly this result, the signature is
    /// the provider's over its digest, and the receipt is at or before
    /// the terminal deadline. None of those is spelled a second time
    /// here.
    ///
    /// What it does *not* establish is that the answer is right. That
    /// is the re-execution's, it runs on the bytes this returns, and
    /// its outcome is a separate durable step.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, [`DeliverError::Endpoint`] when `ready` is not this
    /// endpoint's channel, [`DeliverError::Policy`] when it carries
    /// another execution policy, [`DeliverError::Setup`] when
    /// this endpoint has not caught up to that readiness,
    /// [`DeliverError::OverFrame`] above the signed frame bound,
    /// [`DeliverError::Malformed`] for a signature that is not 64
    /// bytes, [`DeliverError::Record`] when the result does not parse,
    /// and [`DeliverError::Store`] for every rule above.
    pub fn receive(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
        delivered: &WorkDelivered,
    ) -> Result<Delivery, DeliverError> {
        self.receive_inner(work_id, ready, delivered, false)
    }

    fn receive_inner(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
        delivered: &WorkDelivered,
        streamed: bool,
    ) -> Result<Delivery, DeliverError> {
        self.state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;

        bind(ready, &self.store, &self.signer, Role::Client)?;
        if ready.execution_policy() != self.ready.execution_policy() {
            return Err(DeliverError::Policy);
        }
        let (cursor_height, _) = self.state().cursor();
        ready.check_caught_up(cursor_height)?;

        // The bound is on the encoded message, which is what this
        // endpoint agreed to hold; the transport's own framing around
        // it is the transport's and is not measured here.
        let limit = u64::from(ready.execution_policy().max_encoded_result_frame());
        let actual = u64::try_from(delivered.encoded_len()).unwrap_or(u64::MAX);
        if !streamed && actual > limit {
            return Err(DeliverError::OverFrame { actual, limit });
        }

        let result = PaidJobResultV1::decode(&delivered.result)?;
        if matches!(ready.execution_policy(), PaidWorkPolicy::Fetch { .. }) {
            let actual = delivered.transcript.len() as u64;
            let limit = ready.execution_policy().max_spool_bytes();
            if actual > limit {
                return Err(PaidWorkError::OverEnvelope {
                    field: "spooled transcript length",
                    actual,
                    limit,
                }
                .into());
            }
            let authorization = self
                .state()
                .job_by_id(work_id)
                .ok_or(DeliverError::NoSuchJob)?
                .authorization();
            let transcript = hellas_rpc::protocol::work::decode_transcript(
                &delivered.transcript,
                hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES,
            )?;
            let input = PreparedPaidWorkInput::decode(
                self.state()
                    .job_by_id(work_id)
                    .ok_or(DeliverError::NoSuchJob)?
                    .prepared_input(),
                MAX_RECORD_BYTES,
            )
            .map_err(PaidWorkError::from)?;
            let expected = ready.execution_policy().terminal_result(
                ready.channel(),
                authorization,
                &input,
                &transcript,
            )?;
            if expected != result {
                return Err(PaidWorkError::Mismatch {
                    field: "result against its transcript",
                }
                .into());
            }
        }
        let signature = signature(&delivered.provider_signature)
            .ok_or(DeliverError::Malformed("provider signature"))?;
        self.store.commit(
            ChannelRecord::JobResult {
                work_id,
                result,
                provider_signature: signature,
                transcript: delivered.transcript.clone(),
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(Delivery {
            result,
            signature,
            transcript: delivered.transcript.clone(),
        })
    }

    /// Signs the request that asks for one job's plaintext on one
    /// connection.
    ///
    /// Nothing durable is written and nothing is spent: the signature
    /// says who is asking and where, and it authorises a release the
    /// provider journals for itself. Made again on the same connection
    /// it is the same bytes; made on another it is a different request,
    /// because the exporter it covers is that connection's.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`.
    pub fn request_delivery(
        &self,
        work_id: Digest,
        exporter: &[u8; 32],
    ) -> Result<DeliverResultRequest, DeliverError> {
        self.state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let signature = self.signer.sign(signing_hash(delivery_request_digest(
            self.ready.channel(),
            work_id,
            exporter,
        )));
        Ok(DeliverResultRequest {
            work_id: work_id.as_bytes().to_vec(),
            client_signature: signature.as_bytes().to_vec(),
        })
    }

    /// Records that this client's own re-execution reproduced the answer
    /// and it matched.
    ///
    /// It takes no verdict argument, and that is deliberate: a function
    /// that could be handed `false` would be a function some caller
    /// could hand `true`. The only way to record a match is to have
    /// reproduced one, and the caller that has calls this.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, and [`DeliverError::Store`] when the job has no
    /// recorded result or the match cannot be made durable.
    pub fn matched(&mut self, work_id: Digest) -> Result<(), DeliverError> {
        self.state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        self.store.commit(
            ChannelRecord::ResultMatched { work_id },
            &Secp256k1Verifier::new(),
        )?;
        Ok(())
    }

    /// Records that this client's own re-execution did not reproduce the
    /// answer, resting the job at a permanent refuted terminal.
    ///
    /// The refutation is durable for the same reason a match is: a job a
    /// client's own engine refused must never afterwards be paid for,
    /// even across a restart, and a second proposal of it must fail. The
    /// signed result's digest is read off the job this journal recorded;
    /// the reproduction digest is what the client's own engine produced.
    ///
    /// # Errors
    ///
    /// [`DeliverError::NoSuchJob`] when no open job carries this
    /// `work_id`, and [`DeliverError::Store`] when the job has no
    /// recorded result or the refutation cannot be made durable.
    pub fn refuted(
        &mut self,
        work_id: Digest,
        reproduction_digest: Digest,
    ) -> Result<(), DeliverError> {
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let (result, _) = job.result().ok_or(DeliverError::NoSuchJob)?;
        let result_digest = result_digest(self.ready.channel(), result);
        self.store.commit(
            ChannelRecord::JobTerminated {
                work_id,
                outcome: TerminalOutcome::Refuted {
                    result_digest,
                    reproduction_digest,
                },
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(())
    }

    /// Signs the payment for one checked job, and returns the request
    /// that carries it only once it is on the disk.
    ///
    /// This is the only place an [`EarnedCertificate`] is built outside
    /// a test, and neither it nor the binding beside it is a choice:
    /// both come out of [`next_payment`], from this client's own
    /// credited total and the price its own authorization fixed. There
    /// is nothing here a provider quoted.
    ///
    /// The journal then runs
    /// [`hellas_rpc::protocol::work::CreditLedger::credit_payment`] over the
    /// job it recorded itself, so the two signatures below are made
    /// before the ledger has agreed and released after it has — a
    /// certificate the ledger refuses is one whose bytes never leave.
    ///
    /// Called again for a job this channel has already paid for, it
    /// returns the retained bytes rather than signing a second
    /// certificate: that is the crash between the commit and the send,
    /// and re-sending is what recovers a lost acknowledgement.
    ///
    /// # Errors
    ///
    /// [`PaymentError::NoSuchJob`] when no open job carries this
    /// `work_id` and no retained payment does either,
    /// [`PaymentError::NotPayable`] before the result exists, and — from
    /// the journal — before this client's own match is durable,
    /// [`PaymentError::Record`] when the payment would exceed what this
    /// edge can settle, and [`PaymentError::Store`] for every rule the
    /// journal applies — including a payment signed past its deadline.
    pub fn pay(&mut self, work_id: Digest) -> Result<AdmitCertificateRequest, PaymentError> {
        if let Some(retained) = self.state().payment(work_id) {
            return Ok(admit_request(&retained));
        }
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(PaymentError::NoSuchJob)?;
        let Some((result, _)) = job.result() else {
            return Err(PaymentError::NotPayable { phase: job.phase() });
        };
        let (authorization, result) = (*job.authorization(), *result);

        let (certificate, binding) = next_payment(
            self.ready.channel(),
            &authorization,
            &result,
            self.state().ledger().credited_cumulative(),
            self.state().settlement(),
        )?;
        let binding_signature = self.signer.sign(signing_hash(payment_binding_digest(
            self.ready.channel(),
            &binding,
        )));
        let certificate_signature = self
            .signer
            .sign(certificate.digest(self.ready.channel().network()));

        self.store.commit(
            ChannelRecord::JobTerminated {
                work_id,
                outcome: TerminalOutcome::Certified {
                    certificate,
                    binding: Box::new(binding),
                    binding_signature,
                    certificate_signature,
                },
            },
            &Secp256k1Verifier::new(),
        )?;
        Ok(AdmitCertificateRequest {
            certificate: encode_kernel(&certificate),
            binding: binding.encode(),
            binding_signature: binding_signature.as_bytes().to_vec(),
            certificate_signature: certificate_signature.as_bytes().to_vec(),
        })
    }

    /// Reads the provider's acknowledgement of a payment this client
    /// has already made durable.
    ///
    /// Nothing is recorded here, and that is the point: the client's
    /// state was complete before the request left, so this call has
    /// nothing to add and can lose nothing. What it checks is that the
    /// provider credited the amount this client signed — an
    /// acknowledgement of another number is an endpoint whose ledger is
    /// not the one this payment was for.
    ///
    /// # Errors
    ///
    /// [`PaymentError::Refused`] for a refusal,
    /// [`PaymentError::Malformed`] for a response this service does not
    /// define, [`PaymentError::NoSuchJob`] when no retained payment
    /// carries this `work_id`, and [`PaymentError::Acknowledged`] when
    /// the credited amount is not the one signed.
    pub fn acknowledged(
        &self,
        work_id: Digest,
        response: &AdmitCertificateResponse,
    ) -> Result<u64, PaymentError> {
        let credited = match response.outcome.as_ref() {
            Some(AdmitOutcome::Paid(paid)) => paid.credited_cumulative,
            Some(AdmitOutcome::Refused(refused)) => {
                return Err(PaymentError::Refused {
                    refusal: WorkRefusal::from_code(refused.code)
                        .ok_or(PaymentError::Malformed("refusal code"))?,
                    reason: refused.reason.clone(),
                });
            }
            None => return Err(PaymentError::Malformed("outcome")),
        };
        let signed = self
            .state()
            .payment(work_id)
            .ok_or(PaymentError::NoSuchJob)?
            .certificate
            .earned_cumulative();
        if credited == signed {
            Ok(credited)
        } else {
            Err(PaymentError::Acknowledged { signed, credited })
        }
    }
}

/// Signs one delivered job's payment and sends it over a live
/// transport.
///
/// The order is the durability rule at its last step: the certificate
/// is fsynced by [`ClientEndpoint::pay`] before the request is built,
/// and the provider fsyncs its own copy before the answer this reads is
/// produced. A transport fault leaves a durable, unsent payment;
/// calling this again re-sends exactly those bytes.
///
/// # Errors
///
/// [`PaymentError::Transport`] when the call does not complete, and
/// whatever [`ClientEndpoint::pay`] or [`ClientEndpoint::acknowledged`]
/// raises.
pub async fn admit_payment<T>(
    client: &WorkClientImpl<T>,
    endpoint: &mut ClientEndpoint,
    work_id: Digest,
) -> Result<u64, PaymentError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.pay(work_id)?;
    let response = client.admit_certificate(request).await?;
    endpoint.acknowledged(work_id, &response)
}

/// Asks for one accepted job's answer over a live transport and makes it
/// durable.
///
/// Idempotent by the same rule as the exchange above: a lost response
/// costs a round trip, because the provider answers a second call from
/// its own spool and this endpoint's store takes the same result twice
/// as one.
///
/// # Errors
///
/// [`DeliverError::Unbindable`] when the transport exposes no
/// connection exporter to bind the request to,
/// [`DeliverError::Transport`] when the call does not complete,
/// [`DeliverError::Refused`] for a refusal, [`DeliverError::Malformed`]
/// for a response this service does not define, and whatever
/// [`ClientEndpoint::request_delivery`] or [`ClientEndpoint::receive`]
/// raise.
pub async fn fetch_result<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    work_id: Digest,
) -> Result<Delivery, DeliverError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let Some(exporter) = transport.context().open_exporter else {
        return Err(DeliverError::Unbindable);
    };
    let request = endpoint.request_delivery(work_id, &exporter)?;
    let response = WorkClientImpl::new(transport)
        .deliver_result(request)
        .await?;
    match response.outcome {
        Some(DeliverOutcome::Delivered(delivered)) => endpoint.receive(work_id, ready, &delivered),
        Some(DeliverOutcome::Refused(refused)) => Err(DeliverError::Refused {
            refusal: WorkRefusal::from_code(refused.code)
                .ok_or(DeliverError::Malformed("refusal code"))?,
            reason: refused.reason,
        }),
        None => Err(DeliverError::Malformed("outcome")),
    }
}

/// Proposes one job over a live transport and applies the answer.
///
/// The whole exchange, in the order the durability rule fixes: journal,
/// send, journal. Nothing between the two commits is retried here — a
/// transport fault leaves a durable half-signed proposal, and calling
/// this again with the same proposal re-sends the retained bytes.
///
/// # Errors
///
/// [`ProposeError::Transport`] when the call does not complete, and
/// whatever [`ClientEndpoint::propose`] or [`ClientEndpoint::accepted`]
/// raises.
pub async fn propose_work<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    proposal: &JobProposal,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.propose(proposal)?;
    let response = WorkClientImpl::new(transport).accept_work(request).await?;
    endpoint.accepted(&response)
}

/// Resend a retained proposal over a live transport and journal its answer.
///
/// # Errors
/// Returns transport errors and errors from [`ClientEndpoint::resume_proposal`]
/// or [`ClientEndpoint::accepted`].
pub async fn resume_work_proposal<T>(
    transport: T,
    endpoint: &mut ClientEndpoint,
    work_id: Digest,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.resume_proposal(work_id)?;
    let response = WorkClientImpl::new(transport).accept_work(request).await?;
    endpoint.accepted(&response)
}

// ── Wire shapes ───────────────────────────────────────────────────────

fn acceptance_response(result: Result<(Digest, Sig), Refusal>) -> AcceptWorkResponse {
    AcceptWorkResponse {
        outcome: Some(match result {
            Ok((work_id, signature)) => Outcome::Accepted(WorkAccepted {
                provider_signature: signature.as_bytes().to_vec(),
                work_id: work_id.as_bytes().to_vec(),
            }),
            Err(refusal) => Outcome::Refused(WorkRefused {
                code: refusal.code.code() as i32,
                reason: refusal.reason,
            }),
        }),
    }
}

fn wire_request(
    authorization: &PaidJobAuthorizationV1,
    client_signature: Sig,
    prepared_input: Vec<u8>,
) -> AcceptWorkRequest {
    AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: client_signature.as_bytes().to_vec(),
        prepared_input,
    }
}

/// Reads a compact secp256k1 signature from exactly its 64 bytes.
///
/// There is no key-kind discriminator to read: the channel's parties are
/// native secp256k1 keys fixed by the payment terms, so a signature of
/// any other shape is not a signature this channel could verify.
fn signature(bytes: &[u8]) -> Option<Sig> {
    <[u8; Sig::LENGTH]>::try_from(bytes)
        .ok()
        .map(Sig::from_bytes)
}
