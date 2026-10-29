//! The paid-work wire: how a client proposes one job and a provider
//! accepts or refuses it.
//!
//! # What crosses the wire
//!
//! Canonical private records and content references. `AcceptWorkRequest`
//! carries canonical [`PaidJobAuthorizationV2`] bytes and a content reference
//! to the prepared input transferred by UploadContent. Signatures cover the
//! canonical authorization and its exact input commitment.
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
//! Signed events cross one authenticated result stream. The release marker
//! reserves delivery credit durably before its first plaintext prefix. The
//! client records the result only after verifying the complete terminal and
//! successful stream status; authenticated verification is durable before a
//! payment certificate leaves.
//!
//! A retry reads the retained spool and repeats the same release marker,
//! so delivery credit is debited once per job.
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

mod observation;
use hellas_rpc::pb::work::Refusable;
use hex::encode as hex;

use observation::Observation;
pub use observation::ObservationTime;

mod client_channel;
pub use client_channel::{ClientChannel, ClientDriver, ClientObserver, ClientService};

pub mod admission;
mod admitted;
pub use admitted::Admitted;
mod stream;
use admission::{AdmissionError, CapacityDomain, WorkAdmission, WorkPermit};
pub use stream::{PaidProgress, PaidResultStream, ProgressError, fetch_result_stream};

mod upload;
use hellas_rpc::protocol::content_upload::{decode_reference, encode_reference};
use hellas_rpc::{ContentId, ContentRef};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use upload::content_refusal;

use crate::endpoint_lock::{EndpointGuard, EndpointLock};

use hellas_kernel::{
    Decode as _, EarnedCertificate, Move, Party, PaymentCloseStart, PendingSlot, Secp256k1Signer,
    Secp256k1Verifier, Sig, SigVerifier as _, StartId, Tx,
};
use hellas_wire::{StreamTransport, TransportContext, WireStatus};

use prost::Message as _;

use crate::model::setup::{ObservedChannel, ReadyChannel, WorkSetupError};
use crate::model::work::encode_kernel;
use crate::model::work::{
    JobDeadlines, PaidJobAuthorizationV2, PaidJobResultV1, PaidWorkError, PaymentBindingV1,
    PrivateRecord as _, delivery_request_digest, encode_transcript, next_payment,
    payment_binding_digest, result_digest, signing_hash, work_id,
};
use crate::work_close::{
    CatchUpError, CloseChannel, CloseError, CloseProgress, FinalizedBlocks, FinalizedWork, TxSink,
    adjudicated_close, advance_close, catch_up, close_duty_present, close_response, close_start,
    observe, response_body_digest,
};
use crate::work_store::{
    Channel, ChannelRecord, ChannelStateError, ChannelStore, JobPhase, JobState, PaidCertificate,
    Role, TerminalOutcome, WorkStoreError,
};
use hellas_auth::Digest;
use hellas_rpc::observe::{LEVEL, TARGET, Timing};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    StreamResultRequest, WorkAccepted, WorkPaid, WorkRefusalCode, WorkRefused,
    accept_work_response::Outcome, admit_certificate_response::Outcome as AdmitOutcome,
};
use hellas_rpc::protocol::invocation::{AdmissionFacts, PreparedInvocation};
use hellas_rpc::services::work::{WorkClientImpl, WorkHandler};
use hellas_rpc::{OutputEventEnvelope, SubmitTxOutcome};

pub(super) struct ResultTranscript {
    result: Vec<u8>,
    provider_signature: Vec<u8>,
    transcript: Vec<u8>,
}

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
            WorkStoreError::Journal(_) | WorkStoreError::Setup(_) | WorkStoreError::Content(_) => {
                WorkRefusal::Unavailable
            }
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
    /// The background observer has not confirmed recent finalized progress.
    #[error("channel observation is stale; awaiting finalized progress")]
    ObservationStale,
    /// The journal is another channel's.
    #[error("the store's channel is not the one this readiness decided")]
    WrongChannel,
    /// The journal was opened at other funding than the readiness read
    /// found, so the two bound payments differently.
    #[error("the store's settlement is not the one this readiness read")]
    WrongSettlement,
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
/// [`WorkChannelDescriptor::check_ready`](crate::model::setup::WorkChannelDescriptor::check_ready)
/// refuses every one of those. A close capability that needed a
/// [`ReadyChannel`] could therefore never be built for the channels it
/// exists for.
///
/// The two facts every method here reads are the *store's*: the channel
/// each signature is bound to, and what the funded edge settles. Both
/// were fixed when the journal was opened, and `bind` is what asserts
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
/// [`crate::model::work::check_authorization`], never routed: routing many channels through
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
    observation: Option<Observation>,
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
    pub const fn state(&self) -> &Channel {
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
            observation: None,
        })
    }

    /// Wraps a close half as an endpoint that admits no new work.
    ///
    /// Private, because a caller wanting exactly this already has it:
    /// [`CloseEndpoint`] is the close capability, whole. This is what
    /// [`WorkService::close_only`] serves it behind, where one type has
    /// to carry both halves because one handler answers the wire.
    const fn close_only(close: CloseEndpoint) -> Self {
        Self {
            close,
            ready: None,
            observation: None,
        }
    }

    /// The readiness this endpoint admits new work under, or the refusal
    /// that says it has none.
    ///
    /// # Errors
    ///
    /// [`EndpointError::NotAdmitting`] when readiness is unavailable,
    /// and [`EndpointError::ObservationStale`]
    /// while awaiting fresh finalized progress.
    fn admitting(&self) -> Result<&ReadyChannel, EndpointError> {
        let ready = self.ready.as_ref().ok_or(EndpointError::NotAdmitting)?;
        if let Some(observation) = &self.observation {
            observation.check()?;
        }
        Ok(ready)
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
    pub const fn state(&self) -> &Channel {
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
    pub async fn accept(&mut self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        acceptance_response(self.decide(request).await)
    }

    fn authenticate_proposal(
        &self,
        request: &AcceptWorkRequest,
    ) -> Result<(PaidJobAuthorizationV2, Sig, Digest), Refusal> {
        if !request
            .route
            .as_ref()
            .is_some_and(|r| r.selects_payment(self.state().channel().id()))
        {
            return Err(Refusal::invalid(
                "the route does not select this payment channel",
            ));
        }
        let authorization = PaidJobAuthorizationV2::decode(&request.authorization)?;
        if authorization.channel_id != self.state().channel().id() {
            return Err(Refusal::invalid("the authorization names another channel"));
        }
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
        authorization: &PaidJobAuthorizationV2,
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

    async fn decide(&mut self, request: &AcceptWorkRequest) -> Result<(Digest, Sig), Refusal> {
        let (authorization, client_signature, work_id) = self.authenticate_proposal(request)?;
        self.close.store.gc_uploads()?;
        if let Some(retained) = self.prior_acceptance(&authorization, work_id)? {
            if let Some(job) = self.state().job_by_id(work_id) {
                let bytes = job.prepared_input().to_vec();
                if !bytes.is_empty() {
                    self.close
                        .store
                        .uploads
                        .publish_accepted(work_id, &bytes, authorization.retention)
                        .map_err(content_refusal)?;
                }
            }
            return Ok((work_id, retained));
        }
        let ready = self
            .admitting()
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))?
            .clone();
        if self.state().close_prepared().is_some()
            || self.state().close_opened().is_some()
            || self.state().close_settled().is_some()
        {
            return Err(Refusal::new(WorkRefusal::Declined, "channel is closing"));
        }
        let (cursor_height, _) = self.state().cursor();
        let policy = ready.invocation_policy();
        crate::job::check_authorization(
            ready.channel(),
            &authorization,
            policy,
            ready.payment_policy(),
            cursor_height,
        )?;
        ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        let reference = decode_reference(&request.prepared_input)
            .ok_or_else(|| Refusal::invalid("prepared input must be a content reference"))?;
        if reference != authorization.input_content {
            return Err(Refusal::invalid(
                "input reference differs from the signed proposal",
            ));
        }
        let prepared_input = self
            .close
            .store
            .uploads
            .read(work_id, reference, authorization.retention)
            .map_err(content_refusal)?;
        let bundle = PreparedInvocation::from_canonical_bytes(
            &prepared_input,
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(|error| Refusal::invalid(error.to_string()))?;
        crate::job::check_paid_input(ready.channel(), &authorization, policy, &bundle)?;

        let manifest = bundle
            .manifest()
            .map_err(|error| Refusal::invalid(error.to_string()))?;
        let root = self
            .close
            .store
            .uploads
            .root(work_id, manifest.root(), authorization.retention)
            .map_err(content_refusal)?;
        let objects =
            crate::job::content_closure(policy, &manifest, &root, authorization.input_content)?;
        let content = self
            .close
            .store
            .uploads
            .invocation_content(work_id, &objects, authorization.retention)
            .map_err(content_refusal)?;

        // The client's signature, its bundle, and the credit this job
        // costs, on the disk before a co-signature exists to leak.
        self.close
            .store
            .commit(
                ChannelRecord::JobProposed {
                    authorization,
                    client_signature,
                    prepared_input: prepared_input.clone(),
                },
                &Secp256k1Verifier::new(),
            )
            .await?;

        self.close.store.remember_content(work_id, content);
        let signature = self.close.signer.sign(signing_hash(work_id));
        self.close
            .store
            .commit(
                ChannelRecord::JobAccepted {
                    work_id,
                    provider_signature: signature,
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
        self.close
            .store
            .uploads
            .publish_accepted(work_id, &prepared_input, authorization.retention)
            .map_err(content_refusal)?;
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
    /// was never co-signed is refused rather than answered. A job whose
    /// input a metadata-only journal no longer holds is
    /// [`RunAdmission::Indeterminate`]: it must not be executed again.
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
    /// The authorization binds the exact request, manifest and input bytes.
    /// Retained content is recovered and verified from the content store;
    /// ephemeral content must still be present in this process's RAM.
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
    pub async fn begin_run(
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
        if ready.invocation_policy() != self.admitting()?.invocation_policy()
            || ready.payment_policy() != self.admitting()?.payment_policy()
        {
            return Err(RunError::Policy);
        }
        let (cursor_height, _) = self.state().cursor();
        let authorization = *job.authorization();
        crate::model::work::check_payment_policy_binding(
            ready.channel(),
            &authorization,
            ready.payment_policy(),
        )?;
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
        let bundle = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(PaidWorkError::from)?;
        let facts = crate::job::check_paid_input(
            ready.channel(),
            &authorization,
            ready.invocation_policy(),
            &bundle,
        )?;
        let admission = RunAdmission::Invoke(Box::new(Admitted::new(
            bundle,
            facts.limits,
            facts.capacity_domain,
            self.close
                .store
                .invocation_content(work_id, ready.invocation_policy())?,
            WorkAdmission::payment(),
        )));

        self.close
            .store
            .commit(
                ChannelRecord::JobRunning { work_id },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(admission)
    }

    /// Signs the result of the transcript this job's invocation
    /// produced, and returns it only once it is on the disk.
    ///
    /// The transcript is the provider's own: [`crate::job::paid_terminal_result`] refuses
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
    pub async fn record_result(
        &mut self,
        work_id: Digest,
        transcript: &[OutputEventEnvelope],
    ) -> Result<(PaidJobResultV1, Sig), RunError> {
        let job = self.state().job_by_id(work_id).ok_or(RunError::NoSuchJob)?;
        let authorization = *job.authorization();
        let input = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(|e| RunError::Transcript(e.into()))?;
        let ready = self
            .ready
            .as_ref()
            .ok_or(EndpointError::NotAdmitting)?
            .clone();
        // The last fresh readiness, deliberately not `admitting()`: a result
        // signature commits nothing the payment path does not gate on its
        // own freshness check, and refusing here would discard completed
        // upstream work that the client may still pay for. Release and
        // payment still require a fresh observation.
        let channel = ready.channel();
        let result = crate::job::paid_terminal_result(
            channel,
            &authorization,
            ready.invocation_policy(),
            &input,
            transcript,
        )
        .map_err(RunError::Transcript)?;
        let spool = encode_transcript(transcript).map_err(RunError::Transcript)?;
        let facts = crate::job::check_paid_input(
            channel,
            &authorization,
            ready.invocation_policy(),
            &input,
        )?;
        let signature = self
            .close
            .signer
            .sign(signing_hash(result_digest(channel, &result)));
        let delivered = ResultTranscript {
            result: result.encode(),
            provider_signature: signature.as_bytes().to_vec(),
            transcript: Vec::new(),
        };
        for frame in stream::result_frames(&delivered, transcript, facts.max_encoded_result_frame) {
            let frame = frame?;
            if frame.encoded_len() as u64
                > u64::from(facts.max_encoded_result_frame)
                    .min(hellas_wire::frame::MAX_FRAME_BYTES as u64)
            {
                return Err(RunError::Record(PaidWorkError::OverEnvelope {
                    field: "encoded result frame",
                    actual: frame.encoded_len() as u64,
                    limit: u64::from(facts.max_encoded_result_frame),
                }));
            }
        }
        self.close
            .store
            .commit(
                ChannelRecord::JobResult {
                    work_id,
                    result,
                    provider_signature: signature,
                    transcript: spool,
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok((result, signature))
    }

    /// A retained terminal needs authentication, but no permission to admit
    /// new work. Actual delivery still uses this endpoint's readiness, or
    /// the explicitly supplied decision checked against it below.
    async fn release_ready(
        &mut self,
        request: &StreamResultRequest,
        ready: Option<&ReadyChannel>,
        exporter: &[u8; 32],
    ) -> Result<Delivery, DeliverError> {
        if !request
            .route
            .as_ref()
            .is_some_and(|r| r.selects_payment(self.state().channel().id()))
        {
            return Err(DeliverError::Malformed("channel route"));
        }
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
        if self.state().is_closing() {
            return Err(EndpointError::NotAdmitting.into());
        }
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
        crate::model::work::check_payment_policy_binding(
            ready.channel(),
            job.authorization(),
            ready.payment_policy(),
        )?;
        let terminal_deadline = job.authorization().terminal_deadline;

        bind(ready, &self.close.store, &self.close.signer, Role::Provider)?;
        if ready.invocation_policy() != admitted.invocation_policy()
            || ready.payment_policy() != admitted.payment_policy()
        {
            return Err(DeliverError::Policy);
        }
        let (cursor_height, _) = self.state().cursor();
        ready.check_releasable(cursor_height, terminal_deadline)?;

        self.close
            .store
            .commit(
                ChannelRecord::PlaintextReleased { work_id },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    pub async fn admit(&mut self, request: &AdmitCertificateRequest) -> Result<u64, PaymentError> {
        if !request
            .route
            .as_ref()
            .is_some_and(|r| r.selects_payment(self.state().channel().id()))
        {
            return Err(PaymentError::Malformed("channel route"));
        }
        let certificate = earned_certificate(&request.certificate)
            .ok_or(PaymentError::Malformed("certificate"))?;
        let binding = PaymentBindingV1::decode(&request.binding)?;
        let work_id = binding.work_id;
        let binding_signature = signature(&request.binding_signature)
            .ok_or(PaymentError::Malformed("binding signature"))?;
        let certificate_signature = signature(&request.certificate_signature)
            .ok_or(PaymentError::Malformed("certificate signature"))?;

        if self.state().payment(work_id).is_none()
            && let Some(observation) = &self.observation
        {
            observation.check()?;
        }

        let signed_result = self
            .state()
            .job_by_id(work_id)
            .and_then(|job| job.result().copied())
            .or_else(|| {
                self.state()
                    .terminal_by_id(work_id)
                    .and_then(|terminal| match &terminal.outcome {
                        TerminalOutcome::Certified { signed_result, .. } => Some(**signed_result),
                        _ => None,
                    })
            })
            .ok_or_else(|| {
                WorkStoreError::Channel(
                    if let Some(terminal) = self.state().terminal_by_id(work_id) {
                        ChannelStateError::Terminated {
                            step: "crediting a payment",
                            outcome: terminal.outcome.name(),
                        }
                    } else if let Some(job) = self.state().job_by_id(work_id) {
                        ChannelStateError::WrongPhase {
                            step: "crediting a payment",
                            phase: job.phase().name(),
                        }
                    } else {
                        ChannelStateError::WrongChannel {
                            field: "binding work_id",
                        }
                    },
                )
            })?;
        let state = self
            .close
            .store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id,
                    outcome: TerminalOutcome::Certified {
                        signed_result: Box::new(signed_result),
                        certificate,
                        binding: Box::new(binding),
                        binding_signature,
                        certificate_signature,
                    },
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    pub async fn end_run(&mut self, work_id: Digest) -> Result<(), RunError> {
        self.state().job_by_id(work_id).ok_or(RunError::NoSuchJob)?;
        self.close
            .store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id,
                    outcome: TerminalOutcome::Failed {
                        code: PROVIDER_FAULT_CODE,
                    },
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
async fn retain_close_start(
    store: &mut ChannelStore,
    start: &PaymentCloseStart,
) -> Result<(), WorkStoreError> {
    let fsynced = Timing::start();
    store
        .commit(
            ChannelRecord::ClosePrepared {
                start: Box::new(start.clone()),
            },
            &Secp256k1Verifier::new(),
        )
        .await?;
    if let Some(ms) = fsynced.ms() {
        tracing::event!(
            name: "close_prepared_fsync_ms",
            target: TARGET,
            LEVEL,
            edge = %hex(start.payment_edge().to_bytes()),
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
    pub async fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&Channel, WorkStoreError> {
        observe(&mut self.store, block, &Secp256k1Verifier::new()).await?;
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
    pub async fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
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
        retain_close_start(&mut self.store, &start).await?;
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
    async fn fix_close_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, WorkStoreError> {
        let Some((responded, response)) = self.close_duty(start_id)? else {
            return Ok(None);
        };
        self.store
            .commit(responded, &Secp256k1Verifier::new())
            .await?;
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
    /// [`Channel::answerable_contest`]'s judgement and no second
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
    fn close_duty(&self, start_id: StartId) -> Result<Option<(ChannelRecord, Tx)>, WorkStoreError> {
        if self.accepted_contest() == Some(start_id) {
            return Ok(None);
        }
        let Some((contest, certificate)) = self.state().answerable_contest() else {
            return Ok(None);
        };
        if contest.start_id != start_id {
            return Ok(None);
        }
        let channel = self.state().channel();
        let response =
            close_response(channel, start_id, certificate, &self.signer).map_err(|_| {
                WorkStoreError::Channel(ChannelStateError::WrongChannel {
                    field: "close response signer",
                })
            })?;
        Ok(Some((
            ChannelRecord::CloseResponded {
                start_id,
                response_digest: response_body_digest(channel, start_id, &certificate.0),
            },
            Tx::move_action(Move::RespondPaymentClose(response)),
        )))
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
    pub async fn respond_to_close(
        &mut self,
        observed: &ObservedChannel<'_>,
    ) -> Result<Tx, CloseError> {
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
        let response = close_response(&channel, held, certificate, &self.signer)?;
        self.store
            .commit(
                ChannelRecord::CloseResponded {
                    start_id: held,
                    response_digest: response_body_digest(&channel, held, &certificate.0),
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    pub async fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&Channel, WorkStoreError> {
        self.close.observe_finalized(block).await
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
    pub async fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
        self.close.prepare_close().await
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
    pub async fn respond_to_close(
        &mut self,
        observed: &ObservedChannel<'_>,
    ) -> Result<Tx, CloseError> {
        self.close.respond_to_close(observed).await
    }
}

/// A provider that owns its journal outright lends it directly, and owns
/// the answer it may have to give.
impl CloseChannel for CloseEndpoint {
    async fn store(&mut self) -> Result<impl DerefMut<Target = ChannelStore> + Send, CatchUpError> {
        Ok(&mut self.store)
    }

    async fn handoff(&mut self) -> Result<Option<(StartId, Handoff)>, CatchUpError> {
        Ok(self.close_handoff)
    }

    async fn fix_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, CatchUpError> {
        Ok(self.fix_close_answer(start_id).await?)
    }

    async fn record_handoff(
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
    async fn store(&mut self) -> Result<impl DerefMut<Target = ChannelStore> + Send, CatchUpError> {
        Ok(&mut self.store)
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
    pub async fn observe_finalized(
        &mut self,
        block: &FinalizedWork,
    ) -> Result<&Channel, WorkStoreError> {
        observe(&mut self.store, block, &Secp256k1Verifier::new()).await?;
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

/// A backend failure preserves its cause for the operator. Wire adapters decide
/// which details can be disclosed to the caller.
#[derive(Debug, thiserror::Error)]
#[error("the execution backend failed: {0}")]
pub struct BackendFault(#[source] Box<dyn std::error::Error + Send + Sync>);

impl BackendFault {
    pub fn caused_by(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}
impl From<AdmissionError> for BackendFault {
    fn from(error: AdmissionError) -> Self {
        Self::caused_by(error)
    }
}

/// One application-neutral invocation seam after funding and resource admission.
pub trait WorkBackend: Sync {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault>;
    fn execute(
        &self,
        input: Admitted<PreparedInvocation>,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async move { Err(AdmissionError::Unsupported(input.capacity_domain()).into()) }
    }
    fn execute_stream(
        &self,
        input: Admitted<PreparedInvocation>,
        progress: PaidProgress,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        async move {
            let events = self.execute(input).await?;
            for event in &events[..events.len().saturating_sub(1)] {
                progress(event.clone())?;
            }
            Ok(events)
        }
    }
}

/// What [`ProviderEndpoint::begin_run`] found, and what may be done next.
#[derive(Debug)]
pub enum RunAdmission {
    /// The marker is durable and the backend has not been called.
    /// Invoke exactly once, with this journaled input.
    Invoke(Box<Admitted<PreparedInvocation>>),
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
/// the invocation's events are held by its content view and the result stream
/// serves them. Handing them back
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
/// deliberate — the journal must not be held across an
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
    B: WorkBackend + Sync,
{
    let admission = service.begin_run(work_id, ready).await?;
    let input = match admission {
        RunAdmission::Invoke(input) => *input,
        RunAdmission::Running => return Ok(RunOutcome::Running),
        RunAdmission::Indeterminate => return Ok(RunOutcome::Indeterminate),
        RunAdmission::Ready { result, signature } => {
            return Ok(RunOutcome::Ready { result, signature });
        }
    };
    let facts = ready
        .invocation_policy()
        .admit(
            input.invocation(),
            &hellas_auth::PublicKey::Secp256k1(ready.channel().client_key().to_bytes()),
        )
        .map_err(PaidWorkError::from)?;
    let progress_service = service.clone();
    let progress: PaidProgress =
        Arc::new(move |event| progress_service.publish_progress(work_id, &facts, event));

    let transcript = match backend.execute_stream(input, progress).await {
        Ok(transcript) => transcript,
        Err(fault) => return Err(end_failed(service, work_id, RunError::Backend(fault)).await),
    };

    match service.record_result(work_id, &transcript).await {
        Ok((result, signature)) => Ok(RunOutcome::Completed { result, signature }),
        // A transcript that is not this job's, and a result the signed
        // envelope would not carry, are the same kind of fault: the
        // backend produced something this provider cannot turn into a
        // delivery. Both end the job, and both charge the client
        // nothing.
        Err(fault @ (RunError::Transcript(_) | RunError::Record(_))) => {
            Err(end_failed(service, work_id, fault).await)
        }
        Err(error) => Err(error),
    }
}

// ── Delivering the answer ─────────────────────────────────────────────

/// One whole delivery: the signed result and the transcript it
/// summarises.
///
/// The two travel together because neither is the answer alone. The
/// result is a pair of digests the provider stands behind; the
/// transcript is the signed events those digests authenticate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// The provider's signed result.
    pub result: PaidJobResultV1,
    /// The provider's signature over its digest.
    pub signature: Sig,
    /// The encoded transcript, as [`decode_transcript`](crate::model::work::decode_transcript) reads it.
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
            DeliverError::Endpoint(EndpointError::CatchingUp | EndpointError::ObservationStale) => {
                WorkRefusal::NotReady
            }
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
    /// The shared client endpoint is unavailable.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
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
            PaymentError::Endpoint(error) => endpoint_refusal(error),
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
fn admit_request(channel_id: Digest, payment: &PaidCertificate) -> AdmitCertificateRequest {
    AdmitCertificateRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(channel_id)),
        certificate: encode_kernel(&payment.certificate),
        binding: payment.binding.encode(),
        binding_signature: payment.binding_signature.as_bytes().to_vec(),
        certificate_signature: payment.certificate_signature.as_bytes().to_vec(),
    }
}

/// Ends the job as failed, and returns `fault` if that ending was
/// recorded.
async fn end_failed(service: &WorkService, work_id: Digest, fault: RunError) -> RunError {
    match service.end_run(work_id).await {
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
/// concurrent calls of one. Acquiring it yields to other tasks. Journal I/O
/// may await under the guard; chain, transport and backend waits must release it.
///
/// One type carries both halves because one handler answers the wire,
/// and the halves are not both always present: [`Self::close_only`]
/// serves a channel that admits no new work, and every admission method
/// on it answers [`EndpointError::NotAdmitting`] until
/// [`Self::admit_new_work`] is given a fresh readiness decision. Nothing
/// about a close consults that option.
#[derive(Clone, Debug)]
pub struct WorkService {
    endpoint: Arc<EndpointLock<ProviderEndpoint>>,
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
    pub async fn observe_finalized(&mut self, block: &FinalizedWork) -> Result<(), CatchUpError> {
        let mut endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
        self.readable_cursor(&endpoint)?;
        endpoint.observe_finalized(block).await?;
        drop(endpoint);
        self.service.changed.notify_waiters();
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
        let cursor = self.cursor().await?;
        let Some(latest) = source.latest_height().await? else {
            return Ok(cursor);
        };
        self.catch_up_to(source, latest).await
    }

    /// Applies history through a fixed snapshot height, respecting close duties.
    pub async fn catch_up_to<S: FinalizedBlocks + ?Sized>(
        &mut self,
        source: &S,
        latest: u64,
    ) -> Result<u64, CatchUpError> {
        let mut cursor = self.cursor().await?;
        while cursor < latest {
            let next = cursor.saturating_add(1);
            let block = source
                .block_at(next)
                .await?
                .ok_or(CatchUpError::Missing { height: next })?;
            self.observe_finalized(&block).await?;
            cursor = self.cursor().await?;
        }
        Ok(cursor)
    }

    /// The cursor this driver may read on from, or the duty that stops
    /// it.
    async fn cursor(&self) -> Result<u64, CatchUpError> {
        let endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
        self.readable_cursor(&endpoint)
    }

    /// Refuses a driver that named a job this channel's journal does not
    /// hold.
    ///
    /// The open job and the permanent terminal both name it, and either
    /// one contradicts a stranger: ending a job clears the open one but
    /// keeps the terminal, so a check that read only the open job would
    /// stop refusing the moment the job was certified, expired, failed
    /// or rejected.
    ///
    /// A channel that has neither holds no job to contradict, which is
    /// the acceptance phase boundary's own case: the digest being caught
    /// up for is the proposal's, and the journal learns it from the
    /// acceptance this read precedes.
    async fn for_job(&self, work_id: Digest) -> Result<(), CatchUpError> {
        let endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
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

/// A journal projection that retains endpoint ownership and panic handling.
enum ChannelStoreGuard<'a> {
    Provider(EndpointGuard<'a, ProviderEndpoint>),
    Client(EndpointGuard<'a, ClientEndpoint>),
}

impl Deref for ChannelStoreGuard<'_> {
    type Target = ChannelStore;
    fn deref(&self) -> &ChannelStore {
        match self {
            Self::Provider(endpoint) => &endpoint.close.store,
            Self::Client(endpoint) => &endpoint.store,
        }
    }
}

impl DerefMut for ChannelStoreGuard<'_> {
    fn deref_mut(&mut self) -> &mut ChannelStore {
        match self {
            Self::Provider(endpoint) => &mut endpoint.close.store,
            Self::Client(endpoint) => &mut endpoint.store,
        }
    }
}

impl CloseChannel for ChannelDriver<'_> {
    async fn store(&mut self) -> Result<impl DerefMut<Target = ChannelStore> + Send, CatchUpError> {
        Ok(ChannelStoreGuard::Provider(
            self.service
                .endpoint()
                .await
                .map_err(|_| CatchUpError::Busy)?,
        ))
    }

    async fn handoff(&mut self) -> Result<Option<(StartId, Handoff)>, CatchUpError> {
        let endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
        Ok(endpoint.close.close_handoff)
    }

    async fn fix_answer(&mut self, start_id: StartId) -> Result<Option<Tx>, CatchUpError> {
        let mut endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
        Ok(endpoint.close.fix_close_answer(start_id).await?)
    }

    async fn record_handoff(
        &mut self,
        start_id: StartId,
        outcome: SubmitTxOutcome,
    ) -> Result<(), CatchUpError> {
        let mut endpoint = self
            .service
            .endpoint()
            .await
            .map_err(|_| CatchUpError::Busy)?;
        endpoint.close.record_close_handoff(start_id, outcome);
        Ok(())
    }
}

impl WorkService {
    /// Wraps one provider endpoint as a dispatchable service.
    #[must_use]
    pub fn new(endpoint: ProviderEndpoint) -> Self {
        Self {
            endpoint: Arc::new(EndpointLock::new(endpoint)),
            driving: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(tokio::sync::Notify::new()),
            progress: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        }
    }

    /// Wraps one close half as a service that drives closes and admits
    /// no new work.
    ///
    /// This is the mount a channel gets when
    /// [`WorkChannelDescriptor::check_ready`](crate::model::setup::WorkChannelDescriptor::check_ready)
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
    /// [`WorkChannelDescriptor::check_ready`](crate::model::setup::WorkChannelDescriptor::check_ready)
    /// produces. Nothing here refreshes it afterwards: its freshness is
    /// the caller's in exactly the sense [`ReadyChannel`] documents.
    ///
    /// # Errors
    ///
    /// [`EndpointError::Poisoned`] when the endpoint is unreachable, and
    /// the binding errors when the decision is not this journal's own
    /// channel at its own settlement.
    pub async fn admit_new_work(&self, ready: ReadyChannel) -> Result<(), EndpointError> {
        self.endpoint().await?.admit_new_work(ready)
    }

    /// Requires a live background observer before accepting or releasing work.
    pub async fn require_observer(&self) -> Result<(), EndpointError> {
        self.endpoint().await?.observation = Some(Observation::default());
        Ok(())
    }

    /// Publishes readiness after applying all blocks through its snapshot.
    pub async fn observe_ready(
        &self,
        ready: ReadyChannel,
        started: ObservationTime,
        max_age: std::time::Duration,
    ) -> Result<(), EndpointError> {
        let mut endpoint = self.endpoint().await?;
        if ready.check_caught_up(endpoint.state().cursor().0).is_err() {
            return Err(EndpointError::CatchingUp);
        }
        let height = ready.finalized_height();
        endpoint.admit_new_work(ready)?;
        endpoint
            .observation
            .get_or_insert_with(Observation::default)
            .confirm(height, started, max_age);
        drop(endpoint);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Withdraws release permission after a coherent finalized readiness denial.
    /// The last policy remains available for recording completed upstream work.
    pub async fn observe_unavailable(&self, height: u64) -> Result<(), EndpointError> {
        self.endpoint()
            .await?
            .observation
            .get_or_insert_with(Observation::default)
            .reject(height);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Ends admission and delivery after accepted work and the observer have stopped.
    pub async fn stop(&self) -> Result<(), EndpointError> {
        let mut endpoint = self.endpoint().await?;
        let height = endpoint.state().cursor().0;
        endpoint.ready = None;
        endpoint
            .observation
            .get_or_insert_with(Observation::default)
            .reject(height);
        drop(endpoint);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Reads current local admission; no chain I/O is performed.
    pub async fn readiness(&self) -> Result<ReadyChannel, EndpointError> {
        let endpoint = self.endpoint().await?;
        if endpoint.state().is_closing() {
            return Err(EndpointError::NotAdmitting);
        }
        endpoint.admitting().cloned()
    }

    /// Revokes observer freshness without discarding results or close duties.
    pub async fn suspend(&self) -> Result<(), EndpointError> {
        // An endpoint without an observer has no freshness to revoke;
        // installing a defaulted one here would only close admission.
        if let Some(observation) = self.endpoint().await?.observation.as_mut() {
            observation.suspend();
            self.changed.notify_waiters();
        }
        Ok(())
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
    async fn endpoint(&self) -> Result<EndpointGuard<'_, ProviderEndpoint>, EndpointError> {
        self.endpoint
            .lock()
            .await
            .map_err(|_| EndpointError::Poisoned)
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
    /// [`EndpointError::Poisoned`], as `endpoint` documents.
    pub async fn with_state<R>(
        &self,
        read: impl FnOnce(&Channel) -> R,
    ) -> Result<R, EndpointError> {
        Ok(read(self.endpoint().await?.state()))
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
        driver.for_job(work_id).await?;
        driver.catch_up(source).await
    }

    /// Signs, or returns, this channel's retained close start.
    ///
    /// # Errors
    ///
    /// [`CloseError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::prepare_close`] raises otherwise.
    pub async fn prepare_close(&self) -> Result<PaymentCloseStart, CloseError> {
        self.endpoint().await?.prepare_close().await
    }

    /// Builds the close that ends this endpoint's contest, from one
    /// coherent finalized read.
    ///
    /// # Errors
    ///
    /// [`CloseError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::adjudicated_close`] raises otherwise.
    pub async fn adjudicated_close(
        &self,
        observed: &ObservedChannel<'_>,
    ) -> Result<Tx, CloseError> {
        self.endpoint().await?.adjudicated_close(observed)
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

    /// Answers an authenticated proposal from retained state alone, when
    /// possible, without signing, writing the journal, or requiring readiness.
    ///
    /// A retained acceptance takes precedence over expiry: its acknowledgement
    /// may have been lost. Otherwise a retained terminal or an acceptance
    /// deadline already passed by the persisted cursor is permanent. Malformed
    /// or unauthenticated requests are refused before consulting job state.
    /// `None` means fresh readiness and the normal acceptance checks are needed.
    #[must_use]
    pub async fn precheck_acceptance(
        &self,
        request: &AcceptWorkRequest,
    ) -> Option<AcceptWorkResponse> {
        let result = self
            .endpoint()
            .await
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))
            .and_then(|mut endpoint| {
                let (authorization, _, work_id) = endpoint.authenticate_proposal(request)?;
                let retained = endpoint.prior_acceptance(&authorization, work_id)?;
                if retained.is_some()
                    && let Some(job) = endpoint.state().job_by_id(work_id)
                {
                    let bytes = job.prepared_input().to_vec();
                    if !bytes.is_empty() {
                        endpoint
                            .close
                            .store
                            .uploads
                            .publish_accepted(work_id, &bytes, authorization.retention)
                            .map_err(content_refusal)?;
                    }
                }
                Ok(retained.map(|signature| (work_id, signature)))
            });
        result.transpose().map(acceptance_response)
    }

    /// Answers one proposal, or says the endpoint is unreachable.
    pub async fn accept(&self, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        match self.endpoint().await {
            Ok(mut endpoint) => endpoint.accept(request).await,
            Err(error) => AcceptWorkResponse::refused(WorkRefused {
                grant: None,
                code: endpoint_refusal(error).code() as i32,
                reason: error.to_string(),
            }),
        }
    }

    /// Admits one accepted job for a real invocation, and journals the
    /// running marker before it says so.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::begin_run`] raises otherwise.
    pub async fn begin_run(
        &self,
        work_id: Digest,
        ready: &ReadyChannel,
    ) -> Result<RunAdmission, RunError> {
        let result = self.endpoint().await?.begin_run(work_id, ready).await;
        self.changed.notify_waiters();
        result
    }

    /// Signs and journals the result of one invocation's transcript.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::record_result`] raises otherwise.
    pub async fn record_result(
        &self,
        work_id: Digest,
        transcript: &[OutputEventEnvelope],
    ) -> Result<(PaidJobResultV1, Sig), RunError> {
        let result = self
            .endpoint()
            .await?
            .record_result(work_id, transcript)
            .await;
        let result = result.and_then(|completed| {
            self.progress
                .lock()
                .map_err(|_| RunError::Backend(BackendFault::caused_by(ProgressError::Poisoned)))?
                .remove(&work_id);
            Ok(completed)
        });
        self.changed.notify_waiters();
        result
    }

    /// Ends the open job as this provider's own failure.
    ///
    /// # Errors
    ///
    /// [`RunError::Endpoint`] when the endpoint is unreachable, and
    /// whatever [`ProviderEndpoint::end_run`] raises otherwise.
    pub async fn end_run(&self, work_id: Digest) -> Result<(), RunError> {
        let result = self.endpoint().await?.end_run(work_id).await;
        let cleanup = self
            .progress
            .lock()
            .map(|mut progress| {
                progress.remove(&work_id);
            })
            .map_err(|_| RunError::Backend(BackendFault::caused_by(ProgressError::Poisoned)));
        self.changed.notify_waiters();
        result.and(cleanup)
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
    async fn retained_delivery(
        &self,
        request: &StreamResultRequest,
        context: &TransportContext,
    ) -> Result<Delivery, Refusal> {
        let exporter = context
            .open_exporter
            .ok_or_else(|| Refusal::from(DeliverError::Unbindable))?;
        self.endpoint()
            .await
            .map_err(|e| Refusal::new(endpoint_refusal(e), e.to_string()))?
            .release_ready(request, None, &exporter)
            .await
            .map_err(Refusal::from)
    }

    /// Admits one payment, or says why not.
    ///
    /// The answer is produced after [`ProviderEndpoint::admit`] returns,
    /// which is after its record is fsynced. Nothing on this path can
    /// acknowledge a payment the disk does not hold.
    async fn credit(&self, request: &AdmitCertificateRequest) -> AdmitCertificateResponse {
        let outcome = match self.endpoint().await {
            Ok(mut endpoint) => endpoint.admit(request).await.map_err(Refusal::from),
            Err(error) => Err(Refusal::new(endpoint_refusal(error), error.to_string())),
        };
        AdmitCertificateResponse {
            outcome: Some(match outcome {
                Ok(credited_cumulative) => AdmitOutcome::Paid(WorkPaid {
                    credited_cumulative,
                }),
                Err(refusal) => AdmitOutcome::Refused(WorkRefused {
                    grant: None,
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
        EndpointError::CatchingUp
        | EndpointError::NotAdmitting
        | EndpointError::ObservationStale => WorkRefusal::NotReady,
        _ => WorkRefusal::Unavailable,
    }
}

impl WorkHandler for WorkService {
    async fn get_standing(
        &self,
        _request: hellas_rpc::pb::work::GetStandingRequest,
        _context: TransportContext,
    ) -> Result<
        impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::GetStandingResponse>> + Send,
        WireStatus,
    > {
        use hellas_rpc::pb::work::GetStandingResponse;
        Ok(GetStandingResponse::refused(WorkRefused {
            code: WorkRefusalCode::Invalid as i32,
            reason: "GetStanding requires grant funding".into(),
            grant: None,
        }))
    }

    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send, WireStatus>
    {
        Ok(self.accept(&request).await)
    }

    async fn upload_content(
        &self,
        request: hellas_rpc::pb::work::UploadContentRequest,
        context: TransportContext,
    ) -> Result<
        impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::UploadContentResponse>> + Send,
        WireStatus,
    > {
        self.upload(&request, &context).await
    }

    async fn stream_result(
        &self,
        request: StreamResultRequest,
        context: TransportContext,
    ) -> Result<PaidResultStream, WireStatus> {
        Ok(self.result_stream(request, context))
    }

    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send, WireStatus>
    {
        Ok(self.credit(&request).await)
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
/// bundle by [`crate::model::work::propose_authorization`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobProposal {
    /// The inputs the job runs on.
    pub prepared_input: PreparedInvocation,
    /// The three heights the job is bound by.
    pub deadlines: JobDeadlines,
}

/// Why a client could not complete one acceptance exchange.
#[derive(Debug, thiserror::Error)]
pub enum ProposeError {
    #[error(transparent)]
    Content(#[from] crate::content::ContentError),
    /// The shared client endpoint is unavailable.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
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
    ready: Option<ReadyChannel>,
    observation: Option<Observation>,
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
            ready: Some(ready),
            observation: None,
            store,
            signer,
        })
    }

    /// Reopens accounting and close duties without requiring an open channel.
    pub fn recover(store: ChannelStore, signer: Secp256k1Signer) -> Result<Self, EndpointError> {
        bind_store(&store, &signer, Role::Client)?;
        Ok(Self {
            ready: None,
            observation: None,
            store,
            signer,
        })
    }

    /// Returns what this endpoint durably knows.
    #[must_use]
    pub const fn state(&self) -> &Channel {
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
    pub async fn propose(
        &mut self,
        proposal: &JobProposal,
    ) -> Result<AcceptWorkRequest, ProposeError> {
        if let Some(observation) = &self.observation {
            observation.check()?;
        }
        let (cursor_height, _) = self.state().cursor();
        let ready = self.ready.as_ref().ok_or(EndpointError::NotAdmitting)?;
        let policy = ready.invocation_policy();

        let mut retry = None;
        for job in self
            .state()
            .jobs()
            .filter(|job| job.phase() == JobPhase::HalfSigned)
        {
            let retained = *job.authorization();
            let rebuilt = crate::job::propose(
                self.state().channel(),
                policy,
                ready.payment_policy(),
                &proposal.prepared_input,
                retained.proposal_nonce,
                proposal.deadlines,
            )?;
            if rebuilt != retained {
                continue;
            }
            let request = wire_request(
                &retained,
                job.client_signature(),
                job.prepared_input().to_vec(),
            );
            let id = job.work_id();
            retry = Some((id, request));
            break;
        }

        if let Some((id, request)) = retry {
            self.mark_proposal_pending(id).await?;
            return Ok(request);
        }

        if self.state().job_book().pending_proposal().is_some() {
            return Err(ProposeError::Conflict);
        }

        // Nonces form a durable high-water mark. Accepted executions overlap; acceptance proposals wait for a reply.
        // No crash or reordered response can make
        // the sequence move backwards or reuse a number.
        let proposal_nonce = self.state().proposal_nonce_high_water().saturating_add(1);
        let authorization = crate::job::propose(
            self.state().channel(),
            policy,
            ready.payment_policy(),
            &proposal.prepared_input,
            proposal_nonce,
            proposal.deadlines,
        )?;
        crate::job::check_authorization(
            self.state().channel(),
            &authorization,
            policy,
            ready.payment_policy(),
            cursor_height,
        )?;
        crate::job::check_paid_input(
            self.state().channel(),
            &authorization,
            policy,
            &proposal.prepared_input,
        )?;
        ready.check_signable(
            cursor_height,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        let prepared_input = proposal
            .prepared_input
            .canonical_bytes()
            .map_err(PaidWorkError::from)?;
        let work_id = work_id(self.state().channel(), &authorization);

        let signature = self.signer.sign(signing_hash(work_id));
        self.store
            .commit(
                ChannelRecord::JobProposed {
                    authorization,
                    client_signature: signature,
                    prepared_input: prepared_input.clone(),
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(wire_request(&authorization, signature, prepared_input))
    }

    /// Resend a half-signed proposal exactly as journaled, including the
    /// original policy and deadlines. No nonce or new signature is created.
    ///
    /// # Errors
    /// Returns [`ProposeError::NoOpenJob`] for an unknown job and
    /// [`ProposeError::JobInFlight`] if the provider already co-signed it.
    pub async fn resume_proposal(
        &mut self,
        work_id: Digest,
    ) -> Result<AcceptWorkRequest, ProposeError> {
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(ProposeError::NoOpenJob)?;
        if job.phase() != JobPhase::HalfSigned {
            return Err(ProposeError::JobInFlight { phase: job.phase() });
        }
        let request = wire_request(
            job.authorization(),
            job.client_signature(),
            job.prepared_input().to_vec(),
        );
        self.mark_proposal_pending(work_id).await?;
        Ok(request)
    }

    async fn mark_proposal_pending(&mut self, work_id: Digest) -> Result<(), ProposeError> {
        if self
            .state()
            .job_book()
            .pending_proposal()
            .is_some_and(|held| held != work_id)
        {
            return Err(ProposeError::Conflict);
        }
        self.store
            .commit(
                ChannelRecord::ProposalExchange {
                    work_id,
                    pending: true,
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(())
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
    pub async fn accepted(
        &mut self,
        response: &AcceptWorkResponse,
    ) -> Result<Digest, ProposeError> {
        let (work_id, signature) = match response.outcome.as_ref() {
            Some(Outcome::Accepted(accepted)) => (
                work_id_bytes(&accepted.work_id).ok_or(ProposeError::Malformed("work id"))?,
                signature(&accepted.provider_signature)
                    .ok_or(ProposeError::Malformed("provider signature"))?,
            ),
            Some(Outcome::Refused(refused)) => {
                let refusal = WorkRefusal::from_code(refused.code)
                    .ok_or(ProposeError::Malformed("refusal code"))?;
                let work_id = self
                    .state()
                    .job_book()
                    .pending_proposal()
                    .ok_or(ProposeError::NoOpenJob)?;
                self.store
                    .commit(
                        ChannelRecord::ProposalExchange {
                            work_id,
                            pending: false,
                        },
                        &Secp256k1Verifier::new(),
                    )
                    .await?;
                return Err(ProposeError::Refused {
                    refusal,
                    reason: refused.reason.clone(),
                });
            }
            None => return Err(ProposeError::Malformed("outcome")),
        };
        if self
            .state()
            .job_book()
            .pending_proposal()
            .is_some_and(|pending| pending != work_id)
        {
            return Err(ProposeError::Conflict);
        }
        self.state()
            .job_by_id(work_id)
            .ok_or(ProposeError::NoOpenJob)?;
        self.store
            .commit(
                ChannelRecord::JobAccepted {
                    work_id,
                    provider_signature: signature,
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    pub async fn prepare_close(&mut self) -> Result<PaymentCloseStart, CloseError> {
        let (height, _) = self.state().cursor();
        if let Some(retained) = self.state().includable_close_start(height) {
            return Ok(retained.clone());
        }
        let start = close_start(
            self.state().channel(),
            Party::Maker,
            height,
            self.state().executable_certificate(),
            &self.signer,
        )?;
        retain_close_start(&mut self.store, &start).await?;
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

    /// Accepts a complete stream only after its EOF, trailer and signed result verify.
    async fn receive_stream(
        &mut self,
        work_id: Digest,
        ready: &ReadyChannel,
        delivered: &ResultTranscript,
    ) -> Result<Delivery, DeliverError> {
        bind(ready, &self.store, &self.signer, Role::Client)?;
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        crate::model::work::check_payment_policy_binding(
            ready.channel(),
            job.authorization(),
            ready.payment_policy(),
        )?;
        if ready.invocation_policy()
            != self
                .ready
                .as_ref()
                .ok_or(EndpointError::NotAdmitting)?
                .invocation_policy()
        {
            return Err(DeliverError::Policy);
        }
        ready.check_caught_up(self.state().cursor().0)?;
        let result = PaidJobResultV1::decode(&delivered.result)?;
        let signature = signature(&delivered.provider_signature)
            .ok_or(DeliverError::Malformed("provider signature"))?;
        self.store
            .commit(
                ChannelRecord::JobResult {
                    work_id,
                    result,
                    provider_signature: signature,
                    transcript: delivered.transcript.clone(),
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    ) -> Result<StreamResultRequest, DeliverError> {
        self.state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let signature = self.signer.sign(signing_hash(delivery_request_digest(
            self.state().channel(),
            work_id,
            exporter,
        )));
        Ok(StreamResultRequest {
            route: Some(hellas_rpc::pb::work::WorkRoute::payment(
                self.state().channel().id(),
            )),
            work_id: work_id.as_bytes().to_vec(),
            client_signature: signature.as_bytes().to_vec(),
        })
    }

    /// Durably records authenticated invocation verification before payment.
    /// The store rechecks the exact input, signed output and stop rule.
    pub async fn verified(&mut self, work_id: Digest) -> Result<(), DeliverError> {
        self.state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        self.store
            .commit(
                ChannelRecord::ResultVerified { work_id },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(())
    }

    /// Permanently rejects this signed result, retaining only evidence digests.
    pub async fn rejected(
        &mut self,
        work_id: Digest,
        evidence_digest: Digest,
    ) -> Result<(), DeliverError> {
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(DeliverError::NoSuchJob)?;
        let (result, _) = job.result().ok_or(DeliverError::NoSuchJob)?;
        let result_digest = result_digest(self.state().channel(), result);
        self.store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id,
                    outcome: TerminalOutcome::Rejected {
                        result_digest,
                        evidence_digest,
                    },
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
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
    /// [`crate::model::work::CreditLedger::credit_payment`] over the
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
    pub async fn pay(&mut self, work_id: Digest) -> Result<AdmitCertificateRequest, PaymentError> {
        if let Some(retained) = self.state().payment(work_id) {
            return Ok(admit_request(self.state().channel().id(), &retained));
        }
        if let Some(observation) = &self.observation {
            observation.check()?;
        }
        let job = self
            .state()
            .job_by_id(work_id)
            .ok_or(PaymentError::NoSuchJob)?;
        let Some((result, result_signature)) = job.result() else {
            return Err(PaymentError::NotPayable { phase: job.phase() });
        };
        let (authorization, result, result_signature) =
            (*job.authorization(), *result, *result_signature);

        let (certificate, binding) = next_payment(
            self.state().channel(),
            &authorization,
            &result,
            self.state().ledger().credited_cumulative(),
            self.state().settlement(),
        )?;
        let binding_signature = self.signer.sign(signing_hash(payment_binding_digest(
            self.state().channel(),
            &binding,
        )));
        let certificate_signature = self
            .signer
            .sign(certificate.digest(self.state().channel().network()));

        self.store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id,
                    outcome: TerminalOutcome::Certified {
                        signed_result: Box::new((result, result_signature)),
                        certificate,
                        binding: Box::new(binding),
                        binding_signature,
                        certificate_signature,
                    },
                },
                &Secp256k1Verifier::new(),
            )
            .await?;
        Ok(AdmitCertificateRequest {
            route: Some(hellas_rpc::pb::work::WorkRoute::payment(
                self.state().channel().id(),
            )),
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
    endpoint: &mut impl ClientChannel,
    work_id: Digest,
) -> Result<u64, PaymentError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.client().await?.pay(work_id).await?;
    let response = client.admit_certificate(request).await?;
    endpoint.client().await?.acknowledged(work_id, &response)
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
    endpoint: &mut impl ClientChannel,
    proposal: &JobProposal,
    content: &crate::content::InvocationContent,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.client().await?.propose(proposal).await?;
    upload::send_proposal(transport, endpoint, request, content).await
}

/// Resend a retained proposal over a live transport and journal its answer.
///
/// # Errors
/// Returns transport errors and errors from [`ClientEndpoint::resume_proposal`]
/// or [`ClientEndpoint::accepted`].
pub async fn resume_work_proposal<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    work_id: Digest,
    content: &crate::content::InvocationContent,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = endpoint.client().await?.resume_proposal(work_id).await?;
    upload::send_proposal(transport, endpoint, request, content).await
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
                grant: None,
                code: refusal.code.code() as i32,
                reason: refusal.reason,
            }),
        }),
    }
}

fn wire_request(
    authorization: &PaidJobAuthorizationV2,
    client_signature: Sig,
    prepared_input: Vec<u8>,
) -> AcceptWorkRequest {
    AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: client_signature.as_bytes().to_vec(),
        prepared_input: encode_reference(ContentRef::new(
            ContentId::hash(&prepared_input),
            prepared_input.len() as u64,
        )),
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
