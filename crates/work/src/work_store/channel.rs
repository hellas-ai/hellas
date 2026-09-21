//! Durable state for one paid channel.
//!
//! Records are fsynced before signed artifacts leave the endpoint. Replay
//! checks every transition at its recorded cursor height, preserving per-job
//! credit limits and terminal outcomes across restart.

use std::collections::BTreeMap;
use std::path::Path;

use hellas_kernel::{
    Decode, EarnedCertificate, Encode, Key, NetworkId, Party, PayloadHash, PaymentCloseStart, Sig,
    SigVerifier, StartId, WorkPaymentSettlement,
};
use hellas_xet::XetFileHasher;

use crate::work_store::journal::{
    Journal, JournalError, JournalId, JournalKind, MAX_CHECKPOINT_BYTES, MAX_RECORD_BYTES, Role,
};
use crate::work_store::setup::SetupOrigin;
use crate::work_store::{
    Applied, WorkStoreError, cursor::Cursor, hex, put_bytes, put_option, put_u64, take_bytes,
    take_option,
};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::artifacts::PreparedPaidInputV1;
use hellas_rpc::protocol::work::{
    CreditLedger, PaidChannel, PaidJobAuthorizationV1, PaidJobResultV1, PaidWorkError,
    PaymentBindingV1, PrivateRecord as _, decode_transcript, payment_binding_digest,
    prepared_input_digest, result_digest, signing_hash, terminal_result, work_id,
};

mod codec;
mod state;
mod store;

pub(crate) use codec::encode_kernel;
pub use store::ChannelStore;

/// Domain of a channel journal's key.
const CHANNEL_KEY: &[u8] = b"hellas.work.channel-journal-key.v1";

/// Why a channel record is not one this state may hold.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelStateError {
    /// A private-record rule refused the record's own contents.
    #[error(transparent)]
    Record(#[from] PaidWorkError),
    /// A carried signature is not the named party's over this record's
    /// digest.
    #[error("the {slot} signature is not {party}'s over this record")]
    BadSignature {
        /// Which signature failed.
        slot: &'static str,
        /// Party whose key it was checked against.
        party: &'static str,
    },
    /// A step was recorded from a state that cannot take it.
    #[error("{step} cannot be recorded while the job is {phase}")]
    WrongPhase {
        /// Step that was attempted.
        step: &'static str,
        /// Phase the job is in, or `none`.
        phase: &'static str,
    },
    /// A step belongs to the other role.
    #[error("{step} is a {expected} step, and this journal is not one")]
    WrongRole {
        /// Step that was attempted.
        step: &'static str,
        /// Role that may take it.
        expected: &'static str,
    },
    /// A record named another channel, another job, or another entry
    /// than the one this state holds.
    #[error("the record's {field} is not this channel's")]
    WrongChannel {
        /// Which field disagreed.
        field: &'static str,
    },
    /// The named job has reached its permanent terminal and cannot take
    /// this step. Other jobs on the channel have independent lifecycles.
    #[error("{step} is refused: this channel's one job is {outcome}")]
    Terminated {
        /// Step that was attempted.
        step: &'static str,
        /// The terminal the job already reached.
        outcome: &'static str,
    },
    /// A credit limit would have been exceeded.
    #[error("{ledger} credit: {used} lost plus {reserved} reserved plus {price} exceeds {limit}")]
    OverCredit {
        /// Which limit.
        ledger: &'static str,
        /// Unrecovered loss against this counterparty.
        used: u64,
        /// Reserved against the job in flight.
        reserved: u64,
        /// Price this job would add.
        price: u64,
        /// Limit the channel policy fixes.
        limit: u64,
    },
    /// A result arrived for an invocation this process did not make and
    /// cannot know the outcome of.
    #[error("the job's invocation is indeterminate after a restart; a result now would be a guess")]
    Indeterminate,
    /// A provider co-signature was applied after its authorization's
    /// acceptance deadline.
    #[error(
        "a job accepted at finalized height {height} is past the acceptance deadline {deadline}"
    )]
    AcceptanceLate {
        /// Finalized cursor consumed by the durable apply.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// Backend dispatch was durably applied after the terminal deadline.
    #[error(
        "a job dispatched at finalized height {height} is past the terminal deadline {deadline}"
    )]
    DispatchLate {
        /// Finalized cursor consumed by the durable apply.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// A result reached the client after the height it was owed by.
    ///
    /// Late plaintext earns nothing: the provider signed a terminal
    /// deadline, and a client that recorded a receipt past it would be
    /// building the evidence for a payment the same deadline refuses.
    #[error(
        "a result received at finalized height {height} is past the terminal deadline {deadline}"
    )]
    ReceiptLate {
        /// Finalized height the client had processed through.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// A client signed a payment after the height it owed it by.
    ///
    /// Past that height the provider may end this job as expired and
    /// charge its price to this client's loss ledger. A certificate
    /// signed afterwards is executable money whatever the journal
    /// later says, while nothing takes the loss back — so the client
    /// would have paid for one job twice.
    #[error(
        "a payment signed at finalized height {height} is past the payment deadline {deadline}"
    )]
    PaymentLate {
        /// Finalized height the client had processed through.
        height: u64,
        /// Deadline the authorization carries.
        deadline: u64,
    },
    /// The finalized cursor did not move on by exactly one block.
    ///
    /// A skipped height is a block this endpoint never read, and every
    /// close and every certificate it would have carried is a fact this
    /// journal would then be missing.
    #[error("cursor height {actual} is not the block after {held}")]
    CursorNotNext {
        /// Height already recorded.
        held: u64,
        /// Height the record carried.
        actual: u64,
    },
    /// The next block does not name the block the cursor holds as its
    /// parent.
    #[error("the block at height {height} is not a child of the cursor's block")]
    CursorNotContiguous {
        /// Height the record carried.
        height: u64,
    },
    /// A step needs a channel whose payment close has not begun.
    #[error("{step} is refused: this channel's payment close has begun")]
    Closing {
        /// Step that was attempted.
        step: &'static str,
    },
    /// The same step was recorded twice with different contents.
    #[error("{what} was already recorded with different contents")]
    Conflict {
        /// What repeated.
        what: &'static str,
    },
    /// A record's bytes were not canonical.
    #[error("channel record is not canonical")]
    Malformed,
}

/// How far one job has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    /// The client's signature exists; the provider's does not.
    HalfSigned,
    /// Both signatures exist. Nothing has been invoked.
    Accepted,
    /// The backend may have been invoked. Provider-only.
    Running,
    /// Live output may leave; delivery credit is reserved before terminal.
    Streaming,
    /// A signed terminal result exists.
    Ready,
    /// The client's own re-execution reproduced the answer and it
    /// matched. Client-only.
    Matched,
    /// The plaintext has left the provider. Provider-only.
    Delivered,
}

impl core::fmt::Display for JobPhase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl JobPhase {
    const fn name(self) -> &'static str {
        match self {
            Self::HalfSigned => "half-signed",
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Streaming => "streaming",
            Self::Ready => "ready",
            Self::Matched => "matched",
            Self::Delivered => "delivered",
        }
    }

    /// Whether reaching this phase means plaintext left the provider.
    const fn delivered(self) -> bool {
        matches!(self, Self::Delivered | Self::Streaming)
    }

    const fn code(self) -> u8 {
        match self {
            Self::HalfSigned => 0,
            Self::Accepted => 1,
            Self::Running => 2,
            Self::Ready => 3,
            Self::Matched => 4,
            Self::Delivered => 5,
            Self::Streaming => 6,
        }
    }

    const fn from_code(code: u8) -> Result<Self, ChannelStateError> {
        match code {
            0 => Ok(Self::HalfSigned),
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Running),
            3 => Ok(Self::Ready),
            4 => Ok(Self::Matched),
            5 => Ok(Self::Delivered),
            6 => Ok(Self::Streaming),
            _ => Err(ChannelStateError::Malformed),
        }
    }

    /// Which role a job in this phase belongs to, when only one may hold
    /// it.
    const fn only_role(self) -> Option<Role> {
        match self {
            Self::Running | Self::Streaming | Self::Delivered => Some(Role::Provider),
            Self::Matched => Some(Role::Client),
            _ => None,
        }
    }

    /// Whether a signed result exists once a job has reached this phase.
    const fn has_result(self) -> bool {
        matches!(self, Self::Ready | Self::Matched | Self::Delivered)
    }
}

/// How one job ended, permanently.
///
/// Only [`Self::Certified`] records payment. The other outcomes end the
/// job without payment; they do not end the channel's other jobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// The client's certificate paid for the job. These are the exact
    /// bytes a recovered endpoint re-sends: the job is closed, so this is
    /// the only remaining copy of what was agreed.
    Certified {
        /// The scalar consensus will settle.
        certificate: EarnedCertificate,
        /// The private evidence of what it bought.
        ///
        /// Boxed because it is the widest field any of these five
        /// variants carries, and a terminal is one value with five
        /// shapes: the four unpaid endings would otherwise each be as
        /// large as the paid one.
        binding: Box<PaymentBindingV1>,
        /// The client's signature over the binding's digest.
        binding_signature: Sig,
        /// The client's signature over the kernel's earned digest.
        certificate_signature: Sig,
    },
    /// The client's own re-execution did not reproduce the signed result.
    /// The job is over and unpayable; these two digests are what
    /// disagreed.
    Refuted {
        /// The digest the provider signed.
        result_digest: Digest,
        /// The digest the client's re-execution produced.
        reproduction_digest: Digest,
    },
    /// The job can no longer be paid for, at this finalized height:
    /// either a deadline passed with it unfinished or unpaid, or a close
    /// on the payment edge cut it off before one did — a contest or a
    /// settlement admits no payment after it, however much room the
    /// deadline still had.
    Expired {
        /// Deadline the authorization carried — the one that passed, or
        /// the payment deadline the cut-off job could no longer meet.
        deadline: u64,
        /// Finalized height the cursor held when the job expired.
        height: u64,
        /// That block's payload digest.
        payload: [u8; 32],
    },
    /// Execution or validation failed, with the backend's code.
    Failed {
        /// A code naming the failure.
        code: u32,
    },
    /// The process crashed between invocation and terminal persistence,
    /// and no local state can say what the invocation did. Recording this
    /// is an operator's decision, never an automatic one.
    Indeterminate,
}

impl TerminalOutcome {
    /// A one-word name for this terminal, for a refusal message.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Certified { .. } => "certified",
            Self::Refuted { .. } => "refuted",
            Self::Expired { .. } => "expired",
            Self::Failed { .. } => "failed",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// The retained terminal for one work ID.
///
/// Replays and retries consult this record to avoid completing or paying
/// the same job twice. A channel retains a terminal for each finished job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTerminal {
    /// The job that ended.
    pub work_id: Digest,
    /// The phase it had reached when it ended.
    pub phase: JobPhase,
    /// How it ended.
    pub outcome: TerminalOutcome,
}

mod outcome_code {
    pub(super) const CERTIFIED: u8 = 0;
    pub(super) const REFUTED: u8 = 1;
    pub(super) const EXPIRED: u8 = 2;
    pub(super) const FAILED: u8 = 3;
    pub(super) const INDETERMINATE: u8 = 4;
}

/// One durable step of a channel's life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelRecord {
    /// Finalized blocks have been processed through this block.
    ///
    /// The parent rides with the payload because a cursor is only worth
    /// something if it is contiguous: a height alone would let a
    /// watcher skip from block 7 to block 20 and still report that it
    /// had processed everything through 20. What it would have skipped
    /// is every close and every deadline those thirteen blocks crossed.
    CursorAdvanced {
        /// Height processed through.
        height: u64,
        /// The payload digest that block names as its parent.
        parent: [u8; 32],
        /// That block's own payload digest.
        payload: [u8; 32],
    },
    /// The client's signed authorization, and the inputs it commits to.
    ///
    /// The prepared bundle rides here because the quote it came from is
    /// transient: a provider that accepted a job and then restarted must
    /// still be able to execute exactly the job it accepted, and an
    /// authorization carries only the digest of those inputs.
    JobProposed {
        /// The body both parties sign.
        authorization: PaidJobAuthorizationV1,
        /// The client's signature over its `work_id`.
        client_signature: Sig,
        /// The canonical prepared-input bundle the authorization's
        /// `prepared_input_digest` commits to.
        prepared_input: Vec<u8>,
    },
    /// The provider's co-signature over the same `work_id`.
    JobAccepted {
        /// Job whose authorization is being co-signed.
        work_id: Digest,
        /// The provider's signature.
        provider_signature: Sig,
    },
    /// The provider is about to invoke the backend.
    JobRunning {
        /// Job whose invocation is beginning.
        work_id: Digest,
    },
    /// The provider's signed terminal result, and the signed events it
    /// summarises.
    ///
    /// The transcript rides here because the result is a pair of digests
    /// over it: a provider that kept only the digests could not deliver
    /// the answer it was paid for after a restart, and a client that
    /// kept only the digests could not run its own re-execution without
    /// asking the provider for the bytes again.
    JobResult {
        /// Job the result belongs to.
        work_id: Digest,
        /// The result body.
        result: PaidJobResultV1,
        /// The provider's signature over its digest.
        provider_signature: Sig,
        /// The transcript the result was derived from.
        transcript: Vec<u8>,
    },
    /// The provider is about to release the plaintext.
    PlaintextReleased {
        /// Job whose plaintext is being released.
        work_id: Digest,
    },
    /// The client's own re-execution reproduced this job's answer and it
    /// matched.
    ///
    /// Client-only evidence from optional local reproduction. Payment also
    /// permits an authenticated result without this record.
    ResultMatched {
        /// Job whose result the client reproduced.
        work_id: Digest,
    },
    /// The named job reaches its permanent terminal.
    ///
    /// A certified outcome stores the payment and completion together in
    /// one journal record. The prior phase is read from the named job.
    JobTerminated {
        /// Job reaching this terminal.
        work_id: Digest,
        /// How the job ended.
        outcome: TerminalOutcome,
    },
    /// This endpoint has signed a close start, and these are its exact
    /// bytes.
    ///
    /// Written before the signature leaves the process, like every
    /// other signature here — and it is the cutoff for as long as those
    /// bytes could still reach a block. While they could, the channel
    /// admits no new job and credits no new certificate, because a
    /// close that left out a certificate it was still admitting would
    /// be a close below what was earned. Once the window has passed
    /// with no contest on this disk, the signature can reach nothing
    /// and holds nothing shut; see [`ChannelState::is_closing`].
    ClosePrepared {
        /// The signed start, exactly as it will be submitted.
        ///
        /// Boxed because a start reveals the channel's complete terms
        /// and is the widest thing this enum carries by a long way; the
        /// other ten records would otherwise each be as large as it.
        start: Box<PaymentCloseStart>,
    },
    /// A close contest on this channel's payment edge was finalized.
    ///
    /// Two things the block says and nothing else can. The contest
    /// identifier cannot be derived from a retained signature: the
    /// kernel takes it from the start digest *and the height that
    /// accepted it*. And the opener cannot be recovered from the
    /// identifier, which is a hash — so an endpoint that dropped it
    /// could never afterwards say whether the contest that shut its
    /// channel was its own or the counterparty's, which is the whole of
    /// who owes for the job it cut off.
    CloseOpened {
        /// Contest a later response or close must name.
        start_id: StartId,
        /// Which party opened it.
        opener: Party,
        /// Height at which the response window shuts. The block that
        /// accepted the start fixed it, and recovery reads it here rather
        /// than from a second finalized snapshot: a provider that
        /// restarts with this record must know whether the window it may
        /// answer in is still open.
        response_deadline: u64,
        /// The cumulative amount the opener's own start claimed. A
        /// provider answers only a contest opened below what it already
        /// holds, so this is the floor its own certificate must strictly
        /// exceed for an answer to exist.
        claimed: u64,
    },
    /// This endpoint has fixed its answer to the contest on its payment
    /// edge, and this is the digest that answer's signature covers.
    ///
    /// Written before the response leaves the process, like every other
    /// signature here. What it says is that the answer is *chosen*, and
    /// that is all it says: it is fsynced before the submission it
    /// authorises, so a process that dies between the two leaves a
    /// journal holding an answer consensus has never seen. Read as
    /// "handed off" it would be a lie exactly then, which is why nothing
    /// in the duty rule consults it — see
    /// [`ChannelState::answerable_contest`], which decides what is owed
    /// from the contest and the certificate alone.
    ///
    /// The digest rather than the bytes, because the bytes are derived
    /// rather than kept: an answer is fixed by the contest it names and
    /// the certificate this journal already holds, and neither can change
    /// once a contest is open — the channel admits no work and credits no
    /// certificate from [`Self::CloseOpened`] onwards. So a resubmission
    /// re-derives the same answer, and this is what refuses a different
    /// one.
    CloseResponded {
        /// Contest this answer names.
        start_id: StartId,
        /// Digest the responder signed, over the answer's own body.
        response_digest: PayloadHash,
    },
    /// A close consuming this channel's payment edge was finalized.
    CloseSettled {
        /// Height of the block that carried it.
        height: u64,
        /// That block's payload digest.
        payload: [u8; 32],
        /// What the close paid the provider.
        provider_payout: u64,
    },
}

mod tag {
    pub(super) const CURSOR: u8 = 0;
    pub(super) const PROPOSED: u8 = 1;
    pub(super) const ACCEPTED: u8 = 2;
    pub(super) const RUNNING: u8 = 3;
    pub(super) const RESULT: u8 = 4;
    pub(super) const PLAINTEXT: u8 = 5;
    pub(super) const MATCHED: u8 = 6;
    pub(super) const TERMINATED: u8 = 7;
    pub(super) const CLOSE_PREPARED: u8 = 8;
    pub(super) const CLOSE_OPENED: u8 = 9;
    pub(super) const CLOSE_SETTLED: u8 = 10;
    pub(super) const CLOSE_RESPONDED: u8 = 11;
}

/// What one job can still add to a checkpoint after it is proposed.
///
/// The result the provider will sign, the signature over it, and the
/// certified terminal that pays for it — all fixed-width. The transcript
/// is deliberately not in here: it is the one variable-width thing a
/// proposal cannot know, and it is charged where it is known, at
/// [`ChannelRecord::JobResult`], which is still ahead of the provider's
/// own signature leaving the process.
const JOB_TAIL_BYTES: usize = PaidJobResultV1::ENCODED_SIZE
    + PaymentBindingV1::ENCODED_SIZE
    + EarnedCertificate::ENCODED_SIZE
    + 4 * Sig::LENGTH
    + 64;

/// One active job on a channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobState {
    authorization: PaidJobAuthorizationV1,
    work_id: Digest,
    prepared_input: Vec<u8>,
    client_signature: Sig,
    provider_signature: Option<Sig>,
    phase: JobPhase,
    result: Option<(PaidJobResultV1, Sig)>,
    transcript: Vec<u8>,
}

impl JobState {
    /// Returns the authorization both parties sign.
    #[must_use]
    pub const fn authorization(&self) -> &PaidJobAuthorizationV1 {
        &self.authorization
    }

    /// Returns the job's `work_id`.
    #[must_use]
    pub const fn work_id(&self) -> Digest {
        self.work_id
    }

    /// Returns the prepared-input bundle this job executes from.
    ///
    /// Retained because the quote that carried it is transient. What
    /// makes it the right bundle is not that it was stored, but that it
    /// hashes to the digest inside the authorization both parties
    /// signed — which is checked before it is stored, and again on
    /// replay.
    #[must_use]
    pub fn prepared_input(&self) -> &[u8] {
        &self.prepared_input
    }

    /// Returns how far the job has got.
    #[must_use]
    pub const fn phase(&self) -> JobPhase {
        self.phase
    }

    /// Returns the client's signature over the `work_id`.
    #[must_use]
    pub const fn client_signature(&self) -> Sig {
        self.client_signature
    }

    /// Returns the provider's co-signature, once it exists.
    #[must_use]
    pub const fn provider_signature(&self) -> Option<Sig> {
        self.provider_signature
    }

    /// Returns the signed result, once it exists.
    #[must_use]
    pub const fn result(&self) -> Option<&(PaidJobResultV1, Sig)> {
        self.result.as_ref()
    }

    /// Returns the encoded transcript the result was derived from, or
    /// an empty slice before there is one.
    ///
    /// What makes these the right bytes is not that they were stored.
    /// The rule that pairs them with the result is applied when the
    /// record is committed and again when the journal is replayed —
    /// one function, run by both — so a journal that holds a transcript
    /// and a result that do not belong together is one that does not
    /// open.
    #[must_use]
    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

/// One credited payment, exactly as its terminal recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaidCertificate {
    /// The job it paid for.
    ///
    /// Read off the [`JobTerminal`] this channel came to rest at. It is
    /// what lets a recovered endpoint answer "what did I pay for that
    /// work id" after the job itself has been closed by the payment.
    pub work_id: Digest,
    /// The scalar consensus will settle.
    pub certificate: EarnedCertificate,
    /// The private evidence of what it bought.
    pub binding: PaymentBindingV1,
    /// The client's signature over the binding's digest.
    pub binding_signature: Sig,
    /// The client's signature over the kernel's earned digest.
    pub certificate_signature: Sig,
}

/// What one endpoint durably knows about one channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    channel: PaidChannel,
    settlement: WorkPaymentSettlement,
    role: Role,
    ledger: CreditLedger,
    jobs: BTreeMap<Digest, JobState>,
    terminals: BTreeMap<Digest, JobTerminal>,
    proposal_nonce_high_water: u64,
    cursor: (u64, [u8; 32]),
    indeterminate: BTreeMap<Digest, ()>,
    close_prepared: Option<PaymentCloseStart>,
    close_opened: Option<OpenContest>,
    close_responded: Option<RespondedContest>,
    close_settled: Option<CloseSettlement>,
}

/// A finalized close contest on this channel's payment edge, and
/// everything a recovering provider needs to answer it without a second
/// finalized snapshot.
///
/// The [`Self::start_id`] and [`Self::opener`] are what the watcher can
/// read nowhere but from the block that accepted the start. The
/// [`Self::response_deadline`] and [`Self::claimed`] ride with them
/// because an answer exists only while the window is open and only for a
/// contest opened below what this endpoint already holds, and a restart
/// that kept only the identifier could decide neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenContest {
    /// Contest a later response or close must name.
    pub start_id: StartId,
    /// Which party opened it.
    pub opener: Party,
    /// Height at which the response window shuts.
    pub response_deadline: u64,
    /// Cumulative amount the opener's own start claimed.
    pub claimed: u64,
}

/// The one answer this endpoint has chosen for the contest on its
/// payment edge.
///
/// Where [`OpenContest`] is what a block said, this is what this
/// endpoint decided about it: while a contest is open and this is
/// absent, no answer is fixed yet; once it is present, the answer is
/// fixed and no other may be given. What it does not say is that the
/// answer was sent, let alone received — it reaches the disk before the
/// submission it authorises, so a duty may be owed with this record
/// already written. The digest is the answer's own signed body, so a
/// resubmission that re-derives the answer can be checked against what
/// was already chosen rather than trusted to be the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RespondedContest {
    /// Contest the answer names.
    pub start_id: StartId,
    /// Digest the responder signed, over the answer's own body.
    pub response_digest: PayloadHash,
}

/// What a finalized close of this channel's payment edge paid, and
/// where it was.
///
/// Retained because a payout is a coin, and a coin can be spent. The
/// block that carried the close is the durable answer to "was this
/// channel settled"; a later lookup that finds no coin is not evidence
/// that it was not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloseSettlement {
    /// Height of the block that carried the close.
    pub height: u64,
    /// That block's payload digest.
    pub payload: [u8; 32],
    /// What the close paid the provider.
    pub provider_payout: u64,
}
