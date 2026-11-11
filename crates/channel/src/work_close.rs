//! Spending the certificate: the certified cursor, and the two
//! transactions that turn a signed scalar into coins.
//!
//! # Why the cursor is the load-bearing part
//!
//! Five rules elsewhere in this crate are decided against a height —
//! whether a receipt is timely, whether a payment is timely, whether a
//! job's deadlines are still reachable, whether plaintext released now
//! can still arrive, and whether a readiness decision may be acted on —
//! and the close response window against the block time beside it.
//! Every one of them reads
//! [`Channel::cursor`](crate::work_store::Channel::cursor), and a cursor
//! that never moves makes every one of those rules pass: a receipt three
//! hundred blocks late reads as timely against a height that stopped.
//! [`observe`] is the only thing that moves it.
//!
//! # A certified state, not a replay
//!
//! [`observe`] takes one proof-checked read of this channel's objects at
//! one certified block — the payment edge and its pending-close slot —
//! and moves the cursor forward to that block, however far it is. What
//! happened in between is not replayed because it does not need to be:
//! consensus holds the one live contest on an edge in that slot until
//! the edge is closed, so the read either shows the contest, shows the
//! edge gone, or shows neither. A watcher that reads often enough —
//! inside the response window, which is what the channel crate's poll
//! interval and certified-age bound are derived to guarantee — sees
//! every contest while it can still be answered.
//!
//! # Non-destructive broadcast
//!
//! Nothing here consumes evidence to produce a transaction.
//!
//! - [`close_start`] builds and signs; both endpoints commit the exact
//!   bytes before they are handed to a chain. A crash between signing
//!   and that commit loses a signature nobody has, and the retry signs
//!   again at whatever height the cursor has reached. A crash after it
//!   leaves bytes [`advance_close`] re-sends verbatim, and the kernel
//!   admits at most one contest per edge — so a resubmission is not a
//!   second close, it is the same one.
//! - The certificate the start carries stays in the journal it was
//!   admitted into. The start holds a copy; it never becomes the only
//!   copy.
//! - [`adjudicated_close`] is derived, not retained: its payouts come
//!   from the contest record consensus itself holds, read in the same
//!   certified state that shows the duty, so it is rebuilt after any
//!   crash and it is the same transaction.
//!
//! # What this module does not do
//!
//! It signs no cooperative freeze. That exit needs both parties'
//! signatures over one amount and no exchange in this crate negotiates
//! them; a freeze built here would be a transaction with one signature
//! and a place to put the other.

use hellas_kernel::{
    EarnedCertificate, List, MAX_EDGE_OUTPUTS, Party, PartyAuth, PayloadHash, PaymentCloseResponse,
    PaymentCloseStart, Payout, PendingPaymentClose, PendingSlot, Proof, Secp256k1Signer, Sig,
    SigVerifier, StartId, Terms, Tx, WorkPaymentSettlement, adjudicated_payouts,
};
use hex::encode as hex;

use crate::model::setup::ObservedChannel;
use crate::model::work::PaidChannel;
use crate::work::EndpointError;
use crate::work_store::{
    ChannelRecord, ChannelStateError, ChannelStore, JobPhase, Role, TerminalOutcome, WorkStoreError,
};
use hellas_rpc::observe::{LEVEL, TARGET, Timing};

/// Why the chain could not be read or would not take a transaction.
#[derive(Clone, Debug, thiserror::Error)]
pub enum BlockSourceError {
    #[error("the chain source failed: {0}")]
    Failed(String),
}

impl BlockSourceError {
    /// Reports a source failure.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self::Failed(reason.into())
    }
}

/// Where a close transaction is handed to consensus.
///
/// One method, and it is deliberately not a query: submitting says
/// nothing about inclusion, and an endpoint learns whether its start
/// landed from the state it reads, never from the answer to this. Both
/// endpoints need exactly this and neither needs a mempool.
pub trait TxSink {
    /// Hands one transaction to consensus.
    ///
    /// Submitting the same bytes twice is not an error here and must
    /// not be treated as one: the kernel admits at most one contest per
    /// edge, so a resubmission is the same close, not a second.
    fn submit(
        &self,
        tx: Tx,
    ) -> impl core::future::Future<Output = Result<hellas_rpc::SubmitTxOutcome, BlockSourceError>> + Send;
}

/// Why a close could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CloseError {
    /// The key cannot sign for the committed party.
    #[error("the signing key has no authority for the close party")]
    UnauthorizedSigner,
    /// The terms fix a zero-block start window, so no signature could
    /// ever be included.
    #[error("the payment terms admit no start validity window")]
    NoValidityWindow,
    /// The window arithmetic left the representable range.
    #[error("the start validity window overflows past height {height}")]
    WindowOverflow {
        /// Height the window was anchored at.
        height: u64,
    },
    /// A contest is live on this edge and it is not the one this
    /// endpoint opened.
    #[error("the live contest is not the one this endpoint started")]
    OtherContest,
    /// No finalized contest is open for this endpoint's start.
    #[error("no finalized contest is open on this payment edge")]
    NoContest,
    /// The provider's response window has not run out, so consensus
    /// would refuse this close.
    #[error(
        "the response window is open until block time {deadline_ms}, and the read is at {at_ms}"
    )]
    ResponseWindowOpen {
        /// Block time of the read, in milliseconds.
        at_ms: u64,
        /// Block time at which the window shuts.
        deadline_ms: u64,
    },
    /// The contest has already been answered, and there is one answer.
    #[error("this contest has already been answered")]
    AlreadyResponded,
    /// The response window has shut, so consensus would refuse an
    /// answer.
    #[error("the response window shut at block time {deadline_ms}, and the read is at {at_ms}")]
    ResponseWindowClosed {
        /// Block time of the read, in milliseconds.
        at_ms: u64,
        /// Block time at which the window shut.
        deadline_ms: u64,
    },
    /// This endpoint holds nothing the contest does not already settle.
    ///
    /// Not a fault. An answer has to strictly advance the amount, so a
    /// contest already at this endpoint's own high-water is one there
    /// is nothing to say about — and saying it would spend the one
    /// answer the window admits.
    #[error("the contest already settles {settled}, and this endpoint holds {held}")]
    NothingToAdd {
        /// Largest certificate this endpoint holds.
        held: u64,
        /// Amount the contest currently settles at.
        settled: u64,
    },
    /// The payouts this contest settles do not fit what the edge
    /// distributes.
    #[error("the contest settles more than this edge's adjudicated route distributes")]
    Unpayable,
    /// The step could not be made durable, or the journal refused it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The endpoint this close would be decided on is unreachable, so
    /// nothing was decided and nothing was written.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
}

/// How far this channel's close has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseProgress {
    /// The edge is gone. What it paid is the two payout coins.
    Settled,
    /// A contest is finalized on this edge.
    Opened {
        /// The contest a response or a close must name.
        start_id: StartId,
    },
    /// The final adjudicated transaction was offered, but is not yet finalized.
    AdjudicationSubmitted {
        /// Contest whose verified state determined this close.
        start_id: StartId,
        /// What the node did with the final transaction.
        outcome: hellas_rpc::SubmitTxOutcome,
    },
    /// A retained start was handed to consensus at this height. It is
    /// not included until a block says so.
    Submitted {
        /// Last height the submitted signature can be included at.
        valid_through: u64,
        /// What the node did with the transaction.
        outcome: hellas_rpc::SubmitTxOutcome,
    },
    /// Nothing is retained that could still be included, and no contest
    /// opened. The channel is open again, and closing it needs a fresh
    /// signature.
    Nothing,
}

/// Why one certified read could not be applied, or its duty not served.
#[derive(Debug, thiserror::Error)]
pub enum CatchUpError {
    /// This channel already has a cursor driver; ordinary brief journal
    /// operations remain independent of that ownership.
    #[error("this channel already has a cursor driver")]
    Busy,
    /// The job a driver named is not the one this channel's journal
    /// holds, so this channel's cursor is not that driver's to advance.
    #[error("this channel's job is not the one the driver named")]
    OtherJob,
    /// The read or the transaction sink failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A read was refused by the journal.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// The certified contest cannot be distributed by the funded edge.
    #[error(transparent)]
    Close(#[from] CloseError),
}

/// Returns the digest a close opener signs for `start`.
///
/// One spelling on this side of the wire. The kernel builds the same
/// digest from the *edge* it reads, so a start whose terms are not the
/// edge's is refused there before any signature is checked; here the
/// terms are the channel's own, and every start this is called on is
/// one on this channel's payment edge.
#[must_use]
pub fn start_body_digest(channel: &PaidChannel, start: &PaymentCloseStart) -> PayloadHash {
    start.digest(channel.network())
}

/// Builds and signs one close start at finalized height `height`.
///
/// The window is `[height + 1, height + start_validity_blocks]`, and
/// the two ends are the kernel's own inclusive interpretation: the next
/// block is the first one that can carry a signature made now, and the
/// span of a one-block window is one. Both additions are checked, so a
/// height within one window of the ceiling refuses to sign rather than
/// wrapping into a window that has already shut.
///
/// A zero-amount certificate has no representation here and needs none:
/// a journal only ever retains a certificate that exceeded what it
/// already held, and nothing exceeds zero. An opener with nothing to
/// claim passes `None`, which is the kernel's one spelling for it.
///
/// # Errors
///
/// [`CloseError::NoValidityWindow`] when the terms fix a zero-block
/// window, [`CloseError::WindowOverflow`] when either addition leaves the
/// representable range, and [`CloseError::UnauthorizedSigner`] for a key that
/// cannot act for the opener.
pub fn close_start(
    channel: &PaidChannel,
    opener_role: Party,
    height: u64,
    certificate: Option<(EarnedCertificate, Sig)>,
    signer: &Secp256k1Signer,
) -> Result<PaymentCloseStart, CloseError> {
    let parties = channel.payment_terms().parties();
    let party = match opener_role {
        Party::Maker => parties.maker(),
        Party::Taker => parties.taker(),
    };
    let authority = party
        .authority_of(signer.party_key())
        .ok_or(CloseError::UnauthorizedSigner)?;
    let certificate_authority = parties
        .maker()
        .authority_of(channel.client_key())
        .ok_or(CloseError::UnauthorizedSigner)?;
    let span = channel.payment_terms().start_validity_blocks;
    if span == 0 {
        return Err(CloseError::NoValidityWindow);
    }
    let valid_from = height
        .checked_add(1)
        .ok_or(CloseError::WindowOverflow { height })?;
    let valid_through = valid_from
        .checked_add(span - 1)
        .ok_or(CloseError::WindowOverflow { height })?;

    // Built once with a placeholder signature, so the digest is taken
    // from exactly the body that will carry it. The action signature is
    // not part of what it covers, which is what makes this safe rather
    // than circular.
    let unsigned = PaymentCloseStart::new(
        channel.payment_edge(),
        Terms::work_payment(channel.payment_terms().clone()),
        opener_role,
        (valid_from, valid_through),
        certificate.map(|(certificate, sig)| {
            (
                certificate,
                PartyAuth::new(certificate_authority, sig.into()),
            )
        }),
        PartyAuth::new(authority, Sig::from_bytes([0_u8; Sig::LENGTH]).into()),
    );
    let action_sig = signer.sign(start_body_digest(channel, &unsigned));
    Ok(PaymentCloseStart::new(
        channel.payment_edge(),
        Terms::work_payment(channel.payment_terms().clone()),
        opener_role,
        (valid_from, valid_through),
        unsigned.certificate().cloned(),
        PartyAuth::new(authority, action_sig.into()),
    ))
}

/// Returns the digest a responder signs to answer `start_id` with
/// `certificate`.
///
/// One spelling, for [`start_body_digest`]'s reason and one more: the
/// answer's digest is what [`ChannelRecord::CloseResponded`] records, so
/// a second speller of it would let the journal say a different answer
/// was given than the one that was sent.
#[must_use]
pub fn response_body_digest(
    channel: &PaidChannel,
    start_id: StartId,
    certificate: &EarnedCertificate,
) -> PayloadHash {
    hellas_kernel::response_digest(
        channel.network(),
        channel.payment_edge(),
        channel.payment_terms_hash(),
        start_id,
        Party::Taker,
        certificate.digest(channel.network()),
    )
}

/// Builds the provider's one answer to a contest opened below what it
/// holds.
///
/// The certificate is the client's own, already on this endpoint's disk
/// — an answer reveals no new evidence, it spends evidence the client
/// signed and the opener left out. What is journaled before it is not
/// the evidence but the answer itself:
/// [`ChannelRecord::CloseResponded`] carries the digest below, written
/// before these bytes leave the process, and it is what *fixes* which
/// answer the duty the watcher's [`ChannelRecord::CloseOpened`] created
/// is answered by. It says nothing about the duty being done: it is
/// written before the send, so it stands over a consensus that may have
/// received nothing at all.
///
/// # Errors
///
/// [`CloseError::UnauthorizedSigner`] if the signing key cannot act for the provider.
pub fn close_response(
    channel: &PaidChannel,
    start_id: StartId,
    certificate: (EarnedCertificate, Sig),
    signer: &Secp256k1Signer,
) -> Result<PaymentCloseResponse, CloseError> {
    // `response_build_ms`: the digest and the signature over it, which
    // is the whole of what building an answer costs. The journal record
    // that fixes it is not in here — §4 counts that separately, as one
    // of `Wresp`'s three commits.
    let parties = channel.payment_terms().parties();
    let authority = parties
        .taker()
        .authority_of(signer.party_key())
        .ok_or(CloseError::UnauthorizedSigner)?;
    let certificate_authority = parties
        .maker()
        .authority_of(channel.client_key())
        .ok_or(CloseError::UnauthorizedSigner)?;
    let built = Timing::start();
    let digest = response_body_digest(channel, start_id, &certificate.0);
    let (certificate, certificate_sig) = certificate;
    let response = PaymentCloseResponse::new(
        channel.payment_edge(),
        start_id,
        Party::Taker,
        (
            certificate,
            PartyAuth::new(certificate_authority, certificate_sig.into()),
        ),
        PartyAuth::new(authority, signer.sign(digest).into()),
    );
    if let Some(ms) = built.ms() {
        tracing::event!(
            name: "response_build_ms",
            target: TARGET,
            LEVEL,
            edge = %hex(channel.payment_edge().to_bytes()),
            start_id = %hex(start_id.to_bytes()),
            ms,
        );
    }
    Ok(response)
}

/// Builds the close that pays out whatever the contest ended on.
///
/// The amounts are not this endpoint's opinion: `pending` is the record
/// consensus itself holds, and the two payouts come from the kernel's
/// own [`adjudicated_payouts`]. That is why this needs no retained
/// bytes — after any crash it is rebuilt from one finalized read, and
/// it is the same transaction.
///
/// There is no signature on it at all. The amounts were authorized when
/// the certificates behind them were signed, and the window has shut on
/// any further evidence.
///
/// `settlement` is what the *funded* edge distributes, taken from the
/// finalized read that established the channel is live. A close built
/// against an expectation rather than that read would name a total the
/// edge does not hold.
///
/// # Errors
///
/// [`CloseError::Unpayable`] when the settled total does not fit the
/// adjudicated route.
pub fn adjudicated_close(
    channel: &PaidChannel,
    settlement: WorkPaymentSettlement,
    pending: &PendingPaymentClose,
) -> Result<Tx, CloseError> {
    let payouts = adjudicated_payouts(
        settlement,
        channel.payment_terms().parties(),
        pending.final_cumulative(),
        pending.penalty_due(),
        pending.owner_signed(),
    )
    .map_err(|_| CloseError::Unpayable)?;
    let mut outputs = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, payout) in outputs.iter_mut().zip(payouts) {
        *slot = payout;
    }
    Ok(Tx::close(
        channel.payment_edge(),
        Proof::adjudicated(pending.contest_commitment(
            channel.network(),
            channel.payment_edge(),
            channel.payment_terms_hash(),
        )),
        List::take(outputs, payouts.len()),
    ))
}

/// Applies one certified read of this channel to its journal.
///
/// Refused before anything is written when the read is behind the
/// cursor: absence at an older root says nothing about the chain now.
/// Otherwise everything the read *means* is committed before the cursor
/// that says it was read, so a process that dies between them reads
/// again and re-commits the same records — which the journal answers as
/// the retries they are.
///
/// - Every open job whose deadline the read's height has passed rests at
///   its expired terminal ([`expiry_at`]).
/// - A pending-close slot the journal has not recorded is the contest:
///   the open job does not survive it, and [`ChannelRecord::CloseOpened`]
///   copies what consensus fixed — the identifier, the opener, the
///   deadline and the claim.
/// - A payment edge that is gone is the close.
///
/// # Errors
///
/// [`WorkStoreError`] when the read is behind the cursor, its slot is
/// not this edge's contest, or a record is refused.
pub async fn observe<V: SigVerifier>(
    store: &mut ChannelStore,
    observed: &ObservedChannel<'_>,
    verifier: &V,
) -> Result<(), WorkStoreError> {
    let (height, payload) = (observed.height, observed.payload);
    store
        .state()
        .anchoring(height, &payload)
        .map_err(WorkStoreError::from)?;
    let pending = match observed.pending {
        PendingSlot::Absent => None,
        PendingSlot::Present(record) => Some(record),
        PendingSlot::Faulty(_) => {
            return Err(WorkStoreError::from(ChannelStateError::Malformed));
        }
    };
    let window = hellas_kernel::RESPONSE_WINDOW_MS;
    let previous = store.state().certified_at_ms();
    if previous != 0 && observed.certified_at_ms.saturating_sub(previous) >= window {
        tracing::warn!(
            target: TARGET,
            edge = %hex(store.state().channel().payment_edge().to_bytes()),
            gap_ms = observed.certified_at_ms - previous,
            window_ms = window,
            "monitoring gap exceeded the response window",
        );
    }
    for (work_id, outcome) in expiry_at(store.state(), height, payload) {
        store
            .commit(ChannelRecord::JobTerminated { work_id, outcome }, verifier)
            .await?;
    }
    let contest = pending.filter(|_| {
        store.state().close_opened().is_none() && store.state().close_settled().is_none()
    });
    let settled = observed.payment.is_none() && store.state().close_settled().is_none();
    if contest.is_some() || settled {
        end_open_jobs(store, height, payload, verifier).await?;
    }
    if let Some(record) = contest {
        store
            .commit(
                ChannelRecord::CloseOpened {
                    start_id: record.start_id(),
                    opener: record.opener_role(),
                    response_deadline_ms: record.response_deadline_ms(),
                    claimed: record.start_cumulative(),
                },
                verifier,
            )
            .await?;
    }
    if settled {
        store
            .commit(ChannelRecord::CloseSettled { height, payload }, verifier)
            .await?;
    }
    store
        .commit(
            ChannelRecord::Anchored {
                height,
                payload,
                certified_at_ms: observed.certified_at_ms,
                pending,
            },
            verifier,
        )
        .await?;
    Ok(())
}

/// Ends every open job at an expired terminal, at the read that closed
/// the channel to it.
///
/// A contest, a close, or a client's own close start is the cutoff: no
/// payment is credited after it, so a job still in flight is one that can
/// no longer be paid for, and the provider bears whatever compute or
/// delivery it already spent.
pub(crate) async fn end_open_jobs<V: SigVerifier>(
    store: &mut ChannelStore,
    height: u64,
    payload: [u8; 32],
    verifier: &V,
) -> Result<(), WorkStoreError> {
    let open: Vec<_> = store
        .state()
        .jobs()
        .map(|job| (job.work_id(), job.authorization().payment_deadline))
        .collect();
    for (work_id, deadline) in open {
        store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id,
                    outcome: TerminalOutcome::Expired {
                        deadline,
                        height,
                        payload,
                    },
                },
                verifier,
            )
            .await?;
    }
    Ok(())
}

/// Returns the expired terminal the open job has reached at `height`, if
/// it has reached one.
///
/// Three deadlines, and each is a height past which the job can no longer
/// be paid for.
///
/// - **Acceptance.** A proposal the provider never co-signed cannot be
///   co-signed now, so the job is over. Nobody produced anything.
/// - **Terminal.** Past it there is no result either party can use: the
///   client's own journal refuses a receipt, so a result signed now
///   could never be paid for.
/// - **Payment.** A result exists, it was in time, and the height the
///   client signed to pay by has passed. A client that verified a result
///   and did not pay by then can no longer pay for it, so the job is over;
///   a job whose payment was already issued is terminal and is not
///   touched here.
///
/// Each is an [`TerminalOutcome::Expired`] naming the deadline it crossed
/// and the finalized block that crossed it. The party that spent compute
/// or delivery bears it.
///
/// Both roles apply the deadlines, because each is conclusive for the
/// journal that reached it. A provider's job past one can no longer be
/// paid for. A client's accepted job past its terminal deadline can no
/// longer receive a receipt, so it is over. A client's half-signed
/// proposal is over at the same terminal deadline; at its acceptance
/// deadline it is over only when its exact bytes did not survive replay,
/// because a proposal that can still be retried may still recover a
/// co-signature the provider released before that deadline. A client's
/// result-bearing job is over at its payment deadline: the result can no
/// longer be paid for, and an unpaid result is not a funding obligation.
pub(crate) fn expiry_at(
    state: &crate::work_store::Channel,
    height: u64,
    payload: [u8; 32],
) -> Vec<(hellas_auth::Digest, TerminalOutcome)> {
    state
        .jobs()
        .filter_map(|job| {
            let authorization = job.authorization();
            let deadline = match state.role() {
                Role::Provider => {
                    if height > authorization.payment_deadline {
                        authorization.payment_deadline
                    } else if height > authorization.terminal_deadline && job.result().is_none() {
                        authorization.terminal_deadline
                    } else if height > authorization.acceptance_deadline
                        && job.phase() == JobPhase::HalfSigned
                    {
                        authorization.acceptance_deadline
                    } else {
                        return None;
                    }
                }
                Role::Client => {
                    // A half-signed proposal whose exact bytes are gone can
                    // never be co-signed now: the client cannot even ask.
                    // One whose bytes survive keeps the acceptance window
                    // open, because the provider may have co-signed before
                    // the deadline and the client may still recover that
                    // signature; ending it would discard a signed
                    // obligation. Past the terminal deadline no result can
                    // be paid for by either party, so every unfinished
                    // phase is over then.
                    if height > authorization.terminal_deadline
                        && job.result().is_none()
                        && matches!(
                            job.phase(),
                            JobPhase::HalfSigned
                                | JobPhase::Accepted
                                | JobPhase::Running
                                | JobPhase::Streaming
                        )
                    {
                        authorization.terminal_deadline
                    } else if height > authorization.acceptance_deadline
                        && job.phase() == JobPhase::HalfSigned
                        && job.prepared_input().is_empty()
                        && !state.retained_roots().contains_key(&job.work_id())
                    {
                        authorization.acceptance_deadline
                    } else if height > authorization.payment_deadline
                        && job.result().is_some()
                        && state.payment(job.work_id()).is_none()
                    {
                        // The signed window to pay for this result has
                        // closed. A certified terminal is already off the
                        // open-job set, so an issued payment is preserved
                        // untouched rather than re-expired here.
                        authorization.payment_deadline
                    } else {
                        return None;
                    }
                }
            };
            Some((
                job.work_id(),
                TerminalOutcome::Expired {
                    deadline,
                    height,
                    payload,
                },
            ))
        })
        .collect()
}

/// Applies one certified read, then serves the close duty it shows.
///
/// One step, not a loop, and that is what a caller with a clock is
/// for: nothing in this crate has one. What the step gives that caller
/// is the whole answer — [`CloseProgress`] says whether to call again,
/// and the two terminal answers are the two ways a close ends.
///
/// The duty is re-derived from the journal and this read every time:
///
/// - a contest the provider can still answer gets its answer, fixed on
///   the disk through [`CloseChannel::fix_answer`] and offered to the
///   sink — again on every step until a read shows it landed or the
///   window shut, since submitting the same bytes twice is the same
///   answer;
/// - a contest that is answered, or whose window has shut at this read's
///   block time, gets the adjudicated close built from the slot this
///   read carries, which is the record consensus checks it against;
/// - a retained start that can still be included is offered again.
///
/// # Errors
///
/// [`CatchUpError`] when the journal refuses the read, and
/// [`BlockSourceError`] wrapped in it when the sink will not take the
/// transaction.
pub fn advance_close<'a, C, T, V>(
    observed: &'a ObservedChannel<'a>,
    sink: &'a T,
    channel: &'a mut C,
    verifier: &'a V,
) -> impl Future<Output = Result<CloseProgress, CatchUpError>> + 'a
where
    C: CloseChannel + 'a,
    T: TxSink + ?Sized + 'a,
    V: SigVerifier + 'a,
{
    // Construct the driver outside its caller's poll frame. Its journal
    // futures are too large to compose inline at every call site.
    Box::pin(advance_close_inner(observed, sink, channel, verifier))
}

async fn advance_close_inner<C, T, V>(
    observed: &ObservedChannel<'_>,
    sink: &T,
    channel: &mut C,
    verifier: &V,
) -> Result<CloseProgress, CatchUpError>
where
    C: CloseChannel,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    let step = 'borrow: {
        let mut store = channel.store().await?;
        observe(&mut store, observed, verifier).await?;
        let state = store.state();
        if state.close_settled().is_some() {
            break 'borrow CloseStep::Reached(CloseProgress::Settled);
        }
        if let Some((start_id, _)) = state.close_opened() {
            break 'borrow CloseStep::Reached(CloseProgress::Opened { start_id });
        }
        let Some(start) = state.includable_close_start(state.cursor().0) else {
            break 'borrow CloseStep::Reached(CloseProgress::Nothing);
        };
        CloseStep::Start {
            valid_through: start.valid_through_height(),
            tx: Box::new(Tx::move_action(hellas_kernel::Move::StartPaymentClose(
                start.clone(),
            ))),
        }
    };
    match step {
        // The answer, in the order a crash has to survive: the record
        // is fixed under one borrow, and the bytes are offered while
        // nothing is borrowed.
        CloseStep::Reached(CloseProgress::Opened { start_id }) => {
            if let Some(response) = channel.fix_answer(start_id).await? {
                sink.submit(response).await?;
                return Ok(CloseProgress::Opened { start_id });
            }
            let (descriptor, settlement) = {
                let store = channel.store().await?;
                (store.state().channel().clone(), store.state().settlement())
            };
            let PendingSlot::Present(pending) = observed.pending else {
                return Err(CloseError::NoContest.into());
            };
            if pending.responded() || observed.certified_at_ms >= pending.response_deadline_ms() {
                let outcome = sink
                    .submit(adjudicated_close(&descriptor, settlement, &pending)?)
                    .await?;
                return Ok(CloseProgress::AdjudicationSubmitted { start_id, outcome });
            }
            Ok(CloseProgress::Opened { start_id })
        }
        CloseStep::Reached(progress) => Ok(progress),
        CloseStep::Start { valid_through, tx } => {
            let outcome = sink.submit(*tx).await?;
            Ok(CloseProgress::Submitted {
                valid_through,
                outcome,
            })
        }
    }
}

/// What one close step decided under its borrow, and must now do
/// without one.
enum CloseStep {
    /// The step is over, or its remaining work is the contest's answer.
    Reached(CloseProgress),
    /// A retained start that can still be included, and the last height
    /// it can be included at.
    Start {
        /// Last height the retained signature can be included at.
        valid_through: u64,
        /// The retained bytes, verbatim. Boxed because a start is by
        /// far the largest thing this enum carries.
        tx: Box<Tx>,
    },
}

/// Where a close step reaches one channel's journal, and the answer it
/// may owe.
///
/// Journal borrows may span storage I/O, but must end before sink waits.
/// The sequence — apply the read, fix the answer, offer it — is shared by
/// owned endpoints and service drivers.
pub trait CloseChannel: Send {
    /// Borrows the journal until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when the journal cannot be reached.
    fn store(
        &mut self,
    ) -> impl core::future::Future<
        Output = Result<impl core::ops::DerefMut<Target = ChannelStore> + Send, CatchUpError>,
    > + Send;

    /// Durably fixes an answer before returning its transaction, if one is owed.
    ///
    /// # Errors
    /// [`CatchUpError::Busy`] when the channel cannot be reached, or
    /// [`CatchUpError::Store`] when the journal refuses the answer.
    fn fix_answer(
        &mut self,
        _start_id: StartId,
    ) -> impl core::future::Future<Output = Result<Option<Tx>, CatchUpError>> + Send {
        core::future::ready(Ok(None))
    }
}

impl CloseChannel for ChannelStore {
    async fn store(
        &mut self,
    ) -> Result<impl core::ops::DerefMut<Target = Self> + Send, CatchUpError> {
        Ok(self)
    }
}
