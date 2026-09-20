//! Spending the certificate: the finalized cursor, and the two
//! transactions that turn a signed scalar into coins.
//!
//! # Why the cursor is the load-bearing part
//!
//! Five rules elsewhere in this crate are decided against a height —
//! whether a receipt is timely, whether a payment is timely, whether a
//! job's deadlines are still reachable, whether plaintext released now
//! can still arrive, and whether a readiness decision may be acted on.
//! Every one of them reads
//! [`ChannelState::cursor`](crate::work_store::ChannelState::cursor). Until this module
//! there was no writer for it outside tests, and a cursor that never
//! moves makes every one of those rules pass: a receipt three hundred
//! blocks late reads as timely against a height that stopped.
//!
//! So the cursor is not the plumbing around the close. It is what makes
//! the deadlines mean anything, and [`observe`] is the only thing that
//! moves it.
//!
//! # Contiguous, or not at all
//!
//! [`observe`] takes one block and commits one
//! [`ChannelRecord::CursorAdvanced`], and that record refuses anything
//! but the next height whose parent is the block already held. A
//! notification that the chain has reached height 900 is a wake-up; it
//! is not evidence that this endpoint read 880 through 899, and the
//! close and the deadline those blocks may have carried are exactly
//! what it would be missing.
//!
//! [`catch_up`] is therefore a loop and not a jump. A block the source
//! cannot supply stops it, and the cursor stays where it was — which
//! makes every gate above fail closed rather than pass on a stale
//! height.
//!
//! # What a watcher looks for
//!
//! Two things, both on this channel's own payment edge. An accepted
//! [`Move::StartPaymentClose`](hellas_kernel::Move::StartPaymentClose) means a contest is live, and the height
//! that accepted it is the only place the contest's identifier can come
//! from — the kernel derives [`StartId`](hellas_kernel::StartId) from the start
//! digest *and*
//! the inclusion height, so no retained signature determines it. An
//! accepted [`Tx::Close`] means the edge is gone, and what it paid is
//! read out of the transaction consensus admitted.
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
//!   from the contest record consensus itself holds, so it can be
//!   rebuilt after any crash from a fresh finalized read. What cannot be
//!   rebuilt after the edge is consumed is the exact close *bytes* — and
//!   nothing needs them, because [`observe`] recognises settlement by
//!   the edge being closed rather than by matching bytes it kept.
//!
//! # What this module does not do
//!
//! It signs no cooperative freeze. That exit needs both parties'
//! signatures over one amount and no exchange in this crate negotiates
//! them; a freeze built here would be a transaction with one signature
//! and a place to put the other.

use hellas_kernel::{
    EarnedCertificate, List, MAX_EDGE_OUTPUTS, Party, PayloadHash, PaymentCloseResponse,
    PaymentCloseStart, Payout, PendingPaymentClose, Proof, Secp256k1Signer, Sig, SigVerifier,
    StartId, Terms, Tx, WorkPaymentSettlement, adjudicated_payouts, no_earned_digest,
};

use crate::work::{EndpointError, Handoff};
use crate::work_store::{
    Applied, ChannelRecord, ChannelStore, JobPhase, Role, TerminalOutcome, WorkStoreError, hex,
};
use hellas_rpc::observe::{LEVEL, TARGET, Timing};
use hellas_rpc::protocol::work::PaidChannel;

/// One finalized block, as a watcher must see it.
///
/// The transactions are this block's accepted kernel transactions in
/// consensus order — the order `HellasBlock::txs()` exposes, not a set
/// and not a key-sorted projection. Two transactions in one block can
/// be a start and the close that ends it, and reversing them is two
/// different histories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedWork {
    /// Finalized height of this block.
    pub height: u64,
    /// Payload digest this block names as its parent.
    pub parent: [u8; 32],
    /// This block's own payload digest.
    pub payload: [u8; 32],
    /// The kernel transactions this block accepted, in block order.
    pub txs: Vec<Tx>,
}

/// Why a finalized block could not be read.
///
/// Opaque, like [`crate::work::BackendFault`]: a watcher does the same
/// thing for every one of them, which is stop and leave the cursor
/// where it was.
#[derive(Clone, Debug, thiserror::Error)]
#[error("the finalized block source failed: {0}")]
pub struct BlockSourceError(String);

impl BlockSourceError {
    /// Reports a source failure.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Where a close transaction is handed to consensus.
///
/// One method, and it is deliberately not a query: submitting says
/// nothing about inclusion, and an endpoint learns whether its start
/// landed from the blocks it reads, never from the answer to this. It
/// is in this crate rather than in the chain crate for
/// [`FinalizedBlocks`]'s reason — both endpoints need exactly this and
/// neither needs a mempool.
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

/// Where a watcher gets its finalized blocks.
///
/// Narrow on purpose, and in this crate rather than in the chain crate,
/// because both endpoints need exactly this and neither needs a
/// mempool, a coin query, or an activity stream to get it. It is also
/// what lets the loop below be tested against a history a test writes
/// down rather than a validator it runs.
pub trait FinalizedBlocks {
    /// Returns the highest finalized height, or `None` before anything
    /// is finalized.
    fn latest_height(
        &self,
    ) -> impl core::future::Future<Output = Result<Option<u64>, BlockSourceError>> + Send;

    /// Returns the finalized block at `height`.
    ///
    /// `Ok(None)` means this source cannot supply that height — it is
    /// not finalized, or it has been pruned. Both stop a scan; neither
    /// is a reason to skip it.
    fn block_at(
        &self,
        height: u64,
    ) -> impl core::future::Future<Output = Result<Option<FinalizedWork>, BlockSourceError>> + Send;
}

/// Why a close could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CloseError {
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
    #[error("the response window is open until height {deadline}, and the cursor is at {height}")]
    ResponseWindowOpen {
        /// Finalized height the endpoint has reached.
        height: u64,
        /// Height at which the window shuts.
        deadline: u64,
    },
    /// The contest has already been answered, and there is one answer.
    #[error("this contest has already been answered")]
    AlreadyResponded,
    /// The response window has shut, so consensus would refuse an
    /// answer.
    #[error("the response window shut at height {deadline}, and the read is at {height}")]
    ResponseWindowClosed {
        /// Finalized height the read was taken at.
        height: u64,
        /// Height at which the window shut.
        deadline: u64,
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
    /// The edge is gone, and this is what the close paid the provider.
    Settled {
        /// What the finalized close paid the provider.
        provider_payout: u64,
    },
    /// A contest is finalized on this edge.
    Opened {
        /// The contest a response or a close must name.
        start_id: StartId,
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

/// Why a catch-up did not finish.
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
    /// A close duty stops the read at the cursor, which is §5's
    /// stop-before-successor rule refusing it: an answer owed and not
    /// yet taken by a sink, or a settlement after which there is nothing
    /// left to read. A backlog read past either is how a response
    /// deadline is lost.
    #[error("a close duty stops this read at height {height}, and no successor block is read")]
    CloseDuty {
        /// Cursor height the duty was found at.
        height: u64,
    },
    /// The block source failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A block inside the range this endpoint must read is not
    /// available. The cursor stays where it was.
    #[error("finalized block {height} is not available, so the cursor stays behind")]
    Missing {
        /// Height that could not be read.
        height: u64,
    },
    /// A block was refused by the journal.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
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
    let earned = match start.certificate() {
        None => no_earned_digest(channel.payment_edge(), channel.payment_terms_hash()),
        Some((certificate, _)) => certificate.digest(channel.network()),
    };
    hellas_kernel::start_digest(
        channel.network(),
        channel.payment_edge(),
        channel.payment_terms_hash(),
        start.opener_role(),
        (start.valid_from_height(), start.valid_through_height()),
        earned,
    )
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
/// window, and [`CloseError::WindowOverflow`] when either addition
/// leaves the representable range.
pub fn close_start(
    channel: &PaidChannel,
    opener_role: Party,
    height: u64,
    certificate: Option<(EarnedCertificate, Sig)>,
    signer: &Secp256k1Signer,
) -> Result<PaymentCloseStart, CloseError> {
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
        certificate,
        Sig::from_bytes([0_u8; Sig::LENGTH]),
    );
    let action_sig = signer.sign(start_body_digest(channel, &unsigned));
    Ok(PaymentCloseStart::new(
        channel.payment_edge(),
        Terms::work_payment(channel.payment_terms().clone()),
        opener_role,
        (valid_from, valid_through),
        unsigned.certificate().copied(),
        action_sig,
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
#[must_use]
pub fn close_response(
    channel: &PaidChannel,
    start_id: StartId,
    certificate: (EarnedCertificate, Sig),
    signer: &Secp256k1Signer,
) -> PaymentCloseResponse {
    // `response_build_ms`: the digest and the signature over it, which
    // is the whole of what building an answer costs. The journal record
    // that fixes it is not in here — §4 counts that separately, as one
    // of `Wresp`'s three fsyncs.
    let built = Timing::start();
    let digest = response_body_digest(channel, start_id, &certificate.0);
    let response = PaymentCloseResponse::new(
        channel.payment_edge(),
        start_id,
        Party::Taker,
        certificate,
        signer.sign(digest),
    );
    if let Some(ms) = built.ms() {
        tracing::event!(
            name: "response_build_ms",
            target: TARGET,
            LEVEL,
            edge = %hex(&channel.payment_edge().to_bytes()),
            start_id = %hex(&start_id.to_bytes()),
            ms,
        );
    }
    response
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

/// Reads the finalized tip, and samples what asking for it cost.
///
/// `fresh_tip_ms`, as §4's `Wstart` names it: the read a close start is
/// signed against, and the first thing an endpoint waits for before it
/// can put a signature on a chain. One sample per ask, whether or not
/// anything is finalized yet.
async fn fresh_tip<S>(source: &S) -> Result<Option<u64>, BlockSourceError>
where
    S: FinalizedBlocks + ?Sized,
{
    let asked = Timing::start();
    let latest = source.latest_height().await?;
    if let Some(ms) = asked.ms() {
        tracing::event!(
            name: "fresh_tip_ms",
            target: TARGET,
            LEVEL,
            height = latest.unwrap_or_default(),
            finalized = latest.is_some(),
            ms,
        );
    }
    Ok(latest)
}

/// Fetches one finalized block, and samples what fetching it cost.
///
/// `one_block_fetch_ms`, as §4's `Wresp` names it. One block and one
/// sample, because §5 makes the catch-up loop apply one block before it
/// asks for another: the wait a response deadline is spent against is
/// the cost of *one* fetch, never of a backlog.
async fn one_block_fetch<S>(
    source: &S,
    height: u64,
) -> Result<Option<FinalizedWork>, BlockSourceError>
where
    S: FinalizedBlocks + ?Sized,
{
    let asked = Timing::start();
    let block = source.block_at(height).await?;
    if let Some(ms) = asked.ms() {
        tracing::event!(
            name: "one_block_fetch_ms",
            target: TARGET,
            LEVEL,
            height,
            available = block.is_some(),
            ms,
        );
    }
    Ok(block)
}

/// Applies one finalized block to one channel's journal.
///
/// # Nothing is written for a block this journal may not read
///
/// The height and the parent are checked first, against
/// [`ChannelState::reading`](crate::work_store::ChannelState) — the
/// same rule the cursor record itself applies, asked before any of the
/// block's meaning reaches the disk. It has to be first. The
/// transitions below move money and shut the channel, and a block that
/// is not this journal's next one is a block whose contents are not
/// facts: a forged or merely out-of-order `h + 2` would otherwise end a
/// job, record a contest, and only then be refused by the cursor.
///
/// A block this journal has already read is [`Applied::Redundant`] and
/// returns here, having written nothing. Everything it meant is already
/// on the disk.
///
/// # Then the order a crash must be able to stop in
///
/// Everything the block *means* is committed before the cursor that
/// says the block was read, so a process that dies between them
/// re-reads the same block and re-commits the same records — which the
/// journal answers as the retries they are. The other order would
/// advance past a block whose close it had not recorded, and no later
/// scan would go back for it.
///
/// # Errors
///
/// [`WorkStoreError`] when the block is not the contiguous next one —
/// before anything is written — and when a record is refused or cannot
/// be made durable. The cursor is the last thing written, so a refusal
/// anywhere leaves this endpoint still behind this block.
pub fn observe<V: SigVerifier>(
    store: &mut ChannelStore,
    block: &FinalizedWork,
    verifier: &V,
) -> Result<(), WorkStoreError> {
    if store
        .state()
        .reading(block.height, &block.parent, &block.payload)?
        == Applied::Redundant
    {
        return Ok(());
    }
    for (work_id, outcome) in expiry_at(store.state(), block.height, block.payload) {
        store.commit(ChannelRecord::JobTerminated { work_id, outcome }, verifier)?;
    }

    apply_finalized_txs(store, block.height, block.payload, &block.txs, verifier)?;

    store.commit(
        ChannelRecord::CursorAdvanced {
            height: block.height,
            parent: block.parent,
            payload: block.payload,
        },
        verifier,
    )?;
    Ok(())
}

/// Records every contest and settlement a finalized block carries on this
/// channel's payment edge, in block order.
///
/// Split out of [`observe`] because one block is read twice by two
/// different rules. [`observe`] reads a *new* block, after checking the
/// cursor may advance onto it. Mounting a close-only channel replays the
/// origin block's own post-Open moves — the cursor already sits on that
/// block, so it is not a new one, but a `StartPaymentClose` ordered after
/// the Open in it is still a contest this endpoint must see. Both go
/// through here, so a same-block contest is recognised exactly as a
/// later-block one is. The Open itself matches neither arm and is ignored.
pub(crate) fn apply_finalized_txs<V: SigVerifier>(
    store: &mut ChannelStore,
    height: u64,
    payload: [u8; 32],
    txs: &[Tx],
    verifier: &V,
) -> Result<(), WorkStoreError> {
    let channel = store.state().channel().clone();
    let edge = channel.payment_edge();
    for tx in txs {
        match tx {
            Tx::Move {
                action: hellas_kernel::Move::StartPaymentClose(start),
            } if start.payment_edge() == edge => {
                // A contest on this edge is the cutoff, and the open job
                // does not survive it: no payment will be credited after
                // this record, so a job still in flight is a job that can
                // no longer be paid for. It rests at an expired terminal,
                // and the provider bears whatever compute or delivery it
                // already spent on it.
                let open: Vec<_> = store
                    .state()
                    .jobs()
                    .map(|job| (job.work_id(), job.authorization().payment_deadline))
                    .collect();
                for (work_id, deadline) in open {
                    store.commit(
                        ChannelRecord::JobTerminated {
                            work_id,
                            outcome: TerminalOutcome::Expired {
                                deadline,
                                height,
                                payload,
                            },
                        },
                        verifier,
                    )?;
                }
                // The window and the claimed floor are fixed by the block
                // that accepted this start, exactly as the kernel fixed
                // them: the response deadline is the inclusion height plus
                // the terms' omission window, and the claim is what the
                // start's own certificate carried. Journaled here, a
                // provider that restarts holding only this record can
                // still decide whether an answer is open and what it must
                // beat — without a second finalized snapshot.
                let response_deadline =
                    height.saturating_add(channel.payment_terms().omit_response_blocks);
                let claimed = start
                    .certificate()
                    .map_or(0, |(certificate, _)| certificate.earned_cumulative());
                store.commit(
                    ChannelRecord::CloseOpened {
                        start_id: hellas_kernel::start_id(
                            start_body_digest(&channel, start),
                            height,
                        ),
                        opener: start.opener_role(),
                        response_deadline,
                        claimed,
                    },
                    verifier,
                )?;
            }
            Tx::Close { input, outputs, .. } if *input == edge => {
                let provider_payout = outputs
                    .as_slice()
                    .iter()
                    .find(|payout| payout.owner() == channel.provider_key())
                    .map_or(0, |payout| payout.value());
                let open: Vec<_> = store
                    .state()
                    .jobs()
                    .map(|job| (job.work_id(), job.authorization().payment_deadline))
                    .collect();
                for (work_id, deadline) in open {
                    store.commit(
                        ChannelRecord::JobTerminated {
                            work_id,
                            outcome: TerminalOutcome::Expired {
                                deadline,
                                height,
                                payload,
                            },
                        },
                        verifier,
                    )?;
                }
                store.commit(
                    ChannelRecord::CloseSettled {
                        height,
                        payload,
                        provider_payout,
                    },
                    verifier,
                )?;
            }
            _ => {}
        }
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
///   client signed to pay by has passed.
///
/// Each is an [`TerminalOutcome::Expired`] naming the deadline it crossed
/// and the finalized block that crossed it. The provider bears whatever
/// compute or delivery it already spent.
///
/// Only a provider applies them. A client ending a job it might still be
/// paying for would be a client deciding against itself.
fn expiry_at(
    state: &crate::work_store::ChannelState,
    height: u64,
    payload: [u8; 32],
) -> Vec<(hellas_rpc::protocol::Digest, TerminalOutcome)> {
    if state.role() != Role::Provider {
        return Vec::new();
    }
    state
        .jobs()
        .filter_map(|job| {
            let authorization = job.authorization();
            let deadline = if height > authorization.payment_deadline {
                authorization.payment_deadline
            } else if height > authorization.terminal_deadline && job.result().is_none() {
                authorization.terminal_deadline
            } else if height > authorization.acceptance_deadline
                && job.phase() == JobPhase::HalfSigned
            {
                authorization.acceptance_deadline
            } else {
                return None;
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

/// Reads every finalized block this journal has not seen, in order.
///
/// There is no anchoring step and no height this may start at other
/// than the one after the cursor: the store was opened at the block
/// that opened the channel, so "everything this journal has not seen"
/// is everything that has ever happened to this edge. A scan that
/// chose its own starting height would skip the blocks between the
/// channel opening and the first catch-up, and a close settled in one
/// of them is a close this endpoint would never learn about.
///
/// Returns the height the cursor reached.
///
/// # Errors
///
/// [`CatchUpError::Missing`] when a block inside the range cannot be
/// read — the scan stops there and the cursor keeps the last height it
/// did read — plus the source's own failures and the journal's.
/// Reads to the tip, then resubmits this endpoint's retained close
/// start if it has not landed yet.
///
/// One step, not a loop, and that is what a caller with a clock is
/// for: nothing in this crate has one, and a loop written here would
/// spin against a chain that finalizes at its own rate. What the step
/// gives that caller is the whole answer — [`CloseProgress`] says
/// whether to call again, and the two terminal answers are the two
/// ways a close ends.
///
/// The reading comes first, and it has to: the retained bytes are
/// resubmitted only while the journal still shows no contest, and the
/// journal only shows one after the block that opened it has been
/// read. The other order resubmits a start that is already a contest.
///
/// Nothing about a *start* is journaled here. A submission is not a
/// decision — the signature was journaled before it left
/// [`crate::work::ProviderEndpoint::prepare_close`], and these are those
/// same bytes. The one record this writes is the contest's answer,
/// through [`CloseChannel::fix_answer`], and it is written before the
/// answer is offered rather than after one was taken: it fixes which
/// answer this contest is answered by, and says nothing about consensus
/// having received it.
///
/// # Errors
///
/// [`CatchUpError`] for the read, and [`BlockSourceError`] wrapped in
/// it when the sink will not take the transaction.
pub async fn advance_close<C, S, T, V>(
    source: &S,
    sink: &T,
    channel: &mut C,
    verifier: &V,
) -> Result<CloseProgress, CatchUpError>
where
    C: CloseChannel,
    S: FinalizedBlocks + ?Sized,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    let handoff = channel.handoff()?;
    let height = catch_up_until_duty(source, channel, verifier, handoff).await?;
    let step = channel.with_store(|store| {
        let state = store.state();
        if let Some(settled) = state.close_settled() {
            return CloseStep::Reached(CloseProgress::Settled {
                provider_payout: settled.provider_payout,
            });
        }
        if let Some((start_id, _)) = state.close_opened() {
            return CloseStep::Reached(CloseProgress::Opened { start_id });
        }
        let Some(start) = state.includable_close_start(height) else {
            return CloseStep::Reached(CloseProgress::Nothing);
        };
        CloseStep::Start {
            valid_through: start.valid_through_height(),
            tx: Box::new(Tx::move_action(hellas_kernel::Move::StartPaymentClose(
                start.clone(),
            ))),
        }
    })?;
    match step {
        // The answer, in the order a crash has to survive: the record
        // is fixed under one borrow, the bytes are offered while
        // nothing is borrowed, and what the sink did is recorded under
        // another. Nothing waits on a sink holding this journal.
        CloseStep::Reached(CloseProgress::Opened { start_id }) => {
            if let Some(response) = channel.fix_answer(start_id)? {
                let outcome = sink.submit(response).await?;
                channel.record_handoff(start_id, outcome)?;
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
/// Every method here is synchronous, which is the whole content of the
/// trait: a close waits on a source and on a sink, and neither wait may
/// happen while this journal is borrowed. An endpoint that owns its
/// store lends it directly; a service that keeps one behind a lock takes
/// that lock for exactly as long as the step runs and hands back what
/// the step produced. The sequence itself — read to the duty, fix the
/// answer, offer it, record the hand-off — is [`advance_close`]'s and is
/// written once for both.
pub trait CloseChannel {
    /// Lends this channel's journal for exactly as long as `step` runs.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when this journal cannot be reached at
    /// all, which is the only thing an implementation may decide here.
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut ChannelStore) -> R,
    ) -> Result<R, CatchUpError>;

    /// What this channel's last send got back.
    ///
    /// Defaulted to none held, which is the whole of a client's answer:
    /// only a certificate's beneficiary may spend it, so a client never
    /// holds an answer back and never has one a sink took.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when this journal cannot be reached.
    fn handoff(&mut self) -> Result<Option<(StartId, Handoff)>, CatchUpError> {
        Ok(None)
    }

    /// Fixes this channel's answer to `start_id` on the disk and returns
    /// the transaction carrying it, or `None` when no answer is owed.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when this journal cannot be reached, and
    /// [`CatchUpError::Store`] when it refuses the answer.
    fn fix_answer(&mut self, _start_id: StartId) -> Result<Option<Tx>, CatchUpError> {
        Ok(None)
    }

    /// Records what a sink did with the answer to `start_id`.
    ///
    /// # Errors
    ///
    /// [`CatchUpError::Busy`] when this journal cannot be reached.
    fn record_handoff(
        &mut self,
        _start_id: StartId,
        _outcome: hellas_rpc::SubmitTxOutcome,
    ) -> Result<(), CatchUpError> {
        Ok(())
    }
}

impl CloseChannel for ChannelStore {
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut ChannelStore) -> R,
    ) -> Result<R, CatchUpError> {
        Ok(step(self))
    }
}

/// Reads contiguously only until one newly observed block creates a duty.
///
/// `advance_close` services the returned duty before it can ask the source
/// for another block. This is the backlog rule: a restart ten thousand
/// blocks behind cannot discover a response, close, or reclaim obligation in
/// block one and postpone it behind the remaining 9,999 fetches.
///
/// A duty already on the disk when this is entered is returned before
/// [`FinalizedBlocks::latest_height`] is even called, which is the case
/// a restart is: the answer a dead process fixed and never sent is
/// offered again before one successor block is read, so a backlog that
/// runs past the response deadline cannot be what loses it.
///
/// `handoff` is what this caller's last send got back, and its two
/// answers buy different amounts of reading. [`Handoff::Accepted`]
/// suppresses the duty for as long as the contest lasts: a sink holds
/// the answer, and there is nothing left to do but watch.
/// [`Handoff::Offered`] suppresses it for **one** block and then lets it
/// reappear, which is the same backlog rule one step weaker — an answer
/// nobody took must be offered again before the block after next, or a
/// backlog longer than the window swallows every retry and the contest
/// ends unanswered on the claim this endpoint could have beaten.
async fn catch_up_until_duty<C, S, V>(
    source: &S,
    channel: &mut C,
    verifier: &V,
    handoff: Option<(StartId, Handoff)>,
) -> Result<u64, CatchUpError>
where
    C: CloseChannel,
    S: FinalizedBlocks + ?Sized,
    V: SigVerifier,
{
    let mut suppressed = handoff.map(|(start_id, _)| start_id);
    if let Some(height) = channel.with_store(|store| {
        let state = store.state();
        close_duty_present(state, suppressed).then_some(state.cursor().0)
    })? {
        return Ok(height);
    }
    let Some(latest) = fresh_tip(source).await? else {
        return channel.with_store(|store| store.state().cursor().0);
    };
    let mut next = channel
        .with_store(|store| store.state().cursor().0)?
        .saturating_add(1);
    while next <= latest {
        let block = one_block_fetch(source, next)
            .await?
            .ok_or(CatchUpError::Missing { height: next })?;
        channel.with_store(|store| observe(store, &block, verifier))??;
        if handoff.is_some_and(|(_, state)| state == Handoff::Offered) {
            // The one block a still-owed answer paid for is spent.
            suppressed = None;
        }
        if let Some(height) = channel.with_store(|store| {
            let state = store.state();
            close_duty_present(state, suppressed).then_some(state.cursor().0)
        })? {
            return Ok(height);
        }
        next = next.saturating_add(1);
    }
    channel.with_store(|store| store.state().cursor().0)
}

/// Whether this journal holds a close duty its caller must service
/// before another block is fetched.
///
/// A finalized close is one: it is terminal, and there is nothing after
/// it to read.
///
/// A contest is one while
/// [`ChannelState::answerable_contest`](crate::work_store::ChannelState::answerable_contest)
/// says an answer is owed and `suppressed` is not that contest. Two things
/// are deliberately not consulted here.
///
/// The journal's own
/// [`ChannelRecord::CloseResponded`](crate::work_store::ChannelRecord::CloseResponded)
/// is not, because it is fsynced *before* the submission it authorises:
/// a crash between the two leaves a record saying "answered" over a
/// consensus that received nothing, and a scan floor built on it would
/// read the whole successor backlog past the deadline with the answer
/// still on the disk.
///
/// Eligibility is, because an unanswerable contest is not a duty
/// deferred, it is a duty that does not exist — the opener, the role and
/// the held certificate are frozen at the block that recorded the
/// contest, so an endpoint that cannot answer now can never answer, and
/// stopping for it would freeze the cursor on the contest block forever.
///
/// `suppressed` is the contest whose answer the caller's hand-off state
/// currently excuses it from — for good when a sink took the answer, for
/// one block when a sink did not. It is what lets the cursor move on: a
/// sink that refused the answer may have refused it because the answer
/// is already on chain, and only reading further blocks can tell.
/// Retrying is a separate question, and its answer is in
/// [`crate::work::ProviderEndpoint::advance_close`].
pub(crate) fn close_duty_present(
    state: &crate::work_store::ChannelState,
    suppressed: Option<StartId>,
) -> bool {
    state.close_settled().is_some()
        || state
            .answerable_contest()
            .is_some_and(|(contest, _)| Some(contest.start_id) != suppressed)
}

pub async fn catch_up<S, V>(
    source: &S,
    store: &mut ChannelStore,
    verifier: &V,
) -> Result<u64, CatchUpError>
where
    S: FinalizedBlocks + ?Sized,
    V: SigVerifier,
{
    let Some(latest) = fresh_tip(source).await? else {
        return Ok(store.state().cursor().0);
    };
    use futures::{StreamExt as _, stream};

    let next = store.state().cursor().0.saturating_add(1);
    // Fetch ahead without changing the journal's ordered, one-block commits.
    // An idle gateway may have thousands of finalized blocks to read before
    // its next request; serial network round trips can exceed that request.
    let pending = stream::iter(next..=latest)
        .map(|height| async move {
            one_block_fetch(source, height)
                .await?
                .ok_or(CatchUpError::Missing { height })
        })
        .buffered(16);
    futures::pin_mut!(pending);
    while let Some(block) = pending.next().await {
        let block = block?;
        observe(store, &block, verifier)?;
    }
    Ok(store.state().cursor().0)
}
