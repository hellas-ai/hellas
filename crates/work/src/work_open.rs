//! Posting the two Opens: the driver that turns a completed handshake
//! into a channel on chain.
//!
//! # What was missing
//!
//! [`SetupState::decide`] is §6's five-way recovery machine and it has
//! been complete for a while. What it never had was anything to drive
//! it: something that reads one coherent finalized state, asks it what
//! to do, records that step before taking it, and reads the blocks back
//! to find out whether it landed. [`advance_setup`] is that, and it adds
//! no decision of its own — every branch below is a `SetupDecision`, and
//! the two it does not act on say so.
//!
//! # Durable before broadcast
//!
//! The same rule [`crate::work_close`] obeys for a close, in the same
//! order: the marker is committed and fsynced, and only then is the
//! transaction handed to a sink. A crash between the two leaves a
//! journal that says the bond was submitted when it may not have been,
//! and that is the safe half — the next run re-decides from the chain,
//! sees no bond, and submits the *retained* bytes again. A resubmission
//! is the same Open and not a second one: `apply_open` refuses it twice
//! over, once because the funding coins the first one consumed are gone
//! and once with `ApplyError::EdgeExists` for the edge already there.
//!
//! The other order is the one that cannot be recovered from: broadcast
//! first, crash, and the journal has no record that a transaction
//! carrying this provider's signature is in flight.
//!
//! # Where the channel begins
//!
//! [`SetupRecord::Complete`] carries the block the payment Open landed
//! in — its height, its payload, and its parent's payload, which is the
//! cursor a channel watcher starts from. None of those three can be
//! derived from the objects: a live edge says the Open was accepted, not
//! where. So [`advance_setup`] reads finalized blocks until it finds the
//! one whose accepted transactions contain an Open deriving this payment
//! edge.
//!
//! The scan starts at the successor of the journal's immutable
//! [`SetupRecord::ScanArmed`] floor. Its first parent must be the armed
//! payload and every later parent must be the preceding payload. Submission
//! markers are deliberately absent from this calculation: who happened to
//! submit an Open cannot move the observation floor past an authorization a
//! counterparty may already have put on chain.
//!
//! # Who mounts
//!
//! Every step that opens the channel journal hands it back in
//! [`SetupAdvance::mounted`]. There are three: the completion, the
//! close-only mount, and the completed-journal shortcut — which matters
//! because it is the only branch a restarted process reaches a finished
//! setup by, and a caller that had to mount for itself there would have
//! to mount for itself after every restart.
//!
//! A caller receives its channel; it never builds a second one. The
//! alternative is re-deriving the settlement from the armed descriptor
//! and re-running this replay outside the library — and the two
//! spellings come apart at exactly the places that matter. The
//! settlement comes from the coherent live edge rather than from what
//! configuration expected, and the origin block's own post-Open moves
//! are replayed because the mount's cursor already sits on that block.
//! Neither is visible from the descriptor alone.
//!
//! # What it does not do
//!
//! It does not take an unleased bond's Timeout back.
//! [`SetupDecision::TimeoutBond`] is returned to the caller as
//! [`SetupProgress::TimeoutBond`] and nothing here submits it: the
//! journal has no record with which to mark that submission, and this
//! module submits nothing it cannot write down first. Nothing else in
//! this workspace submits one either — `Tx::timeout_close` has no caller
//! outside tests — so a provider whose setup ends there gets its stake
//! back only by an operator building and sending that transaction.
//!
//! It does not exchange revisions with the peer. That is
//! [`crate::work_handshake::send_setup_exchange`], bracketed by its
//! prepare/apply helpers, and a caller runs the two in the obvious order:
//! exchange until the bundle is complete, then drive until the journals
//! record it.

use std::collections::BTreeSet;

use futures::{StreamExt as _, stream};
use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, SigVerifier, Tx};

use crate::work_close::{
    BlockSourceError, FinalizedBlocks, FinalizedWork, TxSink, apply_finalized_txs, observe,
};
use crate::work_store::setup::touches_setup;
use crate::work_store::{
    ChannelStore, ObservedSetup, SetupAbort, SetupDecision, SetupEnd, SetupFault,
    SetupHistoryBatch, SetupHistoryBlock, SetupOrigin, SetupRecord, SetupScan, SetupState,
    SetupStore, WorkStoreError,
};

/// Which channel a setup read answers for, and which coins it must
/// answer for at the same state.
///
/// The coins are the two retained Opens' funding, and they are part of
/// the question rather than a second call for the reason
/// [`SetupState::decide`] takes them in one struct: the branch that
/// locks a provider's stake has their liveness as a premise, and a
/// premise read at a different state than the edges is a premise about
/// a state the decision is not being made at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupQuery {
    /// The tag-4 work-stake bond this setup opens.
    pub bond_edge: EdgeId,
    /// The tag-2 payment edge it opens over that bond.
    pub payment_edge: EdgeId,
    /// Every coin the two retained Opens spend.
    pub funding: BTreeSet<CoinId>,
}

/// One coherent finalized read a setup decision is made from.
///
/// Owned, where [`ObservedSetup`] borrows, because this is what crosses
/// the trait boundary from whatever holds the chain. [`Self::observed`]
/// is the only way to turn it into a decision's input, so the height
/// the edges came from and the height the coins came from cannot be two
/// heights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedSetup {
    /// Finalized height every field below was read at.
    pub height: u64,
    /// The bond edge, or its absence.
    pub bond: Option<Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// Which of the query's coins are still live.
    pub live_funding: BTreeSet<CoinId>,
}

impl FinalizedSetup {
    /// Returns this read as the decision's input.
    #[must_use]
    pub fn observed(&self) -> ObservedSetup<'_> {
        ObservedSetup {
            height: self.height,
            bond: self.bond.as_ref(),
            payment: self.payment.as_ref(),
            lease: self.lease,
            live_funding: &self.live_funding,
        }
    }
}

/// Where a setup decision's finalized state comes from.
///
/// Narrow, and in this crate rather than in the chain crate, for
/// [`FinalizedBlocks`]'s reason: this is the whole of what driving a
/// setup needs from a chain, and an endpoint that does paid work should
/// not have to be handed an activity stream and a mempool to get it.
pub trait SetupView {
    /// Returns one coherent read of this setup, at one finalized block.
    ///
    /// `Ok(None)` means the source has no finalized state to answer
    /// from at all — not that the channel is absent. An existing setup
    /// whose objects are all missing at a real finalized block is
    /// `Ok(Some(..))` with absent objects, and those are different
    /// facts.
    ///
    /// The implementation owes the coherence, exactly as
    /// [`ObservedSetup`]'s caller does: every field must come from one
    /// state, and `live_funding` must be a subset of `query.funding`
    /// read at that same state.
    fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> impl core::future::Future<Output = Result<Option<FinalizedSetup>, BlockSourceError>> + Send;
}

/// Which of the two Opens was handed to consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupStep {
    /// The provider's tag-4 stake bond.
    Bond,
    /// The client's tag-2 payment channel over it.
    Payment,
}

/// How far one step of the driver got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupProgress {
    /// Both edges and this channel's lease are finalized, the journal
    /// now records where, and the channel is mounted at that origin in
    /// [`SetupAdvance::mounted`].
    Complete(SetupOrigin),
    /// One bounded finalized-history batch was durably applied. The caller
    /// yields before asking for another batch.
    HistoryAdvanced {
        /// Last finalized height in the batch.
        through: u64,
    },
    /// Admission is unavailable, but the journal-only channel mount was
    /// opened and its retained Start/Close history replayed. The mount
    /// itself is in [`SetupAdvance::mounted`].
    CloseOnly {
        /// Payment-Open origin recovered from finalized history.
        origin: SetupOrigin,
        /// Whether that history already contains the finalized payment close.
        settled: bool,
    },
    /// A retained Open was journaled and handed to consensus. It is not
    /// included until a block says so.
    Submitted {
        /// Which of the two.
        step: SetupStep,
        /// What the node did with the transaction.
        outcome: hellas_rpc::SubmitTxOutcome,
    },
    /// Nothing for this endpoint to do: the other party has not
    /// produced the next revision, or the transaction being waited on
    /// is not this endpoint's to send.
    AwaitingCounterparty,
    /// The source has no finalized state to decide from yet, or the
    /// question this journal asks moved while its own answer was in
    /// flight and nothing was decided from that answer.
    AwaitingFinalizedState,
    /// The bond is live and unleased and this channel cannot use it.
    /// Its Timeout is immediate, and nothing here sends one.
    TimeoutBond,
    /// The deterministic bond Timeout was journaled and submitted.
    BondTimeoutSubmitted {
        /// What the node did with the transaction.
        outcome: hellas_rpc::SubmitTxOutcome,
    },
    /// Setup stopped with the provider's coins unspent, and the journal
    /// records it.
    Aborted(SetupAbort),
    /// Setup stopped in a state no automatic step can leave, and the
    /// journal records it.
    Faulted(SetupFault),
}

/// One step of the driver, and the channel that step mounted.
///
/// The channel is handed over rather than described, because a
/// description is something a caller has to act on and every caller
/// would act on it the same way. [`ChannelStore`] is also exclusive —
/// its journal is held for as long as the value lives — so handing it
/// back is the only way to give a caller the mount this step made
/// rather than a second one beside it.
#[derive(Debug)]
pub struct SetupAdvance {
    /// How far this step got.
    pub progress: SetupProgress,
    /// The channel journal this step opened, on every step that opens
    /// one: both completion branches and the close-only mount.
    pub mounted: Option<ChannelStore>,
}

impl SetupAdvance {
    /// A step that opened no channel.
    const fn bare(progress: SetupProgress) -> Self {
        Self {
            progress,
            mounted: None,
        }
    }
}

/// Where a setup step reaches one endpoint's journal.
///
/// Synchronous, which is the whole content of it: a setup step waits on
/// a finalized view, on blocks and on a sink, and none of those waits
/// may happen while the journal is borrowed. A caller that owns its
/// store lends it directly; a service that keeps one behind a lock takes
/// that lock for exactly as long as the step runs. The steps themselves
/// are [`advance_setup`]'s and are written once for both.
pub trait SetupChannel {
    /// Lends this setup's journal for exactly as long as `step` runs.
    ///
    /// # Errors
    ///
    /// [`SetupDriveError::Busy`] when the journal cannot be reached at
    /// all, which is the only thing an implementation may decide here.
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut SetupStore) -> R,
    ) -> Result<R, SetupDriveError>;

    /// The same borrow, for a step that can fail on its own.
    ///
    /// # Errors
    ///
    /// [`SetupDriveError::Busy`] as above, and whatever `step` raises.
    fn try_with_store<R>(
        &mut self,
        step: impl FnOnce(&mut SetupStore) -> Result<R, SetupDriveError>,
    ) -> Result<R, SetupDriveError>
    where
        Self: Sized,
    {
        self.with_store(step)?
    }
}

impl SetupChannel for SetupStore {
    fn with_store<R>(
        &mut self,
        step: impl FnOnce(&mut SetupStore) -> R,
    ) -> Result<R, SetupDriveError> {
        Ok(step(self))
    }
}

/// Why one step of the driver did not finish.
#[derive(Debug, thiserror::Error)]
pub enum SetupDriveError {
    /// This setup already has a driver, or a handler panicked while
    /// holding its journal. Nothing was decided and nothing was written.
    #[error("this setup journal is already being driven")]
    Busy,
    /// The finalized state or the block source failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A step could not be made durable, or the journal refused it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
    /// A block inside the origin scan could not be read, so where the
    /// channel begins is still unknown.
    #[error("finalized block {height} is not available, so the channel's origin is unread")]
    OriginUnreadable {
        /// Height that could not be read.
        height: u64,
    },
    /// No finalized block above the floor carries the payment Open.
    ///
    /// Reached by a floor above the block that does carry it, and by a
    /// source that is missing history it claims to have. Either way
    /// nothing is recorded: an origin is a watcher's starting cursor,
    /// and a guessed one skips every block before it.
    #[error("no finalized block in {floor}..={tip} opened payment edge {edge:?}")]
    OriginNotFound {
        /// Height the scan started above.
        floor: u64,
        /// Highest finalized height the source reported.
        tip: u64,
        /// Edge the scan was looking for.
        edge: EdgeId,
    },
    /// The journal has no executable transaction for a step it just
    /// accepted a marker for.
    ///
    /// Unreachable through [`advance_setup`]: `decide` proposes neither
    /// submission before both Opens are executable, and
    /// `SetupStore::commit` refuses both markers for the same reason.
    /// Named so the match is total; no test reaches it, and none claims
    /// to.
    #[error("the journal retains no {step:?} open to submit")]
    NothingRetained {
        /// Step whose transaction was missing.
        step: SetupStep,
    },
    /// This journal predates recovery arming and therefore has no safe
    /// history floor.
    #[error("the setup journal has no armed history scan")]
    ScanNotArmed,
    /// Finalized history did not extend the immutable armed payload.
    #[error("finalized block {height} does not extend the setup's armed history")]
    OriginNotContiguous {
        /// First height whose parent did not match.
        height: u64,
    },
    /// An executable authorization escaped without its recovery descriptor.
    #[error("the setup journal has no armed close descriptor")]
    CloseNotArmed,
    /// The retained executable bundle did not contain a timeout-closeable
    /// bond Open.
    #[error("the setup journal cannot reconstruct the deterministic bond Timeout")]
    TimeoutUnavailable,
}

/// Takes one step of the setup this journal holds.
///
/// One step, not a loop, for [`crate::work_close::advance_close`]'s
/// reason: nothing in this crate has a clock, and a loop written here
/// would spin against a chain that finalizes at its own rate. What the
/// step gives a caller with one is the whole answer —
/// [`SetupProgress`] says whether to call again, the three terminal
/// values are the three ways a setup ends, and
/// [`SetupAdvance::mounted`] is the channel when the step opened one.
///
/// Called on either endpoint. There is no role argument, because
/// `decide` reads the role out of the journal and answers a client with
/// [`SetupDecision::AwaitingCounterparty`] for every step that is the
/// provider's to take — while still answering both parties with
/// [`SetupDecision::Complete`], which is why both journals can record
/// the same origin.
///
/// # Errors
///
/// [`SetupDriveError::Source`] when the finalized read or a block read
/// fails, [`SetupDriveError::Store`] when a record is refused or cannot
/// be made durable, [`SetupDriveError::Busy`] when the journal cannot be
/// reached at all, and the two origin errors when completion cannot be
/// tied to the block that produced it.
pub async fn advance_setup<C, W, B, T, V>(
    view: &W,
    blocks: &B,
    sink: &T,
    channel: &mut C,
    verifier: &V,
) -> Result<SetupAdvance, SetupDriveError>
where
    C: SetupChannel,
    W: SetupView + ?Sized,
    B: FinalizedBlocks + ?Sized,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    // A setup that has already ended is answered from the journal. Not
    // a second copy of `decide`'s first branch — that branch answers
    // the same question and would answer it the same way — but the one
    // shortcut that keeps a finished setup from scanning the chain
    // forever, and the only place the recorded origin is still in hand.
    let completed = match channel.with_store(|store| store.state().end())? {
        Some(SetupEnd::Complete) => true,
        Some(SetupEnd::Aborted(abort)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)));
        }
        Some(SetupEnd::Faulted(fault)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)));
        }
        None => false,
    };

    let Some(query) = channel.with_store(|store| query_of(store.state()))? else {
        // No payment leg has been proposed, so this setup names no
        // payment edge and there is no channel on chain to read for.
        return Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty));
    };

    if completed {
        // A restart reaches a completed setup here and nowhere else, so
        // this is where its channel comes from. The origin is on the
        // disk and no history may be added to an ended setup — but what
        // the payment edge is worth is neither, and it is the one number
        // every close this mount builds has to distribute. So the edge
        // is read, at one coherent state, exactly as the completion that
        // recorded the origin read it; the block scan the shortcut
        // exists to avoid is still avoided.
        let origin = channel
            .with_store(|store| store.state().origin())?
            .ok_or(SetupDriveError::CloseNotArmed)?;
        let Some(finalized) = view.finalized_setup(query).await? else {
            return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
        };
        return channel.try_with_store(|store| {
            Ok(SetupAdvance {
                progress: SetupProgress::Complete(origin),
                mounted: Some(mount(store, verifier, origin, finalized.payment.as_ref())?),
            })
        });
    }

    if let Some((through, tip)) = fetch_history_batch(blocks, channel, verifier).await?
        && through < tip
    {
        return Ok(SetupAdvance::bare(SetupProgress::HistoryAdvanced {
            through,
        }));
    }
    // Once this batch reaches the sampled tip, make the setup decision now.
    // Returning for every new block starves funding on a chain that advances
    // between polls, even after the history reader has caught up.

    // The journal is not held across the finalized read — that is what
    // keeps the ALPN answering while a step waits — so the question can
    // move under its own answer. A revision the ALPN commits during that
    // wait makes the payment Open executable, and `query_of` then names
    // funding coins the answer was never asked about. Coins that were
    // not asked about come back absent, absent is read as spent, and the
    // two decisions that follow from spent payment funding are
    // permanent: `Abort(SetupAbort::PaymentFundingSpent)` and
    // `SetupDecision::TimeoutBond`.
    //
    // So the query is read again under the borrow that decides, and
    // compared with the one the answer was fetched for. A moved question
    // discards its answer — nothing is committed, mounted or submitted
    // from it — and the read is taken again for the query the journal
    // now asks. Bounded, for the reason this is one step and not a loop:
    // nothing here has a clock, and a handshake still arriving is the
    // caller's to come back to.
    const REREADS: usize = 2;
    let (payment_edge, finalized, decision) = 'reread: {
        for _ in 0..REREADS {
            let Some(asked) = channel.with_store(|store| query_of(store.state()))? else {
                return Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty));
            };
            let payment_edge = asked.payment_edge;
            let Some(finalized) = view.finalized_setup(asked.clone()).await? else {
                return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
            };
            // One borrow for the comparison and the step it guards: a
            // query compared in a borrow of its own would be a third
            // state, and the decision would again be made at a state
            // nothing checked.
            let decision = match channel.try_with_store(|store| {
                if query_of(store.state()).as_ref() != Some(&asked) {
                    return Ok(Reread::Moved);
                }
                // After the read, never before it. History proves this
                // channel can no longer be admitted; what it cannot
                // prove is what the surviving payment edge holds, and
                // that is the number every close this mount will build
                // has to distribute. Mounting first would fix the
                // configured expectation as the answer, and the
                // expectation is what admission hoped for rather than
                // what the client funded.
                if store.state().close_only_recovery() {
                    return mount_close_only(store, verifier, finalized.payment.as_ref())
                        .map(|advance| Reread::Mounted(Box::new(advance)));
                }
                Ok(Reread::Decided(store.state().decide(&finalized.observed())))
            })? {
                Reread::Moved => continue,
                Reread::Mounted(advance) => return Ok(*advance),
                Reread::Decided(decision) => decision,
            };
            break 'reread (payment_edge, finalized, decision);
        }
        // Every pass found the question moved. Nothing was decided, and
        // the caller asks again rather than this step deciding from the
        // one answer it has left.
        return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
    };
    match decision {
        SetupDecision::SubmitBond => submit(channel, sink, verifier, SetupStep::Bond).await,
        SetupDecision::SubmitPayment => submit(channel, sink, verifier, SetupStep::Payment).await,
        SetupDecision::Complete => {
            let scan = channel
                .with_store(|store| store.state().scan_armed())?
                .ok_or(SetupDriveError::ScanNotArmed)?;
            let origin = find_origin(blocks, payment_edge, scan).await?;
            channel.try_with_store(|store| {
                store.commit(
                    SetupRecord::Complete {
                        payment_edge: origin.payment_edge,
                        origin_height: origin.height,
                        origin_payload: origin.payload,
                        origin_parent: origin.parent,
                    },
                    verifier,
                )?;
                // The completion is durable before the mount, in the
                // order every other step here is written: the journal
                // records where the channel begins, and only then is a
                // channel opened there. A crash between the two restarts
                // into the shortcut above, which mounts the same channel
                // from the same origin and the same read.
                Ok(SetupAdvance {
                    progress: SetupProgress::Complete(origin),
                    mounted: Some(mount(store, verifier, origin, finalized.payment.as_ref())?),
                })
            })
        }
        SetupDecision::CloseOnly => channel
            .try_with_store(|store| mount_close_only(store, verifier, finalized.payment.as_ref())),
        SetupDecision::Abort(abort) => {
            channel.try_with_store(|store| {
                store.commit(
                    SetupRecord::Ended {
                        outcome: SetupEnd::Aborted(abort),
                    },
                    verifier,
                )?;
                Ok(())
            })?;
            Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)))
        }
        SetupDecision::Fault(fault) => {
            channel.try_with_store(|store| {
                store.commit(
                    SetupRecord::Ended {
                        outcome: SetupEnd::Faulted(fault),
                    },
                    verifier,
                )?;
                Ok(())
            })?;
            Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)))
        }
        SetupDecision::TimeoutBond => {
            let tx = channel.try_with_store(|store| {
                let tx = store
                    .state()
                    .bond_open()
                    .and_then(|open| match open {
                        Tx::Open {
                            funding: _, terms, ..
                        } => Tx::timeout_close(store.state().bond_edge(), &terms),
                        _ => None,
                    })
                    .ok_or(SetupDriveError::TimeoutUnavailable)?;
                store.commit(SetupRecord::BondTimeoutSubmitted, verifier)?;
                Ok(tx)
            })?;
            let outcome = sink.submit(tx).await?;
            Ok(SetupAdvance::bare(SetupProgress::BondTimeoutSubmitted {
                outcome,
            }))
        }
        SetupDecision::AwaitingCounterparty => {
            Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty))
        }
    }
}

/// What the journal said when it was reacquired to decide.
///
/// The three answers of one borrow, because the comparison that decides
/// whether a finalized answer may be used at all and the step that uses
/// it cannot be two borrows.
enum Reread {
    /// The query moved while its own answer was in flight. The answer is
    /// about a funding set this setup no longer asks about, so it is
    /// discarded rather than decided from.
    Moved,
    /// The close-only mount, made under that same borrow. Boxed because
    /// an open channel journal is the outsized answer here and the other
    /// two are a word.
    Mounted(Box<SetupAdvance>),
    /// What `decide` said at the state the answer was fetched for.
    Decided(SetupDecision),
}

async fn fetch_history_batch<C, B, V>(
    blocks: &B,
    channel: &mut C,
    verifier: &V,
) -> Result<Option<(u64, u64)>, SetupDriveError>
where
    C: SetupChannel,
    B: FinalizedBlocks + ?Sized,
    V: SigVerifier,
{
    let scan = channel
        .with_store(|store| store.state().history_cursor())?
        .ok_or(SetupDriveError::ScanNotArmed)?;
    let Some(tip) = blocks.latest_height().await? else {
        return Ok(None);
    };
    if scan.height >= tip {
        return Ok(None);
    }
    let (bond_edge, payment_edge, role) = channel.try_with_store(|store| {
        Ok((
            store.state().bond_edge(),
            store
                .state()
                .payment_edge()
                .ok_or(SetupDriveError::CloseNotArmed)?,
            store.role(),
        ))
    })?;
    let through = tip.min(scan.height.saturating_add(256));
    let mut history = Vec::with_capacity((through - scan.height) as usize);
    // Fetch concurrently, but retain height order for the journal's existing
    // parent-chain checks. The bounded batch is still committed atomically.
    let pending = stream::iter(scan.height.saturating_add(1)..=through)
        .map(|height| history_block(blocks, height))
        .buffered(16);
    futures::pin_mut!(pending);
    while let Some(block) = pending.next().await {
        let block = block?;
        history.push(SetupHistoryBlock {
            height: block.height,
            parent: block.parent,
            payload: block.payload,
            txs: block
                .txs
                .into_iter()
                .filter(|tx| touches_setup(tx, role, bond_edge, payment_edge))
                .collect(),
        });
    }
    channel.try_with_store(|store| {
        store.commit(
            SetupRecord::SetupHistoryBatch(SetupHistoryBatch { blocks: history }),
            verifier,
        )?;
        Ok(())
    })?;
    Ok(Some((through, tip)))
}

async fn history_block<B>(blocks: &B, height: u64) -> Result<FinalizedWork, SetupDriveError>
where
    B: FinalizedBlocks + ?Sized,
{
    blocks
        .block_at(height)
        .await?
        .ok_or(SetupDriveError::OriginUnreadable { height })
}

fn mount_close_only<V: SigVerifier>(
    store: &SetupStore,
    verifier: &V,
    payment: Option<&Edge>,
) -> Result<SetupAdvance, SetupDriveError> {
    let payment_edge = store
        .state()
        .payment_edge()
        .ok_or(SetupDriveError::CloseNotArmed)?;
    let origin = store
        .state()
        .origin()
        .ok_or(SetupDriveError::OriginNotFound {
            floor: store.state().scan_armed().map_or(0, |scan| scan.height),
            tip: store.state().history_cursor().map_or(0, |scan| scan.height),
            edge: payment_edge,
        })?;
    let channel = mount(store, verifier, origin, payment)?;
    let settled = channel.state().close_settled().is_some();
    Ok(SetupAdvance {
        progress: SetupProgress::CloseOnly { origin, settled },
        mounted: Some(channel),
    })
}

/// Opens this setup's channel journal at the origin it recorded, and
/// replays into it the finalized history the setup journal holds.
///
/// The one mount, for every branch that has one to make. What is decided
/// here — the settlement, the origin block's own moves, and the rest of
/// history — is decided once, and the caller receives the result rather
/// than repeating it.
fn mount<V: SigVerifier>(
    store: &SetupStore,
    verifier: &V,
    origin: SetupOrigin,
    payment: Option<&Edge>,
) -> Result<ChannelStore, SetupDriveError> {
    let descriptor = store
        .state()
        .close_descriptor()
        .ok_or(SetupDriveError::CloseNotArmed)?;
    let to_store =
        |error| WorkStoreError::Setup(crate::work_store::SetupStateError::Descriptor(error));
    // A surviving edge settles what it holds. The edge id is a hash over
    // the funding *coins* and the terms, not over their values, so the
    // client that named those coins decides the number and the
    // provider's configured expectation is only ever what it hoped for:
    // an edge funded above or below it is this same channel, and a close
    // built on the expectation would name a total the edge does not
    // distribute. The expectation is the fallback for a consumed edge
    // alone, where there is no longer anything coherent to read it from.
    let settlement = match payment {
        None => descriptor.expected_settlement().map_err(to_store)?,
        Some(payment) => descriptor.funded_settlement(payment).map_err(to_store)?,
    };
    let mut channel = if store.role() == crate::work_store::Role::Provider
        && matches!(
            descriptor.execution_policy(),
            hellas_rpc::protocol::work_profile::PaidWorkPolicy::Fetch { .. }
        ) {
        ChannelStore::open_metadata_only(
            store.root(),
            descriptor.channel().clone(),
            settlement,
            origin,
            verifier,
        )?
    } else {
        ChannelStore::open(
            store.root(),
            descriptor.channel().clone(),
            settlement,
            store.role(),
            origin,
            verifier,
        )?
    };
    // The origin block carries the payment Open that established this
    // channel, and the store opened with its cursor already on that block.
    // A `StartPaymentClose` ordered after the Open in the very same block
    // is a contest a client can raise the instant it opens, and `observe`
    // would never see it: that block is not the cursor's next one, it is
    // the cursor's own. So its post-Open moves are replayed directly —
    // the Open matches no arm and is skipped, and any same-block contest
    // is journaled exactly as a later one would be.
    for block in store.state().history() {
        if block.height == origin.height {
            apply_finalized_txs(
                &mut channel,
                block.height,
                block.payload,
                &block.txs,
                verifier,
            )?;
        }
    }
    for block in store.state().history() {
        if block.height <= origin.height || block.height <= channel.state().cursor().0 {
            continue;
        }
        observe(
            &mut channel,
            &FinalizedWork {
                height: block.height,
                parent: block.parent,
                payload: block.payload,
                txs: block.txs.clone(),
            },
            verifier,
        )?;
    }
    Ok(channel)
}

/// Returns what to read for this setup, once it names a payment edge.
///
/// The coins come from [`SetupState::funding_coins`], which derives them
/// from the retained transactions. A caller cannot ask about a coin set
/// the signed bytes do not name, and the preflight cannot be run against
/// a convenient one.
fn query_of(state: &SetupState) -> Option<SetupQuery> {
    Some(SetupQuery {
        bond_edge: state.bond_edge(),
        payment_edge: state.payment_edge()?,
        funding: state.funding_coins(),
    })
}

/// Journals one submission marker and then broadcasts the retained
/// Open.
///
/// The commit is first and the `?` on it is what makes that binding: a
/// journal that will not take the marker is a journal this endpoint
/// does not broadcast from.
async fn submit<C, T, V>(
    channel: &mut C,
    sink: &T,
    verifier: &V,
    step: SetupStep,
) -> Result<SetupAdvance, SetupDriveError>
where
    C: SetupChannel,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    let record = match step {
        SetupStep::Bond => SetupRecord::BondSubmitted,
        SetupStep::Payment => SetupRecord::PaymentSubmitted,
    };
    let tx = channel.try_with_store(|store| {
        let state = store.commit(record, verifier)?;
        match step {
            SetupStep::Bond => state.bond_open(),
            SetupStep::Payment => state.payment_open(),
        }
        .ok_or(SetupDriveError::NothingRetained { step })
    })?;
    let outcome = sink.submit(tx).await?;
    Ok(SetupAdvance::bare(SetupProgress::Submitted {
        step,
        outcome,
    }))
}

/// Finds the finalized block whose accepted transactions opened
/// `payment_edge`.
///
/// The match is on the edge id the kernel derives from an Open's own
/// funding and terms, not on the retained bytes: the edge is what the
/// snapshot established is live, and it is what the journal's completion
/// record is keyed to.
async fn find_origin<B>(
    blocks: &B,
    payment_edge: EdgeId,
    scan: SetupScan,
) -> Result<SetupOrigin, SetupDriveError>
where
    B: FinalizedBlocks + ?Sized,
{
    let tip = blocks.latest_height().await?.unwrap_or(0);
    let floor = scan.height;
    let mut expected_parent = scan.payload;
    let pending = stream::iter(floor.saturating_add(1)..=tip)
        .map(|height| history_block(blocks, height))
        .buffered(16);
    futures::pin_mut!(pending);
    while let Some(block) = pending.next().await {
        let block = block?;
        let height = block.height;
        if block.parent != expected_parent {
            return Err(SetupDriveError::OriginNotContiguous { height });
        }
        if block.txs.iter().any(|tx| opens(tx, payment_edge)) {
            return Ok(SetupOrigin {
                payment_edge,
                height: block.height,
                payload: block.payload,
                parent: block.parent,
            });
        }
        expected_parent = block.payload;
    }
    Err(SetupDriveError::OriginNotFound {
        floor,
        tip,
        edge: payment_edge,
    })
}

/// Returns whether this transaction is the Open that produces `edge`.
fn opens(tx: &Tx, edge: EdgeId) -> bool {
    match tx {
        Tx::Open { funding, terms, .. } => Tx::edge_id_of(funding, terms) == edge,
        _ => false,
    }
}
