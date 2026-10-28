//! Posting the two Opens: the driver that turns a completed handshake
//! into a channel on chain.
//!
//! Signed revisions and submission markers are durable before export or
//! broadcast. Finalized blocks come from the process's local chain node;
//! setup journals retain only their cursor and handshake outcomes. Mounting
//! replays the channel's close effects from that same local block interface.

use std::collections::BTreeSet;

use futures::{StreamExt as _, stream};
use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, SigVerifier, Terms, Tx};

use crate::work_close::{
    BlockSourceError, FinalizedBlocks, FinalizedWork, TxSink, apply_finalized_txs, observe,
};
use crate::work_store::{
    ChannelRecord, ChannelStore, ObservedSetup, SetupAbort, SetupDecision, SetupEnd, SetupFault,
    SetupOrigin, SetupRecord, SetupState, SetupStore, WorkStoreError,
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
    pub payment_edge: Option<EdgeId>,
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
/// A caller that owns its store lends it directly; a service asynchronously
/// acquires its endpoint lock. Release the borrow before waiting on a finalized
/// view, blocks or a transaction sink. Only journal I/O may await under it.
pub trait SetupChannel {
    /// Borrows this setup's journal until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// [`SetupDriveError::Busy`] when the journal cannot be reached at
    /// all, which is the only thing an implementation may decide here.
    fn store(
        &mut self,
    ) -> impl core::future::Future<
        Output = Result<impl core::ops::DerefMut<Target = SetupStore> + Send, SetupDriveError>,
    > + Send;
}

impl SetupChannel for SetupStore {
    async fn store(
        &mut self,
    ) -> Result<impl core::ops::DerefMut<Target = Self> + Send, SetupDriveError> {
        Ok(self)
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
pub fn advance_setup<'a, C, W, B, T, V>(
    view: &'a W,
    blocks: &'a B,
    sink: &'a T,
    channel: &'a mut C,
    verifier: &'a V,
) -> impl std::future::Future<Output = Result<SetupAdvance, SetupDriveError>> + 'a
where
    C: SetupChannel,
    W: SetupView + ?Sized,
    B: FinalizedBlocks + ?Sized,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    // Construct the driver outside its caller's poll frame. Its bounded
    // kernel witnesses and journal futures are too large to compose inline.
    Box::pin(advance_setup_inner(view, blocks, sink, channel, verifier))
}

async fn advance_setup_inner<C, W, B, T, V>(
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
    let completed = match channel.store().await?.state().end() {
        Some(SetupEnd::Complete) => true,
        Some(SetupEnd::Aborted(abort)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)));
        }
        Some(SetupEnd::Faulted(fault)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)));
        }
        None => false,
    };

    let Some(query) = query_of(channel.store().await?.state()) else {
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
            .store()
            .await?
            .state()
            .origin()
            .ok_or(SetupDriveError::CloseNotArmed)?;
        let Some(finalized) = view.finalized_setup(query).await? else {
            return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
        };
        let advance = {
            let store = channel.store().await?;
            SetupAdvance {
                progress: SetupProgress::Complete(origin),
                mounted: Some(mount(&store, verifier, origin, finalized.payment.as_ref()).await?),
            }
        };
        return finish_mount(blocks, channel, advance, verifier).await;
    }

    if let Some((through, tip)) = scan_finalized(blocks, channel, verifier).await?
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
    for _ in 0..REREADS {
        let Some(asked) = query_of(channel.store().await?.state()) else {
            return Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty));
        };
        let Some(finalized) = view.finalized_setup(asked.clone()).await? else {
            return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
        };
        // Compare, decide and commit under one borrow. Reacquiring after
        // deciding could commit against a revision this read never observed.
        let mut store = channel.store().await?;
        if query_of(store.state()).as_ref() != Some(&asked) {
            continue;
        }
        // History proves whether this channel can still admit work, but
        // settlement must use the surviving payment edge's current value.
        if store.state().close_only_recovery() {
            let advance = mount_close_only(&store, verifier, finalized.payment.as_ref()).await?;
            drop(store);
            return finish_mount(blocks, channel, advance, verifier).await;
        }
        let decision = store.state().decide(&finalized.observed());
        // A newer snapshot can show spent funding before the scan has
        // recorded the Open or Close that explains it. Terminal decisions
        // require that evidence; submissions can proceed as new blocks arrive.
        if matches!(decision, SetupDecision::Abort(_) | SetupDecision::Fault(_))
            && store
                .state()
                .scan_cursor()
                .is_none_or(|scan| scan.height < finalized.height)
        {
            return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
        }
        let advance = match decision {
            SetupDecision::SubmitBond | SetupDecision::SubmitPayment => {
                let (step, record) = match decision {
                    SetupDecision::SubmitBond => (SetupStep::Bond, SetupRecord::BondSubmitted),
                    _ => (SetupStep::Payment, SetupRecord::PaymentSubmitted),
                };
                // Persist the submission marker before handing the Open to consensus.
                let state = store.commit(record, verifier).await?;
                let tx = match step {
                    SetupStep::Bond => state.bond_open(),
                    SetupStep::Payment => state.payment_open(),
                }
                .ok_or(SetupDriveError::NothingRetained { step })?;
                drop(store);
                let outcome = sink.submit(tx).await?;
                return Ok(SetupAdvance::bare(SetupProgress::Submitted {
                    step,
                    outcome,
                }));
            }
            SetupDecision::Complete => {
                let Some(origin) = store.state().origin() else {
                    // Observe the Open on the next scan before recording completion.
                    return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
                };
                store
                    .commit(
                        SetupRecord::Complete {
                            payment_edge: origin.payment_edge,
                            origin_height: origin.height,
                            origin_payload: origin.payload,
                            origin_parent: origin.parent,
                        },
                        verifier,
                    )
                    .await?;
                // Record the origin before opening the channel. A crash between
                // these steps restarts through the completed-setup shortcut.
                SetupAdvance {
                    progress: SetupProgress::Complete(origin),
                    mounted: Some(
                        mount(&store, verifier, origin, finalized.payment.as_ref()).await?,
                    ),
                }
            }
            SetupDecision::CloseOnly => {
                mount_close_only(&store, verifier, finalized.payment.as_ref()).await?
            }
            SetupDecision::Abort(abort) => {
                store
                    .commit(
                        SetupRecord::Ended {
                            outcome: SetupEnd::Aborted(abort),
                        },
                        verifier,
                    )
                    .await?;
                return Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)));
            }
            SetupDecision::Fault(fault) => {
                store
                    .commit(
                        SetupRecord::Ended {
                            outcome: SetupEnd::Faulted(fault),
                        },
                        verifier,
                    )
                    .await?;
                return Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)));
            }
            SetupDecision::TimeoutBond => {
                let tx = store
                    .state()
                    .bundle()
                    .and_then(|bundle| {
                        Tx::timeout_close(
                            store.state().bond_edge(),
                            &Terms::work_stake_bond(bundle.bond_terms().clone()),
                        )
                    })
                    .ok_or(SetupDriveError::TimeoutUnavailable)?;
                store
                    .commit(SetupRecord::BondTimeoutSubmitted, verifier)
                    .await?;
                drop(store);
                let outcome = sink.submit(tx).await?;
                return Ok(SetupAdvance::bare(SetupProgress::BondTimeoutSubmitted {
                    outcome,
                }));
            }
            SetupDecision::AwaitingCounterparty => {
                return Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty));
            }
        };
        drop(store);
        return finish_mount(blocks, channel, advance, verifier).await;
    }
    // Every read found a moved query. Let the next step retry with fresh state.
    Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState))
}

async fn scan_finalized<C, B, V>(
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
        .store()
        .await?
        .state()
        .scan_cursor()
        .ok_or(SetupDriveError::ScanNotArmed)?;
    let Some(tip) = blocks.latest_height().await? else {
        return Ok(None);
    };
    if scan.height >= tip {
        return Ok(None);
    }
    let through = tip.min(scan.height.saturating_add(256));
    let mut history = Vec::with_capacity((through - scan.height) as usize);
    // Fetch concurrently, but retain height order for the journal's existing
    // parent-chain checks. The bounded batch is still committed atomically.
    let pending = stream::iter(scan.height.saturating_add(1)..=through)
        .map(|height| history_block(blocks, height))
        .buffered(16);
    futures::pin_mut!(pending);
    while let Some(block) = pending.next().await {
        history.push(block?);
    }
    {
        let mut store = channel.store().await?;
        let observed = store
            .state()
            .observe(&history)
            .map_err(WorkStoreError::from)?;
        store
            .commit(SetupRecord::Observed(observed), verifier)
            .await?;
    }
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

async fn mount_close_only<V: SigVerifier>(
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
            tip: store.state().scan_cursor().map_or(0, |scan| scan.height),
            edge: payment_edge,
        })?;
    let channel = mount(store, verifier, origin, payment).await?;
    let settled = channel.state().close_settled().is_some();
    Ok(SetupAdvance {
        progress: SetupProgress::CloseOnly { origin, settled },
        mounted: Some(channel),
    })
}

/// Opens the exclusive channel journal while the setup journal is borrowed.
/// Construct its large replay future behind a heap boundary, so setup steps
/// that submit transactions do not carry journal-opening temporaries on their
/// poll stack while connecting to the chain.
fn mount<'a, V: SigVerifier>(
    store: &'a SetupStore,
    verifier: &'a V,
    origin: SetupOrigin,
    payment: Option<&'a Edge>,
) -> impl std::future::Future<Output = Result<ChannelStore, SetupDriveError>> + 'a {
    Box::pin(async move {
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
        let channel = ChannelStore::open(
            store.root(),
            descriptor.channel().clone(),
            settlement,
            store.role(),
            origin,
            store.content_store(),
            verifier,
        )
        .await?;
        Ok(channel)
    })
}

/// Replays outside the setup borrow. The origin marker is written after its
/// effects; a crash replays those idempotent effects before advancing again.
async fn finish_mount<C, B, V>(
    blocks: &B,
    setup: &mut C,
    mut advance: SetupAdvance,
    verifier: &V,
) -> Result<SetupAdvance, SetupDriveError>
where
    C: SetupChannel,
    B: FinalizedBlocks + ?Sized,
    V: SigVerifier,
{
    let (origin, through) = {
        let store = setup.store().await?;
        (
            store
                .state()
                .origin()
                .ok_or(SetupDriveError::CloseNotArmed)?,
            store
                .state()
                .scan_cursor()
                .ok_or(SetupDriveError::ScanNotArmed)?
                .height,
        )
    };
    let channel = advance
        .mounted
        .as_mut()
        .ok_or(SetupDriveError::CloseNotArmed)?;
    if !channel.state().origin_observed() {
        let block = history_block(blocks, origin.height).await?;
        if block.payload != origin.payload
            || block.parent != origin.parent
            || !block.txs.iter().any(|tx| opens(tx, origin.payment_edge))
        {
            return Err(SetupDriveError::OriginNotContiguous {
                height: origin.height,
            });
        }
        apply_finalized_txs(channel, block.height, block.payload, &block.txs, verifier).await?;
        channel
            .commit(ChannelRecord::OriginObserved, verifier)
            .await?;
    }
    for height in channel.state().cursor().0.saturating_add(1)..=through {
        let block = history_block(blocks, height).await?;
        observe(channel, &block, verifier).await?;
    }
    if let SetupProgress::CloseOnly { settled, .. } = &mut advance.progress {
        *settled = channel.state().close_settled().is_some();
    }
    Ok(advance)
}

/// Returns what to read for this setup, once it names a payment edge.
///
/// The coins come from [`SetupState::funding_coins`], which derives them
/// from the retained transactions. A caller cannot ask about a coin set
/// the signed bytes do not name, and the preflight cannot be run against
/// a convenient one.
fn query_of(state: &SetupState) -> Option<SetupQuery> {
    state.bundle()?;
    Some(SetupQuery {
        bond_edge: state.bond_edge(),
        payment_edge: state.payment_edge(),
        funding: state.funding_coins(),
    })
}

/// Returns whether this transaction is the Open that produces `edge`.
fn opens(tx: &Tx, edge: EdgeId) -> bool {
    match tx {
        Tx::Open { funding, terms, .. } => Tx::edge_id_of(funding, terms) == edge,
        _ => false,
    }
}
