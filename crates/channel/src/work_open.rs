//! Posting the two Opens: the driver that turns a completed handshake
//! into a channel on chain.
//!
//! Signed revisions and submission markers are durable before export or
//! broadcast. Each step decides from one certified read of the setup's
//! objects, taken by the caller; the setup journal keeps only what those
//! reads taught it and the handshake's outcomes. The channel begins at
//! the first read that shows its payment edge live and leased.

use std::collections::BTreeSet;

use hellas_kernel::{CoinId, Edge, EdgeId, LeaseSlots, PendingSlot, SigVerifier, Terms, Tx};

use crate::model::setup::ObservedChannel;
use crate::work_close::{BlockSourceError, TxSink, observe};
use crate::work_store::{
    ChannelStore, ObservedSetup, SetupAbort, SetupDecision, SetupEnd, SetupFault, SetupOrigin,
    SetupRecord, SetupState, SetupStore, WorkStoreError,
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

/// One coherent certified read a setup decision is made from.
///
/// Owned, where [`ObservedSetup`] borrows, because this is what crosses
/// from whatever holds the chain. It carries the question it answers,
/// so a step can refuse an answer to a question its journal no longer
/// asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedSetup {
    /// What this read was asked.
    pub query: SetupQuery,
    /// Certified height every field below was read at.
    pub height: u64,
    /// That block's payload digest.
    pub payload: [u8; 32],
    /// That block's timestamp, in milliseconds.
    pub certified_at_ms: u64,
    /// The bond edge, or its absence.
    pub bond: Option<Edge>,
    /// The payment edge, or its absence.
    pub payment: Option<Edge>,
    /// What the bond's lease slots held.
    pub lease: LeaseSlots,
    /// What the payment edge's pending-close slot held.
    pub pending: PendingSlot,
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

    /// Returns this read as the channel journal's first observation.
    #[must_use]
    pub fn observed_channel(&self) -> ObservedChannel<'_> {
        ObservedChannel {
            height: self.height,
            payload: self.payload,
            certified_at_ms: self.certified_at_ms,
            bond: self.bond.as_ref(),
            payment: self.payment.as_ref(),
            lease: self.lease,
            pending: self.pending,
        }
    }
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
    /// Both edges and this channel's lease are live, the journal records
    /// where this endpoint first saw them, and the channel is mounted at
    /// that origin in [`SetupAdvance::mounted`].
    Complete(SetupOrigin),
    /// The payment edge is live but its bond is gone, so the channel
    /// admits nothing and is mounted only to be closed.
    CloseOnly {
        /// Where this endpoint first saw the payment edge.
        origin: SetupOrigin,
        /// Whether the mount's first read already shows the edge closed.
        settled: bool,
    },
    /// A retained Open was journaled and handed to consensus. It is not
    /// included until a read shows it.
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
    /// The read answers a question this journal no longer asks, and
    /// nothing was decided from it.
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
    /// one.
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
/// acquires its endpoint lock. Release the borrow before waiting on a
/// transaction sink. Only journal I/O may await under it.
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
    /// The transaction sink failed.
    #[error(transparent)]
    Source(#[from] BlockSourceError),
    /// A step could not be made durable, or the journal refused it.
    #[error(transparent)]
    Store(#[from] WorkStoreError),
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
    /// An executable authorization escaped without its recovery descriptor.
    #[error("the setup journal has no armed close descriptor")]
    CloseNotArmed,
    /// The retained executable bundle did not contain a timeout-closeable
    /// bond Open.
    #[error("the setup journal cannot reconstruct the deterministic bond Timeout")]
    TimeoutUnavailable,
}

/// Returns what to read for this setup, once it names a payment edge.
///
/// The coins come from [`SetupState::funding_coins`], which derives them
/// from the retained transactions. A caller cannot ask about a coin set
/// the signed bytes do not name, and the preflight cannot be run against
/// a convenient one.
#[must_use]
pub fn setup_query(state: &SetupState) -> Option<SetupQuery> {
    state.bundle()?;
    Some(SetupQuery {
        bond_edge: state.bond_edge(),
        payment_edge: state.payment_edge(),
        funding: state.funding_coins(),
    })
}

/// Takes one step of the setup this journal holds, decided from `read`.
///
/// One step, not a loop: nothing in this crate has a clock, and the
/// caller that does reads the chain again and comes back.
/// [`SetupProgress`] says whether to, the terminal values are the ways a
/// setup ends, and [`SetupAdvance::mounted`] is the channel when the step
/// opened one.
///
/// Called on either endpoint. There is no role argument, because
/// `decide` reads the role out of the journal and answers a client with
/// [`SetupDecision::AwaitingCounterparty`] for every step that is the
/// provider's to take.
///
/// # Errors
///
/// [`SetupDriveError::Source`] when the sink fails,
/// [`SetupDriveError::Store`] when a record is refused or cannot be made
/// durable, and [`SetupDriveError::Busy`] when the journal cannot be
/// reached at all.
pub fn advance_setup<'a, C, T, V>(
    read: &'a FinalizedSetup,
    sink: &'a T,
    channel: &'a mut C,
    verifier: &'a V,
) -> impl std::future::Future<Output = Result<SetupAdvance, SetupDriveError>> + 'a
where
    C: SetupChannel,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    // Construct the driver outside its caller's poll frame. Its bounded
    // kernel witnesses and journal futures are too large to compose inline.
    Box::pin(advance_setup_inner(read, sink, channel, verifier))
}

async fn advance_setup_inner<C, T, V>(
    read: &FinalizedSetup,
    sink: &T,
    channel: &mut C,
    verifier: &V,
) -> Result<SetupAdvance, SetupDriveError>
where
    C: SetupChannel,
    T: TxSink + ?Sized,
    V: SigVerifier,
{
    // Compare, decide and commit under one borrow. Reacquiring after
    // deciding could commit against a revision this read never observed:
    // a revision the handshake commits while the read was in flight makes
    // the payment Open executable, and its funding coins would read as
    // absent — as spent — in an answer that never asked about them.
    let mut store = channel.store().await?;
    match store.state().end() {
        Some(SetupEnd::Aborted(abort)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)));
        }
        Some(SetupEnd::Faulted(fault)) => {
            return Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)));
        }
        Some(SetupEnd::Complete) | None => {}
    }
    let Some(query) = setup_query(store.state()) else {
        // No payment leg has been proposed, so this setup names no
        // payment edge and there is no channel on chain to read for.
        return Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty));
    };
    // A read older than one already recorded is a state already passed:
    // absence there says nothing about the chain now.
    if query != read.query
        || store
            .state()
            .observed_height()
            .is_some_and(|height| read.height < height)
    {
        return Ok(SetupAdvance::bare(SetupProgress::AwaitingFinalizedState));
    }
    if let Some(origin) = store.state().origin() {
        // A restart reaches a completed setup here. The origin is on the
        // disk; what the payment edge is worth is read now, because it is
        // the one number every close this mount builds has to distribute.
        let channel = mount(&store, verifier, origin, read).await?;
        return Ok(SetupAdvance {
            progress: SetupProgress::Complete(origin),
            mounted: Some(channel),
        });
    }
    let observed = read.observed();
    if let Some(observation) = store.state().observe(&observed) {
        store
            .commit(SetupRecord::Observed(observation), verifier)
            .await?;
    }
    let decision = store.state().decide(&observed);
    match decision {
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
            Ok(SetupAdvance::bare(SetupProgress::Submitted {
                step,
                outcome,
            }))
        }
        SetupDecision::Complete | SetupDecision::CloseOnly => {
            let payment_edge = store
                .state()
                .payment_edge()
                .ok_or(SetupDriveError::CloseNotArmed)?;
            let origin = SetupOrigin {
                payment_edge,
                height: read.height,
                payload: read.payload,
            };
            // Record the origin before opening the channel. A crash between
            // these steps restarts through the completed-setup branch.
            store
                .commit(
                    SetupRecord::Complete {
                        payment_edge,
                        origin_height: origin.height,
                        origin_payload: origin.payload,
                    },
                    verifier,
                )
                .await?;
            let channel = mount(&store, verifier, origin, read).await?;
            let progress = if matches!(decision, SetupDecision::Complete) {
                SetupProgress::Complete(origin)
            } else {
                SetupProgress::CloseOnly {
                    origin,
                    settled: channel.state().close_settled().is_some(),
                }
            };
            Ok(SetupAdvance {
                progress,
                mounted: Some(channel),
            })
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
            Ok(SetupAdvance::bare(SetupProgress::Aborted(abort)))
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
            Ok(SetupAdvance::bare(SetupProgress::Faulted(fault)))
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
            Ok(SetupAdvance::bare(SetupProgress::BondTimeoutSubmitted {
                outcome,
            }))
        }
        SetupDecision::AwaitingCounterparty => {
            Ok(SetupAdvance::bare(SetupProgress::AwaitingCounterparty))
        }
    }
}

/// Opens the exclusive channel journal while the setup journal is
/// borrowed, and applies `read` to it as the channel's first
/// observation.
///
/// A contest started in the Open's own block, or before this endpoint
/// first looked, is in that read's pending-close slot, so it is seen
/// here rather than missed. Construct the large future behind a heap
/// boundary, so setup steps do not carry journal-opening temporaries on
/// their poll stack.
fn mount<'a, V: SigVerifier>(
    store: &'a SetupStore,
    verifier: &'a V,
    origin: SetupOrigin,
    read: &'a FinalizedSetup,
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
        // provider's configured expectation is only ever what it hoped for.
        // The expectation is the fallback for a consumed edge alone, where
        // there is no longer anything coherent to read it from.
        let settlement = match read.payment.as_ref() {
            None => descriptor.expected_settlement().map_err(to_store)?,
            Some(payment) => descriptor.funded_settlement(payment).map_err(to_store)?,
        };
        let mut channel = ChannelStore::open(
            store.root(),
            descriptor.channel().clone(),
            settlement,
            store.role(),
            origin,
            store.content_store()?,
            verifier,
        )
        .await?;
        observe(&mut channel, &read.observed_channel(), verifier).await?;
        Ok(channel)
    })
}
