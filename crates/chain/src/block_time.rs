//! Waiting for a block from the future instead of rejecting it.

use crate::{HellasBlock, domain::Context};
use commonware_consensus::{
    Application, CertifiableBlock as _, marshal::ancestry::Ancestry, types::View,
};
use commonware_runtime::{Clock, Metrics, Spawner};
use hellas_kernel::MAX_BLOCK_TIME_LEAD_MS;
use rand_core::Rng;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::watch;

/// Holds each verify until this validator's clock is within
/// [`MAX_BLOCK_TIME_LEAD_MS`] of the block's timestamp, then asks `inner`.
///
/// Simplex needs every honest validator to reach the same certify verdict.
/// One read off the local clock would differ between validators whose
/// clocks differ, and a split verdict can halt the chain. Consensus runs
/// each verify in its own task, so the wait holds back only that block.
///
/// Consensus never cancels that task, so the wait also ends once the
/// block's view is finalized: nothing reads the verdict after that, and a
/// block stamped far ahead would otherwise park its task for good.
#[derive(Clone)]
pub(crate) struct AwaitBlockTime<A> {
    pub(crate) inner: A,
    /// The highest finalized view.
    pub(crate) finalized: watch::Receiver<View>,
}

impl<E, A> Application<E> for AwaitBlockTime<A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E, Block = HellasBlock, Context = Context>,
{
    type SigningScheme = A::SigningScheme;
    type Context = Context;
    type Block = HellasBlock;

    fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<HellasBlock>,
    ) -> impl Future<Output = Option<HellasBlock>> + Send {
        self.inner.propose(context, ancestry)
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<HellasBlock>,
    ) -> bool {
        if let Some(block) = ancestry.peek() {
            let view = block.context().round.view();
            let due = block.timestamp().saturating_sub(MAX_BLOCK_TIME_LEAD_MS);
            let due = UNIX_EPOCH.checked_add(Duration::from_millis(due));
            let mut finalized = self.finalized.clone();
            tokio::select! {
                () = async {
                    match due {
                        Some(due) => context.0.sleep_until(due).await,
                        // Past what this platform's clock can name: never due.
                        None => std::future::pending().await,
                    }
                } => {}
                Ok(_) = finalized.wait_for(|finalized| *finalized >= view) => return false,
            }
        }
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Scheme, TEST_NETWORK};
    use crate::execution::{
        store::UtxoDatabase, store::utxo_db_config, test_support::validator_key,
    };
    use crate::{ApplicationConfig, Mempool};
    use commonware_consensus::{
        Block as _, Heightable as _,
        marshal::ancestry::from_iter,
        types::{Epoch, Round},
    };
    use commonware_cryptography::{Digestible as _, Signer as _, sha256::Digest};
    use commonware_glue::stateful::{Application as _, db::DatabaseSet};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::SystemTimeExt as _;
    use futures::{lock::Mutex, stream};
    use std::sync::Arc;

    /// How far the proposer's clock runs ahead of the lagging validator's.
    const SKEW_MS: u64 = 3 * MAX_BLOCK_TIME_LEAD_MS;

    /// The lagging validator's execution: verifies a block on its own
    /// database and finalizes what it verifies, as the stateful actor and
    /// marshal do behind consensus.
    #[derive(Clone)]
    struct Validator {
        app: Arc<Mutex<crate::Application>>,
        database: Arc<UtxoDatabase<deterministic::Context>>,
    }

    impl Application<deterministic::Context> for Validator {
        type SigningScheme = Scheme;
        type Context = Context;
        type Block = HellasBlock;

        async fn propose(
            &mut self,
            _: (deterministic::Context, Self::Context),
            _: impl Ancestry<HellasBlock>,
        ) -> Option<HellasBlock> {
            None
        }

        async fn verify(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<HellasBlock>,
        ) -> bool {
            // Boxed: the application's futures nest too deep for the test's.
            Box::pin(async move {
                let block = ancestry.peek().cloned().expect("verified block");
                let finalized = (context.0.child("finalized"), context.1.clone());
                let mut app = self.app.lock().await;
                let batches = self.database.new_batches().await;
                let Some(merkleized) = app.verify(context, ancestry, batches).await else {
                    return false;
                };
                self.database.finalize(merkleized).await;
                app.finalized(finalized, &block, &self.database).await;
                true
            })
            .await
        }
    }

    impl Validator {
        /// Builds this validator's block on `parent`, stamped by its clock.
        async fn build(
            &self,
            context: deterministic::Context,
            parent: &HellasBlock,
        ) -> HellasBlock {
            Box::pin(async {
                self.app
                    .lock()
                    .await
                    .propose(
                        (context, child_context(parent)),
                        stream::iter([Arc::new(parent.clone())]),
                        self.database.new_batches().await,
                        &mut Some(Mempool::default()),
                    )
                    .await
                    .expect("proposal")
                    .block
            })
            .await
        }
    }

    fn child_context(parent: &HellasBlock) -> Context {
        Context {
            round: Round::new(Epoch::zero(), View::new(parent.height().get() + 1)),
            leader: validator_key(0).public_key(),
            parent: (parent.context().round.view(), parent.digest()),
        }
    }

    /// A validator at genesis, and its consensus view of the application.
    async fn start(
        context: &deterministic::Context,
    ) -> (
        Validator,
        HellasBlock,
        AwaitBlockTime<Validator>,
        watch::Sender<View>,
    ) {
        let app = Box::pin(crate::Application::new(
            context.child("app"),
            TEST_NETWORK,
            Digest::from([0; 32]),
            validator_key(0).public_key(),
            Vec::new(),
            "lagging",
            ApplicationConfig::default(),
        ))
        .await;
        let genesis = app.genesis_block();
        let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(
            context.child("database"),
            utxo_db_config(context, "lagging_db", 1024, 8),
        )
        .await;
        let validator = Validator {
            app: Arc::new(Mutex::new(app)),
            database: Arc::new(database),
        };
        let (finalized_tx, finalized) = watch::channel(View::zero());
        let consensus = AwaitBlockTime {
            inner: validator.clone(),
            finalized,
        };
        (validator, genesis, consensus, finalized_tx)
    }

    /// `block` as its proposer would have stamped it at `timestamp`.
    fn stamped(block: &HellasBlock, timestamp: u64) -> HellasBlock {
        HellasBlock::new(
            block.context(),
            block.parent(),
            block.height(),
            timestamp,
            block.state_root(),
            block.sync_target(),
            block.txs().to_vec(),
        )
        .with_owner_root(block.owner_root())
    }

    #[test]
    fn lagging_validator_verifies_a_future_block_once_due_and_builds_on_it() {
        deterministic::Runner::default().start(|context| async move {
            let (validator, genesis, mut consensus, _finalized) = start(&context).await;

            // The proposer builds block 1; its clock reads SKEW_MS ahead.
            let proposed = validator.build(context.child("propose"), &genesis).await;
            let start = context.current().epoch_millis();
            let ahead = stamped(&proposed, start + SKEW_MS);

            // Verified once due, not rejected.
            assert!(
                consensus
                    .verify(
                        (context.child("verify_ahead"), ahead.context()),
                        from_iter([Arc::new(ahead.clone()), Arc::new(genesis)]),
                    )
                    .await,
                "a block from the future is waited for, not rejected"
            );
            assert_eq!(
                context.current().epoch_millis(),
                start + SKEW_MS - MAX_BLOCK_TIME_LEAD_MS,
                "verified as soon as it came within the bound"
            );

            // The chain goes on: the lagging validator builds on it, and its
            // block, stamped no earlier than its parent, verifies at once.
            let next = validator.build(context.child("propose_next"), &ahead).await;
            assert_eq!(next.timestamp(), ahead.timestamp());
            let before = context.current();
            assert!(
                consensus
                    .verify(
                        (context.child("verify_next"), next.context()),
                        from_iter([Arc::new(next.clone()), Arc::new(ahead)]),
                    )
                    .await
            );
            assert_eq!(context.current(), before, "no further wait");
            assert_eq!(
                validator.database.read().await.root(),
                next.state_root(),
                "both blocks executed"
            );
        });
    }

    #[test]
    fn a_block_that_never_comes_due_stops_waiting_once_its_view_is_finalized() {
        deterministic::Runner::default().start(|context| async move {
            let (validator, genesis, mut consensus, finalized) = start(&context).await;
            let proposed = validator.build(context.child("propose"), &genesis).await;
            let never = stamped(&proposed, u64::MAX);
            let view = never.context().round.view();

            let mut verify = Box::pin(consensus.verify(
                (context.child("verify_never"), never.context()),
                from_iter([Arc::new(never), Arc::new(genesis)]),
            ));
            let mut pending_for = async |duration| {
                let elapsed = Box::pin(context.sleep(duration));
                matches!(
                    futures::future::select(&mut verify, elapsed).await,
                    futures::future::Either::Right(_)
                )
            };
            assert!(
                pending_for(Duration::from_secs(3600)).await,
                "a block that never comes due is waited for, not rejected"
            );

            // Finalizing an earlier view does not end the wait; its own does.
            finalized.send_modify(|highest| *highest = view.previous().unwrap());
            assert!(pending_for(Duration::from_secs(1)).await);
            finalized.send_modify(|highest| *highest = view);
            assert!(!verify.await, "the verdict after finalization is unread");
        });
    }
}
