pub use crate::block::HellasBlock;

#[cfg(feature = "validator")]
use crate::domain::Transaction;
use crate::domain::{Activity, PublicKey, Scheme, SettlementKey};
#[cfg(feature = "validator")]
use crate::domain::{KERNEL_FEES, MAX_BLOCK_TX_BYTES, MAX_TXS_PER_BLOCK};
use crate::execution::store::empty_state;
#[cfg(feature = "validator")]
use crate::execution::store::{UtxoDatabase, UtxoSyncTarget};
#[cfg(feature = "validator")]
use crate::execution::{ChainVerifier, execute_all, execute_proposal};
use crate::light_client::{ConsensusActivity, ProposalInfo};
use crate::owner_index::OwnerIndex;
use commonware_actor::Feedback;
use commonware_codec::Encode;
#[cfg(feature = "validator")]
use commonware_codec::EncodeSize;
#[cfg(feature = "validator")]
use commonware_consensus::simplex::types::Context;
#[cfg(feature = "validator")]
use commonware_consensus::{Block as _, CertifiableBlock, Heightable, types::Height};
use commonware_consensus::{
    Reporter,
    simplex::types::{Activity as SimplexActivity, Proposal},
};
#[cfg(feature = "validator")]
use commonware_cryptography::Digestible;
#[cfg(feature = "validator")]
use commonware_cryptography::Hasher;
use commonware_cryptography::sha256::Digest;
#[cfg(feature = "validator")]
use commonware_cryptography::sha256::Sha256;
#[cfg(feature = "validator")]
use commonware_glue::stateful::{
    Application as StatefulApplication, Proposed,
    db::{DatabaseSet, Merkleized as _, Unmerkleized as _},
};
use commonware_runtime::Spawner;
#[cfg(feature = "validator")]
use commonware_runtime::telemetry::metrics::Registered;
use commonware_storage::Context as StorageContext;
#[cfg(feature = "validator")]
use commonware_storage::{mmr::Location, qmdb::sync::Target};
#[cfg(feature = "validator")]
use commonware_utils::{SystemTimeExt, non_empty_range};
#[cfg(feature = "validator")]
use futures::{Stream, StreamExt};
use hellas_kernel::NetworkId;
#[cfg(all(test, feature = "validator"))]
use hellas_rpc::SubmitTxOutcome;
#[cfg(feature = "validator")]
use prometheus_client::metrics::gauge::Gauge;
#[cfg(feature = "validator")]
use rand::Rng;
#[cfg(feature = "validator")]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(feature = "validator")]
use std::sync::Arc;
#[cfg(feature = "validator")]
use tokio::sync::Mutex;
use tokio::sync::broadcast;
#[cfg(feature = "validator")]
use tracing::{error, info, warn};

type MarshalVariant = commonware_consensus::marshal::standard::Standard<HellasBlock>;
pub type MarshalMailbox = commonware_consensus::marshal::core::Mailbox<Scheme, MarshalVariant>;

#[derive(Clone, Copy)]
pub struct ApplicationConfig {
    pub page_cache_size: u16,
    pub page_cache_count: usize,
}

impl Default for ApplicationConfig {
    fn default() -> Self {
        Self {
            page_cache_size: crate::execution::store::DEFAULT_PAGE_CACHE_SIZE.get(),
            page_cache_count: crate::execution::store::DEFAULT_PAGE_CACHE_COUNT.get(),
        }
    }
}

// A mempool is a validator's, so all of it compiles for one.
//
// The two things that put a transaction in it are `rpc.rs`, the submit
// path, and `server.rs`, the socket in front of that path; the one thing
// that removes included transactions is `StatefulApplication::finalized`.
// Invalid candidates are also pruned only against finalized state.
// All three are `validator`. A follower forwards what it is handed
// upstream through its light client and proposes no block, so on an
// `indexer` build this held nothing and nobody read it — the same reason
// `Application` above keeps no `network` and no height gauge there.

/// Maximum number of general transactions resident in the mempool.
#[cfg(feature = "validator")]
pub const GENERAL_MEMPOOL_CAPACITY: usize = 120;
/// Maximum number of finalized-contest response slots resident at once.
#[cfg(feature = "validator")]
pub const RESPONSE_MEMPOOL_CAPACITY: usize = 64;
/// Canonical chain encoding of one `PaymentCloseResponse` transaction.
#[cfg(feature = "validator")]
pub const RESPONSE_TRANSACTION_BYTES: usize = 274;
/// Mempool residents re-executed against committed state per finalized block.
///
/// Post-finalization reconciliation runs inside `finalized`, which consensus
/// awaits, so its cost is paid by every validator on every block. Bounding it
/// keeps that cost independent of how full the pool is; the offset rotates
/// with height, so a pool of `GENERAL_MEMPOOL_CAPACITY +
/// RESPONSE_MEMPOOL_CAPACITY` is still fully covered within a handful of
/// blocks. Pruning is an optimisation and nothing depends on it happening in
/// the same block that invalidated a transaction: `propose` re-checks every
/// candidate it picks up.
#[cfg(feature = "validator")]
pub const RECONCILED_PER_BLOCK: usize = 32;

#[cfg(feature = "validator")]
#[derive(Clone)]
pub(crate) struct MempoolEntry {
    pub(crate) digest: Digest,
    pub(crate) transaction: Transaction,
}

#[cfg(feature = "validator")]
impl MempoolEntry {
    pub(crate) fn new(transaction: Transaction) -> Self {
        let digest = Sha256::hash(&transaction.encode());
        Self {
            digest,
            transaction,
        }
    }
}

#[cfg(feature = "validator")]
pub(crate) type ResponseSlot = (hellas_kernel::EdgeId, hellas_kernel::StartId);

#[cfg(feature = "validator")]
#[derive(Default)]
pub(crate) struct MempoolState {
    pub(crate) general: VecDeque<MempoolEntry>,
    pub(crate) responses: BTreeMap<ResponseSlot, MempoolEntry>,
}

#[cfg(feature = "validator")]
#[derive(Clone, Default)]
pub struct Mempool {
    pub(crate) inner: Arc<Mutex<MempoolState>>,
}

#[cfg(feature = "validator")]
impl Mempool {
    #[cfg(test)]
    pub(crate) async fn test_submit(&self, tx: Transaction) -> SubmitTxOutcome {
        let entry = MempoolEntry::new(tx);
        let mut mempool = self.inner.lock().await;
        if mempool
            .general
            .iter()
            .any(|resident| resident.digest == entry.digest)
        {
            return SubmitTxOutcome::Duplicate;
        }
        if mempool.general.len() >= GENERAL_MEMPOOL_CAPACITY {
            return SubmitTxOutcome::Full;
        }
        mempool.general.push_back(entry);
        SubmitTxOutcome::Enqueued
    }

    #[cfg(test)]
    pub(crate) async fn test_transactions(&self) -> Vec<Transaction> {
        let mempool = self.inner.lock().await;
        mempool
            .responses
            .values()
            .chain(mempool.general.iter())
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    async fn snapshot(&self) -> Vec<Transaction> {
        let mempool = self.inner.lock().await;
        mempool
            .responses
            .values()
            .chain(mempool.general.iter())
            .map(|entry| entry.transaction.clone())
            .collect()
    }

    async fn remove(&self, digests: &BTreeSet<Digest>) {
        let mut mempool = self.inner.lock().await;
        // Exact-digest removal cannot replace a newer response or reinsert an
        // entry removed while validation was in flight.
        mempool
            .general
            .retain(|entry| !digests.contains(&entry.digest));
        mempool
            .responses
            .retain(|_, entry| !digests.contains(&entry.digest));
    }
}

#[cfg(feature = "validator")]
pub(crate) fn response_slot(transaction: &Transaction) -> Option<ResponseSlot> {
    let Transaction::Kernel(hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    }) = transaction
    else {
        return None;
    };
    Some((response.payment_edge(), response.start_id()))
}

#[derive(Clone)]
pub struct Application {
    /// The network this node validates. Every kernel context it builds
    /// names it, so every authorization it accepts was made for it.
    ///
    /// Only a validator builds kernel contexts. An `indexer` build keeps
    /// no copy: it passes `network` straight to `OwnerIndex::new` and
    /// never executes a transaction itself.
    #[cfg(feature = "validator")]
    network: NetworkId,
    genesis: HellasBlock,
    /// Read by `execute_proposal`/`execute_all`, which are `validator`-only.
    #[cfg(feature = "validator")]
    genesis_allocations: Arc<Vec<(SettlementKey, u64)>>,
    /// Set by `StatefulApplication::finalized`. Only a validator runs
    /// consensus, so on an `indexer` build the gauge would sit at zero
    /// forever and misreport the follower's height; better absent.
    #[cfg(feature = "validator")]
    finalized_height: Registered<Gauge>,
    owner_index: OwnerIndex,
    #[cfg(feature = "validator")]
    verifier: Arc<ChainVerifier>,
    #[cfg(feature = "validator")]
    mempool: Mempool,
}

impl Application {
    #[cfg(feature = "validator")]
    pub(crate) fn mempool(&self) -> Mempool {
        self.mempool.clone()
    }

    pub fn genesis_block(&self) -> HellasBlock {
        self.genesis.clone()
    }

    pub fn owner_index(&self) -> OwnerIndex {
        self.owner_index.clone()
    }

    pub async fn new<E>(
        context: E,
        network: NetworkId,
        genesis_leader: PublicKey,
        genesis_allocations: Vec<(SettlementKey, u64)>,
        partition_prefix: &str,
        config: ApplicationConfig,
    ) -> Self
    where
        E: StorageContext + Spawner,
    {
        #[cfg(feature = "validator")]
        let finalized_height = context.register(
            "finalized_height",
            "Highest finalized block height",
            Gauge::default(),
        );
        let (state_root, sync_target) = empty_state(
            context,
            partition_prefix,
            config.page_cache_size,
            config.page_cache_count,
        )
        .await;
        let genesis = HellasBlock::genesis(genesis_leader, state_root, sync_target);
        let owner_index = OwnerIndex::new(network, &genesis, genesis_allocations.clone());
        Self {
            #[cfg(feature = "validator")]
            network,
            genesis,
            #[cfg(feature = "validator")]
            genesis_allocations: Arc::new(genesis_allocations),
            #[cfg(feature = "validator")]
            finalized_height,
            owner_index,
            #[cfg(feature = "validator")]
            verifier: Arc::new(ChainVerifier::new()),
            #[cfg(feature = "validator")]
            mempool: Mempool::default(),
        }
    }
}

#[cfg(feature = "validator")]
fn sync_target_from_merkleized<E>(
    merkleized: &<UtxoDatabase<E> as DatabaseSet<E>>::Merkleized,
) -> UtxoSyncTarget
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let bounds = merkleized.bounds();
    Target {
        root: merkleized.root(),
        range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
    }
}

#[cfg(feature = "validator")]
fn kernel_context(
    network: NetworkId,
    height: Height,
    previous_hash: Digest,
) -> hellas_kernel::Context {
    hellas_kernel::Context::with_fees(
        network,
        hellas_kernel::BlockHeight::new(height.get()),
        hellas_kernel::BlockHash::from_bytes(previous_hash.0),
        KERNEL_FEES,
    )
}

#[cfg(feature = "validator")]
impl<E> StatefulApplication<E> for Application
where
    E: Rng + Spawner + StorageContext + Send + Sync + 'static,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = HellasBlock;
    type Databases = UtxoDatabase<E>;
    type InputProvider = Mempool;

    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        block.sync_target()
    }

    async fn genesis(&mut self) -> Self::Block {
        self.genesis.clone()
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let (runtime, consensus_context) = context;
        let mut ancestry = Box::pin(ancestry);
        let parent = ancestry.next().await?;
        let snapshot = input.snapshot().await;
        // A proposed block is not a commitment. Keep resident transactions
        // until finality, but do not execute them twice in one ancestry.
        let finalized_height = self.owner_index.cursor().height;
        let resident_digests: BTreeSet<_> = snapshot
            .iter()
            .map(|tx| Sha256::hash(&tx.encode()))
            .collect();
        let mut ancestor_transactions = BTreeSet::new();
        let mut ancestor = Some(parent.clone());
        if !snapshot.is_empty() {
            while let Some(block) = ancestor {
                if block.height().get() <= finalized_height {
                    break;
                }
                ancestor_transactions.extend(
                    block
                        .txs()
                        .iter()
                        .map(|tx| Sha256::hash(&tx.encode()))
                        .filter(|digest| resident_digests.contains(digest)),
                );
                if ancestor_transactions.len() == resident_digests.len() {
                    break;
                }
                ancestor = ancestry.next().await;
            }
        }
        let pending: Vec<_> = snapshot
            .into_iter()
            .filter(|tx| !ancestor_transactions.contains(&Sha256::hash(&tx.encode())))
            .collect();
        let response_count = pending
            .iter()
            .take_while(|tx| response_slot(tx).is_some())
            .count();
        let response_bytes = response_count.saturating_mul(RESPONSE_TRANSACTION_BYTES);
        let general_count_budget = MAX_TXS_PER_BLOCK.saturating_sub(response_count);
        let general_byte_budget = MAX_BLOCK_TX_BYTES.saturating_sub(response_bytes);
        let (responses, general) = pending.split_at(response_count);
        debug_assert!(responses.iter().all(|transaction| {
            crate::light_client::canonical_submission_size(transaction)
                == RESPONSE_TRANSACTION_BYTES
        }));
        let mut candidates = responses.to_vec();
        let mut general_bytes = 0_usize;
        for transaction in general.iter().cloned() {
            let next_bytes = general_bytes.saturating_add(transaction.encode_size());
            if candidates.len().saturating_sub(response_count) >= general_count_budget
                || next_bytes > general_byte_budget
            {
                break;
            }
            general_bytes = next_bytes;
            candidates.push(transaction);
        }
        let block_height = Height::new(parent.height().get() + 1);
        let block_parent = parent.digest();
        let (batches, txs, _retained) = match execute_proposal(
            kernel_context(self.network, block_height, block_parent),
            self.verifier.as_ref(),
            candidates,
            &self.genesis_allocations,
            MAX_TXS_PER_BLOCK,
            MAX_BLOCK_TX_BYTES,
            batches,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                error!(?err, "proposal execution failed");
                return None;
            }
        };
        let owner_root = crate::execution::owner_tree::root(&batches).await.ok()?;
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");

        let timestamp = runtime.current().epoch_millis().max(parent.timestamp());
        let block = HellasBlock::new(
            consensus_context,
            block_parent,
            block_height,
            timestamp,
            merkleized.root(),
            sync_target_from_merkleized(&merkleized),
            txs,
        )
        .with_owner_root(owner_root);
        Some(Proposed { block, merkleized })
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let (runtime, consensus_context) = context;
        let mut ancestry = Box::pin(ancestry);
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;
        if let Err(err) = block.validate(
            &consensus_context,
            Height::new(parent.height().get() + 1),
            parent.digest(),
            runtime.current().epoch_millis(),
            parent.timestamp(),
        ) {
            warn!(%err, payload = ?block.digest(), "block validation failed");
            return None;
        }

        let batches = execute_all(
            // `previous_hash` is currently inert in kernel apply. Source it
            // from the block field so verify and certified replay cannot
            // diverge when the kernel begins consuming it.
            kernel_context(self.network, block.height(), block.parent()),
            self.verifier.as_ref(),
            block.txs(),
            &self.genesis_allocations,
            batches,
        )
        .await
        .map_err(|err| {
            warn!(?err, payload = ?block.digest(), "block execution failed");
            err
        })
        .ok()?;
        let owner_root = crate::execution::owner_tree::root(&batches).await.ok()?;
        if owner_root != block.owner_root() {
            return None;
        }
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");
        let computed_sync_target = sync_target_from_merkleized(&merkleized);
        if merkleized.root() != block.state_root() || computed_sync_target != block.sync_target() {
            warn!(
                payload = ?block.digest(),
                claimed_state_root = ?block.state_root(),
                computed_state_root = ?merkleized.root(),
                claimed_sync_target = ?block.sync_target(),
                computed_sync_target = ?computed_sync_target,
                "block root mismatch"
            );
            return None;
        }
        Some(merkleized)
    }

    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let batches = execute_all(
            kernel_context(self.network, block.height(), block.parent()),
            self.verifier.as_ref(),
            block.txs(),
            &self.genesis_allocations,
            batches,
        )
        .await
        .expect("replay of certified block failed");
        let owner_root = crate::execution::owner_tree::root(&batches)
            .await
            .expect("owner commitment must replay");
        assert_eq!(
            owner_root,
            block.owner_root(),
            "certified owner commitment must replay"
        );
        let merkleized = batches.merkleize().await.expect("UTXO merkleize failed");
        assert_eq!(merkleized.root(), block.state_root());
        assert_eq!(
            sync_target_from_merkleized(&merkleized),
            block.sync_target()
        );
        merkleized
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        databases: &Self::Databases,
    ) {
        self.finalized_height
            .set(i64::try_from(block.height().get()).unwrap_or(i64::MAX));
        self.owner_index
            .apply_finalized(block)
            .expect("finalized block indexing failed");
        self.mempool
            .remove(
                &block
                    .txs()
                    .iter()
                    .map(|tx| Sha256::hash(&tx.encode()))
                    .collect(),
            )
            .await;
        // Reconcile against committed state, never a speculative proposal.
        // Each candidate gets its own disposable batch so one candidate's
        // effects cannot invalidate another.
        // Startup/state-sync notifications may trail the database checkpoint.
        if self.owner_index.cursor().height == block.height().get()
            && databases.read().await.root() == block.state_root()
        {
            let mut rejected = BTreeSet::new();
            let candidates = self.mempool.snapshot().await;
            // Admission caps how many transactions the pool holds, not how
            // often each is re-examined. Reconciling the whole pool here
            // would make every validator pay one full kernel execution per
            // resident per block, and `submit_general` admits without
            // semantic validation while `ObjectNotFound` is transient and so
            // retained -- a peer can park `GENERAL_MEMPOOL_CAPACITY`
            // never-includable transactions and have them re-verified
            // forever. Examine a bounded window instead, starting at an
            // offset derived from the height so the whole pool is still
            // covered, just across several blocks rather than all at once.
            let examined = candidates.len().min(RECONCILED_PER_BLOCK);
            let start = if candidates.is_empty() {
                0
            } else {
                usize::try_from(block.height().get() % candidates.len() as u64).unwrap_or(0)
            };
            for offset in 0..examined {
                let transaction = &candidates[(start + offset) % candidates.len()];
                let digest = Sha256::hash(&transaction.encode());
                let outcome = execute_proposal(
                    kernel_context(
                        self.network,
                        Height::new(block.height().get() + 1),
                        block.digest(),
                    ),
                    self.verifier.as_ref(),
                    vec![transaction.clone()],
                    &self.genesis_allocations,
                    MAX_TXS_PER_BLOCK,
                    MAX_BLOCK_TX_BYTES,
                    databases.new_batches().await,
                )
                .await;
                // `propose` treats this same error set as a skipped round
                // (see `proposal execution failed` above). Pruning is an
                // optimisation -- a transaction left in the pool is retried
                // next block -- so a storage fault must not be more fatal
                // here than it is there.
                let (_, included, retained) = match outcome {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        error!(?err, "finalized mempool validation failed");
                        break;
                    }
                };
                if included.is_empty() && retained.is_empty() {
                    rejected.insert(digest);
                }
            }
            self.mempool.remove(&rejected).await;
        }
        info!(
            name: "app.finalized",
            height = %block.height(),
            view = %block.context().round.view(),
            payload = ?block.digest(),
            tx_count = block.txs().len(),
        );
    }
}

#[derive(Clone)]
pub struct ActivityReporter<R> {
    inner: R,
    activity_tx: broadcast::Sender<ConsensusActivity>,
}

impl<R> ActivityReporter<R> {
    pub fn new(inner: R, activity_tx: broadcast::Sender<ConsensusActivity>) -> Self {
        Self { inner, activity_tx }
    }
}

impl<R> Reporter for ActivityReporter<R>
where
    R: Reporter<Activity = Activity> + Send,
{
    type Activity = Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Some(converted) = convert_activity(&activity) {
            let _ = self.activity_tx.send(converted);
        }
        self.inner.report(activity)
    }
}

fn proposal_info(p: &Proposal<Digest>) -> ProposalInfo {
    ProposalInfo {
        epoch: p.round.epoch().get(),
        view: p.round.view().get(),
        parent_view: p.parent.get(),
        parent_payload: Digest::from([0u8; 32]),
        payload: p.payload,
    }
}

fn certificate_signers() -> Vec<u32> {
    // The recovered BLS threshold certificate is deliberately
    // non-attributable: it proves a quorum signed, but does not retain a
    // signer bitmap. Consumers that need identities must subscribe to the
    // individual Notarize/Nullify activity emitted alongside certificates.
    Vec::new()
}

fn convert_activity(activity: &Activity) -> Option<ConsensusActivity> {
    match activity {
        SimplexActivity::Notarize(n) => Some(ConsensusActivity::Notarize {
            proposal: proposal_info(&n.proposal),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        }),
        SimplexActivity::Notarization(n) | SimplexActivity::Certification(n) => {
            Some(ConsensusActivity::Notarization {
                proposal: proposal_info(&n.proposal),
                signers: certificate_signers(),
                certificate: n.certificate.encode().to_vec(),
            })
        }
        SimplexActivity::Nullify(n) => Some(ConsensusActivity::Nullify {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signer: n.attestation.signer.get(),
            signature: n.attestation.signature.encode().to_vec(),
        }),
        SimplexActivity::Nullification(n) => Some(ConsensusActivity::Nullification {
            epoch: n.round.epoch().get(),
            view: n.round.view().get(),
            signers: certificate_signers(),
            certificate: n.certificate.encode().to_vec(),
        }),
        SimplexActivity::Finalization(f) => Some(ConsensusActivity::Finalization {
            proposal: proposal_info(&f.proposal),
            signers: certificate_signers(),
            certificate: f.certificate.encode().to_vec(),
        }),
        SimplexActivity::ConflictingNotarize(_) => None,
        SimplexActivity::Finalize(_)
        | SimplexActivity::ConflictingFinalize(_)
        | SimplexActivity::NullifyFinalize(_) => None,
    }
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;
    use crate::execution::{
        store::{UtxoDatabase, utxo_db_config},
        test_support::{kernel_fixture, run_qmdb, validator_key},
    };
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::Signer as _;
    use commonware_runtime::{Supervisor as _, tokio};
    use futures::stream;

    fn next_consensus_context(parent: &HellasBlock) -> Context<Digest, PublicKey> {
        let height = parent.height().get() + 1;
        Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: validator_key(0).public_key(),
            parent: (parent.context().round.view(), parent.digest()),
        }
    }

    async fn propose_from(
        app: &mut Application,
        runtime: &tokio::Context,
        database: &UtxoDatabase<tokio::Context>,
        parent: &HellasBlock,
        candidates: Vec<Transaction>,
        label: &'static str,
    ) -> (Proposed<Application, tokio::Context>, Vec<Transaction>) {
        if parent.height().get() > app.owner_index.cursor().height {
            app.owner_index
                .apply_finalized(parent)
                .expect("finalized test parent");
        }
        let mut mempool = Mempool::default();
        for tx in candidates {
            mempool.test_submit(tx).await;
        }
        let proposed = app
            .propose(
                (runtime.child(label), next_consensus_context(parent)),
                stream::iter([Arc::new(parent.clone())]),
                database.new_batches().await,
                &mut mempool,
            )
            .await
            .expect("application proposal");
        (proposed, mempool.snapshot().await)
    }

    async fn verifies_from(
        app: &mut Application,
        runtime: &tokio::Context,
        database: &UtxoDatabase<tokio::Context>,
        parent: &HellasBlock,
        block: &HellasBlock,
        label: &'static str,
    ) -> bool {
        app.verify(
            (runtime.child(label), block.context()),
            stream::iter([Arc::new(block.clone()), Arc::new(parent.clone())]),
            database.new_batches().await,
        )
        .await
        .is_some()
    }

    fn candidate_block(parent: &HellasBlock, tx: Transaction) -> HellasBlock {
        HellasBlock::new(
            next_consensus_context(parent),
            parent.digest(),
            Height::new(parent.height().get() + 1),
            parent.timestamp(),
            parent.state_root(),
            parent.sync_target(),
            vec![tx],
        )
    }

    #[test]
    fn kernel_context_binds_block_height_parent_hash_and_consensus_fees() {
        let parent = Digest::from([0x42; 32]);
        let context = kernel_context(crate::domain::TEST_NETWORK, Height::new(17), parent);
        assert_eq!(context.block_height(), hellas_kernel::BlockHeight::new(17));
        assert_eq!(
            context.previous_hash(),
            hellas_kernel::BlockHash::from_bytes(parent.0)
        );
        assert_eq!(context.fees(), KERNEL_FEES);
    }

    #[test]
    fn abandoned_proposal_keeps_accepted_transaction_for_retry() {
        run_qmdb(|runtime| async move {
            let fixture = kernel_fixture(100).expect("kernel fixture");
            let mut app = Application::new(
                runtime.child("app"),
                crate::domain::TEST_NETWORK,
                validator_key(0).public_key(),
                fixture.allocations.clone(),
                "abandoned_proposal_app",
                ApplicationConfig {
                    page_cache_size: 1024,
                    page_cache_count: 8,
                },
            )
            .await;
            let database_context = runtime.child("database");
            let config = utxo_db_config(&database_context, "abandoned_proposal_db", 1024, 8);
            let database =
                <UtxoDatabase<_> as DatabaseSet<_>>::init(database_context, config).await;
            let genesis = app.genesis_block();
            let mut mempool = app.mempool();
            let transaction = Transaction::Kernel(fixture.open.clone());
            let bad_auth = Transaction::Kernel(fixture.bad_auth_open().expect("invalid signature"));
            // An empty finalized block from another proposer must prune bad
            // signatures without consuming this node's valid pending Open.
            let mut empty_pool = Mempool::default();
            let empty = app
                .propose(
                    (runtime.child("empty"), next_consensus_context(&genesis)),
                    stream::iter([Arc::new(genesis.clone())]),
                    database.new_batches().await,
                    &mut empty_pool,
                )
                .await
                .expect("empty block");
            mempool.test_submit(transaction.clone()).await;
            mempool.test_submit(bad_auth).await;
            let Proposed {
                block: parent,
                merkleized,
            } = empty;
            database.finalize(merkleized).await;
            app.finalized(
                (runtime.child("empty_finalized"), parent.context()),
                &parent,
                &database,
            )
            .await;
            assert_eq!(mempool.test_transactions().await.len(), 1);
            let genesis = parent;
            assert_eq!(
                mempool.test_submit(transaction.clone()).await,
                SubmitTxOutcome::Duplicate
            );
            for label in ["abandoned", "retry"] {
                let proposed = app
                    .propose(
                        (runtime.child(label), next_consensus_context(&genesis)),
                        stream::iter([Arc::new(genesis.clone())]),
                        database.new_batches().await,
                        &mut mempool,
                    )
                    .await
                    .expect("proposal");
                assert_eq!(proposed.block.txs().len(), 1);
                assert_eq!(proposed.block.txs()[0].encode(), transaction.encode());
                // Consensus may abandon this completed proposal after its view
                // times out. Neither the block nor its batches are finalized.
                drop(proposed);
            }
            let proposed = app
                .propose(
                    (
                        runtime.child("to_finalize"),
                        next_consensus_context(&genesis),
                    ),
                    stream::iter([Arc::new(genesis.clone())]),
                    database.new_batches().await,
                    &mut mempool,
                )
                .await
                .expect("proposal to finalize");
            let Proposed { block, merkleized } = proposed;
            // Supply this parent's state without notifying Application yet:
            // descendant selection must skip its tx, but retain it in the pool.
            database.finalize(merkleized).await;
            let descendant = app
                .propose(
                    (runtime.child("descendant"), next_consensus_context(&block)),
                    stream::iter([Arc::new(block.clone()), Arc::new(genesis)]),
                    database.new_batches().await,
                    &mut mempool,
                )
                .await
                .expect("descendant proposal");
            assert!(descendant.block.txs().is_empty());
            assert_eq!(mempool.test_transactions().await.len(), 1);
            app.finalized(
                (runtime.child("finalized"), block.context()),
                &block,
                &database,
            )
            .await;
            assert!(mempool.test_transactions().await.is_empty());
            runtime.stop(0, None).await.unwrap();
        });
    }

    #[test]
    fn proposal_and_verify_use_block_height_at_timeout_boundary() {
        run_qmdb(|runtime| async move {
            let fixture = kernel_fixture(3).expect("kernel fixture");
            let mut app = Application::new(
                runtime.child("app"),
                crate::domain::TEST_NETWORK,
                validator_key(0).public_key(),
                fixture.allocations.clone(),
                "context_boundary_app",
                ApplicationConfig {
                    page_cache_size: 1024,
                    page_cache_count: 8,
                },
            )
            .await;
            let database_context = runtime.child("database");
            let database_config = utxo_db_config(&database_context, "context_boundary_db", 1024, 8);
            let database =
                <UtxoDatabase<_> as DatabaseSet<_>>::init(database_context, database_config).await;
            let genesis = app.genesis_block();

            let (open, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &genesis,
                vec![Transaction::Kernel(fixture.open.clone())],
                "propose_open",
            )
            .await;
            assert_eq!(remaining.len(), 1);
            assert!(matches!(
                open.block.txs(),
                [Transaction::Kernel(tx)] if tx == &fixture.open
            ));
            assert!(
                verifies_from(
                    &mut app,
                    &runtime,
                    &database,
                    &genesis,
                    &open.block,
                    "verify_open",
                )
                .await
            );
            let Proposed {
                block: open_block,
                merkleized,
            } = open;
            database.finalize(merkleized).await;

            // Height 2 is timeout - 1: mutual close is accepted, while the
            // timeout close is time-healing and remains in the mempool.
            let (mutual_before_timeout, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &open_block,
                vec![Transaction::Kernel(fixture.mutual_close.clone())],
                "propose_mutual_before_timeout",
            )
            .await;
            assert_eq!(remaining.len(), 1);
            assert!(matches!(
                mutual_before_timeout.block.txs(),
                [Transaction::Kernel(tx)] if tx == &fixture.mutual_close
            ));
            assert!(
                verifies_from(
                    &mut app,
                    &runtime,
                    &database,
                    &open_block,
                    &mutual_before_timeout.block,
                    "verify_mutual_before_timeout",
                )
                .await
            );

            let (timeout_before_height, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &open_block,
                vec![Transaction::Kernel(fixture.timeout_close.clone())],
                "propose_timeout_before_height",
            )
            .await;
            assert!(timeout_before_height.block.txs().is_empty());
            assert!(matches!(
                remaining.as_slice(),
                [Transaction::Kernel(tx)] if tx == &fixture.timeout_close
            ));
            let early_timeout = candidate_block(
                &open_block,
                Transaction::Kernel(fixture.timeout_close.clone()),
            );
            assert!(
                !verifies_from(
                    &mut app,
                    &runtime,
                    &database,
                    &open_block,
                    &early_timeout,
                    "verify_timeout_before_height",
                )
                .await
            );

            let (empty_height_two, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &open_block,
                Vec::new(),
                "propose_empty_height_two",
            )
            .await;
            assert!(empty_height_two.block.txs().is_empty());
            assert!(remaining.is_empty());
            // A valid signature can fail only because a speculative branch
            // reached its expiry. Abandoning that branch must allow retry on
            // the shorter finalized ancestry, where it is still valid.
            let mut branch_pool = Mempool::default();
            branch_pool
                .test_submit(Transaction::Kernel(fixture.mutual_close.clone()))
                .await;
            let expired_branch = app
                .propose(
                    (
                        runtime.child("expired_branch"),
                        next_consensus_context(&empty_height_two.block),
                    ),
                    stream::iter([
                        Arc::new(empty_height_two.block.clone()),
                        Arc::new(open_block.clone()),
                    ]),
                    UtxoDatabase::<tokio::Context>::fork_batches(&empty_height_two.merkleized),
                    &mut branch_pool,
                )
                .await
                .expect("expired speculative proposal");
            assert!(expired_branch.block.txs().is_empty());
            assert_eq!(branch_pool.test_transactions().await.len(), 1);
            let retry = app
                .propose(
                    (
                        runtime.child("shorter_branch"),
                        next_consensus_context(&open_block),
                    ),
                    stream::iter([Arc::new(open_block.clone())]),
                    database.new_batches().await,
                    &mut branch_pool,
                )
                .await
                .expect("retry on finalized parent");
            assert!(
                matches!(retry.block.txs(), [Transaction::Kernel(tx)] if tx == &fixture.mutual_close)
            );
            let Proposed {
                block: height_two_block,
                merkleized,
            } = empty_height_two;
            database.finalize(merkleized).await;

            // Height 3 is the timeout: mutual close is now ProofExpired and is
            // omitted (pruned at finalization), while timeout close becomes admissible.
            let (mutual_at_timeout, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &height_two_block,
                vec![Transaction::Kernel(fixture.mutual_close.clone())],
                "propose_mutual_at_timeout",
            )
            .await;
            assert!(mutual_at_timeout.block.txs().is_empty());
            assert_eq!(remaining.len(), 1);
            let expired_mutual = candidate_block(
                &height_two_block,
                Transaction::Kernel(fixture.mutual_close.clone()),
            );
            assert!(
                !verifies_from(
                    &mut app,
                    &runtime,
                    &database,
                    &height_two_block,
                    &expired_mutual,
                    "verify_mutual_at_timeout",
                )
                .await
            );

            let (timeout_at_height, remaining) = propose_from(
                &mut app,
                &runtime,
                &database,
                &height_two_block,
                vec![Transaction::Kernel(fixture.timeout_close.clone())],
                "propose_timeout_at_height",
            )
            .await;
            assert_eq!(remaining.len(), 1);
            assert!(matches!(
                timeout_at_height.block.txs(),
                [Transaction::Kernel(tx)] if tx == &fixture.timeout_close
            ));
            assert!(
                verifies_from(
                    &mut app,
                    &runtime,
                    &database,
                    &height_two_block,
                    &timeout_at_height.block,
                    "verify_timeout_at_height",
                )
                .await
            );
        });
    }
}
