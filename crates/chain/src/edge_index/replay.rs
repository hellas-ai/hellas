//! Root-compatible finalized replay and crash recovery of the index/QMDB commit boundary.
use super::{native::EdgeIndex, store::Result};
#[cfg(test)]
use crate::execution::store::utxo_db_config;
use crate::{
    FinalizedBlockQuery, HellasBlock,
    domain::SettlementKey,
    execution::{
        ChainVerifier, execute_all_observed,
        store::{UtxoDatabase, UtxoDb},
    },
    proof_verify::{ProofBundle, ProofQuery, ProofVerifier, VerifiedAddress, VerifiedBlock},
};
use commonware_codec::DecodeExt as _;
use commonware_consensus::{Block as _, Heightable as _};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::db::{DatabaseSet, ManagedDb};
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;

pub(crate) struct Replay<E: StorageContext + Spawner> {
    database: UtxoDatabase<E>,
    index: EdgeIndex,
    network: hellas_kernel::NetworkId,
    allocations: Vec<(SettlementKey, u64)>,
    genesis: HellasBlock,
    checkpoint: Option<VerifiedBlock>,
}
impl<E: StorageContext + Spawner + Send + Sync + 'static> Replay<E> {
    #[cfg(test)]
    pub async fn new(
        context: E,
        partition: &str,
        index: EdgeIndex,
        network: hellas_kernel::NetworkId,
        allocations: Vec<(SettlementKey, u64)>,
        genesis: HellasBlock,
        verifier: &ProofVerifier,
    ) -> Result<Self> {
        let config = utxo_db_config(
            &context,
            &format!(
                "{partition}-edge-replay-v{}-{}",
                super::SCHEMA_VERSION,
                super::query::cursor_scope(
                    &index.store.identity.network_id,
                    &index.store.identity.genesis_sha256,
                    &index.store.identity.trust_sha256
                )
            ),
            1024,
            128,
        );
        let database = <UtxoDatabase<E> as DatabaseSet<E>>::init(context, config).await;
        Self::attach(database, index, network, allocations, genesis, verifier).await
    }

    /// Attach publication to the full node's execution database. Recovery
    /// finishes before either the local view or the read API becomes visible.
    pub(crate) async fn attach(
        database: UtxoDatabase<E>,
        index: EdgeIndex,
        network: hellas_kernel::NetworkId,
        allocations: Vec<(SettlementKey, u64)>,
        genesis: HellasBlock,
        verifier: &ProofVerifier,
    ) -> Result<Self> {
        let root = database.read().await.root();
        if let Some(intent) = index.store.intent()? {
            verifier.verify(
                intent.proof.clone(),
                ProofQuery::Block(FinalizedBlockQuery::Height(intent.proof.height)),
            )?;
            if hex::encode(root) == intent.proof.state_root {
                index.store.publish_intent()?;
            } else {
                let previous = index
                    .store
                    .latest()?
                    .map_or(hex::encode(genesis.state_root()), |proof| proof.state_root);
                if hex::encode(root) != previous {
                    return Err(
                        "QMDB root matches neither committed index nor replay intent".into(),
                    );
                }
                index.store.clear_intent()?;
            }
        }
        let latest = index.store.latest()?;
        if hex::encode(root)
            != latest.as_ref().map_or_else(
                || hex::encode(genesis.state_root()),
                |proof| proof.state_root.clone(),
            )
        {
            return Err("QMDB and index publication roots disagree".into());
        }
        // Recovery must complete before the HTTP origin exposes any state.
        // Check the durable owner tree and sync range as well as the QMDB root.
        let checkpoint = match &latest {
            Some(proof) => Some(Self::check_checkpoint(&database, proof, verifier).await?),
            None => None,
        };
        Ok(Self {
            database,
            index,
            network,
            allocations,
            genesis,
            checkpoint,
        })
    }
    pub fn next_height(&self) -> Result<u64> {
        self.checkpoint
            .as_ref()
            .map_or(0, |block| block.view().height())
            .checked_add(1)
            .ok_or_else(|| "replay height overflow".into())
    }

    async fn check_checkpoint(
        database: &UtxoDatabase<E>,
        proof: &ProofBundle,
        verifier: &ProofVerifier,
    ) -> Result<VerifiedBlock> {
        let verified = verifier.verify(
            proof.clone(),
            ProofQuery::Block(FinalizedBlockQuery::Height(proof.height)),
        )?;
        let database = database.read().await;
        let target = <UtxoDb<E> as ManagedDb<E>>::sync_target(&database);
        let expected = HellasBlock::decode(proof.canonical_block.as_slice())?.sync_target();
        if database.root() != verified.view().state_root()
            || target.root != expected.root
            || target.range != expected.range
            || crate::execution::owner_tree::stored_root(&database).await?
                != verified.view().owner_root()
        {
            return Err("durable owner checkpoint does not match certified state".into());
        }
        Ok(verified)
    }

    /// Read current holdings from the very QMDB state committed by replay.
    /// The origin serializes this whole call with apply (including publication).
    /// No retained historical tree or follower archive is needed after reopening.
    pub async fn owner_proof(
        &self,
        owner: SettlementKey,
        offset: u64,
        limit: u32,
        payload: Option<&str>,
    ) -> Result<Option<VerifiedAddress>> {
        let Some(verified) = &self.checkpoint else {
            return Ok(None);
        };
        if payload.is_some_and(|payload| payload != verified.bundle().payload) {
            return Ok(None);
        }
        // One read guard covers every node and the root check. The outer Replay
        // lock also excludes the finalize -> index-publication interval.
        let database = self.database.read().await;
        if database.root() != verified.view().state_root()
            || crate::execution::owner_tree::stored_root(&database).await?
                != verified.view().owner_root()
        {
            return Err("durable owner checkpoint does not match certified state".into());
        }
        let page =
            crate::execution::owner_tree::prove_stored_owner_page(&database, owner, offset, limit)
                .await?;
        // The immutable checkpoint was certified on admission or disk recovery.
        // Only owner-page hashes are checked here; no signature work holds Replay.
        Ok(Some(verified.clone().verify_owner_page(
            serde_json::to_vec(&page)?,
            owner,
            offset,
            limit,
        )?))
    }

    pub async fn prepare(
        &mut self,
        block: &HellasBlock,
        verified: &VerifiedBlock,
    ) -> Result<crate::execution::finalized::Executed<E>> {
        if block.digest() != verified.view().payload() {
            return Err("replay block differs from certified checkpoint".into());
        }
        let proof = verified.bundle();
        if proof.network_id != self.index.store.identity.network_id
            || proof.trust_sha256 != self.index.store.identity.trust_sha256
        {
            return Err("replay checkpoint uses a different trust configuration".into());
        }
        let height = block.height().get();
        if height != self.next_height()? {
            return Err("finalized replay gap".into());
        }
        let parent = self
            .checkpoint
            .as_ref()
            .map_or(self.genesis.digest(), |block| block.view().payload());
        if block.parent() != parent {
            return Err("finalized replay parent mismatch".into());
        }
        let context = hellas_kernel::Context::with_fees(
            self.network,
            hellas_kernel::BlockHeight::new(height),
            hellas_kernel::BlockHash::from_bytes(block.parent().0),
            crate::domain::KERNEL_FEES,
        );
        let (batches, changes) = execute_all_observed(
            context,
            &ChainVerifier::new(),
            block.txs(),
            &self.allocations,
            self.database.new_batches().await,
        )
        .await?;
        let merkleized = crate::execution::finalized::check(block, batches).await?;
        self.index.store.prepare(proof.clone(), changes)?;
        Ok(merkleized)
    }

    pub(crate) fn publish(&mut self, verified: VerifiedBlock) -> Result<()> {
        self.index.store.publish_intent()?;
        self.checkpoint = Some(verified);
        Ok(())
    }

    #[cfg(test)]
    pub async fn apply(&mut self, block: &HellasBlock, verified: VerifiedBlock) -> Result<()> {
        if block.height().get() < self.next_height()? {
            if self
                .index
                .store
                .read(None)?
                .proof(block.height().get())?
                .payload
                != verified.bundle().payload
            {
                return Err("conflicting finalized replay payload".into());
            }
            return Ok(());
        }
        let executed = self.prepare(block, &verified).await?;
        self.database.finalize(executed).await;
        self.publish(verified)
    }
}

#[cfg(test)]
pub(crate) mod tests;
