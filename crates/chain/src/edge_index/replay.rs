//! Root-compatible finalized replay and crash recovery of the index/QMDB commit boundary.
use super::{native::EdgeIndex, store::Result};
use crate::{
    FinalizedBlockQuery, HellasBlock,
    domain::{Digest, SettlementKey},
    execution::{
        ChainVerifier, execute_all_observed,
        store::{UtxoDatabase, utxo_db_config},
    },
    verified_explorer::{ExplorerQuery, ExplorerVerifier, ProofBundle},
};
use commonware_consensus::{Block as _, Heightable as _};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;

pub(crate) struct Replay<E: StorageContext + Spawner> {
    database: UtxoDatabase<E>,
    index: EdgeIndex,
    network: hellas_kernel::NetworkId,
    allocations: Vec<(SettlementKey, u64)>,
    genesis: HellasBlock,
    cursor: u64,
}
impl<E: StorageContext + Spawner + Send + Sync + 'static> Replay<E> {
    pub async fn new(
        context: E,
        partition: &str,
        index: EdgeIndex,
        network: hellas_kernel::NetworkId,
        allocations: Vec<(SettlementKey, u64)>,
        genesis: HellasBlock,
        verifier: &ExplorerVerifier,
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
        let root = database.read().await.root();
        if let Some(intent) = index.store.intent()? {
            verifier.verify(
                intent.proof.clone(),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(intent.proof.height)),
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
        let cursor = latest.map_or(0, |proof| proof.height);
        Ok(Self {
            database,
            index,
            network,
            allocations,
            genesis,
            cursor,
        })
    }
    pub async fn apply(&mut self, block: &HellasBlock, proof: ProofBundle) -> Result<()> {
        let height = block.height().get();
        if height <= self.cursor {
            // Archive redelivery is harmless only when it is the exact same finalized payload.
            let stored = self.index.store.read(None)?.proof(height)?;
            if stored.payload != proof.payload {
                return Err("conflicting finalized replay payload".into());
            }
            return Ok(());
        }
        if height != self.cursor.checked_add(1).ok_or("replay height overflow")? {
            return Err("finalized replay gap".into());
        }
        let parent = self
            .index
            .store
            .latest()?
            .map_or(self.genesis.digest(), |proof| {
                Digest(
                    hex::decode(proof.payload)
                        .expect("stored payload")
                        .try_into()
                        .expect("stored hash"),
                )
            });
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
        let owner_root = crate::execution::owner_tree::root(&batches).await?;
        if owner_root != block.owner_root() {
            return Err("replayed owner root differs from certified block".into());
        }
        let merkleized = batches
            .merkleize()
            .await
            .map_err(|e| format!("merkleize: {e:?}"))?;
        if merkleized.root() != block.state_root()
            || hex::encode(merkleized.root()) != proof.state_root
        {
            return Err("replayed state root differs from certified block".into());
        }
        let bounds = merkleized.bounds();
        let target = block.sync_target();
        if target.root != merkleized.root()
            || target.range.start() != bounds.inactivity_floor
            || target.range.end() != commonware_storage::mmr::Location::new(bounds.total_size)
        {
            return Err("replayed sync target differs from certified block".into());
        }
        self.index.store.prepare(proof, changes)?;
        self.database.finalize(merkleized).await;
        self.index.store.publish_intent()?;
        self.cursor = height;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
