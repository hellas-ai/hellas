//! Index intents bracket the shared Stateful actor's database commit.
use super::{EdgeIndex, store::Result};
use crate::{
    ChainIndexer, FinalizedBlockQuery, HellasBlock,
    domain::{Digest, Object, SettlementKey},
    execution::store::{UtxoDatabase, UtxoDb},
    proof_verify::{ProofQuery, ProofVerifier, VerifiedAddress},
};
use commonware_codec::DecodeExt as _;
use commonware_consensus::{Block as _, Heightable};
use commonware_cryptography::Digestible;
use commonware_glue::stateful::db::ManagedDb;
use commonware_runtime::Spawner;
use commonware_storage::Context;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct Publication {
    pub(crate) index: EdgeIndex,
    pub(crate) verifier: Arc<ProofVerifier>,
    pub(crate) archive: ChainIndexer,
}
impl Publication {
    /// Publication can be one block ahead of Marshal's durable acknowledgment.
    /// Replay that certified checkpoint before reconciling the recovered stores.
    pub(crate) fn recovery_height(&self) -> Result<u64> {
        let Some(proof) = self.index.store.latest()? else {
            return Ok(0);
        };
        let height = proof.height;
        self.verifier.verify(
            proof,
            ProofQuery::Block(FinalizedBlockQuery::Height(height)),
        )?;
        Ok(height)
    }

    /// Reconcile the published index only after Stateful has restored execution,
    /// before live input or query service starts. The checkpoint is the executed
    /// archive block, not a height inferred from the index's own metadata.
    pub(crate) async fn recover<E: Context + Spawner + Send + Sync + 'static>(
        &self,
        database: &UtxoDatabase<E>,
        checkpoint: &HellasBlock,
    ) -> Result<()> {
        let reader = database.read().await;
        if reader.root() != checkpoint.state_root() {
            return Err("index recovery checkpoint differs from executed state".into());
        }
        let target = <UtxoDb<E> as ManagedDb<E>>::sync_target(&reader);
        if target.root != checkpoint.sync_target().root
            || target.range != checkpoint.sync_target().range
            || crate::execution::owner_tree::stored_root(&reader).await? != checkpoint.owner_root()
        {
            return Err("index recovery checkpoint differs from executed database metadata".into());
        }
        if let Some(intent) = self.index.store.intent()? {
            let verified = self.verifier.verify(
                intent.proof.clone(),
                ProofQuery::Block(FinalizedBlockQuery::Height(intent.proof.height)),
            )?;
            let block = HellasBlock::decode(intent.proof.canonical_block.as_slice())?;
            if verified.view().payload() == checkpoint.digest() {
                self.index.store.publish_intent()?;
            } else if checkpoint.height().get().checked_add(1) == Some(block.height().get())
                && block.parent() == checkpoint.digest()
            {
                self.index.store.clear_intent()?;
            } else {
                return Err(
                    "index intent is not bound to the recovered execution checkpoint".into(),
                );
            }
        }
        match self.index.store.latest()? {
            Some(proof) => {
                let verified = self.verifier.verify(
                    proof.clone(),
                    ProofQuery::Block(FinalizedBlockQuery::Height(proof.height)),
                )?;
                if verified.view().payload() != checkpoint.digest()
                    || verified.view().state_root() != reader.root()
                {
                    return Err(
                        "index publication differs from the recovered execution checkpoint".into(),
                    );
                }
            }
            None if checkpoint.height().get() == 0 => {}
            None => {
                return Err("historical indexing requires a directory indexed from genesis".into());
            }
        }
        Ok(())
    }

    pub(crate) async fn prepare(
        &self,
        block: &HellasBlock,
        changes: Vec<(Digest, Option<Object>)>,
    ) -> Result<()> {
        let latest = self.index.store.latest()?;
        if let Some(latest) = &latest
            && latest.height >= block.height().get()
        {
            let stored = self.index.store.read(None)?.proof(block.height().get())?;
            if stored.payload != hex::encode(block.digest()) {
                return Err("index checkpoint differs from finalized block".into());
            }
            return Ok(());
        }
        if latest.as_ref().map_or(1, |p| p.height + 1) != block.height().get() {
            return Err("index must replay every finalized block".into());
        }
        let stored = self
            .archive
            .get_finalized_block(FinalizedBlockQuery::Height(block.height().get()))
            .await?
            .ok_or("finalized index block is absent from archive")?;
        let verified = self.verifier.verify_finalized(
            stored,
            ProofQuery::Block(FinalizedBlockQuery::Height(block.height().get())),
        )?;
        if verified.view().payload() != block.digest() {
            return Err("index proof differs from executed block".into());
        }
        self.index.store.prepare(verified.bundle().clone(), changes)
    }

    pub(crate) async fn finalized<E: Context + Spawner + Send + Sync + 'static>(
        &self,
        block: &HellasBlock,
        database: &UtxoDatabase<E>,
    ) -> Result<()> {
        let reader = database.read().await;
        if reader.root() != block.state_root() {
            return Err("index publication differs from executed state".into());
        }
        if let Some(latest) = self.index.store.latest()?
            && latest.height >= block.height().get()
        {
            return Ok(());
        }
        let intent = self
            .index
            .store
            .intent()?
            .ok_or("missing finalized index intent")?;
        if intent.proof.payload != hex::encode(block.digest()) {
            return Err("index intent differs from finalized block".into());
        }
        self.verifier.verify(
            intent.proof,
            ProofQuery::Block(FinalizedBlockQuery::Height(block.height().get())),
        )?;
        self.index.store.publish_intent()
    }

    pub(crate) async fn owner_proof<E: Context + Spawner + Send + Sync + 'static>(
        &self,
        database: &UtxoDatabase<E>,
        owner: SettlementKey,
        offset: u64,
        limit: u32,
        payload: Option<&str>,
    ) -> Result<Option<VerifiedAddress>> {
        let reader = database.read().await;
        let Some(proof) = self.index.store.proof_for_state_root(reader.root())? else {
            return Ok(None);
        };
        if payload.is_some_and(|p| p != proof.payload) {
            return Ok(None);
        }
        let height = proof.height;
        let verified = self.verifier.verify(
            proof,
            ProofQuery::Block(FinalizedBlockQuery::Height(height)),
        )?;
        if reader.root() != verified.view().state_root()
            || crate::execution::owner_tree::stored_root(&reader).await?
                != verified.view().owner_root()
        {
            return Err("owner proof checkpoint differs from executed state".into());
        }
        let page =
            crate::execution::owner_tree::prove_stored_owner_page(&reader, owner, offset, limit)
                .await?;
        Ok(Some(
            verified.verify_owner_page(&page, owner, offset, limit)?,
        ))
    }
}
