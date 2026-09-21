//! Adapter from speculative QMDB batches to the shared authenticated owner tree.
use super::{kernel::ExecutionError, store::UtxoDatabase};
#[cfg(feature = "indexer-api")]
use super::store::UtxoDb;
use crate::{
    domain::{Object, ObjectId, SettlementKey},
    owner_proof::{OWNER_NODE_BYTES, OwnerProofError, OwnerTreeStore, update_holding},
};
#[cfg(feature = "indexer-api")]
use crate::owner_proof::OwnerPageProof;
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;
type Batch<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Unmerkleized;

// These three serve `edge_index::replay` and nothing else. `owner_tree` as a
// whole is also needed by `validator` (for `root`), so the module gate is
// deliberately wider than these items: gate them to their actual consumer
// rather than leaving them dead in a validator-only build.
#[cfg(feature = "indexer-api")]
/// Reads the owner metadata already committed alongside objects in QMDB.
/// The caller must hold one database read guard for the entire proof/checkpoint
/// operation so a concurrent finalize cannot mix nodes from different heights.
struct StoredOwnerTree<'a, E: StorageContext + Spawner>(&'a UtxoDb<E>);

#[cfg(feature = "indexer-api")]
impl<E: StorageContext + Spawner + Send + Sync + 'static> OwnerTreeStore
    for StoredOwnerTree<'_, E>
{
    async fn get_node(
        &self,
        key: ObjectId,
    ) -> Result<Option<[u8; OWNER_NODE_BYTES]>, OwnerProofError> {
        match self
            .0
            .get(&key)
            .await
            .map_err(|error| OwnerProofError::Storage(format!("{error:?}")))?
        {
            None => Ok(None),
            Some(Object::OwnerData(bytes)) => Ok(Some(bytes)),
            Some(_) => Err(OwnerProofError::Invalid),
        }
    }

    async fn put_node(
        &mut self,
        _: ObjectId,
        _: Option<[u8; OWNER_NODE_BYTES]>,
    ) -> Result<(), OwnerProofError> {
        Err(OwnerProofError::Invalid)
    }
}

#[cfg(feature = "indexer-api")]
/// Read the authenticated owner root from finalized QMDB state.
/// Keep the same database read guard held across this call, checkpoint binding,
/// and `prove_stored_owner_page`; separate guards can observe different heights.
pub async fn stored_root<E>(database: &UtxoDb<E>) -> Result<[u8; 32], OwnerProofError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    crate::owner_proof::owner_root(&StoredOwnerTree(database)).await
}

#[cfg(feature = "indexer-api")]
/// Prove holdings directly from finalized owner metadata without replaying it.
/// The caller must hold one database read guard across the entire proof and its
/// checkpoint/root checks, including any call to `stored_root`.
pub async fn prove_stored_owner_page<E>(
    database: &UtxoDb<E>,
    owner: SettlementKey,
    offset: u64,
    limit: u32,
) -> Result<OwnerPageProof, OwnerProofError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    crate::owner_proof::prove_owner_page(&StoredOwnerTree(database), owner, offset, limit).await
}

struct BatchStore<E: StorageContext + Spawner> {
    batch: Option<Batch<E>>,
}
impl<E: StorageContext + Spawner + Send + Sync + 'static> OwnerTreeStore for BatchStore<E> {
    async fn get_node(
        &self,
        key: ObjectId,
    ) -> Result<Option<[u8; OWNER_NODE_BYTES]>, OwnerProofError> {
        match self
            .batch
            .as_ref()
            .expect("batch present")
            .get(&key)
            .await
            .map_err(|error| OwnerProofError::Storage(format!("{error:?}")))?
        {
            None => Ok(None),
            Some(Object::OwnerData(bytes)) => Ok(Some(bytes)),
            Some(_) => Err(OwnerProofError::Invalid),
        }
    }
    async fn put_node(
        &mut self,
        key: ObjectId,
        value: Option<[u8; OWNER_NODE_BYTES]>,
    ) -> Result<(), OwnerProofError> {
        // Domain-separated keys still reject a colliding spendable object before writing.
        self.get_node(key).await?;
        self.batch = Some(
            self.batch
                .take()
                .expect("batch present")
                .write(key, value.map(Object::OwnerData)),
        );
        Ok(())
    }
}

fn ownership(object: Option<Object>) -> Vec<(SettlementKey, u8, u64)> {
    match object {
        Some(Object::Coin(coin)) => vec![(coin.owner, 0, coin.value)],
        Some(Object::Edge(edge)) => {
            let parties = edge.parties();
            let maker = SettlementKey::from(parties.maker());
            let taker = SettlementKey::from(parties.taker());
            if maker == taker {
                vec![(maker, 1, 0)]
            } else {
                vec![(maker, 1, 0), (taker, 1, 0)]
            }
        }
        _ => Vec::new(),
    }
}

pub async fn write_owned<E>(
    batch: Batch<E>,
    id: ObjectId,
    value: Option<Object>,
) -> Result<Batch<E>, (Batch<E>, ExecutionError)>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    let old = match batch.get(&id).await {
        Ok(old) => old,
        Err(error) => return Err((batch, ExecutionError::Storage(format!("{error:?}")))),
    };
    if matches!(old, Some(Object::OwnerData(_))) || matches!(value, Some(Object::OwnerData(_))) {
        return Err((
            batch,
            ExecutionError::Storage("object namespace collides with owner metadata".into()),
        ));
    }
    let mut store = BatchStore { batch: Some(batch) };
    for (owner, _, _) in ownership(old) {
        if let Err(error) = update_holding(&mut store, owner, id, None).await {
            return Err((
                store.batch.take().unwrap(),
                ExecutionError::Storage(error.to_string()),
            ));
        }
    }
    for (owner, kind, balance) in ownership(value) {
        if let Err(error) = update_holding(&mut store, owner, id, Some((kind, balance))).await {
            return Err((
                store.batch.take().unwrap(),
                ExecutionError::Storage(error.to_string()),
            ));
        }
    }
    Ok(store.batch.take().unwrap().write(id, value))
}

pub async fn root<E>(batch: &Batch<E>) -> Result<[u8; 32], OwnerProofError>
where
    E: StorageContext + Spawner + Send + Sync + 'static,
{
    struct ReadBatch<'a, E: StorageContext + Spawner>(&'a Batch<E>);
    impl<E: StorageContext + Spawner + Send + Sync + 'static> OwnerTreeStore for ReadBatch<'_, E> {
        async fn get_node(
            &self,
            key: ObjectId,
        ) -> Result<Option<[u8; OWNER_NODE_BYTES]>, OwnerProofError> {
            match self
                .0
                .get(&key)
                .await
                .map_err(|error| OwnerProofError::Storage(format!("{error:?}")))?
            {
                None => Ok(None),
                Some(Object::OwnerData(bytes)) => Ok(Some(bytes)),
                _ => Err(OwnerProofError::Invalid),
            }
        }
        async fn put_node(
            &mut self,
            _: ObjectId,
            _: Option<[u8; OWNER_NODE_BYTES]>,
        ) -> Result<(), OwnerProofError> {
            Err(OwnerProofError::Invalid)
        }
    }
    crate::owner_proof::owner_root(&ReadBatch(batch)).await
}

// Everything here exercises the `Stored*` adapter, which exists only for
// the indexer; the module would be empty of tests and full of unused
// imports in a validator-only build.
#[cfg(all(test, feature = "indexer-api"))]
mod tests {
    use super::*;
    use crate::{
        domain::{Coin, Digest},
        execution::{store::utxo_db_config, test_support::run_qmdb},
        owner_proof::verify_owner_page,
    };
    use commonware_glue::stateful::db::Unmerkleized as _;

    #[test]
    fn stored_adapter_proves_committed_metadata_and_rejects_objects_and_writes() {
        run_qmdb(|runtime| async move {
            let config = utxo_db_config(&runtime, "stored-owner-adapter", 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let owner = SettlementKey::from_bytes([1; 33]);
            let id = Digest::from([7; 32]);
            let batch = match write_owned(
                database.new_batches().await,
                id,
                Some(Object::Coin(Coin { owner, value: 321 })),
            )
            .await
            {
                Ok(batch) => batch,
                Err((_, error)) => panic!("write owner fixture: {error:?}"),
            };
            let expected_root = root(&batch).await.unwrap();
            database.finalize(batch.merkleize().await.unwrap()).await;

            let guard = database.read().await;
            assert_eq!(stored_root(&guard).await.unwrap(), expected_root);
            let page = prove_stored_owner_page(&guard, owner, 0, 64).await.unwrap();
            let summary = verify_owner_page(expected_root, owner, 0, 64, &page).unwrap();
            assert_eq!(summary.balance, 321);
            assert_eq!(summary.count, 1);
            assert_eq!(page.holdings[0].object_id, id.0);

            let mut adapter = StoredOwnerTree(&*guard);
            assert!(matches!(
                adapter.get_node(id).await,
                Err(OwnerProofError::Invalid)
            ));
            assert!(matches!(
                adapter.put_node(id, None).await,
                Err(OwnerProofError::Invalid)
            ));
            assert!(matches!(
                guard.get(&id).await.unwrap(),
                Some(Object::Coin(_))
            ));
        });
    }
}
