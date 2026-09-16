//! Adapter from speculative QMDB batches to the shared authenticated owner tree.
use super::{kernel::ExecutionError, store::UtxoDatabase};
use crate::{
    domain::{Object, ObjectId, SettlementKey},
    owner_proof::{OWNER_NODE_BYTES, OwnerProofError, OwnerTreeStore, update_holding},
};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::Spawner;
use commonware_storage::Context as StorageContext;
type Batch<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Unmerkleized;

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
