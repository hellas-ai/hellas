//! The root checks shared by consensus verification and finalized replay.
use super::{ChainVerifier, kernel::ExecutionError, store::UtxoDatabase};
use crate::{HellasBlock, domain::SettlementKey};
use commonware_consensus::{Block as _, Heightable as _};
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::Spawner;
use commonware_storage::{Context, mmr::Location};

pub(crate) type Batch<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Unmerkleized;
pub(crate) type Executed<E> = <UtxoDatabase<E> as DatabaseSet<E>>::Merkleized;

pub(crate) async fn execute<E>(
    block: &HellasBlock,
    network: hellas_kernel::NetworkId,
    allocations: &[(SettlementKey, u64)],
    verifier: &ChainVerifier,
    batch: Batch<E>,
) -> Result<Executed<E>, ExecutionError>
where
    E: Context + Spawner + Send + Sync + 'static,
{
    let batch = super::kernel::execute_all(
        hellas_kernel::Context::with_fees(
            network,
            hellas_kernel::BlockHeight::new(block.height().get()),
            hellas_kernel::BlockHash::from_bytes(block.parent().0),
            crate::domain::KERNEL_FEES,
        ),
        verifier,
        block.txs(),
        allocations,
        batch,
    )
    .await?;
    check(block, batch).await
}

pub(crate) async fn check<E>(
    block: &HellasBlock,
    batch: Batch<E>,
) -> Result<Executed<E>, ExecutionError>
where
    E: Context + Spawner + Send + Sync + 'static,
{
    let owner_root = super::owner_tree::root(&batch)
        .await
        .map_err(|error| ExecutionError::Storage(error.to_string()))?;
    if owner_root != block.owner_root() {
        return Err(ExecutionError::RootMismatch("owner"));
    }
    let executed = batch
        .merkleize()
        .await
        .map_err(|error| ExecutionError::Storage(format!("{error:?}")))?;
    let bounds = executed.bounds();
    let target = block.sync_target();
    if executed.root() != block.state_root()
        || target.root != executed.root()
        || target.range.start() != bounds.inactivity_floor
        || target.range.end() != Location::new(bounds.total_size)
    {
        return Err(ExecutionError::RootMismatch("state"));
    }
    Ok(executed)
}
