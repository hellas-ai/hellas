use super::*;
use crate::{
    HellasBlock,
    domain::{Object, ObjectId},
    light_client::ObjectSnapshot,
};
use commonware_codec::{Decode as _, DecodeExt as _, FixedSize as _};
use commonware_storage::{
    merkle::Proof,
    mmr,
    qmdb::{any::unordered::fixed::Operation, verify_proof},
};
use futures_util::{StreamExt as _, stream};
use std::collections::BTreeMap;

type StateOperation = Operation<mmr::Family, ObjectId, Object>;

fn invalid(message: impl std::fmt::Display) -> QueryError {
    QueryError::Remote(format!("invalid finalized object witness: {message}"))
}

pub(super) async fn read(
    client: &RemoteLightClient,
    keys: Vec<ObjectId>,
) -> Result<Option<ObjectSnapshot>, QueryError> {
    if client.verifier.is_none() || keys.len() > 32 {
        return Err(invalid(
            "a pinned verifier and at most 32 keys are required",
        ));
    }
    let keys: BTreeSet<_> = keys.into_iter().collect();
    let Some(finalized) = client
        .get_finalized_block(FinalizedBlockQuery::Latest)
        .await?
    else {
        return Ok(None);
    };
    let block = HellasBlock::decode(finalized.block.as_slice()).map_err(invalid)?;
    let target = block.sync_target();
    if target.root != finalized.snapshot.state_root {
        return Err(invalid("state root differs from the certified sync target"));
    }
    let start = *target.range.start();
    let count = *target.range.end();
    if start >= count {
        return Err(invalid("empty operation witness"));
    }
    // Any-QMDB authenticates history, rather than a key's latest value. Reading
    // its entire certified retained interval also proves absence and prevents an
    // old, individually valid update from masquerading as a current object.
    // Only requested keys and four bounded wire ranges are retained in memory.
    let ranges = stream::iter((start..count).step_by(64))
        .map(|start| {
            let client = client.clone();
            async move {
                let wanted = 64.min(count - start);
                let response = client
                    .get_operations(GetOperationsRequest {
                        op_count: count,
                        start,
                        max_ops: wanted,
                        include_pinned_nodes: false,
                    })
                    .await?;
                if response.operations.len() as u64 != wanted
                    || !response.pinned_nodes.is_empty()
                    || response.proof.len() > 8192
                    || response
                        .operations
                        .iter()
                        .any(|bytes| bytes.len() != StateOperation::SIZE)
                {
                    return Err(invalid("range size"));
                }
                let proof = Proof::<mmr::Family, _>::decode_cfg(response.proof.as_slice(), &128)
                    .map_err(invalid)?;
                let operations = response
                    .operations
                    .iter()
                    .map(|bytes| StateOperation::decode(bytes.as_slice()).map_err(invalid))
                    .collect::<Result<Vec<_>, _>>()?;
                if *proof.leaves != count
                    || !verify_proof::<Sha256, _, _>(
                        &proof,
                        mmr::Location::new(start),
                        &operations,
                        &target.root,
                    )
                {
                    return Err(invalid("range proof"));
                }
                Ok(operations)
            }
        })
        .buffered(4);
    futures_util::pin_mut!(ranges);
    let mut objects = BTreeMap::new();
    let mut last_floor = None;
    while let Some(operations) = ranges.next().await {
        for operation in operations? {
            last_floor = match operation {
                StateOperation::Update(update) => {
                    if keys.contains(&update.0) {
                        objects.insert(update.0, update.1);
                    }
                    None
                }
                StateOperation::Delete(key) => {
                    objects.remove(&key);
                    None
                }
                StateOperation::CommitFloor(_, floor) => Some(*floor),
            };
        }
    }
    if last_floor != Some(start) {
        return Err(invalid("terminal inactivity floor"));
    }
    Ok(Some(ObjectSnapshot {
        network: client.pinned_network()?,
        block: finalized.snapshot,
        objects,
    }))
}
