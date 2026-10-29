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

pub(super) struct View {
    target: crate::UtxoSyncTarget,
    objects: BTreeMap<ObjectId, Object>,
}

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
    // Clones share one verified view, including reads for previously unseen keys.
    // Serialize refreshes so concurrent wallet and channel reads reuse the work.
    let mut view = client.objects.lock().await;
    let Some(finalized) = client
        .get_applied_finalized_block(FinalizedBlockQuery::Latest)
        .await?
    else {
        return Ok(None);
    };
    let block = HellasBlock::decode(finalized.block.as_slice()).map_err(invalid)?;
    let target = block.sync_target();
    if target.root != finalized.snapshot.state_root {
        return Err(invalid("state root differs from the certified sync target"));
    }
    let floor = *target.range.start();
    let count = *target.range.end();
    if floor >= count {
        return Err(invalid("empty operation witness"));
    }
    let start = match view.as_ref() {
        Some(previous) => {
            let end = *previous.target.range.end();
            if floor < *previous.target.range.start() || count < end {
                return Err(invalid("operation witness moved backward"));
            }
            if count == end && target != previous.target {
                return Err(invalid("conflicting operation witness at the same size"));
            }
            if count > end && target.root == previous.target.root {
                return Err(invalid("operation witness grew without changing root"));
            }
            if end < floor { floor } else { end }
        }
        None => floor,
    };
    // Any-QMDB authenticates history, rather than a key's latest value. Reading
    // its entire certified retained interval also proves absence and prevents an
    // old, individually valid update from masquerading as a current object.
    // Later finalized targets extend the same append-only log. Verify its entire
    // new suffix, or bootstrap again if pruning has overtaken the cached cursor.
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
    // Stage changes until every proof and the terminal floor have been checked.
    // Errors and cancellation leave the previous verified view intact.
    let mut changes = BTreeMap::new();
    let mut last_floor = None;
    while let Some(operations) = ranges.next().await {
        for operation in operations? {
            last_floor = match operation {
                StateOperation::Update(update) => {
                    changes.insert(update.0, Some(update.1));
                    None
                }
                StateOperation::Delete(key) => {
                    changes.insert(key, None);
                    None
                }
                StateOperation::CommitFloor(_, floor) => Some(*floor),
            };
        }
    }
    if start < count && last_floor != Some(floor) {
        return Err(invalid("terminal inactivity floor"));
    }
    if start == floor {
        *view = Some(View {
            target: target.clone(),
            objects: BTreeMap::new(),
        });
    }
    let view = view
        .as_mut()
        .expect("a verified initial interval creates the view");
    for (key, object) in changes {
        match object {
            Some(object) => {
                view.objects.insert(key, object);
            }
            None => {
                view.objects.remove(&key);
            }
        }
    }
    view.target = target.clone();
    Ok(Some(ObjectSnapshot {
        network: client.pinned_network()?,
        block: finalized.snapshot,
        objects: keys
            .into_iter()
            .filter_map(|key| view.objects.get(&key).cloned().map(|object| (key, object)))
            .collect(),
    }))
}
