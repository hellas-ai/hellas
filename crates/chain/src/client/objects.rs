use super::*;
use crate::{domain::ObjectId, light_client::ObjectSnapshot};
use std::collections::BTreeSet;

pub(super) async fn read(
    client: &RemoteLightClient,
    keys: Vec<ObjectId>,
) -> Result<Option<ObjectSnapshot>, QueryError> {
    let verifier = &client.proof_verifier;
    if keys.len() > crate::proof_verify::MAX_CURRENT_KEYS {
        return Err(QueryError::InvalidTransaction(
            "at most 32 object keys are allowed".into(),
        ));
    }
    let keys: BTreeSet<_> = keys.into_iter().collect();
    let response = client
        .rpc_client()
        .get_object_proofs(GetObjectProofsRequest {
            object_ids: keys.iter().map(|key| key.to_vec()).collect(),
            payload: None,
            owner: None,
            owner_after_key: None,
        })
        .await
        .map_err(QueryError::from)?;
    if response.block.is_none() {
        return Ok(None);
    }
    let verified = verifier
        .verify_objects(response, &keys, FinalizedBlockQuery::Latest, None)
        .map_err(|error| QueryError::Remote(error.to_string()))?;
    record_progress(
        &client.applied_progress,
        verified.block().view().height(),
        true,
    )?;
    Ok(Some(verified.into_snapshot()))
}
