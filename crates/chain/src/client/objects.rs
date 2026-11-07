use super::*;
use crate::{domain::ObjectId, light_client::ObjectSnapshot};
use std::collections::BTreeSet;

pub(super) async fn read(
    client: &RemoteLightClient,
    keys: Vec<ObjectId>,
    query: FinalizedBlockQuery,
) -> Result<Option<ObjectSnapshot>, QueryError> {
    let verifier = &client.proof_verifier;
    if keys.len() > crate::proof_verify::MAX_CURRENT_KEYS {
        return Err(QueryError::InvalidTransaction(
            "at most 32 object keys are allowed".into(),
        ));
    }
    let keys: BTreeSet<_> = keys.into_iter().collect();
    let payload = match query {
        FinalizedBlockQuery::Latest => None,
        FinalizedBlockQuery::Payload(payload) => Some(payload),
        FinalizedBlockQuery::Height(height) => {
            let Some(block) = client
                .get_applied_finalized_block(FinalizedBlockQuery::Height(height))
                .await?
            else {
                return Ok(None);
            };
            Some(block.snapshot.payload)
        }
    };
    let response = client
        .rpc_client()
        .get_object_proofs(GetObjectProofsRequest {
            object_ids: keys.iter().map(|key| key.to_vec()).collect(),
            payload: payload.map(|digest| digest.to_vec()),
            owner: None,
            owner_offset: 0,
            owner_limit: 0,
            owner_after_key: None,
        })
        .await
        .map_err(QueryError::from)?;
    if response.block.is_none() {
        return Ok(None);
    }
    let expected = payload.map_or(FinalizedBlockQuery::Latest, FinalizedBlockQuery::Payload);
    let verified = verifier
        .verify_objects(response, &keys, expected, None)
        .map_err(|error| QueryError::Remote(error.to_string()))?;
    if matches!(query, FinalizedBlockQuery::Latest) {
        record_progress(
            &client.applied_progress,
            verified.block().view().height(),
            true,
        )?;
    }
    Ok(Some(verified.into_snapshot()))
}
