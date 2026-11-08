use super::*;
use crate::domain::{Object, ObjectKey};
use crate::light_client::Holdings;
use commonware_codec::DecodeExt as _;
use std::collections::{BTreeMap, BTreeSet};

type OwnerCursor = Option<(SettlementKey, Option<ObjectId>)>;

/// The caller's keys as one set, refusing more than the limit as given,
/// before duplicates collapse.
fn key_set(keys: Vec<ObjectKey>) -> Result<BTreeSet<ObjectId>, QueryError> {
    if keys.len() > crate::proof_verify::MAX_CURRENT_KEYS {
        return Err(QueryError::InvalidTransaction(
            "at most 32 object keys are allowed".into(),
        ));
    }
    Ok(keys.into_iter().map(ObjectKey::id).collect())
}

/// The one object request both routes share: `keys`, plus one holdings page
/// of `owner` after its cursor.
fn request(keys: &BTreeSet<ObjectId>, owner: OwnerCursor) -> GetObjectProofsRequest {
    GetObjectProofsRequest {
        object_ids: keys.iter().map(|key| key.to_vec()).collect(),
        payload: None,
        owner: owner.map(|(owner, _)| owner.to_bytes().to_vec()),
        owner_after_key: owner.and_then(|(_, after)| after).map(|key| key.to_vec()),
    }
}

pub(super) async fn read(
    client: &RemoteLightClient,
    keys: Vec<ObjectKey>,
    owner: OwnerCursor,
) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
    let keys = key_set(keys)?;
    let response = client
        .rpc_client()
        .get_object_proofs(request(&keys, owner))
        .await
        .map_err(QueryError::from)?;
    if response.block.is_none() {
        return Ok(None);
    }
    let verified = client
        .proof_verifier
        .verify_objects(
            response,
            &keys,
            FinalizedBlockQuery::Latest,
            owner.map(|(owner, after)| (owner, after.map(|key| key.0))),
        )
        .map_err(|error| QueryError::Remote(error.to_string()))?;
    record_progress(&client.applied_progress, verified.block.height, true)?;
    Ok(Some(verified))
}

/// Unproven object reads from a peer the operator configured as trusted.
///
/// It returns plain values and implements no read trait, so nothing that moves
/// funds can be handed its replies; those take [`Verified`] reads from a
/// [`RemoteLightClient`].
#[derive(Clone)]
pub struct TrustedReader {
    client: LightClientClientImpl<MuxTransport>,
    network: hellas_kernel::NetworkId,
}

impl TrustedReader {
    /// Connect to a peer the caller explicitly trusts, such as its own node.
    pub async fn connect(
        addr: impl Into<String>,
        network: hellas_kernel::NetworkId,
    ) -> Result<Self, QueryError> {
        let transport = connect_transport(&addr.into()).await?;
        Ok(Self {
            client: LightClientClientImpl::new(transport),
            network,
        })
    }

    pub async fn get_objects(
        &self,
        keys: Vec<ObjectKey>,
    ) -> Result<Option<ObjectSnapshot>, QueryError> {
        self.read(key_set(keys)?, None).await
    }

    pub async fn get_holdings(
        &self,
        owner: SettlementKey,
        after: Option<ObjectId>,
    ) -> Result<Option<ObjectSnapshot>, QueryError> {
        self.read(BTreeSet::new(), Some((owner, after))).await
    }

    async fn read(
        &self,
        keys: BTreeSet<ObjectId>,
        owner: OwnerCursor,
    ) -> Result<Option<ObjectSnapshot>, QueryError> {
        let response = self
            .client
            .get_objects(request(&keys, owner))
            .await
            .map_err(QueryError::from)?;
        let Some(snapshot) = response.snapshot else {
            return Ok(None);
        };
        let invalid = |what: &str| QueryError::Remote(format!("invalid {what} in object reply"));
        let mut objects = BTreeMap::new();
        for entry in response.objects {
            let key = ObjectId::from(
                <[u8; 32]>::try_from(entry.object_id.as_slice()).map_err(|_| invalid("key"))?,
            );
            if let Some(bytes) = entry.object {
                objects.insert(
                    key,
                    Object::decode(bytes.as_slice()).map_err(|_| invalid("object"))?,
                );
            }
        }
        let holdings = response
            .owner_page
            .map(|page| {
                let keys = page
                    .holdings
                    .iter()
                    .map(|key| <[u8; 32]>::try_from(key.as_slice()).map(ObjectId::from))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| invalid("holding"))?;
                let count = page.summary.ok_or_else(|| invalid("owner summary"))?.count;
                Ok::<_, QueryError>(Holdings::new(keys, page.offset, count))
            })
            .transpose()?;
        Ok(Some(ObjectSnapshot {
            network: self.network,
            block: latest_block_from_proto(snapshot)?,
            objects,
            holdings,
        }))
    }
}
