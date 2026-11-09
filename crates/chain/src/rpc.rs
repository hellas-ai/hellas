//! Local implementation of the light-client query interface.

#[cfg(feature = "validator")]
use crate::app::{Mempool, MempoolEntry, RESPONSE_MEMPOOL_CAPACITY};
#[cfg(feature = "validator")]
use crate::domain::{ObjectKind, edge_object_id, registry_chunk_object_id};
#[cfg(feature = "validator")]
use hellas_kernel::pending_payment_close_slot;
#[cfg(feature = "validator")]
use std::collections::{BTreeMap, btree_map::Entry};

use crate::domain::{Object, ObjectId, SettlementKey, Transaction};
use crate::{
    execution::store::{UtxoDatabase, UtxoDb},
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, FinalizedBlock, FinalizedBlockQuery, Holdings, LatestBlock, LightClient,
        ObjectSnapshot, QueryError, Verified,
    },
    owner_index::{OwnerCursor, OwnerIndex},
    work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot},
};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::sha256::Digest;
use hellas_kernel::NetworkId;
#[cfg(feature = "validator")]
use hellas_kernel::{
    Batch as KernelBatch, BlockHash, BlockHeight, Coin as KernelCoin, CoinId,
    Context as KernelContext, Edge, EdgeId, InsertError, KernelResult, PaymentCloseResponse,
    RegistryChunk, RegistryChunkId, check_response,
};
use hellas_rpc::SubmitTxOutcome;

fn digest_from_proto(bytes: Vec<u8>, field: &str) -> Result<Digest, QueryError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| QueryError::InvalidTransaction(format!("{field} must be 32 bytes")))?;
    Ok(Digest::from(bytes))
}

fn owner_from_proto(bytes: Vec<u8>) -> Result<SettlementKey, QueryError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| QueryError::InvalidTransaction("owner must be 33 bytes".into()))?;
    Ok(SettlementKey::from_bytes(bytes))
}
#[cfg(feature = "validator")]
use hellas_rpc::observe::{LEVEL, TARGET, Timing};

/// In-process [`LightClient`] backed by the local application handle.
#[derive(Clone)]
pub struct LocalLightClient {
    databases: UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: OwnerIndex,
    ingress: TransactionIngress,
    #[cfg(feature = "full-node")]
    readiness: Option<std::sync::Arc<crate::node::Readiness>>,
    chain_indexer: ChainIndexer,
    consensus_info: ConsensusInfo,
    #[cfg(feature = "full-node")]
    history: Option<crate::node::replication::Network>,
    #[cfg(feature = "full-node")]
    runtime: Option<std::sync::Arc<crate::node::RuntimeGuard>>,
}

#[derive(Clone)]
enum TransactionIngress {
    #[cfg(feature = "validator")]
    Mempool(Mempool),
    #[cfg(feature = "full-node")]
    Validators(std::sync::Arc<[String]>),
}

impl LocalLightClient {
    #[cfg(feature = "validator")]
    pub fn new(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        owner_index: OwnerIndex,
        mempool: Mempool,
        chain_indexer: ChainIndexer,
        consensus_info: ConsensusInfo,
    ) -> Self {
        Self {
            databases,
            owner_index,
            ingress: TransactionIngress::Mempool(mempool),
            #[cfg(feature = "full-node")]
            readiness: None,
            chain_indexer,
            consensus_info,
            #[cfg(feature = "full-node")]
            runtime: None,
            #[cfg(feature = "full-node")]
            history: None,
        }
    }

    #[cfg(feature = "full-node")]
    pub(crate) fn full_node(
        databases: UtxoDatabase<commonware_runtime::tokio::Context>,
        owner_index: OwnerIndex,
        chain_indexer: ChainIndexer,
        consensus_info: ConsensusInfo,
        validators: Vec<String>,
        readiness: std::sync::Arc<crate::node::Readiness>,
    ) -> Self {
        Self {
            databases,
            owner_index,
            chain_indexer,
            consensus_info,
            ingress: TransactionIngress::Validators(validators.into()),
            readiness: Some(readiness),
            runtime: None,
            #[cfg(feature = "full-node")]
            history: None,
        }
    }

    #[cfg(feature = "full-node")]
    pub(crate) fn retain_node(
        mut self,
        runtime: std::sync::Arc<crate::node::RuntimeGuard>,
        history: crate::node::replication::Network,
    ) -> Self {
        self.runtime = Some(runtime);
        self.history = Some(history);
        self
    }

    fn require_ready(&self) -> Result<(), QueryError> {
        #[cfg(feature = "full-node")]
        if let Some(readiness) = &self.readiness {
            readiness.check()?;
        }
        Ok(())
    }

    #[cfg(feature = "validator")]
    fn mempool(&self) -> &Mempool {
        match &self.ingress {
            TransactionIngress::Mempool(pool) => pool,
            #[cfg(feature = "full-node")]
            TransactionIngress::Validators(_) => unreachable!("full nodes forward submissions"),
        }
    }

    #[cfg(feature = "validator")]
    async fn submit_general(&self, tx: Transaction) -> SubmitTxOutcome {
        self.mempool()
            .inner
            .lock()
            .await
            .admit_general(MempoolEntry::new(tx))
    }

    #[cfg(feature = "validator")]
    async fn submit_response(
        &self,
        response: PaymentCloseResponse,
    ) -> Result<SubmitTxOutcome, QueryError> {
        let Some(network) = NetworkId::new(&self.consensus_info.network_id) else {
            return Err(QueryError::StateUnavailable(format!(
                "network id `{}` does not fit a kernel NetworkId",
                self.consensus_info.network_id
            )));
        };
        let slot = (response.payment_edge(), response.start_id());
        let transaction = Transaction::Kernel(hellas_kernel::Tx::move_action(
            hellas_kernel::Move::RespondPaymentClose(response.clone()),
        ));
        let incoming = MempoolEntry::new(transaction);

        // Hold one finalized reader across authentication, the resident sweep,
        // and insertion. An unauthenticated newcomer is checked before taking
        // the mempool lock, so it cannot make the node reverify residents.
        let reader = self.databases.read().await;
        let state_root = reader.root();
        let cursor = self.owner_index.cursor();
        if cursor.height == 0 {
            return Err(QueryError::StateUnavailable(
                "no finalized application state is available".to_string(),
            ));
        }
        if cursor.state_root != state_root {
            return Err(QueryError::StateUnavailable(
                "owner index and application state are not synchronized".to_string(),
            ));
        }
        // The next block is stamped no earlier than this one, so a response
        // already late at this block's time is late at inclusion too.
        let Some(finalized) = self
            .chain_indexer
            .get_finalized_block(FinalizedBlockQuery::Payload(cursor.payload))
            .await?
        else {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        };
        let cursor_time_ms = crate::block_view::FinalizedBlockView::decode(&finalized)
            .map_err(|error| QueryError::StateUnavailable(error.to_string()))?
            .timestamp();
        let Some(admission_height) = cursor.height.checked_add(1) else {
            return Err(QueryError::StateUnavailable(
                "finalized height has no successor for response admission".to_string(),
            ));
        };
        let context = KernelContext::with_fees(
            network,
            BlockHeight::new(admission_height),
            cursor_time_ms,
            BlockHash::from_bytes(cursor.payload.0),
            crate::domain::KERNEL_FEES,
        );

        let mut batch = ResponseAdmissionBatch::default();
        let incoming_edge = response.payment_edge();
        match reader
            .get(&edge_object_id(incoming_edge))
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("edge read failed: {error:?}")))?
        {
            Some(Object::Edge(edge)) => {
                batch.edges.insert(incoming_edge, edge);
            }
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Edge,
                    actual: object.kind(),
                });
            }
            None => {}
        }
        let incoming_pending = pending_payment_close_slot(network, incoming_edge);
        match reader
            .get(&registry_chunk_object_id(incoming_pending))
            .await
            .map_err(|error| {
                QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
            })? {
            Some(Object::RegistryChunk(chunk)) => {
                batch.registry.insert(incoming_pending, chunk);
            }
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::RegistryChunk,
                    actual: object.kind(),
                });
            }
            None => {}
        }

        let verifier = crate::execution::ChainVerifier::new();
        // `validation_ms`: the extracted response validator, the one §4
        // adds to a validator's RPC and its worker. Both an admitted and
        // a rejected response paid for it, so both are sampled — the
        // rejection is validation that ran, not validation that did not.
        let validated = Timing::start();
        let admissible = check_response(&response, context, &verifier, &batch).is_ok();
        if let Some(ms) = validated.ms() {
            tracing::event!(
                name: "validation_ms",
                target: TARGET,
                LEVEL,
                edge = ?incoming_edge,
                start_id = ?response.start_id(),
                admissible,
                ms,
            );
        }
        if !admissible {
            return Ok(SubmitTxOutcome::ValidationRejected);
        }

        // Serialize the sweep and insertion only after the newcomer has
        // authenticated. Residents are still judged against the same reader.
        let mut mempool = self.mempool().inner.lock().await;
        let residents: Vec<PaymentCloseResponse> = mempool
            .responses
            .values()
            .filter_map(|entry| payment_close_response(&entry.transaction).cloned())
            .collect();
        for candidate in residents.iter() {
            let edge_id = candidate.payment_edge();
            if let Entry::Vacant(slot) = batch.edges.entry(edge_id) {
                match reader
                    .get(&edge_object_id(edge_id))
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("edge read failed: {error:?}"))
                    })? {
                    Some(Object::Edge(edge)) => {
                        slot.insert(edge);
                    }
                    Some(object) => {
                        return Err(QueryError::WrongObjectKind {
                            expected: ObjectKind::Edge,
                            actual: object.kind(),
                        });
                    }
                    None => {}
                }
            }
            let pending_id = pending_payment_close_slot(network, edge_id);
            if let Entry::Vacant(slot) = batch.registry.entry(pending_id) {
                match reader
                    .get(&registry_chunk_object_id(pending_id))
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
                    })? {
                    Some(Object::RegistryChunk(chunk)) => {
                        slot.insert(chunk);
                    }
                    Some(object) => {
                        return Err(QueryError::WrongObjectKind {
                            expected: ObjectKind::RegistryChunk,
                            actual: object.kind(),
                        });
                    }
                    None => {}
                }
            }
        }

        mempool.responses.retain(|_, resident| {
            payment_close_response(&resident.transaction).is_some_and(|resident_response| {
                check_response(resident_response, context, &verifier, &batch).is_ok()
            })
        });
        if mempool
            .responses
            .get(&slot)
            .is_some_and(|resident| resident.digest == incoming.digest)
        {
            return Ok(SubmitTxOutcome::Duplicate);
        }

        if mempool.responses.contains_key(&slot)
            || mempool.responses.len() >= RESPONSE_MEMPOOL_CAPACITY
        {
            return Ok(SubmitTxOutcome::Full);
        }
        mempool.responses.insert(slot, incoming);
        Ok(SubmitTxOutcome::Enqueued)
    }
}

#[cfg(feature = "validator")]
fn payment_close_response(transaction: &Transaction) -> Option<&PaymentCloseResponse> {
    let Transaction::Kernel(hellas_kernel::Tx::Move {
        action: hellas_kernel::Move::RespondPaymentClose(response),
    }) = transaction
    else {
        return None;
    };
    Some(response)
}

#[cfg(feature = "validator")]
#[derive(Default)]
struct ResponseAdmissionBatch {
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

#[cfg(feature = "validator")]
impl KernelBatch for ResponseAdmissionBatch {
    fn coin(&self, _id: CoinId) -> Option<KernelCoin> {
        None
    }
    fn insert_coin(&mut self, _id: CoinId, _coin: KernelCoin) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_coin(&mut self, _id: CoinId) -> Option<KernelCoin> {
        None
    }
    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }
    fn insert_edge(&mut self, _id: EdgeId, _edge: Edge) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_edge(&mut self, _id: EdgeId) -> Option<Edge> {
        None
    }
    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.registry.get(&id).copied()
    }
    fn insert_registry_chunk(
        &mut self,
        _id: RegistryChunkId,
        _chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        Err(InsertError::Unavailable)
    }
    fn remove_registry_chunk(&mut self, _id: RegistryChunkId) -> Option<RegistryChunk> {
        None
    }
    fn commit(self) {}
}

/// The finalized block whose state `reader` holds. Glue commits a finalized
/// block, then calls `App::finalized`, which publishes its owner cursor, and
/// commits nothing else until that returns. Under the read guard the state is
/// therefore the published cursor's block or the next finalized block.
async fn coherent_reader<'a>(
    databases: &'a UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
) -> Result<
    (
        commonware_glue::stateful::db::ReadGuard<'a, UtxoDb<commonware_runtime::tokio::Context>>,
        OwnerCursor,
    ),
    QueryError,
> {
    let reader = databases.read().await;
    let cursor = owner_index.cursor();
    if reader.root() == cursor.state_root {
        return Ok((reader, cursor));
    }
    // Marshal reports blocks without awaiting the application, so this lookup
    // cannot wait on the commit that the read guard holds back.
    let next = chain_indexer
        .get_finalized_block(FinalizedBlockQuery::Height(cursor.height.saturating_add(1)))
        .await?
        .map(|block| block.snapshot)
        .filter(|next| next.state_root == reader.root())
        .ok_or_else(|| {
            QueryError::StateUnavailable("database state is not a finalized block".into())
        })?;
    Ok((
        reader,
        OwnerCursor {
            height: next.height,
            payload: next.payload,
            state_root: next.state_root,
        },
    ))
}

/// One object request read under one database snapshot: the keys, plus one
/// holdings page of an owner. Both routes answer from it; the proven route
/// adds proofs at the same reader and root.
struct Lookup<'a> {
    reader:
        commonware_glue::stateful::db::ReadGuard<'a, UtxoDb<commonware_runtime::tokio::Context>>,
    cursor: OwnerCursor,
    objects: Vec<(ObjectId, Option<Object>)>,
    page: Option<crate::owner_proof::OwnerPageProof>,
}

/// `Ok(None)` means there is no applied finalized state to answer from yet.
async fn lookup<'a>(
    databases: &'a UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    mut keys: std::collections::BTreeSet<ObjectId>,
    owner: Option<(SettlementKey, Option<[u8; 32]>)>,
    wanted: Option<Digest>,
) -> Result<Option<Lookup<'a>>, QueryError> {
    if owner_index.cursor().height == 0 {
        if wanted.is_some() {
            return Err(QueryError::StateUnavailable(
                "requested current-state snapshot is unavailable".into(),
            ));
        }
        return Ok(None);
    }
    let (reader, cursor) = coherent_reader(databases, owner_index, chain_indexer).await?;
    if wanted.is_some_and(|wanted| wanted != cursor.payload) {
        return Err(QueryError::StateUnavailable(
            "requested current-state snapshot is unavailable".into(),
        ));
    }
    let page = match owner {
        Some((owner, after)) => {
            let page = crate::execution::owner_tree::prove_stored_owner_page_after(
                &reader,
                owner,
                after,
                crate::owner_proof::OWNER_PAGE_LIMIT,
            )
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("owner page: {error}")))?;
            keys.extend(
                page.holdings
                    .iter()
                    .map(|holding| ObjectId::from(holding.object_id)),
            );
            Some(page)
        }
        None => None,
    };
    if keys.len() > crate::proof_verify::MAX_CURRENT_KEYS {
        return Err(QueryError::InvalidTransaction(
            "owner page and object keys exceed 32".into(),
        ));
    }
    let mut objects = Vec::with_capacity(keys.len());
    for key in keys {
        let object = reader
            .get(&key)
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("object read: {error:?}")))?;
        objects.push((key, object));
    }
    Ok(Some(Lookup {
        reader,
        cursor,
        objects,
        page,
    }))
}

impl Lookup<'_> {
    /// The block the lookup was read at, and that block's timestamp.
    async fn snapshot(
        &self,
        chain_indexer: &ChainIndexer,
    ) -> Result<(LatestBlock, u64), QueryError> {
        let finalized = chain_indexer
            .get_finalized_block(FinalizedBlockQuery::Payload(self.cursor.payload))
            .await?
            .ok_or_else(|| QueryError::StateUnavailable("finalization is unavailable".into()))?;
        let timestamp = crate::block_view::FinalizedBlockView::decode(&finalized)
            .map_err(|error| QueryError::StateUnavailable(error.to_string()))?
            .timestamp();
        Ok((
            LatestBlock {
                height: self.cursor.height,
                payload: self.cursor.payload,
                state_root: self.reader.root(),
                finalization: finalized.snapshot.finalization,
            },
            timestamp,
        ))
    }

    fn holdings(&self) -> Option<Holdings> {
        self.page.as_ref().map(|page| {
            let keys = page
                .holdings
                .iter()
                .map(|holding| ObjectId::from(holding.object_id))
                .collect();
            Holdings::new(keys, page.offset, page.summary().count)
        })
    }
}

/// This node's own read: it executed the state, so the snapshot is verified
/// without a proof.
async fn read_objects(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    network: NetworkId,
    keys: std::collections::BTreeSet<ObjectId>,
    owner: Option<(SettlementKey, Option<ObjectId>)>,
) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
    let owner = owner.map(|(owner, after)| (owner, after.map(|key| key.0)));
    let Some(found) = lookup(databases, owner_index, chain_indexer, keys, owner, None).await?
    else {
        return Ok(None);
    };
    let (block, certified_at_ms) = found.snapshot(chain_indexer).await?;
    let holdings = found.holdings();
    Ok(Some(Verified::new(ObjectSnapshot {
        network,
        block,
        certified_at_ms,
        objects: found
            .objects
            .into_iter()
            .filter_map(|(key, object)| object.map(|object| (key, object)))
            .collect(),
        holdings,
    })))
}

/// Reads every object of one work channel under one database snapshot.
///
/// The reader is taken once and every object comes out of it, which is
/// the whole point: separate `get` calls would answer from up to as many
/// states, and the combinations that produces read as healthy channels
/// that never existed.
///
/// The queried funding coins come out of that same reader, not out of
/// the owner index and not out of a second call. A setup decision locks
/// a provider's stake on the premise that the client's funding is still
/// live, and a coin read at any other state is a premise about a state
/// the decision is not being made at.
async fn work_channel_snapshot_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    network: NetworkId,
    query: WorkChannelQuery,
) -> Result<Option<Verified<WorkChannelSnapshot>>, QueryError> {
    let keys = query
        .object_keys(network)
        .into_iter()
        .map(crate::domain::ObjectKey::id)
        .collect();
    let Some(snapshot) =
        read_objects(databases, owner_index, chain_indexer, network, keys, None).await?
    else {
        return Ok(None);
    };
    let snapshot = WorkChannelSnapshot::from_objects(network, query, snapshot.into_inner())?;
    Ok(Some(Verified::new(snapshot)))
}

impl FinalizedWorkView for LocalLightClient {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<Verified<WorkChannelSnapshot>>, QueryError> {
        self.require_ready()?;
        // The registry slots are keyed by network, so a node whose
        // genesis names an id the kernel cannot carry cannot derive
        // them. Answering with slots derived from some other id would
        // be answering about a different chain's channel.
        let Some(network) = NetworkId::new(&self.consensus_info.network_id) else {
            return Err(QueryError::StateUnavailable(format!(
                "network id `{}` does not fit a kernel NetworkId",
                self.consensus_info.network_id
            )));
        };
        work_channel_snapshot_at(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            network,
            query,
        )
        .await
    }
}

impl LocalLightClient {
    fn network(&self) -> Result<NetworkId, QueryError> {
        NetworkId::new(&self.consensus_info.network_id)
            .ok_or_else(|| QueryError::Remote("invalid chain network".into()))
    }

    /// The lookup a wire request names. `Ok(None)` before any applied state.
    async fn lookup_request(
        &self,
        request: hellas_rpc::pb::chain::GetObjectProofsRequest,
    ) -> Result<Option<Lookup<'_>>, QueryError> {
        self.require_ready()?;
        let keys = request
            .object_ids
            .into_iter()
            .map(|id| digest_from_proto(id, "object_id"))
            .collect::<Result<std::collections::BTreeSet<_>, QueryError>>()?;
        let owner = request.owner.map(owner_from_proto).transpose()?;
        let after = request
            .owner_after_key
            .map(|key| digest_from_proto(key, "owner cursor").map(|key| key.0))
            .transpose()?;
        if owner.is_none() && after.is_some() {
            return Err(QueryError::InvalidTransaction(
                "invalid owner page request".into(),
            ));
        }
        let wanted = request
            .payload
            .map(|payload| digest_from_proto(payload, "payload"))
            .transpose()?;
        lookup(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            keys,
            owner.map(|owner| (owner, after)),
            wanted,
        )
        .await
    }
}

impl LightClient for LocalLightClient {
    async fn get_object_proofs(
        &self,
        request: hellas_rpc::pb::chain::GetObjectProofsRequest,
    ) -> Result<hellas_rpc::pb::chain::GetObjectProofsResponse, QueryError> {
        use commonware_codec::Encode as _;
        let Some(found) = self.lookup_request(request).await? else {
            return Ok(hellas_rpc::pb::chain::GetObjectProofsResponse::default());
        };
        let finalized = self
            .chain_indexer
            .get_finalized_block(FinalizedBlockQuery::Payload(found.cursor.payload))
            .await?
            .ok_or_else(|| {
                QueryError::StateUnavailable("applied finalized block is unavailable".into())
            })?;
        let mut proofs = Vec::with_capacity(found.objects.len());
        for (key, object) in found.objects {
            let proof = if object.is_some() {
                found
                    .reader
                    .key_value_proof(key)
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("inclusion proof: {error:?}"))
                    })?
                    .encode()
                    .to_vec()
            } else {
                found
                    .reader
                    .exclusion_proof(&key)
                    .await
                    .map_err(|error| {
                        QueryError::StateUnavailable(format!("exclusion proof: {error:?}"))
                    })?
                    .encode()
                    .to_vec()
            };
            proofs.push(hellas_rpc::pb::chain::ObjectProof {
                object_id: key.to_vec(),
                object: object.map(|value| value.encode().to_vec()),
                proof,
            });
        }
        Ok(hellas_rpc::pb::chain::GetObjectProofsResponse {
            block: Some(crate::server::finalized_block_to_proto(finalized)),
            proofs,
            owner_page: found
                .page
                .map(crate::owner_proof::OwnerPageProof::into_proto),
        })
    }

    async fn get_plain_objects(
        &self,
        request: hellas_rpc::pb::chain::GetObjectProofsRequest,
    ) -> Result<hellas_rpc::pb::chain::GetObjectsResponse, QueryError> {
        use commonware_codec::Encode as _;
        let Some(found) = self.lookup_request(request).await? else {
            return Ok(hellas_rpc::pb::chain::GetObjectsResponse::default());
        };
        let (snapshot, _) = found.snapshot(&self.chain_indexer).await?;
        Ok(hellas_rpc::pb::chain::GetObjectsResponse {
            snapshot: Some(crate::server::latest_block_to_proto(snapshot)),
            objects: found
                .objects
                .into_iter()
                .map(|(key, object)| hellas_rpc::pb::chain::ObjectEntry {
                    object_id: key.to_vec(),
                    object: object.map(|value| value.encode().to_vec()),
                })
                .collect(),
            owner_page: found.page.map(|page| hellas_rpc::pb::chain::OwnerPage {
                summary: Some(page.summary().into_proto()),
                offset: page.offset,
                holdings: page
                    .holdings
                    .iter()
                    .map(|holding| holding.object_id.to_vec())
                    .collect(),
            }),
        })
    }

    async fn get_objects(
        &self,
        keys: Vec<crate::domain::ObjectKey>,
    ) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
        self.require_ready()?;
        read_objects(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            self.network()?,
            keys.into_iter().map(crate::domain::ObjectKey::id).collect(),
            None,
        )
        .await
    }

    async fn get_holdings(
        &self,
        owner: SettlementKey,
        after: Option<ObjectId>,
    ) -> Result<Option<Verified<ObjectSnapshot>>, QueryError> {
        self.require_ready()?;
        read_objects(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            self.network()?,
            Default::default(),
            Some((owner, after)),
        )
        .await
    }

    async fn get_state_root(&self) -> Result<Option<Digest>, QueryError> {
        self.require_ready()?;
        Ok(Some(self.databases.read().await.root()))
    }

    async fn get_proof(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>, QueryError> {
        let _ = object_id;
        Err(QueryError::StateUnavailable(
            "key proofs are not available".to_string(),
        ))
    }

    async fn get_finalization(&self, payload: Digest) -> Result<Option<Vec<u8>>, QueryError> {
        #[cfg(feature = "full-node")]
        if let Some(readiness) = &self.readiness {
            readiness.running()?;
        }
        self.chain_indexer.get_finalization(payload).await
    }

    async fn get_latest_block(&self) -> Result<Option<LatestBlock>, QueryError> {
        self.require_ready()?;
        self.chain_indexer.get_latest_block().await
    }

    async fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        #[cfg(feature = "full-node")]
        if let Some(readiness) = &self.readiness {
            readiness.running()?;
        }
        let block = self.chain_indexer.get_finalized_block(query).await?;
        #[cfg(feature = "full-node")]
        if block.is_none()
            && let FinalizedBlockQuery::Height(height) = query
            && let Some(history) = &self.history
        {
            if height > self.owner_index.cursor().height {
                return Err(QueryError::StateUnavailable(
                    "requested block is not locally executed".into(),
                ));
            }
            return history
                .fetch(FinalizedBlockQuery::Height(height))
                .await
                .ok_or_else(|| {
                    QueryError::StateUnavailable(
                        "no peer retains the required finalized block".into(),
                    )
                })
                .map(Some);
        }
        Ok(block)
    }

    async fn get_applied_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> Result<Option<FinalizedBlock>, QueryError> {
        self.require_ready()?;
        let (reader, cursor) =
            coherent_reader(&self.databases, &self.owner_index, &self.chain_indexer).await?;
        let selected = if matches!(query, FinalizedBlockQuery::Latest) {
            FinalizedBlockQuery::Payload(cursor.payload)
        } else {
            query
        };
        let Some(block) = self.chain_indexer.get_finalized_block(selected).await? else {
            return Ok(None);
        };
        let target = crate::HellasBlock::decode(block.block.as_slice())
            .map_err(|error| QueryError::StateUnavailable(format!("applied block: {error:?}")))?
            .sync_target();
        let bounds = reader.bounds();
        if block.snapshot.height > cursor.height || target.range.end() > bounds.end {
            return Err(QueryError::NotYetApplied);
        }
        if matches!(query, FinalizedBlockQuery::Latest)
            && (block.snapshot.state_root != reader.root() || target.range.end() != bounds.end)
        {
            return Err(QueryError::StateUnavailable(
                "applied checkpoint does not match committed state".into(),
            ));
        }
        Ok(Some(block))
    }

    fn submit_tx(
        &self,
        tx: Transaction,
    ) -> impl std::future::Future<Output = Result<SubmitTxOutcome, QueryError>> + Send {
        // Keep transport establishment and validator execution frames off the
        // caller's stack; setup and close drivers compose this future deeply.
        Box::pin(async move {
            if crate::light_client::canonical_submission_size(&tx)
                > crate::MAX_CANONICAL_TRANSACTION_BYTES
            {
                return Err(QueryError::InvalidTransaction(format!(
                    "canonical transaction exceeds {} bytes",
                    crate::MAX_CANONICAL_TRANSACTION_BYTES,
                )));
            }
            match &self.ingress {
                #[cfg(feature = "validator")]
                TransactionIngress::Mempool(_) => {
                    if let Some(response) = payment_close_response(&tx).cloned() {
                        self.submit_response(response).await
                    } else {
                        Ok(self.submit_general(tx).await)
                    }
                }
                #[cfg(feature = "full-node")]
                TransactionIngress::Validators(validators) => {
                    let mut error = QueryError::Connect("no validator seed is reachable".into());
                    for address in validators.iter() {
                        let result =
                            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                                crate::client::forward_submission(address, tx.clone()).await
                            })
                            .await;
                        match result {
                            Ok(Ok(outcome)) => return Ok(outcome),
                            Ok(Err(failure)) => error = failure,
                            Err(_) => {}
                        }
                    }
                    Err(error)
                }
            }
        })
    }

    async fn get_validators(&self) -> Result<Vec<String>, QueryError> {
        Ok(self.consensus_info.validators.clone())
    }

    async fn get_consensus_info(&self) -> Result<ConsensusInfo, QueryError> {
        Ok(self.consensus_info.clone())
    }
}

#[cfg(all(test, feature = "validator"))]
mod tests;
