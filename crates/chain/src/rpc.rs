//! Local implementation of the light-client query interface.

#[cfg(feature = "validator")]
use crate::app::{Mempool, MempoolEntry, RESPONSE_MEMPOOL_CAPACITY};
#[cfg(all(test, feature = "validator"))]
use crate::owner_index::OwnerIndexError;
use std::collections::BTreeSet;
#[cfg(feature = "validator")]
use std::collections::{BTreeMap, btree_map::Entry};

use crate::domain::{
    Coin, Object, ObjectId, ObjectKind, SettlementKey, Transaction, coin_object_id, edge_object_id,
    registry_chunk_object_id,
};
use crate::{
    execution::store::UtxoDatabase,
    indexer::ChainIndexer,
    light_client::{
        ConsensusInfo, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock, FinalizedBlockQuery,
        LatestBlock, LightClient, OwnerCoins, OwnerEdges, QueryError,
    },
    owner_index::OwnerIndex,
    work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot},
};
use commonware_cryptography::sha256::Digest;
#[cfg(feature = "validator")]
use hellas_kernel::{
    Batch as KernelBatch, BlockHash, BlockHeight, Coin as KernelCoin, CoinId,
    Context as KernelContext, Edge, EdgeId, InsertError, KernelResult, PaymentCloseResponse,
    RegistryChunk, RegistryChunkId, check_response,
};
use hellas_kernel::{NetworkId, bond_lease_slots, pending_payment_close_slot};
use hellas_rpc::SubmitTxOutcome;
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
        let entry = MempoolEntry::new(tx);
        let mut mempool = self.mempool().inner.lock().await;
        if mempool
            .general
            .iter()
            .any(|resident| resident.digest == entry.digest)
        {
            return SubmitTxOutcome::Duplicate;
        }
        if mempool.general.len() >= crate::GENERAL_MEMPOOL_CAPACITY {
            return SubmitTxOutcome::Full;
        }
        mempool.general.push_back(entry);
        SubmitTxOutcome::Enqueued
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
        let transaction = Transaction::Kernel(hellas_kernel::Tx::move_action(
            hellas_kernel::Move::RespondPaymentClose(response),
        ));
        let incoming = MempoolEntry::new(transaction);
        let slot = (response.payment_edge(), response.start_id());

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
        if self
            .chain_indexer
            .get_finalization(cursor.payload)
            .await?
            .is_none()
        {
            return Err(QueryError::StateUnavailable(
                "owner index cursor finalization is unavailable".to_string(),
            ));
        }
        let Some(admission_height) = cursor.height.checked_add(1) else {
            return Err(QueryError::StateUnavailable(
                "finalized height has no successor for response admission".to_string(),
            ));
        };
        let context = KernelContext::with_fees(
            network,
            BlockHeight::new(admission_height),
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
            .filter_map(|entry| payment_close_response(&entry.transaction).copied())
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

#[cfg(all(test, feature = "validator"))]
fn owner_lookup_error(error: OwnerIndexError) -> QueryError {
    match error {
        OwnerIndexError::WrongObjectKind {
            expected, actual, ..
        } => QueryError::WrongObjectKind { expected, actual },
        error => QueryError::StateUnavailable(format!("owner index lookup failed: {error}")),
    }
}

async fn finalized_floor_height(
    chain_indexer: &ChainIndexer,
    payload: Digest,
) -> Result<u64, QueryError> {
    let Some(finalized) = chain_indexer
        .get_finalized_block(FinalizedBlockQuery::Payload(payload))
        .await?
    else {
        return Err(QueryError::StateUnavailable(
            "requested payload is not finalized".to_string(),
        ));
    };
    Ok(finalized.snapshot.height)
}

fn require_finalized_floor(floor_height: u64, cursor_height: u64) -> Result<(), QueryError> {
    if floor_height > cursor_height {
        return Err(QueryError::StateUnavailable(
            "requested payload is newer than the application state".to_string(),
        ));
    }
    Ok(())
}

async fn get_edge_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<EdgeLookup>, QueryError> {
    let cursor = owner_index.cursor();
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;

    let reader = databases.read().await;
    let state_root = reader.root();
    let cursor = owner_index.cursor();
    require_finalized_floor(floor_height, cursor.height)?;
    if cursor.state_root != state_root {
        return Err(QueryError::StateUnavailable(
            "owner index and application state are not synchronized".to_string(),
        ));
    }
    let edge = match reader
        .get(&object_id)
        .await
        .map_err(|error| QueryError::StateUnavailable(format!("edge read failed: {error:?}")))?
    {
        Some(Object::Edge(edge)) => Some(EdgeState::from(edge)),
        Some(object) => {
            return Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Edge,
                actual: object.kind(),
            });
        }
        None => None,
    };
    Ok(Some(EdgeLookup { state_root, edge }))
}

#[cfg(all(test, feature = "validator"))]
async fn get_coin_at(
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    payload: Digest,
    object_id: ObjectId,
) -> Result<Option<Coin>, QueryError> {
    let (cursor, coin) = owner_index.get_coin_snapshot(&object_id);
    if cursor.height == 0 {
        return Ok(None);
    }
    let floor_height = finalized_floor_height(chain_indexer, payload).await?;
    require_finalized_floor(floor_height, cursor.height)?;
    coin.map_err(owner_lookup_error)
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
///
/// The state the reader holds is the state the owner index has applied
/// up to, so the finalized block reported beside the objects is that
/// index's cursor. If the two have drifted apart between the two reads
/// the whole snapshot is refused rather than reported at a block it was
/// not read at.
async fn work_channel_snapshot_at(
    databases: &UtxoDatabase<commonware_runtime::tokio::Context>,
    owner_index: &OwnerIndex,
    chain_indexer: &ChainIndexer,
    network: NetworkId,
    query: WorkChannelQuery,
) -> Result<Option<WorkChannelSnapshot>, QueryError> {
    let reader = databases.read().await;
    let state_root = reader.root();
    // Read after the reader is held: a cursor sampled before it says
    // nothing about the state the objects will come out of.
    let cursor = owner_index.cursor();
    if cursor.height == 0 {
        return Ok(None);
    }
    if cursor.state_root != state_root {
        return Err(QueryError::StateUnavailable(
            "owner index and application state are not synchronized".to_string(),
        ));
    }
    let Some(finalization) = chain_indexer.get_finalization(cursor.payload).await? else {
        return Err(QueryError::StateUnavailable(
            "owner index cursor finalization is unavailable".to_string(),
        ));
    };

    let mut bond = None;
    let mut payment = None;
    for (slot, edge) in [
        (&mut bond, query.bond_edge),
        (&mut payment, query.payment_edge),
    ] {
        *slot =
            match reader.get(&edge_object_id(edge)).await.map_err(|error| {
                QueryError::StateUnavailable(format!("edge read failed: {error:?}"))
            })? {
                Some(Object::Edge(edge)) => Some(edge),
                Some(object) => {
                    return Err(QueryError::WrongObjectKind {
                        expected: ObjectKind::Edge,
                        actual: object.kind(),
                    });
                }
                None => None,
            };
    }

    let [first_lease, second_lease] = bond_lease_slots(network, query.bond_edge);
    let mut registry = [None, None, None];
    for (stored, id) in registry.iter_mut().zip([
        first_lease,
        second_lease,
        pending_payment_close_slot(network, query.payment_edge),
    ]) {
        *stored = match reader
            .get(&registry_chunk_object_id(id))
            .await
            .map_err(|error| {
                QueryError::StateUnavailable(format!("registry read failed: {error:?}"))
            })? {
            Some(Object::RegistryChunk(chunk)) => Some(chunk),
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::RegistryChunk,
                    actual: object.kind(),
                });
            }
            None => None,
        };
    }
    let [lease_first, lease_second, pending_slot] = registry;

    let mut live_funding = BTreeSet::new();
    for coin in &query.funding {
        match reader
            .get(&coin_object_id(*coin))
            .await
            .map_err(|error| QueryError::StateUnavailable(format!("coin read failed: {error:?}")))?
        {
            Some(Object::Coin(_)) => {
                live_funding.insert(*coin);
            }
            // A spent coin is absent, and that is the answer the
            // preflight wants. An object of another kind under a coin's
            // derived id is not an answer at all.
            None => {}
            Some(object) => {
                return Err(QueryError::WrongObjectKind {
                    expected: ObjectKind::Coin,
                    actual: object.kind(),
                });
            }
        }
    }

    Ok(Some(WorkChannelSnapshot::new(
        query,
        LatestBlock {
            height: cursor.height,
            payload: cursor.payload,
            state_root,
            finalization,
        },
        bond,
        payment,
        [lease_first, lease_second],
        pending_slot,
        live_funding,
    )))
}

impl FinalizedWorkView for LocalLightClient {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
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

impl LightClient for LocalLightClient {
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

    async fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<Coin>, QueryError> {
        self.require_ready()?;
        let floor = finalized_floor_height(&self.chain_indexer, payload).await?;
        let reader = self.databases.read().await;
        let cursor = self.owner_index.cursor();
        require_finalized_floor(floor, cursor.height)?;
        if reader.root() != cursor.state_root {
            return Err(QueryError::StateUnavailable(
                "finalized state is being published".into(),
            ));
        }
        match reader
            .get(&object_id)
            .await
            .map_err(|e| QueryError::StateUnavailable(format!("{e:?}")))?
        {
            Some(Object::Coin(coin)) => Ok(Some(coin)),
            None => Ok(None),
            Some(object) => Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Coin,
                actual: object.kind(),
            }),
        }
    }

    async fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> Result<Option<EdgeLookup>, QueryError> {
        self.require_ready()?;
        get_edge_at(
            &self.databases,
            &self.owner_index,
            &self.chain_indexer,
            payload,
            object_id,
        )
        .await
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
                    if let Some(response) = payment_close_response(&tx).copied() {
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
                                crate::client::RemoteLightClient::connect(address.clone())
                                    .await?
                                    .submit_tx(tx.clone())
                                    .await
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

    async fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerCoins>, QueryError> {
        let (snapshot, holdings) = self.owner_objects(owner).await?;
        Ok(snapshot.map(|snapshot| OwnerCoins {
            snapshot,
            coins: holdings
                .into_iter()
                .filter_map(|(id, object)| match object {
                    Object::Coin(coin) => Some((id, coin.value)),
                    _ => None,
                })
                .collect(),
        }))
    }

    async fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> Result<Option<OwnerEdges>, QueryError> {
        let (snapshot, holdings) = self.owner_objects(owner).await?;
        Ok(snapshot.map(|snapshot| OwnerEdges {
            snapshot,
            edges: holdings
                .into_iter()
                .filter_map(|(object_id, object)| match object {
                    Object::Edge(edge) => Some(EdgeRecord {
                        object_id,
                        maker: edge.parties().maker().into(),
                        taker: edge.parties().taker().into(),
                    }),
                    _ => None,
                })
                .collect(),
        }))
    }
}

#[cfg(all(test, feature = "validator"))]
mod tests;

impl LocalLightClient {
    async fn owner_objects(
        &self,
        owner: SettlementKey,
    ) -> Result<(Option<LatestBlock>, Vec<(ObjectId, Object)>), QueryError> {
        self.require_ready()?;
        let reader = self.databases.read().await;
        let cursor = self.owner_index.cursor();
        if cursor.height == 0 {
            return Ok((None, vec![]));
        }
        if reader.root() != cursor.state_root {
            return Err(QueryError::StateUnavailable(
                "finalized state is being published".into(),
            ));
        }
        let finalization = self
            .chain_indexer
            .get_finalization(cursor.payload)
            .await?
            .ok_or_else(|| QueryError::StateUnavailable("finalization is unavailable".into()))?;
        let mut objects = Vec::new();
        let mut offset = 0;
        loop {
            let page = crate::execution::owner_tree::prove_stored_owner_page(
                &reader,
                owner,
                offset,
                crate::owner_proof::OWNER_PAGE_LIMIT,
            )
            .await
            .map_err(|e| QueryError::StateUnavailable(e.to_string()))?;
            for holding in &page.holdings {
                let id = Digest::from(holding.object_id);
                let object = reader
                    .get(&id)
                    .await
                    .map_err(|e| QueryError::StateUnavailable(format!("{e:?}")))?
                    .ok_or_else(|| {
                        QueryError::StateUnavailable("owner holding has no object".into())
                    })?;
                objects.push((id, object));
            }
            if page.holdings.len() < crate::owner_proof::OWNER_PAGE_LIMIT as usize {
                break;
            }
            offset += page.holdings.len() as u64;
        }
        Ok((
            Some(LatestBlock {
                height: cursor.height,
                payload: cursor.payload,
                state_root: cursor.state_root,
                finalization,
            }),
            objects,
        ))
    }
}
