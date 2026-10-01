//! ChainSync is a transport adapter for Commonware's resolver and marshal feed.
use super::*;
use crate::execution::store::UtxoDatabase;
use bytes::Bytes;
use commonware_codec::Decode;
use commonware_consensus::{
    CertifiableBlock, Reporter, marshal::resolver::handler, simplex::types::Activity,
};
use commonware_resolver::opaque;
use commonware_storage::{mmr, qmdb::sync::resolver as state};
use commonware_utils::channel::oneshot;
use futures_util::{StreamExt, stream::FuturesUnordered};
use hellas_rpc::{
    pb::{chain as pb, swarm},
    peers::{
        DiscoverySource, PeerDirectory, PeerDirectoryConfig, PeerId, PeerManager, RpcObservation,
        ServiceAlias, TransportSecurity,
    },
    services::{
        chain_sync::{ChainSync, ChainSyncClientImpl, GetFinalizedBlock, GetOperations},
        node::{Node, NodeClientImpl},
    },
};
use hellas_wire::{ServiceMarker, iroh::IrohTransport};
use rand::seq::SliceRandom;
use std::{collections::BTreeMap, sync::Mutex as StdMutex, time::Duration};

pub(super) const TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const MAX_PEERS: usize = 64;
type Client = Arc<ChainSyncClientImpl<IrohTransport>>;

#[derive(Clone)]
pub(crate) struct Network {
    pub endpoint: iroh::Endpoint,
    pub directory: PeerDirectory,
    hints: Arc<StdMutex<BTreeMap<iroh::EndpointId, iroh::EndpointAddr>>>,
    clients: Arc<StdMutex<BTreeMap<iroh::EndpointId, Arc<tokio::sync::OnceCell<Client>>>>>,
    pub trust: Trust,
    database: Arc<std::sync::OnceLock<UtxoDatabase<runtime::Context>>>,
}
impl Network {
    pub fn new(endpoint: iroh::Endpoint, trust: Trust) -> Self {
        let directory = PeerDirectory::with_config(
            peer(endpoint.id()),
            PeerDirectoryConfig {
                registry: hellas_rpc::peers::PeerRegistryConfig {
                    max_peers: 128,
                    bucket_capacity: 64.0,
                    bucket_refill_per_sec: 32.0,
                    ..Default::default()
                },
                service_aliases: vec![ServiceAlias::new(ChainSync::ALPN, ChainSync::NAME)],
                ..Default::default()
            },
        );
        Self {
            endpoint,
            directory,
            trust,
            hints: Default::default(),
            clients: Default::default(),
            database: Default::default(),
        }
    }
    pub fn manager(&self) -> PeerManager {
        self.directory.manager()
    }
    pub fn add(&self, address: iroh::EndpointAddr) {
        if address.id == self.endpoint.id() || self.manager().is_blocked(peer(address.id)) {
            return;
        }
        let mut hints = self.hints.lock().unwrap();
        if hints.len() < MAX_PEERS {
            hints.entry(address.id).or_insert(address);
        }
    }
    pub fn seed(&self, address: iroh::EndpointAddr) {
        let id = peer(address.id);
        self.add(address);
        let _ = self.manager().observe_discovered_service::<ChainSync>(
            id,
            DiscoverySource::Manual,
            TransportSecurity::Untrusted,
        );
    }
    pub fn ids(&self) -> Vec<iroh::EndpointId> {
        self.directory
            .known_peers(peer(self.endpoint.id()), ChainSync::ALPN, MAX_PEERS)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| iroh::EndpointId::from_bytes(p.as_bytes()).ok())
            .collect()
    }
    pub fn block(&self, id: iroh::EndpointId) {
        let _ = self
            .manager()
            .block_peer(peer(id), Duration::from_secs(300));
        self.clients.lock().unwrap().remove(&id);
    }
    pub async fn discover(&self, address: iroh::EndpointAddr) {
        if self.manager().is_blocked(peer(address.id)) {
            return;
        }
        let _ = tokio::time::timeout(TIMEOUT, async {
            let connection = self
                .endpoint
                .connect(address.clone(), Node::ALPN.as_bytes())
                .await?;
            let client = NodeClientImpl::new(IrohTransport::new(connection.clone()));
            let result = async {
                let info = client.get_node_info(swarm::GetNodeInfoRequest {}).await?;
                if info.node_id != address.id.to_string() {
                    self.block(address.id);
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                if !info.service_alpns.iter().any(|a| a == ChainSync::ALPN) {
                    return Ok(());
                }
                self.add(address.clone());
                let _ = self.manager().observe_discovered_service::<ChainSync>(
                    peer(address.id),
                    DiscoverySource::Transport("iroh"),
                    TransportSecurity::Authenticated,
                );
                let found = client
                    .get_known_peers(swarm::GetKnownPeersRequest {
                        service_alpn: ChainSync::ALPN.into(),
                    })
                    .await?;
                for bytes in found.peer_ids.into_iter().take(MAX_PEERS) {
                    if let Ok(raw) = <[u8; 32]>::try_from(bytes)
                        && let Ok(id) = iroh::EndpointId::from_bytes(&raw)
                    {
                        self.add(id.into());
                    }
                }
                Ok(())
            }
            .await;
            connection.close(0u32.into(), b"discovery complete");
            result
        })
        .await;
    }
    pub async fn client(&self, id: iroh::EndpointId) -> Result<Client, Error> {
        if self.manager().is_blocked(peer(id)) {
            return Err(invalid("peer is quarantined"));
        }
        let cell = {
            let mut clients = self.clients.lock().unwrap();
            if clients.len() >= MAX_PEERS + 8 && !clients.contains_key(&id) {
                let idle = clients
                    .iter()
                    .find(|(_, cell)| {
                        Arc::strong_count(cell) == 1
                            && cell
                                .get()
                                .is_none_or(|client| Arc::strong_count(client) == 1)
                    })
                    .map(|(id, _)| *id);
                let Some(idle) = idle else {
                    return Err(storage("chain connections busy"));
                };
                clients.remove(&idle);
            }
            clients.entry(id).or_default().clone()
        };
        let address = self
            .hints
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .unwrap_or_else(|| id.into());
        cell.get_or_try_init(|| async {
            let connection = tokio::time::timeout(
                TIMEOUT,
                self.endpoint.connect(address, ChainSync::ALPN.as_bytes()),
            )
            .await
            .map_err(storage)?
            .map_err(storage)?;
            Ok(Arc::new(ChainSyncClientImpl::new(IrohTransport::new(
                connection,
            ))))
        })
        .await
        .cloned()
    }
    pub async fn fetch(&self, query: FinalizedBlockQuery) -> Option<FinalizedBlock> {
        let mut ids = self.ids();
        ids.shuffle(&mut rand::rng());
        let mut pending = futures_util::stream::iter(ids)
            .map(|id| async move {
                let mut permit = self
                    .manager()
                    .acquire_method::<GetFinalizedBlock>(
                        peer(id),
                        RpcObservation::authenticated_transport("iroh"),
                    )
                    .ok()?;
                let result = tokio::time::timeout(TIMEOUT, async {
                    let client = self.client(id).await?;
                    let response = client
                        .get_finalized_block(crate::client::finalized_block_query_to_proto(query))
                        .await
                        .map_err(QueryError::from)?;
                    let Some(wire) = response.block else {
                        return Ok(None);
                    };
                    let block = crate::client::verified_finalized_block_from_proto(wire, None)
                        .map_err(invalid)?;
                    self.trust.verify(&block)?;
                    if match query {
                        FinalizedBlockQuery::Height(h) => h != block.snapshot.height,
                        FinalizedBlockQuery::Payload(d) => d != block.snapshot.payload,
                        FinalizedBlockQuery::Latest => false,
                    } {
                        return Err(invalid("peer answered another block query"));
                    }
                    Ok::<_, Error>(Some(block))
                })
                .await;
                match result {
                    Ok(Ok(block)) => {
                        permit.finish_ok();
                        block
                    }
                    Ok(Err(error @ Error::InvalidBlock(_))) => {
                        permit.finish_err(error.to_string());
                        self.block(id);
                        None
                    }
                    error => {
                        permit.finish_err(format!("{error:?}"));
                        self.clients.lock().unwrap().remove(&id);
                        None
                    }
                }
            })
            .buffer_unordered(8);
        while let Some(block) = pending.next().await {
            if block.is_some() {
                return block;
            }
        }
        None
    }
    /// One bounded discovery pass. Registry capability observations select fetchers.
    pub async fn discover_all(&self) {
        let addresses: Vec<_> = self.hints.lock().unwrap().values().cloned().collect();
        futures_util::stream::iter(addresses)
            .for_each_concurrent(8, |address| self.discover(address))
            .await;
    }
    pub async fn discover_periodically(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            self.discover_all().await;
        }
    }
    pub async fn feed(&self, indexer: ChainIndexer, readiness: Arc<Readiness>) {
        let mut tasks = FuturesUnordered::new();
        let mut running = std::collections::BTreeSet::new();
        let mut discovery = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = discovery.tick() => {
                    for id in self.ids() {
                        if running.len() >= MAX_PEERS { break; }
                        if running.insert(id) {
                            let (network, indexer, readiness) = (self.clone(), indexer.clone(), readiness.clone());
                            tasks.push(async move { network.feed_peer(id, indexer, readiness).await; id });
                        }
                    }
                }
                Some(id) = tasks.next(), if !tasks.is_empty() => { running.remove(&id); }
            }
        }
    }
    async fn feed_peer(
        &self,
        id: iroh::EndpointId,
        indexer: ChainIndexer,
        readiness: Arc<Readiness>,
    ) {
        let mut failures = 0u32;
        while self.ids().contains(&id) {
            let result: Result<(), Error> = async {
                let client = self.client(id).await?;
                let mut events = tokio::time::timeout(
                    TIMEOUT,
                    client.subscribe_finalized(pb::GetLatestBlockRequest {}),
                )
                .await
                .map_err(storage)?
                .map_err(QueryError::from)?;
                loop {
                    let response = tokio::time::timeout(Duration::from_secs(20), events.next())
                        .await
                        .map_err(storage)?
                        .ok_or(QueryError::ChannelClosed)?
                        .map_err(QueryError::from)?;
                    let Some(wire) = response.block else {
                        continue;
                    };
                    let block = crate::client::verified_finalized_block_from_proto(wire, None)
                        .map_err(invalid)?;
                    if self.manager().is_blocked(peer(id)) {
                        return Err(invalid("peer quarantined"));
                    }
                    readiness.observe(&self.trust, &block)?;
                    let proof =
                        crate::finality_proof::FinalityProof::decode(&block.snapshot.finalization)
                            .map_err(invalid)?;
                    let first = HellasBlock::decode(block.block.as_slice()).map_err(invalid)?;
                    for candidate in std::iter::once(first).chain(proof.descendants) {
                        if !indexer
                            .marshal
                            .verified(candidate.context().round, candidate)
                            .await
                        {
                            return Err(storage("marshal closed"));
                        }
                    }
                    let mut marshal = indexer.marshal.clone();
                    marshal.report(Activity::Finalization(proof.certificate));
                    failures = 0;
                }
            }
            .await;
            if matches!(result, Err(Error::InvalidBlock(_))) {
                self.block(id);
                return;
            }
            self.clients.lock().unwrap().remove(&id);
            failures = failures.saturating_add(1);
            tokio::time::sleep(retry_delay(failures)).await;
        }
    }
}
pub(super) fn peer(id: iroh::EndpointId) -> PeerId {
    PeerId::from_bytes(*id.as_bytes())
}
fn retry_delay(attempt: u32) -> Duration {
    let cap = 250u64.saturating_mul(1u64 << attempt.min(7)).min(30_000);
    Duration::from_millis(cap / 2 + rand::random::<u64>() % (cap / 2 + 1))
}
impl opaque::Fetcher for Network {
    type Key = handler::Key<Digest>;
    type Value = Bytes;
    async fn fetch(&self, key: Self::Key) -> Option<Bytes> {
        let query = match key {
            handler::Key::Block(digest) => FinalizedBlockQuery::Payload(digest),
            handler::Key::Finalized { height } => FinalizedBlockQuery::Height(height.get()),
            handler::Key::Notarized { .. } => return None,
        };
        let block = self.fetch(query).await?;
        let decoded = HellasBlock::decode(block.block.as_slice()).ok()?;
        match key {
            handler::Key::Block(_) => Some(decoded.encode()),
            handler::Key::Finalized { .. } => {
                let proof =
                    crate::finality_proof::FinalityProof::decode(&block.snapshot.finalization)
                        .ok()?;
                if !proof.descendants.is_empty() {
                    return None;
                }
                Some((proof.certificate, decoded).encode())
            }
            handler::Key::Notarized { .. } => None,
        }
    }
}

type Operation = commonware_storage::qmdb::any::unordered::fixed::Operation<
    mmr::Family,
    Digest,
    crate::domain::Object,
>;
impl commonware_glue::stateful::db::AttachableResolver<crate::UtxoDb<runtime::Context>>
    for Network
{
    async fn attach_database(&self, db: UtxoDatabase<runtime::Context>) {
        let _ = self.database.set(db);
    }
}
impl state::Resolver for Network {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Operation;
    type Error = Error;
    async fn get_operations(
        &self,
        count: mmr::Location,
        start: mmr::Location,
        max: NonZeroU64,
        pins: bool,
        cancel: oneshot::Receiver<()>,
    ) -> Result<state::FetchResult<mmr::Family, Operation, Digest>, Error> {
        let fetch = async {
            let mut attempt = 0u32;
            loop {
                let mut ids = self.ids();
                ids.shuffle(&mut rand::rng());
                let mut pending = FuturesUnordered::new();
                for id in ids.into_iter().take(8) {
                    pending.push(async move {
                        let mut permit = self
                            .manager()
                            .acquire_method::<GetOperations>(
                                peer(id),
                                RpcObservation::authenticated_transport("iroh"),
                            )
                            .ok()?;
                        let result = tokio::time::timeout(TIMEOUT, async {
                            self.client(id)
                                .await?
                                .get_operations(pb::GetOperationsRequest {
                                    op_count: *count,
                                    start: *start,
                                    max_ops: max.get().min(64),
                                    include_pinned_nodes: pins,
                                })
                                .await
                                .map_err(|e| Error::Query(e.into()))
                        })
                        .await;
                        match result {
                            Ok(Ok(response)) => Some((id, response, permit)),
                            _ => {
                                permit.finish_err("state request failed");
                                self.clients.lock().unwrap().remove(&id);
                                None
                            }
                        }
                    });
                }
                while let Some(response) = pending.next().await {
                    let Some((id, response, mut permit)) = response else {
                        continue;
                    };
                    let decode = || {
                        if response.operations.len() > 64 || response.pinned_nodes.len() > 64 {
                            return Err(invalid("oversized state proof"));
                        }
                        let proof = commonware_storage::merkle::Proof::decode_cfg(
                            response.proof.as_slice(),
                            &128,
                        )
                        .map_err(invalid)?;
                        let operations = response
                            .operations
                            .iter()
                            .map(|v| Operation::decode(v.as_slice()).map_err(invalid))
                            .collect::<Result<_, _>>()?;
                        let pinned_nodes = if pins {
                            Some(
                                response
                                    .pinned_nodes
                                    .iter()
                                    .map(|v| Digest::decode(v.as_slice()).map_err(invalid))
                                    .collect::<Result<_, _>>()?,
                            )
                        } else {
                            None
                        };
                        Ok::<_, Error>((proof, operations, pinned_nodes))
                    };
                    let (proof, operations, pinned_nodes) = match decode() {
                        Ok(v) => v,
                        Err(error) => {
                            permit.finish_err(error.to_string());
                            self.block(id);
                            continue;
                        }
                    };
                    let (callback, outcome) = oneshot::channel();
                    let manager = self.manager();
                    let clients = self.clients.clone();
                    tokio::spawn(async move {
                        match outcome.await {
                            Ok(true) => permit.finish_ok(),
                            Ok(false) => {
                                permit.finish_err("invalid state proof");
                                let _ = manager.block_peer(peer(id), Duration::from_secs(300));
                                clients.lock().unwrap().remove(&id);
                            }
                            Err(_) => {}
                        }
                    });
                    return Ok(state::FetchResult::with_callback(
                        proof,
                        operations,
                        pinned_nodes,
                        callback,
                    ));
                }
                // QMDB treats resolver errors as fatal. An unavailable peer set
                // is transient, so retry here until the engine cancels this range.
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(retry_delay(attempt)).await;
            }
        };
        tokio::select! { result = fetch => result, _ = cancel => Err(storage("state request cancelled")) }
    }
}
impl Network {
    pub async fn operations(
        &self,
        request: pb::GetOperationsRequest,
    ) -> Result<pb::GetOperationsResponse, hellas_wire::WireStatus> {
        let Some(max) = NonZeroU64::new(request.max_ops).filter(|v| v.get() <= 64) else {
            return Err(hellas_wire::WireStatus::new(
                hellas_wire::WireCode::InvalidArgument,
                "operation count must be 1..=64",
            ));
        };
        let count = mmr::Location::new(request.op_count);
        let start = mmr::Location::new(request.start);
        if !count.is_valid() || !start.is_valid_index() || start >= count {
            return Err(hellas_wire::WireStatus::new(
                hellas_wire::WireCode::InvalidArgument,
                "invalid operation range",
            ));
        }
        let db = self.database.get().ok_or_else(|| {
            hellas_wire::WireStatus::new(hellas_wire::WireCode::Unavailable, "state is catching up")
        })?;
        let (_cancel, cancelled) = oneshot::channel();
        let result = state::Resolver::get_operations(
            db,
            count,
            start,
            max,
            request.include_pinned_nodes,
            cancelled,
        )
        .await
        .map_err(|e| {
            hellas_wire::WireStatus::new(hellas_wire::WireCode::Unavailable, e.to_string())
        })?;
        Ok(pb::GetOperationsResponse {
            proof: result.proof.encode().to_vec(),
            operations: result
                .operations
                .iter()
                .map(|v| v.encode().to_vec())
                .collect(),
            pinned_nodes: result
                .pinned_nodes
                .unwrap_or_default()
                .iter()
                .map(|v| v.encode().to_vec())
                .collect(),
        })
    }
}
