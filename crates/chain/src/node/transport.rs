use super::replication::{MAX_PEERS, Network, TIMEOUT as RPC_TIMEOUT, peer};
use super::*;
#[cfg(feature = "validator")]
use crate::execution::store::UtxoDatabase;
use commonware_runtime::Runner as _;
use futures_util::{StreamExt as _, stream::BoxStream};
use hellas_rpc::{
    pb::{chain as pb, swarm},
    peers::PeerManager,
    services::{
        chain_sync::{ChainSync, ChainSyncHandler, ChainSyncServer},
        node::{Node, NodeHandler, NodeServer},
    },
};
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, WireStatus, iroh::IrohTransport};
use std::{sync::Mutex as StdMutex, time::Duration};
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct FullNode(pub(super) Arc<Lease>);
pub(super) struct Lease {
    pub(super) core: Arc<Core>,
    pub(super) manager: PeerManager,
    config: Config,
    network: Network,
    endpoint: iroh::Endpoint,
    stop: StdMutex<Option<oneshot::Sender<()>>>,
    thread: StdMutex<Option<std::thread::JoinHandle<()>>>,
    runtime: Arc<RuntimeGuard>,
}
struct HaltOnExit(Arc<Readiness>);
impl Drop for HaltOnExit {
    fn drop(&mut self) {
        self.0.halted.store(true, Ordering::Release);
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.core.readiness.halted.store(true, Ordering::Release);
        if let Some(stop) = self
            .stop
            .lock()
            .expect("chain shutdown lock poisoned")
            .take()
        {
            let _ = stop.send(());
        }
    }
}
impl FullNode {
    /// Starts one execution store and one peer sync loop. Clones share both.
    pub async fn start(config: Config) -> Result<Self, Error> {
        Self::start_inner(config, Indexing::Off).await
    }
    #[cfg(feature = "indexer-api")]
    pub(crate) async fn start_indexed(
        config: Config,
        trust: hellas_genesis::TrustDocument,
        genesis_json: Vec<u8>,
        partition: String,
    ) -> Result<Self, Error> {
        Self::start_inner(
            config,
            Indexing::On {
                trust,
                genesis_json,
                partition,
            },
        )
        .await
    }
    async fn start_inner(config: Config, indexing: Indexing) -> Result<Self, Error> {
        config.info()?;
        #[cfg(feature = "construction-audit")]
        crate::construction_audit::record();
        let (started, ready) = oneshot::channel();
        let (stop, mut stopped) = oneshot::channel();
        let retained_config = config.clone();
        let thread = std::thread::Builder::new()
            .name("hellas-chain".into())
            .spawn(move || {
                let runtime = runtime::Config::new().with_storage_directory(&config.storage_dir);
                runtime::Runner::new(runtime).start(move |context| async move {
                    let mut serving = tokio::task::JoinSet::new();
                    let opened = async {
                        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                            .alpns(vec![ChainSync::ALPN.as_bytes().to_vec(), Node::ALPN.as_bytes().to_vec()])
                            .bind().await.map_err(storage)?;
                        let trust = match &indexing {
                            Indexing::Off => Trust::Genesis(Arc::new(ConsensusVerifier::new(&config.info()?).map_err(invalid)?)),
                            #[cfg(feature = "indexer-api")]
                            Indexing::On { trust, genesis_json, .. } => {
                                let supplied: hellas_genesis::Genesis = serde_json::from_slice(genesis_json).map_err(invalid)?;
                                if supplied != config.genesis || trust.epochs.first().is_none_or(|epoch| hex::decode(&epoch.threshold_identity).ok().as_ref() != Some(&config.threshold_identity)) {
                                    return Err(invalid("index authority differs from node configuration"));
                                }
                                Trust::Schedule(crate::indexer::trusted_epochs::TrustedEpochs::with_genesis(trust.clone(), genesis_json).map_err(invalid)?, Arc::new(crate::proof_verify::ProofVerifier::with_genesis(trust.clone(), genesis_json).map_err(invalid)?))
                            }
                        };
                        let network = Network::new(endpoint.clone(), trust);
                        for address in &config.peers { network.seed(address.clone()); }
                        for validator in &config.genesis.validators {
                            if let Ok(raw) = hex::decode(&validator.public_key)
                                && let Ok(raw) = <[u8; 32]>::try_from(raw.as_slice())
                                && let Ok(id) = iroh::EndpointId::from_bytes(&raw) { network.add(id.into()); }
                        }
                        let discovery = network.clone();
                        serving.spawn(async move { discovery.discover_periodically().await });
                        let core = Core::open(context.child("node"), &config, indexing, &network, &mut stopped).await?;
                        Ok::<_, Error>((core, network))
                    };
                    let result = opened.await;
                    let (core, network) = match result {
                        Ok(value) => value,
                        Err(error) => {
                            serving.shutdown().await;
                            let _ = context.child("shutdown").stop(0, Some(RPC_TIMEOUT)).await;
                            let _ = started.send(Err(error)); return;
                        }
                    };
                    let _halt = HaltOnExit(core.readiness.clone());
                    let _ = started.send(Ok((core.clone(), network.clone(), Arc::new(RuntimeGuard(Some(context.child("lifetime")))))));
                    let mut tasks = std::mem::take(&mut *core.tasks.lock().unwrap());
                    serving.spawn(serve(SyncService::new(&core, network.clone()), network.clone()));
                    let done = futures_util::future::select_all(tasks.0.iter_mut());
                    tokio::select! {
                        _ = &mut stopped => {},
                        result = done => { tracing::error!(result = ?result.0, "chain execution stopped"); },
                        _ = serving.join_next() => {},
                    }
                    core.readiness.halted.store(true, Ordering::Release);
                    serving.shutdown().await;
                    tasks.stop(&context).await;
                    network.endpoint.close().await;
                });
            })
            .map_err(storage)?;
        let (core, network, runtime) = ready
            .await
            .map_err(|_| storage("chain startup task stopped"))??;
        Ok(Self(Arc::new(Lease {
            core,
            manager: network.manager(),
            endpoint: network.endpoint.clone(),
            network,
            config: retained_config,
            stop: StdMutex::new(Some(stop)),
            thread: StdMutex::new(Some(thread)),
            runtime,
        })))
    }
    #[cfg(feature = "indexer-api")]
    pub(crate) fn index(&self) -> Option<crate::edge_index::EdgeIndex> {
        self.0.core.publication.as_ref().map(|p| p.index.clone())
    }
    #[cfg(feature = "indexer-api")]
    pub(crate) fn archive(&self) -> ChainIndexer {
        self.0.core.indexer.clone()
    }
    #[cfg(feature = "indexer-api")]
    pub(crate) async fn owner_proof(
        &self,
        owner: SettlementKey,
        offset: u64,
        limit: u32,
        payload: Option<&str>,
    ) -> Result<Option<crate::proof_verify::VerifiedAddress>, Error> {
        self.0.core.readiness.running()?;
        self.0
            .core
            .publication
            .as_ref()
            .ok_or_else(|| storage("node has no read index"))?
            .owner_proof(&self.0.core.database, owner, offset, limit, payload)
            .await
            .map_err(storage)
    }
    /// Serve the finalized chain subset on a host's authenticated iroh
    /// connection. Streams and reads share the connection concurrently.
    pub async fn serve_chain(&self, transport: Arc<IrohTransport>) {
        dispatch(
            transport,
            Admission(ChainSyncServer(self.clone()), self.0.manager.clone()),
        )
        .await;
    }
    pub fn config(&self) -> &Config {
        &self.0.config
    }
    pub fn peer_registry(
        &self,
    ) -> Result<hellas_rpc::peers::PeerRegistry, hellas_rpc::peers::PeerManagerError> {
        self.0.manager.snapshot()
    }
    pub fn peer_ids(&self) -> Vec<iroh::EndpointId> {
        self.0.network.ids()
    }
    /// Capabilities for the host's endpoint when it also mounts this ChainSync handler.
    pub fn discovery(
        &self,
        id: iroh::EndpointId,
        service_alpns: Vec<String>,
    ) -> impl NodeHandler + Clone + 'static {
        NodeService {
            id,
            service_alpns,
            network: self.0.network.clone(),
        }
    }
    pub async fn shutdown(self) -> Result<(), Error> {
        if let Some(stop) = self
            .0
            .stop
            .lock()
            .expect("chain shutdown lock poisoned")
            .take()
        {
            let _ = stop.send(());
        }
        let thread = self
            .0
            .thread
            .lock()
            .expect("chain thread lock poisoned")
            .take();
        if let Some(thread) = thread {
            tokio::task::spawn_blocking(move || thread.join())
                .await
                .map_err(storage)?
                .map_err(|_| storage("chain thread panicked"))?;
        }
        Ok(())
    }
    pub fn view(&self) -> Result<ChainView, QueryError> {
        self.0.core.readiness.check()?;
        Ok(ChainView(self.0.core.client.clone().retain_node(
            self.0.runtime.clone(),
            self.0.network.clone(),
        )))
    }
    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.0.endpoint.addr()
    }
    pub fn finalized(&self) -> watch::Receiver<u64> {
        self.0.core.progress.subscribe()
    }
    pub async fn wait_ready(&self) -> Result<ChainView, QueryError> {
        let mut progress = self.finalized();
        loop {
            if let Ok(view) = self.view() {
                return Ok(view);
            }
            if self.0.core.readiness.halted.load(Ordering::Acquire) {
                return Err(QueryError::StateUnavailable("chain node halted".into()));
            }
            tokio::select! {
                result = progress.changed() => { result.map_err(|_| QueryError::ChannelClosed)?; },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    }
}

#[derive(Clone)]
struct SyncService {
    indexer: ChainIndexer,
    progress: watch::Sender<u64>,
    readiness: Option<Arc<Readiness>>,
    network: Network,
}
impl SyncService {
    fn new(core: &Core, network: Network) -> Self {
        Self {
            indexer: core.indexer.clone(),
            progress: core.progress.clone(),
            readiness: Some(core.readiness.clone()),
            network,
        }
    }
}
#[allow(refining_impl_trait)]
impl ChainSyncHandler for SyncService {
    async fn get_latest_block(
        &self,
        _: pb::GetLatestBlockRequest,
    ) -> Result<pb::GetFinalizedBlockResponse, WireStatus> {
        self.get_finalized_block(pb::GetFinalizedBlockRequest { query: None })
            .await
    }
    async fn get_finalized_block(
        &self,
        request: pb::GetFinalizedBlockRequest,
    ) -> Result<pb::GetFinalizedBlockResponse, WireStatus> {
        if let Some(readiness) = &self.readiness {
            readiness.running()?;
        }
        crate::server::read_finalized_block(request, |query| {
            self.indexer.get_finalized_block(query)
        })
        .await
    }
    async fn get_finalization(
        &self,
        request: pb::GetFinalizationRequest,
    ) -> Result<pb::GetFinalizationResponse, WireStatus> {
        crate::server::read_finalization(request, |payload| self.indexer.get_finalization(payload))
            .await
    }
    async fn get_operations(
        &self,
        request: pb::GetOperationsRequest,
    ) -> Result<pb::GetOperationsResponse, WireStatus> {
        self.network.operations(request).await
    }
    async fn subscribe_finalized(
        &self,
        _: pb::GetLatestBlockRequest,
    ) -> Result<BoxStream<'static, Result<pb::GetFinalizedBlockResponse, WireStatus>>, WireStatus>
    {
        let source = self.clone();
        let stream = futures_util::stream::unfold(
            (source.progress.subscribe(), source),
            |(mut progress, source)| async move {
                let wake = tokio::time::timeout(Duration::from_secs(5), progress.changed()).await;
                match wake {
                    Ok(Ok(())) | Err(_) => {
                        let response = source
                            .indexer
                            .get_finalized_block(FinalizedBlockQuery::Latest)
                            .await
                            .map(crate::server::finalized_block_response)
                            .map_err(WireStatus::from);
                        Some((response, (progress, source)))
                    }
                    Ok(Err(_)) => None,
                }
            },
        );
        let initial = self.get_latest_block(pb::GetLatestBlockRequest {}).await;
        Ok(futures_util::stream::once(async move { initial })
            .chain(stream)
            .boxed())
    }
}

// External dispatchers retain the node lease for the complete RPC/stream lifetime.
#[allow(refining_impl_trait)]
impl ChainSyncHandler for FullNode {
    async fn get_latest_block(
        &self,
        request: pb::GetLatestBlockRequest,
    ) -> Result<pb::GetFinalizedBlockResponse, WireStatus> {
        SyncService::new(&self.0.core, self.0.network.clone())
            .get_latest_block(request)
            .await
    }
    async fn get_finalized_block(
        &self,
        request: pb::GetFinalizedBlockRequest,
    ) -> Result<pb::GetFinalizedBlockResponse, WireStatus> {
        SyncService::new(&self.0.core, self.0.network.clone())
            .get_finalized_block(request)
            .await
    }
    async fn get_finalization(
        &self,
        request: pb::GetFinalizationRequest,
    ) -> Result<pb::GetFinalizationResponse, WireStatus> {
        SyncService::new(&self.0.core, self.0.network.clone())
            .get_finalization(request)
            .await
    }
    async fn get_operations(
        &self,
        request: pb::GetOperationsRequest,
    ) -> Result<pb::GetOperationsResponse, WireStatus> {
        self.0.network.operations(request).await
    }
    async fn subscribe_finalized(
        &self,
        request: pb::GetLatestBlockRequest,
    ) -> Result<BoxStream<'static, Result<pb::GetFinalizedBlockResponse, WireStatus>>, WireStatus>
    {
        let stream = SyncService::new(&self.0.core, self.0.network.clone())
            .subscribe_finalized(request)
            .await?;
        Ok(
            futures_util::stream::unfold((self.clone(), stream), |(node, mut stream)| async move {
                stream.next().await.map(|value| (value, (node, stream)))
            })
            .boxed(),
        )
    }
}

#[derive(Clone)]
struct NodeService {
    id: iroh::EndpointId,
    service_alpns: Vec<String>,
    network: Network,
}
#[allow(refining_impl_trait)]
impl NodeHandler for NodeService {
    async fn get_node_info(
        &self,
        _: swarm::GetNodeInfoRequest,
    ) -> Result<swarm::GetNodeInfoResponse, WireStatus> {
        Ok(swarm::GetNodeInfoResponse {
            node_id: self.id.to_string(),
            service_alpns: self.service_alpns.clone(),
            ..Default::default()
        })
    }
    async fn get_known_peers(
        &self,
        request: swarm::GetKnownPeersRequest,
    ) -> Result<swarm::GetKnownPeersResponse, WireStatus> {
        let peer_ids = self
            .network
            .directory
            .known_peers(peer(self.id), &request.service_alpn, MAX_PEERS)
            .unwrap_or_default()
            .into_iter()
            .map(|id| id.as_bytes().to_vec())
            .collect();
        Ok(swarm::GetKnownPeersResponse { peer_ids })
    }
}

pub(super) async fn dispatch<S>(transport: Arc<IrohTransport>, server: S)
where
    S: Dispatcher<IrohTransport> + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send,
{
    let server = Arc::new(server);
    let (incoming, mut requests) = tokio::sync::mpsc::channel(8);
    let mut reader = tokio::task::JoinSet::new();
    // One task owns accept so completing a dispatch cannot cancel a partial frame.
    reader.spawn(async move {
        while let Ok(Some(request)) = transport.accept().await {
            if incoming.send(request).await.is_err() {
                break;
            }
        }
    });
    let mut calls = tokio::task::JoinSet::new();
    loop {
        if calls.len() == 8 {
            let _ = calls.join_next().await;
            continue;
        }
        let request = if calls.is_empty() {
            match tokio::time::timeout(Duration::from_secs(30), requests.recv()).await {
                Ok(request) => request,
                Err(_) => break,
            }
        } else {
            tokio::select! {
                _ = calls.join_next() => continue,
                request = requests.recv() => request,
            }
        };
        let Some(request) = request else {
            break;
        };
        let server = server.clone();
        calls.spawn(async move {
            let _ = server.dispatch(request).await;
        });
    }
}

async fn serve(service: SyncService, network: Network) {
    let mut handshakes = Handshakes::default();
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {},
            incoming = network.endpoint.accept(), if connections.len() < 64 => {
                let Some(incoming) = incoming else { return; };
                if !handshakes.admit(incoming.remote_addr(), network.manager().now_ms()) { incoming.refuse(); continue; }
                let (service, network) = (service.clone(), network.clone());
                connections.spawn(async move {
                    let Ok(Ok(connection)) = tokio::time::timeout(RPC_TIMEOUT, incoming).await else { return; };
                    let id = connection.remote_id();
                    if network.manager().is_blocked(peer(id)) { connection.close(0u32.into(), b"peer quarantined"); return; }
                    let alpn = connection.alpn().to_vec();
                    let transport = Arc::new(IrohTransport::new(connection));
                    if alpn == ChainSync::ALPN.as_bytes() {
                        let server = Admission(ChainSyncServer(service), network.manager());
                        tokio::join!(dispatch(transport, server), network.discover(id.into()));
                    } else if alpn == Node::ALPN.as_bytes() {
                        dispatch(transport, hellas_rpc::serve::AccountingDispatcher::new(NodeServer(NodeService {
                            id: network.endpoint.id(), service_alpns: vec![Node::ALPN.into(), ChainSync::ALPN.into()], network: network.clone(),
                        }), network.manager())).await;
                    }
                });
            }
        }
    }
}

/// Consensus nodes serve their existing archive; no second executor is started.
#[cfg(feature = "validator")]
pub(crate) async fn serve_validator_archive(
    indexer: ChainIndexer,
    activity: tokio::sync::broadcast::Sender<crate::ConsensusActivity>,
    key: iroh::SecretKey,
    database: UtxoDatabase<runtime::Context>,
    verifier: ConsensusVerifier,
) -> Result<(), Error> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(key)
        .alpns(vec![
            ChainSync::ALPN.as_bytes().to_vec(),
            Node::ALPN.as_bytes().to_vec(),
        ])
        .bind()
        .await
        .map_err(storage)?;
    tracing::info!(chain_peer = %endpoint.id(), "serving finalized chain over iroh");
    serve_validator_endpoint(indexer, activity, endpoint, database, verifier).await;
    Ok(())
}

#[cfg(feature = "validator")]
pub(crate) async fn serve_validator_endpoint(
    indexer: ChainIndexer,
    activity: tokio::sync::broadcast::Sender<crate::ConsensusActivity>,
    endpoint: iroh::Endpoint,
    database: UtxoDatabase<runtime::Context>,
    verifier: ConsensusVerifier,
) {
    let network = Network::new(endpoint.clone(), Trust::Genesis(Arc::new(verifier)));
    commonware_glue::stateful::db::AttachableResolver::attach_database(&network, database).await;
    let (progress, _) = watch::channel(0);
    let service = SyncService {
        indexer,
        progress: progress.clone(),
        readiness: None,
        network: network.clone(),
    };
    let mut activity = activity.subscribe();
    let notify = async move {
        // Marshal persistence may finish after consensus reports finalization.
        // A bounded periodic wake also catches that publication and lagged events.
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                event = activity.recv() => match event {
                    Ok(crate::ConsensusActivity::Finalization { .. })
                    | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = tick.tick() => {},
            }
            progress.send_modify(|value| *value = value.wrapping_add(1));
        }
    };
    tokio::select! {
        _ = serve(service, network) => {},
        _ = notify => {},
    }
    endpoint.close().await;
}

/// ChainSync admission is shared across connections, including the host mount.
struct Admission<S>(S, PeerManager);
impl<T, S> Dispatcher<T> for Admission<S>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T> + Send + Sync,
{
    type Error = S::Error;
    async fn dispatch(
        &self,
        mut request: hellas_wire::transport::Inbound<T::Stream>,
    ) -> Result<(), Self::Error> {
        use hellas_wire::transport::Stream;
        let permit = request.context.peer.and_then(|id| {
            self.1
                .acquire_rpc(
                    hellas_rpc::peers::PeerId::from_bytes(id.0),
                    hellas_rpc::peers::RequestKind::new(ChainSync::NAME, "replication"),
                    hellas_rpc::peers::RpcObservation::authenticated_transport("iroh"),
                )
                .ok()
        });
        let Some(mut permit) = permit else {
            request
                .stream
                .reset(hellas_wire::WireCode::ResourceExhausted);
            return Ok(());
        };
        let result = self.0.dispatch(request).await;
        match &result {
            Ok(()) => permit.finish_ok(),
            Err(e) => permit.finish_err(e.to_string()),
        }
        result
    }
}

#[derive(Default)]
struct Handshakes(
    std::collections::BTreeMap<(std::net::IpAddr, bool), (u64, hellas_rpc::peers::TokenBucket)>,
);
impl Handshakes {
    fn admit(&mut self, address: iroh::endpoint::IncomingAddr, now: u64) -> bool {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let iroh::endpoint::IncomingAddr::Ip(socket) = address else {
            // Relays expose an authenticated endpoint identity, not its IP.
            // Identity admission and the global connection bound still apply.
            return true;
        };
        self.0
            .retain(|_, (seen, _)| now.saturating_sub(*seen) < 60_000);
        let ip = socket.ip().to_canonical();
        let subnet = match ip {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(u32::from(ip) & 0xffffff00)),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
        };
        for (key, capacity, rate) in [((ip, false), 8.0, 2.0), ((subnet, true), 32.0, 8.0)] {
            if self.0.len() >= 1024 && !self.0.contains_key(&key) {
                return false;
            }
            let (seen, bucket) = self
                .0
                .entry(key)
                .or_insert_with(|| (now, hellas_rpc::peers::TokenBucket::new(now, capacity)));
            *seen = now;
            if bucket.try_take(now, capacity, rate).is_err() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshakes_bound_each_ip_subnet_and_idle_lifetime() {
        let mut gate = Handshakes::default();
        let ip = |last| {
            iroh::endpoint::IncomingAddr::Ip(std::net::SocketAddr::from(([192, 0, 2, last], 1234)))
        };
        for _ in 0..8 {
            assert!(gate.admit(ip(1), 0));
        }
        assert!(!gate.admit(ip(1), 0));
        for host in 2..5 {
            for _ in 0..8 {
                assert!(gate.admit(ip(host), 0));
            }
        }
        assert!(!gate.admit(ip(5), 0));
        assert!(gate.admit(ip(1), 1_000));
        assert!(gate.admit(ip(1), 61_000));
        assert_eq!(gate.0.len(), 2);
    }
}
