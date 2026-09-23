//! Node server bootstrap.
//!
//! Binds an iroh `Endpoint` with all service ALPNs, runs the executor,
//! and spawns a per-connection accept loop that routes each inbound
//! stream to the right service's dispatcher (selected by ALPN).
//!
//! Peers can reach this node by direct address. Registry publishing is
//! owned by the service-discovery path and is not started from this
//! bootstrap.

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
use hellas_chain::FinalizedWorkView;
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use hellas_executor::GpuConfig;
use hellas_executor::{
    CourtesyServer, ExecuteServer, Executor, ExecutorMetrics, ExecutorSpawnConfig,
    FetchAccessPolicy, FetchQuotaStoreBackend, FetchRouteRegistry, FetchServer,
    FetchTranscriptStoreBackend,
};
#[cfg(test)]
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::cache::control::CacheController;
use hellas_rpc::open::OpenDispatcher;
#[cfg(test)]
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    WorkRefusalCode, WorkRefused, accept_work_response, admit_certificate_response,
    deliver_result_response, exchange_setup_response,
};
use hellas_rpc::peers::PeerId;
use hellas_rpc::peers::{PeerDirectory, PeerManager};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::serve::{AccountingDispatcher, AdminPolicy, Authorized, MethodDispatcher};
use hellas_rpc::services::cache_control::{CacheControl, CacheControlServer};
use hellas_rpc::services::courtesy::{Courtesy, Open as CourtesyOpen};
use hellas_rpc::services::execute::RunTicket;
use hellas_rpc::services::fetch::{Fetch, Open as FetchOpen};
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupServer};
#[cfg(test)]
use hellas_rpc::services::{work::WorkHandler, work_setup::WorkSetupHandler};
use hellas_rpc::{Assurance, ProducerSigningKey};
use hellas_wire::iroh::{IrohTransport, IrohTransportError};
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport};
#[cfg(test)]
use hellas_wire::{TransportContext, WireStatus};
#[cfg(test)]
use hellas_work::work::PaidWorkBackend;
use hellas_work::work_close::FinalizedBlocks;
#[cfg(test)]
use hellas_work::work_close::TxSink;
#[cfg(test)]
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint};
#[cfg(test)]
use hellas_work::work_open::SetupView;
#[cfg(test)]
use hellas_work::work_store::{ChannelStore, JobPhase, Role, SetupStore};
use iroh::{Endpoint, EndpointId, SecretKey, endpoint::Connection, endpoint::presets};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use super::node_handler::NodeHandlerImpl;
use crate::commands::discovery::{DiscoveryAdvertiser, served_alpns, start_server_advertising};
use crate::identity::OpenIdentity;

pub(super) use hellas_sdk::paid_provider::{
    MountedSetup, MountedWork, ProductionWorkSource, UnmountedWork, WorkRunner, WorkRunnerConfig,
};

/// Keep peer-controlled transport state finite. A connection can multiplex
/// several RPCs, so these are deliberately transport limits rather than job
/// scheduler limits.
const MAX_ACTIVE_RPC_CONNECTIONS: usize = 128;
const MAX_RPC_IN_FLIGHT_PER_CONNECTION: usize = 16;
const RPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) struct NodeHandle {
    node_id: EndpointId,
    accept_task: Option<JoinHandle<()>>,
    endpoint: Endpoint,
    discovery: Option<DiscoveryAdvertiser>,
    work: Option<WorkWatcher>,
}

/// The clock over this node's paid-work journals, and the way to stop
/// it.
///
/// Stopped rather than aborted: every journal this task holds is closed
/// when the task returns, and a shutdown that aborted it would drop
/// those files at whatever point the runtime chose. Nothing here is
/// racing a torn write — a journal append is synchronous and fsynced
/// inside its own borrow, and there is no await inside one — but a
/// runner told to stop between two steps is what leaves the operator a
/// process that owns nothing.
struct WorkWatcher {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl NodeHandle {
    pub(super) fn node_id(&self) -> EndpointId {
        self.node_id
    }

    #[cfg(feature = "otel")]
    pub(super) fn iroh_metrics(&self) -> iroh::metrics::EndpointMetrics {
        self.endpoint.metrics().clone()
    }

    pub(super) async fn shutdown(mut self) -> anyhow::Result<()> {
        // The clock first, and joined rather than aborted: its journals
        // are released when its task returns, and a node that closed its
        // endpoint while a step was still writing would be a node whose
        // files outlive it.
        if let Some(watcher) = self.work.take() {
            let _ = watcher.stop.send(());
            let _ = watcher.task.await;
        }
        if let Some(handle) = self.accept_task.take() {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown().await;
        }
        self.endpoint.close().await;
        Ok(())
    }
}

pub(super) struct NodeConfig {
    pub(super) admin_peers: Vec<EndpointId>,
    pub(super) output_cache: hellas_rpc::cache::CacheOptions,
    pub(super) port: Option<u16>,
    pub(super) execute_policy: ExecutePolicy,
    pub(super) queue_size: usize,
    #[cfg(feature = "evaluate")]
    pub(super) content_store: hellas_store::ContentStore,
    pub(super) build: String,
    pub(super) graffiti: Vec<u8>,
    pub(super) fetch_access_policy: FetchAccessPolicy,
    pub(super) artifact_store_path: PathBuf,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_size: usize,
    pub(super) fetch_retained_transcript_capacity: usize,
    pub(super) fetch_replay_max_in_flight: usize,
    /// What the clock over this node's paid-work journals is built
    /// from, or `None` when no work configuration was loaded. Its
    /// presence is still what advertises the two work ALPNs.
    pub(super) work: Option<WorkRunnerConfig>,
    pub(super) secret_key: SecretKey,
    pub(super) producer_key: ProducerSigningKey,
    pub(super) provider_genesis: Vec<u8>,
    pub(super) open_identity: Arc<OpenIdentity>,
    pub(super) assurance: Assurance,
    pub(super) metrics: Arc<ExecutorMetrics>,
    #[cfg(feature = "evaluate")]
    pub(super) artifact_store: ArtifactStoreConfig,
    #[cfg(feature = "evaluate")]
    pub(super) gpu_config: GpuConfig,
}

#[derive(Clone)]
struct RemoteExecutionServices {
    control: CacheController,
    admin_policy: AdminPolicy,
    executor: hellas_executor::ExecutorHandle,
    open_identity: Arc<OpenIdentity>,
}

pub(super) async fn spawn_node(config: NodeConfig) -> anyhow::Result<NodeHandle> {
    let control = CacheController::new(&config.output_cache);
    let admin_policy = AdminPolicy {
        local_owner: false,
        peers: config
            .admin_peers
            .iter()
            .map(|peer| hellas_wire::PeerIdentity(*peer.as_bytes()))
            .collect(),
    };
    let fetch_store = FetchTranscriptStoreBackend::fs_with_capacity(
        config.artifact_store_path.join("fetch-transcripts"),
        config.fetch_retained_transcript_capacity,
    );
    let fetch_access_policy = config
        .fetch_access_policy
        .with_store(FetchQuotaStoreBackend::fs(
            config.artifact_store_path.join("fetch-quota"),
        ));
    let mut executor = ExecutorSpawnConfig::fetch_only(
        Arc::new(config.producer_key),
        Arc::new(config.provider_genesis),
        config.assurance,
        config.fetch_routes,
    );
    executor.output_cache = config.output_cache;
    executor.execute_policy = config.execute_policy;
    executor.queue_capacity = config.queue_size;
    executor.metrics = config.metrics.clone();
    executor.fetch_access_policy = fetch_access_policy;
    executor.fetch_max_in_flight = config.fetch_max_in_flight;
    executor.fetch_queue_capacity = config.fetch_queue_size;
    executor.fetch_replay_max_in_flight = config.fetch_replay_max_in_flight;
    executor.fetch_store = fetch_store;
    #[cfg(feature = "evaluate")]
    {
        executor.artifact_store = config.artifact_store;
        executor.content_store = config.content_store;
        executor.gpu_config = config.gpu_config;
    }
    let handle = Executor::spawn_configured(executor)
        .await
        .context("failed to spawn executor")?;
    let advertised_alpns = served_alpns(config.work.is_some());
    let mut alpns = advertised_alpns.clone();
    if !admin_policy.peers.is_empty() {
        alpns.push(CacheControl::ALPN.as_bytes().to_vec());
    }
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(config.secret_key)
        .alpns(alpns.clone());
    if let Some(port) = config.port {
        builder = builder
            .bind_addr(format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?)
            .map_err(|e| anyhow::anyhow!("invalid bind address: {e}"))?;
    }
    let endpoint = builder
        .bind()
        .await
        .context("failed to bind iroh endpoint")?;
    let node_id = endpoint.id();
    let discovery = start_server_advertising(&endpoint, &advertised_alpns)
        .context("failed to start service discovery advertising")?;

    // -- Construct a shared peer directory.
    //
    // The directory records inbound service observations and is shared
    // across the dispatch path.
    //
    // Deferred until a concrete abuse scenario warrants it: an
    // `AdmittingDispatcher<S>` that looks up per-method policy before
    // forwarding to the generated dispatcher and records inbound request
    // observations in the directory.
    let local_peer = PeerId::from_bytes(*node_id.as_bytes());
    // Seed the directory with this crate's generated service catalogue so
    // ALPN/FQN service-filter queries resolve (p2p ships no service names).
    let directory = Arc::new(PeerDirectory::with_config(
        local_peer,
        hellas_rpc::peer_directory_config(),
    ));

    // -- Build the Node handler with the operator-supplied build hash
    //    and graffiti so introspection (`hellas rpc`) returns real data.
    //    `NodeHandlerImpl: Clone` (its fields are Arc/Copy), so we
    //    clone per-connection rather than wrap in Arc<dyn>.
    let node_handler =
        NodeHandlerImpl::new(node_id, config.build, config.graffiti, directory.clone());

    // -- The clock. Spawned only when a work configuration was loaded,
    //    and given the same mount slot the accept loop reads: the runner
    //    publishes the channel it is handed, and `Work` is answered from
    //    it from that moment on.
    // Local content indexing is complete before bind. Clones of the executor
    // handle live in every remote-execution handler and, when paid work is
    // configured, in its mount as well.
    let remote_execution = RemoteExecutionServices {
        control,
        admin_policy,
        executor: handle.clone(),
        open_identity: config.open_identity,
    };
    let work_mount: MountedWork<ProductionWorkSource> = MountedWork::with_backend(handle);
    let setup_mount = MountedSetup::default();
    let work = config.work.map(|work| {
        let poll = work.poll;
        let runner = WorkRunner::discover(work, work_mount.clone(), setup_mount.clone());
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            match runner {
                Ok(runner) => runner.run(stopped).await,
                // §4's rule, at the one place it could still refuse to
                // start: a root that cannot be enumerated is an operator
                // error, and a node that exited over it would be a node
                // answering no contest at all.
                Err(error) => warn!(%error, "the paid-work journals could not be enumerated"),
            }
        });
        info!(poll_ms = poll.as_millis(), "the paid-work clock is running");
        WorkWatcher { stop, task }
    });
    let serves_work = work.is_some().then(|| work_mount.clone());
    let serves_setup = work.is_some().then(|| setup_mount.clone());

    // -- Accept loop: one task per inbound Connection; per-Connection
    //    dispatch routed by ALPN to the matching service handler.
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        let connection_slots = Arc::new(Semaphore::new(MAX_ACTIVE_RPC_CONNECTIONS));
        loop {
            let incoming = match accept_endpoint.accept().await {
                Some(inc) => inc,
                None => break, // endpoint closed
            };
            // Stop accepting before peer-controlled connection tasks can grow
            // without bound. The endpoint's own finite backlog applies
            // backpressure while every slot is occupied.
            let connection_slot = match connection_slots.clone().acquire_owned().await {
                Ok(slot) => slot,
                Err(_) => break,
            };
            let accepting = match incoming.accept() {
                Ok(a) => a,
                Err(e) => {
                    warn!("incoming accept failed: {e}");
                    continue;
                }
            };
            let node_handler_for_conn = node_handler.clone();
            let manager_for_conn = directory.manager();
            let execution_for_conn = remote_execution.clone();
            let work_for_conn = serves_work.clone();
            let setup_for_conn = serves_setup.clone();
            tokio::spawn(async move {
                let _connection_slot = connection_slot;
                let conn = match tokio::time::timeout(RPC_HANDSHAKE_TIMEOUT, accepting).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        warn!("connection handshake failed: {e}");
                        return;
                    }
                    Err(_) => {
                        warn!("connection handshake timed out");
                        return;
                    }
                };
                let alpn = conn.alpn().to_vec();
                debug!(
                    alpn = %String::from_utf8_lossy(&alpn),
                    "accepted RPC connection"
                );
                if let Err(e) = serve_connection(
                    alpn,
                    conn,
                    execution_for_conn,
                    node_handler_for_conn,
                    manager_for_conn,
                    setup_for_conn,
                    work_for_conn,
                )
                .await
                {
                    warn!("serve_connection error: {e}");
                }
            });
        }
    });

    Ok(NodeHandle {
        node_id,
        accept_task: Some(accept_task),
        endpoint,
        discovery: Some(discovery),
        work,
    })
}

/// Per-connection serve: each inbound substream is dispatched to the
/// service selected by the connection's negotiated ALPN.
async fn serve_connection<S>(
    alpn: Vec<u8>,
    conn: Connection,
    remote_execution: RemoteExecutionServices,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
    setup: Option<MountedSetup>,
    work: Option<MountedWork<S>>,
) -> anyhow::Result<()>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    let transport = Arc::new(IrohTransport::new(conn));
    let context = transport.context();

    // Account for inbound requests and refresh last_seen_ms in the shared registry.
    if alpn == CacheControl::ALPN.as_bytes() {
        serve_loop(
            transport,
            Authorized {
                service: CacheControlServer(remote_execution.control),
                policy: remote_execution.admin_policy,
            },
        )
        .await
    } else if alpn == <Courtesy as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(
            OpenDispatcher::<_, _, CourtesyOpen>::new(
                MethodDispatcher::<_, _, RunTicket>::new(
                    ExecuteServer(remote_execution.executor.clone()),
                    CourtesyServer(remote_execution.executor.clone()),
                ),
                remote_execution.open_identity.clone(),
            ),
            manager,
        );
        serve_loop(transport, server).await
    } else if alpn == <Fetch as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(
            OpenDispatcher::<_, _, FetchOpen>::new(
                MethodDispatcher::<_, _, RunTicket>::new(
                    ExecuteServer(remote_execution.executor.clone()),
                    FetchServer(remote_execution.executor.clone()),
                ),
                remote_execution.open_identity.clone(),
            ),
            manager,
        );
        serve_loop(transport, server).await
    } else if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
        serve_loop(transport, server).await
    } else if let Some(setup) =
        setup.filter(|_| alpn == <WorkSetup as ServiceMarker>::ALPN.as_bytes())
    {
        match setup.service(&context) {
            Some(mounted) => {
                let server = AccountingDispatcher::new(
                    OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                        WorkSetupServer(mounted),
                        remote_execution.open_identity.clone(),
                    ),
                    manager,
                );
                serve_loop(transport, server).await
            }
            None => {
                let server = AccountingDispatcher::new(
                    OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                        WorkSetupServer(UnmountedWork),
                        remote_execution.open_identity.clone(),
                    ),
                    manager,
                );
                serve_loop(transport, server).await
            }
        }
    } else if let Some(work) = work.filter(|_| alpn == <Work as ServiceMarker>::ALPN.as_bytes()) {
        // The mounted channel answers for itself. Until the runner has
        // been handed one there is no channel to answer from, and this
        // is still the bounded retryable `NotReady` §3 left here.
        match work.handler(&context) {
            Some(mounted) => {
                let server = AccountingDispatcher::new(
                    OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                        WorkServer(mounted),
                        remote_execution.open_identity.clone(),
                    ),
                    manager,
                );
                serve_loop(transport, server).await
            }
            None => {
                let server = AccountingDispatcher::new(
                    OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                        WorkServer(UnmountedWork),
                        remote_execution.open_identity.clone(),
                    ),
                    manager,
                );
                serve_loop(transport, server).await
            }
        }
    } else {
        warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
        Ok(())
    }
}

async fn serve_loop<S>(transport: Arc<IrohTransport>, server: S) -> anyhow::Result<()>
where
    S: Dispatcher<IrohTransport> + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    let server = Arc::new(server);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(MAX_RPC_IN_FLIGHT_PER_CONNECTION);
    let accept_transport = transport.clone();
    // One task owns `accept`: dispatch completion can therefore never cancel
    // a partially read Open frame. The bounded channel is the only hand-off.
    let accept_task = tokio::spawn(async move {
        loop {
            match accept_transport.accept().await {
                Ok(Some(inbound)) => {
                    if inbound_tx.send(Ok(inbound)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(IrohTransportError::Connection(_)) => break,
                Err(error) => {
                    let _ = inbound_tx.send(Err(error)).await;
                    break;
                }
            }
        }
    });

    let mut dispatches = JoinSet::new();
    let result = loop {
        if dispatches.len() >= MAX_RPC_IN_FLIGHT_PER_CONNECTION {
            log_dispatch_result(dispatches.join_next().await);
            continue;
        }

        let next = if dispatches.is_empty() {
            match tokio::time::timeout(RPC_CONNECTION_IDLE_TIMEOUT, inbound_rx.recv()).await {
                Ok(next) => next,
                Err(_) => break Ok(()),
            }
        } else {
            tokio::select! {
                next = inbound_rx.recv() => next,
                completed = dispatches.join_next() => {
                    log_dispatch_result(completed);
                    continue;
                }
            }
        };

        match next {
            Some(Ok(inbound)) => {
                let server = server.clone();
                dispatches.spawn(async move { server.dispatch(inbound).await });
            }
            Some(Err(error)) => {
                break Err(anyhow::anyhow!("transport accept failed: {error}"));
            }
            None => break Ok(()),
        }
    };

    accept_task.abort();
    let _ = accept_task.await;
    dispatches.abort_all();
    while dispatches.join_next().await.is_some() {}
    result
}

fn log_dispatch_result<E>(result: Option<Result<Result<(), E>, tokio::task::JoinError>>)
where
    E: std::error::Error,
{
    match result {
        Some(Ok(Err(_))) => {
            // RPC errors can be derived from request content. Keep the trace
            // useful without copying prompt or token material into logs.
            warn!("dispatch error; request details suppressed");
        }
        Some(Err(error)) if !error.is_cancelled() => {
            warn!("RPC dispatch task failed; request details suppressed");
        }
        Some(Ok(Ok(())) | Err(_)) | None => {}
    }
}

#[cfg(test)]
mod tests;
