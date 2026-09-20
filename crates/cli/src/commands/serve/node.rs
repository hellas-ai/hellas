//! Node server bootstrap.
//!
//! Binds an iroh `Endpoint` with all service ALPNs, runs the executor,
//! and spawns a per-connection accept loop that routes each inbound
//! stream to the right service's dispatcher (selected by ALPN).
//!
//! Peers can reach this node by direct address. Registry publishing is
//! owned by the service-discovery path and is not started from this
//! bootstrap.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use futures::future::BoxFuture;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::work_blocks::advance_paid_work_clock;
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedWorkView, WorkBlocks, WorkChannelQuery,
};
#[cfg(feature = "evaluate")]
use hellas_executor::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use hellas_executor::GpuConfig;
use hellas_executor::{
    CourtesyServer, ExecuteServer, Executor, ExecutorMetrics, ExecutorSpawnConfig,
    FetchAccessPolicy, FetchQuotaStoreBackend, FetchRouteRegistry, FetchServer,
    FetchTranscriptStoreBackend,
};
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::cache::control::CacheController;
use hellas_rpc::open::OpenDispatcher;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    WorkRefusalCode, WorkRefused, accept_work_response, admit_certificate_response,
    deliver_result_response, exchange_setup_response,
};
use hellas_rpc::peers::{PeerDirectory, PeerId, PeerManager};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidJobAuthorizationV1, PrivateRecord as _, work_id as accepted_work_id,
};
use hellas_rpc::protocol::work_setup::{
    ProviderChannelPolicy, ReadyChannel, WorkChannelDescriptor,
};
use hellas_rpc::serve::{AccountingDispatcher, AdminPolicy, Authorized, MethodDispatcher};
use hellas_rpc::services::cache_control::{CacheControl, CacheControlServer};
use hellas_rpc::services::courtesy::{Courtesy, Open as CourtesyOpen};
use hellas_rpc::services::execute::RunTicket;
use hellas_rpc::services::fetch::{Fetch, Open as FetchOpen};
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::{Work, WorkHandler, WorkServer};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupHandler, WorkSetupServer};
use hellas_rpc::{Assurance, ProducerSigningKey};
use hellas_wire::iroh::{IrohTransport, IrohTransportError};
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireStatus};
use hellas_work::work::{
    CloseEndpoint, PaidEvaluateBackend, RunError, RunOutcome, WorkService, run_accepted_work,
};
use hellas_work::work_close::{FinalizedBlocks, TxSink};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{SetupAdvance, SetupDriveError, SetupProgress, SetupView};
use hellas_work::work_store::{ChannelStore, JobPhase, Role, SetupStore, discover_setups};
use iroh::{Endpoint, EndpointId, SecretKey, endpoint::Connection, endpoint::presets};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use super::node_handler::NodeHandlerImpl;
use super::work_config::WorkRoutes;
use crate::commands::discovery::{DiscoveryAdvertiser, served_alpns, start_server_advertising};
use crate::identity::OpenIdentity;

type ProductionWorkSource = WorkBlocks<VerifiedRemoteLightClient>;

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
    let handle = Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: config.output_cache,
        execute_policy: config.execute_policy,
        queue_capacity: config.queue_size,
        metrics: config.metrics.clone(),
        producer_key: Arc::new(config.producer_key),
        provider_genesis: Arc::new(config.provider_genesis),
        assurance: config.assurance,
        fetch_access_policy,
        fetch_routes: config.fetch_routes,
        fetch_max_in_flight: config.fetch_max_in_flight,
        fetch_queue_capacity: config.fetch_queue_size,
        fetch_replay_max_in_flight: config.fetch_replay_max_in_flight,
        fetch_store,
        #[cfg(feature = "evaluate")]
        artifact_store: config.artifact_store,
        #[cfg(feature = "evaluate")]
        content_store: config.content_store,
        #[cfg(feature = "evaluate")]
        gpu_config: config.gpu_config,
    })
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

    // Every generated `XServer` is wrapped in `AccountingDispatcher`
    // so per-peer counters (`total_requests`, `last_seen_ms`, RTT
    // EMA) are populated for every inbound. That's the producer side
    // of the data that `PeerDirectory::ranked_known_peers` consumes
    // when surfacing `Node/get_known_peers`; without this wrapper
    // the directory the node hands out is always empty.
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
                let server = AccountingDispatcher::new(WorkSetupServer(mounted), manager);
                serve_loop(transport, server).await
            }
            None => {
                let server = AccountingDispatcher::new(WorkSetupServer(UnmountedWork), manager);
                serve_loop(transport, server).await
            }
        }
    } else if let Some(work) = work.filter(|_| alpn == <Work as ServiceMarker>::ALPN.as_bytes()) {
        // The mounted channel answers for itself. Until the runner has
        // been handed one there is no channel to answer from, and this
        // is still the bounded retryable `NotReady` §3 left here.
        match work.handler(&context) {
            Some(mounted) => {
                let server = AccountingDispatcher::new(WorkServer(mounted), manager);
                serve_loop(transport, server).await
            }
            None => {
                let server = AccountingDispatcher::new(WorkServer(UnmountedWork), manager);
                serve_loop(transport, server).await
            }
        }
    } else {
        warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct UnmountedWork;

fn not_ready() -> WorkRefused {
    WorkRefused {
        code: WorkRefusalCode::NotReady as i32,
        reason: "work state is not mounted".to_string(),
    }
}

impl WorkSetupHandler for UnmountedWork {
    fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<ExchangeSetupResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(ExchangeSetupResponse {
            outcome: Some(exchange_setup_response::Outcome::Refused(not_ready())),
        }))
    }
}

impl WorkHandler for UnmountedWork {
    fn accept_work(
        &self,
        _request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(AcceptWorkResponse {
            outcome: Some(accept_work_response::Outcome::Refused(not_ready())),
        }))
    }

    fn deliver_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(DeliverResultResponse {
            outcome: Some(deliver_result_response::Outcome::Refused(not_ready())),
        }))
    }

    async fn stream_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        Err(WireStatus::new(
            hellas_wire::WireCode::Unavailable,
            "paid work channel is not mounted",
        ))
    }

    fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        core::future::ready(Ok(AdmitCertificateResponse {
            outcome: Some(admit_certificate_response::Outcome::Refused(not_ready())),
        }))
    }
}

// ── The clock ─────────────────────────────────────────────────────────
//
// Everything below is a runner and nothing below is a decision. It
// builds no transaction, fixes no deadline, chooses no settlement,
// judges no duty due, and does not decide whether admission is on: each
// of those is a library edge it calls on a cadence, and the cadence is
// the whole of what this file adds. What it owns is *when* — and the
// journals, which is why it hands them to nobody.

/// What the clock over one node's paid-work journals is built from.
///
/// Every field is something the serve path has already loaded and
/// checked. The policy most of all: it is the loaded work
/// configuration's, carried here rather than derived again, so there is
/// no second place a node could decide what it countersigns over.
pub(super) struct WorkRunnerConfig {
    /// The network the journals are keyed and the signatures bound to.
    pub(super) network: NetworkId,
    /// The threshold identity finalized blocks must authenticate under.
    pub(super) threshold_identity: Vec<u8>,
    /// The configured root the setup journals live under.
    pub(super) journal_root: PathBuf,
    /// Bilateral routes from authenticated peers to owned journals.
    pub(super) routes: WorkRoutes,
    /// The validator RPCs a read and a submission go to.
    pub(super) validators: Vec<String>,
    /// How often the clock ticks.
    pub(super) poll: Duration,
    /// The key every settlement this node signs is signed with.
    pub(super) settlement_key: Secp256k1Signer,
    /// What every setup endpoint this node builds countersigns over.
    pub(super) policy: ProviderChannelPolicy,
}

/// The channel this node answers `Work` from, once the runner has been
/// handed one.
///
/// Written by the runner and read by the accept loop. What crosses is a
/// clone of a handler whose mutable pieces are themselves behind `Arc`s,
/// so the lock is held for a clone and never across a request: the
/// dispatch path never waits while holding the mount, and the clock never
/// waits on a request.
#[derive(Clone)]
pub(super) struct MountedWork<S> {
    mounted: Arc<Mutex<BTreeMap<PeerId, Vec<MountedWorkService<S>>>>>,
    driver: Option<AcceptedWorkDriver>,
}

impl<S> Default for MountedWork<S> {
    fn default() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            driver: None,
        }
    }
}

/// A cloneable, type-erased owner of the backend that runs accepted work.
///
/// The production value owns an [`hellas_executor::ExecutorHandle`].
/// Keeping the backend behind this narrow local seam means the clock and
/// ALPN dispatcher stay parameterized only over their finalized source;
/// neither has a second opinion about paid admission or execution failure.
#[derive(Clone)]
struct AcceptedWorkDriver(Arc<dyn DriveAcceptedWork>);

trait DriveAcceptedWork: Send + Sync {
    fn run(
        &self,
        service: WorkService,
        ready: ReadyChannel,
        work_id: Digest,
    ) -> BoxFuture<'static, Result<RunOutcome, RunError>>;
}

struct BackendWorkDriver<B> {
    backend: Arc<B>,
}

impl<B> DriveAcceptedWork for BackendWorkDriver<B>
where
    B: PaidEvaluateBackend + Send + Sync + 'static,
{
    fn run(
        &self,
        service: WorkService,
        ready: ReadyChannel,
        work_id: Digest,
    ) -> BoxFuture<'static, Result<RunOutcome, RunError>> {
        let backend = Arc::clone(&self.backend);
        Box::pin(
            async move { run_accepted_work(&service, &ready, backend.as_ref(), work_id).await },
        )
    }
}

impl AcceptedWorkDriver {
    fn new<B>(backend: B) -> Self
    where
        B: PaidEvaluateBackend + Send + Sync + 'static,
    {
        Self(Arc::new(BackendWorkDriver {
            backend: Arc::new(backend),
        }))
    }

    /// Starts one accepted job without lending its lifetime to either the
    /// request path or the close clock.
    fn spawn(&self, service: WorkService, ready: ReadyChannel, work_id: Digest) {
        let running = self.0.run(service, ready, work_id);
        let span = hellas_rpc::request_span!(target: "hellas_request", "paid.provider.execute", hellas.work.id = ?work_id, otel.status_code = tracing::field::Empty);
        tokio::spawn(tracing::Instrument::instrument(
            async move {
                match running.await {
                    Ok(RunOutcome::Completed { .. }) => {
                        debug!(?work_id, "the accepted paid job completed")
                    }
                    Ok(RunOutcome::Ready { .. }) => {
                        debug!(?work_id, "the accepted paid job was already complete")
                    }
                    Ok(RunOutcome::Running) => {
                        debug!(?work_id, "the accepted paid job was already running")
                    }
                    Ok(RunOutcome::Indeterminate) => {
                        warn!(
                            ?work_id,
                            "the accepted paid job is indeterminate after restart"
                        )
                    }
                    // `run_accepted_work` has already made backend and
                    // transcript faults terminal before returning them. The
                    // remaining errors have no node-local terminal policy;
                    // keep the exact failure visible to the operator.
                    Err(error) => {
                        tracing::Span::current().record("otel.status_code", "ERROR");
                        warn!(?work_id, %error, "the accepted paid job did not complete");
                    }
                }
            },
            span,
        ));
    }
}

/// One mounted channel's served handler.
///
/// `source` is replaceable because the runner redials a failed validator.
/// The request path copies the current source under the plain mutex and
/// drops that guard before its coherent read awaits. `accepting` spans the
/// complete fresh-read-to-signature sequence, so two acceptance attempts
/// cannot each refresh and then race to consume the same channel credit.
#[derive(Clone)]
struct MountedWorkService<S> {
    bond_edge: EdgeId,
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    source: Arc<Mutex<S>>,
    accepting: Arc<AsyncMutex<()>>,
    driver: Option<AcceptedWorkDriver>,
}

impl<S> MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    /// Re-establishes admission from one fresh coherent read.
    ///
    /// The service is the exact clone the runner drives. Its cursor is
    /// checked after readiness, and that same service receives the fresh
    /// decision before the raw handler is reached. A missing policy,
    /// failed read, failed predicate, lagging cursor, or endpoint failure
    /// therefore leaves the request on the retryable `NotReady` side.
    async fn refresh_admission(&self) -> anyhow::Result<ReadyChannel> {
        // A `std::sync::MutexGuard` is deliberately confined to this
        // block. Holding the source-slot guard across the read would make
        // this handler's future non-`Send` and is not a valid dispatch.
        let source = {
            let held = self
                .source
                .lock()
                .map_err(|_| anyhow::anyhow!("the finalized source lock is poisoned"))?;
            held.clone()
        };
        refresh_work_admission(&self.service, self.descriptor.as_ref(), &source).await
    }

    async fn refresh_delivery(&self, request: &DeliverResultRequest) -> anyhow::Result<()> {
        let Ok(bytes) = request.work_id.as_slice().try_into() else {
            return Ok(());
        };
        let work_id = Digest::from_bytes(bytes);
        let active = self
            .service
            .with_state(|state| state.job_by_id(work_id).is_some());
        if !matches!(active, Ok(true)) {
            return Ok(());
        }
        // A restarted mount has no readiness cached. A retained result must
        // be collectable without first accepting another job. Terminal replies
        // need no fresh admission and are authenticated by the core service.
        let _accepting = self.accepting.lock().await;
        let result = self.refresh_admission().await;
        if let Err(error) = &result {
            debug!(%error, "a delivery attempt found no fresh channel readiness");
        }
        result.map(|_| ())
    }
}

/// Re-establishes admission for the exact driven channel from one coherent
/// finalized read.
///
/// Both the wire handler and restart recovery call this function. A recovered
/// job therefore gets no weaker interpretation of readiness than a new job,
/// and neither path can accidentally trust the readiness cached at mount.
async fn refresh_work_admission<S>(
    service: &WorkService,
    descriptor: Option<&WorkChannelDescriptor>,
    source: &S,
) -> anyhow::Result<ReadyChannel>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    let Some(descriptor) = descriptor else {
        anyhow::bail!("this channel has no admission descriptor");
    };
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: descriptor.channel().payment_edge(),
        funding: Default::default(),
    };
    let Some(snapshot) = source
        .work_channel_snapshot(query.clone())
        .await
        .context("the fresh coherent channel read failed")?
    else {
        anyhow::bail!("no finalized channel snapshot is available");
    };
    if snapshot.query() != &query {
        anyhow::bail!("the finalized source answered for another channel");
    }
    let ready = descriptor
        .check_ready(&snapshot.observed_channel())
        .context("the fresh channel snapshot is not ready")?;
    // Keep one snapshot as the target. Recovery runs on the clock itself,
    // so waiting for another tick here would prevent the cursor advancing.
    // Take the service's existing driver when available; a concurrent clock
    // drive keeps that authority until it finishes its own catch-up.
    for _ in 0..16 {
        let cursor = service
            .with_state(|state| state.cursor().0)
            .context("the mounted channel cursor is unavailable")?;
        if ready.check_caught_up(cursor).is_ok() {
            break;
        }
        if let Ok(mut driver) = service.drive() {
            driver
                .catch_up(source)
                .await
                .context("the mounted channel could not catch up to the fresh snapshot")?;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let cursor = service
        .with_state(|state| state.cursor().0)
        .context("the mounted channel cursor is unavailable")?;
    ready
        .check_caught_up(cursor)
        .context("the mounted channel has not caught up to the fresh snapshot")?;
    service
        .admit_new_work(ready.clone())
        .context("the driven work service refused its fresh readiness")?;
    Ok(ready)
}

impl<S> WorkHandler for MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send, WireStatus>
    {
        if let Some(response) = self.service.precheck_acceptance(&request) {
            return Ok(response);
        }
        let _accepting = self.accepting.lock().await;
        // A preceding request or the clock may have resolved this proposal
        // while admission was serialized. Retained replies need no fresh read.
        if let Some(response) = self.service.precheck_acceptance(&request) {
            return Ok(response);
        }
        let ready = match self.refresh_admission().await {
            Ok(ready) => ready,
            Err(error) => {
                debug!(%error, "an acceptance attempt found no fresh channel readiness");
                return Ok(AcceptWorkResponse {
                    outcome: Some(accept_work_response::Outcome::Refused(WorkRefused {
                        code: WorkRefusalCode::NotReady as i32,
                        reason: "fresh channel readiness is unavailable".to_string(),
                    })),
                });
            }
        };
        // Derive the id from the request while the accepted response
        // is still only a possibility. The response carries only the
        // provider signature, and consulting `state.jobs().next()` after it
        // leaves would race the clock terminalizing that same job.
        let work_id = self
            .service
            .with_state(|state| {
                PaidJobAuthorizationV1::decode(&request.authorization)
                    .ok()
                    .map(|authorization| accepted_work_id(state.channel(), &authorization))
            })
            .ok()
            .flatten();
        let response = self.service.accept(&request);
        if matches!(
            response.outcome.as_ref(),
            Some(accept_work_response::Outcome::Accepted(_))
        ) {
            match (self.driver.as_ref(), work_id) {
                (Some(driver), Some(work_id)) => {
                    driver.spawn(self.service.clone(), ready, work_id);
                }
                (None, Some(work_id)) => {
                    warn!(?work_id, "accepted paid work has no execution backend")
                }
                (_, None) => warn!("accepted paid work has no mounted job to execute"),
            }
        }
        Ok(response)
    }

    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send, WireStatus>
    {
        let response: hellas_rpc::call::WithTrailer<DeliverResultResponse> =
            if self.refresh_delivery(&request).await.is_ok() {
                self.service.deliver_result(request, context).await?.into()
            } else {
                DeliverResultResponse {
                    outcome: Some(deliver_result_response::Outcome::Refused(WorkRefused {
                        code: WorkRefusalCode::NotReady as i32,
                        reason: "fresh channel readiness is unavailable".to_string(),
                    })),
                }
                .into()
            };
        Ok(response)
    }

    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        if self.refresh_delivery(&request).await.is_ok() {
            self.service.stream_result(request, context).await
        } else {
            Err(WireStatus::new(
                hellas_wire::WireCode::Unavailable,
                "fresh channel readiness is unavailable",
            ))
        }
    }

    fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> impl core::future::Future<
        Output = Result<
            impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send,
            WireStatus,
        >,
    > + Send {
        self.service.admit_certificate(request, context)
    }
}

impl<S: Clone> MountedWork<S> {
    fn with_backend<B>(backend: B) -> Self
    where
        B: PaidEvaluateBackend + Send + Sync + 'static,
    {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            driver: Some(AcceptedWorkDriver::new(backend)),
        }
    }

    /// Adds one owned channel under its authenticated peer.
    ///
    /// A peer is served only while exactly one channel is mounted under
    /// it. Retaining a second candidate rather than overwriting either one
    /// makes an ambiguity fail closed instead of turning insertion order
    /// into routing policy.
    fn mount(
        &self,
        peer: PeerId,
        bond_edge: EdgeId,
        service: &WorkService,
        descriptor: Option<WorkChannelDescriptor>,
        accepting: Arc<AsyncMutex<()>>,
        source: &S,
    ) -> bool {
        match self.mounted.lock() {
            Ok(mut held) => {
                let mounted = held.entry(peer).or_default();
                mounted.push(MountedWorkService {
                    bond_edge,
                    service: service.clone(),
                    descriptor,
                    source: Arc::new(Mutex::new(source.clone())),
                    accepting,
                    driver: self.driver.clone(),
                });
                mounted.len() == 1
            }
            Err(_) => false,
        }
    }

    /// The one handler mounted for the transport-vouched peer.
    fn handler(&self, context: &TransportContext) -> Option<MountedWorkService<S>> {
        let peer = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))?;
        self.mounted.lock().ok().and_then(|held| {
            let [mounted] = held.get(&peer)?.as_slice() else {
                return None;
            };
            Some(mounted.clone())
        })
    }

    /// The mounted channel's service, reached through the served
    /// handler.
    ///
    /// Only the tests below ask for it. Serving takes [`Self::handler`],
    /// and the clock drives the very same [`WorkService`] out of
    /// [`Driven::Channel`] without asking the mount for it — so this
    /// exists to let a test read the state of what the node is actually
    /// answering from, and scoping it to `cfg(test)` is what keeps the
    /// served slot to the one accessor that serves.
    #[cfg(test)]
    fn service(&self, context: &TransportContext) -> Option<WorkService> {
        self.handler(context).map(|mounted| mounted.service)
    }

    /// Replaces the finalized source for the matching driven channel.
    ///
    /// A reconnect reaches handlers already cloned by live connections,
    /// because they share this inner source slot. Neither mount lock is
    /// held across a source request.
    fn refresh_source(&self, peer: PeerId, bond_edge: EdgeId, source: &S) {
        let source_slot = self.mounted.lock().ok().and_then(|held| {
            held.get(&peer)?
                .iter()
                .find(|mounted| mounted.bond_edge == bond_edge)
                .map(|mounted| Arc::clone(&mounted.source))
        });
        if let Some(source_slot) = source_slot
            && let Ok(mut held) = source_slot.lock()
        {
            *held = source.clone();
        }
    }

    /// Stops serving `Work` from every channel.
    ///
    /// The clock's last act. A channel nobody is advancing is not a
    /// channel to answer from — its journal is closed the moment the
    /// runner drops it, and a handler still holding it open would be the
    /// one thing keeping the files this process no longer owns.
    fn clear_all(&self) {
        if let Ok(mut held) = self.mounted.lock() {
            held.clear();
        }
    }
}

/// Provider setups this node answers `WorkSetup` from by authenticated peer.
///
/// Written by discovery and read by the accept loop, beside
/// [`MountedWork`]. The clone in this slot is the exact [`SetupService`]
/// stored in [`Driven::Setup`], so serving and driving share one exclusive
/// journal rather than attempting to reopen it.
#[derive(Clone, Debug, Default)]
pub(super) struct MountedSetup(Arc<Mutex<BTreeMap<PeerId, Vec<MountedSetupService>>>>);

#[derive(Clone, Debug)]
struct MountedSetupService {
    bond_edge: EdgeId,
    service: SetupService,
}

impl MountedSetup {
    /// Adds one owned setup under its authenticated peer.
    fn mount(&self, peer: PeerId, bond_edge: EdgeId, service: &SetupService) -> bool {
        match self.0.lock() {
            Ok(mut held) => {
                let mounted = held.entry(peer).or_default();
                mounted.push(MountedSetupService {
                    bond_edge,
                    service: service.clone(),
                });
                mounted.len() == 1
            }
            Err(_) => false,
        }
    }

    /// The exact setup service mounted for the transport-vouched peer,
    /// cloned without holding the map across dispatch.
    fn service(&self, context: &TransportContext) -> Option<SetupService> {
        let peer = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))?;
        self.0.lock().ok().and_then(|held| {
            let [mounted] = held.get(&peer)?.as_slice() else {
                return None;
            };
            Some(mounted.service.clone())
        })
    }

    /// Stops serving only the setup that made this transition.
    fn clear(&self, peer: PeerId, bond_edge: EdgeId) {
        if let Ok(mut held) = self.0.lock()
            && let Some(mounted) = held.get_mut(&peer)
        {
            mounted.retain(|mounted| mounted.bond_edge != bond_edge);
            if mounted.is_empty() {
                held.remove(&peer);
            }
        }
    }

    /// Stops serving every setup during runner shutdown.
    fn clear_all(&self) {
        if let Ok(mut held) = self.0.lock() {
            held.clear();
        }
    }
}

/// One journal, and what the clock drives it as.
///
/// Two live states and one transition between them: a setup is driven
/// until it hands back the channel it mounted, and from then on the
/// channel is what is driven. Nothing here re-derives a mount —
/// [`SetupAdvance::mounted`] is the only way a [`ChannelStore`] reaches
/// this file, and the setup is not driven again afterwards, because a
/// second step would open a second journal on the same file.
enum Driven {
    /// The journal is driven behind the setup service that answers for
    /// it. The policy is retained beside the service: it is the provider
    /// authority from which the full channel descriptor is rebuilt after
    /// the setup reveals its actual terms.
    Setup {
        /// The endpoint this journal is both driven and served behind.
        service: SetupService,
        /// The retained provider authority, behind a pointer.
        ///
        /// Boxed because it is the widest thing this enum carries by a
        /// long way — every other payload here is a handle or a store
        /// pointer, one or two words each — and a journal is one value
        /// with three shapes, so the two that hold no policy would
        /// otherwise each be as large as the one that does.
        /// [`PaymentAdmission`] already holds it behind the same
        /// indirection, and this is built from that one, once per
        /// journal at startup.
        policy: Box<ProviderChannelPolicy>,
    },
    /// The channel this setup mounted, including the recovery authority
    /// needed to finish a job accepted before a process restart.
    Channel(Box<DrivenChannel>),
    /// The setup ended, or its mount was refused. Nothing left to
    /// drive.
    Done,
}

/// One mounted channel as driven by the paid-work clock.
///
/// Recovery lives here rather than in the served route: an accepted job is an
/// obligation recorded by this journal even if peer routing changes while the
/// process is down. `accepting` is also lent to the route when one is mounted,
/// so live acceptance and restart recovery serialize their readiness checks.
struct DrivenChannel {
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    accepting: Arc<AsyncMutex<()>>,
    driver: Option<AcceptedWorkDriver>,
}

impl DrivenChannel {
    fn accepted_work_id(&self) -> anyhow::Result<Option<Digest>> {
        self.service
            .with_state(|state| {
                let mut jobs = state.jobs();
                let job = jobs.next()?;
                (jobs.next().is_none() && job.phase() == JobPhase::Accepted).then(|| job.work_id())
            })
            .context("the driven channel state is unavailable")
    }

    /// Starts a journaled Accepted job after proving current readiness.
    ///
    /// No in-memory `attempted` marker is needed. A racing live request or
    /// clock tick reaches the same endpoint; its durable `JobRunning` record
    /// lets exactly one caller receive `Invoke` and every other caller receive
    /// `Running`.
    async fn resume_accepted<S>(&self, source: &S) -> anyhow::Result<bool>
    where
        S: FinalizedBlocks + FinalizedWorkView + Sync,
    {
        if self.accepted_work_id()?.is_none() {
            return Ok(false);
        }
        let _accepting = self.accepting.lock().await;
        let Some(work_id) = self.accepted_work_id()? else {
            return Ok(false);
        };
        let driver = self
            .driver
            .as_ref()
            .context("the accepted paid job has no execution backend")?;
        let ready = refresh_work_admission(&self.service, self.descriptor.as_ref(), source).await?;
        driver.spawn(self.service.clone(), ready, work_id);
        Ok(true)
    }
}

/// One setup journal on a clock.
struct SetupClock {
    /// The bond this journal stakes, so a log line names which one.
    bond_edge: EdgeId,
    /// The authenticated peer whose configured route names this bond.
    /// Together with `bond_edge`, this is the journal's route identity;
    /// `None` keeps an unconfigured owned journal on its close clock
    /// without making it a fallback service.
    route_peer: Option<PeerId>,
    /// What is being driven for it.
    driven: Driven,
}

impl SetupClock {
    /// Takes this journal's one step, and says whether the chain
    /// answered.
    ///
    /// A source failure is the only outcome the caller acts on: a
    /// validator that stopped answering is dialled again rather than
    /// asked forever. Everything else is this journal's own business and
    /// is logged where it happens.
    async fn tick<S>(
        &mut self,
        source: &S,
        signer: &Secp256k1Signer,
        work_mount: &MountedWork<S>,
        setup_mount: &MountedSetup,
    ) -> bool
    where
        S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
    {
        let bond = hex::encode(self.bond_edge.to_bytes());
        let mut answered = true;
        // One step of the setup this journal holds, with the policy the
        // mount it may hand back is rebuilt from; nothing, once the
        // journal is past its setup.
        let step = match &mut self.driven {
            Driven::Setup { service, policy } => Some((
                service.advance_setup(source, source, source).await,
                policy.clone(),
            )),
            Driven::Channel(_) | Driven::Done => None,
        };
        if let Some((step, policy)) = step {
            match step {
                Ok(SetupAdvance { progress, mounted }) => {
                    if let Some(store) = mounted {
                        if let Some(peer) = self.route_peer {
                            setup_mount.clear(peer, self.bond_edge);
                        }
                        self.take_mount(store, signer, &policy, source, work_mount);
                    } else if matches!(
                        progress,
                        SetupProgress::Aborted(_) | SetupProgress::Faulted(_)
                    ) {
                        warn!(bond, ?progress, "this setup ended with no channel to drive");
                        self.driven = Driven::Done;
                    } else {
                        debug!(bond, ?progress, "the setup advanced");
                    }
                }
                Err(error) => {
                    answered = !matches!(error, SetupDriveError::Source(_));
                    warn!(bond, %error, "this setup did not advance");
                }
            }
        }
        if let Driven::Channel(channel) = &self.driven {
            if let Some(peer) = self.route_peer {
                work_mount.refresh_source(peer, self.bond_edge, source);
            }
            if let Err(error) = channel.resume_accepted(source).await {
                warn!(bond, %error, "an accepted paid job did not resume");
            }
            match advance_paid_work_clock(&channel.service, source).await {
                Ok(progress) => debug!(bond, ?progress, "the channel advanced"),
                Err(error) => {
                    answered &= !error.source_failed();
                    warn!(bond, %error, "this channel's close did not advance");
                }
            }
        }
        answered
    }

    /// Mounts the store the driver handed back.
    ///
    /// Handed back, never reopened: the journal is exclusive, so a
    /// second `ChannelStore::open` on the same file is a refusal rather
    /// than a second view, and the settlement and origin this one
    /// carries are the ones the completing read established.
    fn take_mount<S: Clone>(
        &mut self,
        store: ChannelStore,
        signer: &Secp256k1Signer,
        policy: &ProviderChannelPolicy,
        source: &S,
        mount: &MountedWork<S>,
    ) {
        let bond = hex::encode(self.bond_edge.to_bytes());
        // The setup's retained policy supplies the provider-controlled
        // fields, while the mounted channel supplies the payment edge and
        // complete terms the two parties actually signed. This is a full
        // descriptor reconstruction, not a mount-time readiness cache.
        let descriptor = {
            let channel = store.state().channel();
            match policy.admit(channel.payment_edge(), channel.payment_terms().clone()) {
                Ok(descriptor) => Some(descriptor),
                Err(error) => {
                    warn!(bond, %error, "the mounted channel no longer satisfies its admission policy");
                    None
                }
            }
        };
        match CloseEndpoint::new(store, signer.clone()) {
            Ok(close) => {
                let service = WorkService::close_only(close);
                let accepting = Arc::new(AsyncMutex::new(()));
                if self.route_peer.is_some_and(|peer| {
                    mount.mount(
                        peer,
                        self.bond_edge,
                        &service,
                        descriptor.clone(),
                        Arc::clone(&accepting),
                        source,
                    )
                }) {
                    info!(
                        bond,
                        "this node now answers Work from the channel it mounted"
                    );
                } else {
                    warn!(
                        bond,
                        "this channel has no unique peer route; it is driven and not served",
                    );
                }
                self.driven = Driven::Channel(Box::new(DrivenChannel {
                    service,
                    descriptor,
                    accepting,
                    driver: mount.driver.clone(),
                }));
            }
            // The journal and the key are not both the provider's view
            // of one channel. Nothing this runner can do about it, and
            // dropping the mount is what stops it being reopened every
            // tick.
            Err(error) => {
                warn!(bond, %error, "the mounted channel is not this node's to close");
                self.driven = Driven::Done;
            }
        }
    }
}

/// The clock, over every paid-work journal this node owns.
pub(super) struct WorkRunner<S> {
    clocks: Vec<SetupClock>,
    signer: Secp256k1Signer,
    work_mount: MountedWork<S>,
    setup_mount: MountedSetup,
    poll: Duration,
    validators: Vec<String>,
    consensus_verifier: ConsensusVerifier,
}

impl<S> WorkRunner<S>
where
    S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
{
    /// Opens every setup journal under the configured root.
    ///
    /// The root and the network are the whole of what a restarting node
    /// is told; the bond each journal is about and the role it was
    /// written at come out of the files, which is what `discover_setups`
    /// is for. A journal that cannot be named is reported and not
    /// skipped silently: a file this node cannot open may be a channel
    /// it still owes a close.
    ///
    /// # Errors
    ///
    /// When the root itself cannot be enumerated.
    /// Every owned journal is driven. A configured route additionally
    /// mounts its exact setup service under the authenticated peer that
    /// names it; an unconfigured journal remains a close duty, not a
    /// fallback answer.
    pub(super) fn discover(
        config: WorkRunnerConfig,
        work_mount: MountedWork<S>,
        setup_mount: MountedSetup,
    ) -> anyhow::Result<Self> {
        let consensus_verifier = ConsensusVerifier::new(&ConsensusInfo {
            validators: config.validators.clone(),
            threshold_identity: config.threshold_identity,
            network_id: config.network.as_str().to_owned(),
        })
        .context("the configured threshold identity is not usable")?;
        let settlement_verifier = Secp256k1Verifier::new();
        let found = discover_setups(&config.journal_root, config.network).with_context(|| {
            format!(
                "failed to enumerate the work journals under {}",
                config.journal_root.display(),
            )
        })?;
        for unnamed in &found.unidentified {
            warn!(
                path = %unnamed.path.display(),
                reason = %unnamed.reason,
                "a setup journal under the work root could not be named",
            );
        }
        let mut clocks = Vec::with_capacity(found.setups.len());
        for setup in found.setups {
            let bond = hex::encode(setup.bond_edge.to_bytes());
            let route_peer = config
                .routes
                .iter()
                .find(|route| route.bond == setup.bond_edge)
                .map(|route| route.peer);
            // A close capability binds the provider half, and this
            // process holds the provider's key. A client journal beside
            // this node's own is another party's, and this runner has
            // nothing to sign for it.
            if setup.role != Role::Provider {
                warn!(
                    bond,
                    "a setup journal under the work root is not this node's half"
                );
                continue;
            }
            let store = match SetupStore::open(
                &config.journal_root,
                config.network,
                setup.bond_edge,
                setup.role,
                &settlement_verifier,
            ) {
                Ok(store) => store,
                Err(error) => {
                    warn!(bond, %error, "a discovered setup journal did not open");
                    continue;
                }
            };
            let policy = Box::new(config.policy.clone());
            let service = SetupService::new(SetupEndpoint::new(
                store,
                config.settlement_key.clone(),
                PaymentAdmission::Admits(policy.clone()),
            ));
            if let Some(peer) = route_peer {
                if setup_mount.mount(peer, setup.bond_edge, &service) {
                    info!(
                        bond,
                        "this node now answers WorkSetup from its driven setup"
                    );
                } else {
                    warn!(bond, "this provider setup has an ambiguous peer route");
                }
            } else {
                warn!(bond, "this provider setup has no configured peer route");
            }
            let driven = Driven::Setup { service, policy };
            clocks.push(SetupClock {
                bond_edge: setup.bond_edge,
                route_peer,
                driven,
            });
        }
        Ok(Self {
            clocks,
            signer: config.settlement_key,
            work_mount,
            setup_mount,
            poll: config.poll,
            validators: config.validators,
            consensus_verifier,
        })
    }

    /// Takes one step of every journal, and says whether the chain
    /// answered all of them.
    async fn tick(&mut self, source: &S) -> bool {
        let mut answered = true;
        for clock in &mut self.clocks {
            answered &= clock
                .tick(source, &self.signer, &self.work_mount, &self.setup_mount)
                .await;
        }
        answered
    }

    /// The loop, over whatever chain `dial` produces.
    ///
    /// One tick of every journal per period, and a chain that stopped
    /// answering is dialled again rather than asked forever. The whole
    /// of the cadence is here, and none of the decisions are.
    async fn run_over<D, F>(mut self, mut stop: oneshot::Receiver<()>, dial: D)
    where
        D: Fn() -> F,
        F: core::future::Future<Output = Option<S>>,
    {
        if self.clocks.is_empty() {
            info!("no provider setup journal under the work root; the clock has nothing to drive");
            self.work_mount.clear_all();
            self.setup_mount.clear_all();
            return;
        }
        let mut chain = None;
        loop {
            tokio::select! {
                _ = &mut stop => break,
                () = tokio::time::sleep(self.poll) => {}
            }
            let Some(source) = chain.take() else {
                chain = dial().await;
                continue;
            };
            if self.tick(&source).await {
                chain = Some(source);
            }
        }
        self.work_mount.clear_all();
        self.setup_mount.clear_all();
        info!("the paid-work clock stopped, and its journals are closed");
    }
}

impl WorkRunner<ProductionWorkSource> {
    /// Ticks until told to stop, over the validators the configuration
    /// names.
    async fn run(self, stop: oneshot::Receiver<()>) {
        let validators = self.validators.clone();
        let verifier = self.consensus_verifier.clone();
        self.run_over(stop, move || {
            let validators = validators.clone();
            let verifier = verifier.clone();
            async move { connect_chain(&validators, verifier).await }
        })
        .await;
    }
}

/// Rotate the first candidate on reconnect, including when a connected peer
/// cannot supply historical finalized blocks. Reads and submissions use the
/// selected verified connection.
///
/// One endpoint for both directions. §1's concurrent fan-out to all six
/// is a submission strategy with an outcome rule, and neither exists in
/// this tree yet; inventing one here would be the runner deciding what
/// a submission means.
async fn connect_chain(
    validators: &[String],
    verifier: ConsensusVerifier,
) -> Option<ProductionWorkSource> {
    static NEXT_VALIDATOR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let start =
        NEXT_VALIDATOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % validators.len();
    for url in validators.iter().cycle().skip(start).take(validators.len()) {
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => {
                info!(validator = %url, "the paid-work clock reads and submits here");
                return Some(WorkBlocks::new(client));
            }
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    None
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
