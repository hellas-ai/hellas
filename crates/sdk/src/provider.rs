use hellas_authority::model::grant::records::{check_grant_provider, grant_transport};
use std::path::PathBuf;
use std::sync::Arc;

use hellas_attestation::RootProver;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRouteRegistry};
use hellas_rpc::open::OpenDispatcher;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::signature_wire::signature_to_pb;
use hellas_rpc::{
    Assurance, OPEN_NONCE_LEN, ProviderEnrollmentBundle, RootProof, open_proof_binding,
};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireCode, WireStatus,
};
use iroh::{Endpoint, EndpointId, endpoint::presets};

use crate::NodeIdentity;

/// Startup errors, before a provider accepts requests.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Control(#[from] WireStatus),
    #[error("provider requires a Work funding configuration")]
    FundingRequired,
    #[error("paid channel names an unavailable Fetch route or manifest")]
    MissingPaidRoute,
    #[error("Fetch provider requires a paid Fetch policy")]
    WrongPaidPolicy,
    #[error("provider enrollment does not match this identity")]
    Identity,
    #[error(transparent)]
    GrantConfig(#[from] crate::grant_provider::GrantProviderError),
    #[error(transparent)]
    Grant(#[from] hellas_authority::model::grant::records::GrantError),
    #[error(transparent)]
    NodeStore(#[from] hellas_authority::work_store::grant::NodeStoreError),
    #[error("invalid provider settlement key")]
    SettlementKey,
    #[error(transparent)]
    RouteBinding(#[from] hellas_executor::FetchRouteBindingError),
    #[error(transparent)]
    DuplicateRoute(#[from] hellas_executor::DuplicateFetchRoute),
    #[error(transparent)]
    Executor(#[from] hellas_executor::ExecutorError),
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    Address(#[from] iroh::endpoint::InvalidSocketAddr),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("discovery could not start: {0}")]
    Discovery(String),
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[error(transparent)]
    Paid(#[from] crate::paid_provider::PaidProviderError),
}

/// Paid policy and its process-owned executing chain node.
pub struct PaidProviderOptions {
    config: crate::work_config::WorkConfig,
    node: crate::FullNode,
}
impl PaidProviderOptions {
    pub fn new(
        config: crate::work_config::WorkConfig,
        node: crate::FullNode,
    ) -> Result<Self, crate::work_config::WorkConfigError> {
        config.check_node(&node)?;
        Ok(Self { config, node })
    }
}

/// An attested Fetch provider with an operator-supplied route registry.
pub struct FetchProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: NodeIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub grants: Option<crate::GrantProviderOptions>,
    pub routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub paid_work: Option<PaidProviderOptions>,
}

impl<R> FetchProviderOptions<R> {
    /// Validate Fetch-specific configuration before starting the shared native host.
    pub async fn prepare(self) -> Result<ProviderOptions<R>, ProviderError> {
        let options = self;
        let has_paid_work = options.paid_work.is_some();
        let has_grants = options.grants.is_some();
        if !has_paid_work && !has_grants {
            return Err(ProviderError::FundingRequired);
        }
        let assurance = match options.enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => Assurance::ProducerSigned,
            hellas_rpc::RootKind::SecureEnclave => Assurance::AppleAppAttest,
        };
        if let Some(grants) = &options.grants {
            crate::grant_provider::ProviderResources::Fetch(&options.routes)
                .validate(&grants.policies)?;
        }
        let work_config = options
            .paid_work
            .map(|PaidProviderOptions { config, node }| {
                let settlement_key = hellas_kernel::Secp256k1Signer::from_secret_scalar(
                    options.identity.node_secret_bytes(),
                )
                .map_err(|_| ProviderError::SettlementKey)?;
                let runner_config = crate::paid_provider::WorkRunnerConfig {
                    network: config.chain.network,
                    journal_root: config.journal_root,
                    poll: config.poll,
                    max_observation_age: config.max_observation_age,
                    settlement_key,
                };
                runner_config.validate()?;
                Ok::<_, ProviderError>((runner_config, node))
            })
            .transpose()?;
        let producer_key = Arc::new(options.identity.node_key().clone());
        let mut executor_config =
            ExecutorSpawnConfig::new(producer_key.clone(), assurance, options.routes);
        executor_config.fetch_max_in_flight = options.fetch_max_in_flight;
        executor_config.fetch_queue_capacity = options.fetch_queue_capacity;
        Ok(ProviderOptions {
            port: options.port,
            secret_key: options.identity.transport_key(),
            open_identity: Arc::new(ProviderOpen::new(
                producer_key,
                options.enrollment,
                Some(options.root),
            )?),
            executor: executor_config,
            grants: options.grants.map(|config| ProviderGrants {
                config,
                authority: ProviderAuthority::Journal {
                    root: options.state_directory.join("grants"),
                },
            }),
            work: work_config,
            build: String::new(),
            graffiti: Vec::new(),
            discovery: false,
        })
    }
}

/// Optional local control and explicitly admitted remote control peers.
pub struct ProviderControl {
    pub socket: PathBuf,
    pub tls: Arc<rustls::ServerConfig>,
    pub remote: crate::node_control::RemoteControlAdmission,
}

/// Already initialized node authority and the resources available on this host.
#[derive(Clone)]
pub struct ProviderGrants {
    pub config: crate::GrantProviderOptions,
    pub authority: ProviderAuthority,
}

/// A standalone provider opens its journal once; an embedded provider attaches
/// to the host's existing control service and writer.
#[derive(Clone)]
pub enum ProviderAuthority {
    Journal { root: PathBuf },
    Host(Box<crate::node_control::NodeControl>),
}
impl ProviderAuthority {
    fn remote_admission(&self) -> crate::node_control::RemoteControlAdmission {
        match self {
            Self::Journal { .. } => Default::default(),
            Self::Host(control) => control.remote_admission(),
        }
    }
}

impl ProviderGrants {
    pub(crate) async fn open(
        &self,
        resources: crate::grant_provider::ProviderResources<'_>,
        provider: &ProviderEnrollmentBundle,
    ) -> Result<hellas_authority::node::NodeCoordinator, ProviderError> {
        resources.validate(&self.config.policies)?;
        match &self.authority {
            ProviderAuthority::Journal { root, .. } => {
                Ok(hellas_authority::node::NodeCoordinator::new(
                    hellas_authority::work_store::grant::NodeStore::open(
                        root,
                        hellas_authority::model::grant::grant_network(),
                        Some(provider.clone()),
                        hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
                    )
                    .await?,
                    Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
                ))
            }
            ProviderAuthority::Host(control) => {
                let node = control.node();
                node.check_provider(provider).await?;
                Ok(node)
            }
        }
    }
}

/// Shared provider composition for Fetch, local evaluation and optional paid work.
/// The caller owns discovery advertising and the executing chain node's lifetime.
pub struct ProviderOptions<R> {
    pub executor: ExecutorSpawnConfig,
    pub grants: Option<ProviderGrants>,
    pub port: Option<u16>,
    pub build: String,
    pub graffiti: Vec<u8>,
    pub discovery: bool,
    pub work: Option<(WorkRunnerConfig, crate::FullNode)>,
    pub secret_key: iroh::SecretKey,
    pub open_identity: Arc<ProviderOpen<R>>,
}

impl<R> Clone for ProviderOptions<R> {
    fn clone(&self) -> Self {
        Self {
            executor: self.executor.clone(),
            grants: self.grants.clone(),
            port: self.port,
            build: self.build.clone(),
            graffiti: self.graffiti.clone(),
            work: self.work.clone(),
            secret_key: self.secret_key.clone(),
            open_identity: self.open_identity.clone(),
            discovery: self.discovery,
        }
    }
}

impl<R> ProviderOptions<R> {
    /// Select shared host ownership before starting any service or opening a journal.
    pub fn on_host(
        mut self,
        control: crate::node_control::NodeControl,
    ) -> Result<Self, ProviderError> {
        self.grants
            .as_mut()
            .ok_or(ProviderError::FundingRequired)?
            .authority = ProviderAuthority::Host(Box::new(control));
        Ok(self)
    }
}

use crate::paid_provider::{MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher};
use crate::transport_admission::{
    Admission, AdmittedConnection, IDLE_TIMEOUT, MAX_CONNECTIONS, MAX_LIFETIME,
};
use crate::work_router::WorkRouter;
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::Work;
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupServer};
use hellas_wire::peers::{PeerDirectory, PeerId, PeerManager};
use hellas_wire::serve::AccountingDispatcher;
use iroh::endpoint::{Connection, Incoming};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{debug, warn};
mod discovery;
mod node;
use node::NodeHandlerImpl;
const MAX_RPC_IN_FLIGHT_PER_CONNECTION: usize = 16;

enum IncomingConnection {
    Standalone(Box<Incoming>),
    Host(AdmittedConnection),
}
impl IncomingConnection {
    fn refuse(self) {
        match self {
            Self::Standalone(incoming) => (*incoming).refuse(),
            Self::Host(connection) => drop(connection),
        }
    }
}

const RPC_CONNECTION_IDLE_TIMEOUT: Duration = IDLE_TIMEOUT;
pub struct ProviderHandle {
    configuration: Option<crate::node_control::configuration::ProviderMetadata>,
    administration: Option<hellas_authority::grant_service::WorkAdministration>,
    router: Option<WorkRouter>,
    discovery: Option<discovery::DiscoveryAdvertiser>,
    stop: Option<oneshot::Sender<()>>,
    drained: Option<oneshot::Sender<()>>,
    alpns: Vec<Vec<u8>>,
    endpoint: Endpoint,
    owns_endpoint: bool,
    accept_task: tokio::task::JoinHandle<()>,
    work: Option<WorkWatcher>,
}

impl ProviderHandle {
    pub fn with_configuration(
        mut self,
        metadata: crate::node_control::configuration::ProviderMetadata,
    ) -> Self {
        self.configuration = Some(metadata);
        self
    }
    pub(crate) fn configuration(
        &self,
    ) -> Option<&crate::node_control::configuration::ProviderMetadata> {
        self.configuration.as_ref()
    }

    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn alpns(&self) -> &[Vec<u8>] {
        &self.alpns
    }

    /// Checked native administration over this provider's exact node writer.
    pub fn is_finished(&self) -> bool {
        self.accept_task.is_finished()
    }

    pub fn administration(&self) -> Option<&hellas_authority::grant_service::WorkAdministration> {
        self.administration.as_ref()
    }

    /// Stop ingress, join accepted work and close the endpoint before returning errors.
    pub async fn shutdown(mut self) -> Result<(), ProviderError> {
        self.stop.take();
        let mut result = Ok(());
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown().await;
        }
        if let Some(grants) = self.router.as_ref().and_then(WorkRouter::grant_service) {
            let drained = grants.drain().await.map_err(ProviderError::from);
            result = result.and(drained);
        }
        if let Some(work) = &mut self.work {
            let stopped = work.shutdown().await.map_err(ProviderError::from);
            result = result.and(stopped);
        }
        // Work has reached its durable completion boundary. Stop accepting
        // further substreams, then let already dispatched replies finish.
        self.drained.take();
        let joined = match (&mut self.accept_task).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(ProviderError::Task(error)),
        };
        result = result.and(joined);
        if self.owns_endpoint {
            self.endpoint.close().await;
        }
        result
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

fn served_alpns(
    work_configured: bool,
    grants_configured: bool,
    remote_control: bool,
) -> Vec<Vec<u8>> {
    let mut alpns = vec![Node::ALPN.as_bytes().to_vec()];
    if work_configured {
        alpns.extend([
            hellas_rpc::services::chain_sync::ChainSync::ALPN
                .as_bytes()
                .to_vec(),
            WorkSetup::ALPN.as_bytes().to_vec(),
            Work::ALPN.as_bytes().to_vec(),
        ]);
    }
    if grants_configured && !work_configured {
        alpns.push(Work::ALPN.as_bytes().to_vec());
    }
    if grants_configured && remote_control {
        alpns.push(
            hellas_rpc::services::host_control::HostControl::ALPN
                .as_bytes()
                .to_vec(),
        );
    }
    alpns
}

pub async fn start_fetch_provider<R>(
    config: ProviderOptions<R>,
) -> Result<ProviderHandle, ProviderError>
where
    R: RootProver + Send + Sync + 'static,
{
    if let Some((work, _)) = &config.work {
        work.validate()?;
    }
    let enrollment = &config.open_identity.enrollment;
    check_grant_provider(enrollment)?;
    if grant_transport(enrollment)? != *config.secret_key.public().as_bytes()
        || enrollment.genesis.statement.producer_public_key
            != config.executor.producer_key.public_key()
    {
        return Err(ProviderError::Identity);
    }
    let prepared_grants = match config.grants {
        Some(grants) => {
            let resources = if config.executor.supports_compute() {
                crate::grant_provider::ProviderResources::ComputeAndFetch(
                    &config.executor.fetch_routes,
                )
            } else {
                crate::grant_provider::ProviderResources::Fetch(&config.executor.fetch_routes)
            };
            let store = grants.open(resources, enrollment).await?;
            Some((grants, store))
        }
        None => None,
    };
    let signer = config.executor.producer_key.clone();
    let handle = Executor::spawn_configured(config.executor).await?;
    let remote_control = prepared_grants
        .as_ref()
        .map(|(grants, _)| grants.authority.remote_admission())
        .unwrap_or_default();
    let advertised_alpns = served_alpns(
        config.work.is_some(),
        prepared_grants.is_some(),
        remote_control.enabled(),
    );
    let work_mount = MountedWork::with_backend(handle.clone());
    let setup_mount = MountedSetup::default();
    let chain = config.work.as_ref().map(|(_, chain)| chain.clone());
    let runner = match config.work {
        Some((work, chain)) => Some(
            WorkRunner::discover(work, work_mount.clone(), setup_mount.clone())
                .await?
                .on_node(
                    chain,
                    prepared_grants
                        .as_ref()
                        .ok_or(ProviderError::FundingRequired)?
                        .1
                        .clone(),
                    enrollment.clone(),
                    vec![],
                ),
        ),
        None => None,
    };
    let alpns = advertised_alpns.clone();
    let ingress = match prepared_grants
        .as_ref()
        .map(|(grants, _)| &grants.authority)
    {
        Some(ProviderAuthority::Host(control)) => control.provider_ingress()?,
        _ => None,
    };
    let (endpoint, mut ingress, owns_endpoint) = match ingress {
        Some((endpoint, receiver)) => {
            if endpoint.id() != config.secret_key.public() {
                return Err(ProviderError::Identity);
            }
            (endpoint, Some(receiver), false)
        }
        None => {
            let mut builder = Endpoint::builder(presets::N0)
                .secret_key(config.secret_key)
                .hooks(remote_control.clone())
                .alpns(alpns.clone());
            if let Some(port) = config.port {
                builder = builder.bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?;
            }
            (builder.bind().await?, None, true)
        }
    };
    let discovery = config
        .discovery
        .then(|| discovery::start_server_advertising(&endpoint, &advertised_alpns))
        .transpose()?;
    let node_id = endpoint.id();

    let local_peer = PeerId::from_bytes(*node_id.as_bytes());
    let directory = Arc::new(PeerDirectory::with_config(
        local_peer,
        hellas_rpc::peer_directory_config(),
    ));

    let mut node_handler =
        NodeHandlerImpl::new(node_id, config.build, config.graffiti, directory.clone());
    node_handler.service_alpns = advertised_alpns
        .iter()
        .map(|alpn| String::from_utf8_lossy(alpn).into_owned())
        .collect();
    node_handler.chain = chain.clone();

    let open_identity = config.open_identity;
    let (grants, administration, admin) = if let Some((grants, store)) = prepared_grants {
        let service = hellas_authority::grant_service::GrantService::from_node(
            store,
            &open_identity.enrollment,
            signer,
            handle,
            endpoint
                .addr()
                .ip_addrs()
                .map(ToString::to_string)
                .collect(),
        )
        .await?
        .with_upload_quota(work_mount.upload_quota());
        let administration = hellas_authority::grant_service::WorkAdministration::new(
            service.clone(),
            grants.config.policies,
            grants.config.max_job_millis,
        )?;
        let admin = match grants.authority {
            ProviderAuthority::Host(control) => Some(*control),
            ProviderAuthority::Journal { .. } => None,
        };
        (Some(service), Some(administration), admin)
    } else {
        (None, None, None)
    };
    let work = runner.map(WorkWatcher::spawn);
    let serves_work = match (work.is_some(), grants.as_ref()) {
        (true, Some(grants)) => Some(WorkRouter::both(work_mount, grants.clone())),
        (true, None) => Some(WorkRouter::payment(work_mount)),
        (false, Some(grants)) => Some(WorkRouter::grants(grants.clone())),
        (false, None) => None,
    };
    let serves_setup = work.is_some().then(|| setup_mount.clone());

    let router = serves_work.clone();
    let accept_endpoint = endpoint.clone();
    let (stop, mut stopped) = oneshot::channel();
    let (drained, drain_complete) = oneshot::channel();
    let accept_task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let (quiesce, quiesced) = watch::channel(false);
        let mut admission = Admission::new();
        loop {
            // Both waits are cancellation-safe. Once accepted, a connection's
            // handshake belongs to its task, never to the next select iteration.
            let next = async {
                if let Some(receiver) = &mut ingress {
                    receiver.recv().await.map(IncomingConnection::Host)
                } else {
                    accept_endpoint
                        .accept()
                        .await
                        .map(|incoming| IncomingConnection::Standalone(Box::new(incoming)))
                }
            };
            let incoming = tokio::select! {
                biased;
                _ = &mut stopped => break,
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed { warn!(%error, "node connection task failed"); }
                    continue;
                }
                incoming = next => match incoming { Some(incoming) => incoming, None => break },
            };
            if connections.len() >= MAX_CONNECTIONS {
                incoming.refuse();
                continue;
            }
            let incoming = match incoming {
                IncomingConnection::Standalone(incoming) => {
                    let Some(pending) = admission.accept(*incoming) else {
                        continue;
                    };
                    Ok(pending)
                }
                IncomingConnection::Host(connection) => Err(connection),
            };
            let node_handler_for_conn = node_handler.clone();
            let manager_for_conn = directory.manager();
            let execution_for_conn = open_identity.clone();
            let work_for_conn = serves_work.clone();
            let setup_for_conn = serves_setup.clone();
            let admin_for_conn = admin.clone();
            let mut stopping = quiesced.clone();
            connections.spawn(async move {
                let admitted = match incoming {
                    Err(connection) => connection,
                    Ok(pending) => tokio::select! {
                        _ = quiescing(&mut stopping) => return,
                        connection = pending.finish() => match connection {
                            Some(connection) => connection,
                            None => return,
                        },
                    },
                };
                let conn = admitted.connection.clone();
                let alpn = conn.alpn().to_vec();
                debug!(
                    alpn = %String::from_utf8_lossy(&alpn),
                    "accepted RPC connection"
                );
                if let Some(Err(e)) = admitted
                    .run(serve_connection(
                        alpn,
                        conn,
                        execution_for_conn,
                        node_handler_for_conn,
                        manager_for_conn,
                        setup_for_conn,
                        work_for_conn,
                        admin_for_conn,
                        stopping,
                    ))
                    .await
                {
                    warn!("serve_connection error: {e}");
                }
            });
        }
        let _ = drain_complete.await;
        quiesce.send_replace(true);
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                warn!(%error, "node connection task failed while draining");
            }
        }
    });

    Ok(ProviderHandle {
        configuration: None,
        administration,
        alpns: advertised_alpns,
        router,
        discovery,
        stop: Some(stop),
        drained: Some(drained),
        accept_task,
        endpoint,
        owns_endpoint,
        work,
    })
}

/// Per-connection serve: each inbound substream is dispatched to the
/// service selected by the connection's negotiated ALPN.
#[allow(clippy::too_many_arguments)]
async fn serve_connection<R: RootProver + Send + Sync + 'static>(
    alpn: Vec<u8>,
    conn: Connection,
    open_identity: Arc<ProviderOpen<R>>,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
    setup: Option<MountedSetup>,
    work: Option<WorkRouter>,
    admin: Option<crate::node_control::NodeControl>,
    mut quiesce: watch::Receiver<bool>,
) -> Result<(), ProviderError> {
    if alpn == hellas_rpc::services::host_control::HostControl::ALPN.as_bytes() {
        let admin = admin
            .ok_or_else(|| WireStatus::new(WireCode::Unavailable, "node control is unavailable"))?;
        return tokio::select! {
            _ = quiescing(&mut quiesce) => Ok(()),
            result = admin.serve_iroh(conn) => result.map_err(ProviderError::from),
        };
    }
    let transport = Arc::new(IrohTransport::new(conn));

    // Account for inbound requests and refresh last_seen_ms in the shared registry.
    if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
        serve_loop(transport, server, quiesce).await;
        Ok(())
    } else if alpn == hellas_rpc::services::chain_sync::ChainSync::ALPN.as_bytes()
        && let Some(chain) = node_handler.chain
    {
        let server = AccountingDispatcher::new(
            hellas_rpc::services::chain_sync::ChainSyncServer(chain),
            manager,
        );
        serve_loop(transport, server, quiesce).await;
        Ok(())
    } else if let Some(setup) =
        setup.filter(|_| alpn == <WorkSetup as ServiceMarker>::ALPN.as_bytes())
    {
        let server = AccountingDispatcher::new(
            OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                WorkSetupServer(setup),
                open_identity.clone(),
            ),
            manager,
        );
        serve_loop(transport, server, quiesce).await;
        Ok(())
    } else if let Some(work) = work.filter(|_| alpn == <Work as ServiceMarker>::ALPN.as_bytes()) {
        let connection = tokio::select! {
            _ = quiescing(&mut quiesce) => return Ok(()),
            connection = tokio::time::timeout(IDLE_TIMEOUT, work.accept_iroh(&transport, open_identity.clone())) => {
                let Ok(connection) = connection else { return Ok(()); };
                connection?
            },
        };
        let server = AccountingDispatcher::new(connection, manager);
        serve_loop(transport, server, quiesce).await;
        Ok(())
    } else {
        warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
        Ok(())
    }
}

async fn quiescing(receiver: &mut watch::Receiver<bool>) {
    if receiver.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn serve_loop<T, S>(transport: Arc<T>, server: S, mut quiesce: watch::Receiver<bool>)
where
    T: StreamTransport + Send + Sync + 'static,
    S: Dispatcher<T> + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    let server = Arc::new(server);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(MAX_RPC_IN_FLIGHT_PER_CONNECTION);
    let accept_transport = transport.clone();
    // One task owns `accept`: dispatch completion can therefore never cancel
    // a partially read Open frame. The bounded channel is the only hand-off.
    let mut accepting = JoinSet::new();
    accepting.spawn(async move {
        loop {
            match accept_transport.accept().await {
                Ok(Some(inbound)) => {
                    if inbound_tx.send(Ok(inbound)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = inbound_tx.send(Err(error)).await;
                    break;
                }
            }
        }
    });

    let mut dispatches = JoinSet::new();
    let lifetime = tokio::time::sleep(MAX_LIFETIME);
    tokio::pin!(lifetime);
    let mut draining = false;
    loop {
        if dispatches.len() >= MAX_RPC_IN_FLIGHT_PER_CONNECTION {
            tokio::select! {
                _ = &mut lifetime => break,
                _ = quiescing(&mut quiesce) => { draining = true; break; }
                completed = dispatches.join_next() => log_dispatch_result(completed),
            }
            continue;
        }

        let idle = dispatches.is_empty();
        let next = tokio::select! {
            biased;
            _ = &mut lifetime => break,
            _ = quiescing(&mut quiesce) => { draining = true; break; }
            next = async {
                if idle {
                    tokio::time::timeout(RPC_CONNECTION_IDLE_TIMEOUT, inbound_rx.recv()).await.unwrap_or(None)
                } else {
                    inbound_rx.recv().await
                }
            } => next,
            completed = dispatches.join_next(), if !dispatches.is_empty() => {
                log_dispatch_result(completed);
                continue;
            }
        };

        match next {
            Some(Ok(inbound)) => {
                let server = server.clone();
                dispatches.spawn(async move { server.dispatch(inbound).await });
            }
            Some(Err(_)) => {
                debug!("provider transport ended");
                break;
            }
            None => break,
        }
    }

    accepting.shutdown().await;
    if draining {
        while let Some(result) = dispatches.join_next().await {
            log_dispatch_result(Some(result));
        }
    } else {
        dispatches.shutdown().await;
    }
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
pub(crate) mod tests;

/// The shared confidential-open proof handler. Software enrollment roots are
/// discarded: the enrolled producer alone signs each live transport binding.
pub struct ProviderOpen<R> {
    signer: Arc<hellas_auth::ProducerSigningKey>,
    root: Option<Arc<R>>,
    pub(crate) enrollment: ProviderEnrollmentBundle,
}

impl<R> ProviderOpen<R> {
    pub fn enrollment(&self) -> &ProviderEnrollmentBundle {
        &self.enrollment
    }

    pub fn new(
        signer: Arc<hellas_auth::ProducerSigningKey>,
        enrollment: ProviderEnrollmentBundle,
        root: Option<Arc<R>>,
    ) -> Result<Self, ProviderError> {
        if enrollment.genesis.statement.producer_public_key != signer.public_key() {
            return Err(ProviderError::Identity);
        }
        let root = match enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => None,
            hellas_rpc::RootKind::SecureEnclave => Some(root.ok_or(ProviderError::Identity)?),
        };
        Ok(Self {
            signer,
            root,
            enrollment,
        })
    }
}

impl<R> Clone for ProviderOpen<R> {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            root: self.root.clone(),
            enrollment: self.enrollment.clone(),
        }
    }
}

impl<R> hellas_rpc::open::OpenHandler for ProviderOpen<R>
where
    R: RootProver + Send + Sync + 'static,
{
    async fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> Result<OpenResponse, WireStatus> {
        let nonce: [u8; OPEN_NONCE_LEN] = request.nonce.try_into().map_err(|nonce: Vec<u8>| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!(
                    "confidential open nonce must be {OPEN_NONCE_LEN} bytes, got {}",
                    nonce.len()
                ),
            )
        })?;
        let exporter = context.open_exporter.ok_or_else(|| {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "transport does not expose a confidential-open exporter",
            )
        })?;
        let binding = open_proof_binding(
            &exporter,
            &nonce,
            &self.enrollment.genesis.statement.producer_public_key,
            self.enrollment.content_id(),
            alpn,
        );
        let proof = match self.enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => {
                open_response::Proof::ProducerSignature(signature_to_pb(
                    &self
                        .signer
                        .sign_digest(binding)
                        .map_err(|_| WireStatus::internal("provider signature failed"))?,
                ))
            }
            hellas_rpc::RootKind::SecureEnclave => match self
                .root
                .as_ref()
                .ok_or_else(|| WireStatus::internal("provider root is unavailable"))?
                .prove_open_binding(binding)
                .await
                .map_err(|_| WireStatus::internal("provider open assertion failed"))?
            {
                RootProof::AppleAppAttest(assertion) => {
                    open_response::Proof::AppleAppAttestAssertion(assertion)
                }
                _ => {
                    return Err(WireStatus::internal(
                        "provider root returned incompatible proof",
                    ));
                }
            },
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}
