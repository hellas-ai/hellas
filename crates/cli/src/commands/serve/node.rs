//! Node server bootstrap.
//!
//! Binds an iroh `Endpoint` with all service ALPNs, runs the executor,
//! and spawns a per-connection accept loop that routes each inbound
//! stream to the right service's dispatcher (selected by ALPN).
//!
//! Peers can reach this node by direct address. Registry publishing is
//! owned by the service-discovery path and is not started from this
//! bootstrap.

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context;
#[cfg(test)]
use hellas_chain::FinalizedWorkView;
#[cfg(feature = "evaluate")]
use hellas_executor::GpuConfig;
use hellas_executor::{Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchRouteRegistry};
#[cfg(test)]
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
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
use hellas_rpc::serve::AccountingDispatcher;
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
use hellas_work::work::WorkBackend;
#[cfg(test)]
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
#[cfg(test)]
use tokio::sync::oneshot;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, warn};

use super::node_handler::NodeHandlerImpl;
use crate::commands::discovery::{DiscoveryAdvertiser, served_alpns, start_server_advertising};
use crate::identity::OpenIdentity;
use hellas_sdk::work_router::WorkRouter;

pub(super) use hellas_sdk::paid_provider::{
    MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig, WorkWatcher,
};

/// Keep peer-controlled transport state finite. A connection can multiplex
/// several RPCs, so these are deliberately transport limits rather than job
/// scheduler limits.
const MAX_ACTIVE_RPC_CONNECTIONS: usize = 128;
const MAX_RPC_IN_FLIGHT_PER_CONNECTION: usize = 16;
const RPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) struct NodeHandle {
    router: Option<WorkRouter>,
    _control: Option<hellas_sdk::local::LocalControlServer>,
    node_id: EndpointId,
    accept_task: JoinHandle<()>,
    endpoint: Endpoint,
    discovery: Option<DiscoveryAdvertiser>,
    work: Option<WorkWatcher>,
    chain: Option<hellas_sdk::FullNode>,
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
        self.accept_task.abort();
        let mut result = match (&mut self.accept_task).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(anyhow::Error::from(error)),
        };
        if let Some(grants) = self.router.as_ref().and_then(WorkRouter::grant_service) {
            result = result.and(grants.drain().await.map_err(anyhow::Error::from));
        }

        // The clock first, and joined rather than aborted: its journals
        // are released when its task returns, and a node that closed its
        // endpoint while a step was still writing would be a node whose
        // files outlive it.
        if let Some(watcher) = &mut self.work {
            result = result.and(watcher.shutdown().await.map_err(anyhow::Error::from));
        }
        if let Some(discovery) = self.discovery.take() {
            discovery.shutdown().await;
        }
        self.endpoint.close().await;
        if let Some(chain) = self.chain.take() {
            result = result.and(chain.shutdown().await.map_err(anyhow::Error::from));
        }
        result
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

pub(super) struct NodeConfig {
    pub(super) grants: Option<super::GrantNodeConfig>,
    pub(super) port: Option<u16>,
    pub(super) discovery: bool,
    pub(super) queue_size: usize,
    #[cfg(feature = "evaluate")]
    pub(super) content_store: hellas_store::ContentStore,
    pub(super) build: String,
    pub(super) graffiti: Vec<u8>,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_size: usize,
    /// What the clock over this node's paid-work journals is built
    /// from, or `None` when no work configuration was loaded. Its
    /// presence is still what advertises the two work ALPNs.
    pub(super) work: Option<(WorkRunnerConfig, hellas_sdk::FullNode)>,
    pub(super) secret_key: SecretKey,
    pub(super) producer_key: ProducerSigningKey,
    pub(super) open_identity: Arc<OpenIdentity>,
    pub(super) assurance: Assurance,
    pub(super) metrics: Arc<ExecutorMetrics>,
    #[cfg(feature = "evaluate")]
    pub(super) gpu_config: GpuConfig,
}

#[derive(Clone)]
struct RemoteExecutionServices {
    open_identity: Arc<OpenIdentity>,
}

pub(super) async fn spawn_node(config: NodeConfig) -> anyhow::Result<NodeHandle> {
    if let Some((work, _)) = &config.work {
        work.validate()?;
    }
    if let Some(grants) = &config.grants {
        anyhow::ensure!(
            grants.provider.transport() == *config.secret_key.public().as_bytes(),
            "grant provider transport differs from node identity"
        );
        anyhow::ensure!(
            grants
                .provider
                .bundle()
                .genesis
                .statement
                .producer_public_key
                == config.producer_key.public_key(),
            "grant provider signer differs from node identity"
        );
    }
    let grant_plans = config
        .grants
        .map(|grants| {
            let plan = hellas_sdk::grant_provider::GrantProviderPlan::managed(
                &grants,
                super::provider_resources(&config.fetch_routes),
            )?;
            Ok::<_, hellas_sdk::grant_provider::GrantProviderError>((grants.config, plan))
        })
        .transpose()?;

    let signer = Arc::new(config.producer_key);
    let mut executor =
        ExecutorSpawnConfig::fetch_only(signer.clone(), config.assurance, config.fetch_routes);
    executor.queue_capacity = config.queue_size;
    executor.metrics = config.metrics.clone();
    executor.fetch_max_in_flight = config.fetch_max_in_flight;
    executor.fetch_queue_capacity = config.fetch_queue_size;
    #[cfg(feature = "evaluate")]
    {
        executor.content_store = config.content_store;
        executor.gpu_config = config.gpu_config;
    }
    let handle = Executor::spawn_configured(executor)
        .await
        .context("failed to spawn executor")?;
    let prepared_grants = grant_plans
        .map(|(config, plan)| {
            Ok::<_, hellas_sdk::grant_provider::GrantProviderError>((config, plan.open()?))
        })
        .transpose()?;
    let advertised_alpns = served_alpns(config.work.is_some(), prepared_grants.is_some());
    let work_mount = MountedWork::with_backend(handle.clone());
    let setup_mount = MountedSetup::default();
    let chain = config.work.as_ref().map(|(_, chain)| chain.clone());
    let runner = config
        .work
        .map(|(work, chain)| {
            WorkRunner::discover(work, work_mount.clone(), setup_mount.clone())
                .map(|runner| runner.on_node(chain))
        })
        .transpose()?;
    let alpns = advertised_alpns.clone();
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
    let mut node_handler =
        NodeHandlerImpl::new(node_id, config.build, config.graffiti, directory.clone());
    node_handler.service_alpns = advertised_alpns
        .iter()
        .map(|alpn| String::from_utf8(alpn.clone()).expect("service ALPN is ASCII"))
        .collect();
    node_handler.chain = chain.clone();

    // -- The clock. Spawned only when a work configuration was loaded,
    //    and given the same mount slot the accept loop reads: the runner
    //    publishes the channel it is handed, and `Work` is answered from
    //    it from that moment on.
    // Local content indexing is complete before bind. Clones of the executor
    // handle live in every remote-execution handler and, when paid work is
    // configured, in its mount as well.
    let remote_execution = RemoteExecutionServices {
        open_identity: config.open_identity,
    };
    let (grants, control, admin) = if let Some((grant_config, store)) = prepared_grants {
        let service = hellas_work::grant_service::GrantService::new(
            store,
            signer,
            handle,
            endpoint
                .addr()
                .ip_addrs()
                .map(ToString::to_string)
                .collect(),
            Arc::new(hellas_work::grant_service::wall_clock),
        )?;
        let parent = grant_config
            .control_socket
            .parent()
            .context("grant control socket needs a parent")?;
        hellas_private::create_dir_all_durable(parent)?;
        let admin = hellas_sdk::grant_admin::GrantAdmin::new(
            service.clone(),
            grant_config.resources,
            grant_config.max_job_millis,
        );
        let control = hellas_sdk::local::LocalControlServer::bind(
            &grant_config.control_socket,
            admin.clone().dispatcher(),
        )?;
        (Some(service), Some(control), Some(admin))
    } else {
        (None, None, None)
    };
    let discovery = config
        .discovery
        .then(|| start_server_advertising(&endpoint, &advertised_alpns))
        .transpose()
        .context("failed to start service discovery advertising")?;
    let work = runner.map(WorkWatcher::spawn);
    let serves_work = match (work.is_some(), grants.as_ref()) {
        (true, Some(grants)) => Some(WorkRouter::Both {
            payment: work_mount,
            grants: grants.clone(),
        }),
        (true, None) => Some(WorkRouter::Payment(work_mount)),
        (false, Some(grants)) => Some(WorkRouter::Grants(grants.clone())),
        (false, None) => None,
    };
    let serves_setup = work.is_some().then(|| setup_mount.clone());

    // -- Accept loop: one task per inbound Connection; per-Connection
    //    dispatch routed by ALPN to the matching service handler.
    let router = serves_work.clone();
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        let connection_slots = Arc::new(Semaphore::new(MAX_ACTIVE_RPC_CONNECTIONS));
        let mut connections = JoinSet::new();
        loop {
            let incoming = tokio::select! {
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        warn!(%error, "node connection task failed");
                    }
                    continue;
                }
                incoming = accept_endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                break;
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
            let admin_for_conn = admin.clone();
            connections.spawn(async move {
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
                    admin_for_conn,
                )
                .await
                {
                    warn!("serve_connection error: {e}");
                }
            });
        }
    });

    Ok(NodeHandle {
        chain,
        router,
        _control: control,
        node_id,
        accept_task,
        endpoint,
        discovery,
        work,
    })
}

/// Per-connection serve: each inbound substream is dispatched to the
/// service selected by the connection's negotiated ALPN.
#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    alpn: Vec<u8>,
    conn: Connection,
    remote_execution: RemoteExecutionServices,
    node_handler: NodeHandlerImpl,
    manager: PeerManager,
    setup: Option<MountedSetup>,
    work: Option<WorkRouter>,
    admin: Option<hellas_sdk::grant_admin::GrantAdmin>,
) -> anyhow::Result<()> {
    let transport = Arc::new(IrohTransport::new(conn));

    // Account for inbound requests and refresh last_seen_ms in the shared registry.
    if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
        let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
        serve_loop(transport, server).await
    } else if alpn == hellas_rpc::services::chain_sync::ChainSync::ALPN.as_bytes()
        && let Some(chain) = node_handler.chain
    {
        let server = AccountingDispatcher::new(
            hellas_rpc::services::chain_sync::ChainSyncServer(chain),
            manager,
        );
        serve_loop(transport, server).await
    } else if let Some(setup) =
        setup.filter(|_| alpn == <WorkSetup as ServiceMarker>::ALPN.as_bytes())
    {
        let server = AccountingDispatcher::new(
            OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                WorkSetupServer(setup),
                remote_execution.open_identity.clone(),
            ),
            manager,
        );
        serve_loop(transport, server).await
    } else if let Some(work) = work.filter(|_| alpn == <Work as ServiceMarker>::ALPN.as_bytes()) {
        let server = AccountingDispatcher::new(
            OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                WorkServer(work),
                remote_execution.open_identity.clone(),
            ),
            manager,
        );
        serve_loop(transport, server).await
    } else if let Some(admin) =
        admin.filter(|_| alpn == hellas_rpc::services::host_control::HostControl::ALPN.as_bytes())
    {
        serve_loop(transport, admin.dispatcher()).await
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
