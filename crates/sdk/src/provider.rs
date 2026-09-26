use std::path::PathBuf;
use std::sync::Arc;

use hellas_attestation::RootProver;
use hellas_executor::{
    ExecuteServer, Executor, ExecutorSpawnConfig, FetchAccessPolicy, FetchQuotaStoreBackend,
    FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry, FetchServer,
    FetchTranscriptStoreBackend,
};
use hellas_rpc::open::OpenDispatcher;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::run_ticket::signature_to_pb;
use hellas_rpc::serve::MethodDispatcher;
use hellas_rpc::services::execute::RunTicket;
use hellas_rpc::services::fetch::{Fetch, Open as FetchOpen};
use hellas_rpc::{
    Assurance, OPEN_NONCE_LEN, ProviderEnrollmentBundle, PublicKey, RootProof, open_proof_binding,
};
use hellas_wire::iroh::{IrohTransport, IrohTransportError};
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireCode, WireStatus,
};
use iroh::{Endpoint, EndpointId, endpoint::presets};

use crate::ClientIdentity;

const MAX_ACTIVE_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct OpenAiProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: ClientIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub service: String,
    pub method: String,
    pub bearer_token: String,
    pub allowed_callers: Vec<PublicKey>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub retained_transcript_capacity: usize,
    pub fetch_replay_max_in_flight: usize,
}

/// An attested Fetch provider with an operator-supplied route registry.
pub struct FetchProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: ClientIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub routes: FetchRouteRegistry,
    pub allowed_callers: Vec<PublicKey>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub retained_transcript_capacity: usize,
    pub fetch_replay_max_in_flight: usize,
    #[cfg(feature = "paid-work")]
    pub paid_work: Option<crate::work_config::WorkConfig>,
}

#[cfg(feature = "paid-work")]
struct WorkWatcher {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "paid-work")]
impl Drop for WorkWatcher {
    fn drop(&mut self) {
        self.stop.take();
    }
}

pub struct ProviderHandle {
    endpoint: Endpoint,
    accept_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "paid-work")]
    work: Option<WorkWatcher>,
}

impl ProviderHandle {
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    pub async fn shutdown(mut self) {
        self.accept_task.abort();
        let _ = (&mut self.accept_task).await;
        #[cfg(feature = "paid-work")]
        if let Some(mut work) = self.work.take() {
            if let Some(stop) = work.stop.take() {
                let _ = stop.send(());
            }
            let _ = (&mut work.task).await;
        }
        self.endpoint.close().await;
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
        #[cfg(feature = "paid-work")]
        if let Some(work) = &mut self.work {
            work.stop.take();
        }
    }
}

pub async fn start_openai_provider<R>(
    options: OpenAiProviderOptions<R>,
) -> anyhow::Result<ProviderHandle>
where
    R: RootProver + Send + Sync + 'static,
{
    let upstream = Arc::new(hellas_providers::OpenAiResponsesFetchProvider::with_bearer(
        options.bearer_token,
    )?);
    let adaptor = Arc::new(hellas_providers::ResponsesFetchAdaptorFactory::new(
        hellas_rpc::FetchEnvironment::OpenAiResponses,
    ));
    let mut routes = FetchRouteRegistry::new();
    routes.register(
        FetchRoute::new(options.service, options.method),
        FetchRouteEntry::new(upstream, adaptor, FetchRoutePolicy::default())?,
    )?;
    start_fetch_provider(FetchProviderOptions {
        port: options.port,
        identity: options.identity,
        enrollment: options.enrollment,
        root: options.root,
        state_directory: options.state_directory,
        routes,
        allowed_callers: options.allowed_callers,
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_capacity: options.fetch_queue_capacity,
        retained_transcript_capacity: options.retained_transcript_capacity,
        fetch_replay_max_in_flight: options.fetch_replay_max_in_flight,
        #[cfg(feature = "paid-work")]
        paid_work: None,
    })
    .await
}

pub async fn start_fetch_provider<R>(
    options: FetchProviderOptions<R>,
) -> anyhow::Result<ProviderHandle>
where
    R: RootProver + Send + Sync + 'static,
{
    #[cfg(feature = "paid-work")]
    let has_paid_work = options.paid_work.is_some();
    #[cfg(not(feature = "paid-work"))]
    let has_paid_work = false;
    anyhow::ensure!(
        !options.allowed_callers.is_empty() || has_paid_work,
        "provider requires allowed callers or paid-work configuration"
    );
    #[cfg(feature = "paid-work")]
    if let Some(config) = &options.paid_work {
        use hellas_rpc::protocol::{
            work_fetch::FetchRoutePolicy as PaidRoute, work_profile::PaidWorkPolicy,
        };
        match &config.execution_policy {
            PaidWorkPolicy::Fetch {
                policy,
                route: PaidRoute::SealedRoute { service, method },
            } => {
                anyhow::ensure!(
                    options
                        .routes
                        .entry(&FetchRoute::new(service, method))
                        .is_some_and(
                            |entry| entry.execution_environment() == policy.allowed_environment
                        ),
                    "paid channel names an unavailable Fetch route or manifest"
                );
            }
            PaidWorkPolicy::Fetch {
                policy,
                route: PaidRoute::OpenFetch { .. },
            } => {
                anyhow::ensure!(
                    options.routes.has_environment(policy.allowed_environment),
                    "paid channel names an unavailable HTTPS manifest"
                );
            }
            _ => anyhow::bail!("Fetch provider requires a paid Fetch policy"),
        }
    }
    let producer_key = Arc::new(options.identity.caller_key().clone());
    let access = FetchAccessPolicy::trusted_callers(options.allowed_callers).with_store(
        FetchQuotaStoreBackend::fs(options.state_directory.join("quota")),
    );
    let mut executor_config = ExecutorSpawnConfig::fetch_only(
        producer_key.clone(),
        Arc::new(options.enrollment.canonical_bytes()),
        Assurance::AppleAppAttest,
        options.routes,
    );
    executor_config.fetch_access_policy = access;
    executor_config.fetch_max_in_flight = options.fetch_max_in_flight;
    executor_config.fetch_queue_capacity = options.fetch_queue_capacity;
    executor_config.fetch_replay_max_in_flight = options.fetch_replay_max_in_flight;
    executor_config.fetch_store = FetchTranscriptStoreBackend::fs_with_capacity(
        options.state_directory.join("transcripts"),
        options.retained_transcript_capacity,
    );
    let executor = Executor::spawn_configured(executor_config).await?;

    #[cfg(feature = "paid-work")]
    let work_mount = crate::paid_provider::MountedWork::with_backend(executor.clone());
    #[cfg(feature = "paid-work")]
    let setup_mount = crate::paid_provider::MountedSetup::default();
    #[cfg(feature = "paid-work")]
    let work = if let Some(config) = options.paid_work {
        anyhow::ensure!(
            matches!(
                config.execution_policy,
                hellas_rpc::protocol::work_profile::PaidWorkPolicy::Fetch { .. }
            ),
            "Fetch provider requires a paid Fetch policy"
        );
        anyhow::ensure!(
            options.retained_transcript_capacity == 0,
            "paid Fetch provider requires zero retained transcript capacity"
        );
        crate::work_config::validate_work_routes(&config)?;
        let policy = config.provider_policy();
        let settlement_key = hellas_kernel::Secp256k1Signer::from_secret_scalar(
            options.identity.caller_secret_bytes(),
        )
        .map_err(|_| anyhow::anyhow!("invalid provider settlement key"))?;
        let runner = crate::paid_provider::WorkRunner::discover(
            crate::paid_provider::WorkRunnerConfig {
                network: config.chain.network,
                threshold_identity: config.chain.threshold_identity,
                journal_root: config.journal_root,
                routes: config.routes,
                validators: config.validators,
                poll: config.poll,
                max_observation_age: config.max_observation_age,
                settlement_key,
                policy,
            },
            work_mount.clone(),
            setup_mount.clone(),
        )?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        Some(WorkWatcher {
            stop: Some(stop),
            task: tokio::spawn(runner.run(stopped)),
        })
    } else {
        None
    };
    let open = ProviderOpen {
        root: options.root,
        enrollment: options.enrollment,
    };
    let alpns = vec![<Fetch as ServiceMarker>::ALPN.as_bytes().to_vec()];
    #[cfg(feature = "paid-work")]
    let alpns = if has_paid_work {
        let mut alpns = alpns;
        alpns.extend([
            hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
            hellas_rpc::services::work_setup::WorkSetup::ALPN
                .as_bytes()
                .to_vec(),
        ]);
        alpns
    } else {
        alpns
    };
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(options.identity.transport_key())
        .alpns(alpns);
    if let Some(port) = options.port {
        builder = builder.bind_addr(format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?)?;
    }
    let endpoint = builder.bind().await?;
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_CONNECTIONS));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let incoming = tokio::select! {
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "provider connection task failed");
                    }
                    continue;
                }
                incoming = accept_endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                break;
            };
            let slot = match slots.clone().acquire_owned().await {
                Ok(slot) => slot,
                Err(_) => break,
            };
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(error) => {
                    tracing::warn!(%error, "provider connection accept failed");
                    continue;
                }
            };
            let executor = executor.clone();
            #[cfg(feature = "paid-work")]
            let (work_mount, setup_mount) = (work_mount.clone(), setup_mount.clone());
            let open = open.clone();
            connections.spawn(async move {
                let _slot = slot;
                let connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "provider connection handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("provider connection handshake timed out");
                        return;
                    }
                };
                let alpn = connection.alpn().to_vec();
                let transport = Arc::new(IrohTransport::new(connection));
                #[cfg(feature = "paid-work")]
                if has_paid_work && alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
                    let context = transport.context();
                    if let Some(handler) = work_mount.handler(&context) {
                        let server = OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                            hellas_rpc::services::work::WorkServer(handler),
                            open,
                        );
                        serve(transport, server).await;
                    } else {
                        let server = OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                            hellas_rpc::services::work::WorkServer(
                                crate::paid_provider::UnmountedWork,
                            ),
                            open,
                        );
                        serve(transport, server).await;
                    }
                    return;
                }
                #[cfg(feature = "paid-work")]
                if has_paid_work
                    && alpn == hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes()
                {
                    let context = transport.context();
                    if let Some(handler) = setup_mount.service(&context) {
                        let server =
                            OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                                hellas_rpc::services::work_setup::WorkSetupServer(handler),
                                open,
                            );
                        serve(transport, server).await;
                    } else {
                        let server =
                            OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                                hellas_rpc::services::work_setup::WorkSetupServer(
                                    crate::paid_provider::UnmountedWork,
                                ),
                                open,
                            );
                        serve(transport, server).await;
                    }
                    return;
                }
                if alpn != Fetch::ALPN.as_bytes() {
                    return;
                }
                let server = OpenDispatcher::<_, _, FetchOpen>::new(
                    MethodDispatcher::<_, _, RunTicket>::new(
                        ExecuteServer(executor.clone()),
                        FetchServer(executor),
                    ),
                    open,
                );
                serve(transport, server).await;
            });
        }
    });
    Ok(ProviderHandle {
        endpoint,
        accept_task,
        #[cfg(feature = "paid-work")]
        work,
    })
}

/// Serves one connection until the peer leaves or a dispatch fails. Dispatch
/// is deliberately unbounded here: streaming methods such as `StreamResult`
/// stay open for the lifetime of a job and enforce their own application-level
/// deadlines, so a wall-clock timeout at this layer would cancel paid work
/// mid-delivery.
async fn serve<S>(transport: Arc<IrohTransport>, server: S)
where
    S: Dispatcher<IrohTransport> + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    loop {
        match transport.accept().await {
            Ok(Some(inbound)) => {
                if let Err(error) = Dispatcher::<IrohTransport>::dispatch(&server, inbound).await {
                    tracing::warn!(%error, "provider RPC failed");
                    break;
                }
            }
            Ok(None) | Err(IrohTransportError::Connection(_)) => break,
            Err(error) => {
                tracing::warn!(%error, "provider transport failed");
                break;
            }
        }
    }
}

struct ProviderOpen<R> {
    root: Arc<R>,
    enrollment: ProviderEnrollmentBundle,
}

impl<R> Clone for ProviderOpen<R> {
    fn clone(&self) -> Self {
        Self {
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
        let proof = match self
            .root
            .prove_open_binding(binding)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "provider open proof generation failed");
                WireStatus::internal("provider open proof generation failed")
            })? {
            RootProof::Software(signature) => {
                open_response::Proof::ProducerSignature(signature_to_pb(&signature))
            }
            RootProof::AppleAppAttest(assertion) => {
                open_response::Proof::AppleAppAttestAssertion(assertion)
            }
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}
