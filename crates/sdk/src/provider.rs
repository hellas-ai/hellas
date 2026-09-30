use std::path::PathBuf;
use std::sync::Arc;

use hellas_attestation::RootProver;
use hellas_executor::{Executor, ExecutorSpawnConfig, FetchRoute, FetchRouteRegistry};
#[cfg(any(test, feature = "grant-provider"))]
use hellas_executor::{FetchRouteEntry, FetchRoutePolicy};
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

use crate::ClientIdentity;

const MAX_ACTIVE_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Startup errors, before a provider accepts requests.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider requires a Work funding configuration")]
    FundingRequired,
    #[error("paid channel names an unavailable Fetch route or manifest")]
    MissingPaidRoute,
    #[error("Fetch provider requires a paid Fetch policy")]
    WrongPaidPolicy,
    #[error("provider enrollment does not match this identity")]
    Identity,
    #[error("a revoked contact cannot be re-enabled; import a newly issued contact enrollment")]
    RevokedContact,
    #[error(transparent)]
    Grant(#[from] hellas_rpc::protocol::work_grant::records::GrantError),
    #[error(transparent)]
    GrantStore(#[from] hellas_work::work_store::grant::GrantStoreError),
    #[error("invalid provider settlement key")]
    SettlementKey,
    #[error(transparent)]
    OpenAiKey(#[from] hellas_providers::EmptyOpenAiKey),
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
    #[cfg(feature = "paid-provider")]
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[cfg(feature = "paid-provider")]
    #[error(transparent)]
    Paid(#[from] crate::paid_provider::PaidProviderError),
}

#[cfg(feature = "grant-provider")]
pub struct OpenAiProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: ClientIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub service: String,
    pub method: String,
    pub bearer_token: String,
    pub grantees: Vec<hellas_rpc::protocol::work_grant::records::Principal>,
    /// Per-contact counters. The machine shares the configured execution capacity.
    pub limits: Vec<hellas_rpc::protocol::work_grant::budget::Limit>,
    pub max_job_millis: std::num::NonZeroU64,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
}

/// An attested Fetch provider with an operator-supplied route registry.
pub struct FetchProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: ClientIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    #[cfg(feature = "grant-provider")]
    pub grants: Option<crate::GrantProviderOptions>,
    pub routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    #[cfg(feature = "paid-provider")]
    pub paid_work: Option<crate::work_config::WorkConfig>,
}

#[cfg(feature = "paid-provider")]
struct WorkWatcher {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "paid-provider")]
impl Drop for WorkWatcher {
    fn drop(&mut self) {
        self.stop.take();
    }
}

pub struct ProviderHandle {
    #[cfg(feature = "grant-provider")]
    grants: Option<hellas_work::grant_service::GrantService>,
    endpoint: Endpoint,
    accept_task: tokio::task::JoinHandle<()>,
    #[cfg(feature = "paid-provider")]
    work: Option<WorkWatcher>,
}

impl ProviderHandle {
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Export fresh private Offers to distribute to the configured contacts.
    #[cfg(feature = "grant-provider")]
    pub fn offers(
        &self,
    ) -> Result<Vec<hellas_rpc::protocol::work_grant::records::SignedOffer>, ProviderError> {
        use hellas_rpc::protocol::work_grant::{admin::*, records::*};
        let Some(service) = &self.grants else {
            return Ok(vec![]);
        };
        let ids = service.administer(|store, _| {
            Ok(store
                .state()
                .grants()
                .filter(|g| g.state == GrantState::Active)
                .map(|g| g.id)
                .collect::<Vec<_>>())
        })?;
        ids.into_iter()
            .map(|id| {
                match service.control(
                    GrantCommand::Inspect { id },
                    &[],
                    std::num::NonZeroU64::new(1).unwrap(),
                )? {
                    GrantReply::Status { offer, .. } => Ok(*offer),
                    _ => Err(ProviderError::FundingRequired),
                }
            })
            .collect()
    }

    pub async fn shutdown(mut self) {
        self.accept_task.abort();
        let _ = (&mut self.accept_task).await;
        #[cfg(feature = "grant-provider")]
        if let Some(grants) = &self.grants
            && let Err(error) = grants.drain().await
        {
            tracing::error!(%error, "grant provider drain failed");
        }
        #[cfg(feature = "paid-provider")]
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
        #[cfg(feature = "paid-provider")]
        if let Some(work) = &mut self.work {
            work.stop.take();
        }
    }
}

#[cfg(feature = "grant-provider")]
pub async fn start_openai_provider<R>(
    options: OpenAiProviderOptions<R>,
) -> Result<ProviderHandle, ProviderError>
where
    R: RootProver + Send + Sync + 'static,
{
    let policy = crate::grant_provider::responses_policy(&options.service, &options.method)?;
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
        grants: Some(crate::GrantProviderOptions {
            grantees: options.grantees,
            policies: vec![policy],
            limits: options.limits,
            max_job_millis: options.max_job_millis,
        }),
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_capacity: options.fetch_queue_capacity,
        #[cfg(feature = "paid-provider")]
        paid_work: None,
    })
    .await
}

pub async fn start_fetch_provider<R>(
    options: FetchProviderOptions<R>,
) -> Result<ProviderHandle, ProviderError>
where
    R: RootProver + Send + Sync + 'static,
{
    #[cfg(feature = "paid-provider")]
    let has_paid_work = options.paid_work.is_some();
    #[cfg(not(feature = "paid-provider"))]
    let has_paid_work = false;
    #[cfg(feature = "grant-provider")]
    let has_grants = options.grants.is_some();
    #[cfg(not(feature = "grant-provider"))]
    let has_grants = false;
    if !has_paid_work && !has_grants {
        return Err(ProviderError::FundingRequired);
    }
    #[cfg(feature = "paid-provider")]
    if let Some(config) = &options.paid_work {
        use hellas_rpc::protocol::{
            work_fetch::FetchRoutePolicy as PaidRoute, work_profile::WorkPolicy,
        };
        match &config.work_policy {
            WorkPolicy::Fetch {
                policy,
                route: PaidRoute::SealedRoute { service, method },
            } => {
                if !options
                    .routes
                    .entry(&FetchRoute::new(service, method))
                    .is_some_and(|entry| {
                        entry.execution_environment() == policy.allowed_environment
                    })
                {
                    return Err(ProviderError::MissingPaidRoute);
                }
            }
            WorkPolicy::Fetch {
                policy,
                route: PaidRoute::OpenFetch { .. },
            } => {
                if !options.routes.has_environment(policy.allowed_environment) {
                    return Err(ProviderError::MissingPaidRoute);
                }
            }
            _ => return Err(ProviderError::WrongPaidPolicy),
        }
        crate::work_config::validate_work_routes(config)?;
    }
    options.enrollment.check_grant_provider()?;
    if options.enrollment.genesis.statement.producer_public_key
        != options.identity.caller_key().public_key()
        || options.enrollment.grant_transport()? != *options.identity.node_id().as_bytes()
    {
        return Err(ProviderError::Identity);
    }
    let assurance = match options.enrollment.genesis.statement.root_kind {
        hellas_rpc::RootKind::Software => Assurance::ProducerSigned,
        hellas_rpc::RootKind::SecureEnclave => Assurance::AppleAppAttest,
    };
    #[cfg(feature = "grant-provider")]
    let grant_store = options
        .grants
        .as_ref()
        .map(|grants| {
            crate::grant_provider::prepare(
                grants,
                &options.state_directory,
                options.enrollment.clone(),
                &options.routes,
                options.fetch_max_in_flight,
            )
        })
        .transpose()?;
    let producer_key = Arc::new(options.identity.caller_key().clone());
    let mut executor_config =
        ExecutorSpawnConfig::fetch_only(producer_key.clone(), assurance, options.routes);
    executor_config.fetch_max_in_flight = options.fetch_max_in_flight;
    executor_config.fetch_queue_capacity = options.fetch_queue_capacity;
    let executor = Executor::spawn_configured(executor_config).await?;

    #[cfg(feature = "paid-provider")]
    let work_mount = crate::paid_provider::MountedWork::with_backend(executor.clone());
    #[cfg(feature = "paid-provider")]
    let setup_mount = crate::paid_provider::MountedSetup::default();
    #[cfg(feature = "paid-provider")]
    let work = if let Some(config) = options.paid_work {
        let policy = config.provider_policy();
        let settlement_key = hellas_kernel::Secp256k1Signer::from_secret_scalar(
            options.identity.caller_secret_bytes(),
        )
        .map_err(|_| ProviderError::SettlementKey)?;
        let runner = crate::paid_provider::WorkRunner::discover(
            crate::paid_provider::WorkRunnerConfig {
                network: config.chain.network,
                genesis_payload_digest: config.chain.genesis_payload_digest,
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
        signer: producer_key.clone(),
        root: options.root,
        enrollment: options.enrollment,
    };
    let mut alpns = vec![hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec()];
    if has_paid_work {
        alpns.push(
            hellas_rpc::services::work_setup::WorkSetup::ALPN
                .as_bytes()
                .to_vec(),
        );
    }
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(options.identity.transport_key())
        .alpns(alpns);
    if let Some(port) = options.port {
        builder = builder.bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))?;
    }
    let endpoint = builder.bind().await?;
    #[cfg(feature = "grant-provider")]
    let grants = grant_store
        .map(|store| {
            hellas_work::grant_service::GrantService::new(
                store,
                producer_key,
                executor,
                endpoint
                    .addr()
                    .ip_addrs()
                    .map(ToString::to_string)
                    .collect(),
                Arc::new(hellas_work::grant_service::wall_clock),
            )
        })
        .transpose()?;
    #[cfg(all(feature = "paid-provider", feature = "grant-provider"))]
    if let Some(grants) = &grants {
        assert!(work_mount.mount_grants(grants.clone()));
    }
    #[cfg(all(feature = "grant-provider", not(feature = "paid-provider")))]
    let grant_mount = grants.clone();
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
            #[cfg(feature = "paid-provider")]
            let (work_mount, setup_mount) = (work_mount.clone(), setup_mount.clone());
            #[cfg(all(feature = "grant-provider", not(feature = "paid-provider")))]
            let grant_mount = grant_mount.clone();
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
                #[cfg(feature = "paid-provider")]
                if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
                    let server = OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                        hellas_rpc::services::work::WorkServer(work_mount),
                        open,
                    );
                    serve(transport, server).await;
                    return;
                }
                #[cfg(all(feature = "grant-provider", not(feature = "paid-provider")))]
                if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes()
                    && let Some(service) = grant_mount
                {
                    let server = OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                        hellas_rpc::services::work::WorkServer(service),
                        open,
                    );
                    serve(transport, server).await;
                }
                #[cfg(feature = "paid-provider")]
                if has_paid_work
                    && alpn == hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes()
                {
                    let server =
                        OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                            hellas_rpc::services::work_setup::WorkSetupServer(setup_mount),
                            open,
                        );
                    serve(transport, server).await;
                }
            });
        }
    });
    Ok(ProviderHandle {
        #[cfg(feature = "grant-provider")]
        grants,
        endpoint,
        accept_task,
        #[cfg(feature = "paid-provider")]
        work,
    })
}

/// Serves one connection until the peer leaves or a dispatch fails. Dispatch
/// is deliberately unbounded here: streaming methods such as `StreamResult`
/// stay open for the lifetime of a job and enforce their own application-level
/// deadlines, so a wall-clock timeout at this layer would cancel paid work
/// mid-delivery.
async fn serve<T, S>(transport: Arc<T>, server: S)
where
    T: StreamTransport + Send + Sync + 'static,
    T::Error: std::fmt::Display,
    S: Dispatcher<T> + Send + Sync + 'static,
    S::Error: std::fmt::Display + Send + Sync + 'static,
{
    loop {
        match transport.accept().await {
            Ok(Some(inbound)) => {
                if let Err(error) = Dispatcher::<T>::dispatch(&server, inbound).await {
                    tracing::warn!(%error, "provider RPC failed");
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                tracing::debug!(%error, "provider transport ended");
                break;
            }
        }
    }
}

#[cfg(all(test, feature = "paid-provider", feature = "paid-client"))]
mod tests;

#[cfg(all(test, feature = "grant-provider", feature = "grant-gateway"))]
mod grant_tests;

struct ProviderOpen<R> {
    signer: Arc<hellas_rpc::ProducerSigningKey>,
    root: Arc<R>,
    enrollment: ProviderEnrollmentBundle,
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
