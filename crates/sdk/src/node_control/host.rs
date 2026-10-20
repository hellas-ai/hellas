//! Host-owned lifecycle. Authority checks enqueue commands; this supervisor owns
//! completion and drain even after the requesting control connection disappears.
use super::*;
use crate::{ProviderControl, ProviderError, ProviderHandle};
use futures::future::BoxFuture;
use hellas_work::model::grant::records::grant_transport;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot, watch};

const PROVIDER_NOT_BOUND: &str = "provider is not bound";

pub type ProviderFactory = Arc<
    dyn Fn(
            Option<NodeControl>,
            Option<super::configuration::ProviderUpdate>,
        )
            -> BoxFuture<'static, Result<ProviderHandle, Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + Sync,
>;

/// Starts the gateway with the access the host validated at startup.
pub type GatewayFactory = Arc<
    dyn Fn(
            hellas_gateway::GatewayAccess,
        ) -> BoxFuture<
            'static,
            Result<hellas_gateway::GatewayHandle, Box<dyn std::error::Error + Send + Sync>>,
        > + Send
        + Sync,
>;

/// The provider identity is the authority's binding, read from the store.
pub struct HostOptions {
    /// The normal node transport belongs to the host, across provider restarts.
    pub transport: Option<iroh::Endpoint>,
    pub start_provider: bool,
    pub control: Option<(NodeCoordinator, ProviderControl)>,
    pub provider: Option<ProviderFactory>,
    pub gateway: Option<(hellas_gateway::GatewayAccess, GatewayFactory)>,
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Authority(#[from] NodeStoreError),
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Gateway(#[from] hellas_gateway::GatewayError),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("host services must share the configured identity and authority writer")]
    Composition,
}

pub struct HostHandle {
    pub(super) runtime: Runtime,
    listener: Option<hellas_wire::local::LocalControlServer>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), HostError>>,
    transport: Option<(iroh::Endpoint, tokio::task::JoinHandle<()>)>,
}
impl HostHandle {
    pub fn endpoint(&self) -> Option<&iroh::Endpoint> { self.runtime.transport.as_ref() }

    /// Both services begin stopped. Startup neither creates authority nor grants.
    /// An authority without a provider binding still serves control; provider
    /// start is refused until the binding exists.
    pub async fn start(options: HostOptions) -> Result<Self, HostError> {
        if let Some((access, _)) = &options.gateway {
            if !options
                .control
                .as_ref()
                .is_some_and(|(node, _)| access.shares_writer(node))
            {
                return Err(HostError::Composition);
            }
            access.validate().await?;
        }
        let transport = options.transport;
        let state = Arc::new(Mutex::new(State {
            configuration: None,
            ingress: None,
            provider: None,
            gateway: None,
            work: None,
            provider_state: RuntimeState::Stopped,
            gateway_state: RuntimeState::Stopped,
            provider_failure: None,
            gateway_failure: None,
            access: options.gateway.as_ref().map(|(access, _)| access.clone()),
        }));
        let (commands, receiver) = mpsc::channel(8);
        let runtime = Runtime {
            commands,
            transport: transport.clone(),
            state,
            has_provider: options.provider.is_some(),
            has_gateway: options.gateway.is_some(),
            endpoint: watch::channel(None).0,
        };
        let (control, listener) = if let Some((node, config)) = options.control {
            let mut control = NodeControl::new(node).with_remote_admission(config.remote);
            control.host = Some(runtime.clone());
            let parent = config.socket.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "control socket needs a parent",
                )
            })?;
            hellas_private::create_dir_all_durable(parent)?;
            let listener = control.bind_local(config.socket, config.tls)?;
            (Some(control), Some(listener))
        } else {
            (None, None)
        };
        let (stop, stopped) = watch::channel(false);
        let remote = transport.map(|endpoint| {
            let task = tokio::spawn(accept(endpoint.clone(), control.clone(), runtime.clone(), stopped.clone()));
            (endpoint, task)
        });
        let task = tokio::spawn(run(
            runtime.clone(),
            receiver,
            stopped,
            control,
            options.provider,
            options.gateway.map(|(_, factory)| factory),
        ));
        let host = Self {
            runtime,
            transport: remote,
            listener,
            stop,
            task,
        };
        if options.start_provider {
            let result = host.runtime.enqueue(Service::Provider, true).map_err(ProviderError::from)?
                .await.map_err(|_| ProviderError::from(unavailable()))?;
            if let Err(error) = result { host.shutdown().await?; return Err(ProviderError::from(error).into()); }
        }
        Ok(host)
    }

    /// Current provider endpoint for host metrics; stopping publishes None.
    pub fn provider_endpoint(&self) -> watch::Receiver<Option<iroh::Endpoint>> {
        self.runtime.endpoint.subscribe()
    }

    pub async fn shutdown(mut self) -> Result<(), HostError> {
        self.stop.send_replace(true);
        let listener = match self.listener.take() {
            Some(listener) => listener.shutdown().await.map_err(HostError::from),
            None => Ok(()),
        };
        if let Some((endpoint, task)) = self.transport.take() {
            endpoint.close().await;
            task.await?;
        }
        let stopped = (&mut self.task)
            .await
            .map_err(HostError::from)
            .and_then(|result| result);
        listener.and(stopped)
    }
}
impl Drop for HostHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(Clone)]
pub(super) struct Runtime {
    commands: mpsc::Sender<Command>,
    transport: Option<iroh::Endpoint>,
    state: Arc<Mutex<State>>,
    has_provider: bool,
    has_gateway: bool,
    endpoint: watch::Sender<Option<iroh::Endpoint>>,
}
struct State {
    configuration: Option<super::configuration::ProviderMetadata>,
    ingress: Option<mpsc::Sender<iroh::endpoint::Connection>>,
    provider: Option<ProviderHandle>,
    gateway: Option<hellas_gateway::GatewayHandle>,
    work: Option<hellas_work::grant_service::WorkAdministration>,
    provider_state: RuntimeState,
    gateway_state: RuntimeState,
    /// Why the last start failed, reported to operators while Failed.
    provider_failure: Option<String>,
    gateway_failure: Option<String>,
    access: Option<hellas_gateway::GatewayAccess>,
}
#[derive(Clone, Copy)]
pub(super) enum Service {
    Provider,
    Gateway,
}
struct Command {
    service: Service,
    enabled: bool,
    update: Option<super::configuration::ProviderUpdate>,
    reply: oneshot::Sender<Result<(), WireStatus>>,
}
impl Runtime {
    pub(crate) fn provider_ingress(&self) -> Result<Option<(iroh::Endpoint, mpsc::Receiver<iroh::endpoint::Connection>)>, WireStatus> {
        let Some(endpoint) = &self.transport else { return Ok(None) };
        let (sender, receiver) = mpsc::channel(128);
        self.with(|state| state.ingress = Some(sender))?;
        Ok(Some((endpoint.clone(), receiver)))
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T, WireStatus> {
        self.state
            .lock()
            .map(|mut state| f(&mut state))
            .map_err(|_| unavailable())
    }
    pub(super) fn enqueue(
        &self,
        service: Service,
        enabled: bool,
    ) -> Result<oneshot::Receiver<Result<(), WireStatus>>, WireStatus> {
        if !match service {
            Service::Provider => self.has_provider,
            Service::Gateway => self.has_gateway,
        } {
            return Err(unsupported());
        }
        let (reply, receiver) = oneshot::channel();
        self.commands
            .try_send(Command {
                service,
                enabled,
                update: None,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    WireStatus::new(WireCode::ResourceExhausted, "host command queue is full")
                }
                mpsc::error::TrySendError::Closed(_) => unavailable(),
            })?;
        Ok(receiver)
    }
    pub(super) fn configure(&self, update: super::configuration::ProviderUpdate) -> Result<oneshot::Receiver<Result<(), WireStatus>>, WireStatus> {
        if !self.has_provider { return Err(unsupported()); }
        let (reply, receiver) = oneshot::channel();
        self.commands.try_send(Command { service: Service::Provider, enabled: true, update: Some(update), reply })
            .map_err(|_| WireStatus::new(WireCode::ResourceExhausted, "host command queue unavailable"))?;
        Ok(receiver)
    }
    pub(super) fn decorate(&self, status: &mut HostStatus) -> Result<(), WireStatus> {
        self.with(|state| {
            status.provider_configuration = state.configuration.as_ref()
                .and_then(|metadata| canonical_dag_cbor(metadata).ok()).unwrap_or_default();
            status.provider = self.has_provider.then(|| {
                let mut service = service_status(
                    state.provider_state,
                    state
                        .provider
                        .as_ref()
                        .is_some_and(ProviderHandle::is_finished),
                    state.provider_failure.as_deref(),
                );
                if !status.provider_configured {
                    service.detail = PROVIDER_NOT_BOUND.into();
                }
                service
            });
            status.gateway = self.has_gateway.then(|| {
                service_status(
                    state.gateway_state,
                    state
                        .gateway
                        .as_ref()
                        .is_some_and(hellas_gateway::GatewayHandle::is_finished),
                    state.gateway_failure.as_deref(),
                )
            });
            status.endpoint = self.transport.as_ref().map(|endpoint| endpoint.id().to_string()).unwrap_or_else(|| state
                .provider
                .as_ref()
                .filter(|handle| !handle.is_finished())
                .map(|handle| handle.node_id().to_string())
                .unwrap_or_default());
        })
    }
    pub(super) fn work(
        &self,
    ) -> Result<Option<hellas_work::grant_service::WorkAdministration>, WireStatus> {
        self.with(|state| state.work.clone())
    }
    pub(super) fn access(&self) -> Result<(hellas_gateway::GatewayAccess, String), WireStatus> {
        self.with(|state| {
            let gateway = state
                .gateway
                .as_ref()
                .filter(|handle| !handle.is_finished())
                .ok_or_else(|| {
                    WireStatus::new(WireCode::FailedPrecondition, "gateway is not running")
                })?;
            Ok((
                state.access.clone().ok_or_else(unsupported)?,
                format!("http://{}", gateway.address()),
            ))
        })?
    }
    async fn stop(&self, service: Service) -> Result<(), HostError> {
        // Take the handle before waiting: status remains readable while draining.
        match service {
            Service::Provider => {
                self.endpoint.send_replace(None);
                let handle = self
                    .with(|state| {
                        state.provider_state = RuntimeState::Stopping;
                        state.provider_failure = None;
                        state.ingress = None;
                        state.provider.take()
                    })
                    .map_err(ProviderError::from)?;
                let result = match handle {
                    Some(handle) => handle.shutdown().await.map_err(HostError::from),
                    None => Ok(()),
                };
                self.with(|state| {
                    state.provider_state = if result.is_ok() {
                        RuntimeState::Stopped
                    } else {
                        RuntimeState::Failed
                    }
                })
                .map_err(ProviderError::from)?;
                result
            }
            Service::Gateway => {
                let handle = self
                    .with(|state| {
                        state.gateway_state = RuntimeState::Stopping;
                        state.gateway_failure = None;
                        state.gateway.take()
                    })
                    .map_err(ProviderError::from)?;
                let result = match handle {
                    Some(handle) => handle.shutdown().await.map_err(HostError::from),
                    None => Ok(()),
                };
                self.with(|state| {
                    state.gateway_state = if result.is_ok() {
                        RuntimeState::Stopped
                    } else {
                        RuntimeState::Failed
                    }
                })
                .map_err(ProviderError::from)?;
                result
            }
        }
    }
    async fn set(
        &self,
        command: &Command,
        control: &Option<NodeControl>,
        provider: &Option<ProviderFactory>,
        gateway: &Option<GatewayFactory>,
    ) -> Result<(), WireStatus> {
        if !command.enabled {
            return self.stop(command.service).await.map_err(|_| unavailable());
        }
        let running = self.with(|state| match command.service {
            Service::Provider => state
                .provider
                .as_ref()
                .is_some_and(|handle| !handle.is_finished()),
            Service::Gateway => state
                .gateway
                .as_ref()
                .is_some_and(|handle| !handle.is_finished()),
        })?;
        if running && command.update.is_none() {
            return Ok(());
        }
        // A failed service is drained before an explicit restart, never retried.
        self.stop(command.service)
            .await
            .map_err(|_| unavailable())?;
        match command.service {
            Service::Provider => {
                let factory = provider.as_ref().ok_or_else(unsupported)?;
                if let Some(control) = control
                    && control
                        .node
                        .provider()
                        .await
                        .map_err(|_| unavailable())?
                        .is_none()
                {
                    return Err(WireStatus::new(
                        WireCode::FailedPrecondition,
                        PROVIDER_NOT_BOUND,
                    ));
                }
                self.with(|state| state.provider_state = RuntimeState::Starting)?;
                match factory(control.clone(), command.update.clone()).await {
                    Ok(handle) => {
                        if !match (control, handle.administration()) {
                            (Some(control), Some(admin)) => {
                                admin.node().shares_writer(&control.node)
                            }
                            (None, None) => true,
                            _ => false,
                        } {
                            let _ = handle.shutdown().await;
                            self.with(|state| {
                                state.provider_state = RuntimeState::Failed;
                                state.provider_failure = Some(HostError::Composition.to_string());
                            })?;
                            return Err(unavailable());
                        }
                        self.with(|state| {
                            self.endpoint.send_replace(Some(handle.endpoint().clone()));
                            state.configuration = handle.configuration().cloned();
                            state.work = handle.administration().cloned();
                            state.provider = Some(handle);
                            state.provider_state = RuntimeState::Running;
                        })
                    }
                    Err(error) => {
                        if command.update.is_some() && let Ok(handle) = factory(control.clone(), None).await {
                            self.with(|state| {
                                self.endpoint.send_replace(Some(handle.endpoint().clone()));
                                state.configuration = handle.configuration().cloned();
                                state.work = handle.administration().cloned();
                                state.provider = Some(handle);
                                state.provider_state = RuntimeState::Running;
                            })?;
                        } else {
                            self.with(|state| {
                                state.provider_state = RuntimeState::Failed;
                                state.provider_failure = Some(failure_detail(&*error));
                            })?;
                        }
                        Err(unavailable())
                    }
                }
            }
            Service::Gateway => {
                let factory = gateway.as_ref().ok_or_else(unsupported)?;
                let access = self.with(|state| {
                    state.gateway_state = RuntimeState::Starting;
                    state.access.clone()
                })?;
                match factory(access.ok_or_else(unsupported)?).await {
                    Ok(handle) => self.with(|state| {
                        state.gateway = Some(handle);
                        state.gateway_state = RuntimeState::Running;
                    }),
                    Err(error) => {
                        self.with(|state| {
                            state.gateway_state = RuntimeState::Failed;
                            state.gateway_failure = Some(failure_detail(&*error));
                        })?;
                        Err(unavailable())
                    }
                }
            }
        }
    }
}

async fn run(
    runtime: Runtime,
    mut receiver: mpsc::Receiver<Command>,
    mut stopped: watch::Receiver<bool>,
    control: Option<NodeControl>,
    provider: Option<ProviderFactory>,
    gateway: Option<GatewayFactory>,
) -> Result<(), HostError> {
    loop {
        let command = tokio::select! {
            biased;
            _ = stopped.wait_for(|stop| *stop) => break,
            command = receiver.recv() => match command { Some(command) => command, None => break },
        };
        let result = runtime.set(&command, &control, &provider, &gateway).await;
        let _ = command.reply.send(result);
    }
    receiver.close();
    while let Some(command) = receiver.recv().await {
        let result = runtime.set(&command, &control, &provider, &gateway).await;
        let _ = command.reply.send(result);
    }
    let gateway = runtime.stop(Service::Gateway).await;
    let provider = runtime.stop(Service::Provider).await;
    gateway.and(provider)
}
fn service_status(state: RuntimeState, finished: bool, failure: Option<&str>) -> ServiceStatus {
    let state = if state == RuntimeState::Running && finished {
        RuntimeState::Failed
    } else {
        state
    };
    ServiceStatus {
        state: state as i32,
        detail: if state == RuntimeState::Failed {
            failure.unwrap_or("service stopped with an error").into()
        } else {
            String::new()
        },
    }
}
/// The `{:#}` chain an operator would see in a CLI, bounded so one verbose
/// error cannot push HostStatus past the control frame limit.
fn failure_detail(error: &(dyn std::error::Error + 'static)) -> String {
    const MAX_DETAIL_BYTES: usize = 1024;
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        detail.push_str(": ");
        detail.push_str(&error.to_string());
        source = error.source();
    }
    detail.truncate(detail.floor_char_boundary(MAX_DETAIL_BYTES));
    detail
}
pub(super) fn identity_status(
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
) -> Result<IdentityStatus, WireStatus> {
    let node = grant_transport(enrollment)
        .ok()
        .and_then(|key| iroh::EndpointId::from_bytes(&key).ok())
        .ok_or_else(unavailable)?;
    Ok(IdentityStatus {
        producer_id: hex::encode(
            hellas_auth::ProducerId::from_public_key(
                &enrollment.genesis.statement.producer_public_key,
            )
            .as_bytes(),
        ),
        caller_public_key: hex::encode(enrollment.genesis.statement.producer_public_key.bytes()),
        node_id: node.to_string(),
        attestation: match enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => AttestationState::Software,
            hellas_rpc::RootKind::SecureEnclave => AttestationState::AppleAppAttest,
        } as i32,
        detail: String::new(),
    })
}

/// The host owns transport admission and dispatch, independently of services.
async fn accept(
    endpoint: iroh::Endpoint,
    control: Option<NodeControl>,
    runtime: Runtime,
    mut stopped: watch::Receiver<bool>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let incoming = tokio::select! {
            biased;
            _ = stopped.wait_for(|stop| *stop) => break,
            _ = tasks.join_next(), if !tasks.is_empty() => continue,
            incoming = endpoint.accept() => match incoming { Some(incoming) => incoming, None => break },
        };
        if tasks.len() >= 128 { incoming.refuse(); continue; }
        let control = control.clone();
        let runtime = runtime.clone();
        tasks.spawn(async move {
            let Ok(accepting) = incoming.accept() else { return };
            let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await else { return };
            if connection.alpn() == HostControl::ALPN.as_bytes() {
                if let Some(control) = control { let _ = control.serve_iroh(connection).await; }
            } else {
                let sender = runtime.with(|state| state.ingress.clone()).ok().flatten();
                if sender.as_ref().is_none_or(|sender| sender.try_send(connection.clone()).is_err()) {
                    connection.close(503u32.into(), b"provider unavailable");
                }
            }
        });
    }
    tasks.shutdown().await;
}

/// Attach the normal provider to its existing authority before constructing the
/// host factory. The factory receives that same writer on every restart.
pub async fn prepare_provider<R: hellas_attestation::RootProver + Send + Sync + 'static>(
    provider: &mut crate::ProviderOptions<R>,
    grants: Option<crate::grant_config::GrantConfig>,
) -> Result<Option<(NodeCoordinator, ProviderControl)>, HostError> {
        if provider.grants.is_some() {
            return Err(HostError::Composition);
        }
        let control = if let Some(config) = grants {
            let tls = super::profile::server_identity(
                &config.control_certificate,
                &config.control_private_key,
            )
            .map_err(ProviderError::from)?;
            let grants = crate::ProviderGrants {
                config: crate::GrantProviderOptions {
                    policies: config.resources,
                    max_job_millis: config.max_job_millis,
                },
                authority: crate::ProviderAuthority::Journal {
                    root: config.journal_root,
                },
            };
            let resources = if provider.executor.supports_evaluate() {
                crate::grant_provider::ProviderResources::EvaluateAndFetch(
                    &provider.executor.fetch_routes,
                )
            } else {
                crate::grant_provider::ProviderResources::Fetch(&provider.executor.fetch_routes)
            };
            let node = grants
                .open(resources, &provider.open_identity.enrollment)
                .await?;
            provider.grants = Some(grants);
            Some((
                node,
                ProviderControl {
                    socket: config.control_socket,
                    tls,
                    remote: config.remote_control,
                },
            ))
        } else {
            None
        };
    Ok(control)
}

/// Bind the normal node transport once, before pairing or service startup.
pub async fn bind_transport(
    key: iroh::SecretKey,
    port: Option<u16>,
    admission: RemoteControlAdmission,
) -> Result<iroh::Endpoint, HostError> {
    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(key).hooks(admission).alpns(vec![
            hellas_rpc::services::node::Node::ALPN.as_bytes().to_vec(),
            hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
            hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes().to_vec(),
            hellas_rpc::services::chain_sync::ChainSync::ALPN.as_bytes().to_vec(),
            HostControl::ALPN.as_bytes().to_vec(),
        ]);
    if let Some(port) = port {
        builder = builder.bind_addr(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
            .map_err(ProviderError::from)?;
    }
    Ok(builder.bind().await.map_err(ProviderError::from)?)
}
