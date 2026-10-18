//! Host-owned lifecycle. Authority checks enqueue commands; this supervisor owns
//! completion and drain even after the requesting control connection disappears.
use super::*;
use crate::{ProviderControl, ProviderError, ProviderHandle, grant_gateway::responses};
use futures::future::BoxFuture;
use hellas_work::model::grant::records::grant_transport;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot, watch};

pub type ProviderFactory = Arc<
    dyn Fn(
            Option<NodeControl>,
        )
            -> BoxFuture<'static, Result<ProviderHandle, Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + Sync,
>;

pub struct HostOptions {
    pub identity: Option<hellas_rpc::ProviderEnrollmentBundle>,
    pub control: Option<(NodeCoordinator, ProviderControl)>,
    pub provider: Option<ProviderFactory>,
    pub gateway: Option<(responses::FetchGatewayOptions, iroh::SecretKey)>,
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
}
impl HostHandle {
    /// Both services begin stopped. Startup neither creates authority nor grants.
    pub async fn start(options: HostOptions) -> Result<Self, HostError> {
        if let Some((node, _)) = &options.control
            && options.provider.is_some()
        {
            node.check_provider(options.identity.as_ref().ok_or(HostError::Composition)?)
                .await?;
        }
        if let Some((gateway, _)) = &options.gateway {
            if !options
                .control
                .as_ref()
                .is_some_and(|(node, _)| gateway.access.shares_writer(node))
            {
                return Err(HostError::Composition);
            }
            gateway.access.validate().await?;
        }
        let identity = options.identity.as_ref().map(identity_status).transpose()?;
        let state = Arc::new(Mutex::new(State {
            identity,
            provider: None,
            gateway: None,
            work: None,
            provider_state: RuntimeState::Stopped,
            gateway_state: RuntimeState::Stopped,
            access: options.gateway.as_ref().map(|(g, _)| g.access.clone()),
        }));
        let (commands, receiver) = mpsc::channel(8);
        let runtime = Runtime {
            commands,
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
        let task = tokio::spawn(run(
            runtime.clone(),
            receiver,
            stopped,
            control,
            options.provider,
            options.gateway,
        ));
        Ok(Self {
            runtime,
            listener,
            stop,
            task,
        })
    }

    /// Current provider endpoint for host metrics; stopping publishes None.
    pub fn provider_endpoint(&self) -> watch::Receiver<Option<iroh::Endpoint>> {
        self.runtime.endpoint.subscribe()
    }

    /// Compose the daemon through the same supervisor used by embedded hosts.
    /// Explicit process startup enables its provider; subsequent control is checked.
    pub async fn serve<R: hellas_attestation::RootProver + Send + Sync + 'static>(
        mut provider: crate::ProviderOptions<R>,
        grants: Option<crate::grant_config::GrantConfig>,
    ) -> Result<Self, HostError> {
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
        let identity = Some(provider.open_identity.enrollment.clone());
        let host = Self::start(HostOptions {
            control,
            identity,
            gateway: None,
            provider: Some(Arc::new(move |control| {
                let mut provider = provider.clone();
                Box::pin(async move {
                    if let Some(control) = control {
                        provider = provider.on_host(control)?;
                    }
                    Ok(crate::start_fetch_provider(provider).await?)
                })
            })),
        })
        .await?;
        let result = async {
            host.runtime
                .enqueue(Service::Provider, true)?
                .await
                .map_err(|_| unavailable())?
        }
        .await;
        if let Err(error) = result {
            host.shutdown().await?;
            return Err(ProviderError::from(error).into());
        }
        Ok(host)
    }

    pub async fn shutdown(mut self) -> Result<(), HostError> {
        self.stop.send_replace(true);
        let listener = match self.listener.take() {
            Some(listener) => listener.shutdown().await.map_err(HostError::from),
            None => Ok(()),
        };
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
    state: Arc<Mutex<State>>,
    has_provider: bool,
    has_gateway: bool,
    endpoint: watch::Sender<Option<iroh::Endpoint>>,
}
struct State {
    identity: Option<IdentityStatus>,
    provider: Option<ProviderHandle>,
    gateway: Option<hellas_gateway::GatewayHandle>,
    work: Option<hellas_work::grant_service::WorkAdministration>,
    provider_state: RuntimeState,
    gateway_state: RuntimeState,
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
    reply: oneshot::Sender<Result<(), WireStatus>>,
}
impl Runtime {
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
    pub(super) fn decorate(&self, status: &mut HostStatus) -> Result<(), WireStatus> {
        self.with(|state| {
            status.identity = state.identity.clone();
            status.provider = self.has_provider.then(|| {
                service_status(
                    state.provider_state,
                    state
                        .provider
                        .as_ref()
                        .is_some_and(ProviderHandle::is_finished),
                )
            });
            status.gateway = self.has_gateway.then(|| {
                service_status(
                    state.gateway_state,
                    state
                        .gateway
                        .as_ref()
                        .is_some_and(hellas_gateway::GatewayHandle::is_finished),
                )
            });
            status.endpoint = state
                .provider
                .as_ref()
                .filter(|handle| !handle.is_finished())
                .map(|handle| handle.node_id().to_string())
                .unwrap_or_default();
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
        gateway: &Option<(responses::FetchGatewayOptions, iroh::SecretKey)>,
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
        if running {
            return Ok(());
        }
        // A failed service is drained before an explicit restart, never retried.
        self.stop(command.service)
            .await
            .map_err(|_| unavailable())?;
        match command.service {
            Service::Provider => {
                let factory = provider.as_ref().ok_or_else(unsupported)?;
                self.with(|state| state.provider_state = RuntimeState::Starting)?;
                match factory(control.clone()).await {
                    Ok(handle) => {
                        if !match (control, handle.administration()) {
                            (Some(control), Some(admin)) => {
                                admin.node().shares_writer(&control.node)
                            }
                            (None, None) => true,
                            _ => false,
                        } {
                            let _ = handle.shutdown().await;
                            self.with(|state| state.provider_state = RuntimeState::Failed)?;
                            return Err(unavailable());
                        }
                        self.with(|state| {
                            self.endpoint.send_replace(Some(handle.endpoint().clone()));
                            state.work = handle.administration().cloned();
                            state.provider = Some(handle);
                            state.provider_state = RuntimeState::Running;
                        })
                    }
                    Err(_) => {
                        self.with(|state| state.provider_state = RuntimeState::Failed)?;
                        Err(unavailable())
                    }
                }
            }
            Service::Gateway => {
                let (options, key) = gateway.as_ref().ok_or_else(unsupported)?.clone();
                self.with(|state| state.gateway_state = RuntimeState::Starting)?;
                match async {
                    let transport = crate::grant_client::GrantTransport::remote(key)
                        .await
                        .map_err(|_| unavailable())?;
                    responses::start_fetch(options, transport)
                        .await
                        .map_err(|_| unavailable())
                }
                .await
                {
                    Ok(handle) => self.with(|state| {
                        state.gateway = Some(handle);
                        state.gateway_state = RuntimeState::Running;
                    }),
                    Err(_) => {
                        self.with(|state| state.gateway_state = RuntimeState::Failed)?;
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
    gateway: Option<(responses::FetchGatewayOptions, iroh::SecretKey)>,
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
    let gateway = runtime.stop(Service::Gateway).await;
    let provider = runtime.stop(Service::Provider).await;
    gateway.and(provider)
}
fn service_status(state: RuntimeState, finished: bool) -> ServiceStatus {
    let state = if state == RuntimeState::Running && finished {
        RuntimeState::Failed
    } else {
        state
    };
    ServiceStatus {
        state: state as i32,
        detail: if state == RuntimeState::Failed {
            "service stopped with an error".into()
        } else {
            String::new()
        },
    }
}
fn identity_status(
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
) -> Result<IdentityStatus, HostError> {
    let node =
        iroh::EndpointId::from_bytes(&grant_transport(enrollment).map_err(ProviderError::from)?)
            .map_err(|_| HostError::Composition)?;
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
