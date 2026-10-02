//! One private grant channel behind the same gateway execution interface as a
//! paid pool. HTTP disconnects never abandon an already signed proposal.
use crate::grant_client::{
    GrantClientError, GrantSession, GrantSessionOptions, GrantTransport, GrantWorkResult,
};

pub mod responses;
use futures::future::BoxFuture;
use hellas_gateway::{
    ExecutionEvent, WorkExecutionBackend, WorkExecutionRequest, WorkFetchRequest, WorkGatewayBusy,
    WorkGatewayError, WorkOutputStream,
};
use hellas_rpc::{
    ProducerSigningKey,
    output::OutputEvent,
    protocol::{
        work_fetch::{FetchRoutePolicy, PreparedPaidFetchInputV1},
        work_grant::records::SignedOffer,
        work_profile::{PreparedWorkInput, WorkPolicy},
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

#[derive(Debug, thiserror::Error)]
pub enum GrantGatewayError {
    #[error(transparent)]
    Client(#[from] GrantClientError),
    #[error("no granted resource matches this request")]
    NoMatchingPolicy,
    #[error("several granted resources match; select --grant-policy explicitly")]
    AmbiguousPolicy,
    #[error("gateway output consumer is too slow; accepted work continues")]
    SlowConsumer,
    #[error("queued request exceeded its time budget")]
    QueueTimeout,
    #[error("grant provider transport is invalid")]
    Transport,
}
fn error(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Execution(Box::new(e))
}
fn rejected(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Rejected(Box::new(e))
}
fn client_error(e: GrantClientError) -> WorkGatewayError {
    use hellas_rpc::pb::work::{GrantRefusalCode as C, WorkRefused};
    let code = match &e {
        GrantClientError::Refused { code, .. } => Some(*code),
        GrantClientError::Store(store) => WorkRefused::from(store)
            .grant
            .and_then(|r| C::try_from(r.code).ok()),
        GrantClientError::Grant(grant) => WorkRefused::from(
            &hellas_work::work_store::grant::GrantStoreError::Grant(grant.clone()),
        )
        .grant
        .and_then(|r| C::try_from(r.code).ok()),
        _ => None,
    };
    match code {
        Some(C::Budget) => WorkGatewayError::Quota(Box::new(e)),
        Some(C::Concurrency | C::QueueCapacity | C::StateCapacity) => WorkGatewayBusy.into(),
        Some(
            C::Unauthorized
            | C::Expired
            | C::Paused
            | C::Revoked
            | C::Quarantined
            | C::StaleGeneration
            | C::StaleRevision,
        ) => WorkGatewayError::Denied(Box::new(e)),
        Some(
            C::Malformed
            | C::OutOfScope
            | C::Origin
            | C::PathMethod
            | C::Tls
            | C::Credential
            | C::Headers
            | C::GenerationCap
            | C::StreamUsage
            | C::ResponseCap,
        ) => rejected(e),
        _ => error(e),
    }
}
pub struct GrantGateway {
    session: Arc<AsyncMutex<GrantSession>>,
    offer: SignedOffer,
    policy: Option<String>,
    provider: iroh::EndpointId,
    signer: Arc<ProducerSigningKey>,
    timeout: Duration,
    assurance: hellas_rpc::Assurance,
    endpoint: Option<iroh::Endpoint>,
    admission: Arc<Semaphore>,
    tasks: crate::gateway_work::WorkTasks,
}
impl GrantGateway {
    /// The gateway owns the endpoint lifecycle when given a remote transport.
    pub async fn open(
        options: GrantSessionOptions,
        transport: GrantTransport,
        policy: Option<String>,
    ) -> Result<Arc<Self>, WorkGatewayError> {
        let assurance = options.target.trust().required_assurance;
        let signer = options.signer.clone();
        let timeout = options.timeout;
        let provider = iroh::EndpointId::from_bytes(
            &options
                .target
                .offer()
                .provider
                .grant_transport()
                .map_err(error)?,
        )
        .map_err(|_| error(GrantGatewayError::Transport))?;
        let endpoint = match &transport {
            GrantTransport::Remote(endpoint) => Some(endpoint.clone()),
            GrantTransport::Local(_) => None,
        };
        let mut session = GrantSession::open(options, transport)
            .await
            .map_err(client_error)?;
        // Recover the single unresolved acceptance before admitting fresh work.
        // Lost bodies can only be resolved after their signed acceptance window.
        let deadline = Instant::now() + timeout;
        loop {
            match session.recover().await {
                Ok(_) => break,
                Err(GrantClientError::RecoveryTooEarly) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await
                }
                Err(e) => {
                    let _ = session.shutdown().await;
                    if let Some(endpoint) = endpoint {
                        endpoint.close().await;
                    }
                    return Err(client_error(e));
                }
            }
        }
        let offer = session.offer().clone();
        if policy
            .as_ref()
            .is_some_and(|name| !offer.offer().grant.policies.iter().any(|p| &p.name == name))
        {
            let _ = session.shutdown().await;
            if let Some(endpoint) = endpoint {
                endpoint.close().await;
            }
            return Err(rejected(GrantGatewayError::NoMatchingPolicy));
        }
        Ok(Arc::new(Self {
            session: Arc::new(AsyncMutex::new(session)),
            offer,
            policy,
            provider,
            signer,
            timeout,
            assurance,
            endpoint,
            admission: Arc::new(Semaphore::new(32)),
            tasks: crate::gateway_work::WorkTasks::default(),
        }))
    }

    /// Exact private HTTP routes derived from current standing. Later scope
    /// changes must match these routes or be refused; they cannot move accounts.
    pub fn http_config(&self) -> Result<hellas_gateway::HttpGatewayConfig, WorkGatewayError> {
        let mut policies = self.offer.offer().grant.policies.iter().filter(|p| {
            p.https.is_some() && self.policy.as_ref().is_none_or(|name| name == &p.name)
        });
        let policy = policies
            .next()
            .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
        if policies.next().is_some() {
            return Err(rejected(GrantGatewayError::AmbiguousPolicy));
        }
        let WorkPolicy::Fetch {
            route: FetchRoutePolicy::SealedRoute { service, method },
            ..
        } = &policy.work
        else {
            return Err(rejected(GrantGatewayError::NoMatchingPolicy));
        };
        let template = policy.https.as_ref().expect("filtered HTTPS resource");
        Ok(hellas_gateway::HttpGatewayConfig {
            service: service.clone(),
            method: method.clone(),
            backends: Default::default(),
            max_in_flight: 32,
            routes: template
                .paths
                .iter()
                .flat_map(|path| {
                    template
                        .methods
                        .iter()
                        .map(move |verb| hellas_gateway::HttpRoute {
                            path: path.clone(),
                            method: verb.clone(),
                            url: format!("{}{}", template.origin, path),
                            credential: template.credential.clone(),
                            tls: template.tls.clone(),
                            headers: vec![],
                            max_response_bytes: template.max_response_bytes,
                        })
                })
                .collect(),
        })
    }

    fn submit<E: GrantEvent>(
        &self,
        request: Request,
    ) -> Result<WorkOutputStream<E>, WorkGatewayError> {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| WorkGatewayBusy)?;
        if self.admission.is_closed() {
            return Err(WorkGatewayBusy.into());
        }
        let session = self.session.clone();
        let selected = self.policy.clone();
        let assurance = self.assurance;
        let signer = self.signer.clone();
        let admission = self.admission.clone();
        let deadline = tokio::time::Instant::now() + self.timeout;
        let (sender, receiver) =
            tokio::sync::mpsc::channel(crate::gateway_work::OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = tokio::sync::watch::channel(false);
        let budget = Arc::new(Semaphore::new(crate::gateway_work::OUTPUT_BUFFER_BYTES));
        self.tasks.spawn(async move {
            let _permit = permit;
            let result = async {
                let mut session = tokio::time::timeout_at(deadline, session.lock())
                    .await
                    .map_err(|_| error(GrantGatewayError::QueueTimeout))?;
                if sender.is_closed() || admission.is_closed() {
                    return Err(WorkGatewayBusy.into());
                }
                tokio::time::timeout_at(deadline, async {
                    session.recover().await?;
                    session.refresh().await
                })
                .await
                .map_err(|_| error(GrantGatewayError::QueueTimeout))?
                .map_err(client_error)?;
                let (name, input) = prepare(
                    request,
                    session.offer(),
                    selected.as_deref(),
                    &signer,
                    assurance,
                )?;
                if sender.is_closed() || admission.is_closed() {
                    return Err(WorkGatewayBusy.into());
                }
                let tx = sender.clone();
                let full = overflow.clone();
                let bytes = budget.clone();
                let progress = Arc::new(move |envelope: hellas_rpc::OutputEventEnvelope| {
                    let size = envelope.payload().len().saturating_add(1024);
                    crate::gateway_work::emit(&tx, &full, &bytes, E::prefix(envelope), size);
                    Ok(())
                });
                let output = session
                    .run_before(&name, input, Some(progress), deadline)
                    .await
                    .map_err(client_error)?;
                E::terminal(output)
            }
            .await;
            let size = result.as_ref().map_or(1024, E::bytes);
            crate::gateway_work::emit(&sender, &overflow, &budget, result, size);
        })?;
        Ok(crate::gateway_work::response_stream(
            receiver,
            overflow_receiver,
            || error(GrantGatewayError::SlowConsumer),
        ))
    }
}
enum Request {
    Fetch(WorkFetchRequest),
    Evaluate(WorkExecutionRequest),
}
fn prepare(
    request: Request,
    offer: &SignedOffer,
    selected: Option<&str>,
    signer: &ProducerSigningKey,
    assurance: hellas_rpc::Assurance,
) -> Result<(String, PreparedWorkInput), WorkGatewayError> {
    let input = match request {
        Request::Evaluate(request) => {
            let prepared = crate::gateway_work::prepare_evaluate(request, signer.public_key())?;
            PreparedWorkInput::Evaluate(prepared)
        }
        Request::Fetch(request) => {
            let mut candidates = offer.offer().grant.policies.iter().filter(|p| selected.is_none_or(|name| name == p.name) && matches!(&p.work, WorkPolicy::Fetch { route: FetchRoutePolicy::SealedRoute {service,method}, .. } if service == &request.service && method == &request.method));
            let policy = candidates
                .next()
                .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
            if candidates.next().is_some() {
                return Err(rejected(GrantGatewayError::AmbiguousPolicy));
            }
            let (body, manifest) = if let Some(https) = &policy.https {
                let mut http = hellas_rpc::http_fetch::HttpFetchRequest::decode(&request.body)
                    .map_err(rejected)?;
                https.prepare(&mut http).map_err(rejected)?;
                (
                    serde_json::to_vec(&http).map_err(error)?,
                    hellas_rpc::FetchEnvironment::Http.manifest(),
                )
            } else if policy.work.allowed_environment()
                == hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()
            {
                (
                    request.body,
                    hellas_rpc::FetchEnvironment::OpenAiResponses.manifest(),
                )
            } else {
                return Err(rejected(GrantGatewayError::NoMatchingPolicy));
            };
            let events = hellas_rpc::fetch::build_input_events_with_retention(
                &request.service,
                &request.method,
                &body,
                policy.work.allowed_environment(),
                assurance,
                signer,
                hellas_rpc::Retention::Ephemeral,
            )
            .map_err(error)?;
            return Ok((
                policy.name.clone(),
                PreparedPaidFetchInputV1::new(&events, &manifest)
                    .map_err(error)?
                    .into(),
            ));
        }
    };
    let standing = offer.offer();
    let channel = hellas_rpc::protocol::work_grant::grant_channel_id(
        standing.network,
        standing.provider.content_id(),
        standing.grant.id,
        standing.grant.kind.principal().id(),
        standing.generation,
    );
    let context = hellas_rpc::protocol::work_profile::WorkContext {
        network: standing.network,
        channel: channel.0,
        client: standing.grant.kind.principal().producer(),
        provider: standing.provider.grant_producer().map_err(error)?,
    };
    let prepared_input_digest = input
        .bound_digest(context.network, context.channel)
        .map_err(error)?;
    let request_commitment = hellas_rpc::RequestCommitment::from_digest(
        input.input_commitment().map_err(error)?.digest(),
    );
    let mut candidates = standing.grant.policies.iter().filter(|p| {
        let binding = hellas_rpc::protocol::work_profile::JobInputBinding {
            prepared_input_digest,
            request_commitment,
            environment_commitment: p.work.allowed_environment(),
        };
        selected.is_none_or(|name| name == p.name)
            && p.work.check_bound_input(&context, &binding, &input).is_ok()
    });
    let policy = candidates
        .next()
        .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
    if candidates.next().is_some() {
        return Err(rejected(GrantGatewayError::AmbiguousPolicy));
    }
    Ok((policy.name.clone(), input))
}
trait GrantEvent: Send + 'static {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self, WorkGatewayError>
    where
        Self: Sized;
    fn terminal(output: GrantWorkResult) -> Result<Self, WorkGatewayError>
    where
        Self: Sized;
    fn bytes(&self) -> usize;
}
impl GrantEvent for OutputEvent {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self, WorkGatewayError> {
        hellas_rpc::fetch::decode_fetch_event_payload(event.payload()).map_err(error)
    }
    fn terminal(output: GrantWorkResult) -> Result<Self, WorkGatewayError> {
        let terminal = output
            .events
            .last()
            .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
        Ok(
            hellas_rpc::fetch::decode_fetch_terminal_payload(terminal.payload())
                .map_err(error)?
                .to_output_event(),
        )
    }
    fn bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(crate::gateway_work::OUTPUT_BUFFER_BYTES, |bytes| {
            bytes.len()
        })
    }
}
impl GrantEvent for ExecutionEvent {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self, WorkGatewayError> {
        let delta =
            hellas_rpc::evaluate::decode_token_delta_payload(event.payload()).map_err(error)?;
        Ok(Self::Chunk {
            position: delta.end_position().map_err(error)?,
            tokens: delta.token_bytes(),
        })
    }
    fn terminal(output: GrantWorkResult) -> Result<Self, WorkGatewayError> {
        crate::gateway_work::evaluate_terminal(output.events)
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Chunk { tokens, .. } => tokens.len(),
            Self::Done(hellas_gateway::Outcome::Completed { output_events, .. }) => {
                output_events.iter().map(|e| e.payload().len()).sum()
            }
            _ => 1024,
        }
    }
}
impl WorkExecutionBackend for GrantGateway {
    fn fetch_providers(&self) -> Vec<iroh::EndpointId> {
        if self.offer.offer().grant.policies.iter().any(|p| {
            matches!(p.work, WorkPolicy::Fetch { .. })
                && self.policy.as_ref().is_none_or(|name| name == &p.name)
        }) {
            vec![self.provider]
        } else {
            vec![]
        }
    }
    fn fetch(
        &self,
        request: WorkFetchRequest,
    ) -> Result<WorkOutputStream<OutputEvent>, WorkGatewayError> {
        if request.provider != self.provider {
            return Err(WorkGatewayError::Provider(request.provider));
        }
        self.submit(Request::Fetch(request))
    }
    fn execute(
        &self,
        request: WorkExecutionRequest,
    ) -> Result<WorkOutputStream<ExecutionEvent>, WorkGatewayError> {
        self.submit(Request::Evaluate(request))
    }
    fn timeout(&self) -> Duration {
        self.timeout
    }
    fn drain(&self) -> BoxFuture<'_, Result<(), hellas_gateway::WorkShutdownError>> {
        self.admission.close();
        self.tasks.close();
        Box::pin(async move {
            let tasks = self.tasks.drain().await;
            let session = self
                .session
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|error| hellas_gateway::WorkShutdownError::Recovery(Arc::new(error)));
            if let Some(endpoint) = &self.endpoint {
                endpoint.close().await;
            }
            tasks.and(session)
        })
    }
}

#[cfg(test)]
mod tests;
