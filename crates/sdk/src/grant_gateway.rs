//! One private grant channel behind the same gateway execution interface as a
//! paid pool. HTTP disconnects never abandon an already signed proposal.
use crate::grant_client::{
    GrantClientError, GrantSession, GrantSessionOptions, GrantTransport, GrantWorkResult,
};
use hellas_authority::model::grant::records::{grant_producer, grant_transport};

pub mod responses;
use futures::future::BoxFuture;
use hellas_auth::{ProducerSigningKey, PublicKey};
use hellas_authority::model::grant::records::SignedOffer;
use hellas_channel::content::{EphemeralContent, InvocationContent};
use hellas_gateway::{
    WorkExecutionBackend, WorkFetchRequest, WorkGatewayBusy, WorkGatewayError, WorkOutputStream,
};
use hellas_rpc::output::OutputEvent;
use hellas_rpc::protocol::invocation::{
    Admission, PreparedInvocation,
    fetch::{self, FetchRoutePolicy},
    output::{ArtifactChunk, ArtifactPrefix},
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
fn queue_timeout() -> WorkGatewayError {
    WorkGatewayError::Timeout(Box::new(GrantGatewayError::QueueTimeout))
}
fn rejected(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Rejected(Box::new(e))
}
fn client_error(e: GrantClientError) -> WorkGatewayError {
    use hellas_rpc::pb::work::{GrantRefusalCode as C, WorkRefused};
    let code = match &e {
        GrantClientError::Refused { code, .. } => Some(*code),
        GrantClientError::Wire(status)
        | GrantClientError::Client(hellas_client::ClientError::Wire { source: status, .. })
            if matches!(
                status.code(),
                hellas_wire::WireCode::PermissionDenied | hellas_wire::WireCode::Unauthenticated
            ) =>
        {
            Some(C::Unauthorized)
        }
        GrantClientError::Store(store) => WorkRefused::from(store)
            .grant
            .and_then(|r| C::try_from(r.code).ok()),
        GrantClientError::Grant(grant) => WorkRefused::from(
            &hellas_authority::work_store::grant::NodeStoreError::Grant(grant.clone()),
        )
        .grant
        .and_then(|r| C::try_from(r.code).ok()),
        _ => None,
    };
    if matches!(e, GrantClientError::Timeout) {
        return WorkGatewayError::Timeout(Box::new(e));
    }
    let unreachable = match &e {
        GrantClientError::Wire(status)
        | GrantClientError::Client(hellas_client::ClientError::Wire { source: status, .. }) => {
            status.code() == hellas_wire::WireCode::Unavailable
        }
        GrantClientError::Client(hellas_client::ClientError::Source { source, .. }) => {
            source.is::<iroh::endpoint::ConnectError>()
        }
        _ => false,
    };
    if unreachable {
        return WorkGatewayError::Unreachable(Box::new(e));
    }
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
            &grant_transport(&options.target.offer().provider).map_err(error)?,
        )
        .map_err(|_| error(GrantGatewayError::Transport))?;
        let endpoint = match &transport {
            GrantTransport::Remote(endpoint) => Some(endpoint.clone()),
            GrantTransport::Local(_) => None,
        };
        let mut session = match GrantSession::open(options, transport).await {
            Ok(session) => session,
            Err(error) => {
                if let Some(endpoint) = endpoint {
                    endpoint.close().await;
                }
                return Err(client_error(error));
            }
        };
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
        let (service, method) = policy
            .invocation_policy
            .admissions
            .iter()
            .find_map(|a| match a {
                Admission::Fetch { admission } => match &admission.route {
                    FetchRoutePolicy::SealedRoute { service, method } => Some((service, method)),
                    _ => None,
                },
                _ => None,
            })
            .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
        let template = policy
            .https
            .as_ref()
            .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
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
        request: WorkFetchRequest,
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
                    .map_err(|_| queue_timeout())?;
                if sender.is_closed() || admission.is_closed() {
                    return Err(WorkGatewayBusy.into());
                }
                tokio::time::timeout_at(deadline, async {
                    session.recover().await?;
                    session.refresh().await
                })
                .await
                .map_err(|_| queue_timeout())?
                .map_err(client_error)?;
                let (name, input) = prepare(
                    request,
                    session.offer(),
                    session.store().channel(),
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
                let prefix = std::sync::Mutex::new((ArtifactPrefix::default(), Vec::new()));
                let progress = Arc::new(move |envelope: hellas_rpc::OutputEventEnvelope| {
                    let mut state = prefix.lock().map_err(|_| {
                        hellas_channel::work::BackendFault::caused_by(std::io::Error::other(
                            "prefix lock poisoned",
                        ))
                    })?;
                    let (prefix, pending) = &mut *state;
                    let chunk = prefix
                        .push(&envelope)
                        .map_err(hellas_channel::work::BackendFault::caused_by)?;
                    for event in E::prefix(chunk, pending)
                        .map_err(hellas_channel::work::BackendFault::caused_by)?
                    {
                        let size = event.bytes();
                        crate::gateway_work::emit(&tx, &full, &bytes, Ok(event), size);
                    }
                    Ok(())
                });
                let output = session
                    .run_before(
                        &name,
                        input,
                        &InvocationContent::Ephemeral(EphemeralContent::default()),
                        Some(progress),
                        deadline,
                    )
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
fn prepare(
    request: WorkFetchRequest,
    offer: &SignedOffer,
    _channel: &hellas_authority::work_store::grant::GrantChannelState,
    selected: Option<&str>,
    signer: &ProducerSigningKey,
    assurance: hellas_rpc::Assurance,
) -> Result<(String, PreparedInvocation), WorkGatewayError> {
    let mut candidates = offer.offer().grant.policies.iter().filter_map(|policy| {
        if selected.is_some_and(|name| name != policy.name) { return None; }
        policy.invocation_policy.admissions.iter().find_map(|a| match a { Admission::Fetch { admission } if matches!(&admission.route, FetchRoutePolicy::SealedRoute { service, method } if service == &request.service && method == &request.method) => Some((policy, admission)), _ => None })
    });
    let (policy, admission) = candidates
        .next()
        .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
    if candidates.next().is_some() {
        return Err(rejected(GrantGatewayError::AmbiguousPolicy));
    }
    let body = if let Some(https) = &policy.https {
        let mut http =
            hellas_rpc::http_fetch::HttpFetchRequest::decode(&request.body).map_err(rejected)?;
        https.prepare(&mut http).map_err(rejected)?;
        serde_json::to_vec(&http).map_err(error)?
    } else if matches!(
        admission.contract.schema(),
        hellas_rpc::FetchSchema::StatelessResponsesV1 | hellas_rpc::FetchSchema::ResponsesItemsV1
    ) {
        request.body
    } else {
        return Err(rejected(GrantGatewayError::NoMatchingPolicy));
    };
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        &request.service,
        &request.method,
        &body,
        admission.contract.manifest_id(),
        assurance,
        signer,
        hellas_rpc::Retention::Ephemeral,
    )
    .map_err(error)?;
    let input = fetch::prepare(
        &events,
        &admission.contract,
        PublicKey::Secp256k1(
            grant_producer(&offer.offer().provider)
                .map_err(error)?
                .to_bytes(),
        ),
        policy.invocation_policy.canonical_bytes().map_err(error)?,
        rand::random(),
    )
    .map_err(error)?;
    policy
        .invocation_policy
        .admit(&input, &signer.public_key())
        .map_err(rejected)?;
    Ok((policy.name.clone(), input))
}
trait GrantEvent: Send + 'static {
    fn prefix(chunk: ArtifactChunk, pending: &mut Vec<u8>) -> Result<Vec<Self>, WorkGatewayError>
    where
        Self: Sized;
    fn terminal(output: GrantWorkResult) -> Result<Self, WorkGatewayError>
    where
        Self: Sized;
    fn bytes(&self) -> usize;
}
impl GrantEvent for OutputEvent {
    fn prefix(chunk: ArtifactChunk, pending: &mut Vec<u8>) -> Result<Vec<Self>, WorkGatewayError> {
        crate::gateway_work::fetch_prefix(chunk, pending)
    }
    fn terminal(output: GrantWorkResult) -> Result<Self, WorkGatewayError> {
        crate::gateway_work::fetch_terminal(&output.output, &output.provider_key)
    }
    fn bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(crate::gateway_work::OUTPUT_BUFFER_BYTES, |bytes| {
            bytes.len()
        })
    }
}
impl WorkExecutionBackend for GrantGateway {
    fn fetch_providers(&self) -> Vec<iroh::EndpointId> {
        if self.offer.offer().grant.policies.iter().any(|p| {
            p.invocation_policy
                .admissions
                .iter()
                .any(|a| matches!(a, Admission::Fetch { .. }))
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
        self.submit(request)
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
