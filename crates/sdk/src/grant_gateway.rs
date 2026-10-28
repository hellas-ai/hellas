//! One private grant channel behind the same gateway execution interface as a
//! paid pool. HTTP disconnects never abandon an already signed proposal.

use crate::gateway_work::{
    Completed, GatewayEvent, Requester, WorkGateway, WorkRequest, WorkSource,
};
use crate::grant_client::{GrantClientError, GrantSession, GrantSessionOptions, GrantTransport};
use crate::job::JobInput;
use futures::future::BoxFuture;
use hellas_auth::{ProducerSigningKey, PublicKey};
use hellas_authority::model::grant::records::{
    GrantPolicy, SignedOffer, grant_producer, grant_transport,
};
use hellas_gateway::{WorkGatewayBusy, WorkGatewayError};
use hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, thiserror::Error)]
pub enum GrantGatewayError {
    #[error(transparent)]
    Client(#[from] GrantClientError),
    #[error("no granted resource matches this request")]
    NoMatchingPolicy,
    #[error("several granted resources match; select --grant-policy explicitly")]
    AmbiguousPolicy,
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
/// One private grant channel as a gateway work source.
pub struct GrantSource {
    session: AsyncMutex<GrantSession>,
    offer: SignedOffer,
    policy: Option<String>,
    provider: iroh::EndpointId,
    signer: Arc<ProducerSigningKey>,
    timeout: Duration,
    assurance: hellas_rpc::Assurance,
    endpoint: Option<iroh::Endpoint>,
}
/// A grant channel behind the shared gateway.
pub type GrantGateway = WorkGateway<GrantSource>;

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
        Ok(Arc::new(WorkGateway::new(
            GrantSource {
                session: AsyncMutex::new(session),
                offer,
                policy,
                provider,
                signer,
                timeout,
                assurance,
                endpoint,
            },
            32,
        )))
    }

    /// Exact private HTTP routes derived from current standing, if the grant
    /// has an HTTPS resource. Later scope changes must match these routes or be
    /// refused; they cannot move accounts.
    pub fn http_config(
        &self,
    ) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
        let mut policies = self.source.offer.offer().grant.policies.iter().filter(|p| {
            p.https.is_some()
                && self
                    .source
                    .policy
                    .as_ref()
                    .is_none_or(|name| name == &p.name)
        });
        let Some(policy) = policies.next() else {
            return Ok(None);
        };
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
        Ok(Some(hellas_gateway::HttpGatewayConfig {
            service: Some(service.clone()),
            method: Some(method.clone()),
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
        }))
    }
}

/// A gateway over one grant channel.
#[derive(Clone)]
pub struct GrantServeOptions {
    pub serve: crate::GatewayServeOptions,
    pub session: GrantSessionOptions,
    /// Selects one granted resource when the offer has several.
    pub policy: Option<String>,
}

impl GrantServeOptions {
    /// HTTPS routes come from the grant unless the caller configures them.
    /// The gateway owns the channel and its endpoint from here on.
    pub async fn start(
        self,
        transport: GrantTransport,
    ) -> hellas_gateway::GatewayResult<hellas_gateway::GatewayHandle> {
        let gateway = GrantGateway::open(self.session, transport, self.policy).await?;
        let mut serve = self.serve;
        if serve.http.is_none() {
            serve.http = match gateway.http_config() {
                Ok(http) => http,
                Err(error) => {
                    let error = hellas_gateway::GatewayError::from(error);
                    return Err(
                        match hellas_gateway::WorkExecutionBackend::drain(&*gateway).await {
                            Ok(()) => error,
                            Err(cleanup) => hellas_gateway::GatewayError::Cleanup {
                                primary: Box::new(error),
                                cleanup,
                            },
                        },
                    );
                }
            };
        }
        crate::serve_gateway(gateway, serve).await
    }

    /// The host supplies the access it validated; the configured access is replaced.
    pub fn into_factory(self, key: iroh::SecretKey) -> crate::node_control::host::GatewayFactory {
        Arc::new(move |access| {
            let (mut options, key) = (self.clone(), key.clone());
            options.serve.server.access = access;
            Box::pin(async move {
                let transport = GrantTransport::remote(key).await?;
                Ok(options.start(transport).await?)
            })
        })
    }
}

fn grant_runner(offer: &SignedOffer) -> Result<PublicKey, WorkGatewayError> {
    Ok(PublicKey::Secp256k1(
        grant_producer(&offer.offer().provider)
            .map_err(error)?
            .to_bytes(),
    ))
}

impl GrantSource {
    fn policies(&self) -> impl Iterator<Item = &GrantPolicy> {
        self.offer
            .offer()
            .grant
            .policies
            .iter()
            .filter(|p| self.policy.as_ref().is_none_or(|name| name == &p.name))
    }
}

impl WorkSource for GrantSource {
    type Error = WorkGatewayError;
    type Request = (String, JobInput);

    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        crate::gateway_work::fetch_routes(
            self.provider,
            self.policies().map(|policy| &policy.invocation_policy),
        )
    }

    /// Grant work is memory-only. Exactly one granted policy must admit it.
    fn request(&self, request: WorkRequest) -> Result<(String, JobInput), WorkGatewayError> {
        if let Some(provider) = request.pinned().filter(|p| *p != self.provider) {
            return Err(WorkGatewayError::Provider(provider));
        }
        let mut admitted = None;
        let mut refusal = None;
        for policy in self.policies() {
            match request.admitted(
                &policy.invocation_policy,
                policy.https.as_ref(),
                self.assurance,
                false,
            ) {
                Ok(_) if admitted.is_some() => {
                    return Err(rejected(GrantGatewayError::AmbiguousPolicy));
                }
                Ok(input) => admitted = Some((policy.name.clone(), input)),
                Err(error) => refusal = Some(error),
            }
        }
        admitted.ok_or_else(|| match refusal {
            Some(error) => rejected(error),
            None => rejected(GrantGatewayError::NoMatchingPolicy),
        })
    }

    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        (name, input): (String, JobInput),
        requester: Requester<E, WorkGatewayError>,
    ) -> BoxFuture<'static, Result<Option<Completed>, WorkGatewayError>> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        Box::pin(async move {
            let mut session = tokio::time::timeout_at(deadline, self.session.lock())
                .await
                .map_err(|_| queue_timeout())?;
            if requester.is_closed() {
                return Err(WorkGatewayBusy.into());
            }
            tokio::time::timeout_at(deadline, async {
                session.recover().await?;
                session.refresh().await
            })
            .await
            .map_err(|_| queue_timeout())?
            .map_err(client_error)?;
            // Scope changes may refresh the named policy; they never move the
            // request to another one.
            let offer = session.offer();
            let policy = offer
                .offer()
                .grant
                .policies
                .iter()
                .find(|policy| policy.name == name)
                .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
            let prepared = input
                .prepare(
                    &input.manifest().map_err(rejected)?,
                    &self.signer,
                    rand::random(),
                    grant_runner(offer)?,
                    &policy.invocation_policy,
                    false,
                )
                .map_err(rejected)?;
            if requester.is_closed() {
                return Err(WorkGatewayBusy.into());
            }
            let output = session
                .run_before(
                    &name,
                    prepared,
                    &input.content(),
                    Some(requester.progress()),
                    deadline,
                )
                .await
                .map_err(client_error)?;
            Ok(Some(Completed {
                output: output.output,
                provider: output.provider_key,
            }))
        })
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn gateway_error(error: WorkGatewayError) -> WorkGatewayError {
        error
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), hellas_gateway::WorkShutdownError>> {
        Box::pin(async move {
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
            session
        })
    }
}

#[cfg(test)]
mod tests;
