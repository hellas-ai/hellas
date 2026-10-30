//! One private grant channel behind the same gateway execution interface as a
//! paid pool. HTTP disconnects never abandon an already signed proposal.

use crate::gateway_work::{
    Completed, GatewayEvent, Requester, WorkGateway, WorkRequest, WorkSource,
};
use crate::grant_client::{GrantClientError, GrantSession, GrantSessionOptions, GrantTransport};
use futures::future::BoxFuture;
use hellas_auth::authority::ResourceId;
use hellas_authority::model::grant::records::{GrantPolicy, SignedOffer, grant_transport};
use hellas_gateway::{WorkGatewayBusy, WorkGatewayError};
use hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, thiserror::Error)]
pub enum GrantGatewayError {
    #[error(transparent)]
    Client(#[from] GrantClientError),
    #[error("no granted resource matches this request")]
    NoMatchingPolicy,
    #[error("several granted resources match; select --grant-policy explicitly")]
    AmbiguousPolicy,
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
    policy: Option<ResourceId>,
    provider: iroh::EndpointId,
    channel: hellas_channel::model::grant::ChannelId,
    assurance: hellas_rpc::Assurance,
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
        let endpoint = match &transport {
            GrantTransport::Remote(endpoint) => Some(endpoint.clone()),
            GrantTransport::Local(_) => None,
        };
        let source = match GrantSource::open(options, transport, policy).await {
            Ok(source) => source,
            Err(error) => {
                if let Some(endpoint) = endpoint {
                    endpoint.close().await;
                }
                return Err(error);
            }
        };
        Ok(Arc::new(
            WorkGateway::new(source, 32).with_endpoint(endpoint),
        ))
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
                    .is_none_or(|resource| *resource == p.resource)
        });
        let Some(policy) = policies.next() else {
            return Ok(None);
        };
        if policies.next().is_some() {
            return Err(rejected(GrantGatewayError::AmbiguousPolicy));
        }
        let (service, method, routes) = policy_http_routes(policy)?;
        Ok(Some(hellas_gateway::HttpGatewayConfig {
            service: Some(service),
            method: Some(method),
            backends: Default::default(),
            max_in_flight: 32,
            routes,
        }))
    }
}

/// Project the signed resource into HTTP presentation routes.
fn policy_http_routes(
    policy: &GrantPolicy,
) -> Result<(String, String, Vec<hellas_gateway::HttpRoute>), WorkGatewayError> {
    let mut admitted_routes = policy
        .invocation_policy
        .admissions
        .iter()
        .filter_map(|a| match a {
            Admission::Fetch { admission }
                if admission.contract.schema() == hellas_rpc::FetchSchema::HttpV1 =>
            {
                match &admission.route {
                    FetchRoutePolicy::SealedRoute { service, method } => Some((service, method)),
                    _ => None,
                }
            }
            _ => None,
        });
    let (service, method) = admitted_routes
        .next()
        .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
    if admitted_routes.any(|route| route != (service, method)) {
        return Err(rejected(GrantGatewayError::AmbiguousPolicy));
    }
    let template = policy
        .https
        .as_ref()
        .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
    let routes = template
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
                    models: template
                        .model_policy
                        .as_ref()
                        .and_then(|policies| policies.iter().find(|policy| policy.path == *path))
                        .map(|policy| policy.models.clone()),
                })
        })
        .collect();
    Ok((service.clone(), method.clone(), routes))
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

impl GrantSource {
    /// Open one source without taking ownership of its transport endpoint.
    async fn open(
        options: GrantSessionOptions,
        transport: GrantTransport,
        policy: Option<String>,
    ) -> Result<Self, WorkGatewayError> {
        let assurance = options.target.trust().required_assurance;
        let provider = iroh::EndpointId::from_bytes(
            &grant_transport(&options.target.offer().provider).map_err(error)?,
        )
        .map_err(|_| error(GrantGatewayError::Transport))?;
        let mut session = GrantSession::open(options, transport)
            .await
            .map_err(client_error)?;
        loop {
            match session.recover().await {
                Ok(_) => break,
                Err(GrantClientError::RecoveryTooEarly) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => {
                    let _ = session.shutdown().await;
                    return Err(client_error(e));
                }
            }
        }
        let offer = session.offer().clone();
        let policy = match policy {
            Some(name) => match offer.offer().grant.policies.iter().find(|p| p.name == name) {
                Some(policy) => Some(policy.resource),
                None => {
                    let _ = session.shutdown().await;
                    return Err(rejected(GrantGatewayError::NoMatchingPolicy));
                }
            },
            None => None,
        };
        let channel = session.store().channel().id;
        Ok(Self {
            session: AsyncMutex::new(session),
            offer,
            policy,
            provider,
            channel,
            assurance,
        })
    }

    fn policies(&self) -> impl Iterator<Item = &GrantPolicy> {
        self.offer
            .offer()
            .grant
            .policies
            .iter()
            .filter(|p| self.policy.is_none_or(|resource| resource == p.resource))
    }
}

impl WorkSource for GrantSource {
    type Error = WorkGatewayError;
    type Request = (ResourceId, WorkRequest);

    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        self.policies()
            .flat_map(|policy| {
                crate::gateway_work::fetch_routes(
                    self.provider,
                    std::iter::once(&policy.invocation_policy),
                )
                .into_iter()
                .map(move |mut route| {
                    route.resource = Some(policy.resource);
                    route.channel = Some(self.channel);
                    route
                })
            })
            .collect()
    }

    /// Grant work is memory-only. Exactly one granted policy must admit it.
    fn request(&self, request: WorkRequest) -> Result<Self::Request, WorkGatewayError> {
        if let Some(provider) = request.pinned().filter(|p| *p != self.provider) {
            return Err(WorkGatewayError::Provider(provider));
        }
        if matches!(&request, WorkRequest::Fetch(fetch) if fetch.channel.is_some() != fetch.resource.is_some() || fetch.channel.is_some_and(|channel| channel != self.channel))
        {
            return Err(rejected(GrantGatewayError::NoMatchingPolicy));
        }
        let mut admitted = None;
        let mut refusal = None;
        for policy in self.policies() {
            if matches!(&request, WorkRequest::Fetch(fetch) if fetch.resource.is_some_and(|resource| resource != policy.resource))
            {
                continue;
            }
            match request.admitted(
                &policy.invocation_policy,
                policy.https.as_ref(),
                self.assurance,
                false,
            ) {
                Ok(_) if admitted.is_some() => {
                    return Err(rejected(GrantGatewayError::AmbiguousPolicy));
                }
                Ok(_) => admitted = Some(policy.resource),
                Err(error) => refusal = Some(error),
            }
        }
        admitted
            .map(|resource| (resource, request))
            .ok_or_else(|| match refusal {
                Some(error) => rejected(error),
                None => rejected(GrantGatewayError::NoMatchingPolicy),
            })
    }

    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        (resource, request): Self::Request,
        requester: Requester<E, WorkGatewayError>,
    ) -> BoxFuture<'static, Result<Option<Completed>, WorkGatewayError>> {
        Box::pin(async move {
            let mut session = tokio::select! {
                biased;
                _ = requester.closed() => return Ok(None),
                session = self.session.lock() => session,
            };
            if requester.is_closed() {
                return Err(WorkGatewayBusy.into());
            }
            tokio::select! {
                biased;
                _ = requester.closed() => return Ok(None),
                recovered = async {
                    session.recover().await?;
                    session.refresh().await
                } => { recovered.map_err(client_error)?; }
            }
            // Re-admit the original request against the selected resource after refresh.
            let offer = session.offer();
            let policy = offer
                .offer()
                .grant
                .policies
                .iter()
                .find(|policy| policy.resource == resource)
                .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
            let input = request
                .admitted(
                    &policy.invocation_policy,
                    policy.https.as_ref(),
                    self.assurance,
                    false,
                )
                .map_err(rejected)?;
            let prepared = crate::execution::prepare_grant_input(
                &input,
                policy,
                offer,
                session.execution_signer(),
            )
            .map_err(rejected)?;
            if requester.is_closed() {
                return Err(WorkGatewayBusy.into());
            }
            let proposed = std::sync::atomic::AtomicBool::new(false);
            let content = input.content();
            let operation = session.run_current(
                resource,
                prepared,
                &content,
                Some(requester.progress()),
                Some(requester.accepted()),
                Some(&proposed),
            );
            tokio::pin!(operation);
            let output = tokio::select! {
                biased;
                _ = requester.closed() => {
                    if !proposed.load(std::sync::atomic::Ordering::Acquire) {
                        return Ok(None);
                    }
                    operation.await
                }
                output = &mut operation => output,
            }
            .map_err(client_error)?;
            Ok(Some(Completed {
                transcript: hellas_channel::model::work::encode_transcript(&output.events)
                    .map_err(error)?,
                output: output.output,
                provider: output.provider_key,
            }))
        })
    }

    fn timeout(&self) -> Option<Duration> {
        None
    }

    fn gateway_error(error: WorkGatewayError) -> WorkGatewayError {
        error
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), hellas_gateway::WorkShutdownError>> {
        Box::pin(async move {
            self.session
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|error| hellas_gateway::WorkShutdownError::Recovery(Arc::new(error)))
        })
    }
}

#[cfg(test)]
mod tests;
