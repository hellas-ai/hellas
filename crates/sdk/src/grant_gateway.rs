//! One private grant channel behind the same gateway execution interface as a
//! paid pool. HTTP disconnects never abandon an already signed proposal.

use crate::gateway_work::{
    Completed, GatewayEvent, Requester, WorkGateway, WorkRequest, WorkSource, close_endpoints,
};
use crate::grant_client::{GrantClientError, GrantSession, GrantSessionOptions, GrantTransport};
use futures::future::BoxFuture;
use hellas_auth::authority::ResourceId;
use hellas_authority::model::grant::records::{GrantPolicy, SignedOffer, grant_transport};
use hellas_gateway::{WorkGatewayBusy, WorkGatewayError};
use hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
    #[error("grant provider transport is invalid")]
    Transport,
    #[error("grant pool has duplicate or invalid channel/resource selections")]
    PoolSelection,
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
struct GrantSource {
    session: AsyncMutex<GrantSession>,
    offer: SignedOffer,
    policy: Option<ResourceId>,
    provider: iroh::EndpointId,
    channel: hellas_channel::model::grant::ChannelId,
    assurance: hellas_rpc::Assurance,
}
/// One channel and its explicitly selected resources.
#[derive(Clone)]
pub struct GrantPoolChannel {
    pub session: GrantSessionOptions,
    pub resources: Vec<ResourceId>,
}

/// Static pool configuration; changes take effect on restart.
#[derive(Clone)]
pub struct GrantPoolOptions {
    pub channels: Vec<GrantPoolChannel>,
}

impl GrantPoolOptions {
    /// Check saved channel and resource identities without opening a session.
    pub fn validate(&self) -> Result<(), GrantGatewayError> {
        if self.channels.is_empty() || self.channels.len() > 256 {
            return Err(GrantGatewayError::PoolSelection);
        }
        let mut identities = std::collections::HashSet::new();
        let mut selections = std::collections::HashSet::new();
        let mut count = 0usize;
        for channel in &self.channels {
            if channel.resources.is_empty() {
                return Err(GrantGatewayError::PoolSelection);
            }
            let offer = channel.session.target.offer();
            let provider =
                grant_transport(&offer.provider).map_err(|_| GrantGatewayError::Transport)?;
            if !identities.insert(*channel_id(&channel.session)?.0.as_bytes()) {
                return Err(GrantGatewayError::PoolSelection);
            }
            let mut resources = std::collections::HashSet::new();
            for resource in &channel.resources {
                if !resources.insert(*resource)
                    || !selections.insert((provider, *resource))
                    || !offer
                        .grant
                        .policies
                        .iter()
                        .any(|policy| policy.resource == *resource)
                {
                    return Err(GrantGatewayError::PoolSelection);
                }
                count += 1;
            }
        }
        if count > 256 {
            return Err(GrantGatewayError::PoolSelection);
        }
        Ok(())
    }

    /// Project the saved Fetch routes for offline presentation validation.
    pub fn fetch_routes(&self) -> Result<Vec<hellas_gateway::FetchRoute>, WorkGatewayError> {
        self.validate().map_err(rejected)?;
        let mut routes = Vec::new();
        for channel in &self.channels {
            let offer = channel.session.target.offer();
            let provider =
                iroh::EndpointId::from_bytes(&grant_transport(&offer.provider).map_err(error)?)
                    .map_err(|_| error(GrantGatewayError::Transport))?;
            let id = channel_id(&channel.session).map_err(rejected)?;
            for resource in &channel.resources {
                let policy = offer
                    .grant
                    .policies
                    .iter()
                    .find(|p| p.resource == *resource)
                    .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
                routes.extend(
                    crate::gateway_work::fetch_routes(
                        provider,
                        std::iter::once(&policy.invocation_policy),
                    )
                    .into_iter()
                    .map(|mut route| {
                        route.resource = Some(*resource);
                        route.channel = Some(id);
                        route
                    }),
                );
            }
        }
        Ok(routes)
    }

    /// Project saved signed terms without contacting providers; runtime opens
    /// refresh standing and performs the same projection again.
    pub fn http_config(
        &self,
    ) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
        self.validate().map_err(rejected)?;
        let mut rows = Vec::new();
        for channel in &self.channels {
            let offer = channel.session.target.offer();
            let provider =
                iroh::EndpointId::from_bytes(&grant_transport(&offer.provider).map_err(error)?)
                    .map_err(|_| error(GrantGatewayError::Transport))?;
            let id = channel_id(&channel.session).map_err(rejected)?;
            for resource in &channel.resources {
                let policy = offer
                    .grant
                    .policies
                    .iter()
                    .find(|policy| policy.resource == *resource)
                    .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
                rows.push((provider, id, policy));
            }
        }
        pool_http_config(rows)
    }
}

fn channel_id(
    session: &GrantSessionOptions,
) -> Result<hellas_channel::model::grant::ChannelId, GrantGatewayError> {
    let node = hellas_auth::authority::NodeKey::from_public_key(session.signer.public_key())
        .map_err(|_| GrantGatewayError::PoolSelection)?;
    let client = hellas_channel::model::grant::ChannelClient {
        principal: session.principal,
        node,
    };
    Ok(session.target.offer().channel(client))
}

struct GrantSelection {
    channel: usize,
    resource: ResourceId,
    pending: Arc<AtomicUsize>,
}

/// Dispatches exact grant selections through one shared gateway.
pub struct GrantPoolSource {
    channels: Vec<Arc<GrantSource>>,
    selections: Vec<GrantSelection>,
    explicit: bool,
    choose: std::sync::Mutex<()>,
}

/// A shared gateway backed by one or more grant channels.
pub type GrantPool = WorkGateway<GrantPoolSource>;
impl GrantPool {
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
            WorkGateway::new(GrantPoolSource::single(source), 32).with_endpoint(endpoint),
        ))
    }

    /// Open one session per channel and explicitly select its resources.
    pub async fn open_pool(
        options: GrantPoolOptions,
        transports: Vec<GrantTransport>,
    ) -> Result<Arc<Self>, WorkGatewayError> {
        let mut endpoints: Vec<_> = transports
            .iter()
            .filter_map(|transport| match transport {
                GrantTransport::Remote(endpoint) => Some(endpoint.clone()),
                GrantTransport::Local(_) => None,
            })
            .collect();
        let result = GrantPoolSource::open(options, transports).await;
        match result {
            Ok(source) => Ok(Arc::new(
                WorkGateway::new(source, 32).with_endpoints(endpoints),
            )),
            Err(error) => {
                close_endpoints(&mut endpoints).await;
                Err(error)
            }
        }
    }

    /// Exact private HTTP routes derived from current standing, if the grant
    /// has an HTTPS resource. Later scope changes must match these routes or be
    /// refused; they cannot move accounts.
    pub fn http_config(
        &self,
    ) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
        if self.source.explicit {
            return self.source.pool_http_config();
        }
        let source = &self.source.channels[0];
        let mut policies = source.offer.offer().grant.policies.iter().filter(|p| {
            p.https.is_some()
                && self.source.channels[0]
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

impl GrantPoolSource {
    fn single(source: GrantSource) -> Self {
        let selections = source
            .policies()
            .map(|policy| GrantSelection {
                channel: 0,
                resource: policy.resource,
                pending: Arc::new(AtomicUsize::new(0)),
            })
            .collect();
        Self {
            channels: vec![Arc::new(source)],
            selections,
            explicit: false,
            choose: std::sync::Mutex::new(()),
        }
    }

    async fn open(
        options: GrantPoolOptions,
        transports: Vec<GrantTransport>,
    ) -> Result<Self, WorkGatewayError> {
        if options.channels.len() != transports.len() {
            return Err(rejected(GrantGatewayError::PoolSelection));
        }
        options.validate().map_err(rejected)?;
        let mut channels: Vec<Arc<GrantSource>> = Vec::new();
        let mut selections = Vec::new();
        for (entry, transport) in options.channels.into_iter().zip(transports) {
            let source = match GrantSource::open(entry.session, transport, None).await {
                Ok(source) => source,
                Err(error) => {
                    for source in &channels {
                        let _ = source.shutdown().await;
                    }
                    return Err(error);
                }
            };
            if entry.resources.iter().any(|resource| {
                !source
                    .offer
                    .offer()
                    .grant
                    .policies
                    .iter()
                    .any(|policy| policy.resource == *resource)
            }) {
                let _ = source.shutdown().await;
                for source in &channels {
                    let _ = source.shutdown().await;
                }
                return Err(rejected(GrantGatewayError::NoMatchingPolicy));
            }
            let index = channels.len();
            selections.extend(entry.resources.into_iter().map(|resource| GrantSelection {
                channel: index,
                resource,
                pending: Arc::new(AtomicUsize::new(0)),
            }));
            channels.push(Arc::new(source));
        }
        Ok(Self {
            channels,
            selections,
            explicit: true,
            choose: std::sync::Mutex::new(()),
        })
    }

    fn pool_http_config(
        &self,
    ) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
        let mut rows = Vec::new();
        for selection in &self.selections {
            let source = &self.channels[selection.channel];
            let policy = source
                .policies()
                .find(|policy| policy.resource == selection.resource)
                .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
            rows.push((source.provider, source.channel, policy));
        }
        pool_http_config(rows)
    }
}

fn pool_http_config<'a>(
    rows: impl IntoIterator<
        Item = (
            iroh::EndpointId,
            hellas_channel::model::grant::ChannelId,
            &'a GrantPolicy,
        ),
    >,
) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
    let mut backends = std::collections::BTreeMap::new();
    for (index, (provider, channel, policy)) in rows.into_iter().enumerate() {
        let Some(template) = &policy.https else {
            continue;
        };
        let (_, _, mut routes) = policy_http_routes(policy)?;
        for route in &mut routes {
            route.credential = None;
        }
        backends.insert(
            format!("resource-{index:04}"),
            hellas_gateway::HttpBackend {
                models: vec![],
                credential: template.credential.clone(),
                routes,
                max_in_flight: None,
                provider: Some(provider),
                resource: Some(policy.resource),
                channel: Some(channel),
            },
        );
    }
    if backends.is_empty() {
        return Ok(None);
    }
    let config = hellas_gateway::HttpGatewayConfig {
        service: None,
        method: None,
        routes: vec![],
        backends,
        max_in_flight: 32,
    };
    config.validate().map_err(error)?;
    Ok(Some(config))
}

struct PendingSelection(Arc<AtomicUsize>);
impl Drop for PendingSelection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// An exact resource selected for one request.
pub struct SelectedGrant {
    channel: usize,
    resource: ResourceId,
    request: WorkRequest,
    _pending: PendingSelection,
}

impl WorkSource for GrantPoolSource {
    type Error = WorkGatewayError;
    type Request = SelectedGrant;

    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        self.selections
            .iter()
            .flat_map(|selection| {
                self.channels[selection.channel]
                    .fetch_routes()
                    .into_iter()
                    .filter(move |route| route.resource == Some(selection.resource))
            })
            .collect()
    }

    fn request(&self, request: WorkRequest) -> Result<Self::Request, Self::Error> {
        if let Some(provider) = request.pinned()
            && !self
                .channels
                .iter()
                .any(|channel| channel.provider == provider)
        {
            return Err(WorkGatewayError::Provider(provider));
        }
        if matches!(&request, WorkRequest::Fetch(fetch) if fetch.channel.is_some() != fetch.resource.is_some())
        {
            return Err(rejected(GrantGatewayError::NoMatchingPolicy));
        }
        let _choose = self.choose.lock().map_err(|_| WorkGatewayBusy)?;
        let mut candidates = Vec::new();
        let mut refusal = None;
        for selection in &self.selections {
            let source = &self.channels[selection.channel];
            if request
                .pinned()
                .is_some_and(|provider| provider != source.provider)
                || matches!(&request, WorkRequest::Fetch(fetch) if fetch.channel.is_some_and(|id| id != source.channel) || fetch.resource.is_some_and(|id| id != selection.resource))
            {
                continue;
            }
            let Some(policy) = source
                .policies()
                .find(|policy| policy.resource == selection.resource)
            else {
                continue;
            };
            match request.admitted(
                &policy.invocation_policy,
                policy.https.as_ref(),
                source.assurance,
                false,
            ) {
                Ok(_) => candidates.push(selection),
                Err(error) => refusal = Some(error),
            }
        }
        if candidates.is_empty() {
            return Err(match refusal {
                Some(error) => rejected(error),
                None => rejected(GrantGatewayError::NoMatchingPolicy),
            });
        }
        if !self.explicit && candidates.len() > 1 {
            return Err(rejected(GrantGatewayError::AmbiguousPolicy));
        }
        let selected = candidates
            .into_iter()
            .min_by_key(|selection| selection.pending.load(Ordering::Acquire))
            .ok_or_else(|| rejected(GrantGatewayError::NoMatchingPolicy))?;
        selected.pending.fetch_add(1, Ordering::AcqRel);
        Ok(SelectedGrant {
            channel: selected.channel,
            resource: selected.resource,
            request,
            _pending: PendingSelection(selected.pending.clone()),
        })
    }

    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        selected: Self::Request,
        requester: Requester<E, Self::Error>,
    ) -> BoxFuture<'static, Result<Option<Completed>, Self::Error>> {
        Box::pin(async move {
            let SelectedGrant {
                channel,
                resource,
                request,
                _pending,
            } = selected;
            self.channels[channel]
                .clone()
                .run((resource, request), requester)
                .await
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
            let mut failure = None;
            for source in &self.channels {
                if let Err(error) = source.shutdown().await {
                    failure.get_or_insert(error);
                }
            }
            match failure {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
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
        let gateway = GrantPool::open(self.session, transport, self.policy).await?;
        serve_grant_gateway(gateway, self.serve).await
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

/// A gateway over an explicit static set of grant channels/resources.
#[derive(Clone)]
pub struct GrantPoolServeOptions {
    pub serve: crate::GatewayServeOptions,
    pub pool: GrantPoolOptions,
}

impl GrantPoolServeOptions {
    pub async fn start(
        self,
        transports: Vec<GrantTransport>,
    ) -> hellas_gateway::GatewayResult<hellas_gateway::GatewayHandle> {
        let gateway = GrantPool::open_pool(self.pool, transports).await?;
        serve_grant_gateway(gateway, self.serve).await
    }
}

async fn serve_grant_gateway(
    gateway: Arc<GrantPool>,
    mut serve: crate::GatewayServeOptions,
) -> hellas_gateway::GatewayResult<hellas_gateway::GatewayHandle> {
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

impl GrantSource {
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

    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        (resource, request): (ResourceId, WorkRequest),
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
