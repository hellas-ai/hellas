//! Host composition for the Responses gateway over a pinned grant Offer.
use crate::{
    ClientIdentity,
    grant_client::{GrantSessionOptions, GrantTransport, PinnedOffer},
    grant_gateway::GrantGateway,
};
use hellas_gateway::GatewayHandle;
use hellas_rpc::protocol::{
    work_fetch::FetchRoutePolicy,
    work_grant::records::{GrantError, Principal},
    work_profile::WorkPolicy,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum FetchGatewayError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Key(#[from] iroh::KeyParsingError),
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    Work(#[from] hellas_gateway::WorkGatewayError),
    #[error(transparent)]
    Gateway(#[from] hellas_gateway::GatewayError),
}

pub struct FetchGatewayOptions {
    pub host: String,
    pub port: Option<u16>,
    pub offer: PinnedOffer,
    pub identity: ClientIdentity,
    /// Persistent private directory; a pending acceptance survives host restarts.
    pub journal_root: PathBuf,
    pub request_overrides: serde_json::Map<String, serde_json::Value>,
}

/// This constructor owns endpoint shutdown, including failed startup and drain.
pub async fn start_fetch(options: FetchGatewayOptions) -> Result<GatewayHandle, FetchGatewayError> {
    let grant = &options.offer.offer().grant;
    let client: Principal = grant.kind.principal().clone();
    if client.producer().to_bytes().as_slice() != options.identity.caller_key().public_key().bytes()
        || client.transport() != *options.identity.node_id().as_bytes()
    {
        return Err(GrantError::Audience.into());
    }
    let mut policies = grant.policies.iter().filter(|p| {
        p.https.is_none()
            && p.work.allowed_environment()
                == hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()
    });
    let policy = policies.next().ok_or(GrantError::OutOfScope)?;
    if policies.next().is_some() {
        return Err(GrantError::OutOfScope.into());
    }
    let WorkPolicy::Fetch {
        route: FetchRoutePolicy::SealedRoute { service, method },
        ..
    } = &policy.work
    else {
        return Err(GrantError::OutOfScope.into());
    };
    let (name, service, method) = (policy.name.clone(), service.clone(), method.clone());
    let provider =
        iroh::EndpointId::from_bytes(&options.offer.offer().provider.grant_transport()?)?;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(options.identity.transport_key())
        .bind()
        .await?;
    let backend = GrantGateway::open(
        GrantSessionOptions {
            timeout: Duration::from_millis(grant.max_job_millis.get()),
            target: options.offer,
            client,
            signer: Arc::new(options.identity.caller_key().clone()),
            journal_root: options.journal_root,
        },
        GrantTransport::Remote(endpoint.clone()),
        Some(name),
    )
    .await;
    let work = match backend {
        Ok(work) => work,
        Err(error) => {
            endpoint.close().await;
            return Err(error.into());
        }
    };
    hellas_gateway::start_fetch(hellas_gateway::FetchGatewayOptions {
        host: options.host,
        port: options.port,
        provider,
        service,
        method,
        request_overrides: options.request_overrides,
        work,
    })
    .await
    .map_err(Into::into)
}
