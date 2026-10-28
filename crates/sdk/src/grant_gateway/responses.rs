//! Host composition for the Responses gateway over a pinned grant Offer.
use crate::{
    grant_client::{GrantSessionOptions, GrantTransport, PinnedOffer},
    grant_gateway::GrantGateway,
};
use hellas_authority::model::grant::records::grant_transport;
use hellas_gateway::GatewayHandle;
use std::sync::Arc;
use {
    hellas_authority::model::grant::records::GrantError,
    hellas_authority::model::grant::records::GrantPolicy,
    hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy},
};

#[derive(Debug, thiserror::Error)]
pub enum FetchGatewayError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Key(#[from] iroh::KeyParsingError),
    #[error(transparent)]
    Work(#[from] hellas_gateway::WorkGatewayError),
    #[error(transparent)]
    Gateway(#[from] hellas_gateway::GatewayError),
}

#[derive(Clone)]
pub struct FetchGatewayOptions {
    pub access: hellas_gateway::GatewayAccess,
    pub archive: hellas_gateway::ArchiveOptions,
    pub host: String,
    pub port: Option<u16>,
    pub allow_remote: bool,
    pub wrap: Option<String>,
    pub wrap_args: Vec<String>,
    pub session: GrantSessionOptions,
    pub policy: Option<String>,
    pub request_overrides: serde_json::Map<String, serde_json::Value>,
}

/// Identify the Responses presentation without opening an endpoint or channel.
/// An ambiguous offer requires an explicit resource selection.
pub fn selected_policy<'a>(
    offer: &'a PinnedOffer,
    name: Option<&str>,
) -> Result<Option<&'a GrantPolicy>, GrantError> {
    let mut candidates = offer
        .offer()
        .grant
        .policies
        .iter()
        .filter(|p| name.is_none_or(|name| name == p.name));
    let response = |p: &&GrantPolicy| {
        p.https.is_none()
            && p.invocation_policy.admissions.iter().any(|a| matches!(a, Admission::Fetch { admission } if admission.contract.schema() == hellas_rpc::FetchSchema::StatelessResponsesV1))
    };
    let Some(policy) = candidates.clone().find(response) else {
        return Ok(None);
    };
    if candidates.nth(1).is_some() {
        return Err(GrantError::OutOfScope);
    }
    Ok(Some(policy))
}

/// This constructor owns endpoint shutdown, including failed startup and drain.
pub async fn start_fetch(
    options: FetchGatewayOptions,
    transport: GrantTransport,
) -> Result<GatewayHandle, FetchGatewayError> {
    let policy = selected_policy(&options.session.target, options.policy.as_deref())?
        .ok_or(GrantError::OutOfScope)?;
    let (service, method) = policy
        .invocation_policy
        .admissions
        .iter()
        .find_map(|a| match a {
            Admission::Fetch { admission }
                if admission.contract.schema() == hellas_rpc::FetchSchema::StatelessResponsesV1 =>
            {
                match &admission.route {
                    FetchRoutePolicy::SealedRoute { service, method } => Some((service, method)),
                    _ => None,
                }
            }
            _ => None,
        })
        .ok_or(GrantError::OutOfScope)?;
    let (name, service, method) = (policy.name.clone(), service.clone(), method.clone());
    let provider =
        iroh::EndpointId::from_bytes(&grant_transport(&options.session.target.offer().provider)?)?;
    let work = GrantGateway::open(options.session, transport, Some(name)).await?;
    hellas_gateway::start_fetch(hellas_gateway::FetchGatewayOptions {
        access: options.access,
        archive: options.archive,
        host: options.host,
        port: options.port,
        allow_remote: options.allow_remote,
        wrap: options.wrap,
        wrap_args: options.wrap_args,
        provider,
        service,
        method,
        request_overrides: options.request_overrides,
        work,
    })
    .await
    .map_err(Into::into)
}

impl FetchGatewayOptions {
    /// The host supplies the access it validated; `self.access` is replaced.
    pub fn into_factory(self, key: iroh::SecretKey) -> crate::node_control::host::GatewayFactory {
        Arc::new(move |access| {
            let (mut options, key) = (self.clone(), key.clone());
            options.access = access;
            Box::pin(async move {
                let transport = GrantTransport::remote(key).await?;
                Ok(start_fetch(options, transport).await?)
            })
        })
    }
}
