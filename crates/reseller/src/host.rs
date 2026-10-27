//! Vendor composition uses SDK's checked Fetch service and its existing authority store.
use hellas_rpc::ProviderEnrollmentBundle;
use hellas_sdk::{
    FetchProviderOptions, FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry,
    GrantProviderOptions, NodeIdentity, ProviderError, ProviderHandle, RootProver,
    start_fetch_provider,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, thiserror::Error)]
pub enum OpenAiProviderError {
    #[error(transparent)]
    Config(#[from] crate::OpenAiConfigError),
    #[error(transparent)]
    Grant(#[from] hellas_authority::model::grant::records::GrantError),
    #[error(transparent)]
    Route(#[from] hellas_executor::FetchRouteBindingError),
    #[error(transparent)]
    Duplicate(#[from] hellas_executor::DuplicateFetchRoute),
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

pub struct OpenAiProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: NodeIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub service: String,
    pub method: String,
    pub bearer_token: String,
    pub resource: hellas_auth::authority::ResourceId,
    pub account: hellas_auth::authority::ResourceId,
    pub policy_revision: hellas_auth::authority::Revision,
    pub responses: hellas_authority::model::grant::responses::ResponsesResource,
    pub pricing: hellas_authority::model::grant::pricing::Pricing,
    pub max_job_millis: std::num::NonZeroU64,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
}

pub async fn start_openai_provider<R>(
    options: &OpenAiProviderOptions<R>,
    host: Option<hellas_sdk::node_control::NodeControl>,
) -> Result<ProviderHandle, OpenAiProviderError>
where
    R: RootProver + Send + Sync + 'static,
{
    let policy = crate::responses_policy(
        options.resource,
        options.account,
        options.policy_revision,
        &options.service,
        &options.method,
        options.responses.clone(),
        options.pricing.clone(),
    )?;
    let upstream = Arc::new(crate::OpenAiResponsesFetchProvider::with_bearer(
        options.bearer_token.clone(),
    )?);
    let adaptor = Arc::new(crate::OpenAiResponsesAdaptorFactory::new()?);
    let mut routes = FetchRouteRegistry::new();
    routes.register(
        FetchRoute::new(options.service.clone(), options.method.clone()),
        FetchRouteEntry::new(upstream, adaptor, FetchRoutePolicy::default())?,
    )?;
    let config = FetchProviderOptions {
        port: options.port,
        identity: options.identity.clone(),
        enrollment: options.enrollment.clone(),
        root: options.root.clone(),
        state_directory: options.state_directory.clone(),
        routes,
        grants: Some(GrantProviderOptions {
            policies: vec![policy],
            max_job_millis: options.max_job_millis,
        }),
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_capacity: options.fetch_queue_capacity,
        paid_work: None,
    }
    .prepare()
    .await?;
    let config = match host {
        Some(host) => config.on_host(host)?,
        None => config,
    };
    Ok(start_fetch_provider(config).await?)
}

impl<R: RootProver + Send + Sync + 'static> OpenAiProviderOptions<R> {
    /// Gate supplies its App Attest prover and vendor configuration here; SDK
    /// owns the shared writer, control listener and serialized service lifetime.
    pub fn into_factory(self) -> hellas_sdk::node_control::host::ProviderFactory {
        let options = Arc::new(self);
        hellas_sdk::node_control::host::ProviderFactory {
            prepare: None,
            start: Arc::new(move |host| {
                let options = options.clone();
                Box::pin(async move { Ok(start_openai_provider(&options, host).await?) })
            }),
        }
    }
}

#[cfg(test)]
mod tests;
