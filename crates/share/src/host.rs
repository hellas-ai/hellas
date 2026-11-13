//! A vendor account contributes ordinary daemon entries and authority terms.
use hellas_sdk::daemon_config::{Backend, BackendKind, Document, Listener, Upstream};

pub struct OpenAiShareOptions {
    pub port: u16,
    pub service: String,
    pub method: String,
    pub bearer_token: String,
    pub resource: hellas_auth::authority::ResourceId,
    pub account: hellas_auth::authority::ResourceId,
    pub machine: hellas_authority::model::grant::configuration::ConfiguredBudget,
    pub account_budget: hellas_authority::model::grant::configuration::ConfiguredBudget,
    pub policy_revision: hellas_auth::authority::Revision,
    pub responses: hellas_authority::model::grant::responses::ResponsesResource,
    pub pricing: hellas_authority::model::grant::pricing::Pricing,
    pub max_job_millis: std::num::NonZeroU64,
    pub max_in_flight: std::num::NonZeroUsize,
}

/// The embedder supplies its enrollment and App Attest prover to the daemon's iroh listener.
pub fn openai_document(options: OpenAiShareOptions) -> Result<Document, hellas_sdk::daemon::Error> {
    // Reject an empty or malformed key before constructing a configuration candidate.
    hellas_providers::OpenAiResponsesFetchProvider::with_bearer(options.bearer_token.clone())?;
    let policy = crate::responses_policy(crate::ResponsesPolicyOptions {
        resource: options.resource,
        account: options.account,
        revision: options.policy_revision,
        service: &options.service,
        method: &options.method,
        responses: options.responses,
        pricing: options.pricing,
        max_job_millis: options.max_job_millis,
    })?;
    let id = options.service.clone();
    let document = Document {
        listeners: [(
            "work".into(),
            Listener::Iroh {
                port: options.port,
                backends: vec![id.clone()],
            },
        )]
        .into(),
        backends: [(
            id,
            Backend {
                max_in_flight: options.max_in_flight,
                kind: BackendKind::Fetch {
                    service: options.service,
                    method: options.method,
                    upstream: Upstream::OpenaiResponses {
                        secret: Some(options.bearer_token),
                    },
                },
            },
        )]
        .into(),
        authority: hellas_authority::model::grant::configuration::NodeConfiguration::new(
            Some(options.machine),
            [(options.account, options.account_budget)].into(),
            vec![policy],
        )?,
        ..Default::default()
    };
    document.validate()?;
    Ok(document)
}

#[cfg(test)]
mod tests;
