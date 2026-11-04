//! A converted audio model is a complete, model-pinned Work resource.
use anyhow::{Context, Result};
use hellas_auth::{
    Digest,
    authority::{ResourceId, Revision},
};
use hellas_authority::model::grant::{
    configuration::{ConfiguredBudget, NodeConfiguration},
    pricing::Pricing,
    records::GrantPolicy,
};
use hellas_client::model::{ModelPackage, ModelRequest};
use hellas_rpc::protocol::invocation::{Admission, ComputePrograms, InvocationPolicy, Limits};
use hellas_sdk::grant_config::GrantConfig;
use std::{
    num::{NonZeroU16, NonZeroU64},
    path::Path,
};

pub fn configure(model: &Path, root: &Path) -> Result<GrantConfig> {
    let name = model
        .file_name()
        .and_then(|name| name.to_str())
        .context("model directory needs a resource name")?;
    let package = ModelPackage::open(model)?;
    let capacity = package
        .transcription_capacity()
        .context("--audio-model requires a transcription model")?;
    let rendered = package.render_job(&ModelRequest::Transcription {
        samples: &[0.0; 16000],
        language: Some("en"),
        max_new_tokens: 256,
    })?;
    let job = hellas_sdk::job::Job::compute(
        0,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        hellas_channel::content::InvocationContent::Ephemeral(rendered.content),
    )?;
    let manifest = job.manifest();
    let account = ResourceId(Digest::hash(b"hellas.model.account.v1"));
    let policy = GrantPolicy {
        resource: ResourceId(hellas_auth::hash_tuple(
            "hellas.model.resource.v1",
            &[name.as_bytes(), manifest.content_id().as_bytes()],
        )),
        account,
        revision: Revision(1),
        name: name.into(),
        invocation_policy: InvocationPolicy {
            admissions: vec![Admission::Compute {
                evaluator: manifest.application().evaluator().into(),
                programs: ComputePrograms::Only {
                    manifests: vec![manifest.content_id()],
                },
            }],
            limits: Limits {
                max_upload_bytes: 4194304,
                max_output_bytes: 1048576,
                max_steps: u64::try_from(capacity)?,
                execution_timeout_ms: 900000,
            },
        },
        https: None,
        responses: None,
        pricing: Pricing {
            revision: Revision(1),
            rates: Some(vec![]),
        },
    };
    let budget = ConfiguredBudget {
        max_in_flight: NonZeroU16::MIN,
        limits: vec![],
    };
    let mut config = GrantConfig::unconfigured(root);
    config.max_job_millis = NonZeroU64::new(900000).unwrap();
    config.configuration = NodeConfiguration::new(
        Some(budget.clone()),
        [(account, budget)].into(),
        vec![policy],
    )?;
    Ok(config)
}
