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

/// Enforce require mode before model opening can hash its weight file.
pub fn precheck(content: Option<&Path>, model: &Path) -> Result<()> {
    let loaded =
        crate::content_configuration::ContentConfiguration::load(content.map(Into::into), None)?;
    if loaded.config().index == hellas_store::content::IndexMode::Require {
        let records = hellas_store::fastresume::Records::default();
        let _ = records.load(&loaded.config().upper()?.join("fastresume.bin"));
        let metadata = std::fs::metadata(model.join(hellas_client::model::whisper::WEIGHTS_FILE))?;
        anyhow::ensure!(
            metadata.is_file() && records.get(&metadata).is_some(),
            "audio weights require an unchanged index record; run hellas store index first"
        );
    }
    Ok(())
}

pub async fn configure(model: &Path, root: &Path) -> Result<(GrantConfig, hellas_rpc::ContentRef)> {
    let name = model
        .file_name()
        .and_then(|name| name.to_str())
        .context("model directory needs a resource name")?;
    let package = ModelPackage::open(model).await?;
    let capacity = package
        .transcription_capacity()
        .context("--audio-model requires a transcription model")?;
    let rendered = package
        .render_job(&ModelRequest::Transcription {
            samples: &[0.0; 16000],
            language: Some("en"),
            max_new_tokens: 256,
        })
        .await?;
    let weights = rendered
        .environment
        .assets
        .iter()
        .find(|asset| asset.name == "weights")
        .context("audio model has no weights asset")?
        .object;
    let job = hellas_sdk::job::Job::compute(
        0,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        rendered.content,
    )
    .await?;
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
    Ok((config, weights))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn require_rejects_unknown_or_replaced_audio_weights_before_model_opening() {
        use hellas_store::content::{IndexMode, Reservations};
        let root = tempfile::tempdir().unwrap();
        let model = root.path().join("model");
        std::fs::create_dir(&model).unwrap();
        let weights = model.join(hellas_client::model::whisper::WEIGHTS_FILE);
        std::fs::write(&weights, b"original weights").unwrap();
        let path = root.path().join("content.toml");
        std::fs::write(
            &path,
            "[content]\nupper = 'upper'\nlower = ['model']\nindex = 'require'\n",
        )
        .unwrap();
        let error = precheck(Some(&path), &model).unwrap_err();
        assert!(error.to_string().contains("unchanged index record"));
        // Preparing the index is an explicit owner operation. Startup itself
        // only reads the identity record, before any model metadata or hasher.
        let loaded =
            crate::content_configuration::ContentConfiguration::load(Some(path.clone()), None)
                .unwrap();
        let mut config = loaded.config().clone();
        config.index = IndexMode::Resume;
        let store = config
            .open(
                Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
                Default::default(),
            )
            .await
            .unwrap();
        store.close().await;
        precheck(Some(&path), &model).unwrap();
        let replacement = model.join("replacement");
        std::fs::write(&replacement, b"replaced weights").unwrap();
        std::fs::rename(replacement, weights).unwrap();
        let error = precheck(Some(&path), &model).unwrap_err();
        assert!(error.to_string().contains("unchanged index record"));
    }
}
