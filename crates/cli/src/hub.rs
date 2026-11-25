//! Resolve each mutable Hub ref once in a command or gateway configuration.
use anyhow::{Context as _, Result};
use hellas_client::model::ModelSpec;
use hellas_store::content::Reservations;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, clap::Args)]
pub(crate) struct Companions {
    /// Phonon codec directory, safetensors file or Hub ref.
    #[arg(long, value_name = "REF")]
    codec: Option<PathBuf>,
    /// Phonon voices directory, JSONL catalog or Hub ref.
    #[arg(long, value_name = "REF")]
    voices: Option<PathBuf>,
}

impl Companions {
    pub(crate) fn spec(&self, model: &Path) -> ModelSpec {
        ModelSpec {
            model: model.into(),
            codec: self.codec.clone(),
            voices: self.voices.clone(),
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct Revisions(Arc<Mutex<hellas_store::hf::Revisions>>);

impl Revisions {
    pub(crate) async fn pin_spec(&self, spec: &ModelSpec) -> Result<ModelSpec> {
        spec.check_locator()?;
        let mut spec = spec.clone();
        if spec
            .paths()
            .all(|path| hellas_client::model::hf_uri(path).is_none())
        {
            return Ok(spec);
        }
        let cache = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let pool = Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES);
            let mut cache = cache
                .lock()
                .map_err(|_| anyhow::anyhow!("Hub revision cache poisoned"))?;
            for path in spec.paths_mut() {
                if let Some(uri) = hellas_client::model::hf_uri(path)
                    && let Some(pinned) = cache
                        .pin(uri, &pool, |repo, sha| {
                            eprintln!("resolved hf://{repo}@{sha}")
                        })
                        .with_context(|| format!("resolve Hub revision for {uri}"))?
                {
                    *path = pinned.into();
                }
            }
            Ok(spec)
        })
        .await?
    }
}
