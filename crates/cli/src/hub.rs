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
        use hellas_store::content::Locator;
        let locators = spec
            .paths()
            .map(hellas_client::model::model_locator)
            .collect::<Result<Vec<_>>>()?;
        if !locators
            .iter()
            .any(|locator| matches!(locator, Some(Locator::Hub(_))))
        {
            return Ok(spec);
        }
        let cache = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let pool = Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES);
            let mut cache = cache
                .lock()
                .map_err(|_| anyhow::anyhow!("Hub revision cache poisoned"))?;
            for (path, locator) in spec.paths_mut().zip(locators) {
                if let Some(Locator::Hub(reference)) = locator
                    && let Some(pinned) = cache
                        .pin(reference, &pool, |repo, sha| {
                            eprintln!("resolved hf://{repo}@{sha}")
                        })
                        .with_context(|| format!("resolve Hub revision for {}", path.display()))?
                {
                    *path = pinned.into();
                }
            }
            Ok(spec)
        })
        .await?
    }
}
