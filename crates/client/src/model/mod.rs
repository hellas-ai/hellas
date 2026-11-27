//! Client-side model assets.
#[cfg(feature = "models")]
pub mod decision;
#[cfg(feature = "models")]
pub mod flux;
pub mod gguf;
#[cfg(feature = "models")]
mod native;
#[cfg(feature = "models")]
mod package;
#[cfg(feature = "models")]
mod spec;
#[cfg(feature = "models")]
pub use spec::ModelSpec;
#[cfg(feature = "models")]
mod program;
#[cfg(feature = "models")]
mod source;
#[cfg(feature = "models")]
pub use catena_lang::codegen::GpuDialect;

/// Program renderers: catena-models' program assembly for each GPU runtime,
/// registered under the runtime's evaluators, one per device architecture.
#[cfg(feature = "models")]
const RENDERERS: [(GpuDialect, &str); 2] = [(GpuDialect::Hip, "hip"), (GpuDialect::Cuda, "cuda")];

/// The evaluator id of programs rendered for `dialect` on a device `arch`.
#[cfg(feature = "models")]
pub fn evaluator(dialect: GpuDialect, arch: &str) -> String {
    let (_, runtime) = RENDERERS
        .into_iter()
        .find(|(d, _)| *d == dialect)
        .expect("every dialect renders");
    hellas_rpc::protocol::invocation::compute::evaluator(runtime, arch)
}

/// The renderer registered under `evaluator`.
#[cfg(feature = "models")]
fn renderer(evaluator: &str) -> anyhow::Result<GpuDialect> {
    use hellas_rpc::protocol::invocation::compute;
    RENDERERS
        .into_iter()
        .find(|(_, runtime)| compute::architecture(evaluator, runtime).is_some())
        .map(|(dialect, _)| dialect)
        .ok_or_else(|| anyhow::anyhow!("no program renderer for evaluator {evaluator}"))
}
#[cfg(feature = "models")]
pub use package::{ComputeJob, ModelKind, ModelPackage, ModelRequest, ModelResponse};
#[cfg(feature = "models")]
pub use source::{CatalogUnavailable, acquire_peer_model, publish_model};
#[cfg(feature = "models")]
mod qwen3;
#[cfg(feature = "models")]
pub mod speech;
#[cfg(feature = "models")]
pub mod whisper;

#[cfg(feature = "models")]
pub mod wav;

#[cfg(feature = "models")]
pub fn model_locator(
    source: &std::path::Path,
) -> anyhow::Result<Option<hellas_store::content::Locator>> {
    let Some(value) = source.to_str() else {
        return Ok(None);
    };
    if value.contains("://") {
        Ok(Some(value.parse()?))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "models")]
pub fn is_local(source: &std::path::Path) -> bool {
    source.to_str().is_none_or(|value| !value.contains("://"))
}

/// Execution sources prepared before activating a local backend.
#[cfg(feature = "models")]
#[derive(Default)]
pub struct ModelFiles {
    pub local: Vec<std::path::PathBuf>,
    pub hub: Vec<hellas_store::hf::PinnedFile>,
}
#[cfg(feature = "models")]
impl ModelSpec {
    pub async fn files(&self) -> anyhow::Result<ModelFiles> {
        self.check_locator()?;
        if matches!(
            model_locator(&self.model)?,
            Some(hellas_store::content::Locator::Hellas { .. })
        ) {
            return Ok(ModelFiles::default());
        }
        let spec = self.clone();
        tokio::task::spawn_blocking(move || source::Source::open(&spec)?.files()).await?
    }
}

#[cfg(feature = "models")]
pub fn voice_allowed(voices: &[String], voice: &str) -> bool {
    fn name(v: &str) -> &str {
        if v == "default" {
            catena_models::phonon::DEFAULT_VOICE
        } else {
            v
        }
    }
    if voices.is_empty() {
        return name(voice) == catena_models::phonon::DEFAULT_VOICE;
    }
    voices
        .iter()
        .any(|configured| name(configured) == name(voice))
}
