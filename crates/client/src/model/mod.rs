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
mod program;
#[cfg(feature = "models")]
mod source;
#[cfg(feature = "models")]
pub use catena_lang::codegen::GpuDialect;

/// Program renderers: catena-models' program assembly for each GPU target,
/// registered under the evaluator id its programs name.
#[cfg(feature = "models")]
fn renderers() -> impl Iterator<Item = (String, GpuDialect)> {
    use hellas_rpc::protocol::invocation::compute;
    [(GpuDialect::Hip, "hip"), (GpuDialect::Cuda, "cuda")]
        .map(|(dialect, name)| (compute::evaluator(name), dialect))
        .into_iter()
}

/// The evaluator id of programs rendered for `dialect`.
#[cfg(feature = "models")]
pub fn evaluator(dialect: GpuDialect) -> String {
    renderers()
        .find(|(_, d)| *d == dialect)
        .map(|(id, _)| id)
        .expect("every dialect renders")
}

/// The renderer registered under `evaluator`.
#[cfg(feature = "models")]
fn renderer(evaluator: &str) -> anyhow::Result<GpuDialect> {
    renderers()
        .find(|(id, _)| id == evaluator)
        .map(|(_, dialect)| dialect)
        .ok_or_else(|| anyhow::anyhow!("no program renderer for evaluator {evaluator}"))
}
#[cfg(feature = "models")]
pub use package::{ComputeJob, ModelKind, ModelPackage, ModelRequest, ModelResponse};
#[cfg(feature = "models")]
mod qwen3;
#[cfg(feature = "models")]
pub mod speech;
#[cfg(feature = "models")]
pub mod whisper;

#[cfg(feature = "models")]
pub mod wav;

/// Return the immutable Hub model reference when the source is remote.
#[cfg(feature = "models")]
pub fn hf_uri(source: &std::path::Path) -> Option<&str> {
    source.to_str().filter(|s| s.starts_with("hf://"))
}

/// Execution sources prepared before activating a local backend.
#[cfg(feature = "models")]
pub struct ModelFiles {
    pub local: Vec<std::path::PathBuf>,
    pub hub: Vec<hellas_store::hf::PinnedFile>,
}
#[cfg(feature = "models")]
impl ModelFiles {
    pub async fn resolve(
        models: impl IntoIterator<Item = std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        Self::for_voices(models, &[]).await
    }
    pub async fn for_voices(
        models: impl IntoIterator<Item = std::path::PathBuf>,
        voices: &[String],
    ) -> anyhow::Result<Self> {
        let paths: Vec<_> = models.into_iter().collect();
        let voices = voices.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut all = Self {
                local: Vec::new(),
                hub: Vec::new(),
            };
            for path in paths {
                let files = source::Source::open(&path)?.files(&voices)?;
                all.local.extend(files.local);
                all.hub.extend(files.hub);
            }
            Ok(all)
        })
        .await?
    }
}

#[cfg(feature = "models")]
pub fn voice_allowed(voices: &[String], voice: &str) -> bool {
    let selected = if voice == "default" {
        catena_models::phonon::DEFAULT_VOICE
    } else {
        voice
    };
    native::selected_voices(voices).contains(selected)
}
