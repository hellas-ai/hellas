//! Client-side model assets.
#[cfg(feature = "models")]
pub mod decision;
#[cfg(feature = "models")]
mod descriptor;
#[cfg(feature = "models")]
pub mod flux;
pub mod gguf;
#[cfg(feature = "models")]
mod package;
#[cfg(feature = "models")]
mod program;
#[cfg(feature = "models")]
pub use catena_lang::codegen::GpuDialect;

/// Program renderers: catena-models' program assembly for each GPU target,
/// registered under the evaluator id its programs name.
#[cfg(feature = "models")]
fn renderers() -> impl Iterator<Item = (String, GpuDialect)> {
    let catena = hellas_rpc::protocol::invocation::compute::EVALUATOR;
    [(GpuDialect::Hip, "hip"), (GpuDialect::Cuda, "cuda")]
        .map(|(dialect, name)| (format!("{catena}-{name}"), dialect))
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

#[cfg(feature = "models")]
pub fn pinned_gguf(uri: &str) -> anyhow::Result<hellas_store::hf::PinnedFile> {
    Ok(hellas_store::hf::PinnedFile::resolve(
        uri,
        "gguf",
        &hellas_store::content::Reservations::ram(
            hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
        ),
    )?)
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
        let mut local = Vec::new();
        let mut hub = Vec::new();
        for model in models {
            if let Some(uri) = hf_uri(&model) {
                let uri = uri.to_owned();
                hub.push(tokio::task::spawn_blocking(move || pinned_gguf(&uri)).await??);
            } else {
                ModelPackage::require_local_weights(&model)?;
                local.push(model);
            }
        }
        Ok(Self { local, hub })
    }
}
