//! Client-side model assets.
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
pub mod whisper;

#[cfg(feature = "models")]
pub mod wav;
