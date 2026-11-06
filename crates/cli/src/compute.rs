//! Provider content indexing and GPU session configuration.
use crate::{commands::CliResult, parsers::*};
use anyhow::Context as _;
use clap::Args;
use hellas_executor::{ExecutorSpawnConfig, GpuConfig, GpuDialect};
use hellas_store::ContentStore;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub(crate) struct ServeArgs {
    /// Node content configuration containing [content].
    #[arg(long, value_name = "FILE")]
    pub(crate) content_config: Option<PathBuf>,
    #[arg(skip)]
    pub(crate) audio_content: Option<(PathBuf, hellas_rpc::ContentRef)>,
    /// GPU runtime: auto, hip, or cuda.
    #[arg(long = "gpu-backend", default_value = "auto", value_parser = parse_gpu_backend)]
    pub(crate) gpu_backend: GpuDialect,
    /// Maximum programs retained in a GPU worker session.
    #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = parse_positive_usize)]
    pub(crate) gpu_session_programs: usize,
    /// Maximum static asset bytes retained across GPU jobs.
    #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = parse_positive_u64)]
    pub(crate) gpu_session_asset_bytes: u64,
}
impl ServeArgs {
    pub(crate) fn configure(
        self,
        executor: &mut ExecutorSpawnConfig,
    ) -> CliResult<crate::content_configuration::ContentConfiguration> {
        executor.gpu_config = GpuConfig {
            backend: self.gpu_backend,
            session_programs: self.gpu_session_programs,
            session_asset_bytes: self.gpu_session_asset_bytes,
        };
        crate::content_configuration::ContentConfiguration::load(
            self.content_config,
            self.audio_content,
        )
    }
}
fn parse_gpu_backend(value: &str) -> Result<GpuDialect, String> {
    match value {
        "hip" => Ok(GpuDialect::Hip),
        "cuda" => Ok(GpuDialect::Cuda),
        "auto" if Path::new("/dev/nvidiactl").exists() => Ok(GpuDialect::Cuda),
        "auto" => Ok(GpuDialect::Hip),
        _ => Err("GPU runtime must be auto, hip, or cuda".into()),
    }
}

pub(crate) enum IndexMode {
    Resume,
    Recheck,
}

pub(crate) fn index_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: &Path,
    mode: IndexMode,
) -> CliResult<ContentStore> {
    let store = ContentStore::new();
    let remembered = if matches!(mode, IndexMode::Recheck) {
        0
    } else {
        store.records().load(index_path)
    };
    for path in paths {
        store
            .index(path)
            .with_context(|| format!("failed to index local content {}", path.display()))?;
    }
    let mut adopted = 0usize;
    for root in roots {
        adopted += store
            .adopt(root)
            .with_context(|| format!("failed to adopt local content root {}", root.display()))?
            .len();
    }
    store
        .records()
        .save(index_path)
        .with_context(|| format!("failed to save content index {}", index_path.display()))?;
    info!(
        remembered,
        indexed = store.len(),
        adopted,
        "indexed local content"
    );
    Ok(store)
}
