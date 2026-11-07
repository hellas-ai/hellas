//! Provider content indexing and GPU session configuration.
use crate::{commands::CliResult, parsers::*};
use anyhow::Context as _;
use clap::Args;
use hellas_executor::{ExecutorSpawnConfig, GpuConfig, GpuDialect};
use hellas_store::ContentStore;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub(crate) struct ServeArgs {
    /// Local file that may satisfy a submitted source or asset reference.
    #[arg(long = "content", value_name = "PATH")]
    pub(crate) content_paths: Vec<PathBuf>,
    /// Local directory tree to adopt without downloading content.
    #[arg(long = "content-root", value_name = "DIR")]
    pub(crate) content_roots: Vec<PathBuf>,
    /// Refuse unindexed or changed content instead of hashing at startup.
    /// Prepare files with `store index`; directory adoption is not supported.
    #[arg(long, conflicts_with = "content_roots")]
    pub(crate) require_content_index: bool,
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
        home: &Path,
    ) -> CliResult<()> {
        executor.gpu_config = GpuConfig {
            backend: self.gpu_backend,
            session_programs: self.gpu_session_programs,
            session_asset_bytes: self.gpu_session_asset_bytes,
        };
        let index = hellas_store::state::records_path_in(home);
        let mode = if self.require_content_index {
            IndexMode::Require
        } else {
            IndexMode::Resume
        };
        executor.content_store =
            index_content(&self.content_paths, &self.content_roots, &index, mode)?;
        Ok(())
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
    Require,
}

pub(crate) fn index_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: &Path,
    mode: IndexMode,
) -> CliResult<ContentStore> {
    anyhow::ensure!(
        roots.is_empty() || !matches!(mode, IndexMode::Require),
        "required content indexes support explicit files only"
    );
    let store = ContentStore::new();
    let remembered = if matches!(mode, IndexMode::Recheck) {
        0
    } else {
        store.records().load(index_path)
    };
    for path in paths {
        match mode {
            IndexMode::Require => store.index_remembered(path),
            _ => store.index(path),
        }
        .with_context(|| format!("failed to index local content {}", path.display()))?;
    }
    let mut adopted = 0usize;
    for root in roots {
        adopted += store
            .adopt(root)
            .with_context(|| format!("failed to adopt local content root {}", root.display()))?
            .len();
    }
    if !matches!(mode, IndexMode::Require) {
        store
            .records()
            .save(index_path)
            .with_context(|| format!("failed to save content index {}", index_path.display()))?;
    }
    info!(
        remembered,
        indexed = store.len(),
        adopted,
        "indexed local content"
    );
    Ok(store)
}
