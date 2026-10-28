//! Provider content indexing and GPU session configuration.
use crate::{commands::CliResult, parsers::*};
use anyhow::Context as _;
use clap::Args;
use hellas_executor::{ExecutorSpawnConfig, GpuConfig, GpuDialect};
use hellas_store::ContentStore;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub(crate) struct ServeArgs {
    /// Content store state (default: HELLAS_STORE_DIR or ~/.hellas/store).
    #[arg(long)]
    pub(crate) store_dir: Option<PathBuf>,
    /// Local file that may satisfy a submitted source or asset reference.
    #[arg(long = "content", value_name = "PATH")]
    pub(crate) content_paths: Vec<PathBuf>,
    /// Local directory tree to adopt without downloading content.
    #[arg(long = "content-root", value_name = "DIR")]
    pub(crate) content_roots: Vec<PathBuf>,
    /// Fast-resume index for local content.
    #[arg(long = "content-index", value_name = "FILE")]
    pub(crate) content_index: Option<PathBuf>,
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
    pub(crate) fn configure(self, executor: &mut ExecutorSpawnConfig) -> CliResult<()> {
        executor.gpu_config = GpuConfig {
            backend: self.gpu_backend,
            session_programs: self.gpu_session_programs,
            session_asset_bytes: self.gpu_session_asset_bytes,
        };
        let index = self
            .content_index
            .or_else(|| {
                self.store_dir
                    .as_deref()
                    .map(hellas_store::state::records_path_at)
            })
            .or_else(hellas_store::state::records_path)
            .ok_or_else(|| {
                anyhow::anyhow!("no store location; set HELLAS_STORE_DIR or --store-dir")
            })?;
        executor.content_store = index_content(&self.content_paths, &self.content_roots, &index)?;
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

pub fn index_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: &Path,
) -> CliResult<ContentStore> {
    populate_content(paths, roots, Some(index_path), false)
}

fn populate_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: Option<&Path>,
    recheck: bool,
) -> CliResult<ContentStore> {
    let store = ContentStore::new();
    let remembered = if recheck {
        0
    } else {
        index_path.map_or(0, |path| store.records().load(path))
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
    if let Some(index_path) = index_path {
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
