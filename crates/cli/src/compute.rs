//! Node content configuration carrier and GPU session configuration.
use crate::{commands::CliResult, parsers::*};
use clap::Args;
use hellas_executor::{ExecutorSpawnConfig, GpuConfig, GpuDialect};
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
