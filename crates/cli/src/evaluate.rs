//! Optional local evaluator: CLI arguments and executor preparation.

use crate::{CausalLmArgs, commands::grant_gateway::local::LocalContent, parsers::*};
use clap::Args;
use hellas_executor::{ExecutorSpawnConfig, GpuConfig};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Args)]
pub(crate) struct ServeArgs {
    /// Content store state used by local execution (default: HELLAS_STORE_DIR or ~/.hellas/store).
    #[arg(long)]
    pub(crate) store_dir: Option<PathBuf>,
    /// Local files that may satisfy content references in submitted
    /// canonical causal-LM environments. Repeat for programs/assets.
    #[arg(long = "content", value_name = "PATH")]
    pub(crate) content_paths: Vec<PathBuf>,
    /// Directory tree to adopt into the local content store. Repeat for
    /// HuggingFace/Xet cache roots; no remote fetch is performed.
    #[arg(long = "content-root", value_name = "DIR")]
    pub(crate) content_roots: Vec<PathBuf>,
    /// Fast-resume index for local content (default: ~/.hellas/content-index.bin).
    #[arg(long = "content-index", value_name = "FILE")]
    pub(crate) content_index: Option<PathBuf>,
    /// GPU runtime to use: auto, hip, or cuda.
    #[arg(long = "gpu-backend", default_value_t = hellas_executor::GpuBackend::Auto)]
    pub(crate) gpu_backend: hellas_executor::GpuBackend,
    /// Maximum distinct Catena programs retained in one GPU session.
    #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = parse_positive_usize)]
    pub(crate) gpu_session_programs: usize,
    /// Maximum aggregate static asset bytes retained in one GPU session.
    #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = parse_positive_u64)]
    pub(crate) gpu_session_asset_bytes: u64,
    /// Maximum prompt-plus-output capacity of one GPU generation (at most
    /// 524288 so retained token output fits the artifact transport).
    #[arg(long = "gpu-max-generation-capacity", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_CAPACITY, value_parser = parse_gpu_generation_capacity)]
    pub(crate) gpu_max_generation_capacity: u64,
    /// Maximum non-asset device bytes owned or allocated by one GPU generation.
    #[arg(long = "gpu-max-generation-device-bytes", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES, value_parser = parse_positive_u64)]
    pub(crate) gpu_max_generation_device_bytes: u64,
    /// Maximum seconds spent loading and compiling one Catena program.
    #[arg(long = "gpu-compile-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_COMPILE_TIMEOUT_SECS, value_parser = parse_positive_u64)]
    pub(crate) gpu_compile_timeout_secs: u64,
    /// Maximum seconds for one GPU control operation or full generation.
    #[arg(long = "gpu-execution-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_EXECUTION_TIMEOUT_SECS, value_parser = parse_positive_u64)]
    pub(crate) gpu_execution_timeout_secs: u64,
}

impl ServeArgs {
    pub(crate) fn configure(self, executor: &mut ExecutorSpawnConfig) -> anyhow::Result<()> {
        let gpu_config = GpuConfig::new(
            self.gpu_session_programs,
            self.gpu_session_asset_bytes,
            self.gpu_max_generation_capacity,
            self.gpu_max_generation_device_bytes,
            Duration::from_secs(self.gpu_compile_timeout_secs),
            Duration::from_secs(self.gpu_execution_timeout_secs),
        )
        .map_err(anyhow::Error::msg)?
        .with_backend(self.gpu_backend);
        let index = self
            .content_index
            .or_else(|| {
                self.store_dir
                    .as_deref()
                    .map(hellas_store::state::records_path_at)
            })
            .map(Ok)
            .unwrap_or_else(crate::identity::default_content_index_path)?;
        executor.content_store = crate::commands::environment::index_content(
            &self.content_paths,
            &self.content_roots,
            &index,
        )?;
        executor.gpu_config = gpu_config;
        Ok(())
    }
}

#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("causal_lm_local_content")
        .args(["content_paths", "content_roots"])
        .multiple(true)
))]
pub(crate) struct GatewayArgs {
    /// Execute locally through an explicitly configured allowance
    #[arg(
        long = "local",
        default_value_t = false,
        conflicts_with_all = ["node_id", "node_addrs", "offer", "paid_work_config"],
        requires_all = ["causal_lm_local_content", "environment", "local_grant"]
    )]
    #[cfg_attr(unix, arg(conflicts_with = "machine"))]
    pub(crate) local: bool,
    /// Existing local allowance ID; startup never creates or revises permissions.
    #[arg(long = "local-grant", requires = "local")]
    pub(crate) local_grant: Option<String>,
    /// Maximum number of queued local executions when `--local` is set
    #[arg(
        long = "queue-size",
        default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
    )]
    pub(crate) queue_size: usize,

    /// Local files that satisfy exact program/static content references.
    /// Repeat for multiple objects; used only by local execution legs.
    #[arg(long = "content", value_name = "PATH", requires = "local")]
    pub(crate) content_paths: Vec<PathBuf>,

    /// Directory trees to adopt as local content. No network fetch or
    /// compilation occurs; used only by local execution legs.
    #[arg(long = "content-root", value_name = "DIR", requires = "local")]
    pub(crate) content_roots: Vec<PathBuf>,

    /// Fast-resume content index (default: Hellas store state).
    #[arg(long = "content-index", value_name = "FILE", requires = "local")]
    pub(crate) content_index: Option<PathBuf>,
}

impl GatewayArgs {
    pub(crate) fn content(&self, args: &CausalLmArgs, store_dir: Option<&Path>) -> LocalContent {
        LocalContent {
            grant: self.local_grant.clone(),
            paths: std::iter::once(args.environment.clone())
                .chain(self.content_paths.iter().cloned())
                .collect(),
            roots: self.content_roots.clone(),
            index: self
                .content_index
                .clone()
                .or_else(|| store_dir.map(hellas_store::state::records_path_at)),
            queue_size: self.queue_size,
        }
    }
}

fn parse_gpu_generation_capacity(s: &str) -> Result<u64, String> {
    let value = parse_positive_u64(s)?;
    (value <= hellas_executor::MAX_GPU_GENERATION_CAPACITY)
        .then_some(value)
        .ok_or_else(|| {
            format!(
                "value must not exceed {}",
                hellas_executor::MAX_GPU_GENERATION_CAPACITY
            )
        })
}
