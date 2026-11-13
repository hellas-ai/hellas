//! Node content configuration carrier and, with `compute`, GPU session configuration.
use crate::commands::CliResult;
use clap::Args;
use hellas_executor::ExecutorSpawnConfig;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub(crate) struct ServeArgs {
    /// Node content configuration containing [content].
    #[arg(long, value_name = "FILE")]
    pub(crate) content_config: Option<PathBuf>,
    /// Serve the file at PATH, or every file in the directory at PATH (such
    /// as a converted model package), to jobs that name it; repeat for each.
    #[arg(long = "content", value_name = "PATH")]
    pub(crate) content: Vec<PathBuf>,
    #[cfg(feature = "compute")]
    #[command(flatten)]
    pub(crate) gpu: GpuArgs,
}

#[cfg(feature = "compute")]
#[derive(Args, Debug)]
pub(crate) struct GpuArgs {
    /// GPU runtime: auto, hip, or cuda.
    #[arg(long = "gpu-backend", default_value = "auto", value_parser = parse_gpu_backend)]
    pub(crate) gpu_backend: hellas_executor::GpuDialect,
    /// Maximum programs retained in a GPU worker session.
    #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = crate::parsers::parse_positive_usize)]
    pub(crate) gpu_session_programs: usize,
    /// Maximum static asset bytes retained across GPU jobs.
    #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = crate::parsers::parse_positive_u64)]
    pub(crate) gpu_session_asset_bytes: u64,
}

impl ServeArgs {
    pub(crate) fn configure(
        self,
        executor: &mut ExecutorSpawnConfig,
    ) -> CliResult<crate::content_configuration::ContentConfiguration> {
        #[cfg(feature = "compute")]
        {
            executor.gpu_config = hellas_executor::GpuConfig {
                backend: self.gpu.gpu_backend,
                session_programs: self.gpu.gpu_session_programs,
                session_asset_bytes: self.gpu.gpu_session_asset_bytes,
            };
        }
        #[cfg(not(feature = "compute"))]
        let _ = executor;
        crate::content_configuration::ContentConfiguration::load(self.content_config, self.content)
    }
}

#[cfg(feature = "compute")]
pub(crate) fn parse_gpu_backend(value: &str) -> Result<hellas_executor::GpuDialect, String> {
    use hellas_executor::GpuDialect;
    match value {
        "hip" => Ok(GpuDialect::Hip),
        "cuda" => Ok(GpuDialect::Cuda),
        "auto" if std::path::Path::new("/dev/nvidiactl").exists() => Ok(GpuDialect::Cuda),
        "auto" => Ok(GpuDialect::Hip),
        _ => Err("GPU runtime must be auto, hip, or cuda".into()),
    }
}

/// This machine's executor, signing as `signer`, over the node content store
/// the configuration declares. The caller stops the reload, then closes the
/// content, after the work that reads it.
#[cfg(feature = "compute")]
pub(crate) async fn local(
    home: &hellas_private::StoreLocation,
    native: ServeArgs,
    signer: std::sync::Arc<hellas_auth::ProducerSigningKey>,
) -> CliResult<(
    hellas_sdk::execution::local::LocalExecution,
    crate::content_configuration::ContentReload,
)> {
    let mut executor =
        ExecutorSpawnConfig::new(signer, hellas_executor::FetchRouteRegistry::default());
    let (content, reload) = prepare_content(home, native, &mut executor).await?;
    let backend = match hellas_executor::Executor::spawn_configured(executor).await {
        Ok(backend) => backend,
        Err(error) => {
            reload.shutdown().await?;
            content.close().await;
            return Err(anyhow::Error::from(error).context("start local Work executor"));
        }
    };
    Ok((
        hellas_sdk::execution::local::LocalExecution { backend, content },
        reload,
    ))
}

#[cfg(feature = "compute")]
async fn prepare_content(
    home: &hellas_private::StoreLocation,
    native: ServeArgs,
    executor: &mut ExecutorSpawnConfig,
) -> CliResult<(
    hellas_store::content::DiskStore,
    crate::content_configuration::ContentReload,
)> {
    let configuration = native.configure(executor)?.with_default_upper(
        hellas_sdk::grant_config::GrantConfig::provider_dir(home).join("content"),
    );
    let content = configuration
        .config()
        .open(
            home,
            hellas_store::content::Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ),
            true,
        )
        .await?;
    // Local jobs are ephemeral; this host has no paid channel journals.
    content.finish_recovery().await?;
    let reload = configuration.start(content.clone()).await?;
    Ok((content, reload))
}
