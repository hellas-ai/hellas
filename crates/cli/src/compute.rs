//! Node content configuration carrier and, with `compute`, GPU session configuration.
#[cfg(feature = "compute")]
use crate::commands::CliResult;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub(crate) struct LocalArgs {
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
    /// Registered local evaluator id; omitted selects the native executor.
    #[arg(long = "evaluator", value_parser = hellas_executor::catena::registered_evaluator)]
    pub(crate) evaluator: Option<hellas_executor::GpuDialect>,
    /// Maximum programs retained in a GPU worker session.
    #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = crate::parsers::parse_positive_usize)]
    pub(crate) gpu_session_programs: usize,
    /// Maximum static asset bytes retained across GPU jobs.
    #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = crate::parsers::parse_positive_u64)]
    pub(crate) gpu_session_asset_bytes: u64,
}

/// One-shot local execution uses the same native constructor as the daemon.
#[cfg(feature = "compute")]
pub(crate) async fn local(
    home: &hellas_private::StoreLocation,
    native: LocalArgs,
    signer: std::sync::Arc<hellas_auth::ProducerSigningKey>,
) -> CliResult<hellas_sdk::execution::local::LocalExecution> {
    let configuration = crate::content_configuration::ContentConfiguration::load(
        native.content_config,
        native.content,
    )?
    .with_default_upper(home.join("provider/content"));
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
    let prepared = async {
        content.finish_recovery().await?;
        configuration.apply(&content).await?;
        let backend = hellas_sdk::execution::local::spawn(
            signer,
            hellas_executor::GpuConfig {
                backend: native
                    .gpu
                    .evaluator
                    .unwrap_or_else(hellas_executor::catena::default_gpu),
                session_programs: native.gpu.gpu_session_programs,
                session_asset_bytes: native.gpu.gpu_session_asset_bytes,
            },
        )
        .await?;
        Ok::<_, anyhow::Error>(hellas_sdk::execution::local::LocalExecution {
            backend,
            content: content.clone(),
        })
    }
    .await;
    if prepared.is_err() {
        content.close().await;
    }
    prepared
}
