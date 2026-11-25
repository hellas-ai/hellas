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
    /// Evaluator id a local GPU runtime registers; omitted selects the native
    /// runtime.
    #[arg(long = "evaluator")]
    pub(crate) evaluator: Option<String>,
    /// Maximum programs retained in a GPU worker session.
    #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = crate::parsers::parse_positive_usize)]
    pub(crate) gpu_session_programs: usize,
    /// Maximum static asset bytes retained across GPU jobs.
    #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = crate::parsers::parse_positive_u64)]
    pub(crate) gpu_session_asset_bytes: u64,
}

#[cfg(feature = "compute")]
impl GpuArgs {
    pub(crate) fn config(&self) -> CliResult<hellas_executor::GpuConfig> {
        Ok(hellas_executor::GpuConfig {
            gpu: hellas_executor::catena::Gpu::select(self.evaluator.as_deref())
                .map_err(anyhow::Error::msg)?,
            session_programs: self.gpu_session_programs,
            session_asset_bytes: self.gpu_session_asset_bytes,
        })
    }
}

#[cfg(feature = "compute")]
pub(crate) async fn content(
    home: &hellas_private::StoreLocation,
    native: &LocalArgs,
    local: &[PathBuf],
    hub: &[hellas_store::hf::PinnedFile],
) -> CliResult<hellas_store::content::DiskStore> {
    let mut configuration = crate::content_configuration::load(native.content_config.clone())?;
    configuration
        .upper
        .get_or_insert_with(|| home.join("provider/content"));
    let paths = native
        .content
        .iter()
        .chain(local)
        .map(std::path::absolute)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut initial = configuration.clone();
    initial.lower.extend(paths.iter().cloned());
    let content = initial
        .open(
            home,
            hellas_store::content::Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ),
            true,
        )
        .await?;
    let prepared: CliResult<()> = async {
        content.finish_recovery().await?;
        crate::content_configuration::add_content(&mut configuration, &content, paths).await?;
        hellas_store::content::config::Reconciler::new(configuration.clone())?
            .apply(&content, configuration)
            .await?;
        for file in hub {
            file.acquire(&content).await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = prepared {
        content.close().await;
        return Err(error);
    }
    Ok(content)
}

#[cfg(all(test, feature = "compute"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_content_preserves_require_index_mode_for_explicit_weights() {
        let root = tempfile::tempdir().unwrap();
        let weights = root.path().join("weights");
        std::fs::write(&weights, b"unindexed weights").unwrap();
        let configuration = root.path().join("content.toml");
        std::fs::write(&configuration, "[content]\nindex = \"require\"\n").unwrap();
        let native = LocalArgs {
            content_config: Some(configuration),
            content: vec![],
            gpu: GpuArgs {
                evaluator: None,
                gpu_session_programs: 1,
                gpu_session_asset_bytes: 1024,
            },
        };
        let result = content(
            &hellas_private::StoreLocation::for_test(root.path()),
            &native,
            &[weights],
            &[],
        )
        .await;
        match result {
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("lower file requires an index record"),
                "{error:#}"
            ),
            Ok(store) => {
                store.close().await;
                panic!("require mode must not hash previously unindexed weights");
            }
        }
    }
}
