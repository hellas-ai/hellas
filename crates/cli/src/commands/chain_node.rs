//! Process-owned chain storage for commands that perform paid work.
use std::{num::NonZeroU64, path::PathBuf};

#[derive(Clone, Debug, Default, clap::Args)]
pub struct ChainNodeArgs {
    /// Executed state and block archive (default: ~/.hellas/chain/<network>).
    #[arg(long, value_name = "DIR")]
    chain_store_dir: Option<PathBuf>,
    /// Keep this many executed blocks; omit to serve the complete chain archive.
    #[arg(long, value_name = "N")]
    chain_archive_blocks: Option<NonZeroU64>,
}

impl ChainNodeArgs {
    pub async fn start(
        &self,
        config: &hellas_sdk::work_config::WorkConfig,
    ) -> anyhow::Result<hellas_sdk::FullNode> {
        let directory = self.chain_store_dir.clone().map(Ok).unwrap_or_else(|| {
            crate::identity::default_chain_path(config.chain.network.as_str())
        })?;
        eprintln!(
            "Synchronizing {} chain state in {}",
            config.chain.network,
            directory.display()
        );
        let started = std::time::Instant::now();
        let startup =
            hellas_sdk::FullNode::start(config.node_config(directory, self.chain_archive_blocks)?);
        tokio::pin!(startup);
        let mut progress = tokio::time::interval(std::time::Duration::from_secs(15));
        progress.tick().await;
        let node = loop {
            tokio::select! {
                result = &mut startup => break result?,
                _ = progress.tick() => eprintln!("Waiting for verified chain state ({}s elapsed)", started.elapsed().as_secs()),
            }
        };
        eprintln!("Chain state ready after {}s", started.elapsed().as_secs());
        Ok(node)
    }
}
