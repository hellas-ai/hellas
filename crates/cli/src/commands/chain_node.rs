//! Process-owned chain storage for commands that perform paid work.
use std::num::NonZeroU64;

#[derive(Clone, Debug, Default, clap::Args)]
pub struct ChainNodeArgs {
    /// Keep this many executed blocks; omit to serve the complete chain archive.
    #[arg(long, value_name = "N")]
    chain_archive_blocks: Option<NonZeroU64>,
}

impl ChainNodeArgs {
    pub async fn start(
        &self,
        config: &hellas_sdk::work_config::WorkConfig,
    ) -> anyhow::Result<hellas_sdk::FullNode> {
        let directory = config.chain.node();
        eprintln!(
            "Synchronizing {} chain state in {}",
            config.network(),
            directory.display()
        );
        let started = std::time::Instant::now();
        let startup = hellas_sdk::FullNode::start(config.node_config(self.chain_archive_blocks)?);
        tokio::pin!(startup);
        #[expect(
            clippy::disallowed_methods,
            reason = "inventory class C: startup progress output"
        )]
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
