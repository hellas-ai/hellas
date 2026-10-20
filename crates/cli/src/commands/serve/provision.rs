//! CLI presentation for SDK bond provisioning.
use super::super::CliResult;
pub use hellas_sdk::work_provision::ProvisionOptions;
use hellas_sdk::work_provision::{preview_bond, provision_offer};
use hellas_work::model::grant::records::grant_transport;

pub async fn run_provision(
    options: ProvisionOptions,
    print_bond_only: bool,
    chain: super::super::chain_node::ChainNodeArgs,
    authority: hellas_work::node::NodeCoordinator,
) -> CliResult<()> {
    if print_bond_only {
        println!(
            "bond_edge: {}",
            hex::encode(preview_bond(&options, &authority).await?.to_bytes())
        );
        return Ok(());
    }
    let root = options.work_config.journal_root.clone();
    let node = chain.start(&options.work_config).await?;
    let result = provision_offer(options, &node, &authority).await;
    node.shutdown().await?;
    let made = result?;
    println!(
        "offer journaled: bond {} under {}",
        hex::encode(made.bond_edge.to_bytes()),
        root.display()
    );
    println!(
        "history floor: finalized height {} with payload {}",
        made.floor.height,
        hex::encode(made.floor.payload)
    );
    println!(
        "provider enrollment: {}",
        made.offer.offer().provider.content_id()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "provider": grant_transport(&made.offer.offer().provider).map(hex::encode)?,
            "offer": made.offer,
            "bond": hex::encode(made.bond_edge.to_bytes()),
        }))?
    );
    Ok(())
}
