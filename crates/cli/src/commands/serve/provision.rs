//! CLI presentation for SDK bond provisioning.
use super::super::CliResult;
pub use hellas_sdk::work_provision::ProvisionOptions;
use hellas_sdk::work_provision::{preview_bond, provision_offer};

pub async fn run_provision(options: ProvisionOptions) -> CliResult<()> {
    if options.print_bond_only {
        println!(
            "bond_edge: {}",
            hex::encode(preview_bond(&options)?.to_bytes())
        );
        return Ok(());
    }
    let root = options.work_config.journal_root.clone();
    let made = provision_offer(options).await?;
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
    Ok(())
}
