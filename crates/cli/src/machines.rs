//! Client-side allocation. A provisioned machine is administered as a normal node.
use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct MachinesArgs {
    #[arg(long, global = true)]
    provider: String,
    /// Existing HTTP secret-source configuration: explicit env, file or refresh.
    #[arg(long, global = true)]
    credential_source: PathBuf,
    #[arg(long, global = true)]
    provider_config: Option<PathBuf>,
    #[command(subcommand)]
    command: MachineCommand,
}
#[derive(clap::Subcommand)]
enum MachineCommand {
    Create { #[arg(long)] spec: PathBuf },
    List,
    Destroy { id: String },
}
pub async fn run(args: MachinesArgs) -> Result<()> {
    let credential = serde_json::from_slice(&hellas_private::read_bounded_regular_file(
        &args.credential_source, 64 * 1024,
    )?).context("invalid provider credential source")?;
    let config = args.provider_config.map(|path| -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&hellas_private::read_bounded_regular_file(&path, 64 * 1024)?)?)
    }).transpose()?.unwrap_or_else(|| serde_json::json!({}));
    let provider = hellas_cloud::open(&args.provider, credential, config)?;
    match args.command {
        MachineCommand::Create { spec } => {
            let spec = serde_json::from_slice(&hellas_private::read_bounded_regular_file(&spec, 64 * 1024)?)?;
            println!("{}", serde_json::to_string(&provider.create(&spec).await?)?);
        }
        MachineCommand::List => println!("{}", serde_json::to_string(&provider.list().await?)?),
        MachineCommand::Destroy { id } => provider.destroy(&id).await?,
    }
    Ok(())
}
