//! Explicit caller-owner approval, separate from request execution and offers.
use clap::{Args, Subcommand};
use hellas_sdk::trust_policy::{TrustPolicy, TrustPolicyStore};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Caller-owned private trust directory.
    #[arg(long)]
    store: PathBuf,
    #[command(subcommand)]
    command: TrustCommand,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// Approve pins from a locally reviewed policy file. Zero creates a policy.
    Approve {
        id: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        reason: String,
    },
    /// Inspect the current pins and latest approval record.
    Show { id: String },
}

pub fn run(args: TrustArgs) -> super::CliResult<()> {
    let store = TrustPolicyStore::new(args.store);
    let record = match args.command {
        TrustCommand::Approve {
            id,
            expected_revision,
            policy,
            reason,
        } => {
            let bytes = hellas_private::read_bounded_regular_file(&policy, 64 * 1024)?;
            let policy: TrustPolicy = serde_json::from_slice(&bytes)?;
            store.approve(&id, expected_revision, policy, reason)?
        }
        TrustCommand::Show { id } => store.load(&id)?,
    };
    println!("{}", serde_json::to_string_pretty(&record)?);
    Ok(())
}
