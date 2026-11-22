use super::CliResult;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum ModelCommand {
    /// Keep a model's rendering metadata and weights identity, without its weights.
    Describe {
        /// Converted Whisper or MMS package.
        path: PathBuf,
        /// New descriptor directory.
        #[arg(short = 'o', long, value_name = "DIR")]
        output: PathBuf,
    },
}

pub async fn run(command: ModelCommand) -> CliResult {
    match command {
        ModelCommand::Describe { path, output } => {
            let weights = hellas_client::model::ModelPackage::describe(&path, &output).await?;
            println!(
                "weights: {} ({} bytes), {}",
                weights.id(),
                weights.bytes(),
                output.display()
            );
            Ok(())
        }
    }
}
