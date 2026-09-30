use std::path::PathBuf;

#[cfg(feature = "node")]
pub mod users;

#[derive(clap::Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}
#[derive(clap::Subcommand)]
pub enum AdminCommand {
    #[cfg(feature = "node")]
    Users(users::UserArgs),
    #[cfg(feature = "node")]
    RepairResource {
        policy: String,
        #[arg(long)]
        control_socket: Option<PathBuf>,
    },
    #[cfg(all(feature = "cloud", unix))]
    /// Serve private management RPC for local applications.
    Serve {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}
