use std::path::PathBuf;

#[cfg(feature = "node")]
pub mod users;

#[derive(clap::Args)]
pub struct AdminArgs {
    #[cfg(feature = "node")]
    /// Local node control socket (default: this identity's control.sock).
    #[arg(long, global = true, conflicts_with_all = ["node_contact", "addresses"])]
    pub control_socket: Option<PathBuf>,
    #[cfg(feature = "node")]
    /// Verified node contact whose transport key pins the remote control service.
    #[arg(long = "contact", global = true)]
    pub node_contact: Option<PathBuf>,
    #[cfg(feature = "node")]
    /// Direct UDP address for the remote node; repeat or use commas.
    #[arg(
        long = "address",
        global = true,
        value_delimiter = ',',
        requires = "node_contact"
    )]
    pub addresses: Vec<std::net::SocketAddr>,
    #[command(subcommand)]
    pub command: AdminCommand,
}
#[derive(clap::Subcommand)]
pub enum AdminCommand {
    #[cfg(feature = "node")]
    /// Inspect and edit this node's journaled users and permissions.
    Users(users::UserArgs),
    #[cfg(feature = "node")]
    /// Clear an upstream accounting quarantine after correcting its cause.
    RepairResource {
        /// Configured resource policy name.
        policy: String,
    },
    #[cfg(all(feature = "cloud", unix))]
    /// Serve private management RPC for local applications.
    Serve {
        /// Application management socket (default: this owner's local management socket).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}
