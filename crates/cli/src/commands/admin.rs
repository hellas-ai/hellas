//! Checked node administration. Online commands always use an explicit app profile.
use std::path::PathBuf;
mod node;
pub use node::run;

#[derive(clap::Args)]
pub struct AdminArgs {
    /// Private application credential and independently provisioned server trust.
    #[arg(long, global = true)]
    pub profile: Option<PathBuf>,
    /// Local node socket; defaults to this identity's control.sock.
    #[arg(long, global = true, conflicts_with_all = ["node_contact", "addresses"])]
    pub control_socket: Option<PathBuf>,
    /// Independently verified contact pinning the remote node's transport key.
    #[arg(long = "contact", global = true)]
    pub node_contact: Option<PathBuf>,
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

#[derive(clap::Args)]
pub struct OfflineArgs {
    /// Exclusively locked node store; the daemon must be stopped.
    #[arg(long)]
    pub journal: PathBuf,
    /// JSON GrantSpec for the administrator's exact rights and issuance ceiling.
    #[arg(long)]
    pub administrator: PathBuf,
    /// JSON GrantSpec bounding the initial application credential.
    #[arg(long)]
    pub credential_scope: PathBuf,
    /// New private credential file, published only after durable initialization.
    #[arg(long)]
    pub credential_out: PathBuf,
}

#[derive(clap::Subcommand)]
pub enum AdminCommand {
    /// Read private node status using the profile's selected grant.
    Status,
    /// Replace machine concurrency and budgets; revision zero initializes a provider.
    SetCapacity {
        #[arg(long)]
        expected_revision: u64,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
        max_in_flight: u16,
        /// JSON array of Work limits. Use [] explicitly for no budget limits.
        #[arg(long)]
        limits: PathBuf,
    },
    /// Bind the provider enrollment of an authority bootstrapped without one.
    BindProvider {
        /// Canonical provider enrollment bytes.
        #[arg(long)]
        enrollment: PathBuf,
    },
    /// Apply a typed JSON authority GrantCommand, including its explicit authorization.
    Grant { command: PathBuf },
    /// Issue an application credential, bounded by a JSON GrantSpec.
    IssueCredential {
        #[arg(long)]
        scope: PathBuf,
        /// New private output file; the secret is never printed.
        #[arg(long)]
        credential_out: PathBuf,
    },
    /// Revoke an application credential and its live authenticated sessions.
    RevokeCredential {
        #[arg(long)]
        credential_id: String,
        #[arg(long)]
        expected_revision: u64,
    },
    /// Apply a typed JSON WorkControlCommand using the profile's selected grant.
    Work {
        command: PathBuf,
        /// Export one selected offer in the format accepted by `offer import`.
        #[arg(long)]
        offer_out: Option<PathBuf>,
    },
    /// Export one allowance's offer with a new contact credential as an access bundle.
    ExportBundle {
        /// Allowance whose offer the contact imports.
        #[arg(long)]
        allowance: String,
        /// The contact's Auth grant for work.execute on that allowance.
        #[arg(long)]
        grant_id: String,
        /// JSON GrantSpec bounding the contact's credential.
        #[arg(long)]
        credential_scope: PathBuf,
        /// Provider display name shown to the contact.
        #[arg(long)]
        label: Option<String>,
        /// New private output file; the secret is never printed.
        #[arg(long)]
        out: PathBuf,
    },
    /// Initialize an empty node store and issue the first application credential.
    Bootstrap {
        #[arg(long)]
        root_grant: String,
        #[command(flatten)]
        state: OfflineArgs,
    },
    /// Replace lost administration offline; invalidate prior credentials and sessions.
    Recover {
        #[arg(long)]
        expected_revision: u64,
        #[command(flatten)]
        state: OfflineArgs,
    },
    #[cfg(unix)]
    /// Serve the machine management application endpoint.
    Serve {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}
