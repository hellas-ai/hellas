//! Checked node administration. Online commands always use an explicit app profile.
use std::path::PathBuf;
mod node;
pub use node::{inspect_offline, run};

#[derive(clap::Args)]
pub struct AdminArgs {
    /// Private application credential and independently provisioned server trust.
    #[arg(long, global = true)]
    pub profile: Option<PathBuf>,
    /// Local node socket; defaults to this identity's control.sock.
    #[arg(long, global = true, conflicts_with_all = ["node_enrollment", "addresses"])]
    pub control_socket: Option<PathBuf>,
    /// The remote node's enrollment file or exact transport pin, verified out of band.
    #[arg(long = "node", global = true)]
    pub node_enrollment: Option<String>,
    #[arg(
        long = "address",
        global = true,
        value_delimiter = ',',
        requires = "node_enrollment"
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
    /// JSON CredentialHolder naming the node key of the device that will
    /// hold the initial credential.
    #[arg(long)]
    pub holder: PathBuf,
    /// New private credential file, published only after durable initialization.
    #[arg(long)]
    pub credential_out: PathBuf,
}

#[derive(clap::Subcommand)]
pub enum AdminCommand {
    /// Inspect one record or one bounded metadata page using a JSON InspectionQuery.
    Inspect { command: PathBuf },
    /// Read administration metadata while the daemon is stopped. No passkey needed.
    InspectOffline {
        #[arg(long)]
        journal: PathBuf,
        command: PathBuf,
    },
    /// Read private node status using the profile's selected grant.
    Status,
    /// Apply a typed upstream update; endpoint changes and key replacement/removal require --passkey.
    ConfigureProvider { command: PathBuf },
    /// Start or stop the provider through the normal host lifecycle.
    SetProviderState {
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
    },
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
        /// JSON CredentialHolder: the holding device's node key, or a bearer.
        #[arg(long)]
        holder: PathBuf,
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
    /// Share allowances with a contact: their offers and one new credential,
    /// bound to the contact's device, as an access bundle.
    ExportBundle {
        /// An allowance whose offer the contact imports; repeat for each one.
        #[arg(long = "allowance", required = true)]
        allowances: Vec<String>,
        /// The contact's Auth grant: work.execute on every shared allowance.
        #[arg(long)]
        grant_id: String,
        /// JSON GrantSpec bounding the contact's credential.
        #[arg(long)]
        credential_scope: PathBuf,
        /// JSON CredentialHolder naming the contact device's node key.
        #[arg(long)]
        holder: PathBuf,
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
        /// JSON GrantSpec for a bearer credential (`gateway.invoke` only),
        /// issued by the administrator's passkey session on the new
        /// authority; local HTTP clients present it.
        #[arg(long, requires = "bearer_out")]
        bearer_scope: Option<PathBuf>,
        /// New private file for that bearer credential.
        #[arg(long, requires = "bearer_scope")]
        bearer_out: Option<PathBuf>,
    },
    /// Bootstrap a fresh node using the pairing document from its authenticated console.
    BootstrapRemote {
        #[arg(long)]
        invitation: PathBuf,
        #[arg(long)]
        root_grant: String,
        #[arg(long)]
        administrator: PathBuf,
        #[arg(long)]
        credential_scope: PathBuf,
        /// New private directory for the retained credential and remote profile.
        #[arg(long)]
        profile_out: PathBuf,
    },
    /// Replace lost administration offline; invalidate prior credentials and sessions.
    Recover {
        #[arg(long)]
        expected_revision: u64,
        #[command(flatten)]
        state: OfflineArgs,
    },
}
