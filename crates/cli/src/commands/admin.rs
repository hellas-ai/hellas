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
    /// Approve exact paid terms for a daemon whose owner key stays on this machine.
    SetPaidPolicy {
        #[arg(long)]
        terms: PathBuf,
        #[arg(long)]
        expected_revision: u64,
        /// The provider's Fetch routes, if its paid policy admits Fetch.
        #[arg(long)]
        fetch_config: Option<PathBuf>,
    },
    /// Apply a typed upstream update; endpoint changes and key replacement/removal require --passkey.
    ConfigureProvider { command: PathBuf },
    /// Start or stop the provider through the normal host lifecycle.
    SetProviderState {
        #[arg(long, action = clap::ArgAction::Set)]
        enabled: bool,
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
    /// Give a contact's principal metered access to one configured resource,
    /// as an access bundle bound to one of the contact's devices. Rerunning
    /// with the same contact and resource revises that one share.
    Share {
        /// The verified contact card naming the principal; your own card shares
        /// with yourself.
        #[arg(long)]
        contact: PathBuf,
        /// JSON CredentialHolder naming the receiving device's node key, as
        /// `hellas identity show-holder` prints it.
        #[arg(long)]
        holder: PathBuf,
        /// The configured resource name, e.g. `klein`.
        #[arg(long)]
        resource: String,
        /// A budget limit METER:WINDOW:AMOUNT, e.g. `requests:total:100`; repeat
        /// for each. Without any, only concurrency bounds the share.
        #[arg(long = "limit", value_parser = parse_limit)]
        limits: Vec<hellas_authority::model::grant::budget::Limit>,
        /// The longest one job may run, e.g. `15m`.
        #[arg(long, value_parser = crate::commands::transact::duration)]
        max_job: std::time::Duration,
        /// How long the share's grant and credential stay valid, e.g. `30d`.
        #[arg(long, default_value = "30d", value_parser = crate::commands::transact::duration)]
        expires: std::time::Duration,
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

/// `METER:WINDOW:AMOUNT`, with kebab-case meter and window names.
fn parse_limit(value: &str) -> Result<hellas_authority::model::grant::budget::Limit, String> {
    use hellas_authority::model::grant::budget::{Limit, Meter, Window};
    let [meter, window, amount] = value.split(':').collect::<Vec<_>>()[..] else {
        return Err("a limit is METER:WINDOW:AMOUNT".into());
    };
    let meter = match meter {
        "requests" => Meter::Requests,
        "input-tokens" => Meter::InputTokens,
        "output-tokens" => Meter::OutputTokens,
        "device-millis" => Meter::DeviceMillis,
        "usd-micros" => Meter::UsdMicros,
        _ => {
            return Err(
                "meter is requests, input-tokens, output-tokens, device-millis or usd-micros"
                    .into(),
            );
        }
    };
    let window = match window {
        "hour" => Window::Hour,
        "day" => Window::Day,
        "week" => Window::Week,
        "total" => Window::Total,
        _ => return Err("window is hour, day, week or total".into()),
    };
    let amount = amount
        .parse()
        .map_err(|_| "amount is a non-negative integer")?;
    Ok(Limit {
        meter,
        window,
        amount,
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn share_requires_an_explicit_contact_and_holder_and_parses_limits() {
        let base = [
            "hellas",
            "admin",
            "share",
            "--contact",
            "me.contact",
            "--holder",
            "me.holder",
            "--resource",
            "model",
            "--max-job",
            "15m",
            "--out",
            "me.access",
        ];
        assert!(crate::Cli::try_parse_from(base).is_ok());
        for missing in [3, 5] {
            assert!(
                crate::Cli::try_parse_from(
                    base.iter()
                        .enumerate()
                        .filter_map(
                            |(i, arg)| (!(missing..missing + 2).contains(&i)).then_some(*arg)
                        )
                )
                .is_err()
            );
        }
        assert!(
            crate::Cli::try_parse_from(base.into_iter().chain([
                "--expires",
                "30d",
                "--limit",
                "requests:total:100"
            ]))
            .is_ok()
        );
        for value in [
            "requests:100",
            "requests:total:-1",
            "unknown:day:1",
            "requests:month:1",
            "requests:day:1:2",
        ] {
            assert!(super::parse_limit(value).is_err(), "{value}");
        }
        let limit = super::parse_limit("output-tokens:day:1000").unwrap();
        assert_eq!(limit.amount, 1000);
        assert!(crate::Cli::try_parse_from(["hellas", "admin", "export-bundle"]).is_err());
    }
}
