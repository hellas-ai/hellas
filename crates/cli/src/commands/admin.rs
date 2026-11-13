//! Checked node administration through the profile of a paired node.
use anyhow::Context as _;
use std::path::{Path, PathBuf};
mod node;
mod owner_scope;
pub(super) use node::{connect_local, connect_remote};
pub use node::{daemon, gateway_authority, inspect_offline, pair, routes, run, share};
pub(crate) const CONTROL_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Each paired node's profile is `<home>/nodes/NAME/profile.json`.
fn paired_nodes(home: &Path) -> PathBuf {
    home.join("nodes")
}

/// The profile of the only node this home has paired with.
fn paired_profile(home: &Path) -> anyhow::Result<PathBuf> {
    let directory = paired_nodes(home);
    let mut profiles = Vec::new();
    match std::fs::read_dir(&directory) {
        Ok(entries) => {
            for entry in entries {
                let profile = entry?.path().join("profile.json");
                if profile.try_exists()? {
                    profiles.push(profile);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", directory.display()));
        }
    }
    match <[PathBuf; 1]>::try_from(profiles) {
        Ok([profile]) => Ok(profile),
        Err(profiles) if profiles.is_empty() => {
            anyhow::bail!("no paired node: run `hellas pair INVITE` or pass --profile")
        }
        Err(_) => anyhow::bail!("several paired nodes: pass --profile"),
    }
}

#[derive(clap::Args)]
pub struct AdminArgs {
    /// Private application credential and independently provisioned server
    /// trust (default: the only node paired with `hellas pair`).
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

/// Give a contact metered access to one resource of a node you administer,
/// as an access file bound to the contact's device. Rerunning with the same
/// contact and resource revises that one share.
#[derive(clap::Args)]
pub struct ShareArgs {
    /// Acknowledge sharing a resource that permits arbitrary Compute programs.
    #[arg(long)]
    pub knowingly_unsafe: bool,
    /// The `hellas-contact:...` string the contact sent you.
    #[arg(long, value_name = "CONTACT")]
    pub to: String,
    /// New private access file to hand to the contact; the secret is never printed.
    #[arg(long)]
    pub out: PathBuf,
    /// The configured resource name (default: the node's only resource).
    #[arg(long)]
    pub resource: Option<String>,
    /// A budget limit METER:WINDOW:AMOUNT, e.g. `requests:total:100`; repeat
    /// for each. Without any, only concurrency bounds the share.
    #[arg(long = "limit", value_parser = parse_limit)]
    pub limits: Vec<hellas_authority::model::grant::budget::Limit>,
    /// The longest one job may run, e.g. `15m` (default: the resource's
    /// execution timeout).
    #[arg(long, value_parser = crate::commands::transact::duration)]
    pub max_job: Option<std::time::Duration>,
    /// How long the share's grant and credential stay valid, e.g. `30d`.
    #[arg(long, default_value = "30d", value_parser = crate::commands::transact::duration)]
    pub expires: std::time::Duration,
    /// Provider display name shown to the contact.
    #[arg(long)]
    pub label: Option<String>,
    /// The node's profile (default: the only node paired with `hellas pair`).
    #[arg(long)]
    pub profile: Option<PathBuf>,
    /// Local node socket for a local profile; defaults to this home's control.sock.
    #[arg(long)]
    pub control_socket: Option<PathBuf>,
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
        /// Write the one selected signed offer to this file.
        #[arg(long)]
        offer_out: Option<PathBuf>,
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
    Ok(Limit::new(meter, window, amount))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn share_needs_a_contact_and_an_output_and_parses_limits() {
        let base = [
            "hellas",
            "share",
            "--to",
            "hellas-contact:x",
            "--out",
            "friend.access",
        ];
        assert!(crate::Cli::try_parse_from(base).is_ok());
        for missing in [2, 4] {
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
                "--resource",
                "compute",
                "--max-job",
                "15m",
                "--expires",
                "1d",
                "--limit",
                "requests:total:10"
            ]))
            .is_ok()
        );
        assert!(crate::Cli::try_parse_from(["hellas", "admin", "share"]).is_err());
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
    }
}
