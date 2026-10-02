//! Node permissions are read and edited through the provider's journal writer.
use crate::commands::{
    CliResult,
    contributions::{data_root, principal, save},
    read_bounded_regular_file,
};
use anyhow::{Context, ensure};
use hellas_rpc::{
    pb::host::GrantControlRequest,
    protocol::work_grant::{admin::*, budget::*, records::*, *},
    services::host_control::HostControlClientImpl,
};
use std::{
    num::{NonZeroU16, NonZeroU64},
    path::PathBuf,
};

use super::{AdminArgs, AdminCommand};
#[derive(clap::Args)]
pub struct UserArgs {
    #[command(subcommand)]
    command: Users,
}
#[derive(clap::Subcommand)]
enum Users {
    /// List this node's users and permission summaries.
    List,
    /// Register a verified contact and optionally grant admin or Work permission.
    Add {
        /// File containing the user's verified contact enrollment.
        contact: PathBuf,
        /// Allow this user to administer the node; grants no Work permission.
        #[arg(long)]
        admin: bool,
        #[command(flatten)]
        terms: Terms,
    },
    /// Show a user, or the terms and counters of one selected grant.
    Show {
        /// Principal ID printed by add or list.
        user: String,
        /// Select a Work grant by its hexadecimal ID.
        #[arg(long)]
        grant: Option<String>,
    },
    /// Atomically edit a user's permissions and selected Work grant.
    Update {
        /// Principal ID printed by add or list.
        user: String,
        /// Grant permission to administer this node.
        #[arg(long, conflicts_with = "no_admin")]
        admin: bool,
        /// Remove admin permission while retaining Work grants.
        #[arg(long)]
        no_admin: bool,
        /// Select a Work grant; required when the user has several current grants.
        #[arg(long, conflicts_with = "new_grant")]
        grant: Option<String>,
        /// Create an additional Work grant using the supplied policies and bounds.
        #[arg(long)]
        new_grant: bool,
        /// Stop new jobs on the selected grant; open result streams may finish.
        #[arg(long, conflicts_with_all = ["resume", "new_grant", "new_generation", "policies"])]
        pause: bool,
        /// Allow new jobs on the selected paused grant.
        #[arg(long, conflicts_with_all = ["new_grant", "new_generation", "policies"])]
        resume: bool,
        /// Permanently revoke the selected grant and stop its result delivery.
        #[arg(long, conflicts_with_all = ["pause", "resume", "new_grant", "new_generation", "policies"])]
        revoke: bool,
        /// Recover from a lost client journal without resetting quota counters.
        #[arg(long, conflicts_with_all = ["new_grant", "policies", "admin", "no_admin"])]
        new_generation: bool,
        #[command(flatten)]
        terms: Terms,
    },
    /// Revoke all of a user's permissions while retaining quota counters.
    Remove {
        /// Principal ID printed by add or list; the owner cannot be removed.
        user: String,
    },
    /// Export the signed Offer for one of the user's Work grants.
    Offer {
        /// Principal ID printed by add or list.
        user: String,
        /// Select a Work grant; required when the user has several current grants.
        #[arg(long)]
        grant: Option<String>,
        /// Write the private signed Offer to this file.
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(clap::Args, Default)]
struct Terms {
    /// Allow a configured resource policy; repeat to select several policies.
    #[arg(long = "policy")]
    policies: Vec<String>,
    /// Set meter=amount/window, e.g. requests=2000/day; windows: hour/day/week/total.
    #[arg(long = "limit", conflicts_with = "clear_limits")]
    limits: Vec<String>,
    /// Remove the selected grant's quota limits; machine limits still apply.
    #[arg(long)]
    clear_limits: bool,
    /// Maximum simultaneous jobs (creation default: 1).
    #[arg(long)]
    max_in_flight: Option<NonZeroU16>,
    /// Absolute job lifetime bound, e.g. 90s or 2m (creation default: 90s).
    #[arg(long)]
    max_job: Option<String>,
    /// Expire the grant after this duration, e.g. 7d; updates otherwise preserve expiry.
    #[arg(long, conflicts_with = "no_expiry")]
    expires: Option<String>,
    /// Remove the grant's expiry; other resource and quota bounds still apply.
    #[arg(long)]
    no_expiry: bool,
    /// Consent to resources backed by the node operator's upstream accounts.
    #[arg(long, conflicts_with = "no_account_backed")]
    allow_account_backed: bool,
    /// Remove consent to account-backed resources.
    #[arg(long)]
    no_account_backed: bool,
}
impl Terms {
    fn supplied(&self) -> bool {
        !self.policies.is_empty()
            || !self.limits.is_empty()
            || self.clear_limits
            || self.max_in_flight.is_some()
            || self.max_job.is_some()
            || self.expires.is_some()
            || self.no_expiry
            || self.allow_account_backed
            || self.no_account_backed
    }
    fn merge(self, previous: Option<&Offer>, now: UnixMillis) -> CliResult<GrantTerms> {
        let old = previous.map(|o| &o.grant);
        let policies = if self.policies.is_empty() {
            old.map(|g| g.policies.iter().map(|p| p.name.clone()).collect())
                .unwrap_or_default()
        } else {
            self.policies
        };
        ensure!(
            !policies.is_empty(),
            "a Work permission needs at least one --policy"
        );
        let limits = if self.clear_limits {
            vec![]
        } else if self.limits.is_empty() {
            old.map(|g| g.limits.clone()).unwrap_or_default()
        } else {
            self.limits
                .iter()
                .map(|s| limit(s))
                .collect::<CliResult<_>>()?
        };
        let expires_in_millis = if self.no_expiry {
            None
        } else if let Some(s) = self.expires {
            Some(duration(&s)?)
        } else {
            old.and_then(|g| g.expires)
                .map(|t| {
                    NonZeroU64::new(t.0.saturating_sub(now.0))
                        .context("grant has expired; supply --expires or --no-expiry")
                })
                .transpose()?
        };
        Ok(GrantTerms {
            policies,
            limits,
            max_job_millis: self
                .max_job
                .as_deref()
                .map(duration)
                .transpose()?
                .or_else(|| old.map(|g| g.max_job_millis))
                .unwrap_or(NonZeroU64::new(90_000).unwrap()),
            max_in_flight: self
                .max_in_flight
                .or_else(|| old.map(|g| g.max_in_flight))
                .unwrap_or(NonZeroU16::new(1).unwrap()),
            expires_in_millis,
            allow_account_backed: if self.no_account_backed {
                false
            } else {
                self.allow_account_backed || old.is_some_and(|g| g.allow_account_backed)
            },
        })
    }
}
fn duration(value: &str) -> CliResult<NonZeroU64> {
    let (number, scale) = if let Some(n) = value.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = value.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = value.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = value.strip_suffix('h') {
        (n, 3_600_000)
    } else if let Some(n) = value.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        anyhow::bail!("duration requires ms, s, m, h or d suffix");
    };
    let millis = number
        .parse::<u64>()?
        .checked_mul(scale)
        .context("duration overflow")?;
    NonZeroU64::new(millis).context("duration must be positive")
}
fn limit(value: &str) -> CliResult<Limit> {
    let (meter, amount) = value
        .split_once('=')
        .context("limit requires meter=amount/window")?;
    let (amount, window) = amount
        .split_once('/')
        .context("limit requires amount/window")?;
    let meter = match meter {
        "requests" => Meter::Requests,
        "input-tokens" => Meter::InputTokens,
        "output-tokens" => Meter::OutputTokens,
        "device-millis" => Meter::DeviceMillis,
        _ => anyhow::bail!("unknown grant meter: {meter}"),
    };
    let window = match window {
        "hour" => Window::Hour,
        "day" => Window::Day,
        "week" => Window::Week,
        "total" => Window::Total,
        _ => anyhow::bail!("unknown grant window: {window}"),
    };
    Ok(Limit {
        meter,
        window,
        amount: amount.parse()?,
    })
}

fn id(value: &str) -> CliResult<PrincipalId> {
    Ok(PrincipalId(value.parse()?))
}
fn grant_id(value: &str) -> CliResult<GrantId> {
    Ok(GrantId(hex::decode(value)?.try_into().map_err(|_| {
        anyhow::anyhow!("grant ID must have 32 hexadecimal characters")
    })?))
}
enum Client {
    Local(HostControlClientImpl<hellas_wire::mux::MuxTransport>),
    Remote(HostControlClientImpl<hellas_wire::iroh::IrohTransport>),
}
impl Client {
    async fn request(&self, command: GrantCommand) -> CliResult<GrantReply> {
        let request = GrantControlRequest {
            command: command.encode()?,
        };
        let response = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            match self {
                Self::Local(c) => c.grant_control(request).await,
                Self::Remote(c) => c.grant_control(request).await,
            }
        })
        .await??;
        Ok(GrantReply::decode(&response.reply)?)
    }
    async fn user(&self, user: PrincipalId) -> CliResult<UserStatus> {
        match self
            .request(GrantCommand::Users(UserCommand::Show { id: user }))
            .await?
        {
            GrantReply::User(status) => Ok(*status),
            _ => anyhow::bail!("invalid user response"),
        }
    }
    async fn offer(
        &self,
        user: PrincipalId,
        grant: GrantId,
    ) -> CliResult<(
        Box<SignedOffer>,
        UnixMillis,
        Vec<hellas_rpc::protocol::work_grant::standing::NodeAllowance>,
    )> {
        match self
            .request(GrantCommand::Users(UserCommand::Offer { id: user, grant }))
            .await?
        {
            GrantReply::Status { offer, now, nodes } => Ok((offer, now, nodes)),
            _ => anyhow::bail!("invalid Offer response"),
        }
    }
}
fn select(status: &UserStatus, value: Option<&str>) -> CliResult<GrantSummary> {
    if let Some(value) = value {
        let id = grant_id(value)?;
        return status
            .grants
            .iter()
            .find(|g| g.id == id)
            .cloned()
            .context("grant does not belong to this user");
    }
    let mut available = status
        .grants
        .iter()
        .filter(|g| g.state != GrantState::Revoked);
    let g = available
        .next()
        .context("user has no current Work grant; use --new-grant with --policy")?;
    ensure!(
        available.next().is_none(),
        "user has several grants; select --grant ID"
    );
    Ok(g.clone())
}
#[cfg(feature = "node")]
pub async fn run(args: AdminArgs, identity: &crate::identity::LocalIdentity) -> CliResult<()> {
    let owner = principal(identity)?;
    let mut endpoint = None;
    let client = if let Some(contact) = args.node_contact {
        use hellas_wire::ServiceMarker;
        let provider = Principal::decode(&read_bounded_regular_file(
            &contact,
            "node contact",
            MAX_PRINCIPAL_BYTES,
        )?)?;
        let ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(identity.transport_key.clone())
            .bind()
            .await?;
        let address = iroh::EndpointAddr::from_parts(
            iroh::EndpointId::from_bytes(&provider.transport())?,
            args.addresses.into_iter().map(iroh::TransportAddr::Ip),
        );
        let connection = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            ep.connect(
                address,
                hellas_rpc::services::host_control::HostControl::ALPN.as_bytes(),
            ),
        )
        .await??;
        endpoint = Some(ep);
        Client::Remote(HostControlClientImpl::new(
            hellas_wire::iroh::IrohTransport::new(connection),
        ))
    } else {
        let socket = args
            .control_socket
            .unwrap_or(data_root(&owner)?.join("control.sock"));
        Client::Local(HostControlClientImpl::new(
            hellas_sdk::local::connect(&socket).await?,
        ))
    };
    let result = match args.command {
        AdminCommand::Users(args) => users(args.command, &client).await,
        AdminCommand::RepairResource { policy } => {
            client
                .request(GrantCommand::RepairResource { policy })
                .await?;
            println!("{{\"repaired\":true}}");
            Ok(())
        }
        #[cfg(all(feature = "cloud", unix))]
        AdminCommand::Serve { .. } => unreachable!("management serve uses the cloud adapter"),
    };
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
    }
    result
}
async fn users(command: Users, client: &Client) -> CliResult<()> {
    let command = match command {
        Users::List => UserCommand::List,
        Users::Add {
            contact,
            admin,
            terms,
        } => {
            let principal = Principal::decode(&read_bounded_regular_file(
                &contact,
                "contact",
                MAX_PRINCIPAL_BYTES,
            )?)?;
            let expected_revision = match client
                .request(GrantCommand::Users(UserCommand::List))
                .await?
            {
                GrantReply::Users(users) => users
                    .iter()
                    .find(|u| u.id == principal.id())
                    .map(|u| u.revision),
                _ => anyhow::bail!("invalid user list"),
            };
            let work = if terms.supplied() {
                Some((GrantId(rand::random()), terms.merge(None, UnixMillis(0))?))
            } else {
                None
            };
            UserCommand::Add {
                principal: Box::new(principal),
                expected_revision,
                admin,
                work,
            }
        }
        Users::Show { user, grant } => {
            let status = client.user(id(&user)?).await?;
            if let Some(g) = grant {
                let selected = select(&status, Some(&g))?;
                let reply = client
                    .request(GrantCommand::Inspect { id: selected.id })
                    .await?;
                print_reply(reply)?;
            } else {
                print_reply(GrantReply::User(Box::new(status)))?;
            }
            return Ok(());
        }
        Users::Remove { user } => {
            let id = id(&user)?;
            UserCommand::Remove {
                id,
                expected_revision: client.user(id).await?.user.revision,
            }
        }
        Users::Offer { user, grant, out } => {
            let id = id(&user)?;
            let selected = select(&client.user(id).await?, grant.as_deref())?;
            let (offer, _, _) = client.offer(id, selected.id).await?;
            save(&out, &offer.encode()?)?;
            println!(
                "{}",
                serde_json::json!({ "grant_id": hex::encode(selected.id.0) })
            );
            return Ok(());
        }
        Users::Update {
            user,
            admin,
            no_admin,
            grant,
            new_grant,
            pause,
            resume,
            revoke,
            new_generation,
            terms,
        } => {
            let id = id(&user)?;
            let status = client.user(id).await?;
            ensure!(
                status.user.is_active(),
                "removed user must be explicitly added again"
            );
            let admin = if admin {
                Some(true)
            } else if no_admin {
                Some(false)
            } else {
                None
            };
            ensure!(
                !(pause || resume || revoke || new_generation) || !terms.supplied(),
                "state/generation updates cannot also replace Work terms"
            );
            let work = if new_grant {
                Some(UserWork::Create {
                    id: GrantId(rand::random()),
                    terms: terms.merge(None, UnixMillis(0))?,
                })
            } else if terms.supplied() || pause || resume || revoke || new_generation {
                let g = select(&status, grant.as_deref())?;
                if new_generation {
                    client
                        .request(GrantCommand::NewGeneration {
                            id: g.id,
                            expected_revision: g.revision,
                        })
                        .await?;
                    print_reply(GrantReply::User(Box::new(client.user(id).await?)))?;
                    return Ok(());
                }
                Some(if pause || resume || revoke {
                    UserWork::SetState {
                        id: g.id,
                        expected_revision: g.revision,
                        state: if revoke {
                            GrantState::Revoked
                        } else if pause {
                            GrantState::Paused
                        } else {
                            GrantState::Active
                        },
                    }
                } else {
                    let (offer, now, _) = client.offer(id, g.id).await?;
                    UserWork::Revise {
                        id: g.id,
                        expected_revision: g.revision,
                        keep_expiry: terms.expires.is_none() && !terms.no_expiry,
                        terms: terms.merge(Some(offer.offer()), now)?,
                    }
                })
            } else {
                None
            };
            ensure!(
                admin.is_some() || work.is_some(),
                "update needs a permission change"
            );
            UserCommand::Update {
                id,
                expected_revision: status.user.revision,
                admin,
                work,
            }
        }
    };
    print_reply(client.request(GrantCommand::Users(command)).await?)
}
fn print_reply(reply: GrantReply) -> CliResult<()> {
    let value = match reply {
        GrantReply::Users(users) => serde_json::to_value(users.into_iter().map(|u| serde_json::json!({
            "user": u.id.0.to_string(), "revision": u.revision, "permissions": u.permissions, "grants":u.grants
        })).collect::<Vec<_>>())?,
        GrantReply::User(status) => serde_json::json!({ "user":status.user.principal.id().0.to_string(), "revision":status.user.revision,
            "permissions":status.user.permissions, "grants": status.grants.into_iter().map(|g| serde_json::json!({
                "grant_id":hex::encode(g.id.0), "revision":g.revision, "state":g.state, "policies":g.policies, "generation":g.generation, "expires":g.expires })).collect::<Vec<_>>() }),
        GrantReply::Status { offer, now, nodes } => serde_json::json!({ "grant_id":hex::encode(offer.offer().grant.id.0),
            "revision":offer.offer().grant.revision, "state":offer.offer().grant.state, "generation":offer.offer().generation, "now":now.0, "nodes":nodes }),
        _ => anyhow::bail!("unexpected admin response"),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[test]
    fn permission_commands_reject_ambiguous_or_conflicting_updates() {
        for args in [
            vec!["hellas", "grant", "list"],
            vec!["hellas", "control", "serve"],
            vec![
                "hellas",
                "admin",
                "users",
                "update",
                "user",
                "--admin",
                "--no-admin",
            ],
            vec![
                "hellas", "admin", "users", "update", "user", "--pause", "--resume",
            ],
            vec![
                "hellas",
                "admin",
                "users",
                "update",
                "user",
                "--grant",
                "id",
                "--new-grant",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(args).is_err());
        }
        assert!(
            crate::Cli::try_parse_from(["hellas", "admin", "users", "add", "contact", "--admin"])
                .is_ok()
        );
    }
}
