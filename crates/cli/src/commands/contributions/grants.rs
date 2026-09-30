use super::*;
use hellas_rpc::{
    pb::host::GrantControlRequest,
    protocol::work_grant::{admin::*, budget::*, *},
    services::host_control::HostControlClientImpl,
};
use std::num::{NonZeroU16, NonZeroU64};

#[derive(clap::Args)]
pub struct GrantArgs {
    /// Owner-only local control socket; defaults to this identity's grant state.
    #[arg(long, global = true)]
    pub control_socket: Option<PathBuf>,
    #[command(subcommand)]
    pub command: GrantCommandArgs,
}
#[derive(clap::Subcommand)]
pub enum GrantCommandArgs {
    Create {
        #[arg(long)]
        to: String,
        #[command(flatten)]
        terms: GrantTermsArgs,
        #[arg(long)]
        offer_out: PathBuf,
    },
    /// Replace terms using named local policies; counters are preserved.
    Revise {
        id: String,
        #[command(flatten)]
        terms: GrantTermsArgs,
        #[arg(long)]
        offer_out: Option<PathBuf>,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    Revoke {
        id: String,
    },
    List,
    Usage {
        id: String,
    },
    /// Export a fresh private Offer without changing its grant terms.
    Export {
        id: String,
        #[arg(long)]
        offer_out: PathBuf,
    },
    /// Recover a lost client journal without resetting allowance counters.
    NewGeneration {
        id: String,
        #[arg(long)]
        offer_out: PathBuf,
    },
    /// Clear a quarantined resource after fixing its upstream accounting.
    RepairResource {
        policy: String,
    },
    /// Explicitly initialize this local identity as the provider's owner.
    InitializeOwner,
}
#[derive(clap::Args)]
pub struct GrantTermsArgs {
    #[arg(long = "policy", required = true)]
    policies: Vec<String>,
    /// requests=2000/day, output-tokens=200000/day; windows: hour/day/week/total.
    #[arg(long = "limit")]
    limits: Vec<String>,
    #[arg(long, default_value = "1")]
    max_in_flight: NonZeroU16,
    #[arg(long, default_value = "90s")]
    max_job: String,
    #[arg(long)]
    expires: Option<String>,
    /// Permit upstream account usage billed to this provider's owner.
    #[arg(long)]
    allow_account_backed: bool,
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
        _ => anyhow::bail!("unsupported grant meter: {meter}"),
    };
    let window = match window {
        "hour" => Window::Hour,
        "day" => Window::Day,
        "week" => Window::Week,
        "total" => Window::Total,
        _ => anyhow::bail!("unsupported grant window: {window}"),
    };
    Ok(Limit {
        meter,
        window,
        amount: amount.parse()?,
    })
}
impl GrantTermsArgs {
    fn terms(self) -> CliResult<GrantTerms> {
        Ok(GrantTerms {
            policies: self.policies,
            limits: self
                .limits
                .iter()
                .map(|v| limit(v))
                .collect::<CliResult<_>>()?,
            max_job_millis: duration(&self.max_job)?,
            max_in_flight: self.max_in_flight,
            expires_in_millis: self.expires.as_deref().map(duration).transpose()?,
            allow_account_backed: self.allow_account_backed,
        })
    }
}
fn grant_id(value: &str) -> CliResult<GrantId> {
    Ok(GrantId(hex::decode(value)?.try_into().map_err(|_| {
        anyhow::anyhow!("grant ID must have 32 hexadecimal characters")
    })?))
}
async fn request(
    client: &HostControlClientImpl<hellas_wire::mux::MuxTransport>,
    command: GrantCommand,
) -> CliResult<GrantReply> {
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        client.grant_control(GrantControlRequest {
            command: command.encode()?,
        }),
    )
    .await??;
    Ok(GrantReply::decode(&response.reply)?)
}
async fn revision(
    client: &HostControlClientImpl<hellas_wire::mux::MuxTransport>,
    id: GrantId,
) -> CliResult<Revision> {
    let GrantReply::Status { offer, .. } = request(client, GrantCommand::Inspect { id }).await?
    else {
        anyhow::bail!("invalid grant status response");
    };
    Ok(offer.offer().grant.revision)
}
pub async fn run(args: GrantArgs, identity: &crate::identity::LocalIdentity) -> CliResult<()> {
    let identity = principal(identity)?;
    let socket = args
        .control_socket
        .unwrap_or(data_root(&identity)?.join("control.sock"));
    let client = HostControlClientImpl::new(
        hellas_sdk::local::connect(&socket)
            .await
            .with_context(|| format!("connect local grant control {}", socket.display()))?,
    );
    let (command, out) = match args.command {
        GrantCommandArgs::Create {
            to,
            terms,
            offer_out,
        } => (
            GrantCommand::Create {
                id: GrantId(rand::random()),
                principal: load_contact(&identity, &to)?,
                terms: terms.terms()?,
            },
            Some(offer_out),
        ),
        GrantCommandArgs::Revise {
            id,
            terms,
            offer_out,
        } => {
            let id = grant_id(&id)?;
            (
                GrantCommand::Revise {
                    id,
                    expected_revision: revision(&client, id).await?,
                    terms: terms.terms()?,
                },
                offer_out,
            )
        }
        GrantCommandArgs::Pause { id } => {
            let id = grant_id(&id)?;
            (
                GrantCommand::SetState {
                    id,
                    expected_revision: revision(&client, id).await?,
                    state: GrantState::Paused,
                },
                None,
            )
        }
        GrantCommandArgs::Resume { id } => {
            let id = grant_id(&id)?;
            (
                GrantCommand::SetState {
                    id,
                    expected_revision: revision(&client, id).await?,
                    state: GrantState::Active,
                },
                None,
            )
        }
        GrantCommandArgs::Revoke { id } => {
            let id = grant_id(&id)?;
            (
                GrantCommand::SetState {
                    id,
                    expected_revision: revision(&client, id).await?,
                    state: GrantState::Revoked,
                },
                None,
            )
        }
        GrantCommandArgs::List => (GrantCommand::List, None),
        GrantCommandArgs::Usage { id } => (GrantCommand::Inspect { id: grant_id(&id)? }, None),
        GrantCommandArgs::Export { id, offer_out } => (
            GrantCommand::Inspect { id: grant_id(&id)? },
            Some(offer_out),
        ),
        GrantCommandArgs::NewGeneration { id, offer_out } => {
            let id = grant_id(&id)?;
            (
                GrantCommand::NewGeneration {
                    id,
                    expected_revision: revision(&client, id).await?,
                },
                Some(offer_out),
            )
        }
        GrantCommandArgs::RepairResource { policy } => {
            (GrantCommand::RepairResource { policy }, None)
        }
        GrantCommandArgs::InitializeOwner => (
            GrantCommand::InitializeOwner {
                principal: identity,
            },
            None,
        ),
    };
    let reply = request(&client, command).await?;
    if let Some(path) = out {
        let GrantReply::Status { offer, .. } = &reply else {
            anyhow::bail!("grant operation did not return an Offer");
        };
        save(&path, &offer.encode()?)?;
    }
    match reply {
        GrantReply::Status { offer, now, nodes } => println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "grant_id": hex::encode(offer.offer().grant.id.0), "revision": offer.offer().grant.revision.0,
            "state": offer.offer().grant.state, "generation": offer.offer().generation, "now": now.0, "nodes": nodes }))?),
        GrantReply::Listing(entries) => println!("{}", serde_json::to_string_pretty(&entries.into_iter().map(|g| serde_json::json!({
            "grant_id": hex::encode(g.id.0), "principal": g.principal.0.to_string(), "owner": g.owner, "revision": g.revision.0,
            "state": g.state, "policies": g.policies, "expires": g.expires.map(|t| t.0), "generation": g.generation
        })).collect::<Vec<_>>())?),
        GrantReply::Repaired => println!("{{\"repaired\":true}}"),
    }
    Ok(())
}
