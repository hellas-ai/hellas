#![recursion_limit = "256"]

use hellas_private::StoreLocation;
#[macro_use]
extern crate tracing;

use clap::{Args, Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
mod compute;

mod commands;
mod identity;
#[cfg(unix)]
mod machines;
#[cfg(feature = "otel")]
mod metrics;
mod owner;
mod platform_hardening;
mod tracing_config;

fn validate_serve_assurance(
    software_root: bool,
    assurance: hellas_rpc::Assurance,
    root_kind: Option<hellas_rpc::RootKind>,
) -> Result<(), String> {
    if assurance == hellas_rpc::Assurance::AppleAppAttest
        && (software_root
            || root_kind.is_some_and(|kind| kind != hellas_rpc::RootKind::SecureEnclave))
    {
        Err(
            "Apple App Attest assurance requires a Secure Enclave root; \
             --software-root cannot be used"
                .to_owned(),
        )
    } else {
        Ok(())
    }
}

/// Providers and existing authority operations read their identity; requester
/// commands create a local signing identity on first use.
fn load_command_identity(
    command: &Commands,
    path: &Path,
) -> anyhow::Result<identity::LocalIdentity> {
    let grant_identity = matches!(
        command,
        Commands::Admin(_)
            | Commands::Gateway { offer: Some(_), .. }
            | Commands::Gateway {
                local_grant: Some(_),
                ..
            }
            | Commands::Offer {
                command: commands::contributions::OfferCommand::ImportBundle { .. },
            }
    );
    let read_only = grant_identity
        || matches!(
            command,
            Commands::Identity {
                command: IdentityCommand::ShowNodeId
                    | IdentityCommand::ShowEnrollmentId
                    | IdentityCommand::ShowHolder
                    | IdentityCommand::ExportEnrollment { .. },
            }
        );
    if read_only {
        identity::load_existing(path)
    } else {
        identity::load_or_create(path)
    }
}

#[derive(Args)]
struct RemoteTrustArgs {
    /// Assurance required for remote execution.
    #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
    assurance: hellas_rpc::Assurance,

    /// Caller-owned native trust directory.
    #[arg(long, conflicts_with = "paid_work_config")]
    trust_store: Option<PathBuf>,
    /// Previously approved local policy ID.
    #[arg(long, requires = "trust_store", conflicts_with = "paid_work_config")]
    trust_policy: Option<String>,
}

impl RemoteTrustArgs {
    fn load(&self, home: &Path) -> anyhow::Result<hellas_client::ProviderTrustAnchor> {
        let directory = self
            .trust_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--trust-store is required for grant execution"))?;
        let id = self
            .trust_policy
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--trust-policy is required for grant execution"))?;
        Ok(
            hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                id,
                self.assurance,
                identity::assertion_counters(home)?,
            )?,
        )
    }
}

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version = option_env!("GIT_REV").unwrap_or(env!("CARGO_PKG_VERSION")))]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Select a compiled chain (default: the most senior compiled chain).
    #[arg(long, global = true, conflicts_with = "chain_config")]
    chain: Option<String>,

    /// Complete independently authenticated custom chain profile.
    #[arg(long, global = true, value_name = "FILE")]
    chain_config: Option<PathBuf>,
    /// Process state home (default: HELLAS_HOME or $HOME/.hellas).
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Journal durability: process crashes only, or also OS crash/power loss.
    #[arg(long, global = true, default_value = "crash")]
    durability: hellas_private::Durability,

    /// Choose the software platform root when a command creates an identity.
    #[arg(long = "software-root", global = true)]
    software_root: bool,

    #[command(flatten)]
    owner: owner::OwnerArgs,

    /// Also append tracing output to this file.
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create the local identity file if it does not exist
    Init {
        /// Create a fresh private software owner key alongside this device identity.
        #[arg(long)]
        passkey_out: Option<PathBuf>,
    },
    /// Print the node ID (hex public key) derived from the identity file
    ShowNodeId,
    /// Print the ContentId of the canonical enrollment bundle
    ShowEnrollmentId,
    /// Print the JSON CredentialHolder naming this node's key, for issuing a
    /// credential this node will hold
    ShowHolder,
    /// Write this node's canonical enrollment, which operators pin to reach it
    ExportEnrollment {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CodexAuthCommand {
    /// Sign in to Codex with device-code OAuth and store credentials locally
    Login,
    /// Import credentials from an existing Codex CLI auth file
    Import {
        /// Source auth file (default: $HOME/.codex/auth.json)
        #[arg(long = "from")]
        source_path: Option<PathBuf>,
    },
    /// Show whether local Codex credentials are configured
    Status,
}

// Parsed once at startup and immediately destructured; boxing the large
// variants would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    /// Approve and inspect caller-owned provider trust policies.
    Trust(commands::trust::TrustArgs),
    #[cfg(unix)]
    /// Create, list and destroy machines through a configured provider.
    Machines(machines::MachinesArgs),
    /// Introduce the principal with a signed contact card, or save a contact's.
    Contact {
        #[command(subcommand)]
        command: commands::contributions::ContactCommand,
    },
    /// Import a private provider Offer addressed to this principal.
    Offer {
        #[command(subcommand)]
        command: commands::contributions::OfferCommand,
    },
    /// Administer node authority and settings.
    Admin(commands::admin::AdminArgs),
    /// Run the RPC server
    Serve {
        #[command(flatten)]
        native: compute::ServeArgs,
        /// Assurance offered by this provider.
        #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
        assurance: hellas_rpc::Assurance,
        /// Port to listen on. Omit it to let the OS select an available port.
        #[arg(long)]
        port: Option<u16>,
        /// Disable mDNS and DHT service advertising; clients must use direct addresses.
        #[arg(long)]
        no_discovery: bool,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Paid terms (TOML). With an owner passkey, approve and fund them at
        /// startup; without one, require the exact remotely approved policy
        /// and stake already delegated by the owner.
        #[arg(
            long = "paid-work-config",
            value_name = "FILE",
            conflicts_with = "await_owner"
        )]
        work_config_file: Option<PathBuf>,
        #[command(flatten)]
        chain_node: commands::chain_node::ChainNodeArgs,
        /// Resources and listeners for an explicitly initialized authority store.
        #[arg(long = "grant-config")]
        grant_config_file: Option<PathBuf>,
        /// Serve a converted Whisper model with model-pinned grants and one concurrent job.
        #[arg(long, requires = "await_owner", conflicts_with = "grant_config_file")]
        audio_model: Option<PathBuf>,
        /// Wait for one owner pairing if the home provider authority is uninitialized.
        #[arg(long)]
        await_owner: bool,
        #[cfg(feature = "otel")]
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        #[cfg(feature = "otel")]
        /// IP address for unauthenticated metrics; non-loopback exposes them to the network.
        #[arg(long, default_value = "127.0.0.1")]
        metrics_addr: std::net::IpAddr,
        /// Operator graffiti tag (up to 16 bytes, padded/truncated)
        #[arg(long = "graffiti", default_value = "")]
        graffiti: String,
        /// Fetch configuration file: sealed upstream destinations and
        /// credentials and route capabilities. No file
        /// means this node serves no Fetch routes.
        #[arg(long = "fetch-config")]
        fetch_config_file: Option<PathBuf>,
        /// Validate Fetch and grant resources without starting a node.
        #[arg(long)]
        check_config: bool,
        /// Maximum number of Fetch provider streams running at once.
        #[arg(
            long = "fetch-max-in-flight",
            default_value_t = hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            value_parser = parse_positive_usize
        )]
        fetch_max_in_flight: usize,
        /// Maximum number of Fetch executions waiting behind active provider streams.
        #[arg(
            long = "fetch-queue-size",
            default_value_t = hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY
        )]
        fetch_queue_size: usize,
    },
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    ///
    /// Every route requires `Authorization: Bearer <token>`. Use
    /// --gateway-profile to select its provisioned Auth authority and credential.
    /// Hellas routes run --text-model as paid Compute jobs; the shared model
    /// adapter handles text and tool calls with the GGUF's tokenizer.
    Gateway {
        /// Qwen3 GGUF served by the text routes. Providers must already hold it.
        #[arg(long, value_name = "FILE")]
        text_model: Option<PathBuf>,
        /// Converted Whisper package served at /v1/audio/transcriptions.
        #[arg(long, value_name = "DIR")]
        audio_model: Option<PathBuf>,
        /// Converted Flux2 Klein package served at /v1/images/generations.
        #[arg(long, value_name = "DIR")]
        image_model: Option<PathBuf>,
        /// Content store, and with --local-grant the local GPU executor.
        #[command(flatten)]
        native: compute::ServeArgs,
        /// Run this node's own, already configured allowance in process: no
        /// chain and no remote provider.
        #[arg(long, value_name = "ID", conflicts_with_all = ["offer", "paid_work_config", "grant_pool_config"])]
        local_grant: Option<String>,
        /// Use a private Offer previously verified by `offer import`.
        #[arg(long, value_name = "ALIAS", conflicts_with_all = ["paid_work_config", "grant_pool_config"])]
        offer: Option<String>,
        /// Use an explicit list of private grant channels and resources.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["offer", "local_grant", "paid_work_config", "grant_policy", "work_profile", "http_fetch_config", "trust_policy"])]
        grant_pool_config: Option<PathBuf>,
        /// Check grant pool aliases, trust and saved terms without connecting.
        #[arg(long, requires = "grant_pool_config")]
        check_config: bool,
        /// Select one resource when the Offer includes several matching policies.
        #[arg(long)]
        grant_policy: Option<String>,
        /// Private application credential, authority and Work authorization grant.
        #[arg(long, value_name = "FILE")]
        work_profile: Option<PathBuf>,
        /// Serve exact HTTP routes through HTTPS Fetch. A grant with an HTTPS
        /// resource supplies its own routes.
        #[arg(long, value_name = "FILE")]
        http_fetch_config: Option<PathBuf>,
        /// Disable payload archives and require ZDR for every HTTP request.
        #[arg(long)]
        zdr: bool,
        /// Pay a pool of providers using durable on-chain funded work channels.
        #[arg(long = "paid-work-config", value_name = "FILE")]
        paid_work_config: Option<PathBuf>,
        /// Private profile selecting the local HTTP authority and scoped credential.
        #[arg(long = "gateway-profile", value_name = "FILE")]
        gateway_profile: Option<PathBuf>,
        /// Allow a non-loopback listener using the provisioned gateway authority.
        #[arg(long)]
        allow_remote: bool,
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        /// Host interface to bind. Every request requires bearer authentication.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on. Omit to try 8080 with fallback to an OS-assigned port.
        #[arg(long)]
        port: Option<u16>,
        #[cfg(feature = "otel")]
        /// Prometheus metrics port (e.g. 9090).
        #[arg(long)]
        metrics_port: Option<u16>,
        #[cfg(feature = "otel")]
        /// IP address for unauthenticated metrics; non-loopback exposes them to the network.
        #[arg(long, default_value = "127.0.0.1")]
        metrics_addr: std::net::IpAddr,
        /// Fallback max new tokens when request omits max_tokens
        #[arg(
            long = "default-max-tokens",
            default_value_t = 128,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        default_max_tokens: u32,
        /// JSON object merged into OpenAI Responses requests before they are
        /// signed and sent as a Fetch.
        #[arg(long = "responses-overrides", value_parser = parse_json_object)]
        responses_overrides: Option<serde_json::Map<String, serde_json::Value>>,
        /// Models the Responses Fetch answers to when /v1/responses is shared
        /// with other routes. Repeat or use commas.
        #[arg(long = "responses-model", value_delimiter = ',')]
        responses_models: Vec<String>,
        /// Wrap a child command with the gateway as its OpenAI/Anthropic backend.
        #[arg(long = "wrap")]
        wrap: Option<String>,
        /// Trailing args forwarded verbatim to the wrapped command (after `--`).
        #[arg(last = true, allow_hyphen_values = true, requires = "wrap")]
        wrap_args: Vec<String>,
    },
    /// Query a remote node via RPC
    Rpc {
        /// Node ID to check
        node_id: EndpointId,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "address", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
    },
    /// Execute a reusable job folder, or settle its provider channels.
    Transact(commands::transact::TransactArgs),
    /// Buy an HTTPS Fetch using the same job and payment path.
    Fetch(commands::transact::FetchArgs),
    /// Buy one call of a Catena program using the same job and payment path.
    Run(commands::transact::RunArgs),
    /// Convert a local published Whisper checkpoint into a client model package.
    ConvertWhisper {
        #[arg(long, value_name = "DIR")]
        checkpoint: PathBuf,
        #[arg(long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Transcribe one WAV with a client-rendered Whisper job on a paid provider.
    Transcribe(commands::transact::TranscribeArgs),
    /// Convert a local distilled Flux2 Klein 4B snapshot into client metadata and provider assets.
    ConvertFlux {
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Generate one PNG with a client-rendered Flux job on a paid provider.
    Image(commands::transact::ImageArgs),
    /// Inspect and fill the content store
    Store {
        #[command(subcommand)]
        command: commands::store::StoreCommand,
    },
    /// Query or run Hellas chain components
    Chain {
        #[command(subcommand)]
        command: commands::chain::ChainCommand,
    },
    /// Inspect the local identity file
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Manage Codex OAuth credentials
    CodexAuth {
        #[command(subcommand)]
        command: CodexAuthCommand,
    },
    /// Discover peers and log network events
    Monitor {
        /// Stop monitoring after N seconds (default: run until Ctrl+C)
        #[arg(long = "timeout-secs")]
        timeout_secs: Option<u64>,
        /// Disable peer interrogation RPCs (health + known peers)
        #[arg(long = "no-interrogate", default_value_t = false)]
        no_interrogate: bool,
    },
}

fn validate_identity_options(command: &Commands, software_root: bool) -> Result<(), String> {
    let identity_free = match command {
        Commands::Admin(commands::admin::AdminArgs {
            command: commands::admin::AdminCommand::InspectOffline { .. },
            ..
        }) => Some("admin inspect-offline"),
        Commands::Trust(_) => Some("trust"),
        #[cfg(unix)]
        Commands::Machines(_) => Some("machines"),
        Commands::Contact { .. } => Some("contact"),
        Commands::Offer {
            command: commands::contributions::OfferCommand::Import { .. },
        } => Some("offer import"),
        Commands::Store { .. } => Some("store"),
        Commands::Serve {
            check_config: true, ..
        } => Some("serve --check-config"),
        Commands::Chain { .. } => Some("chain"),
        Commands::CodexAuth { .. } => Some("codex-auth"),
        _ => None,
    };
    if let Some(name) = identity_free
        && software_root
    {
        return Err(format!(
            "--software-root cannot be used with `{name}`; that command does not use a Hellas identity"
        ));
    }

    let reads_existing_identity = matches!(
        command,
        Commands::Gateway { offer: Some(_), .. }
            | Commands::Gateway {
                grant_pool_config: Some(_),
                ..
            }
            | Commands::Gateway {
                local_grant: Some(_),
                ..
            }
            | Commands::Offer {
                command: commands::contributions::OfferCommand::ImportBundle { .. },
            }
            | Commands::Admin(_)
            | Commands::Identity {
                command: IdentityCommand::ShowNodeId
                    | IdentityCommand::ShowEnrollmentId
                    | IdentityCommand::ShowHolder
                    | IdentityCommand::ExportEnrollment { .. },
            }
    );
    if software_root && reads_existing_identity {
        return Err(
            "--software-root only selects the root when creating an identity; this command reads an existing identity"
                .to_string(),
        );
    }
    Ok(())
}

fn main() {
    // SafeRuntime launches the current executable as a worker child. This
    // must run before Tokio creates worker threads and before clap, tracing,
    // or any stdout-producing command so the child speaks only Catena's worker
    // protocol on stdout.
    match hellas_executor::child_main() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("error: failed to start Catena worker: {error}");
            std::process::exit(1);
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: failed to start async runtime: {error}");
            std::process::exit(1);
        }
    };
    runtime.block_on(async_main());
}

async fn async_main() {
    // Parse the CLI first so we can honour the global `--log-file`
    // flag in the subscriber setup. clap's parser is cheap; doing it
    // before tracing init means very early subscriber-internal failures
    // (which print to stderr regardless) are the only thing that
    // bypasses the requested log file.
    let cli = Cli::parse();
    let home = match identity::resolve_home(cli.home.as_deref()) {
        Ok(home) => StoreLocation::from_home(&home, cli.durability),
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2);
        }
    };
    let identity_path = home.join("identity");
    let selected_chain = if let Some(path) = &cli.chain_config {
        hellas_sdk::work_config::load_chain_profile(path).map_err(anyhow::Error::from)
    } else if let Some(name) = &cli.chain {
        hellas_chain::genesis::Chain::parse(name)
            .map(hellas_chain::genesis::ChainProfile::known)
            .ok_or_else(|| anyhow::anyhow!("unknown compiled chain {name}"))
    } else {
        Ok(hellas_chain::genesis::ChainProfile::known(
            hellas_chain::genesis::Chain::default(),
        ))
    };
    let selected_chain = match selected_chain {
        Ok(chain) => chain,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(2);
        }
    };
    if let Err(error) = validate_identity_options(&cli.command, cli.software_root) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
    if let Commands::Serve { assurance, .. } = &cli.command
        && let Err(error) = validate_serve_assurance(cli.software_root, *assurance, None)
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    if matches!(&cli.command, Commands::Serve { .. })
        && let Err(err) = platform_hardening::harden_provider_process()
    {
        eprintln!("error: failed to harden provider process: {err}");
        std::process::exit(1);
    }
    #[cfg(feature = "otel")]
    let metrics = match &cli.command {
        Commands::Serve {
            metrics_port,
            metrics_addr,
            ..
        }
        | Commands::Gateway {
            metrics_port,
            metrics_addr,
            ..
        } => metrics_port.map(|port| {
            (
                (*metrics_addr, port).into(),
                metrics::MetricsBundle::default(),
            )
        }),
        _ => None,
    };
    let tracer_provider = tracing_config::init_tracing(
        cli.log_file.as_deref(),
        #[cfg(feature = "otel")]
        metrics.as_ref().map(|(_, bundle)| &bundle.registry),
    );
    if let Commands::Trust(args) = cli.command {
        let result = commands::trust::run(args);
        tracer_provider.shutdown();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if let Commands::Serve {
        check_config: true,
        fetch_config_file,
        grant_config_file,
        audio_model,
        ..
    } = &cli.command
    {
        let result = if let Some(model) = audio_model {
            commands::serve::audio_model::configure(model, &home).map(|_| ())
        } else {
            commands::serve::validate_provider_config(
                fetch_config_file.as_deref(),
                grant_config_file.as_deref(),
                &home,
            )
        };
        tracer_provider.shutdown();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    // A selected faucet account stays with this identity across restarts.
    let persistent_owner = matches!(
        &cli.command,
        Commands::Serve { .. }
            | Commands::Transact(_)
            | Commands::Fetch(_)
            | Commands::Run(_)
            | Commands::Transcribe(_)
            | Commands::Image(_)
            | Commands::Gateway {
                paid_work_config: Some(_),
                ..
            }
    );
    let owner = match if persistent_owner {
        cli.owner.load_persistent(&home, &selected_chain)
    } else {
        cli.owner.load(&selected_chain)
    } {
        Ok(owner) => owner,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
    };
    let passkey = owner
        .as_ref()
        .map(|key| key as &dyn hellas_authority::authenticator::Authenticator);

    if let Commands::CodexAuth { command } = &cli.command {
        let result = match command {
            CodexAuthCommand::Login => {
                commands::codex_auth::login(&home.join("codex-auth.json")).await
            }
            CodexAuthCommand::Import { source_path } => commands::codex_auth::import_codex_cli(
                &home.join("codex-auth.json"),
                source_path.as_deref(),
            ),
            CodexAuthCommand::Status => commands::codex_auth::status(&home.join("codex-auth.json")),
        };
        tracer_provider.shutdown();
        if let Err(err) = result {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
        return;
    }

    // Chain commands carry their own authentication material and transport.
    // Running them must not create an unrelated provider identity as a side
    // effect; in particular, validator config generation runs in a pure Nix
    // build where there is deliberately no writable home directory.
    let command = match cli.command {
        Commands::Admin(
            args @ commands::admin::AdminArgs {
                command: commands::admin::AdminCommand::InspectOffline { .. },
                ..
            },
        ) => {
            let result = commands::admin::inspect_offline(args, &home).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(unix)]
        Commands::Machines(args) => {
            let result = machines::run(args).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command @ (Commands::Contact { .. }
        | Commands::Offer {
            command: commands::contributions::OfferCommand::Import { .. },
        }) => {
            let result: anyhow::Result<()> = async {
                match command {
                    Commands::Contact { command } => {
                        commands::contributions::contact(command, passkey, &home).await
                    }
                    Commands::Offer { command } => {
                        commands::contributions::offer(command, passkey, None, &home)
                    }
                    _ => Ok(()),
                }
            }
            .await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::ConvertFlux { checkpoint, output } => {
            let result = hellas_client::model::flux::convert_flux(&checkpoint, &output);
            tracer_provider.shutdown();
            match result {
                Ok(assets) => {
                    for asset in assets {
                        println!(
                            "{}: {} ({} bytes), {}",
                            asset.name,
                            asset.object.id(),
                            asset.object.bytes(),
                            output.join(format!("{}.bin", asset.name)).display()
                        );
                    }
                }
                Err(error) => {
                    eprintln!("error: {error:#}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Commands::ConvertWhisper { checkpoint, output } => {
            let result = hellas_client::model::whisper::convert_whisper(&checkpoint, &output);
            tracer_provider.shutdown();
            match result {
                Ok(object) => println!(
                    "weights: {} ({} bytes), {}",
                    object.id(),
                    object.bytes(),
                    output
                        .join(hellas_client::model::whisper::WEIGHTS_FILE)
                        .display()
                ),
                Err(error) => {
                    eprintln!("error: {error:#}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Commands::Store { command } => {
            let result = commands::store::run(command, &home).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command => command,
    };

    let command = match command {
        Commands::Chain { command } => {
            let result =
                commands::chain::run(command, owner.as_ref(), &selected_chain, &home).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        command => command,
    };

    // Before anything binds, and before any other startup work: a
    // command that cannot have an identity has nothing further to do.
    let local_identity = match load_command_identity(&command, &identity_path) {
        Ok(identity) => identity,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };
    let secret_key = local_identity.transport_key.clone();
    if let Commands::Serve { assurance, .. } = &command
        && let Err(error) = validate_serve_assurance(
            cli.software_root,
            *assurance,
            Some(local_identity.enrollment.genesis.statement.root_kind),
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match command {
        Commands::Offer { command } => {
            commands::contributions::offer(command, passkey, Some(&local_identity.node_key), &home)
        }
        Commands::Contact { .. } => {
            unreachable!("contact commands handled before identity load")
        }
        Commands::Admin(args) => commands::admin::run(args, &local_identity, passkey, &home).await,

        Commands::Serve {
            mut native,
            assurance,
            port,
            no_discovery,
            queue_size,
            work_config_file,
            chain_node,
            grant_config_file,
            audio_model,
            await_owner,
            #[cfg(feature = "otel")]
                metrics_port: _,
            #[cfg(feature = "otel")]
                metrics_addr: _,
            graffiti,
            fetch_config_file,
            check_config: _,
            fetch_max_in_flight,
            fetch_queue_size,
        } => {
            // Loaded before anything binds: a work configuration that
            // will not load is a node that would advertise two paid
            // ALPNs and then have nothing to mount behind them.
            match work_config_file
                .as_deref()
                .map(|path| {
                    commands::serve::paid::PaidWork::load(
                        path,
                        home.clone(),
                        owner.clone(),
                        fetch_config_file.as_deref(),
                        selected_chain.clone(),
                    )
                })
                .transpose()
            {
                Err(error) => Err(error),
                Ok(paid) => {
                    async {
                        // The key every settlement this node signs is signed
                        // with, taken from the identity loaded above and
                        // never made here.
                        let settlement_key = identity::settlement_signer(&local_identity)?;
                        let open_identity = local_identity.open_identity();
                        let grants = if let Some(path) = grant_config_file.as_deref() {
                            anyhow::ensure!(
                                assurance == hellas_rpc::Assurance::ProducerSigned,
                                "grants require producer-signed assurance"
                            );
                            let config = hellas_sdk::grant_config::GrantConfig::load(path, &home)?;
                            Some(config)
                        } else if let Some(model) = audio_model.as_deref() {
                            anyhow::ensure!(
                                assurance == hellas_rpc::Assurance::ProducerSigned,
                                "grants require producer-signed assurance"
                            );
                            native
                                .content_paths
                                .push(model.join(hellas_client::model::whisper::WEIGHTS_FILE));
                            Some(commands::serve::audio_model::configure(model, &home)?)
                        } else {
                            None
                        };

                        let (grants, transport) = if await_owner {
                            let (grants, transport) = commands::serve::bootstrap::prepare(
                                &home,
                                &local_identity,
                                port,
                                grants,
                            )
                            .await?;
                            (Some(grants), transport)
                        } else {
                            (grants, None)
                        };
                        let fetch_config_file = match (fetch_config_file, await_owner) {
                            (Some(path), _) => Some(path),
                            (None, true) => {
                                let path =
                                    hellas_sdk::grant_config::GrantConfig::provider_dir(&home)
                                        .join("fetch.json");
                                if !path.try_exists()? {
                                    hellas_private::write_atomically(
                                        &path,
                                        ".initializing",
                                        br#"{"revision":0,"routes":[]}"#,
                                    )?;
                                }
                                Some(path)
                            }
                            (None, false) => None,
                        };
                        commands::serve::run(commands::serve::ServeOptions {
                            home: home.clone(),
                            transport,
                            port,
                            discovery: !no_discovery,
                            queue_size,
                            native,
                            paid,
                            chain_node,
                            grants,
                            #[cfg(feature = "otel")]
                            metrics,
                            graffiti,
                            fetch_config_file,
                            fetch_max_in_flight,
                            fetch_queue_size,
                            secret_key,
                            producer_key: local_identity.node_key,
                            settlement_key,
                            open_identity,
                            assurance,
                        })
                        .await
                    }
                    .await
                }
            }
        }
        Commands::Gateway {
            text_model,
            audio_model,
            image_model,
            native,
            local_grant,
            offer,
            grant_pool_config,
            check_config,
            grant_policy,
            work_profile,
            http_fetch_config,
            zdr,
            paid_work_config,
            gateway_profile,
            allow_remote,
            remote_trust,
            host,
            port,
            #[cfg(feature = "otel")]
                metrics_port: _,
            #[cfg(feature = "otel")]
                metrics_addr: _,
            default_max_tokens,
            responses_overrides,
            responses_models,
            wrap,
            wrap_args,
        } => async {
            let assurance = remote_trust.assurance;
            let pool_options = if let Some(path) = grant_pool_config.as_deref() {
                let client = commands::contributions::require_principal(passkey)?;
                let root = commands::contributions::data_root(&home, &client)?;
                let trust_directory = remote_trust
                    .trust_store
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--trust-store is required for a grant pool"))?;
                Some(commands::grant_gateway::load_pool(
                    path,
                    &home,
                    &root,
                    trust_directory,
                    &local_identity,
                    client,
                    assurance,
                )?)
            } else {
                None
            };
            if check_config {
                let pool = pool_options
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("--check-config requires a grant pool"))?;
                hellas_gateway::ResponsesFetch::from_routes(
                    &pool.fetch_routes()?,
                    responses_overrides.clone().unwrap_or_default(),
                    responses_models.clone(),
                )?;
                println!("grant pool configuration is valid");
                return Ok(());
            }
            let application = work_profile
                .as_deref()
                .map(hellas_sdk::node_control::profile::ClientProfile::load)
                .transpose()?
                .map(std::sync::Arc::new);
            let work_application = || {
                application
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--work-profile is required for grant Work"))
            };
            let mut local_service = None;
            let grant_source = if let Some(name) = offer.as_deref() {
                let client = commands::contributions::require_principal(passkey)?;
                let offer = commands::contributions::load_offer(&home, &client, name)?;
                let target = hellas_sdk::grant_client::UnpinnedOffer::decode(
                    &offer.encode()?,
                    hellas_auth::authority::UnixMillis(0),
                )?
                .pin(&remote_trust.load(&home)?)?;
                anyhow::ensure!(
                    assurance == target.trust().required_assurance,
                    "requested assurance differs from the pinned grant provider"
                );
                Some((
                    commands::grant_gateway::session(
                        &home,
                        target,
                        &local_identity,
                        client,
                        work_application()?,
                    )?,
                    hellas_sdk::grant_client::GrantTransport::Remote(
                        hellas_sdk::grant_client::bind_endpoint(secret_key.clone()).await?,
                    ),
                ))
            } else if let Some(grant) = local_grant.as_deref() {
                anyhow::ensure!(
                    assurance == hellas_rpc::Assurance::ProducerSigned,
                    "local Work requires producer-signed assurance"
                );
                let (session, service) = commands::grant_gateway::local::prepare(
                    &home,
                    grant,
                    native,
                    &local_identity,
                    commands::contributions::require_principal(passkey)?,
                    work_application()?,
                    remote_trust.load(&home)?,
                )
                .await?;
                local_service = Some(service.clone());
                Some((
                    session,
                    hellas_sdk::grant_client::GrantTransport::Local(service),
                ))
            } else {
                None
            };
            anyhow::ensure!(
                grant_policy.is_none() || grant_source.is_some(),
                "--grant-policy requires a remote or local allowance"
            );
            let hellas_sdk::node_control::profile::GatewayHost {
                node,
                access,
                control,
            } = hellas_sdk::node_control::profile::GatewayProfile::load(&home.child(
                gateway_profile.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--gateway-profile is required to serve HTTP")
                })?,
            ))
            .await?;
            let http = http_fetch_config
                .map(
                    |path| -> anyhow::Result<hellas_gateway::HttpGatewayConfig> {
                        let bytes = commands::read_bounded_regular_file(
                            &path,
                            "HTTP gateway config",
                            4 << 20,
                        )?;
                        Ok(serde_json::from_slice(&bytes)?)
                    },
                )
                .transpose()?;
            let text = text_model.map(|model| hellas_gateway::TextOptions {
                model_name: model
                    .file_stem()
                    .map_or_else(String::new, |stem| stem.to_string_lossy().into_owned()),
                model,
                default_max_tokens,
            });
            let mut models: Vec<_> = text
                .into_iter()
                .map(hellas_gateway::ModelOptions::Text)
                .collect();
            if let Some(model) = audio_model {
                models.push(hellas_gateway::ModelOptions::Whisper(
                    hellas_gateway::AudioOptions {
                        model_name: model
                            .file_name()
                            .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
                        model,
                        default_max_tokens: default_max_tokens as usize,
                    },
                ));
            }
            if let Some(model) = image_model {
                models.push(hellas_gateway::ModelOptions::Flux(
                    hellas_gateway::ImageOptions {
                        model_name: model
                            .file_name()
                            .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
                        model,
                    },
                ));
            }
            let serve = hellas_sdk::GatewayServeOptions {
                server: hellas_gateway::ServerOptions {
                    access,
                    archive: hellas_gateway::ArchiveOptions {
                        directory: home.join("gateway-archive"),
                        zdr,
                    },
                    allow_remote,
                    host,
                    port,
                    wrap,
                    wrap_args,
                },
                models,
                http,
                responses_overrides: responses_overrides.unwrap_or_default(),
                responses_models,
            };
            #[cfg(feature = "otel")]
            let metrics = metrics.map(|(address, bundle)| {
                let bundle = match grant_source.as_ref().map(|(_, transport)| transport) {
                    Some(hellas_sdk::grant_client::GrantTransport::Remote(endpoint)) => {
                        let (_, receiver) = tokio::sync::watch::channel(Some(endpoint.clone()));
                        bundle.with_iroh(receiver)
                    }
                    _ => bundle,
                };
                (address, bundle)
            });
            #[cfg(feature = "otel")]
            if let Some((address, bundle)) = metrics {
                metrics::spawn_metrics_server(address, bundle).await?;
            }
            let gateway = if let Some(pool) = pool_options {
                let endpoint = hellas_sdk::grant_client::bind_endpoint(secret_key.clone()).await?;
                let transports = (0..pool.channels.len())
                    .map(|_| hellas_sdk::grant_client::GrantTransport::Remote(endpoint.clone()))
                    .collect();
                hellas_sdk::grant_gateway::GrantPoolServeOptions { serve, pool }
                    .start(transports)
                    .await?
            } else if let Some((session, transport)) = grant_source {
                hellas_sdk::grant_gateway::GrantServeOptions {
                    serve,
                    session,
                    policy: grant_policy,
                }
                .start(transport)
                .await?
            } else if let Some(path) = paid_work_config.as_ref() {
                anyhow::ensure!(
                    serve.http.is_some() || assurance == hellas_rpc::Assurance::ProducerSigned,
                    "token-native paid work uses producer-signed assurance"
                );
                let config =
                    hellas_sdk::work_config::WorkConfig::for_chain(selected_chain.clone(), &home)?;
                let client_chain = config.chain.clone();
                let options = hellas_sdk::paid_gateway::load_pool_options(path, assurance, config)?;
                let passkey = owner.clone().ok_or_else(|| {
                    anyhow::anyhow!("paid work requires --passkey, --faucet or --faucet-account")
                })?;
                let payer = std::sync::Arc::new(hellas_sdk::client_owner::ClientOwner::new(
                    std::sync::Arc::new(passkey),
                    identity::settlement_signer(&local_identity)?.party_key(),
                    &client_chain,
                )?);
                let paid = hellas_sdk::paid_gateway::PaidGateway::open(
                    options,
                    hellas_sdk::NodeIdentity::from_secret_bytes(
                        secret_key.to_bytes(),
                        local_identity.node_key.to_secret_bytes(),
                    )?,
                    payer,
                )
                .await?;
                hellas_sdk::serve_gateway(paid, serve).await?
            } else {
                anyhow::bail!(
                    "the gateway needs a work source: --local-grant, --offer or --paid-work-config"
                );
            };
            let served = hellas_gateway::wait_for_shutdown(gateway)
                .await
                .map_err(anyhow::Error::from);
            let stopped = match control {
                Some(control) => served.and(control.shutdown().await.map_err(anyhow::Error::from)),
                None => served,
            };
            // The gateway's session only drained the local service it borrowed.
            let stopped = match local_service {
                Some(service) => stopped.and(service.shutdown().await.map_err(anyhow::Error::from)),
                None => stopped,
            };
            node.close().await;
            stopped
        }
        .await,
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::Transact(args) => {
            async {
                commands::transact::run(
                    args,
                    commands::transact::Context::new(
                        &local_identity,
                        owner.as_ref(),
                        &home,
                        &selected_chain,
                    )?,
                )
                .await
            }
            .await
        }
        Commands::Fetch(args) => {
            async {
                commands::transact::fetch(
                    args,
                    commands::transact::Context::new(
                        &local_identity,
                        owner.as_ref(),
                        &home,
                        &selected_chain,
                    )?,
                )
                .await
            }
            .await
        }
        Commands::Run(args) => {
            async {
                commands::transact::run_program(
                    args,
                    commands::transact::Context::new(
                        &local_identity,
                        owner.as_ref(),
                        &home,
                        &selected_chain,
                    )?,
                )
                .await
            }
            .await
        }
        Commands::Transcribe(args) => {
            async {
                commands::transact::transcribe(
                    args,
                    commands::transact::Context::new(
                        &local_identity,
                        owner.as_ref(),
                        &home,
                        &selected_chain,
                    )?,
                )
                .await
            }
            .await
        }
        Commands::Image(args) => {
            async {
                commands::transact::image(
                    args,
                    commands::transact::Context::new(
                        &local_identity,
                        owner.as_ref(),
                        &home,
                        &selected_chain,
                    )?,
                )
                .await
            }
            .await
        }
        Commands::ConvertWhisper { .. } | Commands::ConvertFlux { .. } => {
            unreachable!("conversion handled before identity load")
        }
        Commands::Trust(args) => commands::trust::run(args),
        Commands::Chain { .. } => unreachable!("chain commands handled before identity load"),
        Commands::Store { .. } => unreachable!("store commands handled before identity load"),
        #[cfg(unix)]
        Commands::Machines(_) => {
            unreachable!("management commands handled before identity load")
        }
        Commands::Identity { command } => match command {
            IdentityCommand::Init { passkey_out } => passkey_out
                .as_deref()
                .map(commands::identity::create_passkey)
                .transpose()
                .map(|_| ()),
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
            IdentityCommand::ShowEnrollmentId => {
                commands::identity::show_enrollment_id(&local_identity.enrollment)
            }
            IdentityCommand::ShowHolder => {
                commands::identity::show_holder(&local_identity.node_key)
            }
            IdentityCommand::ExportEnrollment { out } => {
                commands::identity::export_enrollment(&local_identity.enrollment, out.as_deref())
            }
        },
        Commands::CodexAuth { .. } => unreachable!("codex-auth handled before identity load"),
        Commands::Monitor {
            timeout_secs,
            no_interrogate,
        } => commands::monitor::run(timeout_secs, !no_interrogate, secret_key).await,
    };

    tracer_provider.shutdown();

    if let Err(err) = result {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

mod parsers;
#[cfg(test)]
mod tests;
use parsers::*;
