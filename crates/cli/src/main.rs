#![recursion_limit = "256"]

use hellas_private::StoreLocation;
#[macro_use]
extern crate tracing;

use clap::{Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::PathBuf;
mod compute;
mod content_configuration;

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
    assurance: hellas_rpc::Assurance,
    root_kind: hellas_rpc::RootKind,
) -> Result<(), String> {
    if assurance == hellas_rpc::Assurance::AppleAppAttest
        && root_kind != hellas_rpc::RootKind::SecureEnclave
    {
        Err("Apple App Attest assurance requires a Secure Enclave root".to_owned())
    } else {
        Ok(())
    }
}

/// Commands that act for the principal create its home key on first use.
/// Job commands create it only when they pay or use a grant.
fn acts_for_principal(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Contact { .. }
            | Commands::Share(_)
            | Commands::Identity {
                command: IdentityCommand::Init
            }
            | Commands::Pair { .. }
            | Commands::Faucet { .. }
    )
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
    /// Create this home's device identity and principal key if they do not exist
    Init,
    /// Print the node ID (hex public key) derived from the identity file
    ShowNodeId,
    /// Print the ContentId of the canonical enrollment bundle
    ShowEnrollmentId,
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
    /// Print the one `hellas-contact:` string to send to someone who will
    /// share with you: your principal, signed, and this device.
    Contact {
        /// The name you introduce yourself by (default: $USER).
        #[arg(long)]
        name: Option<String>,
    },
    /// Give a contact metered access to a node you administer.
    Share(commands::admin::ShareArgs),
    /// Become the owner of a fresh node with the invite its `serve` printed.
    Pair {
        /// The `hellas-invite:...` line, copied from the node's own console.
        invite: String,
        /// Name for the paired node in this home.
        #[arg(long, default_value = "default")]
        name: String,
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
        /// Paid terms (TOML). With the principal key, approve and fund them
        /// at startup; without one, require the exact remotely approved policy
        /// and stake already delegated by the owner. Without paid terms, an
        /// uninitialized node prints an invite and waits for `hellas pair`.
        #[arg(long = "paid-work-config", value_name = "FILE")]
        work_config_file: Option<PathBuf>,
        /// Resources and listeners for an explicitly initialized authority store.
        #[arg(long = "grant-config")]
        grant_config_file: Option<PathBuf>,
        /// Admit this exact Compute program (an id from `hellas program`) in the
        /// one shared `compute` resource; repeat for each program.
        #[arg(long = "program", value_name = "PROGRAM", conflicts_with_all = ["grant_config_file", "work_config_file"])]
        programs: Vec<hellas_rpc::protocol::invocation::compute::ProgramId>,
        /// Serve a configuration that admits any Compute program (`any` in
        /// paid terms, or `Any` in a grant resource); without it
        /// such a node refuses to start. Compiling and running a program from
        /// an unknown author hands that author roughly root on this host.
        #[arg(long)]
        knowingly_unsafe: bool,
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
    /// Every route requires `Authorization: Bearer <token>`. On loopback the
    /// gateway keeps its own authority under the home and its bearer in
    /// `gateway/bearer` there, so a web page cannot spend what it runs on;
    /// --gateway-profile selects an explicitly provisioned one instead.
    Gateway {
        /// The models the routes render jobs from, and where requests run:
        /// the job commands' --access, --pay or --local.
        #[command(flatten)]
        execution: commands::transact::GatewayArgs,
        /// Serve exact HTTP routes through HTTPS Fetch. A grant with an HTTPS
        /// resource supplies its own routes.
        #[arg(long, value_name = "FILE")]
        http_fetch_config: Option<PathBuf>,
        /// Disable payload archives and require ZDR for every HTTP request.
        #[arg(long)]
        zdr: bool,
        /// Private profile selecting a provisioned HTTP authority and scoped credential.
        #[arg(long = "gateway-profile", value_name = "FILE")]
        gateway_profile: Option<PathBuf>,
        /// Allow a non-loopback listener using the provisioned gateway authority.
        #[arg(long, requires = "gateway_profile")]
        allow_remote: bool,
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
    /// Fetch a published Whisper checkpoint and convert it into a model
    /// package, e.g. `openai/whisper-tiny@COMMIT`.
    ConvertWhisper {
        /// `ORG/NAME@COMMIT`, pinned to a 40-hex commit.
        checkpoint: commands::convert::Checkpoint,
        #[arg(short = 'o', long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Print the program manifest a model's jobs run, which `serve
    /// --program` admits: a Qwen GGUF or a converted Whisper package.
    Program {
        #[arg(value_name = "PATH")]
        model: PathBuf,
        /// The registered renderer (evaluator id) the program is compiled for.
        #[arg(long, value_name = "EVALUATOR")]
        backend: String,
    },
    /// Transcribe one WAV with a client-rendered Whisper job.
    Transcribe(commands::transact::TranscribeArgs),
    /// Answer one prompt with a client-rendered Qwen3 text job.
    Text(commands::transact::TextArgs),
    /// Fetch a published distilled Flux2 Klein 4B snapshot and convert it
    /// into client metadata and provider assets.
    ConvertFlux {
        /// `ORG/NAME@COMMIT`, pinned to a 40-hex commit.
        checkpoint: commands::convert::Checkpoint,
        #[arg(short = 'o', long, value_name = "DIR")]
        output: PathBuf,
    },
    /// Generate one PNG with a client-rendered Flux job.
    Image(commands::transact::ImageArgs),
    /// Inspect and manage node content with Owner authority.
    Store(commands::store::StoreArgs),
    /// Get devnet coins for this principal from a public faucet account.
    Faucet {
        #[arg(long, default_value_t = commands::faucet::DEFAULT_AMOUNT)]
        amount: u64,
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

fn main() {
    // SafeRuntime launches the current executable as a worker child. This
    // must run before Tokio creates worker threads and before clap, tracing,
    // or any stdout-producing command so the child speaks only Catena's worker
    // protocol on stdout.
    #[cfg(feature = "compute")]
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
        native,
        ..
    } = &cli.command
    {
        let result = async {
            anyhow::ensure!(fetch_config_file.is_some() || grant_config_file.is_some() || native.content_config.is_some() || !native.content.is_empty(), "--check-config requires --content, --content-config, --fetch-config or --grant-config");
            commands::serve::validate_provider_config(
                fetch_config_file.as_deref(),
                grant_config_file.as_deref(),
                native.content_config.as_deref(),
                &home,
            )
        }.await;
        tracer_provider.shutdown();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    let owner = match cli.owner.load(&home).and_then(|owner| match owner {
        None if acts_for_principal(&cli.command) => owner::principal(&home).map(Some),
        owner => Ok(owner),
    }) {
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
        Commands::ConvertFlux { checkpoint, output } => {
            let result = commands::convert::flux(&checkpoint, &output);
            tracer_provider.shutdown();
            if let Err(error) = result {
                eprintln!("error: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Program { model, backend } => {
            let result = hellas_client::model::ModelPackage::open(&model, &backend)
                .await
                .and_then(|package| package.program())
                .map(|program| println!("{program}"));
            tracer_provider.shutdown();
            if let Err(error) = result {
                eprintln!("error: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::ConvertWhisper { checkpoint, output } => {
            let result = commands::convert::whisper(&checkpoint, &output);
            tracer_provider.shutdown();
            if let Err(error) = result {
                eprintln!("error: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Store(args) if args.profile.is_none() => {
            let result = commands::store::run(args, &home, None, passkey).await;
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
        Commands::Faucet { amount } => {
            let result = commands::faucet::faucet(
                amount,
                owner.as_ref().expect("the faucet pays the principal"),
                &selected_chain,
            )
            .await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
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

    // Before anything binds, and before any other startup work.
    let local_identity = match identity::load_or_create(&identity_path) {
        Ok(identity) => identity,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };
    let secret_key = local_identity.transport_key.clone();
    if let Commands::Serve { assurance, .. } = &command
        && let Err(error) = validate_serve_assurance(
            *assurance,
            local_identity.enrollment.genesis.statement.root_kind,
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match command {
        Commands::Contact { name } => {
            async {
                let name = match name {
                    Some(name) => name,
                    None => std::env::var("USER")
                        .map_err(|_| anyhow::anyhow!("pass --name: $USER is not set"))?,
                };
                let passkey = passkey.expect("a contact acts for the principal");
                let contact =
                    commands::contributions::contact(&name, passkey, &local_identity.node_key)
                        .await?;
                println!("{contact}");
                Ok(())
            }
            .await
        }
        Commands::Share(args) => {
            commands::admin::share(args, &local_identity, passkey, &home).await
        }
        Commands::Admin(args) => commands::admin::run(args, &local_identity, passkey, &home).await,
        Commands::Pair { invite, name } => {
            let passkey = passkey.expect("pairing acts for the principal");
            commands::admin::pair(&invite, &name, &local_identity, passkey, &home).await
        }
        Commands::Store(args) => {
            commands::store::run(args, &home, Some(&local_identity), passkey).await
        }

        Commands::Serve {
            native,
            assurance,
            port,
            no_discovery,
            queue_size,
            work_config_file,
            grant_config_file,
            programs,
            knowingly_unsafe,
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
                        } else if !programs.is_empty() {
                            anyhow::ensure!(
                                assurance == hellas_rpc::Assurance::ProducerSigned,
                                "grants require producer-signed assurance"
                            );
                            Some(hellas_sdk::grant_config::GrantConfig::compute(
                                &home,
                                hellas_rpc::protocol::invocation::Admission::compute_only(
                                    &programs,
                                )?,
                            )?)
                        } else {
                            None
                        };
                        let admits_any =
                            paid.as_ref().is_some_and(|paid| paid.admits_any_program())
                                || grants.as_ref().is_some_and(|grants| {
                                    grants.configuration.resources().iter().any(|resource| {
                                        resource.invocation_policy.admits_any_program()
                                    })
                                });
                        anyhow::ensure!(
                            !admits_any || knowingly_unsafe,
                            "this configuration admits any Compute program, which hands anyone \
                             who can submit jobs roughly root on this host; pass \
                             --knowingly-unsafe to serve it anyway"
                        );
                        commands::serve::run(commands::serve::ServeOptions {
                            home: home.clone(),
                            port,
                            discovery: !no_discovery,
                            queue_size,
                            native,
                            paid,
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
            execution,
            http_fetch_config,
            zdr,
            gateway_profile,
            allow_remote,
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
        } => {
            async {
                let principal = match owner.as_ref() {
                    Some(owner) => owner.clone(),
                    None => owner::principal(&home)?,
                };
                let directory = home.join("gateway");
                let own = gateway_profile.is_none();
                let profile = match gateway_profile {
                    Some(profile) => profile,
                    None => {
                        commands::admin::gateway_profile(
                            &directory,
                            &home,
                            &local_identity,
                            &principal,
                        )
                        .await?
                    }
                };
                let hellas_sdk::node_control::profile::GatewayHost {
                    node,
                    access,
                    control,
                } = hellas_sdk::node_control::profile::GatewayProfile::load(&home.child(profile))
                    .await?;
                if own {
                    let bearer = directory.join("bearer");
                    if !bearer.try_exists()? {
                        hellas_private::write_atomically(
                            &bearer,
                            ".writing",
                            access.bearer().as_bytes(),
                        )?;
                    }
                    eprintln!("gateway bearer: {}", bearer.display());
                }
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
                let models = execution
                    .models
                    .iter()
                    .map(|model| {
                        hellas_gateway::ModelOptions::at(model.clone(), default_max_tokens)
                    })
                    .collect();
                let context = commands::transact::Context::new(
                    &local_identity,
                    Some(&principal),
                    &home,
                    &selected_chain,
                )?;
                let served = commands::transact::gateway(execution, context, async |work| {
                    #[cfg(feature = "otel")]
                    if let Some((address, bundle)) = metrics {
                        let bundle = match work.target().endpoint() {
                            Some(endpoint) => {
                                let (_, receiver) =
                                    tokio::sync::watch::channel(Some(endpoint.clone()));
                                bundle.with_iroh(receiver)
                            }
                            None => bundle,
                        };
                        metrics::spawn_metrics_server(address, bundle).await?;
                    }
                    let http = match http {
                        Some(http) => Some(http),
                        None => work.target().http_config()?,
                    };
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
                    let gateway = hellas_sdk::serve_gateway(work, serve).await?;
                    Ok(hellas_gateway::wait_for_shutdown(gateway).await?)
                })
                .await;
                let stopped = match control {
                    Some(control) => {
                        served.and(control.shutdown().await.map_err(anyhow::Error::from))
                    }
                    None => served,
                };
                node.close().await;
                stopped
            }
            .await
        }
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
        Commands::Text(args) => {
            async {
                commands::transact::text(
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
        Commands::ConvertWhisper { .. }
        | Commands::ConvertFlux { .. }
        | Commands::Program { .. } => {
            unreachable!("model commands handled before identity load")
        }
        Commands::Trust(args) => commands::trust::run(args),
        Commands::Chain { .. } | Commands::Faucet { .. } => {
            unreachable!("chain commands handled before identity load")
        }
        #[cfg(unix)]
        Commands::Machines(_) => {
            unreachable!("management commands handled before identity load")
        }
        Commands::Identity { command } => match command {
            IdentityCommand::Init => Ok(()),
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
            IdentityCommand::ShowEnrollmentId => {
                commands::identity::show_enrollment_id(&local_identity.enrollment)
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
