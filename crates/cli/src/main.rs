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
mod wrap;

mod commands;
mod identity;
#[cfg(unix)]
mod machines;
#[cfg(feature = "otel")]
mod metrics;
mod owner;
mod platform_hardening;
mod tracing_config;

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
    /// Run the stateful daemon, configured live through backend and route verbs.
    Serve {
        #[arg(long)]
        port: Option<u16>,
        #[cfg(feature = "otel")]
        #[arg(long)]
        metrics_port: Option<u16>,
        #[cfg(feature = "otel")]
        #[arg(long, default_value = "127.0.0.1")]
        metrics_addr: std::net::IpAddr,
    },
    /// Serve models and upstreams from flags, without saving routing configuration.
    Gateway {
        #[command(flatten)]
        args: commands::daemon::GatewayArgs,
        #[cfg(feature = "otel")]
        #[arg(long)]
        metrics_port: Option<u16>,
        #[cfg(feature = "otel")]
        #[arg(long, default_value = "127.0.0.1")]
        metrics_addr: std::net::IpAddr,
    },
    Backend {
        #[command(flatten)]
        control: commands::daemon::ControlArgs,
        #[command(subcommand)]
        command: commands::daemon::BackendCommand,
    },
    Route {
        #[command(flatten)]
        control: commands::daemon::ControlArgs,
        #[command(subcommand)]
        command: commands::daemon::RouteCommand,
    },
    Routes {
        #[command(flatten)]
        control: commands::daemon::ControlArgs,
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
    /// Prepare model metadata for rendering jobs on another machine.
    Model {
        #[command(subcommand)]
        command: commands::model::ModelCommand,
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
        Commands::Model { command } => {
            let result = commands::model::run(command).await;
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

        Commands::Serve { port, .. } => {
            async {
                commands::daemon::serve(
                    &home,
                    &local_identity,
                    owner.as_ref(),
                    &selected_chain,
                    port,
                    #[cfg(feature = "otel")]
                    metrics,
                )
                .await
            }
            .await
        }
        Commands::Gateway { args, .. } => {
            async {
                commands::daemon::gateway(
                    args,
                    &home,
                    &local_identity,
                    owner.as_ref(),
                    &selected_chain,
                    #[cfg(feature = "otel")]
                    metrics,
                )
                .await
            }
            .await
        }
        Commands::Backend { control, command } => {
            commands::admin::daemon(
                control,
                Some(commands::daemon::Edit::Backend(command)),
                &local_identity,
                passkey,
                &home,
            )
            .await
        }
        Commands::Route { control, command } => {
            commands::admin::daemon(
                control,
                Some(commands::daemon::Edit::Route(command)),
                &local_identity,
                passkey,
                &home,
            )
            .await
        }
        Commands::Routes { control } => {
            commands::admin::daemon(control, None, &local_identity, passkey, &home).await
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
        | Commands::Model { .. }
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

#[cfg(feature = "compute")]
mod parsers;
#[cfg(test)]
mod tests;
