#[macro_use]
extern crate tracing;

use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(feature = "evaluate")]
mod evaluate;

mod commands;
mod identity;
#[cfg(unix)]
mod machines;
mod metrics;
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

/// Loads the identity this command runs under, creating one only where
/// creating one is what the operator asked for.
///
/// Identity queries read the file and create nothing as a side effect: doing
/// so could race with a running service's own creator. Paid-work commands also read
/// an existing identity: providers, provisioning, the operator client, and
/// gateways configured with a paid provider pool. They sign with the stored
/// identity's key, so the key must be one an operator already made —
/// `identity init` is where it comes from. Minting one here would give
/// the node a settlement party nobody has funded and no bond names, and
/// the first symptom would be a channel that cannot be opened.
///
/// # Errors
///
/// Whatever the identity file's own loader says, which names the file it
/// could not read.
fn load_command_identity(
    command: &Commands,
    path: Option<&Path>,
) -> anyhow::Result<identity::LocalIdentity> {
    let settles_paid_work = matches!(
        command,
        Commands::Serve {
            work_config_file: Some(_),
            ..
        } | Commands::Provision { .. }
            | Commands::PaidWork { .. }
            | Commands::Gateway {
                paid_work_config: Some(_),
                ..
            }
    );
    let grant_identity = matches!(
        command,
        Commands::Admin(_)
            | Commands::Gateway { offer: Some(_), .. }
            | Commands::Offer {
                command: commands::contributions::OfferCommand::ImportBundle { .. },
            }
    );
    #[cfg(feature = "evaluate")]
    let grant_identity = grant_identity
        || matches!(command, Commands::Gateway { evaluation, .. } if evaluation.local);
    let read_only = grant_identity
        || settles_paid_work
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum GatewayResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

impl From<GatewayResponsesBackend> for hellas_gateway::ResponsesBackend {
    fn from(value: GatewayResponsesBackend) -> Self {
        match value {
            GatewayResponsesBackend::Hellas => Self::Hellas,
            GatewayResponsesBackend::Proxy => Self::Proxy,
            GatewayResponsesBackend::Fetch => Self::Fetch,
        }
    }
}

/// Execution requires an explicit Work backend; proxy mode has no Hellas peer.
fn gateway_provider_trust(
    responses_backend: GatewayResponsesBackend,
) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
    if responses_backend != GatewayResponsesBackend::Proxy {
        return Err(hellas_client::ClientError::FundingRequired.into());
    }
    Ok(None)
}

/// Caller-selected trust policy for commands that execute on a remote provider.
#[derive(Args)]
struct RemoteTrustArgs {
    /// Assurance required for remote execution.
    #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
    assurance: hellas_rpc::Assurance,

    /// Caller-owned native trust directory.
    #[arg(long, requires = "trust_policy", conflicts_with = "paid_work_config")]
    trust_store: Option<PathBuf>,
    /// Previously approved local policy ID.
    #[arg(long, requires = "trust_store", conflicts_with = "paid_work_config")]
    trust_policy: Option<String>,
}

impl RemoteTrustArgs {
    fn load(&self) -> anyhow::Result<hellas_client::ProviderTrustAnchor> {
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
                identity::assertion_counters()?,
            )?,
        )
    }
}

/// One canonical causal-LM route and its untrusted text-presentation boundary.
#[derive(Args)]
struct CausalLmArgs {
    /// Canonical causal-LM environment root. Without --manifest-id, these
    /// local file bytes are the trust anchor and determine the exact manifest.
    #[arg(long = "environment", value_name = "FILE")]
    environment: PathBuf,

    /// Optional caller-selected manifest ContentId for --environment. When
    /// supplied, the file must derive exactly this ID before any route starts.
    #[arg(
        long = "manifest-id",
        value_name = "CONTENT_ID",
        value_parser = parse_content_id_hex
    )]
    manifest_id: Option<hellas_rpc::ContentId>,

    /// Presentation-only model label. It defaults to the derived manifest ID
    /// and never enters the manifest, quote, or trusted executor input.
    #[arg(long = "model", value_name = "NAME")]
    model: Option<String>,

    /// Tokenizer JSON used only for local text presentation. It is not part of
    /// the Hellas execution guarantee.
    #[arg(long = "tokenizer", value_name = "PATH")]
    tokenizer: PathBuf,

    /// Caller-selected stop token ID. Repeat or comma-separate. No stop tokens
    /// are inferred from the tokenizer or causal-LM environment.
    #[arg(long = "stop-token", value_delimiter = ',')]
    stop_token_ids: Vec<u32>,
}

#[derive(Parser)]
#[command(name = "hellas")]
#[command(version)]
#[command(about = "Hellas node CLI")]
struct Cli {
    /// Path to the versioned local identity for commands that use one
    /// (default: $HOME/.hellas/identity).
    #[arg(long = "identity", global = true)]
    identity: Option<PathBuf>,

    /// Choose the software platform root when a command creates an identity.
    #[arg(long = "software-root", global = true)]
    software_root: bool,

    /// The software passkey of the principal this command acts for: a file of
    /// 32 raw bytes or 64 hex digits. Contacts, offers, grant data, gateway
    /// allowances and passkey administration sessions use it.
    #[arg(long, global = true)]
    passkey: Option<PathBuf>,

    /// Also append tracing output to this file.
    #[arg(long = "log-file", global = true)]
    log_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create the local identity file if it does not exist
    Init,
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
    Login {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
    },
    /// Import credentials from an existing Codex CLI auth file
    Import {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
        /// Source auth file (default: $HOME/.codex/auth.json)
        #[arg(long = "from")]
        source_path: Option<PathBuf>,
    },
    /// Show whether local Codex credentials are configured
    Status {
        /// Codex auth store path (default: $HOME/.hellas/codex-auth.json)
        #[arg(long = "auth-path")]
        auth_path: Option<PathBuf>,
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
    /// Introduce the principal with a signed contact card, or save a friend's.
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
        #[cfg(feature = "evaluate")]
        #[command(flatten)]
        evaluation: evaluate::ServeArgs,
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
        /// Paid-work configuration. Its presence serves WorkSetup and Work;
        /// Work remains retryably not ready until the configured state mounts.
        #[arg(long = "work-config")]
        work_config_file: Option<PathBuf>,
        #[command(flatten)]
        chain_node: commands::chain_node::ChainNodeArgs,
        /// Resources and listeners for an explicitly initialized authority store.
        #[arg(long = "grant-config")]
        grant_config_file: Option<PathBuf>,
        /// Wait for one owner pairing if uninitialized; use this directory for node state.
        #[arg(long, num_args = 0..=1, default_missing_value = ".")]
        await_owner: Option<PathBuf>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
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
    /// Hellas routes use the configured causal-LM environment; the shared
    /// model adapter handles text and tool calls using --tokenizer and
    /// --chat-template.
    #[command(
        mut_arg("environment", |arg| arg
            .required(false)
            .required_unless_present_any(["responses_backend", "http_fetch_config", "offer"])
            .required_if_eq("responses_backend", "hellas")
            .requires("tokenizer")),
        mut_arg("tokenizer", |arg| arg.required(false).requires("environment"))
    )]
    Gateway {
        /// Inference reuse policy; record mode fails requests if cache writes fail.
        #[arg(long, default_value = "off")]
        output_cache: hellas_rpc::cache::CachePolicy,
        /// Content and output cache state (default: HELLAS_STORE_DIR or ~/.hellas/store).
        #[arg(long)]
        store_dir: Option<PathBuf>,
        /// Use a private Offer previously verified by `offer import`.
        #[arg(long, value_name = "ALIAS", conflicts_with_all = ["node_id", "node_addrs", "responses_backend", "http_fetch_config"])]
        #[arg(conflicts_with = "paid_work_config")]
        offer: Option<String>,
        /// Select one resource when the Offer includes several matching policies.
        #[arg(long)]
        grant_policy: Option<String>,
        /// Private application credential, authority and Work authorization grant.
        #[arg(long, value_name = "FILE")]
        work_profile: Option<PathBuf>,
        /// Serve exact HTTP routes through paid HTTPS Fetch.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["responses_backend", "environment"])]
        #[arg(requires = "paid_work_config")]
        http_fetch_config: Option<PathBuf>,
        /// Request/response archive directory (default: ~/.hellas/gateway-archive).
        #[arg(long, value_name = "DIRECTORY")]
        archive_dir: Option<PathBuf>,
        /// Disable payload archives and require ZDR for every HTTP request.
        #[arg(long)]
        zdr: bool,
        /// Pay a pool of providers using durable on-chain funded work channels.
        #[arg(long = "paid-work-config", value_name = "FILE")]
        paid_work_config: Option<PathBuf>,
        #[command(flatten)]
        chain_node: commands::chain_node::ChainNodeArgs,
        /// Private profile selecting the local HTTP authority and scoped credential.
        #[arg(long = "gateway-profile", value_name = "FILE")]
        gateway_profile: Option<PathBuf>,
        /// Allow a non-loopback listener using the provisioned gateway authority.
        #[arg(long)]
        allow_remote: bool,
        /// Explicit local text-chat template.
        #[arg(long = "chat-template", value_name = "TEMPLATE")]
        chat_template: Option<hellas_presentation::ChatTemplate>,
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        #[command(flatten)]
        causal_lm: Option<CausalLmArgs>,
        /// Host interface to bind. Every request requires bearer authentication.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on. Omit to try 8080 with fallback to an OS-assigned port.
        #[arg(long)]
        port: Option<u16>,
        /// Direct target node id (omit to use discovery)
        #[arg(long)]
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "address", value_delimiter = ',')]
        #[arg(requires = "node_id")]
        node_addrs: Vec<SocketAddr>,
        #[cfg(feature = "evaluate")]
        #[command(flatten)]
        evaluation: evaluate::GatewayArgs,
        /// Max execution retries on failure (discovery mode)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Fallback max new tokens when request omits max_tokens
        #[arg(
            long = "default-max-tokens",
            default_value_t = 128,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        default_max_tokens: u32,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Backend used only for /v1/responses; other gateway APIs are unchanged.
        #[arg(long = "responses-backend", value_enum, default_value_t = GatewayResponsesBackend::Hellas)]
        responses_backend: GatewayResponsesBackend,
        /// Upstream endpoint used when --responses-backend=proxy.
        #[arg(
            long = "responses-proxy-url",
            default_value = "https://api.openai.com/v1/responses"
        )]
        responses_proxy_url: String,
        /// Environment variable holding the bearer token for --responses-backend=proxy.
        #[arg(long = "responses-proxy-api-key-env", default_value = "OPENAI_API_KEY")]
        responses_proxy_api_key_env: String,
        /// Fetch route service used when --responses-backend=fetch.
        #[arg(long = "responses-fetch-route-service", default_value = "codex")]
        responses_fetch_route_service: String,
        /// Fetch route method used when --responses-backend=fetch.
        #[arg(long = "responses-fetch-route-method", default_value = "responses")]
        responses_fetch_route_method: String,
        /// Exact Fetch contract ProgramManifest ContentId expected from the provider route.
        #[arg(
            long = "responses-fetch-execution-environment",
            required_if_eq("responses_backend", "fetch"),
            value_parser = parse_content_id_hex
        )]
        responses_fetch_execution_environment: Option<hellas_rpc::ContentId>,
        /// JSON object merged into OpenAI Responses requests before signing
        /// and sending them through Fetch.
        #[arg(long = "responses-fetch-request-overrides", value_parser = parse_json_object)]
        responses_fetch_request_overrides: Option<serde_json::Map<String, serde_json::Value>>,
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
    /// Inspect or run the durable paid-work client path.
    PaidWork {
        #[command(subcommand)]
        command: commands::paid_work::PaidWorkCommand,
    },
    /// Inspect and fill the content store
    Store {
        /// Content store state (default: HELLAS_STORE_DIR or ~/.hellas/store).
        #[arg(long, global = true)]
        store_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: commands::store::StoreCommand,
    },
    /// Build or inspect canonical causal-LM environments.
    Environment {
        #[command(subcommand)]
        command: commands::environment::EnvironmentCommand,
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
    /// Make one of this provider's bond offers, so its client has something to
    /// answer
    ///
    /// A node serves `WorkSetup` from the setup journals under its work
    /// root and creates none, so a fresh provider offers nothing however
    /// well it is configured. This signs one bond and journals it, and
    /// returns only once the runner's own replay of that journal finds
    /// it. A root may hold several offers only when their configured routes,
    /// bonds, and every staked coin are pairwise disjoint.
    Provision {
        #[command(flatten)]
        chain_node: commands::chain_node::ChainNodeArgs,
        /// The paid-work configuration this offer is made under
        #[arg(long = "work-config")]
        work_config: PathBuf,
        /// Existing node grant configuration; its authority must already be bootstrapped.
        #[arg(long = "grant-config")]
        grant_config: PathBuf,
        /// Alias of an already imported, verified client contact.
        #[arg(long)]
        client_contact: String,
        /// The client node signer this bond names as taker, hex-encoded.
        #[arg(long = "client")]
        client: String,
        /// Return the provider's stake without delegating it back to this node.
        #[arg(long)]
        lock_provider_payout: bool,
        /// A coin this provider stakes, hex-encoded. Repeat it for each
        /// coin; the stake is the provider's alone, so none of these is
        /// the client's.
        #[arg(long = "stake-coin", required = true)]
        stake_coin: Vec<String>,
        /// Height the bond expires at, which is also the admission
        /// horizon of the channel it insures
        #[arg(long = "bond-timeout")]
        bond_timeout: u64,
        /// What the bond's timeout returns to this provider. Consensus
        /// requires it to be the staked edge's close value exactly, and
        /// refuses the open otherwise.
        #[arg(long = "timeout-payout")]
        timeout_payout: u64,
        /// The largest job price this bond covers
        #[arg(long = "max-job-price")]
        max_job_price: u64,
        /// Print the bond edge using the existing authority and contact,
        /// before opening paid-work journals or connecting to validators.
        #[arg(long = "print-bond-only")]
        print_bond_only: bool,
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

fn validate_identity_options(
    command: &Commands,
    identity: Option<&Path>,
    software_root: bool,
) -> Result<(), String> {
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
        Commands::Environment { .. } => Some("environment"),
        Commands::Serve {
            check_config: true, ..
        } => Some("serve --check-config"),
        Commands::Chain { .. } => Some("chain"),
        Commands::CodexAuth { .. } => Some("codex-auth"),
        _ => None,
    };
    if let Some(name) = identity_free
        && (identity.is_some() || software_root)
    {
        let options = match (identity.is_some(), software_root) {
            (true, true) => "--identity and --software-root",
            (true, false) => "--identity",
            (false, true) => "--software-root",
            (false, false) => unreachable!("an identity option was present"),
        };
        return Err(format!(
            "{options} cannot be used with `{name}`; that command does not use a Hellas identity"
        ));
    }

    let reads_existing_identity = matches!(
        command,
        Commands::Gateway { offer: Some(_), .. }
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
            | Commands::Serve {
                work_config_file: Some(_),
                ..
            }
            | Commands::Provision { .. }
            | Commands::PaidWork { .. }
            | Commands::Gateway {
                paid_work_config: Some(_),
                ..
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
    #[cfg(feature = "evaluate")]
    match catena_lang::safe_gpu::run_worker_if_requested() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("error: failed to start Catena GPU worker: {error}");
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
    if let Err(error) =
        validate_identity_options(&cli.command, cli.identity.as_deref(), cli.software_root)
    {
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
    let tracer_provider = tracing_config::init_tracing(cli.log_file.as_deref());
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
        ..
    } = &cli.command
    {
        let result = commands::serve::validate_provider_config(
            fetch_config_file.as_deref(),
            grant_config_file.as_deref(),
        );
        tracer_provider.shutdown();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }

    if let Commands::CodexAuth { command } = &cli.command {
        let result = match command {
            CodexAuthCommand::Login { auth_path } => {
                commands::codex_auth::login(auth_path.as_deref()).await
            }
            CodexAuthCommand::Import {
                auth_path,
                source_path,
            } => {
                commands::codex_auth::import_codex_cli(auth_path.as_deref(), source_path.as_deref())
            }
            CodexAuthCommand::Status { auth_path } => {
                commands::codex_auth::status(auth_path.as_deref())
            }
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
            let result = commands::admin::inspect_offline(args).await;
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
            let result = cli
                .passkey
                .as_deref()
                .map(commands::chain::passkey)
                .transpose()
                .and_then(|passkey| match command {
                    Commands::Contact { command } => {
                        commands::contributions::contact(command, passkey.as_ref())
                    }
                    Commands::Offer { command } => {
                        commands::contributions::offer(command, passkey.as_ref(), None)
                    }
                    _ => Ok(()),
                });
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Store { command, store_dir } => {
            let result = commands::store::run(command, store_dir).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Environment { command } => {
            let result = commands::environment::run(command).await;
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
            let result = commands::chain::run(command, cli.passkey.as_deref()).await;
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
    let local_identity = match load_command_identity(&command, cli.identity.as_deref()) {
        Ok(identity) => identity,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };
    let secret_key = local_identity.transport_key.clone();
    let passkey = match cli
        .passkey
        .as_deref()
        .map(commands::chain::passkey)
        .transpose()
    {
        Ok(passkey) => passkey,
        Err(err) => {
            eprintln!("error: {err:#}");
            std::process::exit(1);
        }
    };
    let passkey = passkey.as_ref();
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
            commands::contributions::offer(command, passkey, Some(&local_identity.node_key))
        }
        Commands::Contact { .. } => {
            unreachable!("contact commands handled before identity load")
        }
        Commands::Admin(args) => commands::admin::run(args, &local_identity, passkey).await,

        Commands::Serve {
            #[cfg(feature = "evaluate")]
            evaluation,
            assurance,
            port,
            no_discovery,
            queue_size,
            work_config_file,
            chain_node,
            grant_config_file,
            await_owner,
            metrics_port,
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
                .map(commands::serve::load_work_config)
                .transpose()
            {
                Err(error) => Err(error.into()),
                Ok(work_config) => {
                    async {
                        // The key every settlement this node signs is signed
                        // with, taken from the identity loaded above and
                        // never made here.
                        let settlement_key = identity::settlement_signer(&local_identity)?;
                        let open_identity = local_identity.open_identity();
                        let grants = if let Some(path) = grant_config_file.as_deref() {
                            anyhow::ensure!(assurance == hellas_rpc::Assurance::ProducerSigned, "grants require producer-signed assurance");
                            let root = passkey
                                .map(commands::contributions::principal)
                                .transpose()?
                                .map(|owner| commands::contributions::data_root(&owner))
                                .transpose()?;
                            let config = hellas_sdk::grant_config::GrantConfig::load(path, root.as_deref())?;
                            Some(config)
                        } else { None };

                        let (grants, transport) = match await_owner.as_deref() {
                            Some(root) => {
                                let (grants, transport) = commands::serve::bootstrap::prepare(root, &local_identity, port, grants).await?;
                                (Some(grants), transport)
                            }
                            None => (grants, None),
                        };
                        let fetch_config_file = match (fetch_config_file, await_owner.as_deref()) {
                            (Some(path), _) => Some(path),
                            (None, Some(root)) => {
                                let path = std::path::absolute(root)?.join("fetch.json");
                                if !path.try_exists()? {
                                    hellas_private::write_atomically(&path, ".initializing", br#"{"revision":0,"routes":[]}"#)?;
                                }
                                Some(path)
                            }
                            (None, None) => None,
                        };
                        commands::serve::run(commands::serve::ServeOptions {
                            transport,
                            port,
                            discovery: !no_discovery,
                            queue_size,
                            #[cfg(feature = "evaluate")]
                            evaluation,
                            work_config,
                            chain_node,
                            grants,
                            metrics_port,
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
        Commands::Provision {
            chain_node,
            work_config,
            grant_config,
            client_contact,
            client,
            lock_provider_payout,
            stake_coin,
            bond_timeout,
            timeout_payout,
            max_job_price,
            print_bond_only,
        } => match commands::serve::load_work_config(&work_config) {
            Err(error) => Err(error.into()),
            Ok(work_config) => async {
                let authority = identity::open_authority(
                    &grant_config, passkey.map(commands::contributions::principal).transpose()?,
                ).await?;
                let contact = commands::contributions::load_contact(authority.owner().await?, &client_contact)?;
                commands::serve::run_provision(commands::serve::ProvisionOptions {
                    work_config,
                    // The bond is staked by the party this node already
                    // settles as, taken from the identity loaded above
                    // and never made here.
                    settlement_key: identity::settlement_signer(&local_identity)?,
                    provider: local_identity.enrollment.clone(),
                    addresses: Vec::new(),
                    client: contact,
                    client_node: hellas_kernel::Key::from_bytes(commands::paid_work::fixed_hex("--client", &client)?),
                    redelegate_payout: !lock_provider_payout,
                    stake_coins: stake_coin.iter().map(|coin| {
                        commands::paid_work::fixed_hex("--stake-coin", coin).map(hellas_kernel::CoinId::from_bytes)
                    }).collect::<anyhow::Result<_>>()?,
                    bond_timeout,
                    timeout_payout,
                    max_job_price,
                }, print_bond_only, chain_node, authority)
                .await
            }.await
        },
        Commands::Gateway {
            output_cache,
            store_dir,
            offer,
            grant_policy,
            work_profile,
            http_fetch_config,
            archive_dir,
            zdr,
            paid_work_config,
            chain_node,
            gateway_profile,
            allow_remote,
            chat_template,
            remote_trust,
            causal_lm,
            host,
            port,
            node_id,
            node_addrs,
            #[cfg(feature = "evaluate")]
            evaluation,
            retries,
            default_max_tokens,
            metrics_port,
            responses_backend,
            responses_proxy_url,
            responses_proxy_api_key_env,
            responses_fetch_route_service,
            responses_fetch_route_method,
            responses_fetch_execution_environment,
            responses_fetch_request_overrides,
            wrap,
            wrap_args,
        } => {
            async {
                #[cfg(feature = "evaluate")]
                let local_content = causal_lm.as_ref().map(|args| evaluation.content(args, store_dir.as_deref()));
                let cache_options =
                    commands::gateway_cache::options(output_cache, store_dir.clone())?;
                let (
                    loaded_environment,
                    model_name,
                    tokenizer,
                    stop_token_ids,
                ) = if let Some(CausalLmArgs {
                    environment,
                    manifest_id,
                    model,
                    tokenizer,
                    stop_token_ids,
                }) = causal_lm
                {
                    let loaded_environment =
                        commands::llm::load_environment(&environment, manifest_id)?;
                    let model_name = model.unwrap_or_else(|| {
                        loaded_environment.execution().manifest_id().to_string()
                    });
                    (
                        Some(loaded_environment.into_execution()),
                        model_name,
                        Some(tokenizer),
                        stop_token_ids,
                    )
                } else {
                    (None, String::new(), None, Vec::new())
                };
                let assurance = remote_trust.assurance;
                let application = work_profile.as_deref().map(hellas_sdk::node_control::profile::ClientProfile::load)
                    .transpose()?.map(std::sync::Arc::new);
                let work_application = || application.clone().ok_or_else(|| anyhow::anyhow!("--work-profile is required for grant Work"));
                let grant_target = if let Some(name) = offer.as_deref() {
                    let client = commands::contributions::require_principal(passkey)?;
                    let offer = commands::contributions::load_offer(&client, name)?;
                    Some(hellas_sdk::grant_client::UnpinnedOffer::decode(
                        &offer.encode()?,  hellas_auth::authority::UnixMillis(0),
                    )?.pin(&remote_trust.load()?)?)
                } else { None };
                let grant_source = if let Some(target) = grant_target
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly {
                    anyhow::ensure!(assurance == target.trust().required_assurance, "requested assurance differs from the pinned grant provider");
                    Some((commands::grant_gateway::session(target, &local_identity, commands::contributions::require_principal(passkey)?, work_application()?)?,
                        hellas_sdk::grant_client::GrantTransport::remote(secret_key.clone()).await?))
                } else { None };
                #[cfg(feature = "evaluate")]
                let (grant_source, grant_policy) = if evaluation.local && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly {
                    anyhow::ensure!(responses_backend == GatewayResponsesBackend::Hellas, "--local requires the Hellas execution backend");
                    anyhow::ensure!(grant_policy.as_deref().is_none_or(|name| name == "local"), "the local resource is named local");
                    anyhow::ensure!(assurance == hellas_rpc::Assurance::ProducerSigned, "local Work requires producer-signed assurance");
                    (Some(commands::grant_gateway::local::prepare(
                        local_content.ok_or_else(|| anyhow::anyhow!("--local requires indexed content"))?,
                        &local_identity, commands::contributions::require_principal(passkey)?, work_application()?, remote_trust.load()?,
                    ).await?), Some("local".into()))
                } else { (grant_source, grant_policy) };
                if let Some((session, _)) = grant_source.as_ref()
                    && hellas_sdk::grant_gateway::responses::selected_policy(&session.target, grant_policy.as_deref())?.is_some()
                {
                    anyhow::ensure!(paid_work_config.is_none() && loaded_environment.is_none(), "Responses grants require their own Fetch gateway");
                    anyhow::ensure!(output_cache == hellas_rpc::cache::CachePolicy::Off, "Responses grants require --output-cache off");
                    anyhow::ensure!(metrics_port.is_none(), "Responses Fetch does not support --metrics-port");
                    let hellas_sdk::node_control::profile::GatewayHost { access, control, .. } = hellas_sdk::node_control::profile::GatewayProfile::load(
                        gateway_profile.as_deref().ok_or_else(|| anyhow::anyhow!("--gateway-profile is required to serve HTTP"))?
                    ).await?;
                    let (session, transport) = grant_source.ok_or_else(|| anyhow::anyhow!("Responses grants require a transport"))?;
                    let gateway = hellas_sdk::grant_gateway::responses::start_fetch(
                        hellas_sdk::grant_gateway::responses::FetchGatewayOptions {
                            access, host, port, allow_remote, wrap, wrap_args,
                            archive: hellas_gateway::ArchiveOptions {
                                directory: archive_dir.map(Ok).unwrap_or_else(identity::default_gateway_archive_path)?, zdr,
                            },
                            session,
                            policy: grant_policy,
                            request_overrides: responses_fetch_request_overrides.unwrap_or_default(),
                        }, transport
                    ).await?;
                    let result = hellas_gateway::wait_for_shutdown(gateway).await.map_err(anyhow::Error::from);
                    return match control {
                        Some(control) => result.and(control.shutdown().await.map_err(anyhow::Error::from)),
                        None => result,
                    };
                }
                let hellas_sdk::node_control::profile::GatewayHost { access: gateway_access, control, node: authority } = hellas_sdk::node_control::profile::GatewayProfile::load(
                    gateway_profile.as_deref().ok_or_else(|| anyhow::anyhow!("--gateway-profile is required to serve HTTP"))?
                ).await?;
                let mut chain_shutdown = None;
                let paid_work = if let Some(path) = paid_work_config.as_ref()
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly
                {
                    anyhow::ensure!(
                        node_id.is_none()
                            && responses_backend == GatewayResponsesBackend::Hellas,
                        "--paid-work-config requires remote Hellas execution without --local, --node-id, or a Responses override",
                    );
                    anyhow::ensure!(http_fetch_config.is_some() || assurance == hellas_rpc::Assurance::ProducerSigned,
                        "token-native paid work uses producer-signed assurance");
                    let options = hellas_sdk::paid_gateway::load_pool_options(path, assurance)?;
                    let node = chain_node.start(&options.providers.first().ok_or_else(|| anyhow::anyhow!("paid pool has no providers"))?.config).await?;
                    chain_shutdown = Some(node.clone());
                    Some(
                        hellas_sdk::paid_gateway::PaidGateway::open(
                            options,
                            hellas_sdk::NodeIdentity::from_secret_bytes(secret_key.to_bytes(), local_identity.node_key.to_secret_bytes())?,
                            node,
                            authority,
                        ).await? as std::sync::Arc<dyn hellas_gateway::WorkExecutionBackend>
                    )
                } else {
                    None
                };

                anyhow::ensure!(grant_policy.is_none() || offer.is_some() || grant_source.is_some(), "--grant-policy requires a remote or local allowance");
                let grant_gateway = if let Some((session, transport)) = grant_source {
                    Some(hellas_sdk::grant_gateway::GrantGateway::open(session, transport, grant_policy).await?)
                } else { None };
                let paid_work = grant_gateway.as_ref().map(|backend| backend.clone() as std::sync::Arc<dyn hellas_gateway::WorkExecutionBackend>).or(paid_work);
                let shutdown = paid_work.clone();
                let result = async {
                let provider_trust = if paid_work.is_some()
                    || output_cache == hellas_rpc::cache::CachePolicy::ReplayOnly
                {
                    None
                } else {
                    gateway_provider_trust(responses_backend)?
                };
                let archive = hellas_gateway::ArchiveOptions {
                    directory: archive_dir.map(Ok).unwrap_or_else(identity::default_gateway_archive_path)?,
                    zdr,
                };
                let http_config = if let Some(path) = http_fetch_config {
                    let bytes = commands::read_bounded_regular_file(&path, "HTTP gateway config", 4 << 20)?;
                    Some(serde_json::from_slice(&bytes)?)
                } else if loaded_environment.is_none() {
                    grant_gateway.as_ref().map(|gateway| gateway.http_config()).transpose()?
                } else { None };
                let served = async {
                if let Some(config) = http_config {
                    anyhow::ensure!(output_cache == hellas_rpc::cache::CachePolicy::Off,
                        "HTTP routes archive exchanges; inference replay must be off");
                    anyhow::ensure!(metrics_port.is_none(), "HTTP Fetch exports OpenTelemetry metrics; --metrics-port is unsupported");
                    return hellas_gateway::run_http(hellas_gateway::HttpGatewayOptions {
                        config,
                        paid: paid_work.ok_or_else(|| anyhow::anyhow!("HTTP proxy requires a Work backend"))?,
                        archive, access: gateway_access, allow_remote, host, port, wrap, wrap_args,
                    }).await.map_err(anyhow::Error::from);
                }
                hellas_gateway::run(hellas_gateway::GatewayOptions {
                    archive,
                    output_cache: cache_options,
                    paid_work,
                    access: gateway_access,
            allow_remote,
                    chat_template,
                    host,
                    port,
                    node_id,
                    node_addrs,
                    retries,
                    default_max_tokens,
                    model_name,
                    causal_lm: loaded_environment,
                    tokenizer,
                    stop_token_ids,
                    metrics_port,
                    responses_backend: responses_backend.into(),
                    responses_proxy_url,
                    responses_proxy_api_key_env,
                    responses_fetch_route_service,
                    responses_fetch_route_method,
                    responses_fetch_execution_environment,
                    responses_fetch_request_overrides: responses_fetch_request_overrides
                        .unwrap_or_default(),
                    provider_trust,
                    producer_key: local_identity.node_key,
                    assurance,
                    secret_key,
                    wrap,
                    wrap_args,
                })
                .await.map_err(anyhow::Error::from)
                }.await;
                match control {
                    Some(control) => served.and(control.shutdown().await.map_err(anyhow::Error::from)),
                    None => served,
                }
                }.await;
                let mut result = result;
                if let Some(backend) = shutdown {
                    result = result.and(backend.drain().await.map_err(anyhow::Error::from));
                }
                if let Some(node) = chain_shutdown {
                    result = result.and(node.shutdown().await.map_err(anyhow::Error::from));
                }
                result
            }
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::PaidWork { command } => match identity::settlement_signer(&local_identity) {
            Ok(settlement_key) => async {
                commands::paid_work::run(
                    command,
                    secret_key,
                    settlement_key,
                    local_identity.node_key.clone(),
                    passkey.map(commands::contributions::principal).transpose()?,
                )
                .await
            }.await,
            Err(error) => Err(error),
        },
        Commands::Trust(args) => commands::trust::run(args),
        Commands::Chain { .. } => unreachable!("chain commands handled before identity load"),
        Commands::Store { .. } => unreachable!("store commands handled before identity load"),
        #[cfg(unix)]
        Commands::Machines(_) => {
            unreachable!("management commands handled before identity load")
        }
        Commands::Environment { .. } => {
            unreachable!("environment commands handled before identity load")
        }
        Commands::Identity { command } => match command {
            IdentityCommand::Init => Ok(()),
            IdentityCommand::ShowNodeId => commands::identity::show_node_id(&secret_key),
            IdentityCommand::ShowEnrollmentId => {
                commands::identity::show_enrollment_id(&local_identity.enrollment)
            }
            IdentityCommand::ShowHolder => commands::identity::show_holder(&local_identity.node_key),
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
