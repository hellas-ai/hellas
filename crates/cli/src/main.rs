#[macro_use]
extern crate tracing;

#[cfg(feature = "gateway")]
use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};
use iroh::EndpointId;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(feature = "evaluate")]
use std::time::Duration;

#[cfg(all(feature = "cloud", unix))]
mod cloud;
mod commands;
mod identity;
#[cfg(feature = "node")]
mod metrics;
#[cfg(feature = "node")]
mod platform_hardening;
mod tracing_config;

#[cfg(feature = "node")]
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
    #[cfg(feature = "node")]
    let settles_paid_work = matches!(
        command,
        Commands::Serve {
            work_config_file: Some(_),
            ..
        } | Commands::Provision { .. }
            | Commands::PaidWork { .. }
    );
    #[cfg(not(feature = "node"))]
    let settles_paid_work = false;
    #[cfg(all(feature = "node", feature = "gateway"))]
    let settles_paid_work = settles_paid_work
        || matches!(
            command,
            Commands::Gateway {
                paid_work_config: Some(_),
                ..
            }
        );
    #[cfg(all(feature = "cloud", unix))]
    let owned_machine = command.owned_machine().is_some();
    #[cfg(not(all(feature = "cloud", unix)))]
    let owned_machine = false;
    let grant_identity = matches!(command, Commands::Contact { .. } | Commands::Offer { .. });
    #[cfg(feature = "node")]
    let grant_identity = grant_identity || matches!(command, Commands::Admin(_));
    #[cfg(feature = "gateway")]
    let grant_identity =
        grant_identity || matches!(command, Commands::Gateway { offer: Some(_), .. });
    #[cfg(feature = "evaluate")]
    let grant_identity = grant_identity || matches!(command, Commands::Gateway { local: true, .. });
    let read_only = grant_identity
        || owned_machine
        || settles_paid_work
        || matches!(
            command,
            Commands::Identity {
                command: IdentityCommand::ShowNodeId | IdentityCommand::ShowEnrollmentId,
            }
        );
    if read_only {
        identity::load_existing(path)
    } else {
        identity::load_or_create(path)
    }
}

#[cfg(feature = "gateway")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum GatewayResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

#[cfg(feature = "gateway")]
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
#[cfg(feature = "gateway")]
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

    /// Out-of-band ContentId pin for the remote node's canonical enrollment
    /// bundle. This is a hash asserted by the caller, not a document learned
    /// from the node being checked.
    #[arg(
        long = "provider",
        value_name = "CONTENT_ID",
        value_parser = parse_content_id_hex
    )]
    provider_genesis: Option<hellas_rpc::ContentId>,

    /// Apple App Attest application CDhashes trusted for confidential open.
    /// Repeat the flag or pass a comma-separated list of 32-byte hex values.
    #[arg(
        long = "apple-app-attest-cdhashes",
        value_delimiter = ',',
        value_parser = parse_hex_array::<32>
    )]
    apple_app_attest_cdhashes: Vec<[u8; 32]>,

    /// Apple App Attest application identity in <teamID>.<bundleID> form.
    #[arg(long = "apple-app-attest-app-id")]
    apple_app_attest_app_id: Option<String>,
}

/// One canonical causal-LM route and its untrusted text-presentation boundary.
#[cfg(feature = "llm")]
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

    /// Local files that satisfy exact program/static content references.
    /// Repeat for multiple objects; used only by local execution legs.
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content",
        value_name = "PATH",
        requires = "causal_lm_local_mode"
    )]
    content_paths: Vec<PathBuf>,

    /// Directory trees to adopt as local content. No network fetch or
    /// compilation occurs; used only by local execution legs.
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content-root",
        value_name = "DIR",
        requires = "causal_lm_local_mode"
    )]
    content_roots: Vec<PathBuf>,

    /// Fast-resume content index (default: Hellas store state).
    #[cfg(feature = "evaluate")]
    #[arg(
        long = "content-index",
        value_name = "FILE",
        requires = "causal_lm_local_mode"
    )]
    content_index: Option<PathBuf>,

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
}

#[derive(Subcommand)]
enum ProducerKeyCommand {
    /// Print the producer public key and derived producer id
    Show,
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
    #[cfg(all(feature = "cloud", unix))]
    /// Provision and inspect remote Hellas workers.
    Cloud(hellas_cloud::cloud::CloudArgs),
    #[cfg(all(feature = "cloud", unix))]
    /// Discover and administer machines owned by the selected Hellas identity.
    Machines(hellas_cloud::machines::MachinesArgs),
    /// Share this identity's verified public enrollment.
    Contact {
        #[command(subcommand)]
        command: commands::contributions::ContactCommand,
    },
    /// Import a private provider Offer addressed to this identity.
    Offer {
        #[command(subcommand)]
        command: commands::contributions::OfferCommand,
    },
    #[cfg(any(feature = "node", all(feature = "cloud", unix)))]
    /// Administer this node and its users.
    Admin(commands::admin::AdminArgs),
    #[cfg(feature = "node")]
    /// Run the RPC server
    Serve {
        /// Content store state used by local execution (default: HELLAS_STORE_DIR or ~/.hellas/store).
        #[cfg(feature = "evaluate")]
        #[arg(long)]
        store_dir: Option<PathBuf>,
        /// Assurance offered by this provider.
        #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
        assurance: hellas_rpc::Assurance,
        /// Port to listen on. Omit it to let the OS select an available port.
        #[arg(long)]
        port: Option<u16>,
        /// Maximum number of queued executions waiting behind the active worker
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
        /// Local files that may satisfy content references in submitted
        /// canonical causal-LM environments. Repeat for programs/assets.
        #[cfg(feature = "evaluate")]
        #[arg(long = "content", value_name = "PATH")]
        content_paths: Vec<PathBuf>,
        /// Directory tree to adopt into the local content store. Repeat for
        /// HuggingFace/Xet cache roots; no remote fetch is performed.
        #[cfg(feature = "evaluate")]
        #[arg(long = "content-root", value_name = "DIR")]
        content_roots: Vec<PathBuf>,
        /// Fast-resume index for local content (default: ~/.hellas/content-index.bin).
        #[cfg(feature = "evaluate")]
        #[arg(long = "content-index", value_name = "FILE")]
        content_index: Option<PathBuf>,
        /// GPU runtime to use: auto, hip, or cuda.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-backend", default_value_t = hellas_executor::GpuBackend::Auto)]
        gpu_backend: hellas_executor::GpuBackend,
        /// Maximum distinct Catena programs retained in one GPU session.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-session-programs", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_PROGRAMS, value_parser = parse_positive_usize)]
        gpu_session_programs: usize,
        /// Maximum aggregate static asset bytes retained in one GPU session.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-session-asset-bytes", default_value_t = hellas_executor::DEFAULT_GPU_SESSION_ASSET_BYTES, value_parser = parse_positive_u64)]
        gpu_session_asset_bytes: u64,
        /// Maximum prompt-plus-output capacity of one GPU generation (at most
        /// 524288 so retained token output fits the artifact transport).
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-max-generation-capacity", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_CAPACITY, value_parser = parse_gpu_generation_capacity)]
        gpu_max_generation_capacity: u64,
        /// Maximum non-asset device bytes owned or allocated by one GPU generation.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-max-generation-device-bytes", default_value_t = hellas_executor::DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES, value_parser = parse_positive_u64)]
        gpu_max_generation_device_bytes: u64,
        /// Maximum seconds spent loading and compiling one Catena program.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-compile-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_COMPILE_TIMEOUT_SECS, value_parser = parse_positive_u64)]
        gpu_compile_timeout_secs: u64,
        /// Maximum seconds for one GPU control operation or full generation.
        #[cfg(feature = "evaluate")]
        #[arg(long = "gpu-execution-timeout-secs", default_value_t = hellas_executor::DEFAULT_GPU_EXECUTION_TIMEOUT_SECS, value_parser = parse_positive_u64)]
        gpu_execution_timeout_secs: u64,
        /// Paid-work configuration. Its presence serves WorkSetup and Work;
        /// Work remains retryably not ready until the configured state mounts.
        #[arg(long = "work-config")]
        work_config_file: Option<PathBuf>,
        /// Grant resources and machine safety limits; no chain configuration is needed.
        #[arg(long = "grant-config")]
        grant_config_file: Option<PathBuf>,
        /// Explicitly initialize the local identity as owner.
        #[arg(long, conflicts_with_all = ["owner_enrollment", "check_config"])]
        init_owner: bool,
        /// Authenticated managed-machine owner enrollment supplied by the agent.
        #[arg(long, value_name = "FILE", conflicts_with = "check_config")]
        owner_enrollment: Option<PathBuf>,

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
    #[cfg(feature = "gateway")]
    /// Run HTTP gateway exposing OpenAI/Anthropic/plain APIs over Hellas network
    ///
    /// Every route requires `Authorization: Bearer <token>`. Use
    /// --bearer-token-file to retain the credential across restarts.
    /// Hellas routes use the configured causal-LM environment; the shared
    /// model adapter handles text and tool calls using --tokenizer and
    /// --chat-template.
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_mode")
                .args(["local"])
        ))
    )]
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_content")
                .args(["content_paths", "content_roots"])
                .multiple(true)
        ))
    )]
    #[command(
        mut_arg("environment", |arg| arg
            .required(false)
            .required_unless_present_any(["responses_backend", "http_fetch_config", "offer"])
            .required_if_eq("responses_backend", "hellas")
            .requires("tokenizer")),
        mut_arg("tokenizer", |arg| arg.required(false).requires("environment"))
    )]
    #[cfg_attr(all(feature = "cloud", unix), command(group(
        clap::ArgGroup::new("remote_target").args(["node_id", "machine"])
    )))]
    #[cfg_attr(all(feature = "cloud", unix), command(mut_arg("environment", |arg| arg.required_unless_present_any(["responses_backend", "http_fetch_config", "offer", "machine"]))))]
    Gateway {
        /// Inference reuse policy; record mode fails requests if cache writes fail.
        #[arg(long, default_value = "off")]
        output_cache: hellas_rpc::cache::CachePolicy,
        /// Content and output cache state (default: HELLAS_STORE_DIR or ~/.hellas/store).
        #[arg(long)]
        store_dir: Option<PathBuf>,
        /// Use a private Offer previously verified by `offer import`.
        #[arg(long, value_name = "ALIAS", conflicts_with_all = ["node_id", "node_addrs", "provider_genesis", "responses_backend", "http_fetch_config"])]
        #[cfg_attr(feature = "node", arg(conflicts_with = "paid_work_config"))]
        #[cfg_attr(all(feature = "cloud", unix), arg(conflicts_with = "machine"))]
        #[cfg_attr(feature = "evaluate", arg(conflicts_with = "local"))]
        offer: Option<String>,
        /// Select one resource when the Offer includes several matching policies.
        #[arg(long)]
        grant_policy: Option<String>,
        /// Serve exact HTTP routes through paid HTTPS Fetch.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["responses_backend", "environment"])]
        #[cfg_attr(all(feature = "cloud", unix), arg(conflicts_with = "machine"))]
        #[cfg_attr(feature = "node", arg(requires = "paid_work_config"))]
        http_fetch_config: Option<PathBuf>,
        /// Request/response archive directory (default: ~/.hellas/gateway-archive).
        #[arg(long, value_name = "DIRECTORY")]
        archive_dir: Option<PathBuf>,
        /// Disable payload archives and require ZDR for every HTTP request.
        #[arg(long)]
        zdr: bool,
        /// Pay a pool of providers using durable on-chain funded work channels.
        #[cfg(feature = "node")]
        #[arg(long = "paid-work-config", value_name = "FILE")]
        paid_work_config: Option<PathBuf>,
        /// Load a private bearer credential file, creating it when absent.
        #[arg(long = "bearer-token-file", value_name = "FILE")]
        bearer_token_file: Option<PathBuf>,
        /// Allow a non-loopback listener; requires --bearer-token-file.
        #[arg(long)]
        allow_remote: bool,
        /// Explicit local text-chat template.
        #[arg(long = "chat-template", value_name = "TEMPLATE")]
        chat_template: Option<hellas_presentation::ChatTemplate>,
        /// Select an owned machine from this identity's inventory.
        #[cfg(all(feature = "cloud", unix))]
        #[arg(long, conflicts_with_all = ["node_id", "provider_genesis", "apple_app_attest_app_id", "apple_app_attest_cdhashes"])]
        #[cfg_attr(feature = "evaluate", arg(conflicts_with = "local"))]
        #[cfg_attr(feature = "node", arg(conflicts_with = "paid_work_config"))]
        machine: Option<String>,
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
        #[cfg_attr(all(feature = "cloud", unix), arg(requires = "remote_target"))]
        #[cfg_attr(not(all(feature = "cloud", unix)), arg(requires = "node_id"))]
        node_addrs: Vec<SocketAddr>,
        /// Execute locally through this identity's durable owner grant
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "local",
            default_value_t = false,
            conflicts_with_all = ["node_id", "node_addrs"],
            requires = "causal_lm_local_content"
        )]
        local: bool,
        /// Maximum number of queued local executions when `--local` is set
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "queue-size",
            default_value_t = hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY
        )]
        queue_size: usize,
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
        /// Built-in Fetch environment alias (`codex-responses` or
        /// `openai-responses`) or exact ProgramManifest ContentId expected from
        /// the provider route.
        #[arg(
            long = "responses-fetch-execution-environment",
            required_if_eq("responses_backend", "fetch"),
            value_parser = parse_fetch_environment
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
    #[cfg(feature = "node")]
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
    #[cfg(feature = "chain")]
    Chain {
        #[command(subcommand)]
        command: commands::chain::ChainCommand,
    },
    /// Inspect the local identity file
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Inspect the local producer signing key
    ProducerKey {
        #[command(subcommand)]
        command: ProducerKeyCommand,
    },
    /// Manage Codex OAuth credentials
    CodexAuth {
        #[command(subcommand)]
        command: CodexAuthCommand,
    },
    #[cfg(feature = "node")]
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
        /// The paid-work configuration this offer is made under
        #[arg(long = "work-config")]
        work_config: PathBuf,
        /// The client this bond names as taker, hex-encoded
        #[arg(long = "client")]
        client: String,
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
        /// Print the deterministic bond edge and exit before evidence,
        /// routes, validators, or journals are opened.
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

#[cfg(all(feature = "cloud", unix))]
impl Commands {
    fn owned_machine(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "gateway")]
            Self::Gateway { machine, .. } => machine.as_deref(),
            _ => None,
        }
    }
}

fn validate_identity_options(
    command: &Commands,
    identity: Option<&Path>,
    software_root: bool,
) -> Result<(), String> {
    let identity_free = match command {
        Commands::Store { .. } => Some("store"),
        Commands::Environment { .. } => Some("environment"),
        #[cfg(feature = "node")]
        Commands::Serve {
            check_config: true, ..
        } => Some("serve --check-config"),
        #[cfg(feature = "chain")]
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

    let reads_existing_identity = match command {
        #[cfg(all(feature = "cloud", unix))]
        command if command.owned_machine().is_some() => true,
        #[cfg(all(feature = "cloud", unix))]
        Commands::Cloud(_) | Commands::Machines(_) => true,
        Commands::Contact { .. } | Commands::Offer { .. } => true,
        #[cfg(feature = "gateway")]
        Commands::Gateway { offer: Some(_), .. } => true,
        #[cfg(any(feature = "node", all(feature = "cloud", unix)))]
        Commands::Admin(_) => true,
        Commands::Identity {
            command: IdentityCommand::ShowNodeId | IdentityCommand::ShowEnrollmentId,
        }
        | Commands::ProducerKey { .. } => true,
        #[cfg(feature = "node")]
        Commands::Serve {
            work_config_file: Some(_),
            ..
        }
        | Commands::Provision { .. } => true,
        #[cfg(feature = "node")]
        Commands::PaidWork { .. } => true,
        #[cfg(all(feature = "node", feature = "gateway"))]
        Commands::Gateway {
            paid_work_config: Some(_),
            ..
        } => true,
        _ => false,
    };
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
    #[cfg(feature = "node")]
    if let Commands::Serve { assurance, .. } = &cli.command
        && let Err(error) = validate_serve_assurance(cli.software_root, *assurance, None)
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    #[cfg(feature = "node")]
    if matches!(&cli.command, Commands::Serve { .. })
        && let Err(err) = platform_hardening::harden_provider_process()
    {
        eprintln!("error: failed to harden provider process: {err}");
        std::process::exit(1);
    }
    let tracer_provider = tracing_config::init_tracing(cli.log_file.as_deref());
    #[cfg(feature = "node")]
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

    if let Commands::ProducerKey {
        command: ProducerKeyCommand::Show,
    } = &cli.command
    {
        let result = identity::load_existing(cli.identity.as_deref())
            .and_then(|identity| commands::identity::show_producer_key(&identity.producer_key));
        tracer_provider.shutdown();
        if let Err(err) = result {
            eprintln!("error: {err:#}");
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
        #[cfg(all(feature = "cloud", unix))]
        command @ Commands::Admin(commands::admin::AdminArgs {
            command: commands::admin::AdminCommand::Serve { .. },
            ..
        }) => {
            let result = cloud::run(command, cli.identity.as_deref()).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(all(feature = "cloud", unix))]
        command @ (Commands::Cloud(_) | Commands::Machines(_)) => {
            let result = cloud::run(command, cli.identity.as_deref()).await;
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

    #[cfg(feature = "chain")]
    let command = match command {
        Commands::Chain { command } => {
            let result = commands::chain::run(command).await;
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
    #[cfg(feature = "node")]
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
        Commands::Contact { command } => commands::contributions::contact(command, &local_identity),
        Commands::Offer { command } => commands::contributions::offer(command, &local_identity),
        #[cfg(feature = "node")]
        Commands::Admin(args) => commands::admin::users::run(args, &local_identity).await,
        #[cfg(all(feature = "cloud", unix, not(feature = "node")))]
        Commands::Admin(_) => unreachable!("admin serve returned above"),

        #[cfg(feature = "node")]
        Commands::Serve {
            #[cfg(feature = "evaluate")]
            store_dir,
            assurance,
            port,
            queue_size,
            #[cfg(feature = "evaluate")]
            content_paths,
            #[cfg(feature = "evaluate")]
            content_roots,
            #[cfg(feature = "evaluate")]
            content_index,
            #[cfg(feature = "evaluate")]
            gpu_session_programs,
            #[cfg(feature = "evaluate")]
            gpu_backend,
            #[cfg(feature = "evaluate")]
            gpu_session_asset_bytes,
            #[cfg(feature = "evaluate")]
            gpu_max_generation_capacity,
            #[cfg(feature = "evaluate")]
            gpu_max_generation_device_bytes,
            #[cfg(feature = "evaluate")]
            gpu_compile_timeout_secs,
            #[cfg(feature = "evaluate")]
            gpu_execution_timeout_secs,
            work_config_file,
            grant_config_file,
            init_owner,
            owner_enrollment,
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
                        let settlement_key = identity::settlement_signer(&local_identity);
                        let open_identity = local_identity.open_identity();
                        let grants = if grant_config_file.is_some() || init_owner || owner_enrollment.is_some() {
                            anyhow::ensure!(assurance == hellas_rpc::Assurance::ProducerSigned, "grants require producer-signed assurance");
                            let provider = commands::contributions::principal(&local_identity)?;
                            let root = commands::contributions::data_root(&provider)?;
                            let config = if let Some(path) = grant_config_file.as_deref() {
                                hellas_sdk::grant_config::GrantConfig::load(path, &root)?
                            } else { hellas_sdk::grant_config::GrantConfig::unconfigured(&root) };
                            let owner = if init_owner { Some(provider.clone()) } else {
                                owner_enrollment.as_deref().map(|path| {
                                    let bytes = commands::read_bounded_regular_file(path, "owner enrollment", hellas_rpc::protocol::work_grant::records::MAX_PRINCIPAL_BYTES)?;
                                    Ok::<_,anyhow::Error>(hellas_rpc::protocol::work_grant::records::Principal::decode(&bytes)?)
                                }).transpose()?
                            };
                            Some(commands::serve::GrantNodeConfig { config, provider, owner })
                        } else { None };

                        #[cfg(feature = "evaluate")]
                        let gpu_config = hellas_executor::GpuConfig::new(
                            gpu_session_programs,
                            gpu_session_asset_bytes,
                            gpu_max_generation_capacity,
                            gpu_max_generation_device_bytes,
                            Duration::from_secs(gpu_compile_timeout_secs),
                            Duration::from_secs(gpu_execution_timeout_secs),
                        )
                        .map_err(anyhow::Error::msg)?
                        .with_backend(gpu_backend);
                        commands::serve::run(commands::serve::ServeOptions {
                            port,
                            queue_size,
                            #[cfg(feature = "evaluate")]
                            content_paths,
                            #[cfg(feature = "evaluate")]
                            content_roots,
                            #[cfg(feature = "evaluate")]
                            content_index: content_index.or_else(|| {
                                store_dir
                                    .as_deref()
                                    .map(hellas_store::state::records_path_at)
                            }),
                            #[cfg(feature = "evaluate")]
                            gpu_config,
                            work_config,
                            grants,
                            metrics_port,
                            graffiti,
                            fetch_config_file,
                            fetch_max_in_flight,
                            fetch_queue_size,
                            secret_key,
                            producer_key: local_identity.producer_key,
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
        #[cfg(feature = "node")]
        Commands::Provision {
            work_config,
            client,
            stake_coin,
            bond_timeout,
            timeout_payout,
            max_job_price,
            print_bond_only,
        } => match commands::serve::load_work_config(&work_config) {
            Err(error) => Err(error.into()),
            Ok(work_config) => async {
                commands::serve::run_provision(commands::serve::ProvisionOptions {
                    work_config,
                    // The bond is staked by the party this node already
                    // settles as, taken from the identity loaded above
                    // and never made here.
                    settlement_key: identity::settlement_signer(&local_identity),
                    provider: local_identity.enrollment.clone(),
                    addresses: Vec::new(),
                    client: hellas_kernel::Key::from_bytes(commands::paid_work::fixed_hex("--client", &client)?),
                    stake_coins: stake_coin.iter().map(|coin| {
                        commands::paid_work::fixed_hex("--stake-coin", coin).map(hellas_kernel::CoinId::from_bytes)
                    }).collect::<anyhow::Result<_>>()?,
                    bond_timeout,
                    timeout_payout,
                    max_job_price,
                }, print_bond_only)
                .await
            }.await
        },
        #[cfg(feature = "gateway")]
        Commands::Gateway {
            output_cache,
            store_dir,
            offer,
            grant_policy,
            http_fetch_config,
            archive_dir,
            zdr,
            #[cfg(feature = "node")]
            paid_work_config,
            bearer_token_file,
            allow_remote,
            chat_template,
            #[cfg(all(feature = "cloud", unix))]
            machine,
            remote_trust,
            causal_lm,
            host,
            port,
            node_id,
            node_addrs,
            #[cfg(feature = "evaluate")]
            local,
            #[cfg(feature = "evaluate")]
            queue_size,
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
                let local_content = causal_lm.as_ref().map(|args| commands::grant_gateway::local::LocalContent {
                    paths: std::iter::once(args.environment.clone()).chain(args.content_paths.iter().cloned()).collect(),
                    roots: args.content_roots.clone(),
                    index: args.content_index.clone().or_else(|| store_dir.as_deref().map(hellas_store::state::records_path_at)),
                    queue_size,
                });
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
                    #[cfg(feature = "evaluate")]
                    content_paths: _,
                    #[cfg(feature = "evaluate")]
                    content_roots: _,
                    #[cfg(feature = "evaluate")]
                    content_index: _,
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
                #[cfg(all(feature = "cloud", unix))]
                anyhow::ensure!(
                    machine.is_none() || responses_backend != GatewayResponsesBackend::Proxy,
                    "--machine cannot be used with the external proxy backend"
                );
                let assurance = remote_trust.assurance;
                #[cfg(all(feature = "node", not(feature = "evaluate")))]
                let local = false;
                #[cfg(feature = "node")]
                let paid_work = if let Some(path) = paid_work_config.as_ref()
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly
                {
                    anyhow::ensure!(
                        !local && node_id.is_none()
                            && responses_backend == GatewayResponsesBackend::Hellas,
                        "--paid-work-config requires remote Hellas execution without --local, --node-id, or a Responses override",
                    );
                    #[cfg(feature = "evaluate")]
                    anyhow::ensure!(http_fetch_config.is_some() || assurance == hellas_rpc::Assurance::ProducerSigned,
                        "token-native paid work uses producer-signed assurance");
                    anyhow::ensure!(
                        remote_trust.provider_genesis.is_none()
                            && remote_trust.apple_app_attest_app_id.is_none()
                            && remote_trust.apple_app_attest_cdhashes.is_empty(),
                        "set provider enrollment and Apple trust pins in --paid-work-config",
                    );
                    Some(
                        hellas_sdk::paid_gateway::PaidGateway::open(
                            hellas_sdk::paid_gateway::load_pool_options(path, assurance)?,
                            hellas_sdk::ClientIdentity::from_secret_bytes(secret_key.to_bytes(), local_identity.producer_key.to_secret_bytes())?,
                        ).await? as std::sync::Arc<dyn hellas_gateway::WorkExecutionBackend>
                    )
                } else {
                    None
                };
                #[cfg(not(feature = "node"))]
                let paid_work = None;
                let grant_target = if let Some(name) = offer.as_deref() {
                    let client = commands::contributions::principal(&local_identity)?;
                    let offer = commands::contributions::load_offer(&client, name)?;
                    Some(hellas_sdk::grant_client::UnpinnedOffer::decode(
                        &offer.encode()?, client.id(), hellas_rpc::protocol::work_grant::UnixMillis(0),
                    )?.pin(&identity::provider_trust(
                        Some(offer.offer().provider.content_id()), assurance,
                        remote_trust.apple_app_attest_app_id.clone(),
                        remote_trust.apple_app_attest_cdhashes.clone(),
                    )?)?)
                } else { None };
                #[cfg(all(feature = "cloud", unix))]
                let grant_target = if let Some(name) = machine.as_deref()
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly {
                    Some(cloud::machine_target(name, &local_identity, node_addrs.clone()).await?)
                } else { grant_target };
                #[cfg(feature = "evaluate")]
                let local_grant = if local && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly {
                    anyhow::ensure!(responses_backend == GatewayResponsesBackend::Hellas, "--local requires the Hellas execution backend");
                    anyhow::ensure!(grant_policy.as_deref().is_none_or(|name| name == "local"), "the local owner resource is named local");
                    anyhow::ensure!(assurance == hellas_rpc::Assurance::ProducerSigned, "local Work requires producer-signed assurance");
                    Some(commands::grant_gateway::local::open(
                        loaded_environment.as_ref().ok_or_else(|| anyhow::anyhow!("--local requires a causal-LM environment"))?.environment(),
                        &stop_token_ids,
                        local_content.ok_or_else(|| anyhow::anyhow!("--local requires indexed content"))?,
                        &local_identity,
                    ).await?)
                } else { None };
                #[cfg(not(feature = "evaluate"))]
                let local_grant = None;
                anyhow::ensure!(grant_policy.is_none() || grant_target.is_some() || local_grant.is_some(), "--grant-policy requires an Offer or owner grant");
                let grant_gateway = if let Some(target) = grant_target
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly {
                    anyhow::ensure!(assurance == target.trust().required_assurance, "requested assurance differs from the pinned grant provider");
                    Some(commands::grant_gateway::remote(target, &local_identity, grant_policy).await?)
                } else { None };
                let grant_gateway = grant_gateway.or(local_grant);
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
                if let Some(config) = http_config {
                    anyhow::ensure!(output_cache == hellas_rpc::cache::CachePolicy::Off,
                        "HTTP routes archive exchanges; inference replay must be off");
                    anyhow::ensure!(metrics_port.is_none(), "HTTP Fetch exports OpenTelemetry metrics; --metrics-port is unsupported");
                    return hellas_gateway::run_http(hellas_gateway::HttpGatewayOptions {
                        config,
                        paid: paid_work.ok_or_else(|| anyhow::anyhow!("HTTP proxy requires a Work backend"))?,
                        archive, bearer_token_file, allow_remote, host, port, wrap, wrap_args,
                    }).await;
                }
                hellas_gateway::run(hellas_gateway::GatewayOptions {
                    archive,
                    output_cache: cache_options,
                    paid_work,
                    bearer_token_file,
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
                    producer_key: local_identity.producer_key,
                    assurance,
                    secret_key,
                    wrap,
                    wrap_args,
                })
                .await
                }.await;
                if let Some(backend) = shutdown { backend.drain().await; }
                result
            }
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        #[cfg(feature = "node")]
        Commands::PaidWork { command } => {
            commands::paid_work::run(
                command,
                secret_key,
                identity::settlement_signer(&local_identity),
                local_identity.producer_key.clone(),
            )
            .await
        }
        #[cfg(feature = "chain")]
        Commands::Chain { .. } => unreachable!("chain commands handled before identity load"),
        Commands::Store { .. } => unreachable!("store commands handled before identity load"),
        #[cfg(all(feature = "cloud", unix))]
        Commands::Cloud(_) | Commands::Machines(_) => {
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
        },
        Commands::ProducerKey { .. } => unreachable!("producer-key handled before identity load"),
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
