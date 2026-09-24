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
    let read_only = owned_machine
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

/// The trust anchor this gateway's remote routes are built from, or
/// `None` for a gateway that has none to build.
///
/// Every non-local Hellas route dials either a direct node or discovery, and
/// Fetch always dials remotely. Their trust anchor is required before the
/// gateway binds; local Hellas execution and a proxy-only gateway need none.
#[cfg(feature = "gateway")]
fn gateway_provider_trust(
    local: bool,
    responses_backend: GatewayResponsesBackend,
    expected_genesis: Option<hellas_rpc::ContentId>,
    assurance: hellas_rpc::Assurance,
    apple_app_attest_app_id: Option<String>,
    apple_app_attest_cdhashes: Vec<[u8; 32]>,
) -> anyhow::Result<Option<hellas_client::ProviderTrustAnchor>> {
    let dials_provider = (responses_backend == GatewayResponsesBackend::Hellas && !local)
        || responses_backend == GatewayResponsesBackend::Fetch;
    if !dials_provider && expected_genesis.is_none() {
        return Ok(None);
    }
    identity::provider_trust(
        expected_genesis,
        assurance,
        apple_app_attest_app_id,
        apple_app_attest_cdhashes,
    )
    .map(Some)
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
    /// Inference reuse policy shared by execution commands. In record mode,
    /// a cache write failure fails the request, even if inference succeeded.
    #[arg(long, global = true, default_value = "off")]
    output_cache: hellas_rpc::cache::CachePolicy,

    /// Hellas content store state (default: HELLAS_STORE_DIR or ~/.hellas/store)
    #[arg(long, global = true)]
    store_dir: Option<PathBuf>,
    /// Serve local control RPC on an owner-only Unix socket (gateway/serve)
    #[arg(long, global = true)]
    control_socket: Option<PathBuf>,
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
    #[cfg(all(feature = "cloud", unix))]
    /// Internal management RPC for local applications.
    Control(hellas_cloud::machines::ControlArgs),
    #[cfg(feature = "node")]
    /// Run the RPC server
    Serve {
        /// Iroh peers allowed to administer this node, including reading/exporting
        /// all cached transcripts and clearing them. Omitted means no remote admin.
        #[arg(long = "admin-peer")]
        admin_peers: Vec<iroh::EndpointId>,
        /// Restrict every inbound Hellas RPC connection to this owner identity.
        #[arg(long)]
        owner: Option<EndpointId>,
        /// Assurance offered by this provider.
        #[arg(long, default_value = "producer-signed", value_parser = parse_assurance)]
        assurance: hellas_rpc::Assurance,
        /// Port to listen on. Omit it to let the OS select an available port.
        #[arg(long)]
        port: Option<u16>,
        /// Evaluate policy: 'none' (default), 'any', or
        /// 'only(EXECUTION_ENVIRONMENT_ID_GLOB,...)'.
        #[arg(long = "execute-policy", default_value = "none")]
        execute_policy: hellas_rpc::policy::ExecutePolicy,
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
        /// Fast-resume index for local content (default: under the artifact
        /// store directory).
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
        /// Maximum distinct retained Evaluate executions. Zero disables new
        /// retained completions. The value is persisted per artifact-store
        /// root; stop every sharing process before changing it.
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "evaluate-retained-execution-capacity",
            default_value_t = hellas_executor::DEFAULT_EVALUATE_RETAINED_EXECUTION_CAPACITY
        )]
        evaluate_retained_execution_capacity: usize,
        /// Persistent canonical artifact blob store path (default: $HOME/.hellas/artifacts)
        #[arg(long = "artifact-store-path")]
        artifact_store_path: Option<PathBuf>,
        /// Paid-work configuration. Its presence serves WorkSetup and Work;
        /// Work remains retryably not ready until the configured state mounts.
        #[arg(long = "work-config")]
        work_config_file: Option<PathBuf>,
        /// Prometheus metrics port (e.g. 9090)
        #[arg(long = "metrics-port")]
        metrics_port: Option<u16>,
        /// Operator graffiti tag (up to 16 bytes, padded/truncated)
        #[arg(long = "graffiti", default_value = "")]
        graffiti: String,
        /// Fetch configuration file: sealed upstream destinations and
        /// credentials, route capabilities, and caller access policy. No file
        /// means this node serves no Fetch routes.
        #[arg(long = "fetch-config")]
        fetch_config_file: Option<PathBuf>,
        /// Validate fetch routes and credentials without starting a node.
        #[arg(long, requires = "fetch_config_file")]
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
        /// Maximum distinct retained Fetch inputs across completed transcripts
        /// and indeterminate running markers. Zero disables new retention. The
        /// value is persisted per store root; stop every process sharing that
        /// root before changing it or removing its capacity metadata.
        #[arg(
            long = "fetch-retained-transcript-capacity",
            default_value_t = hellas_rpc::DEFAULT_FETCH_RETAINED_TRANSCRIPT_CAPACITY
        )]
        fetch_retained_transcript_capacity: usize,
        /// Maximum retained Fetch replays with a live, not-yet-drained consumer.
        #[arg(
            long = "fetch-replay-max-in-flight",
            default_value_t = hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            value_parser = parse_positive_usize
        )]
        fetch_replay_max_in_flight: usize,
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
                .args(["local", "verify_local"])
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
            .required_unless_present_any(["responses_backend", "http_fetch_config"])
            .required_if_eq("responses_backend", "hellas")
            .requires("tokenizer")),
        mut_arg("tokenizer", |arg| arg.required(false).requires("environment"))
    )]
    #[cfg_attr(all(feature = "cloud", unix), command(group(
        clap::ArgGroup::new("remote_target").args(["node_id", "machine"])
    )))]
    Gateway {
        /// Serve exact HTTP routes through the generic HTTPS Fetch environment.
        #[arg(long, value_name = "FILE", conflicts_with_all = ["responses_backend", "environment"])]
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
        #[arg(long = "node-addr", value_delimiter = ',')]
        #[cfg_attr(all(feature = "cloud", unix), arg(requires = "remote_target"))]
        #[cfg_attr(not(all(feature = "cloud", unix)), arg(requires = "node_id"))]
        node_addrs: Vec<SocketAddr>,
        /// Run locally with Catena instead of the Hellas network
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "local",
            default_value_t = false,
            conflicts_with_all = ["node_id", "node_addrs"],
            requires = "causal_lm_local_content"
        )]
        local: bool,
        /// Run remotely and verify that the response matches local Catena execution
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with_all = ["local", "verify"],
            requires = "causal_lm_local_content"
        )]
        verify_local: bool,
        /// Verify the primary remote node against a second remote node
        #[cfg_attr(
            feature = "evaluate",
            arg(
                long = "verify",
                conflicts_with_all = ["local", "verify_local"],
                requires = "node_id"
            )
        )]
        #[cfg_attr(not(feature = "evaluate"), arg(long = "verify", requires = "node_id"))]
        verify: Option<EndpointId>,
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
    /// Inspect and prune inference recordings
    OutputCache(commands::output_cache::OutputCacheArgs),
    /// Query a remote node via RPC
    Rpc {
        /// Node ID to check
        node_id: EndpointId,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        node_addrs: Vec<SocketAddr>,
    },
    /// Fetch canonical artifact bytes from a node
    Artifact {
        #[command(subcommand)]
        command: commands::artifact::ArtifactCommand,
    },
    /// Inspect or run the durable paid-work client path.
    #[cfg(feature = "node")]
    PaidWork {
        #[command(subcommand)]
        command: commands::paid_work::PaidWorkCommand,
    },
    /// Inspect and fill the content store
    Store {
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
    #[cfg(feature = "llm")]
    /// Run token-native Catena inference remotely, or locally when built with `evaluate`
    #[cfg_attr(
        feature = "evaluate",
        command(group(
            clap::ArgGroup::new("causal_lm_local_mode").args(["local", "verify_local"])
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
    #[cfg_attr(all(feature = "cloud", unix), command(group(
        clap::ArgGroup::new("remote_target").args(["node_id", "machine"])
    )))]
    Llm {
        /// Select any owned cloud or bare-metal machine from this identity's inventory.
        #[cfg(all(feature = "cloud", unix))]
        #[arg(long, conflicts_with_all = ["node_id", "provider_genesis", "apple_app_attest_app_id", "apple_app_attest_cdhashes"])]
        #[cfg_attr(feature = "evaluate", arg(conflicts_with_all = ["local", "verify_local"]))]
        machine: Option<String>,
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        #[command(flatten)]
        causal_lm: CausalLmArgs,
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        #[cfg_attr(all(feature = "cloud", unix), arg(requires = "remote_target"))]
        #[cfg_attr(not(all(feature = "cloud", unix)), arg(requires = "node_id"))]
        node_addrs: Vec<SocketAddr>,
        /// Prompt to send (required)
        #[arg(short = 'p', long = "prompt")]
        prompt: String,
        /// Publish prompt- and token-bearing artifacts through Courtesy.
        #[arg(long = "retain", action = clap::ArgAction::SetTrue)]
        retain: bool,
        /// Maximum number of new tokens to generate
        #[arg(
            long = "max-new-tokens",
            default_value_t = 16,
            value_parser = clap::value_parser!(u32).range(1..)
        )]
        max_new_tokens: u32,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Run locally with Catena instead of the Hellas network
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "local",
            default_value_t = false,
            conflicts_with_all = ["verify_local", "node_id", "node_addrs"],
            requires = "causal_lm_local_content"
        )]
        local: bool,
        /// Run remotely and locally, then verify that both outputs match
        #[cfg(feature = "evaluate")]
        #[arg(
            long = "verify-local",
            default_value_t = false,
            conflicts_with = "local",
            requires = "causal_lm_local_content"
        )]
        verify_local: bool,
    },
    /// Run a signed, manifest-pinned Fetch request
    ///
    /// The selected Fetch contract strictly structures the upstream request
    /// and destructures its adversarial response into signed output. A
    /// platform-backed assurance authenticates the app; producer-signed does not.
    #[cfg_attr(all(feature = "cloud", unix), command(group(
        clap::ArgGroup::new("remote_target").args(["node_id", "machine"])
    )))]
    Fetch {
        /// Select any owned cloud or bare-metal machine from this identity's inventory.
        #[cfg(all(feature = "cloud", unix))]
        #[arg(long, conflicts_with_all = ["node_id", "provider_genesis", "apple_app_attest_app_id", "apple_app_attest_cdhashes"])]
        machine: Option<String>,
        #[command(flatten)]
        remote_trust: RemoteTrustArgs,
        /// Node ID to run on remotely (omit to auto-discover)
        node_id: Option<EndpointId>,
        /// Direct UDP address hint for the target node. Repeat or use commas.
        #[arg(long = "node-addr", value_delimiter = ',')]
        #[cfg_attr(all(feature = "cloud", unix), arg(requires = "remote_target"))]
        #[cfg_attr(not(all(feature = "cloud", unix)), arg(requires = "node_id"))]
        node_addrs: Vec<SocketAddr>,
        /// Fetch service label. The protocol records it but does not interpret it.
        #[arg(long)]
        service: String,
        /// Fetch method label. The protocol records it but does not interpret it.
        #[arg(long)]
        method: String,
        /// Built-in Fetch environment alias (`http`, `codex-responses`, or
        /// `openai-responses`) or exact ProgramManifest ContentId. This pins
        /// the exact request structuring and response destructuring contract.
        #[arg(long = "execution-environment", value_parser = parse_fetch_environment)]
        execution_environment: hellas_rpc::ContentId,
        /// Exact UTF-8 JSON request input signed by this caller.
        #[arg(
            long,
            conflicts_with = "payload_file",
            required_unless_present = "payload_file"
        )]
        payload: Option<String>,
        /// Read exact UTF-8 JSON request input from a file.
        #[arg(long = "payload-file")]
        payload_file: Option<PathBuf>,
        /// Max execution retries on failure (discovery path only)
        #[arg(long = "retries", default_value_t = 2)]
        retries: usize,
        /// Publish the signed input/output transcript through Courtesy.
        #[arg(long = "retain", action = clap::ArgAction::SetTrue)]
        retain: bool,
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
            Self::Fetch { machine, .. } => machine.as_deref(),
            #[cfg(feature = "llm")]
            Self::Llm { machine, .. } => machine.as_deref(),
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
        Commands::OutputCache(args) if args.node_id.is_none() => Some("output-cache"),
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
        Commands::OutputCache(args) => args.node_id.is_some(),
        #[cfg(all(feature = "cloud", unix))]
        command if command.owned_machine().is_some() => true,
        #[cfg(all(feature = "cloud", unix))]
        Commands::Cloud(_) | Commands::Machines(_) | Commands::Control(_) => true,
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
        fetch_config_file: Some(path),
        ..
    } = &cli.command
    {
        let result = commands::serve::validate_fetch_config(path);
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
        Commands::OutputCache(args) => {
            let result =
                commands::output_cache::run(args, cli.store_dir, cli.identity.as_deref()).await;
            tracer_provider.shutdown();
            if let Err(error) = result {
                eprintln!("error: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        #[cfg(all(feature = "cloud", unix))]
        command @ (Commands::Cloud(_) | Commands::Machines(_) | Commands::Control(_)) => {
            let result = cloud::run(command, cli.identity.as_deref()).await;
            tracer_provider.shutdown();
            if let Err(err) = result {
                eprintln!("error: {err:#}");
                std::process::exit(1);
            }
            return;
        }
        Commands::Store { command } => {
            let result = commands::store::run(command, cli.store_dir).await;
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
            Some(local_identity.genesis.statement.root_kind),
        )
    {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let result = match command {
        #[cfg(feature = "node")]
        Commands::Serve {
            owner,
            assurance,
            admin_peers,
            port,
            execute_policy,
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
            #[cfg(feature = "evaluate")]
            evaluate_retained_execution_capacity,
            artifact_store_path,
            work_config_file,
            metrics_port,
            graffiti,
            fetch_config_file,
            check_config: _,
            fetch_max_in_flight,
            fetch_queue_size,
            fetch_retained_transcript_capacity,
            fetch_replay_max_in_flight,
        } => {
            // Loaded before anything binds: a work configuration that
            // will not load is a node that would advertise two paid
            // ALPNs and then have nothing to mount behind them.
            match work_config_file
                .as_deref()
                .map(commands::serve::load_work_config)
                .transpose()
            {
                Err(error) => Err(error),
                Ok(work_config) => {
                    async {
                        // The key every settlement this node signs is signed
                        // with, taken from the identity loaded above and
                        // never made here.
                        let settlement_key = identity::settlement_signer(&local_identity);
                        let open_identity = local_identity.open_identity();
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
                        let cache_options = commands::output_cache::options(
                            cli.output_cache,
                            cli.store_dir.clone(),
                        )?;
                        let _control = commands::local_control::serve(
                            cli.control_socket.as_deref(),
                            &cache_options,
                        )?;
                        commands::serve::run(commands::serve::ServeOptions {
                            admin_peers,
                            output_cache: cache_options,
                            owner,
                            port,
                            execute_policy,
                            queue_size,
                            #[cfg(feature = "evaluate")]
                            content_paths,
                            #[cfg(feature = "evaluate")]
                            content_roots,
                            #[cfg(feature = "evaluate")]
                            content_index: content_index.or_else(|| {
                                cli.store_dir
                                    .as_deref()
                                    .map(hellas_store::state::records_path_at)
                            }),
                            #[cfg(feature = "evaluate")]
                            gpu_config,
                            #[cfg(feature = "evaluate")]
                            evaluate_retained_execution_capacity,
                            artifact_store_path,
                            work_config,
                            metrics_port,
                            graffiti,
                            fetch_config_file,
                            fetch_max_in_flight,
                            fetch_queue_size,
                            fetch_retained_transcript_capacity,
                            fetch_replay_max_in_flight,
                            secret_key,
                            producer_key: local_identity.producer_key,
                            settlement_key,
                            provider_genesis: local_identity.enrollment.canonical_bytes(),
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
            Err(error) => Err(error),
            Ok(work_config) => {
                commands::serve::run_provision(commands::serve::ProvisionOptions {
                    work_config,
                    // The bond is staked by the party this node already
                    // settles as, taken from the identity loaded above
                    // and never made here.
                    settlement_key: identity::settlement_signer(&local_identity),
                    client,
                    stake_coins: stake_coin,
                    bond_timeout,
                    timeout_payout,
                    max_job_price,
                    print_bond_only,
                })
                .await
            }
        },
        Commands::OutputCache(..) => unreachable!("cache commands handled before identity load"),
        #[cfg(feature = "gateway")]
        Commands::Gateway {
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
            verify_local,
            verify,
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
                let output_cache = cli.output_cache;
                let cache_options =
                    commands::output_cache::options(output_cache, cli.store_dir.clone())?;
                let _control =
                    commands::local_control::serve(cli.control_socket.as_deref(), &cache_options)?;
                let (
                    loaded_environment,
                    model_name,
                    tokenizer,
                    stop_token_ids,
                    local_content_store,
                ) = if let Some(CausalLmArgs {
                    environment,
                    manifest_id,
                    model,
                    #[cfg(feature = "evaluate")]
                    content_paths,
                    #[cfg(feature = "evaluate")]
                    content_roots,
                    #[cfg(feature = "evaluate")]
                    content_index,
                    tokenizer,
                    stop_token_ids,
                }) = causal_lm
                {
                    let loaded_environment =
                        commands::llm::load_environment(&environment, manifest_id)?;
                    let model_name = model.unwrap_or_else(|| {
                        loaded_environment.execution().manifest_id().to_string()
                    });
                    #[cfg(feature = "evaluate")]
                    let local_content_store =
                        if output_cache == hellas_rpc::cache::CachePolicy::ReplayOnly {
                            None
                        } else {
                            commands::llm::local_content_store(
                                local || verify_local,
                                &environment,
                                &loaded_environment,
                                content_paths,
                                content_roots,
                                content_index.or_else(|| {
                                    cli.store_dir
                                        .as_deref()
                                        .map(hellas_store::state::records_path_at)
                                }),
                            )?
                        };
                    #[cfg(not(feature = "evaluate"))]
                    let local_content_store = ();
                    (
                        Some(loaded_environment.into_execution()),
                        model_name,
                        Some(tokenizer),
                        stop_token_ids,
                        local_content_store,
                    )
                } else {
                    #[cfg(feature = "evaluate")]
                    let local_content_store = None;
                    #[cfg(not(feature = "evaluate"))]
                    let local_content_store = ();
                    (None, String::new(), None, Vec::new(), local_content_store)
                };
                #[cfg(not(feature = "evaluate"))]
                let () = local_content_store;
                #[cfg(all(feature = "cloud", unix))]
                anyhow::ensure!(
                    machine.is_none() || responses_backend != GatewayResponsesBackend::Proxy,
                    "--machine cannot be used with the external proxy backend"
                );
                #[cfg(all(feature = "cloud", unix))]
                let (node_id, remote_trust) = cloud::machine_route(
                    machine.as_deref(),
                    &secret_key,
                    node_id,
                    remote_trust,
                )
                .await?;
                let assurance = remote_trust.assurance;
                #[cfg(not(feature = "evaluate"))]
                let local = false;
                #[cfg(feature = "node")]
                let paid_work = if let Some(path) = paid_work_config.as_ref()
                    && output_cache != hellas_rpc::cache::CachePolicy::ReplayOnly
                {
                    anyhow::ensure!(
                        !local && verify.is_none() && node_id.is_none()
                            && responses_backend == GatewayResponsesBackend::Hellas,
                        "--paid-work-config requires remote Hellas execution without --local, --verify, --node-id, or a Responses override",
                    );
                    #[cfg(feature = "evaluate")]
                    anyhow::ensure!(!verify_local, "--paid-work-config cannot use --verify-local");
                    anyhow::ensure!(
                        assurance == hellas_rpc::Assurance::ProducerSigned,
                        "paid-work execution uses producer-signed assurance",
                    );
                    anyhow::ensure!(
                        remote_trust.provider_genesis.is_none(),
                        "--paid-work-config uses the pool's bond and endpoint identities; omit the courtesy --provider pin",
                    );
                    Some(
                        commands::paid_work::load_gateway_backend(
                            path,
                            secret_key.clone(),
                            identity::settlement_signer(&local_identity),
                        ).await?
                    )
                } else {
                    None
                };
                #[cfg(not(feature = "node"))]
                let paid_work = None;
                let provider_trust = if paid_work.is_some()
                    || output_cache == hellas_rpc::cache::CachePolicy::ReplayOnly
                {
                    None
                } else {
                    gateway_provider_trust(
                        local,
                        responses_backend,
                        remote_trust.provider_genesis,
                        assurance,
                        remote_trust.apple_app_attest_app_id,
                        remote_trust.apple_app_attest_cdhashes,
                    )?
                };
                hellas_gateway::run(hellas_gateway::GatewayOptions {
                    archive: hellas_gateway::ArchiveOptions {
                        directory: archive_dir.map(Ok).unwrap_or_else(identity::default_gateway_archive_path)?,
                        zdr,
                    },
                    http_fetch: http_fetch_config
                        .map(|path| -> anyhow::Result<_> {
                            Ok(serde_json::from_slice(&std::fs::read(path)?)?)
                        })
                        .transpose()?,
                    output_cache: cache_options,
                    paid_work,
                    bearer_token_file,
            allow_remote,
                    chat_template,
                    host,
                    port,
                    node_id,
                    node_addrs,
                    #[cfg(feature = "evaluate")]
                    local,
                    #[cfg(feature = "evaluate")]
                    verify_local,
                    verify,
                    #[cfg(feature = "evaluate")]
                    queue_size,
                    retries,
                    default_max_tokens,
                    model_name,
                    causal_lm: loaded_environment,
                    #[cfg(feature = "evaluate")]
                    local_content_store,
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
                    #[cfg(feature = "evaluate")]
                    provider_genesis: local_identity.enrollment.canonical_bytes(),
                    assurance,
                    secret_key,
                    wrap,
                    wrap_args,
                })
                .await
            }
            .await
        }
        Commands::Rpc {
            node_id,
            node_addrs,
        } => commands::rpc::run(node_id, node_addrs, secret_key).await,
        Commands::Artifact { command } => commands::artifact::run(command, secret_key).await,
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
        Commands::Cloud(_) | Commands::Machines(_) | Commands::Control(_) => {
            unreachable!("management commands handled before identity load")
        }
        Commands::Environment { .. } => {
            unreachable!("environment commands handled before identity load")
        }
        #[cfg(feature = "llm")]
        Commands::Llm {
            #[cfg(all(feature = "cloud", unix))]
            machine,
            remote_trust,
            causal_lm,
            node_id,
            node_addrs,
            prompt,
            retain,
            max_new_tokens,
            retries,
            #[cfg(feature = "evaluate")]
            local,
            #[cfg(feature = "evaluate")]
            verify_local,
        } => {
            async {
                let CausalLmArgs {
                    environment,
                    manifest_id,
                    model,
                    #[cfg(feature = "evaluate")]
                    content_paths,
                    #[cfg(feature = "evaluate")]
                    content_roots,
                    #[cfg(feature = "evaluate")]
                    content_index,
                    tokenizer,
                    stop_token_ids,
                } = causal_lm;
                let loaded_environment =
                    commands::llm::load_environment(&environment, manifest_id)?;
                let model_name = model
                    .unwrap_or_else(|| loaded_environment.execution().manifest_id().to_string());
                #[cfg(feature = "evaluate")]
                let local_content_store =
                    if cli.output_cache == hellas_rpc::cache::CachePolicy::ReplayOnly {
                        None
                    } else {
                        commands::llm::local_content_store(
                            local || verify_local,
                            &environment,
                            &loaded_environment,
                            content_paths,
                            content_roots,
                            content_index.or_else(|| {
                                cli.store_dir
                                    .as_deref()
                                    .map(hellas_store::state::records_path_at)
                            }),
                        )?
                    };
                #[cfg(all(feature = "cloud", unix))]
                let (node_id, remote_trust) = cloud::machine_route(
                    machine.as_deref(), &secret_key, node_id, remote_trust,
                ).await?;
                commands::llm::run(
                    commands::llm::ExecuteOptions {
                        output_cache: commands::output_cache::options(
                            cli.output_cache,
                            cli.store_dir,
                        )?,
                        node_id,
                        node_addrs,
                        model_name,
                        causal_lm: loaded_environment.into_execution(),
                        #[cfg(feature = "evaluate")]
                        local_content_store,
                        tokenizer,
                        stop_token_ids,
                        prompt,
                        retain,
                        max_new_tokens,
                        retries,
                        #[cfg(feature = "evaluate")]
                        local,
                        #[cfg(feature = "evaluate")]
                        verify_local,
                        producer_key: local_identity.producer_key,
                        #[cfg(feature = "evaluate")]
                        provider_genesis: local_identity.enrollment.canonical_bytes(),
                        expected_provider_genesis: remote_trust.provider_genesis,
                        apple_app_attest_app_id: remote_trust.apple_app_attest_app_id,
                        apple_app_attest_cdhashes: remote_trust.apple_app_attest_cdhashes,
                        assurance: remote_trust.assurance,
                    },
                    secret_key,
                )
                .await
            }
            .await
        }
        Commands::Fetch {
            #[cfg(all(feature = "cloud", unix))]
            machine,
            remote_trust,
            node_id,
            node_addrs,
            service,
            method,
            execution_environment,
            payload,
            payload_file,
            retries,
            retain,
        } => {
            let payload = match (payload, payload_file) {
                (Some(payload), None) => Ok(payload.into_bytes()),
                (None, Some(path)) => commands::fetch::load_payload_file(&path),
                (None, None) => unreachable!("clap requires --payload or --payload-file"),
                (Some(_), Some(_)) => unreachable!("clap rejects both payload sources"),
            };
            match payload {
                Ok(payload) => {
                    async {
                        #[cfg(all(feature = "cloud", unix))]
                        let (node_id, remote_trust) = cloud::machine_route(
                            machine.as_deref(), &secret_key, node_id, remote_trust,
                        ).await?;
                        commands::fetch::run(
                            commands::fetch::ExecuteOptions {
                                output_cache: commands::output_cache::options(
                                    cli.output_cache,
                                    cli.store_dir,
                                )?,
                                node_id,
                                node_addrs,
                                service,
                                method,
                                execution_environment,
                                payload,
                                retries,
                                retain,
                                producer_key: local_identity.producer_key,
                                expected_provider_genesis: remote_trust.provider_genesis,
                                apple_app_attest_app_id: remote_trust.apple_app_attest_app_id,
                                apple_app_attest_cdhashes: remote_trust.apple_app_attest_cdhashes,
                                assurance: remote_trust.assurance,
                            },
                            secret_key,
                        )
                        .await
                    }
                    .await
                }
                Err(err) => Err(err),
            }
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
