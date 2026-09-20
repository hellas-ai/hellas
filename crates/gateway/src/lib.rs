#[macro_use]
extern crate tracing;

mod access;
mod anthropic;
mod backend;
mod dispatch;
mod fetch_backend;
mod metrics;
mod openai;
mod plain;
mod provenance_layer;
mod proxy;
mod responses;
mod state;
#[cfg_attr(not(feature = "otel"), path = "telemetry_disabled.rs")]
mod telemetry;
mod wrap;

use anyhow::{Context, bail};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use futures::Stream;
use hellas_client::{cache, execution};
use hellas_rpc::ProducerSigningKey;
use iroh::{EndpointId, SecretKey};
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use self::state::GatewayState;

pub use execution::{
    CausalLmExecutionEnvironment, CliRuntime, ExecutionEvent, ExecutionRequest,
    ExecutionRequestOptions, ExecutionStrategy, Outcome, PreparedExecution, StopReason,
};

const DEFAULT_HTTP_PORT: u16 = 8080;

/// Token-native input handed to a configured paid-work client.
pub struct PaidExecutionRequest {
    pub environment: hellas_rpc::CausalLmEnvironment,
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}

pub trait PaidExecutionBackend: Send + Sync {
    /// Reject incompatible policies before opening a channel. The returned
    /// operation survives HTTP cancellation. Prefixes are authenticated as
    /// they arrive; completion is emitted after durable payment acknowledgement.
    fn execute(
        &self,
        request: PaidExecutionRequest,
    ) -> anyhow::Result<futures::stream::BoxStream<'static, anyhow::Result<ExecutionEvent>>>;

    /// Finish outstanding payment operations during graceful shutdown.
    fn drain(&self) -> futures::future::BoxFuture<'_, ()>;
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct GatewayOptions {
    pub output_cache: cache::CacheOptions,
    pub paid_work: Option<Arc<dyn PaidExecutionBackend>>,
    /// Load or create a stable bearer credential in a private file.
    pub bearer_token_file: Option<PathBuf>,
    pub host: String,
    pub port: Option<u16>,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    #[cfg(feature = "evaluate")]
    pub local: bool,
    #[cfg(feature = "evaluate")]
    pub verify_local: bool,
    pub verify: Option<EndpointId>,
    #[cfg(feature = "evaluate")]
    pub queue_size: usize,
    pub retries: usize,
    pub default_max_tokens: u32,
    /// Fixed presentation label returned to API clients. It is not sent to an
    /// executor and cannot select trusted execution content.
    pub model_name: String,
    /// Strict canonical Catena causal-LM manifest and locally checked root
    /// metadata, bound to an independent caller pin.
    pub causal_lm: Option<CausalLmExecutionEnvironment>,
    /// Locally available Xet content used by a local execution leg. The
    /// executor may only reopen the objects named below the manifest root; it
    /// does not fetch or compile while admitting the environment.
    #[cfg(feature = "evaluate")]
    pub local_content_store: Option<hellas_store::ContentStore>,
    /// Application-selected tokenizer used only before and after execution.
    /// It is not part of the Catena environment or Hellas execution claim.
    pub tokenizer: Option<PathBuf>,
    /// Explicit local chat format; plain completions remain plain text.
    pub chat_template: Option<hellas_presentation::ChatTemplate>,
    /// Application-selected stop IDs sent explicitly with every request.
    pub stop_token_ids: Vec<u32>,
    pub metrics_port: Option<u16>,
    pub responses_backend: ResponsesBackend,
    pub responses_proxy_url: String,
    pub responses_proxy_api_key_env: String,
    pub responses_fetch_route_service: String,
    pub responses_fetch_route_method: String,
    /// Exact manifest ID for the attested Fetch route. Fetch owns its request
    /// structuring and response destructuring as trusted computation, unlike
    /// the causal-LM path whose tokenizer and decoding remain local
    /// presentation policy.
    pub responses_fetch_execution_environment: Option<hellas_rpc::ContentId>,
    pub responses_fetch_request_overrides: JsonMap<String, JsonValue>,
    /// The out-of-band anchor every remote route is verified against.
    /// `None` is the absence of a *route*, never a route dialled without
    /// an anchor: each remote constructor takes an anchor by value, so a
    /// gateway given none has no remote route to run and says so.
    pub provider_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub producer_key: ProducerSigningKey,
    #[cfg(feature = "evaluate")]
    pub provider_genesis: Vec<u8>,
    pub assurance: hellas_rpc::Assurance,
    pub secret_key: SecretKey,
    pub wrap: Option<String>,
    pub wrap_args: Vec<String>,
}

/// Minimal embedded gateway for a single verified Fetch-backed Responses
/// route. It deliberately has no tokenizer, Catena environment, local
/// evaluator, metrics server, or child-process wrapper.
pub struct FetchGatewayOptions {
    pub host: String,
    pub port: Option<u16>,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub retries: usize,
    pub service: String,
    pub method: String,
    pub execution_environment: hellas_rpc::ContentId,
    pub request_overrides: JsonMap<String, JsonValue>,
    pub provider_trust: hellas_client::ProviderTrustAnchor,
    pub caller_key: ProducerSigningKey,
    pub assurance: hellas_rpc::Assurance,
    pub secret_key: SecretKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponsesBackend {
    Hellas,
    Proxy,
    Fetch,
}

/// A running authenticated HTTP gateway owned by its embedding process.
pub struct GatewayHandle {
    address: SocketAddr,
    bearer: String,
    shutdown: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl GatewayHandle {
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Return the ephemeral credential for an explicit local UI/control
    /// surface. The value is never included in `Debug` or logs.
    pub fn bearer(&self) -> &str {
        &self.bearer
    }

    pub fn request_shutdown(&self) {
        self.shutdown.notify_one();
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.request_shutdown();
        (&mut self.task)
            .await
            .context("gateway task failed to join")?
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

/// Start a gateway without installing process signal handlers.
pub async fn start(options: GatewayOptions) -> anyhow::Result<GatewayHandle> {
    let state = Arc::new(GatewayState::from_options(&options).await?);

    // Every route below reaches an executor, so every route below is
    // behind this run's credential. The layer goes on last, which in axum
    // puts it outermost: a request without the credential is answered
    // before a handler, the provenance layer, or the executor sees it.
    let bearer = Arc::new(match options.bearer_token_file.as_ref() {
        Some(path) => access::Bearer::load_or_create(path)?,
        None => access::Bearer::generate(),
    });
    let app = Router::new()
        .route("/v1/chat/completions", post(openai::handle))
        .route("/v1/responses", post(responses::handle))
        .route("/v1/messages", post(anthropic::handle))
        .route("/v1/completions", post(plain::handle))
        .with_state(state.clone())
        .layer(provenance_layer::ProvenanceLayer)
        .layer(axum::middleware::from_fn(telemetry::trace_request))
        .layer(access::BearerLayer::new(bearer.clone()));

    if let Some(metrics_port) = options.metrics_port {
        let registry = Arc::new(prometheus_client::registry::Registry::default());
        let bundle = crate::metrics::MetricsBundle::new(registry);
        crate::metrics::spawn_metrics_server(
            metrics_port,
            bundle,
            access::BearerLayer::new(bearer.clone()),
        );
    }

    #[cfg(feature = "evaluate")]
    if state.local {
        info!("local Catena execution, queue size: {}", options.queue_size);
    } else if state.verify_local {
        info!(
            "local Catena verification, queue size: {}",
            options.queue_size
        );
    } else if let Some(verify_node) = state.verify_node_id.as_ref() {
        info!("Verifying primary node against remote shadow node {verify_node}");
    }
    #[cfg(not(feature = "evaluate"))]
    if let Some(verify_node) = state.verify_node_id.as_ref() {
        info!("Verifying primary node against remote shadow node {verify_node}");
    }

    info!("timeout: {}s", state.inference_timeout.as_secs());
    if let Some(causal_lm) = state.causal_lm.as_ref() {
        info!(
            model = %state.model_name,
            program_manifest = %causal_lm.manifest_id(),
            "using configured causal-LM environment"
        );
    }

    launch_gateway(
        app,
        &options.host,
        options.port,
        bearer,
        options.wrap.as_deref(),
        &options.wrap_args,
        options.paid_work.clone(),
    )
    .await
}

/// Start the small Responses-only gateway used by native hosts such as Gate.
pub async fn start_fetch(options: FetchGatewayOptions) -> anyhow::Result<GatewayHandle> {
    let state = Arc::new(GatewayState::from_fetch_options(&options).await?);
    let bearer = Arc::new(access::Bearer::generate());
    let app = Router::new()
        .route("/v1/responses", post(responses::handle))
        .with_state(state)
        .layer(provenance_layer::ProvenanceLayer)
        .layer(axum::middleware::from_fn(telemetry::trace_request))
        .layer(access::BearerLayer::new(bearer.clone()));
    launch_gateway(app, &options.host, options.port, bearer, None, &[], None).await
}

async fn launch_gateway(
    app: Router,
    host: &str,
    port: Option<u16>,
    bearer: Arc<access::Bearer>,
    wrap_command: Option<&str>,
    wrap_args: &[String],
    paid_work: Option<Arc<dyn PaidExecutionBackend>>,
) -> anyhow::Result<GatewayHandle> {
    let listener = bind_gateway(host, port).await?;
    let bound_addr = listener
        .local_addr()
        .context("listener has no local address")?;
    info!("gateway listening on {bound_addr}");
    bearer.announce();

    let wrap_child = if let Some(command) = wrap_command {
        let base = format!("http://{bound_addr}");
        info!("wrapping `{command}` with gateway base {base}");
        Some(wrap::spawn(
            command,
            wrap_args,
            &base,
            &bearer.child_credential(),
        )?)
    } else {
        None
    };

    let bearer_value = bearer.child_credential();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let server_shutdown = shutdown.clone();
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(async move {
            server_shutdown.notified().await;
        }),
    );

    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        match wrap_child {
            Some(mut child) => {
                tokio::pin!(server);
                tokio::select! {
                    res = &mut server => {
                        // Gateway stopped or errored; kill_on_drop tears the
                        // wrapped child down too.
                        res.context("gateway server failed")?;
                    }
                    status = child.wait() => {
                        let status = status.context("waiting on wrapped child failed")?;
                        task_shutdown.notify_one();
                        server.await.context("gateway server failed")?;
                        if !status.success() {
                            bail!("wrapped command exited with status {status}");
                        }
                    }
                }
            }
            None => {
                server.await.context("gateway server failed")?;
            }
        }
        if let Some(backend) = paid_work {
            backend.drain().await;
        }
        Ok(())
    });

    Ok(GatewayHandle {
        address: bound_addr,
        bearer: bearer_value,
        shutdown,
        task,
    })
}

/// CLI lifecycle wrapper around [`start`].
pub async fn run(options: GatewayOptions) -> anyhow::Result<()> {
    let mut handle = start(options).await?;
    tokio::select! {
        signal = shutdown_signal() => {
            signal?;
            handle.request_shutdown();
            (&mut handle.task)
                .await
                .context("gateway task failed to join")?
        }
        result = &mut handle.task => {
            result.context("gateway task failed to join")?
        }
    }
}

async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// Bind the configured gateway interface. All inference routes require
/// bearer authentication. With `--port`, fail on conflict (the user asked for that
/// exact port). Without it, try 8080 first and fall back to an
/// OS-assigned port on EADDRINUSE so a stray dev gateway doesn't block a
/// fresh one.
async fn bind_gateway(host: &str, port: Option<u16>) -> anyhow::Result<tokio::net::TcpListener> {
    if let Some(p) = port {
        let addr = access::bind_addr(host, p).await?;
        return tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind gateway on {addr}"));
    }
    let preferred = access::bind_addr(host, DEFAULT_HTTP_PORT).await?;
    match tokio::net::TcpListener::bind(preferred).await {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(preferred.ip(), 0);
            info!("failed to bind {preferred}; attempting to bind {fallback}");
            tokio::net::TcpListener::bind(fallback)
                .await
                .with_context(|| format!("failed to bind gateway on {fallback}"))
        }
        Err(err) => Err(err).with_context(|| format!("failed to bind gateway on {preferred}")),
    }
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": { "message": message.into() } })),
    )
        .into_response()
}

/// Wrap an event stream as an SSE response. The stream IS the producer —
/// no spawn, no channel. When axum drops the response body the stream is
/// dropped, propagating drop-cancellation through every layer (decoder,
/// inference, broadcast subscriber, executor's per-running cancel token).
fn sse_response<S>(stream: S) -> Response
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn sse_data<T: Serialize>(payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().data(data)
}

fn sse_event_data<T: Serialize>(event: &str, payload: &T) -> Event {
    let data = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());
    Event::default().event(event).data(data)
}

fn next_id(prefix: &str) -> String {
    let n = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// How many seconds remain until `deadline`, clamped to at least one
/// second so timeout error messages don't report `0s`.
fn timeout_secs_until(deadline: tokio::time::Instant) -> u64 {
    deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .as_secs()
        .max(1)
}
