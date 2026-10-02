#[macro_use]
extern crate tracing;

mod access;
mod anthropic;
mod archive;
mod backend;
mod dispatch;
mod error;
pub use error::{GatewayConfigError, GatewayError, GatewayResult};
mod http_fetch;
mod metrics;
mod openai;
mod plain;
mod provenance_layer;
mod proxy;
mod responses;
mod state;
mod wrap;

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

pub use archive::ArchiveOptions;
pub use execution::{
    CausalLmExecutionEnvironment, ExecutionEvent, Outcome, PreparedExecution, StopReason,
};
pub use http_fetch::{HttpGatewayConfig, HttpGatewayOptions, HttpRoute, RoutingError, start_http};

const DEFAULT_HTTP_PORT: u16 = 8080;

/// Token-native input handed to a funded Work client.
pub struct WorkExecutionRequest {
    pub environment: hellas_rpc::CausalLmEnvironment,
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}

/// A Fetch pinned to one funded provider by the HTTP account router.
pub struct WorkFetchRequest {
    pub provider: EndpointId,
    pub service: String,
    pub method: String,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkGatewayError {
    #[error("request does not match its resource: {0}")]
    Rejected(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("grant access refused: {0}")]
    Denied(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("resource allowance exhausted: {0}")]
    Quota(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Work backend does not support HTTP Fetch")]
    Unsupported,
    #[error("provider {0} has no HTTP Fetch resource")]
    Provider(EndpointId),
    #[error(transparent)]
    Busy(#[from] WorkGatewayBusy),
    #[error("Work execution failed: {0}")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
}

pub type WorkOutputStream<E> = futures::stream::BoxStream<'static, Result<E, WorkGatewayError>>;
pub type WorkFetchStream = WorkOutputStream<hellas_rpc::output::OutputEvent>;

/// Work admission capacity is exhausted or the backend is shutting down.
#[derive(Debug, thiserror::Error)]
#[error("Work gateway is busy; retry later")]
pub struct WorkGatewayBusy;

#[derive(Clone, Debug, thiserror::Error)]
pub enum WorkShutdownError {
    #[error("gateway task state is poisoned")]
    Poisoned,
    #[error("gateway task failed: {0}")]
    Task(#[source] Arc<tokio::task::JoinError>),
    #[error("gateway retains unresolved work for recovery: {0}")]
    Recovery(#[source] Arc<dyn std::error::Error + Send + Sync>),
}

pub trait WorkExecutionBackend: Send + Sync {
    /// Providers configured for the HTTP Fetch manifest.
    fn fetch_providers(&self) -> Vec<EndpointId> {
        Vec::new()
    }

    /// Authenticated prefixes, then durable completion. After proposal the
    /// backend owns collection and funding obligations across disconnects.
    fn fetch(&self, _request: WorkFetchRequest) -> Result<WorkFetchStream, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
    }

    /// End-to-end budget, including queued time, advertised to HTTP consumers.
    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }

    /// Reject incompatible policies before opening a channel. The returned
    /// operation may stop on HTTP cancellation before a proposal is released;
    /// afterwards it retains responsibility for collection and funding obligations.
    /// Prefixes are authenticated as they arrive; completion is durably recorded.
    fn execute(
        &self,
        request: WorkExecutionRequest,
    ) -> Result<WorkOutputStream<ExecutionEvent>, WorkGatewayError>;

    /// Finish accepted work and its funding obligations during graceful shutdown.
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>>;
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct ConnectionId {
    id: u64,
    alive: Arc<()>,
}

impl
    axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::TcpListener>>
    for ConnectionId
{
    fn connect_info(_: axum::serve::IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed),
            alive: Arc::new(()),
        }
    }
}

pub struct GatewayOptions {
    pub archive: ArchiveOptions,
    pub output_cache: cache::CacheOptions,
    pub paid_work: Option<Arc<dyn WorkExecutionBackend>>,
    /// Load or create a stable bearer credential in a private file.
    pub bearer_token_file: Option<PathBuf>,
    /// Permit a non-loopback listener, with a persistent bearer credential.
    pub allow_remote: bool,
    pub host: String,
    pub port: Option<u16>,
    pub node_id: Option<EndpointId>,
    pub node_addrs: Vec<SocketAddr>,
    pub retries: usize,
    pub default_max_tokens: u32,
    /// Fixed presentation label returned to API clients. It is not sent to an
    /// executor and cannot select trusted execution content.
    pub model_name: String,
    /// Strict canonical Catena causal-LM manifest and locally checked root
    /// metadata, bound to an independent caller pin.
    pub causal_lm: Option<CausalLmExecutionEnvironment>,
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
    pub assurance: hellas_rpc::Assurance,
    pub secret_key: SecretKey,
    pub wrap: Option<String>,
    pub wrap_args: Vec<String>,
}

mod fetch_gateway;
pub use fetch_gateway::{FetchGatewayOptions, start_fetch};

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
    task: tokio::task::JoinHandle<crate::GatewayResult<()>>,
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

    pub async fn shutdown(mut self) -> crate::GatewayResult<()> {
        self.request_shutdown();
        (&mut self.task).await.map_err(GatewayError::Task)?
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        self.shutdown.notify_one();
    }
}

/// Start a gateway without installing process signal handlers.
pub async fn start(options: GatewayOptions) -> crate::GatewayResult<GatewayHandle> {
    let paid_work = options.paid_work.clone();
    let result = start_gateway(options).await;
    if result.is_err()
        && let Some(backend) = paid_work
    {
        return finish_cleanup(result, backend.drain().await);
    }
    result
}

async fn start_gateway(options: GatewayOptions) -> crate::GatewayResult<GatewayHandle> {
    let listener = bind_gateway(
        &options.host,
        options.port,
        options.allow_remote && options.bearer_token_file.is_some(),
    )
    .await?;
    let state = Arc::new(GatewayState::from_options(&options).await?);
    let archive_policy = archive::Policy::new(
        options.archive.clone(),
        options.output_cache.policy != cache::CachePolicy::Off,
    );
    archive_policy.prepare();

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
        .layer(axum::middleware::from_fn_with_state(
            archive_policy,
            archive::record,
        ));
    #[cfg(feature = "otel")]
    let app = app.layer(axum::middleware::from_fn(
        hellas_rpc::telemetry::http::trace_request,
    ));
    let app = app.layer(access::BearerLayer::new(bearer.clone()));

    if let Some(metrics_port) = options.metrics_port {
        let registry = Arc::new(prometheus_client::registry::Registry::default());
        let bundle = crate::metrics::MetricsBundle::new(registry);
        crate::metrics::spawn_metrics_server(
            metrics_port,
            bundle,
            access::BearerLayer::new(bearer.clone()),
        );
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
        listener,
        bearer,
        options.wrap.as_deref(),
        &options.wrap_args,
        options.paid_work.clone(),
    )
    .await
}

async fn launch_gateway(
    app: Router,
    listener: tokio::net::TcpListener,
    bearer: Arc<access::Bearer>,
    wrap_command: Option<&str>,
    wrap_args: &[String],
    paid_work: Option<Arc<dyn WorkExecutionBackend>>,
) -> crate::GatewayResult<GatewayHandle> {
    let bound_addr = listener.local_addr()?;
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
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ConnectionId>(),
        )
        .with_graceful_shutdown(async move {
            server_shutdown.notified().await;
        }),
    );

    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let result = async {
            match wrap_child {
                Some(mut child) => {
                    tokio::pin!(server);
                    tokio::select! {
                        res = &mut server => {
                            // Gateway stopped or errored; kill_on_drop tears the
                            // wrapped child down too.
                            res?;
                        }
                        status = child.wait() => {
                            let status = status?;
                            task_shutdown.notify_one();
                            server.await?;
                            if !status.success() {
                                return Err(GatewayError::WrappedCommand(status));
                            }
                        }
                    }
                }
                None => {
                    server.await?;
                }
            }
            Ok(())
        }
        .await;
        finish_paid_work(paid_work, result).await
    });

    Ok(GatewayHandle {
        address: bound_addr,
        bearer: bearer_value,
        shutdown,
        task,
    })
}

fn finish_cleanup<T>(
    result: GatewayResult<T>,
    drained: Result<(), WorkShutdownError>,
) -> GatewayResult<T> {
    match (result, drained) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Ok(())) => Err(error),
        (Err(primary), Err(cleanup)) => Err(GatewayError::Cleanup {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}

// Keep cleanup outside the fallible server/child branch: a failed wrapper is
// also a normal reason for its HTTP requests to have been disconnected.
async fn finish_paid_work(
    paid_work: Option<Arc<dyn WorkExecutionBackend>>,
    result: crate::GatewayResult<()>,
) -> crate::GatewayResult<()> {
    if let Some(backend) = paid_work {
        return finish_cleanup(result, backend.drain().await);
    }
    result
}

/// CLI lifecycle wrapper around [`start`].
pub async fn run(options: GatewayOptions) -> crate::GatewayResult<()> {
    wait_for_shutdown(start(options).await?).await
}

/// Run a paid HTTP gateway with process signal handling.
pub async fn run_http(options: HttpGatewayOptions) -> crate::GatewayResult<()> {
    wait_for_shutdown(start_http(options).await?).await
}

async fn wait_for_shutdown(mut handle: GatewayHandle) -> crate::GatewayResult<()> {
    tokio::select! {
        signal = shutdown_signal() => {
            handle.request_shutdown();
            let stopped = (&mut handle.task).await.map_err(GatewayError::Task)?;
            signal.and(stopped)
        }
        result = &mut handle.task => {
            result.map_err(GatewayError::Task)?
        }
    }
}

async fn shutdown_signal() -> crate::GatewayResult<()> {
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
async fn bind_gateway(
    host: &str,
    port: Option<u16>,
    allow_remote: bool,
) -> crate::GatewayResult<tokio::net::TcpListener> {
    if let Some(p) = port {
        let addr = access::bind_addr(host, p, allow_remote).await?;
        return tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| GatewayError::Bind {
                address: addr,
                source,
            });
    }
    let preferred = access::bind_addr(host, DEFAULT_HTTP_PORT, allow_remote).await?;
    match tokio::net::TcpListener::bind(preferred).await {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(preferred.ip(), 0);
            info!("failed to bind {preferred}; attempting to bind {fallback}");
            tokio::net::TcpListener::bind(fallback)
                .await
                .map_err(|source| GatewayError::Bind {
                    address: fallback,
                    source,
                })
        }
        Err(err) => Err(GatewayError::Bind {
            address: preferred,
            source: err,
        }),
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

#[cfg(test)]
mod paid_shutdown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Backend {
        drained: AtomicBool,
        fail: bool,
    }
    impl WorkExecutionBackend for Backend {
        fn execute(
            &self,
            _: WorkExecutionRequest,
        ) -> Result<WorkOutputStream<ExecutionEvent>, WorkGatewayError> {
            unreachable!("shutdown does not submit new work")
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), WorkShutdownError>> {
            Box::pin(async {
                self.drained.store(true, Ordering::Relaxed);
                if self.fail {
                    Err(WorkShutdownError::Poisoned)
                } else {
                    Ok(())
                }
            })
        }
    }

    #[tokio::test]
    async fn failed_server_still_drains_paid_work() {
        let backend = Arc::new(Backend {
            drained: AtomicBool::new(false),
            fail: false,
        });
        let error = finish_paid_work(
            Some(backend.clone()),
            Err(GatewayError::Io(std::io::Error::other("injected failure"))),
        )
        .await
        .unwrap_err();
        assert!(backend.drained.load(Ordering::Relaxed));
        assert!(matches!(error, GatewayError::Io(_)));
    }
    #[tokio::test]
    async fn cleanup_errors_reach_the_caller_and_preserve_the_primary_failure() {
        let backend = Arc::new(Backend {
            drained: AtomicBool::new(false),
            fail: true,
        });
        let error = finish_paid_work(Some(backend.clone()), Ok(()))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GatewayError::Shutdown(WorkShutdownError::Poisoned)
        ));
        let primary = GatewayError::Io(std::io::Error::other("injected server failure"));
        let error = finish_paid_work(Some(backend.clone()), Err(primary))
            .await
            .unwrap_err();
        assert!(
            matches!(error, GatewayError::Cleanup { primary, cleanup: WorkShutdownError::Poisoned } if matches!(*primary, GatewayError::Io(_)))
        );
        assert!(backend.drained.load(Ordering::Relaxed));
    }
}
