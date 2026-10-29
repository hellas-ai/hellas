#[macro_use]
extern crate tracing;

mod access;
pub use access::GatewayAccess;
mod anthropic;
mod archive;
mod audio;
mod backend;
mod compose;
mod dispatch;
mod error;
pub use error::{GatewayConfigError, GatewayError, GatewayResult};
mod http_fetch;
mod openai;
mod plain;
mod provenance_layer;
mod responses;
mod responses_fetch;
mod state;
mod wrap;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use futures::Stream;
use hellas_adaptors::BackendError;
use hellas_auth::authority::UnixMillis;
use iroh::EndpointId;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub use archive::ArchiveOptions;
pub use hellas_rpc::compute_event::ComputeEvent;
pub use http_fetch::{HttpGatewayConfig, HttpRoute, RoutingError};

const DEFAULT_HTTP_PORT: u16 = 8080;

/// A Fetch pinned to one funded provider by the HTTP account router.
pub struct WorkFetchRequest {
    pub provider: EndpointId,
    pub service: String,
    pub method: String,
    pub body: Vec<u8>,
}

/// One Fetch a work source can run: the provider, the contract schema, and
/// the route the provider's policy seals, if it seals one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRoute {
    pub provider: EndpointId,
    pub schema: hellas_rpc::FetchSchema,
    /// `None` for an open Fetch, whose route the caller names.
    pub sealed: Option<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkGatewayError {
    #[error("request does not match its resource: {0}")]
    Rejected(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("grant access refused: {0}")]
    Denied(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("resource allowance exhausted: {0}")]
    Quota(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Work backend does not support this application")]
    Unsupported,
    #[error("provider {0} has no HTTP Fetch resource")]
    Provider(EndpointId),
    #[error(transparent)]
    Busy(#[from] WorkGatewayBusy),
    #[error("provider is unreachable: {0}")]
    Unreachable(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Work deadline passed: {0}")]
    Timeout(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Work execution failed: {0}")]
    Execution(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The one mapping from Work failures to what every presentation reports.
impl From<WorkGatewayError> for BackendError {
    fn from(error: WorkGatewayError) -> Self {
        let message = error.to_string();
        match error {
            WorkGatewayError::Rejected(_)
            | WorkGatewayError::Unsupported
            | WorkGatewayError::Provider(_) => BackendError::Rejected(message),
            WorkGatewayError::Denied(_) => BackendError::Denied(message),
            WorkGatewayError::Quota(_) => BackendError::Quota(message),
            WorkGatewayError::Busy(_) => BackendError::Busy(message),
            WorkGatewayError::Timeout(_) => BackendError::Timeout(message),
            WorkGatewayError::Unreachable(_) | WorkGatewayError::Execution(_) => {
                BackendError::Unavailable(message)
            }
        }
    }
}

/// The HTTP status of a backend failure, on every presentation.
pub(crate) fn backend_status(error: &BackendError) -> StatusCode {
    match error {
        BackendError::Rejected(_) => StatusCode::BAD_REQUEST,
        BackendError::Denied(_) => StatusCode::FORBIDDEN,
        BackendError::Quota(_) => StatusCode::TOO_MANY_REQUESTS,
        BackendError::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
        BackendError::Conflict(_) => StatusCode::CONFLICT,
        BackendError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        BackendError::Unavailable(_) => StatusCode::BAD_GATEWAY,
        BackendError::Failed(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
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

/// The source every presentation runs its jobs on.
pub trait WorkExecutionBackend: Send + Sync {
    /// The Fetches this source can run, for presentations that pin one.
    fn fetch_routes(&self) -> Vec<FetchRoute> {
        Vec::new()
    }

    /// Authenticated prefixes, then durable completion. After proposal the
    /// backend owns collection and funding obligations across disconnects.
    fn fetch(&self, _request: WorkFetchRequest) -> Result<WorkFetchStream, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
    }

    /// Run a rendered job on a provider admitting Compute. Authenticated
    /// emitted values and named outputs precede the durable completion.
    fn run(
        &self,
        _job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
    }

    /// End-to-end budget, including queued time, advertised to HTTP consumers.
    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }

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

/// Where and to whom the gateway listens, and what it keeps.
#[derive(Clone)]
pub struct ServerOptions {
    /// Provisioned Auth credential and the host authority that admits HTTP requests.
    pub access: GatewayAccess,
    pub archive: ArchiveOptions,
    /// Permit a non-loopback listener.
    pub allow_remote: bool,
    pub host: String,
    pub port: Option<u16>,
    pub wrap: Option<String>,
    pub wrap_args: Vec<String>,
}

/// One gateway: HTTP presentations over one work source.
pub struct GatewayOptions {
    pub server: ServerOptions,
    pub work: Arc<dyn WorkExecutionBackend>,
    pub presentations: Presentations,
}

/// The HTTP surfaces a gateway offers. A path served by several of them is
/// split by the request's model; an overlap is a startup error.
#[derive(Clone, Default)]
pub struct Presentations {
    /// OpenAI chat, completions and Responses, and Anthropic messages,
    /// rendered locally into Compute text jobs.
    pub models: Vec<ModelOptions>,
    /// OpenAI Responses forwarded as a Fetch to one sealed route.
    pub responses: Option<ResponsesFetch>,
    /// Exact HTTP routes forwarded as HTTPS Fetches, with account routing.
    pub http: Option<HttpGatewayConfig>,
}

#[derive(Clone)]
pub enum ModelOptions {
    Text(TextOptions),
    Whisper(AudioOptions),
}

#[derive(Clone)]
pub struct AudioOptions {
    /// Converted Whisper package directory, used only by the client.
    pub model: PathBuf,
    pub model_name: String,
    pub default_max_tokens: usize,
}

#[derive(Clone)]
pub struct TextOptions {
    /// Qwen3 GGUF whose rendered program, weights and tokenizer serve the
    /// text routes; providers must already hold the file.
    pub model: PathBuf,
    /// The model name these routes answer to and report.
    pub model_name: String,
    pub default_max_tokens: u32,
}

#[derive(Clone)]
pub struct ResponsesFetch {
    pub provider: EndpointId,
    pub service: String,
    pub method: String,
    /// Merged into every request body before signing.
    pub overrides: JsonMap<String, JsonValue>,
    /// Models these routes answer to; empty means any.
    pub models: Vec<String>,
}

impl ResponsesFetch {
    /// The one sealed Responses route among `routes`, if there is one.
    pub fn from_routes(
        routes: &[FetchRoute],
        overrides: JsonMap<String, JsonValue>,
        models: Vec<String>,
    ) -> GatewayResult<Option<Self>> {
        let mut sealed = routes.iter().filter_map(|route| match &route.sealed {
            Some((service, method))
                if route.schema == hellas_rpc::FetchSchema::StatelessResponsesV1 =>
            {
                Some((route.provider, service, method))
            }
            _ => None,
        });
        let Some((provider, service, method)) = sealed.next() else {
            return Ok(None);
        };
        if sealed.next().is_some() {
            return Err(GatewayConfigError::AmbiguousResponses.into());
        }
        Ok(Some(Self {
            provider,
            service: service.clone(),
            method: method.clone(),
            overrides,
            models,
        }))
    }
}

/// A running authenticated HTTP gateway owned by its embedding process.
pub struct GatewayHandle {
    address: SocketAddr,
    bearer: String,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<crate::GatewayResult<()>>,
}

impl GatewayHandle {
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Return the provisioned credential for an explicit local UI/control
    /// surface. The value is never included in `Debug` or logs.
    pub fn bearer(&self) -> &str {
        &self.bearer
    }

    pub fn request_shutdown(&self) {
        self.shutdown.send_replace(true);
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub async fn shutdown(mut self) -> crate::GatewayResult<()> {
        self.request_shutdown();
        (&mut self.task)
            .await
            .map_err(GatewayError::Task)
            .and_then(|result| result)
    }
}

impl Drop for GatewayHandle {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
    }
}

/// Start a gateway without installing process signal handlers. A failed
/// start still drains the work source.
pub async fn start(options: GatewayOptions) -> crate::GatewayResult<GatewayHandle> {
    let work = options.work.clone();
    let result = start_gateway(options).await;
    if result.is_err() {
        return finish_cleanup(result, work.drain().await);
    }
    result
}

async fn start_gateway(options: GatewayOptions) -> crate::GatewayResult<GatewayHandle> {
    let GatewayOptions {
        server,
        work,
        presentations,
    } = options;
    let listener = bind_gateway(&server.host, server.port, server.allow_remote).await?;
    let bearer = server.access.clone();
    bearer.validate().await?;
    let archive_policy = archive::Policy::new(server.archive.clone());
    archive_policy.prepare();

    let app = compose::router(&presentations, &work).await?;
    // Every route reaches a work source, so every route is behind the
    // provisioned Auth credential. The layer goes on last, which in axum
    // puts it outermost: a request without the credential is answered
    // before a handler, the provenance layer, or the source sees it.
    let app =
        app.layer(provenance_layer::ProvenanceLayer)
            .layer(axum::middleware::from_fn_with_state(
                archive_policy,
                archive::record,
            ));
    #[cfg(feature = "otel")]
    let app = app.layer(axum::middleware::from_fn(
        hellas_rpc::telemetry::http::trace_request,
    ));
    let app = app.layer(access::BearerLayer::new(bearer.clone()));
    info!("timeout: {}s", work.timeout().as_secs());

    launch_gateway(
        app,
        listener,
        bearer,
        server.wrap.as_deref(),
        &server.wrap_args,
        work,
    )
    .await
}

async fn launch_gateway(
    app: Router,
    listener: tokio::net::TcpListener,
    bearer: GatewayAccess,
    wrap_command: Option<&str>,
    wrap_args: &[String],
    work: Arc<dyn WorkExecutionBackend>,
) -> crate::GatewayResult<GatewayHandle> {
    let bound_addr = listener.local_addr()?;
    info!("gateway listening on {bound_addr}");
    bearer.announce();

    let wrap_child = if let Some(command) = wrap_command {
        let base = format!("http://{bound_addr}");
        info!("wrapping `{command}` with gateway base {base}");
        Some(wrap::spawn(command, wrap_args, &base, &bearer.bearer())?)
    } else {
        None
    };

    let bearer_value = bearer.bearer();
    let (shutdown, mut server_shutdown) = tokio::sync::watch::channel(false);
    let server = std::future::IntoFuture::into_future(
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ConnectionId>(),
        )
        .with_graceful_shutdown(async move {
            let _ = server_shutdown.wait_for(|stopped| *stopped).await;
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
                            task_shutdown.send_replace(true);
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
        finish_cleanup(result, work.drain().await)
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

/// CLI lifecycle wrapper around [`start`].
pub async fn run(options: GatewayOptions) -> crate::GatewayResult<()> {
    wait_for_shutdown(start(options).await?).await
}

/// Wait for a process signal or wrapped child, then join every gateway listener.
pub async fn wait_for_shutdown(mut handle: GatewayHandle) -> crate::GatewayResult<()> {
    tokio::select! {
        signal = shutdown_signal() => {
            handle.request_shutdown();
            let stopped = (&mut handle.task).await.map_err(GatewayError::Task).and_then(|result| result);
            signal.and(stopped)
        }
        result = &mut handle.task => {
            result.map_err(GatewayError::Task).and_then(|result| result)
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
    (UnixMillis::now().unwrap_or_default().0 / 1_000) as i64
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

    #[test]
    fn cleanup_errors_reach_the_caller_and_preserve_the_primary_failure() {
        assert!(matches!(
            finish_cleanup(Ok(()), Err(WorkShutdownError::Poisoned)),
            Err(GatewayError::Shutdown(WorkShutdownError::Poisoned))
        ));
        let primary = GatewayError::Io(std::io::Error::other("injected server failure"));
        let error =
            finish_cleanup::<()>(Err(primary), Err(WorkShutdownError::Poisoned)).unwrap_err();
        assert!(
            matches!(error, GatewayError::Cleanup { primary, cleanup: WorkShutdownError::Poisoned } if matches!(*primary, GatewayError::Io(_)))
        );
    }
}
