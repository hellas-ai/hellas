pub mod jobs;
#[macro_use]
extern crate tracing;

mod access;
mod affinity;
mod route;
mod routing;
pub use access::GatewayAccess;
pub use route::{HttpTarget, Presentation, Route};
pub use routing::RoutingState;
mod archive;
mod audio;
mod backend;
mod compute;
mod dispatch;
mod error;
pub mod router;
pub use error::{GatewayConfigError, GatewayError, GatewayResult};
mod http_fetch;
mod image;
mod provenance_layer;
mod responses_fetch;
mod state;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::Stream;
use hellas_adaptors::BackendError;
use hellas_auth::authority::UnixMillis;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub use archive::ArchiveOptions;
pub use hellas_rpc::compute_event::ComputeEvent;
pub use http_fetch::{HttpRoute, RoutingError};

/// A Fetch run under the selected backend's policy.
#[derive(Clone)]
pub struct WorkFetchRequest {
    pub service: String,
    pub method: String,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkGatewayError {
    #[error("{0}")]
    PreProposal(Box<WorkGatewayError>),
    #[error("request does not match its resource: {0}")]
    Rejected(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("grant access refused: {0}")]
    Denied(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("resource allowance exhausted: {0}")]
    Quota(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Work backend does not support this application")]
    Unsupported,
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
            WorkGatewayError::PreProposal(error) => Self::from(*error),
            WorkGatewayError::Rejected(_) | WorkGatewayError::Unsupported => {
                BackendError::Rejected(message)
            }
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

/// One event of accepted work, as a source reports it to presentations.
#[derive(Clone, Debug)]
pub enum WorkEvent<E> {
    /// The provider accepted the job. Reported once, before any output.
    Accepted(hellas_rpc::provenance::ExecutionProvenance),
    /// Authenticated output: prefixes, then the terminal.
    Output(E),
    /// Canonical bytes of the provider-signed transcript, reported once the
    /// job has completed, just before its terminal output.
    Transcript(Vec<u8>),
}

pub type WorkOutputStream<E> =
    futures::stream::BoxStream<'static, Result<WorkEvent<E>, WorkGatewayError>>;
pub type WorkFetchStream = WorkOutputStream<hellas_rpc::output::OutputEvent>;

/// The acceptance at the head of `events`, if the source reports one; any
/// other first event stays at the head.
pub(crate) async fn accepted<E: Send + 'static>(
    events: &mut WorkOutputStream<E>,
) -> Option<hellas_rpc::provenance::ExecutionProvenance> {
    use futures::StreamExt as _;
    let first = events.next().await?;
    if let Ok(WorkEvent::Accepted(provenance)) = first {
        return Some(provenance);
    }
    let rest = std::mem::replace(events, Box::pin(futures::stream::empty()));
    *events = Box::pin(futures::stream::once(std::future::ready(first)).chain(rest));
    None
}

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

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct BackendInfo {
    pub id: String,
    pub evaluator: Option<String>,
    pub max_in_flight: usize,
    pub in_flight: usize,
    pub down: bool,
}

/// The source every presentation runs its jobs on.
pub trait WorkExecutionBackend: Send + Sync {
    fn backends(&self) -> Vec<BackendInfo>;
    /// The provider's acceptance, authenticated prefixes, the signed
    /// transcript, then durable completion. After proposal the backend owns
    /// collection and funding obligations across disconnects.
    fn fetch(
        &self,
        _backend: &str,
        _request_job: Arc<jobs::Job>,
        _request: WorkFetchRequest,
    ) -> Result<WorkFetchStream, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
    }

    /// Run a rendered Compute job: acceptance, authenticated artifact chunks,
    /// the signed transcript, then durable completion. The backend owns
    /// proposed work across requester disconnects.
    fn run(
        &self,
        _backend: &str,
        _request_job: Arc<jobs::Job>,
        _job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        Err(WorkGatewayError::Unsupported)
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

#[derive(Clone)]
pub struct ImageOptions {
    pub model_name: String,
}

#[derive(Clone)]
pub struct AudioOptions {
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
    pub service: String,
    pub method: String,
    /// Merged into every request body before signing.
    pub overrides: JsonMap<String, JsonValue>,
}

/// Listener tasks belong to the daemon; accepted jobs belong to its job table.
pub fn serve_listener(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<GatewayResult<()>> {
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ConnectionId>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|stop| *stop).await;
        })
        .await
        .map_err(Into::into)
    })
}

pub async fn listener_router(
    app: axum::Router,
    node: hellas_authority::node::NodeCoordinator,
    archive: ArchiveOptions,
) -> GatewayResult<axum::Router> {
    let policy = archive::Policy::new(archive);
    policy.prepare();
    let app =
        app.layer(provenance_layer::ProvenanceLayer)
            .layer(axum::middleware::from_fn_with_state(
                policy,
                archive::record,
            ));
    #[cfg(feature = "otel")]
    let app = app.layer(axum::middleware::from_fn(
        hellas_rpc::telemetry::http::trace_request,
    ));
    Ok(app.layer(access::BearerLayer::new(node)))
}

/// A refusal or failure in the OpenAI error shape.
fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    path_error("", status, message)
}

/// A request an adaptor rejected, in the OpenAI error shape.
fn request_error(error: hellas_adaptors::openai::RequestError) -> Response {
    let status = StatusCode::from_u16(error.status).expect("an adaptor status is valid");
    json_error(status, error.message)
}

/// A refusal or failure on `path`, in the error shape of the wire format
/// served there: Anthropic's on its Messages path, OpenAI's elsewhere.
fn path_error(path: &str, status: StatusCode, message: impl Into<String>) -> Response {
    let render = if path == state::ANTHROPIC_PATH {
        hellas_adaptors::anthropic::render_error
    } else {
        hellas_adaptors::openai::render_error
    };
    dispatch::wire_response(render(status.as_u16(), message.into()))
        .unwrap_or_else(|_| status.into_response())
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

fn work_error(error: WorkGatewayError) -> Response {
    let error: BackendError = error.into();
    json_error(backend_status(&error), error.to_string())
}

#[cfg(test)]
mod test_support;
