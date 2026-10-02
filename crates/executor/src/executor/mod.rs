mod actor;
mod handle;
use crate::ExecutorError;
pub use actor::{Executor, ExecutorSpawnConfig};
use hellas_rpc::execution_event::WorkEvent;
use hellas_rpc::{Assurance, OutputEventEnvelope, ProducerSigningKey};
use hellas_wire::WireStatus;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
#[derive(Clone)]
pub(crate) struct ProviderContext {
    pub producer_key: Arc<ProducerSigningKey>,
    pub assurance: Assurance,
}

/// Per-execution receiver returned to the Work consumer.
/// Dropping it closes the matching sender held by the worker, which the
/// worker observes on its next chunk send and reports as an execution failure.
pub(crate) type ExecuteEventReceiver = mpsc::Receiver<Result<WorkEvent, WireStatus>>;

#[derive(Debug)]
pub struct ExecuteOutcome {
    pub events: ExecuteEventReceiver,
    pub(crate) completion: oneshot::Receiver<()>,
}
pub(crate) enum ExecutorOwedRequest {
    RunPaidFetch {
        span: tracing::Span,
        input:
            Box<hellas_work::work::PreparedFetchInput<hellas_work::work::admission::AdmittedWork>>,
        progress: Option<hellas_work::work::PaidProgress>,
        reply: oneshot::Sender<Result<Vec<hellas_rpc::OutputEventEnvelope>, ExecutorError>>,
    },
    /// Start one already-authorized paid job.
    ///
    /// No ticket, no quote, and no admission of its own: the paid endpoint
    /// decided this invocation was owed and made that decision durable before
    /// this message was sent.
    RunPaidEvaluate {
        span: tracing::Span,
        input: Box<
            hellas_work::work::PreparedEvaluateInput<hellas_work::work::admission::AdmittedWork>,
        >,
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
}

pub(crate) enum ExecutorCompletion {
    PaidFetch {
        reply: oneshot::Sender<Result<Vec<OutputEventEnvelope>, ExecutorError>>,
        result: Result<Vec<OutputEventEnvelope>, ExecutorError>,
    },
    #[cfg(feature = "evaluate")]
    EvaluateFinished(Box<crate::worker::WorkerCompletion>),
}
pub(crate) struct FetchProviderRun {
    pub output_events: Vec<OutputEventEnvelope>,
}
pub(crate) struct FetchProviderFailure {
    pub position: u64,
    pub error: crate::FetchProviderError,
}
#[derive(Clone)]
pub struct ExecutorHandle {
    pub(super) owed_tx: mpsc::Sender<ExecutorOwedRequest>,
    pub(crate) fetch_capacity: Arc<tokio::sync::Semaphore>,
    pub(crate) gpu_capacity: Option<Arc<tokio::sync::Semaphore>>,
}
