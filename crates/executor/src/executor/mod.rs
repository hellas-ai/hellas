mod actor;
mod handle;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::worker::WorkerCompletion;
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, GetStatsResponse, QuoteResponse, QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{RunTicketRequest, Ticket, WorkEvent};
use hellas_rpc::pb::fetch::FetchRequest as PbFetchRequest;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::{Assurance, InputCommitment, OutputEventEnvelope, ProducerSigningKey};
use hellas_wire::WireStatus;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

#[cfg(all(test, feature = "evaluate"))]
use crate::evaluate::EvaluateJob;
use crate::fetch_policy::FetchQuotaReservation;
use crate::fetch_projection::FetchProjector;
use crate::fetch_provider::{FetchProvider, FetchProviderError, PreparedFetchRequest};
pub use actor::{Executor, ExecutorSpawnConfig};

#[derive(Clone)]
pub(crate) struct ProviderContext {
    pub producer_key: Arc<ProducerSigningKey>,
    pub genesis: Arc<Vec<u8>>,
    pub assurance: Assurance,
}

/// Per-execution receiver returned to the streaming `Execute` consumer.
/// Dropping it closes the matching sender held by the worker, which the
/// worker observes on its next chunk send and reports as an execution failure.
pub(crate) type ExecuteEventReceiver = mpsc::Receiver<Result<WorkEvent, WireStatus>>;

/// Quote response paired with the provenance the executor committed to.
/// `provenance` is the same value the executor logs at quote/accept time;
/// callers (the tonic Execute impl) attach it to outgoing Response
/// metadata so gateways/clients can correlate the wire response with the
/// commitment that produced it.
#[derive(Debug)]
pub struct TicketOutcome<R> {
    pub response: R,
    pub provenance: ExecutionProvenance,
}

/// Streaming execution paired with the provenance committed to at
/// quote-acceptance time. Scheme results are carried by signed terminal
/// output events in the stream, not by `ExecutionProvenance`.
#[derive(Debug)]
pub struct ExecuteOutcome {
    pub provenance: ExecutionProvenance,
    pub events: ExecuteEventReceiver,
}

/// Requests entering the executor actor from its in-process clients.
///
/// The channel carrying these is bounded because most senders are ultimately
/// driven by peers. Completion notifications use a separate channel: an
/// adversary filling this mailbox must not prevent accepted work from retiring.
pub(crate) enum ExecutorRequest {
    QuoteEvaluate {
        request: PbEvaluateRequest,
        reply: oneshot::Sender<Result<TicketOutcome<Ticket>, ExecutorError>>,
    },
    QuoteFetch {
        request: PbFetchRequest,
        reply: oneshot::Sender<Result<TicketOutcome<Ticket>, ExecutorError>>,
    },
    QuoteTokens {
        request: QuoteTokensRequest,
        reply: oneshot::Sender<Result<TicketOutcome<QuoteResponse>, ExecutorError>>,
    },
    GetArtifact {
        request: GetArtifactRequest,
        reply: oneshot::Sender<Result<GetArtifactResponse, ExecutorError>>,
    },
    /// Single streaming entry point: validate the quote, accept the job
    /// (queueing if the worker is busy), and return a Receiver wired to
    /// the worker's per-execution sender.
    Execute {
        span: tracing::Span,
        request: RunTicketRequest,
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
    GetStats {
        reply: oneshot::Sender<Result<GetStatsResponse, ExecutorError>>,
    },
    #[cfg(all(test, feature = "evaluate"))]
    StartEvaluateForTest {
        job: Box<EvaluateJob>,
        execution_id: String,
        request_commitment: [u8; 32],
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
    #[cfg(all(test, feature = "evaluate"))]
    BarrierForTest {
        entered: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    },
}

/// Trusted work whose invocation has already been made durable by its owner.
///
/// This has a distinct bounded ingress so peer RPC traffic cannot delay its
/// admission past queued best-effort execution.
pub(crate) enum ExecutorOwedRequest {
    /// Start one already-authorized paid job.
    ///
    /// No ticket, no quote, and no admission of its own: the paid endpoint
    /// decided this invocation was owed and made that decision durable before
    /// this message was sent.
    RunPaidEvaluate {
        span: tracing::Span,
        input: Box<hellas_work::work::PreparedEvaluateInput>,
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
    #[cfg(all(test, feature = "evaluate"))]
    StartEvaluateForTest {
        job: Box<EvaluateJob>,
        execution_id: String,
        request_commitment: [u8; 32],
        reply: oneshot::Sender<Result<ExecuteOutcome, ExecutorError>>,
    },
}

/// Trusted notifications from the bounded set of active execution producers.
pub(crate) enum ExecutorCompletion {
    #[cfg(feature = "evaluate")]
    EvaluateFinished(Box<WorkerCompletion>),
    FetchFinished(Box<FetchCompletion>),
}

pub(crate) struct FetchCompletion {
    pub input_commitment: InputCommitment,
    pub request_commitment_id: [u8; 32],
    pub quota_reservation: Option<FetchQuotaReservation>,
    pub execution_id: String,
    pub metric_name: String,
    pub sender: ExecuteEventReceiverSender,
    pub result: Result<FetchProviderRun, FetchProviderFailure>,
}

pub(crate) type ExecuteEventReceiverSender = mpsc::Sender<Result<WorkEvent, WireStatus>>;

pub(crate) struct FetchProviderRun {
    pub output_events: Vec<OutputEventEnvelope>,
    pub position: u64,
}

pub(crate) struct FetchProviderFailure {
    pub position: u64,
    pub error: FetchProviderError,
}

pub(crate) struct PendingFetch {
    pub span: tracing::Span,
    pub request: PreparedFetchRequest,
    pub provider: Arc<dyn FetchProvider>,
    pub projector: Box<dyn FetchProjector>,
    pub quota_reservation: Option<FetchQuotaReservation>,
    pub input_commitment: InputCommitment,
    pub assurance: Assurance,
    pub request_commitment_id: [u8; 32],
    pub execution_id: String,
    pub metric_name: String,
    pub sender: ExecuteEventReceiverSender,
}

#[derive(Clone)]
pub struct ExecutorHandle {
    pub(super) tx: mpsc::Sender<ExecutorRequest>,
    pub(super) owed_tx: mpsc::Sender<ExecutorOwedRequest>,
}
