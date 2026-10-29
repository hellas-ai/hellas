//! Collect a non-streaming Compute response with its accepted identity and evidence.
use super::{ComputeEvent, WorkEvent, WorkExecutionBackend, WorkGatewayError};
use axum::http::StatusCode;
use futures::StreamExt;
use hellas_client::model::ComputeJob;
use hellas_rpc::{protocol::invocation::output::InvocationOutput, provenance::ExecutionProvenance};

pub(super) struct Completion {
    pub output: Result<InvocationOutput, (StatusCode, String)>,
    pub accepted: Option<ExecutionProvenance>,
    pub transcript: Option<Vec<u8>>,
}

pub(super) async fn collect(
    work: &dyn WorkExecutionBackend,
    job: ComputeJob,
    deadline: Option<tokio::time::Instant>,
    timeout_message: &str,
) -> Completion {
    let (mut accepted, mut transcript) = (None, None);
    let mut stream = match work.run(job) {
        Ok(stream) => stream,
        Err(error) => {
            return Completion {
                output: Err(failure(error)),
                accepted,
                transcript,
            };
        }
    };
    let output = loop {
        match crate::before_deadline(deadline, stream.next()).await {
            Ok(Some(Ok(WorkEvent::Accepted(value)))) => accepted = Some(value),
            Ok(Some(Ok(WorkEvent::Transcript(value)))) => transcript = Some(value),
            Ok(Some(Ok(WorkEvent::Output(ComputeEvent::Output(_))))) => {}
            Ok(Some(Ok(WorkEvent::Output(ComputeEvent::Done { output, .. })))) => break Ok(output),
            Ok(Some(Err(error))) => break Err(failure(error)),
            Ok(None) => {
                break Err((
                    StatusCode::BAD_GATEWAY,
                    "execution stream ended without terminal outcome".into(),
                ));
            }
            Err(_) => break Err((StatusCode::GATEWAY_TIMEOUT, timeout_message.into())),
        }
    };
    Completion {
        output,
        accepted,
        transcript,
    }
}

fn failure(error: WorkGatewayError) -> (StatusCode, String) {
    let error: hellas_adaptors::BackendError = error.into();
    (super::backend_status(&error), error.to_string())
}
