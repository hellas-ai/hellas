//! Collect a non-streaming Compute response with its accepted identity and evidence.
use super::{ComputeEvent, WorkEvent, WorkGatewayError};
use axum::http::StatusCode;
use futures::StreamExt;
use hellas_rpc::{protocol::invocation::output::InvocationOutput, provenance::ExecutionProvenance};

pub(super) struct Completion {
    pub output: Result<InvocationOutput, (StatusCode, String)>,
    pub accepted: Option<ExecutionProvenance>,
    pub transcript: Option<Vec<u8>>,
}

pub(super) async fn collect(mut stream: crate::WorkOutputStream<ComputeEvent>) -> Completion {
    let (mut accepted, mut transcript) = (None, None);
    let output = loop {
        match stream.next().await {
            Some(Ok(WorkEvent::Accepted(value))) => accepted = Some(value),
            Some(Ok(WorkEvent::Transcript(value))) => transcript = Some(value),
            Some(Ok(WorkEvent::Output(ComputeEvent::Output(_)))) => {}
            Some(Ok(WorkEvent::Output(ComputeEvent::Done { output, .. }))) => break Ok(output),
            Some(Err(error)) => break Err(failure(error)),
            None => {
                break Err((
                    StatusCode::BAD_GATEWAY,
                    "execution stream ended without terminal outcome".into(),
                ));
            }
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
