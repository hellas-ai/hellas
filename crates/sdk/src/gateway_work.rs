//! Funding-independent gateway input preparation and bounded output delivery.
use futures::stream::BoxStream;
use hellas_gateway::{ExecutionEvent, Outcome, StopReason, WorkExecutionRequest, WorkGatewayError};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1, SourceRef,
    TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

pub const OUTPUT_BUFFER_BYTES: usize = 2 * hellas_work::work_store::journal::MAX_RECORD_BYTES;
pub const OUTPUT_EVENT_OVERHEAD: usize = 1024;
pub const OUTPUT_BUFFER_EVENTS: usize = OUTPUT_BUFFER_BYTES / OUTPUT_EVENT_OVERHEAD;
pub type BufferedEvent<E, X> = (Result<E, X>, OwnedSemaphorePermit);
fn error(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Execution(Box::new(e))
}

pub fn prepare_evaluate(
    request: WorkExecutionRequest,
    runner: hellas_rpc::PublicKey,
) -> Result<PreparedPaidInputV1, WorkGatewayError> {
    hellas_client::execution::validate_causal_lm_invocation(
        &request.environment,
        &request.input_ids,
        request.max_new_tokens,
        &request.stop_token_ids,
    )
    .map_err(|e| WorkGatewayError::Rejected(Box::new(e)))?;
    let manifest = request.environment.manifest();
    let tokens = TokenIds::from_u32s(request.input_ids);
    let policy = TextPolicy::from_u32_stop_tokens(request.max_new_tokens, request.stop_token_ids);
    let identity = TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        tokens.output_id(),
        policy.output_id(),
    );
    let evaluate = hellas_rpc::EvaluateRequest {
        text_execution: execution.input_id().digest(),
        runner_public_key: runner,
        execution_environment: manifest.content_id(),
        nonce: rand::random(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    Ok(PreparedPaidInputV1::new(
        &evaluate, &manifest, &execution, &tokens, &policy, &identity,
    ))
}

/// Called only after the funding session has verified the complete transcript.
pub fn evaluate_terminal(
    events: Vec<hellas_rpc::OutputEventEnvelope>,
) -> Result<ExecutionEvent, WorkGatewayError> {
    let envelope = events
        .last()
        .ok_or(hellas_rpc::evaluate::EvaluateProtocolError::EmptyOutputTranscript)
        .map_err(error)?;
    let terminal =
        hellas_rpc::evaluate::decode_terminal_payload(envelope.payload()).map_err(error)?;
    let stop_reason =
        if terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN {
            // The canonical terminal decoder checks the stop witness.
            StopReason::StopToken(
                terminal
                    .matched_stop_token_id
                    .expect("validated stop witness"),
            )
        } else {
            StopReason::MaxNewTokens
        };
    Ok(ExecutionEvent::Done(Outcome::Completed {
        total_tokens: terminal.usage.billable_units().map_err(error)?,
        stop_reason,
        text_artifact: terminal.text_artifact,
        output_events: events,
    }))
}

pub fn emit<E, X>(
    sender: &mpsc::Sender<BufferedEvent<E, X>>,
    overflow: &watch::Sender<bool>,
    budget: &Arc<Semaphore>,
    event: Result<E, X>,
    bytes: usize,
) {
    if *overflow.borrow() || sender.is_closed() {
        return;
    }
    let bytes = bytes.saturating_add(OUTPUT_EVENT_OVERHEAD);
    let permits = u32::try_from(bytes)
        .ok()
        .and_then(|n| budget.clone().try_acquire_many_owned(n).ok());
    let Some(permits) = permits else {
        overflow.send_replace(true);
        return;
    };
    if matches!(
        sender.try_send((event, permits)),
        Err(mpsc::error::TrySendError::Full(_))
    ) {
        overflow.send_replace(true);
    }
}
pub fn response_stream<E: Send + 'static, X: Send + 'static>(
    mut receiver: mpsc::Receiver<BufferedEvent<E, X>>,
    mut overflow: watch::Receiver<bool>,
    slow_consumer: fn() -> X,
) -> BoxStream<'static, Result<E, X>> {
    Box::pin(async_stream::try_stream! {
        loop {
            if *overflow.borrow() { receiver.close(); Err(slow_consumer())?; }
            let event = tokio::select! {
                biased;
                _ = overflow.changed(), if overflow.has_changed().is_ok() => continue,
                event = receiver.recv() => event,
            };
            match event { Some((event, permit)) => { drop(permit); yield event?; }, None => return }
        }
    })
}
