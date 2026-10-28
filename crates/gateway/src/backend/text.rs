use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::{BackendError, BackendEvent, OutputEvent};

use crate::execution::Outcome;

use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, generation_stream};
use super::provenance::{provenance_from_execution, stop_reason_from_runtime, usage};

pub(super) fn text_events(
    mut prepared: PreparedGeneration,
) -> impl futures::Stream<Item = Result<BackendEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let mut tools = prepared.chat.take().unwrap_or_else(hellas_presentation::chat::ChatTurn::plain);
        let stream_provenance = prepared.provenance.clone();
        let deadline = prepared.deadline();
        let inner = generation_stream(prepared);
        tokio::pin!(inner);

        loop {
            match tokio::time::timeout_at(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    for event in tools.feed(&delta).map_err(|error| BackendError::failed(error.to_string()))? { yield event.into(); }
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Completed {
                    output_tokens,
                    stop_reason,
                    text_artifact,
                    ..
                })))) => {
                    info!(
                        %text_artifact,
                        provenance = ?stream_provenance,
                        output_tokens,
                        ?stop_reason,
                        "gateway stream ready"
                    );
                    if let Some(provenance) = stream_provenance.as_ref().map(provenance_from_execution) {
                        yield BackendEvent::Provenance(provenance);
                    }
                    for event in tools.finish(stop_reason_from_runtime(stop_reason)).map_err(|error| BackendError::failed(error.to_string()))? { yield event.into(); }
                    yield OutputEvent::Finished {
                        stop_reason: if tools.called() { hellas_adaptors::StopReason::ToolCall } else { stop_reason_from_runtime(stop_reason) },
                        usage: Some(usage(prompt_tokens, output_tokens)),
                    }.into();
                    return;
                }
                Ok(Some(Ok(GenerationEvent::Done(Outcome::Failed { error, .. })))) => {
                    Err(BackendError::failed(format!("Inference error: {error}")))?;
                }
                Ok(Some(Err(err))) => Err(err)?,
                Ok(None) => Err(BackendError::failed("execution stream ended without terminal outcome"))?,
                Err(_) => Err(BackendError::failed(format!(
                    "inference timed out after {}s",
                    super::super::timeout_secs_until(deadline)
                )))?,
            }
        }
    }
}
