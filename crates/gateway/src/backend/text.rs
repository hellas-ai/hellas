use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::{BackendError, BackendEvent, OutputEvent};

use super::generation::TextCompletion;

use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, generation_stream};
use super::provenance::{completed_provenance, stop_reason_from_runtime, usage};

pub(super) fn text_events(
    mut prepared: PreparedGeneration,
) -> impl futures::Stream<Item = Result<BackendEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let mut tools = prepared.chat.take().unwrap_or_else(hellas_presentation::chat::ChatTurn::plain);
        let stream_provenance = prepared.provenance.clone();
        let mut transcript = None;
        let inner = generation_stream(prepared);
        tokio::pin!(inner);

        loop {
            match inner.next().await {
                Some(Ok(GenerationEvent::Transcript(signed))) => transcript = Some(signed),
                Some(Ok(GenerationEvent::Delta(delta))) => {
                    for event in tools.feed(&delta).map_err(|error| BackendError::failed(error.to_string()))? { yield event.into(); }
                }
                Some(Ok(GenerationEvent::Done(TextCompletion {
                    output_tokens,
                    stop_reason,
                    text_artifact,
                    ..
                }))) => {
                    info!(
                        %text_artifact,
                        provenance = ?stream_provenance,
                        output_tokens,
                        ?stop_reason,
                        "gateway stream ready"
                    );
                    if let Some(transcript) = &transcript {
                        yield BackendEvent::Provenance(completed_provenance(stream_provenance.as_ref(), transcript));
                    }
                    for event in tools.finish(stop_reason_from_runtime(stop_reason.clone())).map_err(|error| BackendError::failed(error.to_string()))? { yield event.into(); }
                    yield OutputEvent::Finished {
                        stop_reason: if tools.called() { hellas_adaptors::StopReason::ToolCall } else { stop_reason_from_runtime(stop_reason) },
                        usage: Some(usage(prompt_tokens, output_tokens)),
                    }.into();
                    return;
                }
                Some(Err(err)) => Err(err)?,
                None => Err(BackendError::failed("execution stream ended without terminal outcome"))?,
            }
        }
    }
}
