use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::{BackendError, OutputEvent};

use super::generation::TextCompletion;

use super::super::state::PreparedGeneration;
use super::generation::{GenerationEvent, generation_stream};
use super::provenance::{provenance_from_execution, stop_reason_from_runtime, usage};

pub(super) fn text_events(
    mut prepared: PreparedGeneration,
) -> impl futures::Stream<Item = Result<OutputEvent, BackendError>> + Send {
    try_stream! {
        let prompt_tokens = prepared.prompt_tokens;
        let mut tools = prepared.chat.take().unwrap_or_else(hellas_presentation::chat::ChatTurn::plain);
        let stream_provenance = prepared.provenance.clone();
        let deadline = prepared.deadline();
        let inner = generation_stream(prepared);
        tokio::pin!(inner);

        loop {
            match crate::before_deadline(deadline, inner.next()).await {
                Ok(Some(Ok(GenerationEvent::Delta(delta)))) => {
                    for event in tools.feed(&delta).map_err(|error| BackendError::failed(error.to_string()))? { yield event; }
                }
                Ok(Some(Ok(GenerationEvent::Done(TextCompletion {
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
                        yield OutputEvent::Provenance(provenance);
                    }
                    for event in tools.finish(stop_reason_from_runtime(stop_reason.clone())).map_err(|error| BackendError::failed(error.to_string()))? { yield event; }
                    yield OutputEvent::Finished {
                        stop_reason: if tools.called() { hellas_adaptors::StopReason::ToolCall } else { stop_reason_from_runtime(stop_reason) },
                        usage: Some(usage(prompt_tokens, output_tokens)),
                    };
                    return;
                }
                Ok(Some(Err(err))) => Err(err)?,
                Ok(None) => Err(BackendError::failed("execution stream ended without terminal outcome"))?,
                Err(_) => Err(BackendError::failed("inference timed out"))?,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComputeEvent;
    use hellas_rpc::protocol::invocation::{
        Artifact,
        compute::{RunMetadata, StopReason},
        output::{InvocationOutput, Outcome},
    };

    #[tokio::test(start_paused = true)]
    async fn text_waits_without_a_client_deadline_but_keeps_explicit_budgets() {
        for timeout in [None, Some(std::time::Duration::from_secs(5))] {
            let prepared = PreparedGeneration {
                chat: None,
                prepared: Box::pin(async_stream::try_stream! {
                    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                    yield ComputeEvent::Output(hellas_rpc::protocol::invocation::output::ArtifactChunk {
                        name: "emitted".into(),
                        format: "catena.u64le.v1".into(),
                        offset: 0,
                        bytes: hellas_rpc::JsonBytes(0u64.to_le_bytes().to_vec()),
                    });
                    yield ComputeEvent::Done {
                        output: InvocationOutput {
                            outcome: Outcome::Succeeded,
                            artifacts: vec![Artifact::new("emitted", "catena.u64le.v1", 0u64.to_le_bytes().to_vec())],
                            metadata: hellas_rpc::JsonBytes(hellas_rpc::canonical_dag_cbor(&RunMetadata { steps: 1, stop: Some(StopReason::MaxSteps) }).unwrap()),
                        },
                        provider: hellas_auth::ProducerSigningKey::from_secret_bytes([7;32]).unwrap().public_key(),
                    };
                }),
                provenance: None,
                prompt_tokens: 1,
                presentation: std::sync::Arc::new(
                    hellas_presentation::TextPresentation::from_gguf(
                        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../client/src/model/package/mini-qwen3.gguf"),
                    )
                    .unwrap(),
                ),
                inference_timeout: timeout,
            };
            let events = text_events(prepared).collect::<Vec<_>>().await;
            if timeout.is_some() {
                assert!(
                    events
                        .last()
                        .unwrap()
                        .as_ref()
                        .unwrap_err()
                        .to_string()
                        .contains("inference timed out")
                );
            } else {
                assert!(matches!(
                    events.last(),
                    Some(Ok(OutputEvent::Finished { .. }))
                ));
            }
        }
    }
}
