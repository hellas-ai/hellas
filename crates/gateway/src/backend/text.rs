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
                    for event in tools.feed(&delta).map_err(|error| BackendError::Output(error.to_string()))? { yield event.into(); }
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
                    for event in tools.finish(stop_reason_from_runtime(stop_reason.clone())).map_err(|error| BackendError::Output(error.to_string()))? { yield event.into(); }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComputeEvent;
    use hellas_rpc::protocol::invocation::{
        Artifact,
        compute::{RunMetadata, StopReason},
        output::{InvocationOutput, Outcome},
    };
    /// Output that breaks the turn's tool contract is the model's, and the
    /// same request repeats it: it is reported as unusable, not as a failure
    /// a retry could cure.
    #[tokio::test]
    async fn output_breaking_the_tool_contract_is_unusable() {
        use hellas_adaptors::{
            RawRequest, WireAdaptor, openai::chat_completions::OpenAiChatCompletionsAdaptor,
        };
        let presentation = std::sync::Arc::new(
            hellas_presentation::TextPresentation::from_gguf(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../client/src/model/package/mini-qwen3.gguf"),
            )
            .unwrap(),
        );
        let adaptor = OpenAiChatCompletionsAdaptor;
        let parsed = adaptor
            .parse(
                RawRequest::from_value(serde_json::json!({
                    "model": "m", "messages": [{"role": "user", "content": "hi"}],
                    "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}],
                    "tool_choice": "required"
                }))
                .unwrap(),
            )
            .unwrap();
        let canonical = adaptor.to_execution_request(&parsed).unwrap().canonical;
        let chat = presentation.prepare(&canonical).unwrap().turn;
        let prepared = PreparedGeneration {
            chat: Some(chat),
            prepared: Box::pin(futures::stream::iter([Ok(crate::WorkEvent::Output(
                ComputeEvent::Done {
                    output: InvocationOutput {
                        outcome: Outcome::Succeeded,
                        artifacts: vec![Artifact::new("emitted", "catena.u64le.v1", Vec::new())],
                        metadata: hellas_rpc::JsonBytes(
                            hellas_rpc::canonical_dag_cbor(&RunMetadata {
                                steps: 0,
                                stop: Some(StopReason::Matched(3)),
                            })
                            .unwrap(),
                        ),
                    },
                    provider: hellas_auth::PublicKey::Secp256k1([0x02; 33]),
                },
            ))])),
            provenance: None,
            prompt_tokens: 1,
            presentation,
        };
        let events = text_events(prepared).collect::<Vec<_>>().await;
        let error = events.last().unwrap().as_ref().unwrap_err();
        assert!(matches!(error, BackendError::Output(_)), "{error}");
    }
}
