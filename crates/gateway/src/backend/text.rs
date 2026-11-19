//! Decode the native text artifact and project its tokens to wire events.
use super::super::state::PreparedGeneration;
use super::provenance::{completed_provenance, stop_reason_from_runtime, usage};
use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::{BackendError, BackendEvent, OutputEvent};
use hellas_presentation::TextOutputDecoder;
use hellas_rpc::{
    compute_event::ComputeEvent, protocol::invocation::compute::RunMetadata,
    provenance::ExecutionProvenance,
};

fn invalid(error: impl std::fmt::Display) -> BackendError {
    BackendError::failed(format!("Inference error: {error}"))
}
fn output_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::Output(error.to_string())
}

pub(super) fn text_events(
    PreparedGeneration {
        chat,
        mut prepared,
        prompt_tokens,
        presentation,
    }: PreparedGeneration,
    accepted: Option<ExecutionProvenance>,
) -> impl futures::Stream<Item = Result<BackendEvent, BackendError>> + Send {
    try_stream! {
        let mut tools = chat.unwrap_or_else(hellas_presentation::chat::ChatTurn::plain);
        let mut signed = None;
        let mut decoder = TextOutputDecoder::new(&presentation);
        let mut pending = Vec::new();
        let mut received = 0u64;
        while let Some(event) = prepared.next().await {
            let event = match event.map_err(BackendError::from)? {
                crate::WorkEvent::Output(event) => event,
                crate::WorkEvent::Transcript(transcript) => {
                    signed = Some(transcript);
                    continue;
                }
                crate::WorkEvent::Accepted(_) => continue,
            };
            match event {
                ComputeEvent::Output(chunk) => {
                    if chunk.name != "emitted" || chunk.format != "catena.u64le.v1" {
                        Err(invalid("text job returned an unexpected output"))?;
                    }
                    let (offset, bytes) = (chunk.offset, chunk.bytes);
                    if offset != received { Err(invalid("noncontiguous emitted token bytes"))?; }
                    received = received.checked_add(bytes.as_bytes().len() as u64)
                        .ok_or_else(|| invalid("emitted token length overflow"))?;
                    pending.extend_from_slice(bytes.as_bytes());
                    let (whole, _) = pending.as_chunks::<8>();
                    let tokens = whole.iter().map(|bytes| u32::try_from(u64::from_le_bytes(*bytes)))
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(invalid)?;
                    pending.drain(..tokens.len() * 8);
                    let delta = decoder.push_bytes(&hellas_rpc::encode_token_ids(&tokens))
                        .map_err(invalid)?;
                    if !delta.is_empty() {
                        for event in tools.feed(&delta).map_err(output_error)? { yield event.into(); }
                    }
                }
                ComputeEvent::Done { output, .. } => {
                    if !output.is_success() {
                        Err(invalid(format!("text job failed on the provider: {:?}", output.outcome)))?;
                    }
                    let metadata: RunMetadata = hellas_rpc::protocol::value::decode_canonical_dag_cbor(output.metadata.as_bytes())
                        .map_err(invalid)?;
                    let emitted = output.artifacts.iter().find(|artifact| artifact.name == "emitted")
                        .ok_or_else(|| invalid("text output has no emitted tokens"))?;
                    if !pending.is_empty() || emitted.format != "catena.u64le.v1"
                        || received != emitted.bytes.as_bytes().len() as u64
                        || metadata.steps.checked_mul(8) != Some(received) {
                        Err(invalid("incomplete text token stream"))?;
                    }
                    let output_tokens = metadata.steps;
                    let stop_reason = metadata.stop.ok_or_else(|| invalid("text output has no stop reason"))?;
                    let text_artifact = emitted.content_id().map_err(invalid)?.digest();
                    let delta = decoder.finish().map_err(invalid)?;
                    if !delta.is_empty() {
                        for event in tools.feed(&delta).map_err(output_error)? { yield event.into(); }
                    }
                    info!(%text_artifact, provenance = ?accepted, output_tokens, ?stop_reason, "gateway stream ready");
                    if let Some(transcript) = signed {
                        yield BackendEvent::Provenance(completed_provenance(accepted.as_ref(), &transcript));
                    }
                    let stop = stop_reason_from_runtime(stop_reason);
                    for event in tools.finish(stop).map_err(output_error)? { yield event.into(); }
                    yield OutputEvent::Finished {
                        stop_reason: if tools.called() { hellas_adaptors::StopReason::ToolCall } else { stop },
                        usage: Some(usage(prompt_tokens, output_tokens)),
                    }.into();
                    return;
                }
            }
        }
        Err(BackendError::failed("execution stream ended without terminal outcome"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ComputeEvent;
    use hellas_rpc::JsonBytes;
    use hellas_rpc::protocol::invocation::{
        Artifact,
        compute::StopReason,
        output::{ArtifactChunk, InvocationOutput, Outcome},
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn split_compute_values_decode_to_text_and_usage() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/package/mini-qwen3.gguf");
        let bytes: Vec<_> = [0u64, 1].into_iter().flat_map(u64::to_le_bytes).collect();
        let mut events = Vec::new();
        for (offset, bytes) in [(0, &bytes[..3]), (3, &bytes[3..9]), (9, &bytes[9..])] {
            events.push(Ok(ComputeEvent::Output(ArtifactChunk {
                name: "emitted".into(),
                format: "catena.u64le.v1".into(),
                offset,
                bytes: JsonBytes(bytes.to_vec()),
            })));
        }
        let emitted = Artifact::new("emitted", "catena.u64le.v1", bytes);
        events.push(Ok(ComputeEvent::Done {
            provider: hellas_auth::ProducerSigningKey::from_secret_bytes([7; 32])
                .unwrap()
                .public_key(),
            output: InvocationOutput {
                outcome: Outcome::Succeeded,
                artifacts: vec![emitted],
                metadata: JsonBytes(
                    hellas_rpc::canonical_dag_cbor(&RunMetadata {
                        steps: 2,
                        stop: Some(StopReason::MaxSteps),
                    })
                    .unwrap(),
                ),
            },
        }));
        let stream = text_events(
            PreparedGeneration {
                chat: None,
                prepared: Box::pin(
                    futures::stream::iter(events).map(|event| event.map(crate::WorkEvent::Output)),
                ),
                prompt_tokens: 1,
                presentation: Arc::new(
                    hellas_presentation::TextPresentation::from_gguf(&path).unwrap(),
                ),
            },
            None,
        );
        tokio::pin!(stream);
        let mut text = String::new();
        let mut completed = false;
        while let Some(event) = stream.next().await {
            match event.unwrap() {
                BackendEvent::Output(OutputEvent::TextDelta { delta, .. }) => text.push_str(&delta),
                BackendEvent::Output(OutputEvent::Finished { stop_reason, usage }) => {
                    assert_eq!(usage.unwrap().output_tokens, Some(2));
                    assert_eq!(stop_reason, hellas_adaptors::StopReason::MaxOutputTokens);
                    completed = true;
                }
                event => panic!("unexpected event {event:?}"),
            }
        }
        assert_eq!(text, "hi");
        assert!(completed);
    }

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
            prompt_tokens: 1,
            presentation,
        };
        let events = text_events(prepared, None).collect::<Vec<_>>().await;
        let error = events.last().unwrap().as_ref().unwrap_err();
        assert!(matches!(error, BackendError::Output(_)), "{error}");
    }
}
