use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::BackendError;
use thiserror::Error;

use hellas_rpc::{
    compute_event::ComputeEvent,
    protocol::invocation::compute::{RunMetadata, StopReason},
};

#[derive(Debug, Clone)]
pub(super) struct TextCompletion {
    pub output_tokens: u64,
    pub stop_reason: StopReason,
    pub text_artifact: hellas_auth::Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::{
        JsonBytes,
        protocol::invocation::{
            Artifact,
            output::{ArtifactChunk, InvocationOutput, Outcome},
        },
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
        let digest = emitted.content_id().unwrap().digest();
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
        let stream = generation_stream(PreparedGeneration {
            chat: None,
            prepared: Box::pin(
                futures::stream::iter(events).map(|event| event.map(crate::WorkEvent::Output)),
            ),
            provenance: None,
            prompt_tokens: 1,
            presentation: Arc::new(
                hellas_presentation::TextPresentation::from_gguf(&path).unwrap(),
            ),
            deadline: Some(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
        });
        tokio::pin!(stream);
        let mut text = String::new();
        let mut completed = false;
        while let Some(event) = stream.next().await {
            match event.unwrap() {
                GenerationEvent::Transcript(_) => panic!("fixture has no transcript"),
                GenerationEvent::Delta(delta) => text.push_str(&delta),
                GenerationEvent::Done(done) => {
                    assert_eq!(done.output_tokens, 2);
                    assert_eq!(done.stop_reason, StopReason::MaxSteps);
                    assert_eq!(done.text_artifact, digest);
                    completed = true;
                }
            }
        }
        assert_eq!(text, "hi");
        assert!(completed);
    }
}
use hellas_presentation::TextOutputDecoder;

use super::super::state::PreparedGeneration;

#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Delta(String),
    /// Canonical bytes of the provider-signed transcript.
    Transcript(Vec<u8>),
    Done(TextCompletion),
}

#[derive(Debug, Error)]
pub(super) enum GenerationError {
    #[error("Inference error: {0}")]
    Execution(#[from] crate::WorkGatewayError),
    #[error("Inference error: {0}")]
    Decode(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("execution stream ended without terminal outcome")]
    MissingTerminalOutcome,
}

impl From<GenerationError> for BackendError {
    fn from(error: GenerationError) -> Self {
        match error {
            GenerationError::Execution(error) => error.into(),
            error => Self::failed(error.to_string()),
        }
    }
}

pub(super) fn generation_stream(
    generation: PreparedGeneration,
) -> impl futures::Stream<Item = Result<GenerationEvent, GenerationError>> + Send {
    let PreparedGeneration {
        prepared,
        presentation,
        ..
    } = generation;
    try_stream! {
        let invalid = |message: &str| GenerationError::Decode(std::io::Error::other(message).into());
        let mut decoder = TextOutputDecoder::new(&presentation);
        let mut pending = Vec::new();
        let mut received = 0u64;
        tokio::pin!(prepared);
        while let Some(event) = prepared.next().await {
            let event = match event? {
                crate::WorkEvent::Output(event) => event,
                crate::WorkEvent::Transcript(transcript) => {
                    yield GenerationEvent::Transcript(transcript);
                    continue;
                }
                // PreparedGeneration::accept consumed the acceptance.
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
                        .map_err(|error| GenerationError::Decode(error.into()))?;
                    pending.drain(..tokens.len() * 8);
                    let delta = decoder.push_bytes(&hellas_rpc::encode_token_ids(&tokens))
                        .map_err(|error| GenerationError::Decode(error.into()))?;
                    if !delta.is_empty() { yield GenerationEvent::Delta(delta); }
                }
                ComputeEvent::Done { output, .. } => {
                    if !output.is_success() {
                        Err(invalid(&format!("text job failed on the provider: {:?}", output.outcome)))?;
                    }
                    let metadata: RunMetadata = hellas_rpc::protocol::value::decode_canonical_dag_cbor(output.metadata.as_bytes())
                        .map_err(|error| GenerationError::Decode(error.into()))?;
                    let emitted = output.artifacts.iter().find(|artifact| artifact.name == "emitted")
                        .ok_or_else(|| invalid("text output has no emitted tokens"))?;
                    if !pending.is_empty() || emitted.format != "catena.u64le.v1"
                        || received != emitted.bytes.as_bytes().len() as u64
                        || metadata.steps.checked_mul(8) != Some(received) {
                        Err(invalid("incomplete text token stream"))?;
                    }
                    let outcome = TextCompletion {
                        output_tokens: metadata.steps,
                        stop_reason: metadata.stop.ok_or_else(|| invalid("text output has no stop reason"))?,
                        text_artifact: emitted.content_id().map_err(|error| GenerationError::Decode(error.into()))?.digest(),
                    };
                    let delta = decoder.finish().map_err(|error| GenerationError::Decode(error.into()))?;
                    if !delta.is_empty() { yield GenerationEvent::Delta(delta); }
                    yield GenerationEvent::Done(outcome);
                    return;
                }
            }
        }
        Err(GenerationError::MissingTerminalOutcome)?;
    }
}
