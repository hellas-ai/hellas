use async_stream::try_stream;
use futures::StreamExt;
use hellas_adaptors::BackendError;
use thiserror::Error;

use crate::execution::Outcome;
use hellas_client::ClientError;
use hellas_presentation::TextOutputDecoder;

use super::super::state::PreparedGeneration;

#[derive(Debug, Clone)]
pub(super) enum GenerationEvent {
    Delta(String),
    Done(Outcome),
}

#[derive(Debug, Error)]
pub(super) enum GenerationError {
    #[error("Inference error: {0}")]
    Execution(#[from] ClientError),
    #[error("Inference error: {0}")]
    Decode(#[from] anyhow::Error),
    #[error("execution stream ended without terminal outcome")]
    MissingTerminalOutcome,
}

impl From<GenerationError> for BackendError {
    fn from(error: GenerationError) -> Self {
        Self::failed(error.to_string())
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
        let mut decoder = TextOutputDecoder::new(&presentation);
        let inner = prepared;
        tokio::pin!(inner);
        while let Some(event) = inner.next().await {
            match event? {
                crate::execution::ExecutionEvent::Chunk { tokens, .. } => {
                    let delta = decoder.push_bytes(&tokens)?;
                    if !delta.is_empty() {
                        yield GenerationEvent::Delta(delta);
                    }
                }
                crate::execution::ExecutionEvent::Done(outcome) => {
                    if matches!(outcome, Outcome::Completed { .. }) {
                        let delta = decoder.finish()?;
                        if !delta.is_empty() {
                            yield GenerationEvent::Delta(delta);
                        }
                    }
                    yield GenerationEvent::Done(outcome);
                    return;
                }
            }
        }
        Err(GenerationError::MissingTerminalOutcome)?;
    }
}
