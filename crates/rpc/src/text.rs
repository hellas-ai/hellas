//! Events of one text generation job, as the gateway presents them.
use hellas_auth::Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextEvent {
    Chunk { position: u64, tokens: Vec<u8> },
    Done(TextOutcome),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TextOutcome {
    Completed {
        /// Tokens generated after the prompt.
        output_tokens: u64,
        stop_reason: TextStop,
        text_artifact: Digest,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextStop {
    StopToken(u32),
    MaxNewTokens,
}

impl TextEvent {
    pub fn terminal(&self) -> Option<bool> {
        match self {
            Self::Chunk { .. } => None,
            Self::Done(TextOutcome::Completed { .. }) => Some(true),
            Self::Done(TextOutcome::Failed { .. }) => Some(false),
        }
    }
}
