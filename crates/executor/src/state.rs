//! Worker inputs and terminal observations. Admission belongs to Work.
use crate::ExecutorError;
use hellas_rpc::MAX_STOP_TOKEN_IDS;
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::execution_event::{
    WorkEvent as PbWorkEvent, WorkFailed as PbWorkFailed, WorkFinished as PbWorkFinished,
    work_event,
};
use hellas_rpc::stream::output_event_to_pb;
use uuid::Uuid;
#[derive(Debug, Clone)]
pub struct Invocation {
    pub input_ids: Vec<u32>,
    pub max_new_tokens: u32,
    pub stop_token_ids: Vec<u32>,
}
pub(crate) fn validate_invocation(
    invocation: &Invocation,
    vocabulary_size: u64,
    maximum_capacity: u64,
) -> Result<(), ExecutorError> {
    if invocation.input_ids.is_empty() {
        return Err(ExecutorError::InvalidTokenPayload(
            "input token IDs must not be empty".to_string(),
        ));
    }
    if invocation.max_new_tokens == 0 {
        return Err(ExecutorError::InvalidTokenPayload(
            "max_new_tokens must be greater than zero".to_string(),
        ));
    }
    if invocation.stop_token_ids.len() > MAX_STOP_TOKEN_IDS {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "stop token IDs contains {} entries, over the limit of {MAX_STOP_TOKEN_IDS}",
            invocation.stop_token_ids.len()
        )));
    }
    for (field, tokens) in [
        ("input token IDs", invocation.input_ids.as_slice()),
        ("stop token IDs", invocation.stop_token_ids.as_slice()),
    ] {
        if let Some(token) = tokens
            .iter()
            .copied()
            .find(|&token| u64::from(token) >= vocabulary_size)
        {
            return Err(ExecutorError::InvalidTokenPayload(format!(
                "{field} contain token {token}, but environment vocabulary size is {}",
                vocabulary_size
            )));
        }
    }
    let total_tokens = u64::try_from(invocation.input_ids.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(invocation.max_new_tokens));
    if total_tokens > maximum_capacity {
        return Err(ExecutorError::InvalidTokenPayload(format!(
            "prompt plus max_new_tokens is {total_tokens} tokens, but environment capacity is {}",
            maximum_capacity
        )));
    }
    Ok(())
}
pub fn new_execution_id() -> String {
    make_id("exec")
}
fn make_id(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}
#[cfg(feature = "evaluate")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    StopToken(u32),
    MaxNewTokens,
}

#[cfg(feature = "evaluate")]
#[derive(Debug, Clone)]
pub enum Termination {
    Completed {
        terminal_output_event: Box<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[cfg(feature = "evaluate")]
impl Termination {
    pub fn into_event(self) -> PbWorkEvent {
        let kind = match self {
            Self::Completed {
                terminal_output_event,
                ..
            } => work_event::Kind::Finished(PbWorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal_output_event.as_ref())),
                assurance_evidence: Vec::new(),
            }),
            Self::Failed { position, error } => {
                work_event::Kind::Failed(PbWorkFailed { position, error })
            }
        };
        PbWorkEvent { kind: Some(kind) }
    }
}
