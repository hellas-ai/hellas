//! Validate the canonical input graph carried by an admitted Work job.
use crate::{ExecutorError, state::Invocation};
use hellas_rpc::protocol::artifacts::{
    InputAddressed, OutputAddressed, PreparedPaidInputParts, SourceRef, TextArtifact, TokenIds,
};
use hellas_rpc::{EvaluateRequest, ProgramManifest};
pub(crate) struct ResolvedEvaluateExecution {
    pub evaluate_request: EvaluateRequest,
    pub invocation: Invocation,
}
pub(crate) fn resolve_prepared_paid_input(
    parts: PreparedPaidInputParts,
) -> Result<(ProgramManifest, ResolvedEvaluateExecution), ExecutorError> {
    let PreparedPaidInputParts {
        evaluate_request,
        manifest,
        text_execution,
        prompt_tokens,
        text_policy,
        identity_artifact,
    } = parts;

    if manifest.content_id() != evaluate_request.execution_environment {
        return Err(invalid_prepared_graph("manifest content id"));
    }
    let TextArtifact::Identity { bound_term } = &identity_artifact else {
        return Err(invalid_prepared_graph("identity artifact kind"));
    };
    if bound_term.as_bytes() != evaluate_request.execution_environment.as_bytes() {
        return Err(invalid_prepared_graph("identity artifact bound term"));
    }
    if text_execution.from() != &SourceRef::output(identity_artifact.output_id()) {
        return Err(invalid_prepared_graph("text execution source"));
    }
    if text_execution.input_id().digest() != evaluate_request.text_execution {
        return Err(invalid_prepared_graph("text execution id"));
    }
    if text_execution.prompt_tokens() != prompt_tokens.output_id() {
        return Err(invalid_prepared_graph("prompt tokens id"));
    }
    if text_execution.policy() != text_policy.output_id() {
        return Err(invalid_prepared_graph("text policy id"));
    }

    let invocation = Invocation {
        input_ids: token_ids_to_u32(&prompt_tokens),
        max_new_tokens: text_policy.max_new_tokens(),
        stop_token_ids: text_policy
            .stop_token_ids()
            .iter()
            .map(|token| token.as_u32())
            .collect(),
    };
    Ok((
        manifest,
        ResolvedEvaluateExecution {
            evaluate_request,
            invocation,
        },
    ))
}
fn invalid_prepared_graph(field: &'static str) -> ExecutorError {
    ExecutorError::InvalidInput(format!("journaled paid input has mismatched {field}"))
}
fn token_ids_to_u32(tokens: &TokenIds) -> Vec<u32> {
    tokens
        .as_slice()
        .iter()
        .map(|token| token.as_u32())
        .collect()
}

#[cfg(test)]
mod tests;
