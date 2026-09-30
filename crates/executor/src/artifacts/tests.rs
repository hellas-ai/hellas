use super::*;
use hellas_rpc::{
    ContentId,
    protocol::artifacts::{BoundTermId, TextExecution, TextPolicy},
};
fn runner_public_key() -> hellas_rpc::PublicKey {
    hellas_rpc::ProducerSigningKey::from_secret_bytes([8; 32])
        .expect("valid test key")
        .public_key()
}
fn paid_parts() -> PreparedPaidInputParts {
    let manifest = ProgramManifest::new(
        hellas_rpc::Application::new("hellas/catena-gpu-0.0.1", "causal-lm-0.0.1").unwrap(),
        ContentId::from_bytes([0x42; 32]),
    );
    let execution_environment = manifest.content_id();
    let identity_artifact =
        TextArtifact::identity(BoundTermId::from_digest(execution_environment.digest()));
    let prompt_tokens = TokenIds::from([1, 2, 3]);
    let text_policy = TextPolicy::from_u32_stop_tokens(8, [4, 5]);
    let text_execution = TextExecution::new(
        SourceRef::output(identity_artifact.output_id()),
        prompt_tokens.output_id(),
        text_policy.output_id(),
    );
    let evaluate_request = EvaluateRequest {
        text_execution: text_execution.input_id().digest(),
        runner_public_key: runner_public_key(),
        execution_environment,
        nonce: [7; 32],
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    PreparedPaidInputParts {
        evaluate_request,
        manifest,
        text_execution,
        prompt_tokens,
        text_policy,
        identity_artifact,
    }
}
#[test]
fn journaled_paid_input_resolves_without_transient_state() {
    let parts = paid_parts();
    let expected_request = parts.evaluate_request.clone();
    let expected_manifest = parts.manifest.clone();

    let (manifest, resolved) = resolve_prepared_paid_input(parts).unwrap();

    assert_eq!(manifest, expected_manifest);
    assert_eq!(resolved.evaluate_request, expected_request);
    assert_eq!(resolved.invocation.input_ids, [1, 2, 3]);
    assert_eq!(resolved.invocation.max_new_tokens, 8);
    assert_eq!(resolved.invocation.stop_token_ids, [4, 5]);
}
#[test]
fn journaled_paid_input_rechecks_its_graph() {
    let mut parts = paid_parts();
    parts.prompt_tokens = TokenIds::from([99]);

    let error = resolve_prepared_paid_input(parts)
        .err()
        .expect("invalid graph");

    assert!(error.to_string().contains("prompt tokens id"), "{error}");
}
