//! Exercise the real client factory with hostile process configuration in a child.
use hellas_providers::{execute_responses_request, responses_http_client};

use hellas_providers::test_support as interception;

#[tokio::test]
async fn responses_transport_rejects_operator_interception() {
    interception::rejects_operator_interception(
        "responses_transport_rejects_operator_interception",
        1,
        |url| async move {
            execute_responses_request(
                &responses_http_client(Default::default()).unwrap(),
                url,
                "PRIVATE_CREDENTIAL_CANARY",
                b"PRIVATE_PROMPT_CANARY".to_vec(),
                "fixture-idempotency",
                "fixture",
            )
            .await
            .is_err()
        },
    )
    .await;
}
