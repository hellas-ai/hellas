use std::sync::Arc;

use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend,
};

mod generation;
mod provenance;
pub(crate) mod telemetry;
mod text;

use self::text::text_events;
use super::state::TextState;

#[derive(Clone)]
pub(super) struct GatewayBackend {
    state: Arc<TextState>,
}

impl GatewayBackend {
    pub(super) fn new(state: Arc<TextState>) -> Self {
        Self { state }
    }
}

impl ExecutionBackend for GatewayBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let mut inference = telemetry::Inference::new(&request, &self.state.inference_metrics);
            let prepared = match stateless(request.raw.value()).and_then(|()| {
                inference
                    .span
                    .in_scope(|| self.state.prepare_wire_execution(&request.execution))
            }) {
                Ok(prepared) => prepared,
                Err(error) => {
                    inference.fail(&error);
                    return Err(error);
                }
            };
            inference.response_model(&request.execution.canonical.model.name);
            let initial_provenance = prepared
                .provenance
                .as_ref()
                .map(self::provenance::provenance_from_execution);
            Ok(BackendStream::new(
                inference.stream(text_events(prepared)),
                initial_provenance,
            ))
        })
    }
}

/// Text jobs keep nothing between requests: a request may neither ask for its
/// response to be stored nor continue one the gateway never kept.
fn stateless(body: &serde_json::Value) -> Result<(), BackendError> {
    match body.get("store") {
        None | Some(serde_json::Value::Bool(false)) => {}
        Some(serde_json::Value::Bool(true)) => {
            return Err(BackendError::rejected(
                "this gateway keeps no responses; `store` must be false",
            ));
        }
        Some(_) => return Err(BackendError::rejected("`store` must be a boolean")),
    }
    if ["previous_response_id", "conversation"]
        .iter()
        .any(|field| body.get(field).is_some_and(|value| !value.is_null()))
    {
        return Err(BackendError::Conflict(
            "unknown or expired server-side continuation; resend full context".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_requests_may_not_store_or_continue_server_side_state() {
        for body in [
            json!({}),
            json!({"store": false}),
            json!({"previous_response_id": null}),
        ] {
            stateless(&body).unwrap();
        }
        for body in [json!({"store": true}), json!({"store": "no"})] {
            assert!(matches!(stateless(&body), Err(BackendError::Rejected(_))));
        }
        for body in [
            json!({"previous_response_id": "resp_1"}),
            json!({"conversation": "conv_1"}),
        ] {
            let error = stateless(&body).unwrap_err();
            assert!(matches!(error, BackendError::Conflict(_)));
            assert_eq!(
                crate::backend_status(&error),
                axum::http::StatusCode::CONFLICT
            );
            assert!(error.to_string().contains("resend full context"));
        }
    }
}
