use std::sync::Arc;
use tracing::Instrument;

use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend,
};

mod generation;
mod provenance;
#[cfg_attr(feature = "otel", path = "telemetry/otel.rs")]
#[cfg_attr(not(feature = "otel"), path = "telemetry/noop.rs")]
pub(crate) mod telemetry;
mod text;

use self::text::text_events;
use super::state::{GatewayState, PreparedGeneration};

#[derive(Clone)]
pub(super) struct GatewayBackend {
    state: Arc<GatewayState>,
}

impl GatewayBackend {
    pub(super) fn new(state: Arc<GatewayState>) -> Self {
        Self { state }
    }

    async fn prepare(&self, request: &BackendRequest) -> Result<PreparedGeneration, BackendError> {
        let retention = retention_from_json(request.raw.value())?;
        self.state
            .prepare_wire_execution(&request.execution, retention)
            .await
            .map_err(|err| match err.status {
                axum::http::StatusCode::FORBIDDEN => BackendError::Denied(err.message),
                axum::http::StatusCode::TOO_MANY_REQUESTS => BackendError::Quota(err.message),
                axum::http::StatusCode::SERVICE_UNAVAILABLE => BackendError::Busy(err.message),
                status if status.is_client_error() => BackendError::rejected(err.message),
                _ => BackendError::failed(err.message),
            })
    }
}

impl ExecutionBackend for GatewayBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let mut inference = telemetry::Inference::new(&request, &self.state.inference_metrics);
            let prepared = match self
                .prepare(&request)
                .instrument(inference.span.clone())
                .await
            {
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

use hellas_rpc::Retention;
use serde_json::{Map as JsonMap, Value as JsonValue};
pub(super) fn retention_from_json(value: &JsonValue) -> Result<Retention, BackendError> {
    let object = value
        .as_object()
        .ok_or_else(|| BackendError::rejected("request body must be a JSON object"))?;
    retention_from_json_object(object)
}
fn retention_from_json_object(
    object: &JsonMap<String, JsonValue>,
) -> Result<Retention, BackendError> {
    match object.get("store") {
        None => Ok(Retention::Ephemeral),
        Some(JsonValue::Bool(store)) => Ok(Retention::from_retain(*store)),
        Some(_) => Err(BackendError::rejected("`store` must be a boolean")),
    }
}

fn execution_error(error: hellas_client::ClientError) -> BackendError {
    if let hellas_client::ClientError::External(ref source) = error
        && let Some(work) = source.downcast_ref::<crate::WorkGatewayError>()
    {
        return match work {
            crate::WorkGatewayError::Rejected(_) => BackendError::rejected(work.to_string()),
            crate::WorkGatewayError::Denied(_) => BackendError::Denied(work.to_string()),
            crate::WorkGatewayError::Quota(_) => BackendError::Quota(work.to_string()),
            crate::WorkGatewayError::Busy(_) => BackendError::Busy(work.to_string()),
            _ => BackendError::failed(work.to_string()),
        };
    }
    BackendError::failed(error.to_string())
}
