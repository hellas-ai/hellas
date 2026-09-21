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
        let retention = super::fetch_backend::retention_from_json(request.raw.value())?;
        self.state
            .prepare_wire_execution(&request.execution, retention)
            .await
            .map_err(|err| {
                if err.status.is_client_error() {
                    BackendError::rejected(err.message)
                } else {
                    BackendError::failed(err.message)
                }
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
