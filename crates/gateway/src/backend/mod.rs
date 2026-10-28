use std::sync::Arc;

use hellas_adaptors::{BackendFuture, BackendRequest, BackendStream, ExecutionBackend};

mod generation;
mod provenance;
#[cfg_attr(feature = "otel", path = "telemetry/otel.rs")]
#[cfg_attr(not(feature = "otel"), path = "telemetry/noop.rs")]
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
            let prepared = match inference
                .span
                .in_scope(|| self.state.prepare_wire_execution(&request.execution))
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
