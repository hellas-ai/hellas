//! Responses presentation over an already funded, authenticated Work backend.
use super::backend::provenance::{completed_provenance, provenance_from_execution};
use super::{WorkEvent, WorkFetchRequest, route::RouteExecution};
use axum::{Router, body::Bytes, extract::State, response::Response, routing::post};
use futures::StreamExt;
use hellas_adaptors::{
    BackendError, BackendEvent, BackendFuture, BackendRequest, BackendStream, ExecutionBackend,
    openai::responses::OpenAiResponsesAdaptor,
};
use serde_json::Value;
use std::sync::Arc;

/// The path the Responses presentation serves.
pub(super) const PATH: &str = "/v1/responses";

pub(super) fn router(
    service: String,
    method: String,
    overrides: serde_json::Map<String, Value>,
    work: Arc<RouteExecution>,
) -> Router {
    Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(ResponsesState {
            work,
            service,
            method,
            overrides,
        }))
}
struct ResponsesState {
    work: Arc<RouteExecution>,
    service: String,
    method: String,
    overrides: serde_json::Map<String, Value>,
}
#[derive(Clone)]
struct FetchBackend {
    state: Arc<ResponsesState>,
    selection: crate::routing::Selection,
}
async fn handle(
    State(state): State<Arc<ResponsesState>>,
    axum::Extension(selection): axum::Extension<crate::routing::Selection>,
    body: Bytes,
) -> Response {
    super::dispatch::serve(
        OpenAiResponsesAdaptor,
        "OpenAI Responses",
        super::dispatch::render_context("resp"),
        FetchBackend { state, selection },
        &body,
    )
    .await
}

impl ExecutionBackend for FetchBackend {
    fn stream<'a>(&'a self, request: BackendRequest) -> BackendFuture<'a, BackendStream> {
        Box::pin(async move {
            let mut body = request
                .raw
                .value()
                .as_object()
                .cloned()
                .ok_or_else(|| BackendError::rejected("Responses body must be an object"))?;
            if body.get("store").is_some_and(|v| v != &Value::Bool(false))
                || self
                    .state
                    .overrides
                    .get("store")
                    .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err(BackendError::rejected(
                    "Work Fetch supports store:false only",
                ));
            }
            body.extend(self.state.overrides.clone());
            body.insert("stream".into(), Value::Bool(true));
            body.insert("store".into(), Value::Bool(false));
            let mut events = self
                .state
                .work
                .fetch(&mut self.selection.clone(), |_| {
                    Ok(WorkFetchRequest {
                        service: self.state.service.clone(),
                        method: self.state.method.clone(),
                        body: serde_json::to_vec(&body)
                            .map_err(|e| crate::WorkGatewayError::Rejected(e.into()))?,
                    })
                })
                .await
                .map_err(BackendError::from)?;
            let accepted = crate::accepted(&mut events).await;
            let initial = accepted.as_ref().map(provenance_from_execution);
            Ok(BackendStream::new(
                events.filter_map(move |event| {
                    std::future::ready(match event {
                        Ok(WorkEvent::Output(event)) => Some(Ok(event.into())),
                        Ok(WorkEvent::Transcript(transcript)) => {
                            Some(Ok(BackendEvent::Provenance(completed_provenance(
                                accepted.as_ref(),
                                &transcript,
                            ))))
                        }
                        Ok(WorkEvent::Accepted(_)) => None,
                        Err(error) => Some(Err(BackendError::from(error))),
                    })
                }),
                initial,
            ))
        })
    }
}

#[cfg(test)]
mod tests;
