//! Responses presentation over an already funded, authenticated Work backend.
use super::{WorkExecutionBackend, WorkFetchRequest};
use axum::{Router, body::Bytes, extract::State, response::Response, routing::post};
use futures::StreamExt;
use hellas_adaptors::{
    BackendError, BackendFuture, BackendRequest, BackendStream, ExecutionBackend, RenderContext,
    openai::responses::OpenAiResponsesAdaptor,
};
use serde_json::Value;
use std::sync::Arc;

/// The path the Responses presentation serves.
pub(super) const PATH: &str = "/v1/responses";

pub(super) fn router(
    options: super::ResponsesFetch,
    work: Arc<dyn WorkExecutionBackend>,
) -> Router {
    Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(FetchBackend { work, options }))
}

#[derive(Clone)]
struct FetchBackend {
    work: Arc<dyn WorkExecutionBackend>,
    options: super::ResponsesFetch,
}

async fn handle(State(backend): State<Arc<FetchBackend>>, body: Bytes) -> Response {
    let adaptor = OpenAiResponsesAdaptor;
    let (parsed, request) =
        match super::dispatch::parse_backend_request(&adaptor, &body, "OpenAI Responses") {
            Ok(value) => value,
            Err(response) => return *response,
        };
    super::dispatch::backend_wire_response(
        parsed.stream.unwrap_or(false),
        adaptor,
        parsed,
        backend.as_ref().clone(),
        request,
        RenderContext::new(
            super::next_id("resp"),
            super::next_id("msg"),
            super::now_unix(),
        ),
        "OpenAI Responses",
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
                    .options
                    .overrides
                    .get("store")
                    .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err(BackendError::rejected(
                    "Work Fetch supports store:false only",
                ));
            }
            body.extend(self.options.overrides.clone());
            body.insert("stream".into(), Value::Bool(true));
            body.insert("store".into(), Value::Bool(false));
            let events = self
                .work
                .fetch(WorkFetchRequest {
                    provider: self.options.provider,
                    service: self.options.service.clone(),
                    method: self.options.method.clone(),
                    body: serde_json::to_vec(&body)
                        .map_err(|e| BackendError::rejected(e.to_string()))?,
                })
                .map_err(BackendError::from)?;
            Ok(BackendStream::new(
                events.map(|event| event.map_err(BackendError::from)),
                None,
            ))
        })
    }
}

#[cfg(test)]
mod tests;
