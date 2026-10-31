//! Responses presentation over an already funded, authenticated Work backend.
use super::backend::provenance::{completed_provenance, provenance_from_execution};
use super::{WorkEvent, WorkExecutionBackend, WorkFetchRequest};
use axum::{Router, body::Bytes, extract::State, response::Response, routing::post};
use futures::StreamExt;
use hellas_adaptors::{
    BackendError, BackendEvent, BackendFuture, BackendRequest, BackendStream, ExecutionBackend,
    RenderContext, openai::responses::OpenAiResponsesAdaptor,
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
            let mut events = self
                .work
                .fetch(WorkFetchRequest {
                    resource: None,
                    channel: None,
                    provider: self.options.provider,
                    service: self.options.service.clone(),
                    method: self.options.method.clone(),
                    body: serde_json::to_vec(&body)
                        .map_err(|e| BackendError::rejected(e.to_string()))?,
                })
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
