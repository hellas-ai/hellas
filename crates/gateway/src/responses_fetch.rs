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

pub(super) fn router(options: super::ResponsesFetch, work: Arc<RouteExecution>) -> Router {
    Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new((work, options)))
}

#[derive(Clone)]
struct FetchBackend {
    work: Arc<RouteExecution>,
    options: super::ResponsesFetch,
    selection: crate::routing::Selection,
}

async fn handle(
    State(state): State<Arc<(Arc<RouteExecution>, super::ResponsesFetch)>>,
    axum::Extension(selection): axum::Extension<crate::routing::Selection>,
    body: Bytes,
) -> Response {
    let context = super::dispatch::render_context("resp");
    let backend = FetchBackend {
        work: state.0.clone(),
        options: state.1.clone(),
        selection,
    };
    super::dispatch::serve(
        OpenAiResponsesAdaptor,
        "OpenAI Responses",
        context,
        backend,
        None,
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
                .fetch(
                    &mut self.selection.clone(),
                    WorkFetchRequest {
                        service: self.options.service.clone(),
                        method: self.options.method.clone(),
                        body: serde_json::to_vec(&body)
                            .map_err(|e| BackendError::rejected(e.to_string()))?,
                    },
                )
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
