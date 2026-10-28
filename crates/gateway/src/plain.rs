use super::backend::GatewayBackend;
use super::dispatch::{backend_wire_response, parse_backend_request};
use super::state::TextState;
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_adaptors::RenderContext;
use hellas_adaptors::openai::completions::OpenAiCompletionsAdaptor;
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<TextState>>, body: Bytes) -> Response {
    let adaptor = OpenAiCompletionsAdaptor;
    let (mut parsed, mut request) =
        match parse_backend_request(&adaptor, &body, "OpenAI Completions") {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let stream = parsed.stream == Some(true);
    parsed.model = state.model_name.clone();
    request.execution.canonical.model.name = state.model_name.clone();
    let backend = GatewayBackend::new(state);
    backend_wire_response(
        stream,
        adaptor,
        parsed,
        backend,
        request,
        render_context(),
        "OpenAI Completions",
    )
    .await
}

fn render_context() -> RenderContext {
    let id = next_id("cmpl");
    RenderContext::new(id.clone(), id, now_unix())
}
