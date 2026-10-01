use super::backend::GatewayBackend;
use super::dispatch::{backend_wire_response, parse_backend_request};
use super::state::GatewayState;
use super::{next_id, now_unix};
use axum::body::Bytes;
use axum::extract::State;
use axum::response::Response;
use hellas_adaptors::openai::responses::OpenAiResponsesAdaptor;
use hellas_adaptors::openai::responses::ParsedResponseRequest;
use hellas_adaptors::{BackendRequest, RenderContext};
use std::sync::Arc;

pub(super) async fn handle(State(state): State<Arc<GatewayState>>, body: Bytes) -> Response {
    let adaptor = OpenAiResponsesAdaptor;
    let (mut parsed, mut request) = match parse_backend_request(&adaptor, &body, "OpenAI Responses")
    {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let stream = parsed.stream.unwrap_or(false);
    if let Some(proxy) = state.responses_proxy.as_ref() {
        return backend_wire_response(
            stream,
            adaptor,
            parsed,
            state.cached(proxy.as_ref().clone()),
            request,
            render_context(),
            "OpenAI Responses",
        )
        .await;
    }

    apply_model_override(&mut parsed, &mut request, &state.model_name);

    let backend = GatewayBackend::new(state);
    backend_wire_response(
        stream,
        adaptor,
        parsed,
        backend,
        request,
        render_context(),
        "OpenAI Responses",
    )
    .await
}

fn apply_model_override(
    parsed: &mut ParsedResponseRequest,
    request: &mut BackendRequest,
    model: &str,
) {
    parsed.model = model.to_string();
    request.execution.canonical.model.name = model.to_string();
}

fn render_context() -> RenderContext {
    RenderContext::new(next_id("resp"), next_id("msg"), now_unix())
}
