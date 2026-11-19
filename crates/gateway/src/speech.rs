//! JSON speech requests rendered through the existing Compute route.
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
pub(super) use hellas_adaptors::openai::audio_speech::PATH;
use hellas_adaptors::openai::audio_speech::SpeechRequest;
use hellas_client::model::{ModelRequest, ModelResponse};
use std::sync::Arc;
struct StateData {
    model: String,
    work: Arc<crate::route::RouteExecution>,
}
pub(super) fn router(model: String, work: Arc<crate::route::RouteExecution>) -> Router {
    Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(StateData { model, work }))
}
async fn handle(
    State(state): State<Arc<StateData>>,
    axum::Extension(mut selection): axum::Extension<crate::routing::Selection>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let parse = || {
        if uri.query().is_some() {
            return Err("speech does not accept query settings".to_owned());
        }
        let encoding = headers
            .get("content-encoding")
            .map(|v| v.to_str())
            .transpose()
            .map_err(|e| e.to_string())?;
        let body = hellas_authority::model::http_usage::decode_request_body(encoding, &body)
            .map_err(str::to_owned)?;
        let request = SpeechRequest::parse(&body).map_err(|e| e.message)?;
        request.native(&state.model).map_err(|e| e.message)?;
        Ok::<_, String>(request)
    };
    let request = match parse() {
        Ok(request) => request,
        Err(error) => return crate::json_error(StatusCode::BAD_REQUEST, error),
    };
    let (package, stream) = match state
        .work
        .compute(
            &mut selection,
            &ModelRequest::Speech {
                text: &request.input,
                speed: request.speed,
            },
        )
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return crate::work_error(error),
    };
    let crate::compute::Completion {
        output,
        accepted,
        transcript,
    } = crate::compute::collect(stream).await;
    let result = output.and_then(|output| match package.decode(&output) {
        Ok(ModelResponse::Speech(audio)) => audio
            .wav()
            .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string())),
        Ok(_) => Err((StatusCode::BAD_GATEWAY, "unexpected model response".into())),
        Err(error) => Err((StatusCode::BAD_GATEWAY, error.to_string())),
    });
    let mut response = match result {
        Ok(bytes) => ([(axum::http::header::CONTENT_TYPE, "audio/wav")], bytes).into_response(),
        Err((status, message)) => crate::backend::provenance::json_response(
            status,
            hellas_adaptors::openai::error_json(message),
            accepted.as_ref(),
            transcript.as_deref(),
        ),
    };
    if let Some(transcript) = &transcript {
        let (name, value) = crate::backend::provenance::transcript_header(transcript);
        response.headers_mut().insert(name, value);
    }
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}
