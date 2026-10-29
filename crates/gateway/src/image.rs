//! Image preparation and PNG encoding stay on the caller's side of Compute.
use super::{
    ComputeEvent, GatewayError, GatewayResult, ImageOptions, WorkEvent, WorkExecutionBackend,
    json_error,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::StatusCode,
    response::Response,
    routing::post,
};
use base64::Engine as _;
use futures::StreamExt;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, flux::ImageRequest};
use std::sync::Arc;

pub(super) const PATH: &str = "/v1/images/generations";
pub(super) const MAX_REQUEST_BYTES: usize = 64 << 10;
struct ImageState {
    package: Arc<ModelPackage>,
    name: String,
    work: Arc<dyn WorkExecutionBackend>,
}
pub(super) async fn router(
    options: &ImageOptions,
    work: Arc<dyn WorkExecutionBackend>,
) -> GatewayResult<Router> {
    let path = options.model.clone();
    let package = tokio::task::spawn_blocking(move || ModelPackage::open(&path))
        .await?
        .map_err(|error| GatewayError::Presentation(error.into()))?;
    if !package.is_image() {
        return Err(GatewayError::Presentation(
            "image route requires a Flux model".into(),
        ));
    }
    Ok(Router::new()
        .route(PATH, post(handle))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(ImageState {
            package: Arc::new(package),
            name: options.model_name.clone(),
            work,
        })))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    model: String,
    prompt: String,
    #[serde(default)]
    seed: u64,
    #[serde(default = "steps")]
    steps: usize,
    #[serde(default = "size")]
    size: String,
    #[serde(default = "one")]
    n: usize,
    #[serde(default = "format")]
    response_format: String,
}
fn steps() -> usize {
    4
}
fn size() -> String {
    "512x512".into()
}
fn one() -> usize {
    1
}
fn format() -> String {
    "b64_json".into()
}

async fn handle(
    State(state): State<Arc<ImageState>>,
    request: Result<Json<Request>, JsonRejection>,
) -> Response {
    let request = match request {
        Ok(Json(request)) => request,
        Err(error) => {
            return json_error(
                if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    error.status()
                } else {
                    StatusCode::BAD_REQUEST
                },
                error.body_text(),
            );
        }
    };
    if request.model != state.name {
        return json_error(StatusCode::NOT_FOUND, "unknown model");
    }
    if request.n != 1 || request.response_format != "b64_json" {
        return json_error(
            StatusCode::BAD_REQUEST,
            "n must be 1 and response_format must be b64_json",
        );
    }
    let size = request
        .size
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<usize>().ok()?, h.parse::<usize>().ok()?)));
    let Some((width, height)) = size else {
        return json_error(StatusCode::BAD_REQUEST, "size must be WIDTHxHEIGHT");
    };
    if let Err(error) = (ImageRequest {
        prompt: &request.prompt,
        seed: request.seed,
        width,
        height,
        steps: request.steps,
    })
    .validate()
    {
        return json_error(StatusCode::BAD_REQUEST, error.to_string());
    }
    let deadline = state
        .work
        .timeout()
        .map(|timeout| tokio::time::Instant::now() + timeout);
    let package = state.package.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        package.render_job(&ModelRequest::Image(ImageRequest {
            prompt: &request.prompt,
            seed: request.seed,
            width,
            height,
            steps: request.steps,
        }))
    });
    let job = match crate::before_deadline(deadline, prepared).await {
        Ok(Ok(Ok(job))) => job,
        Ok(Ok(Err(error))) => return json_error(StatusCode::BAD_REQUEST, error.to_string()),
        Ok(Err(error)) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        Err(_) => return json_error(StatusCode::GATEWAY_TIMEOUT, "image preparation timed out"),
    };
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return json_error(StatusCode::GATEWAY_TIMEOUT, "image preparation timed out");
    }
    let mut stream = match state.work.run(job) {
        Ok(stream) => stream,
        Err(error) => {
            let error: hellas_adaptors::BackendError = error.into();
            return json_error(super::backend_status(&error), error.to_string());
        }
    };
    let mut accepted = None;
    let mut transcript = None;
    let (status, mut body) = loop {
        match crate::before_deadline(deadline, stream.next()).await {
            Ok(Some(Ok(WorkEvent::Accepted(value)))) => accepted = Some(value),
            Ok(Some(Ok(WorkEvent::Transcript(value)))) => transcript = Some(value),
            Ok(Some(Ok(WorkEvent::Output(ComputeEvent::Output(_))))) => {}
            Ok(Some(Ok(WorkEvent::Output(ComputeEvent::Done { output, .. })))) => {
                let package = state.package.clone();
                let png = tokio::task::spawn_blocking(
                    move || -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
                        let ModelResponse::Image(image) = package.decode(&output)? else {
                            return Err("unexpected model response".into());
                        };
                        image.png(width, height).map_err(Into::into)
                    },
                );
                break match crate::before_deadline(deadline, png).await {
                    Ok(Ok(Ok(png))) => (
                        StatusCode::OK,
                        serde_json::json!({
                            "created":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                            "data":[{"b64_json":base64::engine::general_purpose::STANDARD.encode(png)}],
                        }),
                    ),
                    Ok(Ok(Err(error))) => error_body(StatusCode::BAD_GATEWAY, error.to_string()),
                    Ok(Err(error)) => {
                        error_body(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
                    }
                    Err(_) => error_body(StatusCode::GATEWAY_TIMEOUT, "image encoding timed out"),
                };
            }
            Ok(Some(Err(error))) => {
                let error: hellas_adaptors::BackendError = error.into();
                break error_body(super::backend_status(&error), error.to_string());
            }
            Ok(None) => {
                break error_body(
                    StatusCode::BAD_GATEWAY,
                    "execution stream ended without terminal outcome",
                );
            }
            Err(_) => break error_body(StatusCode::GATEWAY_TIMEOUT, "image generation timed out"),
        }
    };
    if let Some(transcript) = transcript {
        body["hellas"] = serde_json::to_value(crate::backend::provenance::completed_provenance(
            accepted.as_ref(),
            &transcript,
        ))
        .expect("provenance serializes");
    }
    use axum::response::IntoResponse;
    let mut response = (status, Json(body)).into_response();
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}
fn error_body(status: StatusCode, message: impl Into<String>) -> (StatusCode, serde_json::Value) {
    (
        status,
        serde_json::json!({"error":{"message":message.into()}}),
    )
}

#[cfg(test)]
mod tests;
