//! Image preparation and PNG encoding stay on the caller's side of Compute.
use super::{GatewayError, GatewayResult, ImageOptions, json_error, route::RouteExecution};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::StatusCode,
    response::Response,
    routing::post,
};
use hellas_adaptors::openai::{
    error_json,
    images::{self, ImageGeneration},
};
use hellas_client::model::{ModelRequest, ModelResponse, flux::ImageRequest};
use std::sync::Arc;

pub(super) const PATH: &str = "/v1/images/generations";
pub(super) const MAX_REQUEST_BYTES: usize = 64 << 10;
struct ImageState {
    name: String,
    work: Arc<RouteExecution>,
}
pub(super) async fn router(
    options: &ImageOptions,
    work: Arc<RouteExecution>,
) -> GatewayResult<Router> {
    let package = work
        .packages
        .values()
        .next()
        .ok_or_else(|| GatewayError::Presentation("image route needs a renderer".into()))?;
    if !package.is_image() {
        return Err(GatewayError::Presentation(
            "image route requires a Flux model".into(),
        ));
    }
    Ok(Router::new()
        .route(PATH, post(handle))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(Arc::new(ImageState {
            name: options.model_name.clone(),
            work,
        })))
}
async fn handle(
    State(state): State<Arc<ImageState>>,
    axum::Extension(mut selection): axum::Extension<crate::routing::Selection>,
    request: Result<Json<serde_json::Value>, JsonRejection>,
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
    let request = match ImageGeneration::parse(request, &state.name) {
        Ok(request) => request,
        Err(error) => return crate::request_error(error),
    };
    let (width, height) = (request.width, request.height);
    if let Err(error) = image_request(&request).validate() {
        return json_error(StatusCode::BAD_REQUEST, error.to_string());
    }
    let deadline = state
        .work
        .work
        .timeout()
        .map(|timeout| tokio::time::Instant::now() + timeout);
    let (package, stream) = match state
        .work
        .compute(
            &mut selection,
            &ModelRequest::Image(image_request(&request)),
            deadline,
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
    } = crate::compute::collect(stream, deadline, "image generation timed out").await;
    let (status, body) = match output {
        Ok(output) => {
            let png = tokio::task::spawn_blocking(
                move || -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
                    let ModelResponse::Image(image) = package.decode(&output)? else {
                        return Err("unexpected model response".into());
                    };
                    image.png(width, height).map_err(Into::into)
                },
            );
            match crate::before_deadline(deadline, png).await {
                Ok(Ok(Ok(png))) => (
                    StatusCode::OK,
                    images::render(&png, crate::now_unix() as u64),
                ),
                Ok(Ok(Err(error))) => (StatusCode::BAD_GATEWAY, error_json(error.to_string())),
                Ok(Err(error)) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    error_json(error.to_string()),
                ),
                Err(_) => (
                    StatusCode::GATEWAY_TIMEOUT,
                    error_json("image encoding timed out"),
                ),
            }
        }
        Err((status, message)) => (status, error_json(message)),
    };
    let mut response = crate::backend::provenance::json_response(
        status,
        body,
        accepted.as_ref(),
        transcript.as_deref(),
    );
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}
fn image_request(request: &ImageGeneration) -> ImageRequest<'_> {
    ImageRequest {
        prompt: &request.prompt,
        seed: request.seed,
        width: request.width,
        height: request.height,
        steps: request.steps,
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
mod tests;
