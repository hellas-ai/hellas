//! Image preparation and PNG encoding stay on the caller's side of Compute.
use super::{GatewayError, GatewayResult, ImageOptions, WorkExecutionBackend, json_error};
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
    let package = ModelPackage::open(
        &path,
        &work.evaluator().ok_or(crate::GatewayError::Presentation(
            "Compute models need a renderer (evaluator id)".into(),
        ))?,
    )
    .await
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
async fn handle(
    State(state): State<Arc<ImageState>>,
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
        .timeout()
        .map(|timeout| tokio::time::Instant::now() + timeout);
    let package = state.package.clone();
    let prepared = async move {
        package
            .render_job(&ModelRequest::Image(image_request(&request)))
            .await
    };
    let job = match crate::before_deadline(deadline, prepared).await {
        Ok(Ok(job)) => job,
        Ok(Err(error)) => return json_error(StatusCode::BAD_REQUEST, error.to_string()),
        Err(_) => return json_error(StatusCode::GATEWAY_TIMEOUT, "image preparation timed out"),
    };
    if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
        return json_error(StatusCode::GATEWAY_TIMEOUT, "image preparation timed out");
    }
    let crate::compute::Completion {
        output,
        accepted,
        transcript,
    } = crate::compute::collect(
        state.work.as_ref(),
        job,
        deadline,
        "image generation timed out",
    )
    .await;
    let (status, body) = match output {
        Ok(output) => {
            let package = state.package.clone();
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
