//! Image request shape and PNG encoding.
use super::{
    GatewayResult, json_error,
    pipeline::{self, Operation, Reply},
    route::RouteExecution,
};
use axum::{
    Extension, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::post,
};
use hellas_adaptors::openai::images::{self, ImageGeneration};
use hellas_client::model::{ModelKind, ModelRequest, ModelResponse, flux::ImageRequest};
use std::sync::Arc;

pub(super) const PATH: &str = "/v1/images/generations";
pub(super) const MAX_REQUEST_BYTES: usize = 64 << 10;
struct ImageState {
    name: String,
    work: Arc<RouteExecution>,
}
pub(super) fn router(model_name: String, work: Arc<RouteExecution>) -> GatewayResult<Router> {
    work.require_kind(ModelKind::Image)?;
    Ok(Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(ImageState {
            name: model_name,
            work,
        })))
}
async fn handle(
    State(state): State<Arc<ImageState>>,
    Extension(selected): Extension<crate::routing::Selection>,
    Extension(body): Extension<serde_json::Value>,
    headers: HeaderMap,
) -> Response {
    if !crate::affinity::json_content_type(&headers) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Expected request with `Content-Type: application/json`",
        );
    }
    let request = match ImageGeneration::parse(body, &state.name) {
        Ok(request) => request,
        Err(error) => return crate::request_error(error),
    };
    let request = image_request(&request);
    let (width, height) = (request.width, request.height);
    pipeline::buffered(
        &state.work,
        selected,
        Operation::Compute(ModelRequest::Image(request)),
        move |output| {
            let ModelResponse::Image(image) = output else {
                return Err(pipeline::invalid_output("unexpected model response"));
            };
            let png = image.png(width, height).map_err(pipeline::invalid_output)?;
            Ok(Reply::Json(images::render(&png, crate::now_unix() as u64)))
        },
    )
    .await
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
