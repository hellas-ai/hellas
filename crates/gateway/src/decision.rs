//! Decision request shape: the model's own format in, its envelope out.
use super::{
    GatewayError, GatewayResult, json_error,
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
use hellas_client::model::{ModelKind, ModelPackage, decision::InvalidRequest};
use std::sync::Arc;

pub(super) const PATH: &str = "/v1/systemone";
pub(super) const MAX_REQUEST_BYTES: usize = 1 << 20;
struct DecisionState {
    name: String,
    /// Every renderer's package reads the same request format from the model.
    package: Arc<ModelPackage>,
    work: Arc<RouteExecution>,
}
pub(super) fn router(model_name: String, work: Arc<RouteExecution>) -> GatewayResult<Router> {
    work.require_kind(ModelKind::Decision)?;
    let package = work
        .packages
        .values()
        .next()
        .ok_or_else(|| GatewayError::Presentation("decision route needs a renderer".into()))?
        .clone();
    Ok(Router::new()
        .route(PATH, post(handle))
        .with_state(Arc::new(DecisionState {
            name: model_name,
            package,
            work,
        })))
}
async fn handle(
    State(state): State<Arc<DecisionState>>,
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
    let prepare = state.clone();
    let request = match tokio::task::spawn_blocking(move || prepare.package.decision_request(body))
        .await
    {
        Ok(Ok(request)) => Arc::new(request),
        Ok(Err(error)) if error.is::<InvalidRequest>() => {
            return json_error(StatusCode::BAD_REQUEST, error.to_string());
        }
        Ok(Err(error)) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        Err(error) => return json_error(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    let respond = (state.clone(), request.clone());
    pipeline::buffered(
        &state.work,
        selected,
        Operation::Compute(request.job()),
        move |output| {
            let (state, request) = respond;
            state
                .package
                .decision_response(&state.name, &request, output)
                .map(Reply::Json)
                .map_err(pipeline::invalid_output)
        },
    )
    .await
}

#[cfg(test)]
mod tests;
