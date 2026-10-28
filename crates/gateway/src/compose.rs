//! One router over every presentation. A path served by several of them is
//! split by the request's model.
use super::{
    GatewayConfigError, GatewayResult, Presentations, WorkExecutionBackend, http_fetch, json_error,
    responses_fetch, state,
};
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

/// A presentation's claim on one path: the models it answers to there, or
/// any model when the list is empty.
struct Claim {
    path: String,
    models: Vec<String>,
    router: Router,
}

pub(crate) async fn router(
    presentations: &Presentations,
    work: &Arc<dyn WorkExecutionBackend>,
) -> GatewayResult<Router> {
    let mut claims = Vec::new();
    if let Some(text) = &presentations.text {
        let state = Arc::new(state::TextState::open(text, work.clone()).await?);
        let router = state::router(state);
        for path in state::PATHS {
            claims.push(Claim {
                path: path.into(),
                models: vec![text.model_name.clone()],
                router: router.clone(),
            });
        }
    }
    if let Some(responses) = &presentations.responses {
        claims.push(Claim {
            path: responses_fetch::PATH.into(),
            models: responses.models.clone(),
            router: responses_fetch::router(responses.clone(), work.clone()),
        });
    }
    if let Some(http) = &presentations.http {
        let (router, paths) = http_fetch::router(http.clone(), work.clone())?;
        for (path, models) in paths {
            claims.push(Claim {
                path,
                models,
                router: router.clone(),
            });
        }
    }
    if claims.is_empty() {
        return Err(GatewayConfigError::NoPresentation.into());
    }
    let mut paths = BTreeMap::<String, Vec<Claim>>::new();
    for claim in claims {
        paths.entry(claim.path.clone()).or_default().push(claim);
    }
    let mut app = Router::new();
    for (path, mut claims) in paths {
        if claims.len() == 1 {
            let router = claims.remove(0).router;
            app = app.route(
                &path,
                axum::routing::any(move |request| serve(router.clone(), request)),
            );
            continue;
        }
        let mut by_model = BTreeMap::new();
        for claim in claims {
            if claim.models.is_empty() {
                return Err(GatewayConfigError::RouteConflict(path).into());
            }
            for model in claim.models {
                if by_model.insert(model, claim.router.clone()).is_some() {
                    return Err(GatewayConfigError::RouteConflict(path).into());
                }
            }
        }
        let by_model = Arc::new(by_model);
        app = app.route(
            &path,
            axum::routing::any(move |request: Request| split(by_model.clone(), request)),
        );
    }
    Ok(app)
}

/// Requests on a shared path go to the presentation serving their model.
async fn split(models: Arc<BTreeMap<String, Router>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) =
        axum::body::to_bytes(body, hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES).await
    else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let model = http_fetch::affinity::decoded_body(&parts.headers, &body)
        .ok()
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .and_then(|value| value.get("model")?.as_str().map(str::to_owned));
    let Some(router) = model.and_then(|model| models.get(&model).cloned()) else {
        return json_error(
            StatusCode::NOT_FOUND,
            "no presentation on this path serves the requested model",
        );
    };
    serve(router, Request::from_parts(parts, Body::from(body))).await
}

async fn serve(router: Router, request: Request) -> Response {
    match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

#[cfg(test)]
mod tests;
