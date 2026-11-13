//! One exact route table for all HTTP presentations.
use crate::{
    GatewayResult, Presentation, Route, WorkExecutionBackend, affinity::Hints, path_error,
    route::RouteExecution, routing::Routing,
};
use axum::{Router, body::Body, extract::Request, http::StatusCode, response::Response};
use std::sync::Arc;
use tower::ServiceExt;

pub async fn router(
    routes: Vec<Route>,
    work: Arc<dyn WorkExecutionBackend>,
    jobs: Arc<crate::jobs::Jobs>,
) -> GatewayResult<Router> {
    let routing = Routing::new(routes, work.clone())?;
    let mut presentations = Vec::new();
    for route in &routing.routes {
        let execution = RouteExecution::open(route, work.clone()).await?;
        let router = match &route.presentation {
            Presentation::Model {
                model,
                package,
                max_tokens,
            } => match hellas_client::model::ModelKind::of(package) {
                hellas_client::model::ModelKind::Text => crate::state::router(Arc::new(
                    crate::state::TextState::open(
                        &crate::TextOptions {
                            model: package.clone(),
                            model_name: model.clone(),
                            default_max_tokens: *max_tokens,
                        },
                        execution,
                    )
                    .await?,
                )),
                hellas_client::model::ModelKind::Transcription => {
                    crate::audio::router(
                        &crate::AudioOptions {
                            model_name: model.clone(),
                            default_max_tokens: *max_tokens as usize,
                        },
                        execution,
                    )
                    .await?
                }
                hellas_client::model::ModelKind::Image => {
                    crate::image::router(
                        &crate::ImageOptions {
                            model_name: model.clone(),
                        },
                        execution,
                    )
                    .await?
                }
            },
            Presentation::Responses {
                service,
                method,
                overrides,
                ..
            } => crate::responses_fetch::router(
                crate::ResponsesFetch {
                    service: service.clone(),
                    method: method.clone(),
                    overrides: overrides.clone(),
                },
                execution,
            ),
            Presentation::Http { targets } => {
                crate::http_fetch::router(targets.clone(), execution)?
            }
        };
        presentations.push(router);
    }
    Ok(Router::new()
        .fallback(move |request| {
            dispatch(
                routing.clone(),
                presentations.clone(),
                jobs.clone(),
                request,
            )
        })
        .layer(axum::extract::DefaultBodyLimit::disable()))
}

async fn dispatch(
    routing: Arc<Routing>,
    presentations: Vec<Router>,
    jobs: Arc<crate::jobs::Jobs>,
    request: Request,
) -> Response {
    let job = match jobs.admit(&crate::jobs::Request {
        origin: request
            .extensions()
            .get::<crate::jobs::Origin>()
            .cloned()
            .unwrap_or(crate::jobs::Origin::Local),
        method: request.method().to_string(),
        path: request.uri().path().into(),
    }) {
        Ok(job) => job,
        Err(error) => return path_error(request.uri().path(), error.status, error.message),
    };
    let limit = request_limit(request.uri().path());
    let (mut parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let body = match axum::body::to_bytes(body, limit).await {
        Ok(body) => body,
        Err(_) => {
            return path_error(
                &path,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds route limit",
            );
        }
    };
    let hints = if path == crate::audio::PATH && routing.routes.iter().any(|route| matches!(&route.presentation, Presentation::Model { package, .. } if matches!(hellas_client::model::ModelKind::of(package), hellas_client::model::ModelKind::Transcription))) {
        match crate::audio::multipart_model(Request::from_parts(
            parts.clone(),
            Body::from(body.clone()),
        ))
        .await
        {
            Ok(model) => Hints {
                model: Some(model),
                ..Default::default()
            },
            Err(response) => return *response,
        }
    } else {
        match Hints::read_optional(&parts.headers, &body) {
            Ok(hints) => hints,
            Err(message) => return path_error(&path, StatusCode::BAD_REQUEST, message),
        }
    };
    let connection = parts
        .extensions
        .get::<axum::extract::ConnectInfo<crate::ConnectionId>>()
        .map(|c| &c.0);
    let (row, selection) =
        match routing.select(&path, parts.method.as_str(), hints, connection, job) {
            Ok(selected) => selected,
            Err(failure) => {
                let mut response = path_error(&path, failure.status, failure.message);
                if let Some(retry) = failure.retry {
                    response
                        .headers_mut()
                        .insert("retry-after", retry.to_string().parse().unwrap());
                }
                return response;
            }
        };
    parts.extensions.insert(selection);
    match presentations[row]
        .clone()
        .oneshot(Request::from_parts(parts, Body::from(body)))
        .await
    {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// The route budget applies before archival and extraction.
pub(crate) fn request_limit(path: &str) -> usize {
    if path == crate::audio::PATH {
        crate::audio::MAX_REQUEST_BYTES
    } else if path == crate::image::PATH {
        crate::image::MAX_REQUEST_BYTES
    } else {
        hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES
    }
}
