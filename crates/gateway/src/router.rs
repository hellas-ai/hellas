//! One exact route table for all HTTP presentations.
use crate::{
    GatewayResult, Presentation, Route, WorkExecutionBackend, affinity::Hints, path_error,
    route::RouteExecution, routing::Routing,
};
use axum::{Router, body::Body, extract::Request, http::StatusCode, response::Response};
use hellas_client::model::ModelPackage;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

pub type Models = BTreeMap<PathBuf, Result<BTreeMap<String, Arc<ModelPackage>>, String>>;
use tower::ServiceExt;

pub async fn router(
    routes: Vec<Route>,
    work: Arc<dyn WorkExecutionBackend>,
    jobs: Arc<crate::jobs::Jobs>,
    memory: Arc<crate::RoutingState>,
) -> GatewayResult<Router> {
    let mut evaluators: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    let backends = work.backends();
    for route in &routes {
        if let Presentation::Model { package, .. } = &route.presentation {
            for id in &route.backends {
                let evaluator = backends
                    .iter()
                    .find(|backend| backend.id == *id)
                    .and_then(|backend| backend.evaluator.clone())
                    .ok_or_else(|| {
                        crate::GatewayError::Presentation(
                            format!("backend {id} has no Compute evaluator").into(),
                        )
                    })?;
                evaluators
                    .entry(package.clone())
                    .or_default()
                    .insert(evaluator);
            }
        }
    }
    let mut models = Models::new();
    for (path, evaluators) in evaluators {
        models.insert(
            path.clone(),
            Ok(ModelPackage::open_many(&path, evaluators)
                .await
                .map_err(|error| crate::GatewayError::Presentation(error.into()))?),
        );
    }
    let (router, errors) = with_models(routes, work, jobs, memory, &models).await?;
    if let Some(error) = errors.into_values().next() {
        return Err(crate::GatewayError::Presentation(error.into()));
    }
    Ok(router)
}

/// Assemble presentations from prepared packages. Failed packages retain their
/// route keys and answer 503 while the operator repairs the live document.
pub async fn with_models(
    routes: Vec<Route>,
    work: Arc<dyn WorkExecutionBackend>,
    jobs: Arc<crate::jobs::Jobs>,
    memory: Arc<crate::RoutingState>,
    models: &Models,
) -> GatewayResult<(Router, BTreeMap<String, String>)> {
    let routing = Routing::new(routes, work.clone(), memory)?;
    let mut presentations = Vec::new();
    let mut errors = BTreeMap::new();
    for route in &routing.routes {
        let prepared: GatewayResult<Router> = async {
            let packages = match &route.presentation {
                Presentation::Model { package, .. } => models
                    .get(package)
                    .ok_or_else(|| {
                        crate::GatewayError::Presentation("model was not prepared".into())
                    })?
                    .as_ref()
                    .map_err(|error| crate::GatewayError::Presentation(error.clone().into()))?
                    .clone(),
                _ => BTreeMap::new(),
            };
            let execution = Arc::new(RouteExecution {
                work: work.clone(),
                packages,
            });
            Ok(match &route.presentation {
                Presentation::Model {
                    model,
                    package,
                    max_tokens,
                    modality,
                } => match modality {
                    hellas_client::model::ModelKind::Text => crate::state::router(Arc::new(
                        crate::state::TextState::open(
                            package.clone(),
                            model.clone(),
                            *max_tokens,
                            execution,
                        )
                        .await?,
                    )),
                    hellas_client::model::ModelKind::Transcription => {
                        crate::audio::router(model.clone(), *max_tokens as usize, execution).await?
                    }
                    hellas_client::model::ModelKind::Image => {
                        crate::image::router(model.clone(), execution).await?
                    }
                },
                Presentation::Responses {
                    service,
                    method,
                    overrides,
                    ..
                } => crate::responses_fetch::router(
                    service.clone(),
                    method.clone(),
                    overrides.clone(),
                    execution,
                ),
                Presentation::Http { targets } => {
                    crate::http_fetch::router(targets.clone(), execution)?
                }
            })
        }
        .await;
        let router = match prepared {
            Ok(router) => router,
            Err(crate::GatewayError::Presentation(error)) => {
                let reason = error.to_string();
                for id in &route.backends {
                    errors.insert(id.clone(), reason.clone());
                }
                Router::new().fallback(move |request: Request| {
                    let reason = reason.clone();
                    async move {
                        path_error(
                            request.uri().path(),
                            StatusCode::SERVICE_UNAVAILABLE,
                            reason,
                        )
                    }
                })
            }
            Err(error) => return Err(error),
        };
        presentations.push(router);
    }
    Ok((
        Router::new()
            .fallback(move |request| {
                dispatch(
                    routing.clone(),
                    presentations.clone(),
                    jobs.clone(),
                    request,
                )
            })
            .layer(axum::extract::DefaultBodyLimit::disable()),
        errors,
    ))
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
    let hints = if path == crate::audio::PATH
        && routing.routes.iter().any(|route| {
            matches!(
                &route.presentation,
                Presentation::Model {
                    modality: hellas_client::model::ModelKind::Transcription,
                    ..
                }
            )
        }) {
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
