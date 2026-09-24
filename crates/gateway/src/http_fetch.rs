//! HTTP bytes over authenticated Fetch, without translating vendor schemas.
mod affinity;
mod config;
mod observation;
mod routing;

pub use config::HttpGatewayConfig;
#[cfg(test)]
mod tests;

use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
use std::sync::Arc;
use tracing::Instrument;

use super::{GatewayHandle, GatewayOptions, PaidExecutionBackend, PaidFetchRequest, access};

#[derive(Clone)]
pub(crate) struct BackendName(pub String);

fn attributed(mut response: Response, name: &str) -> Response {
    response.extensions_mut().insert(BackendName(name.into()));
    response
}

struct HttpState {
    service: String,
    method: String,
    paid: Arc<dyn PaidExecutionBackend>,
    routing: Arc<routing::Routing>,
    metrics: observation::Metrics,
}

#[derive(Debug, thiserror::Error)]
enum HttpOpenError {
    #[error("HTTP proxy requires a paid Fetch backend")]
    MissingPaidBackend,
    #[error("missing authenticated HTTP response head")]
    MissingHead,
    #[error(transparent)]
    Paid(#[from] super::PaidGatewayError),
    #[error(transparent)]
    Headers(#[from] hellas_rpc::http_fetch::HttpRequestError),
}

pub(super) async fn start(options: GatewayOptions) -> anyhow::Result<GatewayHandle> {
    let config = options
        .http_fetch
        .as_ref()
        .context("missing HTTP configuration")?
        .clone();
    config.validate()?;
    let paid = options
        .paid_work
        .clone()
        .ok_or(HttpOpenError::MissingPaidBackend)?;
    ensure!(
        options.output_cache.policy == hellas_rpc::cache::CachePolicy::Off,
        "HTTP routes archive exchanges; inference replay must be off"
    );
    let archive_policy = super::archive::Policy::new(options.archive.clone(), false);
    archive_policy.prepare();
    let routing = Arc::new(routing::Routing::new(&config, &paid.fetch_providers())?);
    let state = Arc::new(HttpState {
        service: config.service,
        method: config.method,
        paid: paid.clone(),
        routing,
        metrics: observation::Metrics::new(),
    });
    let bearer = Arc::new(match &options.bearer_token_file {
        Some(path) => access::Bearer::load_or_create(path)?,
        None => access::Bearer::generate(),
    });
    let mut app = Router::new();
    let paths: std::collections::BTreeSet<_> = state
        .routing
        .backends
        .iter()
        .flat_map(|backend| backend.routes.iter().map(|route| route.path.as_str()))
        .collect();
    for path in paths {
        app = app.route(path, axum::routing::any(handle));
    }
    let app = app
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            archive_policy,
            super::archive::record,
        ));
    #[cfg(feature = "otel")]
    let app = app.layer(axum::middleware::from_fn(
        hellas_rpc::telemetry::http::trace_request,
    ));
    let app = app.layer(access::BearerLayer::new(bearer.clone()));
    let listener = super::bind_gateway(
        &options.host,
        options.port,
        options.allow_remote && options.bearer_token_file.is_some(),
    )
    .await?;
    super::launch_gateway(
        app,
        listener,
        bearer,
        options.wrap.as_deref(),
        &options.wrap_args,
        Some(paid),
    )
    .await
}

fn error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({"error": {"message": message}})),
    )
        .into_response()
}

async fn handle(State(state): State<Arc<HttpState>>, request: Request) -> Response {
    let mut observed = observation::Observation::new(&state.metrics, request.uri().path());
    let (parts, body) = request.into_parts();
    // Reserve space for URL, headers and JSON around the base64 body.
    let body_limit = (hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES - 64 * 1024) / 4 * 3;
    let body = match axum::body::to_bytes(body, body_limit).await {
        Ok(body) => body,
        Err(_) => {
            observed.status(413);
            observed.complete();
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "HTTP request exceeds Fetch limit",
            );
        }
    };
    let connection = parts
        .extensions
        .get::<axum::extract::ConnectInfo<super::ConnectionId>>()
        .map(|c| &c.0);
    let selected = match state.routing.select(
        parts.uri.path(),
        parts.method.as_str(),
        &parts.headers,
        &body,
        connection,
    ) {
        Ok(selected) => selected,
        Err(failure) => {
            observed.status(failure.status.as_u16());
            observed.complete();
            let mut response = error(failure.status, failure.message);
            if let Some(seconds) = failure.retry {
                response
                    .headers_mut()
                    .insert("retry-after", seconds.to_string().parse().unwrap());
            }
            if let Some(backend) = failure.backend {
                let name = &state.routing.backends[backend].name;
                observed.backend(name, "session");
                return attributed(response, name);
            }
            return response;
        }
    };
    let backend = &state.routing.backends[selected.backend];
    let route = &backend.routes[selected.endpoint];
    let permit = selected.permit;
    observed.backend(&backend.name, selected.affinity);
    observed.model(selected.model.as_deref());
    observed.bind_response(
        state
            .routing
            .response_binding(selected.backend, &route.path),
    );
    let mut upstream = match route.request(body, &parts.headers) {
        Ok(upstream) => upstream,
        Err(_) => {
            observed.status(400);
            observed.complete();
            return error(StatusCode::BAD_REQUEST, "unsupported HTTP header encoding");
        }
    };
    if let Some(query) = parts.uri.query() {
        upstream
            .url
            .push(if upstream.url.contains('?') { '&' } else { '?' });
        upstream.url.push_str(query);
    }
    let payload = match serde_json::to_vec(&upstream) {
        Ok(payload) if upstream.validate().is_ok() => payload,
        _ => {
            observed.status(400);
            observed.complete();
            return error(StatusCode::BAD_REQUEST, "invalid HTTP request");
        }
    };
    let result = open(&state, backend.provider, payload)
        .instrument(observed.span.clone())
        .await;
    let (status, headers, mut events) = match result {
        Ok(value) => value,
        Err(HttpOpenError::Paid(super::PaidGatewayError::Busy(_))) => {
            observed.status(503);
            return attributed(
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "paid Fetch is busy; retry later",
                ),
                &backend.name,
            );
        }
        Err(_) => {
            observed.status(502);
            state.routing.transport_failed(selected.backend);
            return attributed(
                error(StatusCode::BAD_GATEWAY, "authenticated Fetch failed"),
                &backend.name,
            );
        }
    };
    observed.status(status);
    let representation_length = if parts.method == axum::http::Method::HEAD || status == 304 {
        headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| HeaderValue::from_str(value).ok())
    } else {
        None
    };
    let mut headers = response_headers(headers);
    if let Some(length) = representation_length {
        headers.insert("content-length", length);
    }
    observed.content(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        headers
            .get("content-encoding")
            .and_then(|value| value.to_str().ok()),
    );
    state.routing.observe(selected.backend, status, &headers);
    if parts.method == axum::http::Method::HEAD || status == 204 || status == 304 {
        let end = events.next().instrument(observed.span.clone()).await;
        if !matches!(
            end,
            Some(Ok(OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None
            }))
        ) {
            observed.status(502);
            return error(StatusCode::BAD_GATEWAY, "invalid bodyless HTTP completion");
        }
        observed.complete();
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::from_u16(status).unwrap();
        *response.headers_mut() = std::mem::take(&mut headers);
        return attributed(response, &backend.name);
    }
    let stream = async_stream::try_stream! {
        let _permit = permit;
        let mut size = 0usize;
        while let Some(event) = events.next().instrument(observed.span.clone()).await {
            let event = event.map_err(|_| std::io::Error::other("Fetch stream verification failed"))?;
            match event {
                OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 })) => {
                    let bytes = hellas_rpc::http_fetch::decode_base64(&base64)
                        .map_err(|_| std::io::Error::other("invalid HTTP response encoding"))?;
                    size = size.saturating_add(bytes.len());
                    if bytes.is_empty() || size > upstream.max_response_bytes as usize {
                        Err(std::io::Error::other("HTTP response exceeds Fetch limit"))?;
                    }
                    observed.chunk(&bytes);
                    yield Bytes::from(bytes);
                }
                OutputEvent::Finished { stop_reason: StopReason::EndOfText, usage: None } => {
                    observed.complete();
                    return;
                }
                _ => Err(std::io::Error::other("unexpected HTTP Fetch event"))?,
            }
        }
        Err(std::io::Error::other("HTTP Fetch ended without verified completion"))?;
    };
    let stream: futures::stream::BoxStream<'static, Result<Bytes, std::io::Error>> =
        Box::pin(stream);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    *response.headers_mut() = headers;
    attributed(response, &backend.name)
}

async fn open(
    state: &HttpState,
    provider: iroh::EndpointId,
    payload: Vec<u8>,
) -> Result<(u16, Vec<(String, String)>, super::PaidFetchStream), HttpOpenError> {
    let mut stream = state.paid.fetch(PaidFetchRequest {
        provider,
        service: state.service.clone(),
        method: state.method.clone(),
        body: payload,
    })?;
    match stream.next().await.transpose()? {
        Some(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
            status,
            headers,
        }))) if (200..=599).contains(&status) => {
            hellas_rpc::http_fetch::check_headers(&headers, false)?;
            Ok((status, headers, stream))
        }
        _ => Err(HttpOpenError::MissingHead),
    }
}

fn response_headers(headers: Vec<(String, String)>) -> HeaderMap {
    let mut result = HeaderMap::new();
    let connection = connection_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    for (name, value) in headers {
        if !hop_header(&name)
            && !connection.contains(&name)
            && !matches!(name.as_str(), "content-length" | "set-cookie")
            && !name.starts_with("x-hellas-")
            && let (Ok(name), Ok(value)) = (
                name.parse::<axum::http::HeaderName>(),
                value.parse::<HeaderValue>(),
            )
        {
            result.append(name, value);
        }
    }
    result
}

fn hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn connection_headers<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<String> {
    headers
        .filter(|(name, _)| *name == "connection")
        .flat_map(|(_, value)| value.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect()
}
