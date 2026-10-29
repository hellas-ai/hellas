//! HTTP bytes over authenticated Fetch, without translating vendor schemas.
//!
//! The provider's acceptance heads the response as `x-hellas-commitment-bin`
//! and `x-hellas-provider`; the base64 signed transcript trails the body as
//! `x-hellas-transcript` (a header on a bodyless response).
pub(crate) mod affinity;
mod config;
mod observation;
mod routing;
pub use routing::RoutingError;

pub use config::{HttpGatewayConfig, HttpRoute};
#[cfg(test)]
mod tests;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
use hellas_rpc::provenance::{ExecutionProvenance, TRANSCRIPT_KEY};
use http_body::Frame;
use std::sync::Arc;
use tracing::Instrument;

use super::{WorkEvent, WorkExecutionBackend, WorkFetchRequest};
use hellas_adaptors::BackendError;

#[derive(Clone)]
pub(crate) struct BackendName(pub String);

fn attributed(mut response: Response, name: &str) -> Response {
    response.extensions_mut().insert(BackendName(name.into()));
    response
}

struct HttpState {
    /// The Fetch route of each backend, by backend index.
    fetch_routes: Vec<(String, String)>,
    paid: Arc<dyn WorkExecutionBackend>,
    routing: Arc<routing::Routing>,
    metrics: observation::Metrics,
}

#[derive(Debug, thiserror::Error)]
enum HttpOpenError {
    #[error("missing authenticated HTTP response head")]
    MissingHead,
    #[error(transparent)]
    Paid(#[from] super::WorkGatewayError),
    #[error(transparent)]
    Headers(#[from] hellas_rpc::http_fetch::HttpRequestError),
}

/// A path and the models it answers to; empty means any model.
pub(super) type ServedPath = (String, Vec<String>);

/// The HTTPS presentation over `paid`, and the paths it serves.
pub(super) fn router(
    config: HttpGatewayConfig,
    paid: Arc<dyn WorkExecutionBackend>,
) -> crate::GatewayResult<(Router, Vec<ServedPath>)> {
    config.validate()?;
    let routes: Vec<_> = paid
        .fetch_routes()
        .into_iter()
        .filter(|route| route.schema == hellas_rpc::FetchSchema::HttpV1)
        .collect();
    let mut providers = Vec::new();
    for route in &routes {
        if !providers.contains(&route.provider) {
            providers.push(route.provider);
        }
    }
    let routing = Arc::new(routing::Routing::new(&config, &providers)?);
    let named = config.service.clone().zip(config.method.clone());
    let fetch_routes = routing
        .backends
        .iter()
        .map(|backend| fetch_route(&routes, backend, named.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut paths = std::collections::BTreeMap::<String, Option<Vec<String>>>::new();
    for backend in &routing.backends {
        for route in &backend.routes {
            let models = paths.entry(route.path.clone()).or_insert(Some(Vec::new()));
            match (models.as_mut(), backend.models.is_empty()) {
                (Some(models), false) => models.extend(backend.models.iter().cloned()),
                _ => *models = None,
            }
        }
    }
    let state = Arc::new(HttpState {
        fetch_routes,
        paid,
        routing,
        metrics: observation::Metrics::new(),
    });
    let mut app = Router::new();
    for path in paths.keys() {
        app = app.route(path, axum::routing::any(handle));
    }
    let paths = paths
        .into_iter()
        .map(|(path, models)| (path, models.unwrap_or_default()))
        .collect();
    Ok((app.with_state(state), paths))
}

/// The one Fetch route a backend uses on its provider. A provider may seal
/// several HTTPS routes; the configuration then names one of them.
fn fetch_route(
    routes: &[crate::FetchRoute],
    backend: &routing::Backend,
    named: Option<&(String, String)>,
) -> Result<(String, String), crate::GatewayConfigError> {
    if backend.resource.is_some() != backend.channel.is_some()
        || (backend.resource.is_some() && named.is_some())
    {
        return Err(crate::GatewayConfigError::FetchRouteMismatch(
            backend.name.clone(),
        ));
    }
    let mut sealed = Vec::new();
    let mut open = false;
    for route in routes.iter().filter(|route| {
        route.provider == backend.provider
            && backend
                .resource
                .is_none_or(|resource| route.resource == Some(resource))
            && backend
                .channel
                .is_none_or(|channel| route.channel == Some(channel))
    }) {
        match &route.sealed {
            Some(route) => sealed.push(route),
            None => open = true,
        }
    }
    let name = || backend.name.clone();
    match (named, sealed.as_slice()) {
        (Some(named), sealed) if sealed.contains(&named) || (open && sealed.is_empty()) => {
            Ok(named.clone())
        }
        (Some(_), _) if !open => Err(crate::GatewayConfigError::FetchRouteMismatch(name())),
        (Some(named), _) => Ok(named.clone()),
        (None, [one]) => Ok((*one).clone()),
        (None, []) => Err(crate::GatewayConfigError::MissingFetchRoute(name())),
        (None, _) => Err(crate::GatewayConfigError::AmbiguousFetchRoute(name())),
    }
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
                observed.backend(name, failure.affinity.unwrap_or("session"));
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
    let result = open(&state, selected.backend, backend.provider, payload)
        .instrument(observed.span.clone())
        .await;
    let (accepted, status, headers, mut events) = match result {
        Ok(value) => value,
        Err(failure) => {
            let error = match failure {
                HttpOpenError::Paid(error) => BackendError::from(error),
                failure => BackendError::Unavailable(chain(&failure)),
            };
            let message = match error {
                BackendError::Rejected(_) => "request exceeds or mismatches the granted resource",
                BackendError::Denied(_) => "grant access refused",
                BackendError::Quota(_) => "resource allowance exhausted",
                BackendError::Busy(_) => "Work Fetch is busy; retry later",
                BackendError::Conflict(_) => "conflicting request",
                BackendError::Timeout(_) => "authenticated Fetch timed out",
                BackendError::Unavailable(_) | BackendError::Failed(_) => {
                    "authenticated Fetch failed"
                }
            };
            if matches!(
                error,
                BackendError::Timeout(_) | BackendError::Unavailable(_) | BackendError::Failed(_)
            ) {
                tracing::warn!(backend = %backend.name, %error, "HTTP Fetch failed");
                state.routing.transport_failed(selected.backend);
            }
            let status = super::backend_status(&error);
            observed.status(status.as_u16());
            return attributed(self::error(status, message), &backend.name);
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
        let mut end = events.next().instrument(observed.span.clone()).await;
        let mut transcript = None;
        if let Some(Ok(WorkEvent::Transcript(signed))) = end {
            transcript = Some(transcript_value(&signed));
            end = events.next().instrument(observed.span.clone()).await;
        }
        if !matches!(
            end,
            Some(Ok(WorkEvent::Output(OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: None
            })))
        ) {
            observed.status(502);
            return error(StatusCode::BAD_GATEWAY, "invalid bodyless HTTP completion");
        }
        observed.complete();
        // Without a body there is nowhere to trail it; the head waited for it.
        if let Some(transcript) = transcript {
            headers.insert(TRANSCRIPT_KEY, transcript);
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::from_u16(status).unwrap();
        *response.headers_mut() = std::mem::take(&mut headers);
        return provenanced(attributed(response, &backend.name), accepted);
    }
    let name = backend.name.clone();
    let stream = async_stream::try_stream! {
        let _permit = permit;
        let mut size = 0usize;
        let mut transcript = None;
        while let Some(event) = events.next().instrument(observed.span.clone()).await {
            let event = event.map_err(|failure| {
                tracing::warn!(backend = %name, error = %chain(&failure), "HTTP Fetch stream failed");
                std::io::Error::other("Fetch stream verification failed")
            })?;
            let event = match event {
                WorkEvent::Output(event) => event,
                WorkEvent::Transcript(signed) => {
                    transcript = Some(transcript_value(&signed));
                    continue;
                }
                WorkEvent::Accepted(_) => continue,
            };
            match event {
                OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 })) => {
                    let bytes = hellas_rpc::http_fetch::decode_base64(&base64)
                        .map_err(|_| std::io::Error::other("invalid HTTP response encoding"))?;
                    size = size.saturating_add(bytes.len());
                    if size > upstream.max_response_bytes as usize {
                        Err(std::io::Error::other("HTTP response exceeds Fetch limit"))?;
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    observed.chunk(&bytes);
                    yield Frame::data(Bytes::from(bytes));
                }
                OutputEvent::Finished { stop_reason: StopReason::EndOfText, usage: None } => {
                    observed.complete();
                    if let Some(transcript) = transcript.take() {
                        yield Frame::trailers(HeaderMap::from_iter([(axum::http::HeaderName::from_static(TRANSCRIPT_KEY), transcript)]));
                    }
                    return;
                }
                _ => Err(std::io::Error::other("unexpected HTTP Fetch event"))?,
            }
        }
        Err(std::io::Error::other("HTTP Fetch ended without verified completion"))?;
    };
    let stream: futures::stream::BoxStream<'static, Result<Frame<Bytes>, std::io::Error>> =
        Box::pin(stream);
    // Announce the trailer: HTTP/1.1 sends it to clients that accept
    // trailers (`TE: trailers`).
    headers.insert(
        axum::http::header::TRAILER,
        HeaderValue::from_static(TRANSCRIPT_KEY),
    );
    let mut response = Response::new(Body::new(http_body_util::StreamBody::new(stream)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    *response.headers_mut() = headers;
    provenanced(attributed(response, &backend.name), accepted)
}

/// The accepted job's identity, for the provenance layer to render as headers.
fn provenanced(mut response: Response, accepted: Option<ExecutionProvenance>) -> Response {
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
}

/// The signed transcript as a header value: base64 of its canonical bytes.
fn transcript_value(transcript: &[u8]) -> HeaderValue {
    use base64::Engine as _;
    HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(transcript))
        .expect("base64 is always a valid header value")
}

/// The provider's acceptance, if reported, and the upstream response head.
type Opened = (
    Option<ExecutionProvenance>,
    u16,
    Vec<(String, String)>,
    super::WorkFetchStream,
);

async fn open(
    state: &HttpState,
    backend: usize,
    provider: iroh::EndpointId,
    payload: Vec<u8>,
) -> Result<Opened, HttpOpenError> {
    let (service, method) = &state.fetch_routes[backend];
    let mut stream = state.paid.fetch(WorkFetchRequest {
        provider,
        resource: state.routing.backends[backend].resource,
        channel: state.routing.backends[backend].channel,
        service: service.clone(),
        method: method.clone(),
        body: payload,
    })?;
    let accepted = super::accepted(&mut stream).await;
    match stream.next().await.transpose()? {
        Some(WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
            HttpResponseEvent::Head { status, headers },
        )))) if (200..=599).contains(&status) => {
            hellas_rpc::http_fetch::check_headers(&headers, false)?;
            Ok((accepted, status, headers, stream))
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

/// Error messages and their causes, without repeating causes already quoted.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}
