//! HTTP bytes over authenticated Fetch, without translating vendor schemas.
//!
//! The provider's acceptance heads the response as `x-hellas-commitment-bin`
//! and `x-hellas-provider`; the signed transcript trails the body as
//! `x-hellas-transcript` (a header on a bodyless response). A transcript too
//! large to carry inline is not delivered to the HTTP caller: the trailer is
//! omitted and `x-hellas-transcript-digest` names the lowercase hex SHA-256 of
//! the canonical signed bytes, which the caller must obtain out of band. The
//! gateway neither retains nor serves that copy.
mod config;
mod observation;
use crate::routing;
pub use crate::routing::RoutingError;

pub use config::HttpRoute;
#[cfg(test)]
mod tests;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use futures::StreamExt;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
use hellas_rpc::provenance::{ExecutionProvenance, TRANSCRIPT_DIGEST_KEY, TRANSCRIPT_KEY};
use http_body::Frame;
use std::sync::Arc;
use tracing::Instrument;

use super::{WorkEvent, WorkFetchRequest, json_error};
use crate::backend::provenance::transcript_header;
use hellas_adaptors::BackendError;

#[derive(Clone)]
pub(crate) struct BackendName(pub String);

fn attributed(mut response: Response, name: &str) -> Response {
    response.extensions_mut().insert(BackendName(name.into()));
    response
}

struct HttpState {
    fetch_route: (String, String),
    paid: Arc<crate::route::RouteExecution>,
    route: HttpRoute,
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

pub(super) fn router(
    route: HttpRoute,
    service: String,
    method: String,
    paid: Arc<crate::route::RouteExecution>,
) -> crate::GatewayResult<Router> {
    route.validate()?;
    let path = route.path.clone();
    Ok(Router::new()
        .route(&path, axum::routing::any(handle))
        .with_state(Arc::new(HttpState {
            fetch_route: (service, method),
            paid,
            route,
            metrics: observation::Metrics::new(),
        })))
}

async fn handle(
    State(state): State<Arc<HttpState>>,
    axum::Extension(mut selected): axum::Extension<routing::Selection>,
    request: Request,
) -> Response {
    let mut observed = observation::Observation::new(&state.metrics, request.uri().path());
    let (parts, body) = request.into_parts();
    // Reserve space for URL, headers and JSON around the base64 body.
    let body_limit = (hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES - 64 * 1024) / 4 * 3;
    let body = match axum::body::to_bytes(body, body_limit).await {
        Ok(body) => body,
        Err(_) => {
            observed.status(413);
            observed.complete();
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "HTTP request exceeds Fetch limit",
            );
        }
    };
    let route = &state.route;
    observed.model(selected.model.as_deref());
    let mut upstream = match route.request(body, &parts.headers) {
        Ok(upstream) => upstream,
        Err(_) => {
            observed.status(400);
            observed.complete();
            return json_error(StatusCode::BAD_REQUEST, "unsupported HTTP header encoding");
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
            return json_error(StatusCode::BAD_REQUEST, "invalid HTTP request");
        }
    };
    let result = open(&state, &mut selected, payload)
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
                tracing::warn!(backend = ?selected.backend, %error, "HTTP Fetch failed");
            }
            let status = super::backend_status(&error);
            observed.status(status.as_u16());
            return attributed(
                json_error(status, message),
                selected.backend.as_deref().unwrap_or(""),
            );
        }
    };
    let backend = selected.backend.as_deref().unwrap_or("");
    observed.backend(backend, selected.affinity);
    observed.bind_response(selected.response_binding(&route.path));
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
    selected.observe(status, &headers);
    if parts.method == axum::http::Method::HEAD || status == 204 || status == 304 {
        let mut end = events.next().instrument(observed.span.clone()).await;
        let mut transcript = None;
        if let Some(Ok(WorkEvent::Transcript(signed))) = end {
            transcript = Some(signed);
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
            return json_error(StatusCode::BAD_GATEWAY, "invalid bodyless HTTP completion");
        }
        observed.complete();
        // Without a body there is nowhere to trail it; the head waited for it.
        if let Some(transcript) = transcript {
            let (name, value) = transcript_header(&transcript);
            headers.insert(name, value);
        }
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::from_u16(status).unwrap();
        *response.headers_mut() = std::mem::take(&mut headers);
        return provenanced(attributed(response, backend), accepted);
    }
    let name = backend.to_owned();
    let stream = async_stream::try_stream! {
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
                    transcript = Some(signed);
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
                        let (name, value) = transcript_header(&transcript);
                        yield Frame::trailers(HeaderMap::from_iter([(name, value)]));
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
    // trailers (`TE: trailers`). Which of the two evidence fields arrives
    // depends on the transcript's size, which is not known yet.
    headers.insert(
        axum::http::header::TRAILER,
        HeaderValue::from_str(&format!("{TRANSCRIPT_KEY}, {TRANSCRIPT_DIGEST_KEY}"))
            .expect("header names are valid trailer tokens"),
    );
    let mut response = Response::new(Body::new(http_body_util::StreamBody::new(stream)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap();
    *response.headers_mut() = headers;
    provenanced(attributed(response, backend), accepted)
}

/// The accepted job's identity, for the provenance layer to render as headers.
fn provenanced(mut response: Response, accepted: Option<ExecutionProvenance>) -> Response {
    if let Some(accepted) = accepted {
        response.extensions_mut().insert(accepted);
    }
    response
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
    selection: &mut routing::Selection,
    payload: Vec<u8>,
) -> Result<Opened, HttpOpenError> {
    let (service, method) = &state.fetch_route;
    let mut stream = state
        .paid
        .fetch(
            selection,
            WorkFetchRequest {
                service: service.clone(),
                method: method.clone(),
                body: payload,
            },
        )
        .await?;
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
