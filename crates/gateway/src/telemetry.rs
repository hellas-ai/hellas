//! HTTP spans cover the response body lifetime, including SSE backpressure.

use axum::body::{Body, HttpBody};
use axum::extract::{MatchedPath, Request};
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use hellas_wire::metadata::Metadata;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::{Instrument, Span};

pub(super) async fn trace_request(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched");
    let span = tracing::info_span!(
        target: "hellas_request",
        "http.server",
        otel.kind = "server",
        http.request.method = %request.method(),
        http.route = route,
        http.response.status_code = tracing::field::Empty,
        http.response.body.size = tracing::field::Empty,
        hellas.first_response_body_ms = tracing::field::Empty,
        hellas.response.complete = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    );
    let mut metadata = Metadata::new();
    for key in ["traceparent", "tracestate"] {
        if let Some(value) = request
            .headers()
            .get(key)
            .and_then(|value| value.to_str().ok())
        {
            metadata.insert_text(key, value);
        }
    }
    hellas_rpc::telemetry::set_remote_parent(&span, &metadata);
    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    span.record(
        "http.response.status_code",
        i64::from(response.status().as_u16()),
    );
    if response.status().is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    let mut context = Metadata::new();
    hellas_rpc::telemetry::inject(&span, &mut context);
    if let Some(value) = context.get("traceparent").and_then(|value| value.as_text()) {
        if let Ok(header) = HeaderValue::from_str(value) {
            response.headers_mut().insert("traceparent", header);
        }
        if let Some(trace_id) = value.split('-').nth(1)
            && let Ok(header) = HeaderValue::from_str(trace_id)
        {
            response.headers_mut().insert("x-hellas-trace-id", header);
        }
    }
    response.map(|body| {
        Body::new(TracedBody {
            body,
            span,
            started,
            bytes: 0,
            first: true,
            complete: false,
        })
    })
}

struct TracedBody {
    body: Body,
    span: Span,
    started: Instant,
    bytes: u64,
    first: bool,
    complete: bool,
}

impl Drop for TracedBody {
    fn drop(&mut self) {
        self.span.record(
            "http.response.body.size",
            i64::try_from(self.bytes).unwrap_or(i64::MAX),
        );
        self.span.record(
            "hellas.response.complete",
            self.complete || self.body.is_end_stream(),
        );
    }
}

impl HttpBody for TracedBody {
    type Data = <Body as HttpBody>::Data;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let _entered = this.span.enter();
        let result = Pin::new(&mut this.body).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if this.first && !data.is_empty() {
                        this.span.record(
                            "hellas.first_response_body_ms",
                            this.started.elapsed().as_secs_f64() * 1_000.0,
                        );
                        this.first = false;
                    }
                    this.bytes += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(_))) => {
                this.span.record("otel.status_code", "ERROR");
            }
            Poll::Ready(None) => {
                this.complete = true;
            }
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}
