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

pub async fn trace_request(request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("unmatched");
    let span = tracing::info_span!(
        target: "hellas_request",
        parent: None,
        "http.server",
        otel.kind = "server",
        http.request.method = %request.method(),
        http.route = route,
        http.response.status_code = tracing::field::Empty,
        http.response.body.size = tracing::field::Empty,
        hellas.first_response_body_ms = tracing::field::Empty,
        hellas.response.complete = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
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
    super::set_remote_parent(&span, &metadata);
    let mut trace = ResponseTrace {
        span,
        started: Instant::now(),
        bytes: 0,
        first: true,
        complete: false,
        failed: false,
    };
    let mut response = next.run(request).instrument(trace.span.clone()).await;
    trace.span.record(
        "http.response.status_code",
        i64::from(response.status().as_u16()),
    );
    if response.status().is_server_error() {
        trace.span.record("otel.status_code", "ERROR");
    }
    let mut context = Metadata::new();
    super::inject(&trace.span, &mut context);
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
        trace.complete = body.is_end_stream();
        Body::new(TracedBody { body, trace })
    })
}

struct TracedBody {
    body: Body,
    trace: ResponseTrace,
}

/// The handler owns this guard until it transfers it to the response body.
/// Dropping either stage before completion records the same cancellation.
struct ResponseTrace {
    span: Span,
    started: Instant,
    bytes: u64,
    first: bool,
    complete: bool,
    failed: bool,
}

impl Drop for ResponseTrace {
    fn drop(&mut self) {
        self.span.record(
            "http.response.body.size",
            i64::try_from(self.bytes).unwrap_or(i64::MAX),
        );
        let complete = !self.failed && self.complete;
        self.span.record("hellas.response.complete", complete);
        if !complete && !self.failed {
            self.span.record("error.type", "cancelled");
            self.span.record("otel.status_code", "ERROR");
        }
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
        let _entered = this.trace.span.enter();
        let result = Pin::new(&mut this.body).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if this.trace.first && !data.is_empty() {
                        this.trace.span.record(
                            "hellas.first_response_body_ms",
                            this.trace.started.elapsed().as_secs_f64() * 1_000.0,
                        );
                        this.trace.first = false;
                    }
                    this.trace.bytes += data.len() as u64;
                }
            }
            Poll::Ready(Some(Err(_))) => {
                this.trace.span.record("otel.status_code", "ERROR");
                this.trace.span.record("error.type", "body_error");
                this.trace.failed = true;
            }
            Poll::Ready(None) => {
                this.trace.complete = true;
            }
            Poll::Pending => {}
        }
        this.trace.complete |= this.body.is_end_stream();
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::get;
    use opentelemetry::trace::{Status, TracerProvider};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;

    #[tokio::test]
    async fn http_spans_cover_handler_and_body_completion_errors_and_cancellation() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("http-test"))),
        );
        let app = axum::Router::new()
            .route("/ok", get(|| async { "hello" }))
            .route("/empty", get(|| async { Body::empty() }))
            .route("/pending", get(std::future::pending::<&'static str>))
            .route(
                "/bad",
                get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "failed") }),
            )
            .route(
                "/cancel",
                get(|| async {
                    Body::from_stream(futures_util::stream::pending::<
                        Result<bytes::Bytes, std::io::Error>,
                    >())
                }),
            )
            .route(
                "/body-error",
                get(|| async {
                    Body::from_stream(futures_util::stream::iter([
                        Ok(bytes::Bytes::from_static(b"partial")),
                        Err(std::io::Error::other("private body failure")),
                    ]))
                }),
            )
            .layer(axum::middleware::from_fn(trace_request));
        for (index, route) in ["/ok", "/bad", "/cancel", "/body-error", "/empty"]
            .into_iter()
            .enumerate()
        {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(route).body(Body::empty()).unwrap())
                .with_subscriber(dispatch.clone())
                .await
                .unwrap();
            assert_eq!(
                exporter.get_finished_spans().unwrap().len(),
                index,
                "HTTP span ended at headers instead of body completion"
            );
            let mut body = response.into_body();
            if route != "/cancel" {
                while std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                    .await
                    .is_some()
                {}
            }
            drop(body);
        }
        let mut pending = Box::pin(
            app.oneshot(
                Request::builder()
                    .uri("/pending")
                    .body(Body::empty())
                    .unwrap(),
            )
            .with_subscriber(dispatch),
        );
        assert!(futures_util::poll!(&mut pending).is_pending());
        assert_eq!(exporter.get_finished_spans().unwrap().len(), 5);
        drop(pending);
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 6);
        let cancelled = spans.last().unwrap();
        assert!(
            cancelled
                .attributes
                .iter()
                .any(|kv| kv.key.as_str() == "error.type"
                    && kv.value == opentelemetry::Value::from("cancelled"))
        );
        assert!(
            !cancelled
                .attributes
                .iter()
                .any(|kv| kv.key.as_str() == "http.response.status_code"),
            "cancelled handler never produced response headers"
        );
        for (span, (route, complete, failed)) in spans.iter().zip([
            ("/ok", true, false),
            ("/bad", true, true),
            ("/cancel", false, true),
            ("/body-error", false, true),
            ("/empty", true, false),
            ("/pending", false, true),
        ]) {
            assert!(
                span.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "http.route"
                        && kv.value == opentelemetry::Value::from(route))
            );
            assert!(
                span.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "hellas.response.complete"
                        && kv.value == opentelemetry::Value::Bool(complete))
            );
            assert_eq!(matches!(span.status, Status::Error { .. }), failed);
            assert!(!format!("{span:?}").contains("private body failure"));
        }
        provider.shutdown().unwrap();
    }
}
