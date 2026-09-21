use axum::{Router, response::Response};

pub(super) fn layer(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(trace_request))
}

async fn trace_request(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    use tracing::Instrument;
    let span = hellas_rpc::request_span!(target: "hellas_request", parent: None, "indexer.http",
        otel.kind = "server", http.request.method = %request.method(),
        http.response.status_code = tracing::field::Empty);
    let mut headers = hellas_wire::Metadata::new();
    for name in ["traceparent", "tracestate"] {
        if let Some(value) = request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
        {
            headers.insert_text(name, value);
        }
    }
    hellas_rpc::telemetry::set_remote_parent(&span, &headers);
    let response = next.run(request).instrument(span.clone()).await;
    span.record(
        "http.response.status_code",
        i64::from(response.status().as_u16()),
    );
    response
}
