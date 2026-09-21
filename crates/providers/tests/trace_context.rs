#![cfg(feature = "otel")]

// Exercise the application's single SDK/subscriber setup in its own process.
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Response},
    routing::post,
};
use futures::StreamExt;
use hellas_executor::{FetchProviderError, FetchProviderResponse};
use hellas_providers::{execute_responses_request, responses_http_client};
use reqwest::Url;

async fn test_endpoint(app: Router, path: &str) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Url::parse(&format!("http://{}{path}", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    endpoint
}

async fn execute_test_request(endpoint: Url) -> Result<FetchProviderResponse, FetchProviderError> {
    execute_responses_request(
        &responses_http_client(),
        endpoint,
        "secret",
        br#"{"model":"m","input":"hi","stream":true}"#.to_vec(),
        "idempotency",
        "test",
    )
    .await
}

#[tokio::test]
async fn fetch_http_propagates_parent_and_keeps_span_until_stream_is_consumed() {
    use opentelemetry::trace::{SpanKind, Status, TracerProvider};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing::Instrument;
    use tracing_subscriber::prelude::*;

    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer("test"))
            .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                metadata.is_span()
                    && (metadata.target() == "hellas_request"
                        || metadata.name() == "test.fetch.request")
            })),
    );
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let (headers_tx, mut headers_rx) = tokio::sync::mpsc::channel(1);
    let endpoint = test_endpoint(
        Router::new().route(
            "/responses",
            post(move |headers: HeaderMap| {
                let headers_tx = headers_tx.clone();
                async move {
                    headers_tx.send(headers).await.unwrap();
                    Response::builder()
                        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from("data: PRIVATE_RESPONSE_SENTINEL\n\n"))
                        .unwrap()
                }
            }),
        ),
        "/responses?private_query=PRIVATE_QUERY_SENTINEL",
    )
    .await;
    let parent = tracing::info_span!(parent: None, "test.fetch.request");
    let mut response = execute_test_request(endpoint)
        .instrument(parent.clone())
        .await
        .unwrap();
    let headers = headers_rx.recv().await.unwrap();
    let traceparent = headers
        .get("traceparent")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        exporter.get_finished_spans().unwrap().is_empty(),
        "HTTP headers must not close the streamed client span"
    );
    assert!(response.stream.next().await.unwrap().is_ok());
    assert!(
        exporter.get_finished_spans().unwrap().is_empty(),
        "one body chunk must not close the client span"
    );
    assert!(response.stream.next().await.is_none());
    drop(response);
    drop(parent);
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 2, "one request and one HTTP transport span");
    let request = spans
        .iter()
        .find(|span| span.name == "test.fetch.request")
        .unwrap();
    let http = spans
        .iter()
        .find(|span| span.span_kind == SpanKind::Client)
        .unwrap();
    assert_eq!(http.name, "POST");
    assert!(!matches!(http.status, Status::Error { .. }));
    assert_eq!(http.parent_span_id, request.span_context.span_id());
    assert_eq!(
        http.span_context.trace_id(),
        request.span_context.trace_id()
    );
    assert_eq!(
        traceparent,
        format!(
            "00-{}-{}-01",
            http.span_context.trace_id(),
            http.span_context.span_id()
        )
    );
    assert!(
        http.attributes
            .iter()
            .any(|kv| kv.key.as_str() == "http.response.status_code"
                && kv.value == opentelemetry::Value::I64(200))
    );
    for span in spans {
        assert!(span.events.is_empty());
        assert!(span.attributes.iter().all(|kv| {
            let value = kv.value.to_string();
            !value.contains("PRIVATE_")
                && !value.contains("secret")
                && !value.contains("idempotency")
        }));
    }
    let endpoint = test_endpoint(
        Router::new().route(
            "/responses",
            post(|| async {
                Response::builder()
                    .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(futures::stream::pending::<
                        Result<Vec<u8>, std::io::Error>,
                    >()))
                    .unwrap()
            }),
        ),
        "/responses",
    )
    .await;
    let response = execute_test_request(endpoint).await.unwrap();
    drop(response);
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    let cancelled = spans.last().unwrap();
    assert!(matches!(cancelled.status, Status::Error { .. }));
    assert!(
        cancelled
            .attributes
            .iter()
            .any(|kv| kv.key.as_str() == "error.type"
                && kv.value == opentelemetry::Value::from("cancelled"))
    );
    provider.shutdown().unwrap();
}
