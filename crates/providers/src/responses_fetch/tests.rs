use super::*;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Redirect, Response};
use axum::routing::post;
use futures::stream;
use reqwest::header::{HeaderMap, HeaderValue};
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn redirect() -> Redirect {
    Redirect::temporary("/sink")
}

async fn sink(State(hits): State<Arc<AtomicUsize>>) {
    hits.fetch_add(1, Ordering::SeqCst);
}

async fn json_success() -> Response {
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"ok":true}"#))
        .unwrap()
}

async fn oversized_error() -> Response {
    let mut body = vec![b'x'; MAX_FETCH_ERROR_BODY_BYTES];
    body.extend_from_slice(b"SECRET_AFTER_LIMIT");
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::from(body))
        .unwrap()
}

async fn sensitive_error() -> Response {
    Response::builder()
        .status(StatusCode::UNPROCESSABLE_ENTITY)
        .body(Body::from("UPSTREAM_PRIVATE_SENTINEL"))
        .unwrap()
}

async fn oversized_event_stream() -> Response {
    let chunk = vec![b'x'; MAX_SSE_RESPONSE_BYTES / 3];
    let chunks = stream::iter([
        Ok::<_, Infallible>(Bytes::from(chunk.clone())),
        Ok(Bytes::from(chunk.clone())),
        Ok(Bytes::from(chunk)),
        Ok(Bytes::from_static(b"x")),
    ]);
    Response::builder()
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/event-stream; charset=utf-8",
        )
        .body(Body::from_stream(chunks))
        .unwrap()
}

fn stalled_error_before_first_byte() -> reqwest::Response {
    axum::http::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(reqwest::Body::wrap_stream(stream::pending::<
            Result<Bytes, Infallible>,
        >()))
        .unwrap()
        .into()
}

fn stalled_error_after_partial_body() -> reqwest::Response {
    let chunks =
        stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"useful diagnostic")) })
            .chain(stream::pending());
    axum::http::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(reqwest::Body::wrap_stream(chunks))
        .unwrap()
        .into()
}

fn promptly_streamed_error() -> reqwest::Response {
    let chunks = stream::iter([
        Bytes::from_static(b"useful "),
        Bytes::from_static(b"diagnostic"),
    ])
    .then(|chunk| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok::<_, Infallible>(chunk)
    });
    axum::http::Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(reqwest::Body::wrap_stream(chunks))
        .unwrap()
        .into()
}

async fn test_endpoint(app: Router, path: &str) -> Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Url::parse(&format!(
        "http://{}{}",
        listener.local_addr().unwrap(),
        path
    ))
    .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
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
async fn attested_fetch_client_never_follows_redirects() {
    let hits = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/origin", post(redirect))
        .route("/sink", post(sink))
        .with_state(hits.clone());
    let endpoint = test_endpoint(app, "/origin").await;

    let result = execute_test_request(endpoint).await;
    let Err(error) = result else {
        panic!("redirect unexpectedly reached an upstream success response");
    };

    assert!(error.to_string().contains("HTTP 307"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "otel")]
#[tokio::test]
async fn fetch_http_propagates_parent_and_keeps_span_until_stream_is_consumed() {
    use opentelemetry::trace::{SpanKind, TracerProvider};
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
    let _subscriber = tracing::subscriber::set_default(subscriber);
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
    provider.shutdown().unwrap();
}

#[tokio::test]
async fn successful_fetch_requires_event_stream_content_type() {
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(json_success)),
        "/responses",
    )
    .await;

    let Err(error) = execute_test_request(endpoint).await else {
        panic!("JSON success unexpectedly passed the SSE content-type check");
    };

    assert!(error.to_string().contains("without text/event-stream"));
}

#[tokio::test]
async fn provider_local_error_diagnostic_retains_only_a_bounded_body_prefix() {
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(oversized_error)),
        "/responses",
    )
    .await;

    let response = responses_http_client().post(endpoint).send().await.unwrap();
    let diagnostic = error_body_prefix(response).await;

    assert!(diagnostic.contains(&format!(
        "body prefix limited to {MAX_FETCH_ERROR_BODY_BYTES} bytes"
    )));
    assert!(!diagnostic.contains("SECRET_AFTER_LIMIT"));
    assert!(diagnostic.len() < MAX_FETCH_ERROR_BODY_BYTES + 256);
}

#[tokio::test]
async fn unsuccessful_fetch_never_forwards_the_upstream_body_to_the_caller() {
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(sensitive_error)),
        "/responses",
    )
    .await;

    let Err(error) = execute_test_request(endpoint).await else {
        panic!("HTTP error unexpectedly passed");
    };
    let message = error.to_string();

    assert_eq!(
        message,
        "fetch provider failed: test upstream rejected the request (HTTP 422)"
    );
    assert!(!message.contains("UPSTREAM_PRIVATE_SENTINEL"));
}

#[tokio::test(start_paused = true)]
async fn error_body_stalled_before_first_byte_hits_the_read_deadline() {
    let upstream = stalled_error_before_first_byte();
    let read_timeout = Duration::from_secs(5);
    let started = tokio::time::Instant::now();

    let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

    assert_eq!(started.elapsed(), read_timeout);
    assert_eq!(diagnostic, "[error body read timed out after 5 seconds]");
}

#[tokio::test(start_paused = true)]
async fn partial_error_body_is_retained_when_the_read_deadline_expires() {
    let upstream = stalled_error_after_partial_body();
    let read_timeout = Duration::from_secs(5);
    let started = tokio::time::Instant::now();

    let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

    assert_eq!(started.elapsed(), read_timeout);
    assert_eq!(
        diagnostic,
        "useful diagnostic [error body read timed out after 5 seconds]"
    );
}

#[tokio::test(start_paused = true)]
async fn promptly_streamed_error_body_completes_within_the_read_deadline() {
    let upstream = promptly_streamed_error();
    let read_timeout = Duration::from_secs(5);
    let started = tokio::time::Instant::now();

    let diagnostic = error_body_prefix_with_deadline(upstream, read_timeout).await;

    assert_eq!(started.elapsed(), Duration::from_secs(2));
    assert_eq!(diagnostic, "useful diagnostic");
}

#[tokio::test]
async fn stalled_sse_body_hits_the_idle_deadline() {
    async fn stalled() -> Response {
        let chunks =
            stream::once(async { Ok::<_, Infallible>(Bytes::from_static(b"data: first\n\n")) })
                .chain(stream::pending());
        Response::builder()
            .header(CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(chunks))
            .unwrap()
    }

    let app = Router::new().route("/stalled", post(stalled));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = responses_http_client()
        .post(format!("http://{addr}/stalled"))
        .send()
        .await
        .unwrap();
    let stream =
        stream_response_with_idle_timeout(response, "test".to_string(), Duration::from_millis(10));
    futures::pin_mut!(stream);

    assert_eq!(stream.next().await.unwrap().unwrap(), b"data: first\n\n");
    let error = stream.next().await.unwrap().unwrap_err().to_string();
    assert!(error.contains("produced no bytes"), "{error}");
}

#[tokio::test]
async fn successful_fetch_caps_cumulative_upstream_bytes() {
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(oversized_event_stream)),
        "/responses",
    )
    .await;
    let mut stream = execute_test_request(endpoint).await.unwrap().stream;
    let mut accepted = 0_usize;
    let error = loop {
        match stream.next().await {
            Some(Ok(chunk)) => accepted = accepted.checked_add(chunk.len()).unwrap(),
            Some(Err(error)) => break error,
            None => panic!("oversized upstream stream ended without a limit error"),
        }
    };

    assert!(accepted <= MAX_SSE_RESPONSE_BYTES);
    assert!(
        error
            .to_string()
            .contains("stream exceeded the 3145728-byte limit")
    );
}

#[test]
fn effective_model_uses_standard_header_and_rejects_ambiguous_duplicates() {
    let mut headers = HeaderMap::new();
    headers.append("x-openai-model", HeaderValue::from_static("fallback"));
    headers.append("openai-model", HeaderValue::from_static("official"));
    assert_eq!(
        effective_model_from_headers(&headers).unwrap().as_deref(),
        Some("official")
    );

    headers.append("openai-model", HeaderValue::from_static("conflict"));
    assert!(
        effective_model_from_headers(&headers)
            .unwrap_err()
            .to_string()
            .contains("conflicting duplicate openai-model")
    );

    let mut malformed = HeaderMap::new();
    malformed.append(
        "openai-model",
        HeaderValue::from_bytes(b"\xff").expect("opaque HTTP header value"),
    );
    assert!(
        effective_model_from_headers(&malformed)
            .unwrap_err()
            .to_string()
            .contains("not valid UTF-8")
    );
}
