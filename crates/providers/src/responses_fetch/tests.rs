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
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<String>>);

impl tracing::field::Visit for CapturedLogs {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        write!(self.0.lock().unwrap(), "{field}={value:?} ").unwrap();
    }
}

impl tracing::Subscriber for CapturedLogs {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut self.clone());
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut self.clone());
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

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
async fn unsuccessful_fetch_never_logs_or_returns_the_upstream_body() {
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(sensitive_error)),
        "/responses",
    )
    .await;

    let logs = CapturedLogs::default();
    // Keep this subscriber installed for the test binary: other HTTP tests
    // also register the shared warning callsite on their runtime threads.
    tracing::subscriber::set_global_default(logs.clone()).unwrap();
    let Err(error) = execute_test_request(endpoint).await else {
        panic!("HTTP error unexpectedly passed");
    };
    let message = error.to_string();

    assert_eq!(
        message,
        "fetch provider failed: test upstream rejected the request (HTTP 422)"
    );
    assert!(!message.contains("UPSTREAM_PRIVATE_SENTINEL"));
    let logged = logs.0.lock().unwrap();
    assert!(logged.contains("upstream_status=422"), "{logged}");
    assert!(!logged.contains("UPSTREAM_PRIVATE_SENTINEL"), "{logged}");
}

#[tokio::test]
async fn an_unsuccessful_fetch_does_not_wait_for_an_error_body() {
    async fn stalled() -> Response {
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from_stream(stream::pending::<
                Result<Bytes, Infallible>,
            >()))
            .unwrap()
    }
    let endpoint = test_endpoint(
        Router::new().route("/responses", post(stalled)),
        "/responses",
    )
    .await;
    let result = tokio::time::timeout(Duration::from_secs(2), execute_test_request(endpoint))
        .await
        .expect("the response body must not be polled");
    let Err(error) = result else {
        panic!("HTTP error unexpectedly passed");
    };
    assert!(error.to_string().contains("HTTP 502"));
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
