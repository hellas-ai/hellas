use super::*;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use hellas_adaptors::openai::responses::OpenAiResponsesAdaptor;
use hellas_adaptors::{
    OutputEvent, OutputItem, RawRequest, StopReason, TextChannel, Usage, WireAdaptor,
};
use std::sync::Arc;
use tokio::sync::oneshot;

type CapturedRequest = (Option<String>, Bytes);
type CaptureSender = oneshot::Sender<CapturedRequest>;
type SharedCaptureSender = Arc<tokio::sync::Mutex<Option<CaptureSender>>>;

#[derive(Clone)]
struct Capture {
    tx: SharedCaptureSender,
}

async fn capture_responses_sse(
    State(capture): State<Capture>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = headers
        .get(AUTHORIZATION.as_str())
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    if let Some(tx) = capture.tx.lock().await.take() {
        let _ = tx.send((auth, body));
    }
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(
            r#"event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_1","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"hel"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"lo"}

event: response.output_text.done
data: {"type":"response.output_text.done","item_id":"msg_1","text":"hello"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}

"#,
        ))
        .unwrap()
}

fn backend_request(body: Bytes) -> BackendRequest {
    let raw = RawRequest::from_slice(&body).unwrap();
    let adaptor = OpenAiResponsesAdaptor;
    let parsed = adaptor.parse(raw.clone()).unwrap();
    let execution = adaptor.to_execution_request(&parsed).unwrap();
    BackendRequest::new(execution, raw)
}

fn test_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_certs_only(std::iter::empty::<reqwest::Certificate>())
        .build()
        .unwrap()
}

fn test_proxy(addr: std::net::SocketAddr, bearer_token: Option<String>) -> ResponsesProxy {
    ResponsesProxy::with_client(
        test_client(),
        Url::parse(&format!("http://{addr}/v1/responses")).unwrap(),
        bearer_token,
    )
}

#[test]
fn cache_identity_hashes_the_effective_request_and_endpoint_not_credentials() {
    use crate::cache::CacheIdentity;
    let proxy = test_proxy("127.0.0.1:1234".parse().unwrap(), Some("secret-one".into()));
    let request = backend_request(Bytes::from_static(
        br#"{"model":"fixture","input":"hello","stream":false}"#,
    ));
    let key = proxy.cache_key(&request).unwrap();
    let streaming = backend_request(Bytes::from_static(
        br#"{"model":"fixture","input":"hello","stream":true}"#,
    ));
    assert_eq!(key, proxy.cache_key(&streaming).unwrap());
    let other_token = test_proxy("127.0.0.1:1234".parse().unwrap(), Some("secret-two".into()));
    assert_eq!(key, other_token.cache_key(&request).unwrap());
    let other_endpoint = test_proxy("127.0.0.1:1235".parse().unwrap(), None);
    assert_ne!(key, other_endpoint.cache_key(&request).unwrap());
    let mut other_model = request.clone();
    other_model.execution.canonical.model.name = "other".into();
    assert_ne!(key, proxy.cache_key(&other_model).unwrap());
    let other_input = backend_request(Bytes::from_static(
        br#"{"model":"fixture","input":"changed"}"#,
    ));
    assert_ne!(key, proxy.cache_key(&other_input).unwrap());
}

#[tokio::test]
async fn streaming_backend_forwards_request_body_and_bearer_token() {
    let (tx, rx) = oneshot::channel();
    let captured = Capture {
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
    };
    let app = Router::new()
        .route("/v1/responses", post(capture_responses_sse))
        .with_state(captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let proxy = test_proxy(addr, Some("test-key".to_string()));
    let body = Bytes::from_static(br#"{"model":"m","input":"hello","seed":7}"#);
    let stream = proxy.stream(backend_request(body)).await.unwrap();
    let _result = stream.collect().await.unwrap();

    let (auth, forwarded_body) = rx.await.unwrap();
    assert_eq!(auth.as_deref(), Some("Bearer test-key"));
    let forwarded: JsonValue = serde_json::from_slice(&forwarded_body).unwrap();
    assert_eq!(forwarded["model"], "m");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["seed"], 7);
    assert_eq!(forwarded["stream"], true);
}

#[tokio::test]
async fn rewrites_model_when_execution_model_changes() {
    let (tx, rx) = oneshot::channel();
    let captured = Capture {
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
    };
    let app = Router::new()
        .route("/v1/responses", post(capture_responses_sse))
        .with_state(captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let proxy = test_proxy(addr, None);
    let body = Bytes::from_static(br#"{"model":"public","input":"hello","seed":7}"#);
    let mut request = backend_request(body);
    request.execution.canonical.model.name = "upstream".to_string();

    let stream = proxy.stream(request).await.unwrap();
    let _result = stream.collect().await.unwrap();

    let (_auth, forwarded_body) = rx.await.unwrap();
    let forwarded: JsonValue = serde_json::from_slice(&forwarded_body).unwrap();
    assert_eq!(forwarded["model"], "upstream");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["seed"], 7);
    assert_eq!(forwarded["stream"], true);
}

#[tokio::test]
async fn stream_collects_projected_response() {
    let (tx, rx) = oneshot::channel();
    let captured = Capture {
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
    };
    let app = Router::new()
        .route("/v1/responses", post(capture_responses_sse))
        .with_state(captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let body = Bytes::from_static(br#"{"model":"m","input":"hello","metadata":{"trace":"abc"}}"#);
    let proxy = test_proxy(addr, Some("test-key".to_string()));

    let stream = proxy.stream(backend_request(body)).await.unwrap();
    let result = stream.collect().await.unwrap();

    let (auth, forwarded_body) = rx.await.unwrap();
    assert_eq!(auth.as_deref(), Some("Bearer test-key"));
    let forwarded: JsonValue = serde_json::from_slice(&forwarded_body).unwrap();
    assert_eq!(forwarded["model"], "m");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["metadata"]["trace"], "abc");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(result.usage.unwrap().total_tokens, Some(5));
    assert_eq!(result.stop_reason, StopReason::EndOfText);
    assert_eq!(
        result.output,
        vec![OutputItem::Text {
            text: "hello".to_string(),
            channel: TextChannel::Output,
        }]
    );
}

#[tokio::test]
async fn streaming_backend_projects_responses_sse() {
    let (tx, rx) = oneshot::channel();
    let captured = Capture {
        tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
    };
    let app = Router::new()
        .route("/v1/responses", post(capture_responses_sse))
        .with_state(captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let body = Bytes::from_static(br#"{"model":"m","input":"hello","stream":true}"#);
    let proxy = test_proxy(addr, Some("test-key".to_string()));
    let stream = proxy.stream(backend_request(body.clone())).await.unwrap();
    let events = stream
        .events
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let (auth, forwarded_body) = rx.await.unwrap();
    assert_eq!(auth.as_deref(), Some("Bearer test-key"));
    let forwarded: JsonValue = serde_json::from_slice(&forwarded_body).unwrap();
    assert_eq!(forwarded["model"], "m");
    assert_eq!(forwarded["input"], "hello");
    assert_eq!(forwarded["stream"], true);
    assert_eq!(
        events,
        vec![
            OutputEvent::TextDelta {
                index: 0,
                delta: "hel".to_string(),
                channel: TextChannel::Output,
            },
            OutputEvent::TextDelta {
                index: 0,
                delta: "lo".to_string(),
                channel: TextChannel::Output,
            },
            OutputEvent::Finished {
                stop_reason: StopReason::EndOfText,
                usage: Some(Usage {
                    input_tokens: Some(3),
                    output_tokens: Some(2),
                    total_tokens: Some(5),
                }),
            },
        ]
    );
}
