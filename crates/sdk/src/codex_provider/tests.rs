use super::*;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::routing::post;
use base64::Engine;
use futures::StreamExt;
use hellas_rpc::JsonBytes;
use std::sync::Arc;
use tokio::sync::oneshot;

type CapturedRequest = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Bytes,
);

#[derive(Clone)]
struct Capture {
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<CapturedRequest>>>>,
}

async fn capture_responses_sse(
    State(capture): State<Capture>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let account_id = headers
        .get("ChatGPT-Account-ID")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let originator = headers
        .get("Originator")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    if let Some(tx) = capture.tx.lock().await.take() {
        let _ = tx.send((auth, idempotency_key, accept, account_id, originator, body));
    }
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(
            r#"event: response.created
data: {"type":"response.created","response":{"id":"resp_codex_up","object":"response","created_at":42,"status":"in_progress"}}

event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_codex_up","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_codex_up","delta":"ok"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_codex_up","object":"response","created_at":42,"status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

"#,
        ))
        .unwrap()
}

fn request(body: &[u8]) -> PreparedFetchRequest {
    let call = hellas_executor::FetchCall::new(
        "codex",
        "responses",
        JsonBytes::new(body.to_vec()),
        None,
        hellas_rpc::InputCommitment::from_digest(hellas_auth::Digest::from_bytes([7; 32])),
    );
    PreparedFetchRequest::new(&call, call.body.clone())
}

#[tokio::test]
async fn forwards_streaming_request_with_codex_token() {
    let (tx, rx) = oneshot::channel();
    let app = Router::new()
        .route("/codex/responses", post(capture_responses_sse))
        .with_state(Capture {
            tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let access_token = non_expiring_token();
    let auth = native_store(dir.path(), &access_token, "acct-1");
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
    headers.insert("ChatGPT-Account-ID", HeaderValue::from_static("acct-1"));
    headers.insert("Originator", HeaderValue::from_static(CODEX_ORIGINATOR));
    let (endpoint, client) = hellas_providers::test_support::https_forward(
        Url::parse(&format!("http://{addr}/codex/responses")).unwrap(),
        headers,
    );
    let mut provider = CodexResponsesFetchProvider::with_store(endpoint, auth);
    provider.client = client;

    let body = br#"{"model":"gpt-5.5-codex","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],"stream":true}"#;
    let call = hellas_executor::FetchCall::new(
        "codex",
        "responses",
        JsonBytes::new(body.to_vec()),
        None,
        hellas_rpc::InputCommitment::from_digest(hellas_auth::Digest::from_bytes([7; 32])),
    );
    use hellas_executor::FetchAdaptorFactory as _;
    let prepared = hellas_providers::CodexResponsesAdaptorFactory::new(8)
        .unwrap()
        .create(&call)
        .unwrap()
        .provider_request;
    let expected_body = prepared.body.clone();
    let mut stream = provider.run(prepared).await.unwrap().stream;
    let mut output = Vec::new();
    while let Some(event) = stream.next().await {
        output.push(event.unwrap());
    }
    let (auth, idempotency_key, accept, account_id, originator, forwarded_body) = rx.await.unwrap();

    assert_eq!(auth, Some(format!("Bearer {access_token}")));
    assert_eq!(idempotency_key, Some(request(body).idempotency_key()));
    assert_eq!(accept.as_deref(), Some("text/event-stream"));
    assert_eq!(account_id.as_deref(), Some("acct-1"));
    assert_eq!(originator.as_deref(), Some(CODEX_ORIGINATOR));
    assert_eq!(forwarded_body.as_ref(), expected_body.as_bytes());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&forwarded_body).unwrap()["max_output_tokens"],
        8
    );
    let joined = String::from_utf8(output.concat()).unwrap();
    assert!(joined.contains("event: response.created"));
    assert!(joined.contains(r#""id":"resp_codex_up""#));
    assert!(joined.contains(r#""delta":"ok""#));
    assert!(joined.contains("event: response.completed"));
}

#[test]
fn refuses_chatgpt_route_without_account_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("codex-auth.json");
    std::fs::write(
        &path,
        br#"{"version":1,"tokens":{"access_token":"access","refresh_token":"refresh"},"last_refresh":null,"refresh_token_blocked":null}"#,
    )
    .unwrap();
    assert!(CodexResponsesFetchProvider::new(Some(&path)).is_err());
}

#[test]
fn production_endpoint_is_the_manifest_endpoint() {
    assert_eq!(
        Url::parse(CODEX_RESPONSES_ENDPOINT).unwrap().as_str(),
        "https://chatgpt.com/backend-api/codex/responses"
    );
}

fn non_expiring_token() -> String {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
    format!("header.{payload}.signature")
}

use hellas_providers::test_support as interception;

#[tokio::test]
async fn codex_requests_reject_operator_interception_without_refresh() {
    interception::rejects_operator_interception(
        concat!(
            module_path!(),
            "::codex_requests_reject_operator_interception_without_refresh"
        )
        .trim_start_matches("hellas_sdk::"),
        1,
        |url| async move {
            let dir = tempfile::tempdir().unwrap();
            let auth = native_store(dir.path(), &non_expiring_token(), "PRIVATE_ACCOUNT_CANARY");
            let provider = CodexResponsesFetchProvider::with_store(url, auth.clone());
            let response = provider.run(request(b"PRIVATE_PROMPT_CANARY")).await;
            let rejected = response.is_err();
            drop(response);
            let before = std::fs::read(dir.path().join("auth.json")).unwrap();
            native_store(dir.path(), "expired", "PRIVATE_ACCOUNT_CANARY");
            let expired_before = std::fs::read(dir.path().join("auth.json")).unwrap();
            let expired = auth.credentials().await;
            rejected
                && expired.is_err()
                && std::fs::read(dir.path().join("auth.json")).unwrap() == expired_before
                && before != expired_before
        },
    )
    .await;
}

fn native_store(directory: &std::path::Path, token: &str, account: &str) -> CodexAuthStore {
    let path = directory.join("auth.json");
    let value = serde_json::json!({"auth_mode":"chatgpt","tokens":{"access_token":token,"account_id":account,"refresh_token":"DO_NOT_REFRESH"}});
    hellas_private::write_atomically(&path, "json", &serde_json::to_vec(&value).unwrap()).unwrap();
    CodexAuthStore::new(Some(&path)).unwrap()
}
