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
    let auth = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse("http://127.0.0.1/token").unwrap(),
    );
    let access_token = non_expiring_token();
    auth.save(&crate::commands::codex_auth::CodexAuthState::new(
        crate::commands::codex_auth::test_tokens_with_account_id(
            &access_token,
            "refresh",
            "acct-1",
        ),
        None,
    ))
    .unwrap();
    let provider = CodexResponsesFetchProvider::with_store(
        Url::parse(&format!("http://{addr}/codex/responses")).unwrap(),
        auth,
    );

    let body = br#"{"model":"gpt-5.5-codex","input":"hello","stream":true}"#;
    let mut stream = provider.run(request(body)).await.unwrap().stream;
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
    assert_eq!(forwarded_body.as_ref(), body);
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
async fn codex_requests_and_refresh_reject_operator_interception() {
    interception::rejects_operator_interception(
        concat!(
            module_path!(),
            "::codex_requests_and_refresh_reject_operator_interception"
        )
        .trim_start_matches("hellas::"),
        2,
        |url| async move {
            let dir = tempfile::tempdir().unwrap();
            let auth = CodexAuthStore::with_token_url(dir.path().join("auth.json"), url.clone());
            auth.save(&crate::commands::codex_auth::CodexAuthState::new(
                crate::commands::codex_auth::test_tokens_with_account_id(
                    &non_expiring_token(),
                    "PRIVATE_REFRESH_CANARY",
                    "PRIVATE_ACCOUNT_CANARY",
                ),
                None,
            ))
            .unwrap();
            let provider = CodexResponsesFetchProvider::with_store(url, auth.clone());
            let response = provider.run(request(b"PRIVATE_PROMPT_CANARY")).await;
            let rejected = response.is_err();
            drop(response);
            // Force a separate refresh through the actual store/client path.
            auth.save(&crate::commands::codex_auth::CodexAuthState::new(
                crate::commands::codex_auth::test_tokens_with_account_id(
                    "expired",
                    "PRIVATE_REFRESH_CANARY",
                    "PRIVATE_ACCOUNT_CANARY",
                ),
                None,
            ))
            .unwrap();
            let refreshed = auth.access_token().await;
            rejected && refreshed.is_err()
        },
    )
    .await;
}
