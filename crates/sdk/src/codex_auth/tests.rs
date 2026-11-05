use super::*;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde_json::json;
use std::sync::Arc;

#[test]
fn parses_jwt_expiry() {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
    let token = format!("x.{payload}.y");
    assert_eq!(access_token_expires_at(&token), Some(4102444800));
}

#[test]
fn save_and_load_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::new(Some(&dir.path().join("codex-auth.json"))).unwrap();
    let state = CodexAuthState::new(
        CodexTokens {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            account_id: None,
        },
        Some("1".to_string()),
    );

    store.save(&state).unwrap();
    let loaded = store.load().unwrap();

    assert_eq!(loaded.tokens.access_token, "access");
    assert_eq!(loaded.tokens.refresh_token, "refresh");
    assert_eq!(loaded.last_refresh.as_deref(), Some("1"));
}

#[test]
fn import_codex_cli_auth_extracts_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("codex-cli-auth.json");
    fs::write(
        &source_path,
        serde_json::to_vec(&serde_json::json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": "ignored",
                "access_token": "access",
                "refresh_token": "refresh",
                "account_id": "acct-1"
            },
            "last_refresh": "123"
        }))
        .unwrap(),
    )
    .unwrap();

    let target_path = dir.path().join("hellas-codex-auth.json");
    import_codex_cli(Some(&target_path), Some(&source_path)).unwrap();
    let loaded = CodexAuthStore::new(Some(&target_path))
        .unwrap()
        .load()
        .unwrap();

    assert_eq!(loaded.tokens.access_token, "access");
    assert_eq!(loaded.tokens.refresh_token, "refresh");
    assert_eq!(loaded.tokens.account_id.as_deref(), Some("acct-1"));
    assert_eq!(loaded.last_refresh.as_deref(), Some("123"));
}

#[test]
fn v1_auth_state_without_account_id_remains_loadable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("codex-auth.json");
    fs::write(
        &path,
        br#"{"version":1,"tokens":{"access_token":"access","refresh_token":"refresh"},"last_refresh":null,"refresh_token_blocked":null}"#,
    )
    .unwrap();
    let store = CodexAuthStore::new(Some(&path)).unwrap();
    assert_eq!(store.load().unwrap().tokens.account_id, None);
    assert!(matches!(
        store.account_id(),
        Err(CodexAuthError::MissingAccountId)
    ));
}

#[test]
fn import_rejects_invalid_account_ids() {
    for account_id in [
        JsonValue::String(String::new()),
        JsonValue::String("account\r\nsmuggle".to_string()),
        JsonValue::String("x".repeat(MAX_ACCOUNT_ID_BYTES + 1)),
        JsonValue::Number(1.into()),
    ] {
        let value = serde_json::json!({
            "tokens": {
                "access_token": "access",
                "refresh_token": "refresh",
                "account_id": account_id,
            }
        });
        assert!(matches!(
            tokens_from_codex_cli_json(&value),
            Err(CodexAuthError::InvalidAccountId)
        ));
    }
}

#[tokio::test]
async fn refresh_rotates_tokens() {
    #[derive(Clone)]
    struct Capture(Arc<tokio::sync::Mutex<Option<String>>>);

    async fn token(State(capture): State<Capture>, body: String) -> axum::Json<JsonValue> {
        *capture.0.lock().await = Some(body);
        axum::Json(json!({
            "access_token": "new.access.token",
            "refresh_token": "new-refresh"
        }))
    }

    let capture = Capture(Arc::new(tokio::sync::Mutex::new(None)));
    let app = Router::new()
        .route("/token", post(token))
        .with_state(capture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: Some("acct-1".to_string()),
            },
            None,
        ))
        .unwrap();

    let access = store.access_token().await.unwrap();
    assert_eq!(access, "new.access.token");
    assert_eq!(
        store.load().unwrap().tokens.account_id.as_deref(),
        Some("acct-1")
    );
    let body = capture.0.lock().await.clone().unwrap();
    assert!(body.contains("grant_type=refresh_token"));
    assert!(body.contains("refresh_token=old-refresh"));
    assert!(body.contains("client_id=app_EMoamEEZ73f0CkXaXp7hrann"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_refreshes_do_not_block_the_async_runtime_or_rotate_twice() {
    #[derive(Clone)]
    struct RefreshState {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        access_token: String,
        started: Arc<tokio::sync::Notify>,
        finish: Arc<tokio::sync::Semaphore>,
    }

    async fn token(State(state): State<RefreshState>) -> axum::Json<JsonValue> {
        state
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        state.started.notify_one();
        let _finish = state.finish.acquire().await.unwrap();
        axum::Json(json!({
            "access_token": state.access_token,
            "refresh_token": "new-refresh"
        }))
    }

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
    let access_token = format!("header.{payload}.signature");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let finish = Arc::new(tokio::sync::Semaphore::new(0));
    let app = Router::new()
        .route("/token", post(token))
        .with_state(RefreshState {
            calls: Arc::clone(&calls),
            access_token: access_token.clone(),
            started: started.clone(),
            finish: finish.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: None,
            },
            None,
        ))
        .unwrap();

    let ready = Arc::new(tokio::sync::Barrier::new(17));
    let refreshes: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            let ready = ready.clone();
            tokio::spawn(async move {
                ready.wait().await;
                store.access_token().await
            })
        })
        .collect();
    ready.wait().await;
    // Probe runtime progress while a refresh holds the file lock. Finishing
    // all sixteen reads and the durable token write is not a liveness clock.
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("file-lock contention must not block Tokio workers");
    finish.add_permits(1);
    let tokens = futures::future::join_all(refreshes).await;
    assert!(
        tokens
            .into_iter()
            .all(|token| matches!(token, Ok(Ok(token)) if token == access_token))
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_refresh_error_blocks_token() {
    async fn token() -> (axum::http::StatusCode, axum::Json<JsonValue>) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({"error":"invalid_grant"})),
        )
    }

    let app = Router::new().route("/token", post(token));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: None,
            },
            None,
        ))
        .unwrap();

    assert!(store.access_token().await.is_err());
    assert!(store.load().unwrap().refresh_token_blocked.is_some());
}

#[tokio::test]
async fn refresh_errors_never_return_or_persist_upstream_content() {
    async fn token() -> (axum::http::StatusCode, axum::Json<JsonValue>) {
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": {
                    "code": "invalid_grant",
                    "message": format!("PRIVATE_REFRESH_CANARY{}", "x".repeat(4_096)),
                }
            })),
        )
    }

    let app = Router::new().route("/token", post(token));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: None,
            },
            None,
        ))
        .unwrap();

    let error = store.access_token().await.unwrap_err().to_string();
    assert!(!error.contains("PRIVATE_REFRESH_CANARY"), "{error}");
    let blocked = store
        .load()
        .unwrap()
        .refresh_token_blocked
        .expect("terminal error is persisted");
    assert!(blocked.message.len() < 256);
    assert!(!blocked.message.contains("PRIVATE_REFRESH_CANARY"));
    // A stored reason from an older writer is not safe diagnostic input either.
    let mut state = store.load().unwrap();
    state.refresh_token_blocked.as_mut().unwrap().message = "PRIVATE_REFRESH_CANARY".into();
    store.save(&state).unwrap();
    let repeated = store.access_token().await.unwrap_err().to_string();
    assert!(!repeated.contains("PRIVATE_REFRESH_CANARY"));
}

#[tokio::test]
async fn oversized_refresh_body_is_retryable_and_never_persisted() {
    async fn token() -> String {
        "x".repeat(MAX_REFRESH_RESPONSE_BYTES + 1)
    }

    let app = Router::new().route("/token", post(token));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: None,
            },
            None,
        ))
        .unwrap();

    let error = store.access_token().await.unwrap_err().to_string();
    assert!(error.contains("response body exceeds"), "{error}");
    assert!(store.load().unwrap().refresh_token_blocked.is_none());
}

#[tokio::test]
async fn malformed_refresh_success_is_retryable() {
    async fn token() -> axum::Json<JsonValue> {
        axum::Json(json!({"refresh_token":"new-refresh"}))
    }

    let app = Router::new().route("/token", post(token));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let store = CodexAuthStore::with_token_url(
        dir.path().join("codex-auth.json"),
        Url::parse(&format!("http://{addr}/token")).unwrap(),
    );
    store
        .save(&CodexAuthState::new(
            CodexTokens {
                access_token: "expired".to_string(),
                refresh_token: "old-refresh".to_string(),
                account_id: None,
            },
            None,
        ))
        .unwrap();

    assert!(store.access_token().await.is_err());
    assert!(store.load().unwrap().refresh_token_blocked.is_none());
}
