use super::*;
use hellas_auth::Digest;
use hellas_executor::{FetchCall, MockFetchProvider};
use hellas_rpc::{InputCommitment, JsonBytes};
use std::sync::atomic::{AtomicU64, Ordering};
struct Fixture {
    _dir: tempfile::TempDir,
    config: AccountConfig,
    used: Arc<AtomicU64>,
    _task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self._task.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let used = Arc::new(AtomicU64::new(0));
        let state = used.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/metrics", listener.local_addr().unwrap());
        let app = axum::Router::new().route("/metrics", axum::routing::get(move || { let state = state.clone(); async move {
            let used = state.load(Ordering::SeqCst);
            format!("llm_account_info{{provider=\"test\",upstream=\"openai\",account=\"personal\"}} 1\nllm_quota_data_fresh{{provider=\"test\"}} 1\nllm_quota_scrape_success{{provider=\"test\"}} 1\nllm_quota_last_success_timestamp_seconds{{provider=\"test\"}} {}\nllm_quota_utilization_ratio{{provider=\"test\",scope=\"all\",window=\"seven_day\"}} {}\n", now().unwrap(), used)
        }}));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _dir: dir,
            config: AccountConfig {
                ledger: PathBuf::new(),
                window_seconds: 60,
                max_requests: 3,
                max_tokens: 10000,
                max_concurrency: 1,
                max_request_bytes: 1000,
                max_output_tokens: 100,
                accounting: AccountingProfile::OpenaiResponses,
                quota: QuotaSource {
                    url,
                    provider: "test".into(),
                    upstream: "openai".into(),
                    account: "personal".into(),
                    max_age_seconds: 60,
                    reserve: Reserve::RemainingRatio {
                        minimum: 0.2,
                        scope: "all".into(),
                        windows: vec!["seven_day".into()],
                    },
                },
            },
            used,
            _task: task,
        }
        .with_path()
    }
    fn with_path(mut self) -> Self {
        self.config.ledger = self._dir.path().join("ledger.sqlite");
        self
    }
    fn account(&self) -> Arc<AccountLimiter> {
        AccountRegistry::new(&BTreeMap::from([("personal".into(), self.config.clone())]))
            .unwrap()
            .accounts
            .remove("personal")
            .unwrap()
    }
}
#[tokio::test]
async fn concurrency_cancel_and_restart_retain_durable_window() {
    let mut fixture = Fixture::new().await;
    fixture.config.max_requests = 1;
    let account = fixture.account();
    let reservation = account.reserve(100).await.unwrap();
    assert!(
        account
            .reserve(100)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("concurrency")
    );
    drop(reservation); // no usage: full conservative charge
    assert!(
        account
            .reserve(100)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("window")
    );
    let pool = account.ledger().await.unwrap().pool.clone();
    pool.close().await;
    drop(pool);
    drop(account);
    let account = fixture.account();
    assert!(
        account
            .reserve(100)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("window")
    );
    sqlx::query("UPDATE calls SET at=at-61")
        .execute(&account.ledger().await.unwrap().pool)
        .await
        .unwrap();
    assert!(account.reserve(100).await.is_ok());
}
#[tokio::test]
async fn token_window_charges_full_cap_without_refunds() {
    let mut fixture = Fixture::new().await;
    fixture.config.max_tokens = 100;
    let account = fixture.account();
    drop(account.reserve(80).await.unwrap());
    assert!(account.reserve(21).await.is_err());
    drop(account.reserve(20).await.unwrap());
    assert!(account.reserve(1).await.is_err());
}
fn request() -> PreparedFetchRequest {
    let call = FetchCall::new(
        "codex",
        "responses",
        JsonBytes::new(br#"{"model":"test","input":"hello","max_output_tokens":8}"#.to_vec()),
        None,
        InputCommitment::from_digest(Digest::from_bytes([1; 32])),
    );
    PreparedFetchRequest::new(&call, call.body.clone())
}
#[tokio::test]
async fn reserve_refusal_and_bad_requests_never_reach_upstream() {
    let fixture = Fixture::new().await;
    let registry = AccountRegistry::new(&BTreeMap::from([(
        "personal".into(),
        fixture.config.clone(),
    )]))
    .unwrap();
    let environment = hellas_rpc::FetchContract::http().unwrap().manifest_id();
    let raw = Arc::new(MockFetchProvider::new(environment));
    let request = request();
    raw.insert(
        "codex",
        "responses",
        request.body.as_bytes(),
        [b"data".to_vec()],
    );
    let provider = registry
        .bind(raw.clone(), Some("personal"), &BTreeMap::new(), false)
        .unwrap();
    fixture.used.store(1, Ordering::SeqCst);
    assert!(provider.run(request.clone()).await.is_err());
    assert_eq!(raw.calls("codex", "responses", request.body.as_bytes()), 0);
    fixture.used.store(0, Ordering::SeqCst);
    let response = provider.run(request.clone()).await.unwrap();
    assert_eq!(raw.calls("codex", "responses", request.body.as_bytes()), 1);
    assert!(provider.run(request.clone()).await.is_err());
    drop(response); // unpolled stream must release concurrency
    assert!(provider.run(request).await.is_ok());
}
#[tokio::test]
async fn aliases_and_separate_dispatchers_share_one_account_window() {
    let mut fixture = Fixture::new().await;
    fixture.config.max_requests = 1;
    let registry = AccountRegistry::new(&BTreeMap::from([(
        "personal".into(),
        fixture.config.clone(),
    )]))
    .unwrap();
    let raw = Arc::new(MockFetchProvider::new(
        hellas_rpc::FetchContract::http().unwrap().manifest_id(),
    ));
    let aliases = BTreeMap::from([
        ("one".into(), "personal".into()),
        ("two".into(), "personal".into()),
    ]);
    let first = registry.bind(raw.clone(), None, &aliases, true).unwrap();
    let second = registry.bind(raw.clone(), None, &aliases, true).unwrap();
    let request = |alias| {
        let request = hellas_rpc::http_fetch::HttpFetchRequest {
            url: "https://example.test/health".into(),
            method: "GET".into(),
            headers: vec![],
            body_base64: String::new(),
            credential: Some(alias),
            max_response_bytes: 1024,
            tls: hellas_rpc::http_fetch::HttpTls {
                roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
        };
        let call = FetchCall::new(
            "custom",
            "get",
            JsonBytes::new(serde_json::to_vec(&request).unwrap()),
            None,
            InputCommitment::from_digest(Digest::from_bytes([2; 32])),
        );
        PreparedFetchRequest::new(&call, call.body.clone())
    };
    let one = request("one".into());
    let two = request("two".into());
    raw.insert("custom", "get", one.body.as_bytes(), [b"ok".to_vec()]);
    drop(first.run(one.clone()).await.unwrap());
    assert!(second.run(two.clone()).await.is_err());
    assert_eq!(raw.calls("custom", "get", one.body.as_bytes()), 1);
    assert_eq!(raw.calls("custom", "get", two.body.as_bytes()), 0);
    assert!(
        fixture
            .account()
            .reserve(1)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("already in use")
    );
    assert!(
        AccountRegistry::new(&BTreeMap::from([
            ("one".into(), fixture.config.clone()),
            ("two".into(), fixture.config.clone())
        ]))
        .is_err()
    );
}

#[tokio::test]
async fn request_caps_are_bounded_and_unambiguous() {
    let fixture = Fixture::new().await;
    assert_eq!(
        request_reservation(br#"{"max_output_tokens":8}"#, &fixture.config).unwrap(),
        8
    );
    let mut chat = fixture.config.clone();
    chat.accounting = AccountingProfile::OpenaiChat;
    assert_eq!(
        request_reservation(br#"{"max_tokens":8,"stream":true}"#, &chat).unwrap(),
        8
    );
    for body in [
        br#"{"max_output_tokens":8,"max_tokens":8}"#.as_slice(),
        br#"{"max_tokens":0}"#,
        br#"{"max_tokens":9,"n":2}"#,
        br#"{"max_tokens":9,"max_tokens":8}"#,
        br#"{"max_tokens":101}"#,
    ] {
        assert!(request_reservation(body, &fixture.config).is_err());
    }
}
