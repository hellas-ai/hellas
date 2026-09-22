use super::*;
use axum::Router;
use axum::routing::get;
use std::sync::Mutex;
use tower::ServiceExt;

/// A bearer with a known token, so tests can present the right one.
fn fixed_bearer() -> (Arc<Bearer>, String) {
    let mut token = [0u8; TOKEN_BYTES];
    for (index, byte) in token.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let hex = encode_hex(&token);
    (Arc::new(Bearer { token }), hex)
}

fn guarded_router(bearer: Arc<Bearer>) -> Router {
    Router::new()
        .route("/v1/chat/completions", get(|| async { "reached" }))
        .layer(BearerLayer::new(bearer))
}

async fn status_of(router: &Router, request: Request<Body>) -> StatusCode {
    router.clone().oneshot(request).await.unwrap().status()
}

fn get_request(uri: &str) -> axum::http::request::Builder {
    Request::builder().method("GET").uri(uri)
}

#[tokio::test]
async fn missing_header_is_refused() {
    let (bearer, _) = fixed_bearer();
    let router = guarded_router(bearer);
    let request = get_request("/v1/chat/completions")
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_value_is_refused() {
    let (bearer, hex) = fixed_bearer();
    let router = guarded_router(bearer);
    // Same length, one nibble different.
    let mut wrong = hex.clone();
    wrong.replace_range(0..1, "f");
    assert_eq!(wrong.len(), hex.len());
    let request = get_request("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer {wrong}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_length_is_refused() {
    let (bearer, hex) = fixed_bearer();
    let router = guarded_router(bearer);
    for credential in [
        String::new(),
        hex[..TOKEN_HEX_LEN - 1].to_string(),
        format!("{hex}0"),
        hex.repeat(3),
    ] {
        let request = get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            status_of(&router, request).await,
            StatusCode::UNAUTHORIZED,
            "a {}-character credential was accepted",
            credential.len()
        );
    }
}

#[tokio::test]
async fn right_token_in_a_query_parameter_is_refused() {
    let (bearer, hex) = fixed_bearer();
    let router = guarded_router(bearer);
    for uri in [
        format!("/v1/chat/completions?access_token={hex}"),
        format!("/v1/chat/completions?authorization=Bearer%20{hex}"),
    ] {
        let request = get_request(&uri).body(Body::empty()).unwrap();
        assert_eq!(
            status_of(&router, request).await,
            StatusCode::UNAUTHORIZED,
            "a credential in the query string was accepted: {uri}"
        );
    }
}

#[tokio::test]
async fn right_token_in_another_header_is_refused() {
    let (bearer, hex) = fixed_bearer();
    let router = guarded_router(bearer);
    for name in ["x-api-key", "x-hellas-authorization", "proxy-authorization"] {
        let request = get_request("/v1/chat/completions")
            .header(name, format!("Bearer {hex}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            status_of(&router, request).await,
            StatusCode::UNAUTHORIZED,
            "a credential in `{name}` was accepted"
        );
    }
    // And a cookie carrying it is no better.
    let request = get_request("/v1/chat/completions")
        .header(header::COOKIE, format!("authorization=Bearer {hex}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(status_of(&router, request).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn correct_authorization_bearer_is_accepted() {
    let (bearer, hex) = fixed_bearer();
    let router = guarded_router(bearer);
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let request = get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("{scheme} {hex}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            status_of(&router, request).await,
            StatusCode::OK,
            "`{scheme}` with the run's credential was refused"
        );
    }
}

/// The clause is about work, and work is what this asserts: every
/// input length costs the same number of digit steps. This is a
/// shape assertion, not a timing measurement — a wall-clock test
/// would be flaky — but it is the shape the clause is about, because
/// an early `len() !=` return is precisely what would make the counts
/// differ.
#[test]
fn compare_does_not_short_circuit_on_length() {
    let (bearer, hex) = fixed_bearer();
    let mut counts = Vec::new();
    for credential in [
        String::new(),
        "0".to_string(),
        hex[..TOKEN_HEX_LEN - 1].to_string(),
        hex.clone(),
        format!("{hex}{hex}"),
        "z".repeat(4096),
    ] {
        DIGIT_STEPS.set(0);
        let _ = bearer.accepts(credential.as_bytes());
        counts.push(DIGIT_STEPS.get());
    }
    assert!(
        counts.iter().all(|count| *count == TOKEN_HEX_LEN),
        "digit steps varied with the credential's length: {counts:?}"
    );
}

/// Records everything any `tracing` subscriber would be handed, so
/// the "never logged" clause is asserted rather than merely intended.
#[derive(Clone, Default)]
struct Recorder {
    lines: Arc<Mutex<Vec<String>>>,
}

struct Collect(String);

impl tracing::field::Visit for Collect {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        use fmt::Write;
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl Recorder {
    fn push(&self, metadata: &tracing::Metadata<'_>, collected: Collect) {
        self.lines.lock().unwrap().push(format!(
            "{} {} {}",
            metadata.target(),
            metadata.name(),
            collected.0
        ));
    }

    fn captured(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

impl tracing::Subscriber for Recorder {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    /// `sometimes`, not the default `always`/`never`, because the
    /// interest cache is global while this subscriber is only the
    /// default on one thread. Cached as `never` by a sibling test
    /// running without a subscriber, the callsite would go quiet and
    /// this test would pass over a credential it never saw.
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut collected = Collect(String::new());
        span.record(&mut collected);
        self.push(span.metadata(), collected);
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut collected = Collect(String::new());
        values.record(&mut collected);
        self.lines.lock().unwrap().push(collected.0);
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut collected = Collect(String::new());
        event.record(&mut collected);
        self.push(event.metadata(), collected);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

#[tokio::test]
async fn credential_reaches_no_trace_no_error_body_and_no_debug() {
    let (bearer, hex) = fixed_bearer();

    // `{:?}` is the way a secret usually escapes: a struct holding it
    // is logged whole. This one cannot be.
    assert_eq!(format!("{bearer:?}"), "Bearer(redacted)");
    assert!(!format!("{bearer:?}").contains(&hex));

    let recorder = Recorder::default();
    let guard = tracing::subscriber::set_default(recorder.clone());
    // Drop whatever interest a sibling test's no-op subscriber cached,
    // so these callsites are re-asked and reach the recorder.
    tracing::callsite::rebuild_interest_cache();
    let router = guarded_router(bearer.clone());

    // Every path: accepted, refused for each reason, and the
    // announcement (which finds no tty under `cargo test`).
    let mut bodies = Vec::new();
    let requests = vec![
        get_request("/v1/chat/completions")
            .body(Body::empty())
            .unwrap(),
        get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {hex}"))
            .body(Body::empty())
            .unwrap(),
        get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, format!("Bearer {hex}extra"))
            .body(Body::empty())
            .unwrap(),
        get_request("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer deadbeef")
            .body(Body::empty())
            .unwrap(),
        get_request(&format!("/v1/chat/completions?access_token={hex}"))
            .body(Body::empty())
            .unwrap(),
        get_request("/v1/chat/completions")
            .header("x-api-key", format!("Bearer {hex}"))
            .body(Body::empty())
            .unwrap(),
    ];
    for request in requests {
        let response = router.clone().oneshot(request).await.unwrap();
        let headers = format!("{:?}", response.headers());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        bodies.push(headers);
        bodies.push(String::from_utf8_lossy(&body).into_owned());
    }
    bearer.announce();
    drop(guard);

    for line in recorder.captured() {
        assert!(
            !line.contains(&hex),
            "the run's credential reached a trace event: {line}"
        );
    }
    for body in bodies {
        assert!(
            !body.contains(&hex),
            "the run's credential was echoed back to the caller: {body}"
        );
    }
}

#[tokio::test]
async fn loopback_is_decided_by_parsing_not_by_spelling() {
    // `127.0.0.2` is loopback and is not the string `127.0.0.1`, so
    // only a parsed check accepts it.
    for host in ["127.0.0.1", "127.0.0.2", "::1"] {
        let addr = bind_addr(host, 0, false)
            .await
            .unwrap_or_else(|err| panic!("`{host}` should be loopback: {err}"));
        assert!(addr.ip().is_loopback());
    }
}

#[tokio::test]
async fn explicitly_configured_network_bind_is_resolved() {
    let addr = bind_addr("192.0.2.1", 8080, true).await.unwrap();
    assert_eq!(addr, "192.0.2.1:8080".parse().unwrap());
}

#[tokio::test]
async fn non_loopback_requires_explicit_remote_access() {
    for host in ["0.0.0.0", "192.0.2.1", "::"] {
        assert!(bind_addr(host, 8080, false).await.is_err());
    }
}
