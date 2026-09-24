use super::*;

#[test]
fn account_backoff_is_shared_and_never_shortened_by_another_response() {
    let account = Arc::new(Account {
        slots: Arc::new(Semaphore::new(1)),
        retry_at: Mutex::new(Instant::now()),
    });
    let other_route = account.clone();
    let header = |seconds: &'static str| {
        HeaderMap::from_iter([(
            "retry-after".parse().unwrap(),
            HeaderValue::from_static(seconds),
        )])
    };
    account.observe(429, &header("60"));
    assert!(other_route.delay() > Duration::from_secs(59));
    other_route.observe(429, &header("1"));
    assert!(account.delay() > Duration::from_secs(59));
    other_route.observe(503, &header("120"));
    assert!(account.delay() > Duration::from_secs(119));
    account.observe(200, &header("600"));
    assert!(account.delay() < Duration::from_secs(121));
    let permit = account.slots.clone().try_acquire_owned().unwrap();
    assert!(other_route.slots.clone().try_acquire_owned().is_err());
    drop(permit);
    assert!(other_route.slots.clone().try_acquire_owned().is_ok());
}

#[test]
fn forward_only_protocol_headers_and_keep_retry_and_quota_metadata() {
    let route = HttpRoute {
        path: "/v1/messages".into(),
        method: "POST".into(),
        url: "https://api.example.com/v1/messages".into(),
        credential: "account".into(),
        headers: vec![("anthropic-version".into(), "2023-06-01".into())],
        forward_headers: vec!["content-type".into(), "anthropic-version".into()],
    };
    let incoming = HeaderMap::from_iter([
        (
            "authorization".parse().unwrap(),
            HeaderValue::from_static("Bearer BUYER"),
        ),
        (
            "x-api-key".parse().unwrap(),
            HeaderValue::from_static("BUYER"),
        ),
        (
            "content-type".parse().unwrap(),
            HeaderValue::from_static("application/json"),
        ),
        (
            "anthropic-version".parse().unwrap(),
            HeaderValue::from_static("override"),
        ),
    ]);
    let request = route.request(Bytes::from_static(b"{\"private\":1}"), &incoming);
    assert_eq!(request.body().unwrap(), b"{\"private\":1}");
    assert_eq!(
        request.headers,
        vec![
            ("anthropic-version".into(), "2023-06-01".into()),
            ("content-type".into(), "application/json".into())
        ]
    );
    let response = response_headers(vec![
        ("retry-after".into(), "3".into()),
        ("x-ratelimit-remaining-tokens".into(), "0".into()),
        ("content-length".into(), "1234".into()),
        ("set-cookie".into(), "secret".into()),
        ("connection".into(), "keep-alive".into()),
        ("content-type".into(), "text/event-stream".into()),
    ]);
    assert_eq!(response.len(), 3);
    assert_eq!(response["retry-after"], "3");
    assert_eq!(response["x-ratelimit-remaining-tokens"], "0");
    assert_eq!(retry_delay(&response), Duration::from_secs(3));
}

#[test]
fn retry_after_supports_dates_and_has_a_nonzero_fallback() {
    assert_eq!(retry_delay(&HeaderMap::new()), Duration::from_secs(1));
    for value in ["invalid", "0", "-2"] {
        let headers =
            HeaderMap::from_iter([("retry-after".parse().unwrap(), value.parse().unwrap())]);
        assert_eq!(retry_delay(&headers), Duration::from_secs(1));
    }
    let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(60));
    let headers = HeaderMap::from_iter([("retry-after".parse().unwrap(), date.parse().unwrap())]);
    assert!((59..=60).contains(&retry_delay(&headers).as_secs()));
}

#[test]
fn credential_and_hop_headers_cannot_be_added_to_the_forward_list() {
    for name in ["authorization", "x-api-key", "cookie", "host", "connection"] {
        let config = HttpGatewayConfig {
            service: "http".into(),
            method: "request".into(),
            max_in_flight: 2,
            routes: vec![HttpRoute {
                path: "/v1/messages".into(),
                method: "POST".into(),
                url: "https://example.com/v1/messages".into(),
                credential: "account".into(),
                headers: vec![],
                forward_headers: vec![name.into()],
            }],
        };
        assert!(config.validate().is_err());
    }
}
