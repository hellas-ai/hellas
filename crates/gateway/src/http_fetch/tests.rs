use super::config::{HttpRoute, public_tls};
use super::routing::retry_delay;
use super::*;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

#[test]
fn forward_only_protocol_headers_and_keep_retry_and_quota_metadata() {
    let route = HttpRoute {
        path: "/v1/messages".into(),
        method: "POST".into(),
        url: "https://api.example.com/v1/messages".into(),
        credential: Some("account".into()),
        tls: public_tls(),
        headers: vec![("anthropic-version".into(), "2023-06-01".into())],
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
    let request = route
        .request(Bytes::from_static(b"{\"private\":1}"), &incoming)
        .unwrap();
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
fn credentials_and_hop_headers_cannot_be_configured_as_static_headers() {
    for name in ["authorization", "x-api-key", "cookie", "host", "connection"] {
        let config = HttpGatewayConfig {
            service: "http".into(),
            method: "request".into(),
            max_in_flight: 2,
            backends: BTreeMap::new(),
            routes: vec![HttpRoute {
                path: "/v1/messages".into(),
                method: "POST".into(),
                url: "https://example.com/v1/messages".into(),
                credential: Some("account".into()),
                tls: public_tls(),
                headers: vec![(name.into(), "secret".into())],
            }],
        };
        assert!(config.validate().is_err());
    }
}

#[test]
fn extension_headers_and_duplicates_survive_but_connection_tokens_do_not() {
    let route: HttpRoute = serde_json::from_value(serde_json::json!({
        "path":"/v1/chat/completions", "method":"POST", "url":"https://example.com/v1/chat/completions"
    })).unwrap();
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("idempotency-key", "key"),
        ("x-stainless-retry-count", "0"),
        ("content-encoding", "gzip"),
        ("connection", "X-Private-Hop"),
        ("x-private-hop", "secret"),
        ("x-beta", "one"),
        ("x-beta", "two"),
        ("x-hellas-zdr", "true"),
        ("cookie", "secret"),
    ] {
        headers.append(name, value.parse().unwrap());
    }
    let request = route.request(Bytes::new(), &headers).unwrap();
    assert_eq!(request.headers.len(), 5);
    assert_eq!(
        request
            .headers
            .iter()
            .filter(|(n, _)| n == "x-beta")
            .count(),
        2
    );
    assert!(!request.headers.iter().any(|(name, _)| {
        ["connection", "x-private-hop", "cookie", "x-hellas-zdr"].contains(&name.as_str())
    }));
    let response = response_headers(vec![
        ("connection".into(), "X-Private-Hop".into()),
        ("x-private-hop".into(), "secret".into()),
        ("location".into(), "/next".into()),
        ("etag".into(), "v1".into()),
    ]);
    assert_eq!(response.len(), 2);
    assert_eq!(response["location"], "/next");
}
