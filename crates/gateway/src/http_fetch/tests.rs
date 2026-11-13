use super::config::{HttpRoute, public_tls};
use super::*;
use crate::WorkExecutionBackend;
use hellas_rpc::provenance::ExecutionProvenance;
use std::time::Duration;

#[tokio::test]
async fn http_uses_the_paid_backend_and_waits_for_its_payment_completion() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Paid {
        requests: AtomicUsize,
        drained: AtomicBool,
        ack: Arc<tokio::sync::Notify>,

        busy: bool,
    }
    impl WorkExecutionBackend for Paid {
        fn backends(&self) -> Vec<crate::BackendInfo> {
            crate::test_support::backend(None)
        }

        fn run(
            &self,
            _backend: &str,
            _request_job: Arc<crate::jobs::Job>,
            _: hellas_client::model::ComputeJob,
        ) -> Result<crate::WorkOutputStream<crate::ComputeEvent>, crate::WorkGatewayError> {
            unreachable!("HTTP must use Fetch")
        }
        fn fetch(
            &self,
            _backend: &str,
            _request_job: Arc<crate::jobs::Job>,
            request: WorkFetchRequest,
        ) -> Result<crate::WorkFetchStream, crate::WorkGatewayError> {
            self.requests.fetch_add(1, Ordering::Relaxed);

            assert_eq!((&*request.service, &*request.method), ("http", "request"));
            let http = hellas_rpc::http_fetch::HttpFetchRequest::decode(&request.body).unwrap();
            assert_eq!(http.url, "https://example.com/v1/responses?x=%2F&x=y");
            assert_eq!(http.body().unwrap(), b"opaque request");
            assert!(
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .unwrap()
                    .get("credential")
                    .is_none()
            );
            if self.busy {
                return Err(crate::WorkGatewayBusy.into());
            }
            let ack = self.ack.clone();
            Ok(Box::pin(async_stream::try_stream! {
                yield WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                    status: 200, headers: vec![("content-type".into(), "application/octet-stream".into())],
                })));
                yield WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64: "AP8K".into() })));
                ack.notified().await;
                yield WorkEvent::Output(OutputEvent::Finished { stop_reason: StopReason::EndOfText, usage: None });
            }))
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async {
                self.drained.store(true, Ordering::Relaxed);
                Ok(())
            })
        }
    }
    for busy in [false, true] {
        let paid = Arc::new(Paid {
            requests: AtomicUsize::new(0),
            drained: AtomicBool::new(false),
            ack: Arc::default(),
            busy,
        });
        let config = vec![http("/v1/responses", None)];
        let archive = tempfile::tempdir().unwrap();
        let fixture = crate::access::tests::Fixture::new().await;
        let handle = crate::test_support::server::serve(
            fixture.access.node(),
            fixture.access.bearer(),
            crate::ArchiveOptions {
                directory: archive.path().into(),
                zdr: true,
            },
            paid.clone(),
            Arc::new(crate::jobs::Jobs::default()),
            config,
        )
        .await
        .unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{}/v1/responses?x=%2F&x=y", handle.address());
        assert_eq!(
            client
                .post(&url)
                .body("opaque request")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(paid.requests.load(Ordering::Relaxed), 0);
        let response = client
            .post(&url)
            .bearer_auth(handle.bearer())
            .body("opaque request")
            .send()
            .await
            .unwrap();
        assert_eq!(paid.requests.load(Ordering::Relaxed), 1);
        if busy {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        } else {
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.bytes_stream();
            assert_eq!(body.next().await.unwrap().unwrap(), &b"\x00\xff\n"[..]);
            assert!(
                tokio::time::timeout(Duration::from_millis(20), body.next())
                    .await
                    .is_err()
            );
            paid.ack.notify_one();
            assert!(body.next().await.is_none());
        }
        handle.shutdown().await.unwrap();
        assert!(paid.drained.load(Ordering::Relaxed));
        assert_eq!(std::fs::read_dir(archive.path()).unwrap().count(), 0);
    }
}

#[test]
fn forward_only_protocol_headers_and_keep_retry_and_quota_metadata() {
    let route = HttpRoute {
        max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
        path: "/v1/messages".into(),
        method: "POST".into(),
        url: "https://api.example.com/v1/messages".into(),
        tls: public_tls(),
        headers: vec![("anthropic-version".into(), "2023-06-01".into())],
        models: None,
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
}

#[test]
fn credentials_and_hop_headers_cannot_be_configured_as_static_headers() {
    for name in hellas_rpc::http_fetch::CREDENTIAL_HEADERS
        .iter()
        .copied()
        .chain(["host", "connection"])
    {
        let config = HttpRoute {
            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
            path: "/v1/messages".into(),
            method: "POST".into(),
            url: "https://example.com/v1/messages".into(),
            tls: public_tls(),
            headers: vec![(name.into(), "secret".into())],
            models: None,
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

struct Proxied {
    status: u16,
    body: Option<&'static str>,
    transcript: Vec<u8>,
}

impl WorkExecutionBackend for Proxied {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend(None)
    }

    fn fetch(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        _: WorkFetchRequest,
    ) -> Result<crate::WorkFetchStream, crate::WorkGatewayError> {
        let mut events = vec![
            WorkEvent::Accepted(ExecutionProvenance {
                commitment_id: [0x7c; 32],
                provider: hellas_auth::PublicKey::Secp256k1([0x02; 33]),
            }),
            WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
                HttpResponseEvent::Head {
                    status: self.status,
                    // A provider cannot speak for the gateway.
                    headers: vec![("x-hellas-provider".into(), "forged".into())],
                },
            ))),
        ];
        if let Some(body) = self.body {
            events.push(WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(
                HttpResponseEvent::Body {
                    base64: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        body,
                    ),
                },
            ))));
        }
        events.push(WorkEvent::Transcript(self.transcript.clone()));
        events.push(WorkEvent::Output(OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        }));
        Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

/// The raw HTTP/1.1 exchange, so the wire shows where each value travels.
async fn exchange(address: std::net::SocketAddr, bearer: &str) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = "opaque request";
    socket
        .write_all(
            format!(
                "POST /v1/responses HTTP/1.1\r\nhost: gateway\r\nauthorization: Bearer {bearer}\r\n\
                 te: trailers\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

/// A gateway serving the HTTP Fetch presentation, with archiving enabled so
/// trailers must pass through it too. The directory stays alive with the test.
async fn proxy(paid: Arc<Proxied>) -> (crate::test_support::server::Server, tempfile::TempDir) {
    let config = vec![http("/v1/responses", None)];
    let archive = tempfile::tempdir().unwrap();
    let fixture = crate::access::tests::Fixture::new().await;
    let handle = crate::test_support::server::serve(
        fixture.access.node(),
        fixture.access.bearer(),
        crate::ArchiveOptions {
            directory: archive.path().into(),
            zdr: false,
        },
        paid,
        Arc::new(crate::jobs::Jobs::default()),
        config,
    )
    .await
    .unwrap();
    (handle, archive)
}

/// Proxied HTTPS responses name the accepted job and its provider in their
/// head, and trail the body with the transcript that provider signed. A
/// bodyless response, whose head waits for completion, carries it as a header.
#[tokio::test]
async fn https_responses_carry_provenance_in_headers_and_the_transcript_in_trailers() {
    use base64::Engine as _;
    let transcript = b"provider-signed transcript".to_vec();
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transcript);
    let provider = format!("secp256k1:{}", "02".repeat(33));
    for (status, body) in [(200, Some("streamed body")), (204, None)] {
        let paid = Arc::new(Proxied {
            status,
            body,
            transcript: transcript.clone(),
        });
        let (handle, _archive) = proxy(paid).await;
        let wire = exchange(handle.address(), handle.bearer()).await;
        let (head, rest) = wire.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&format!("HTTP/1.1 {status}")), "{head}");
        assert!(
            head.contains(&format!(
                "\r\nx-hellas-commitment-bin: {}\r\n",
                "7c".repeat(32)
            )),
            "{head}"
        );
        assert!(
            head.contains(&format!("\r\nx-hellas-provider: {provider}\r\n")),
            "{head}"
        );
        assert!(!head.contains("forged"), "{head}");
        match body {
            Some(body) => {
                assert!(
                    head.contains(
                        "\r\ntrailer: x-hellas-transcript, x-hellas-transcript-digest\r\n"
                    ),
                    "{head}"
                );
                assert!(!head.contains("x-hellas-transcript:"), "{head}");
                assert!(rest.contains(body), "{rest}");
                assert!(
                    rest.ends_with(&format!("\r\n0\r\nx-hellas-transcript: {encoded}\r\n\r\n")),
                    "{rest:?}"
                );
            }
            None => {
                assert!(
                    head.contains(&format!("\r\nx-hellas-transcript: {encoded}\r\n")),
                    "{head}"
                );
                assert!(rest.is_empty(), "{rest:?}");
            }
        }
        handle.shutdown().await.unwrap();
    }
}

/// Evidence larger than the inline bound travels as its digest, so a
/// successful response remains consumable by clients with bounded trailers.
#[tokio::test]
async fn oversized_transcripts_are_named_by_digest_instead_of_inlined() {
    use hellas_rpc::provenance::{MAX_INLINE_TRANSCRIPT_BYTES, TRANSCRIPT_DIGEST_KEY, encode_hex};
    use sha2::Digest as _;
    let transcript = vec![b't'; MAX_INLINE_TRANSCRIPT_BYTES];
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&sha2::Sha256::digest(&transcript));
    let digest = encode_hex(&digest);
    for (status, body) in [(200, Some("streamed body")), (204, None)] {
        let paid = Arc::new(Proxied {
            status,
            body,
            transcript: transcript.clone(),
        });
        let (handle, _archive) = proxy(paid).await;
        let wire = exchange(handle.address(), handle.bearer()).await;
        let (head, rest) = wire.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with(&format!("HTTP/1.1 {status}")), "{head}");
        assert!(!head.contains("x-hellas-transcript:"), "{head}");
        match body {
            Some(_) => {
                assert!(
                    head.contains(
                        "\r\ntrailer: x-hellas-transcript, x-hellas-transcript-digest\r\n"
                    ),
                    "{head}"
                );
                assert!(
                    rest.ends_with(&format!(
                        "\r\n0\r\n{TRANSCRIPT_DIGEST_KEY}: {digest}\r\n\r\n"
                    )),
                    "{rest:?}"
                );
            }
            None => {
                assert!(
                    head.contains(&format!("\r\n{TRANSCRIPT_DIGEST_KEY}: {digest}\r\n")),
                    "{head}"
                );
                assert!(rest.is_empty(), "{rest:?}");
            }
        }
        handle.shutdown().await.unwrap();
    }
}

struct ContinuationBackend {
    calls: std::sync::atomic::AtomicUsize,
}
impl WorkExecutionBackend for ContinuationBackend {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend(None)
    }

    fn fetch(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        _: WorkFetchRequest,
    ) -> Result<crate::WorkFetchStream, crate::WorkGatewayError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::pin(async_stream::try_stream! {
            yield WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: 200, headers: vec![("content-type".into(), "application/json".into())],
            })));
            yield WorkEvent::Output(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body {
                base64: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, br#"{"id":"resp_1","object":"response"}"#),
            })));
            yield WorkEvent::Output(OutputEvent::Finished { stop_reason: StopReason::EndOfText, usage: None });
        }))
    }
    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn signed_single_route_registers_response_for_followup() {
    use tower::ServiceExt;
    let work = Arc::new(ContinuationBackend { calls: 0.into() });
    let config = vec![http("/v1/responses", Some(vec!["m".into()]))];
    let app = crate::router::router(
        config,
        work.clone(),
        Arc::new(crate::jobs::Jobs::default()),
        Default::default(),
    )
    .await
    .unwrap();
    for body in [
        r#"{"model":"m"}"#,
        r#"{"model":"m","previous_response_id":"resp_1"}"#,
    ] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::post("/v1/responses")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
    }
    assert_eq!(work.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn duplicate_session_header_never_discards_an_unknown_continuation() {
    use tower::ServiceExt;
    let work = Arc::new(ContinuationBackend { calls: 0.into() });
    let config = vec![
        http("/v1/responses", None),
        http("/v1/audio/transcriptions", None),
    ];
    let app = crate::router::router(
        config,
        work.clone(),
        Arc::new(crate::jobs::Jobs::default()),
        Default::default(),
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .header("x-hellas-session-id", "one")
                .header("x-hellas-session-id", "two")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"previous_response_id":"unknown"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(work.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"previous_response_id":"unknown"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(work.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    // Opaque multipart remains routable; invalid affinity metadata is still rejected.
    let multipart =
        "--audio\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nopaque\r\n--audio--\r\n";
    for (duplicate, expected) in [(true, StatusCode::BAD_REQUEST), (false, StatusCode::OK)] {
        let mut request = axum::http::Request::post("/v1/audio/transcriptions")
            .header("content-type", "multipart/form-data; boundary=audio");
        if duplicate {
            request = request
                .header("x-hellas-session-id", "one")
                .header("x-hellas-session-id", "two");
        }
        let response = app
            .clone()
            .oneshot(request.body(axum::body::Body::from(multipart)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(work.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let response = app
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .body(axum::body::Body::from("opaque request"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(work.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

fn http(path: &str, models: Option<Vec<String>>) -> crate::Route {
    crate::test_support::route(crate::Presentation::Http {
        targets: ["test"]
            .into_iter()
            .map(|id| {
                (
                    id.into(),
                    crate::HttpTarget {
                        service: "http".into(),
                        method: "request".into(),
                        route: HttpRoute {
                            path: path.into(),
                            method: "POST".into(),
                            url: format!("https://example.com{path}"),
                            tls: public_tls(),
                            headers: vec![],
                            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                            models: models.clone(),
                        },
                    },
                )
            })
            .collect(),
    })
}

#[tokio::test]
async fn failover_uses_each_backends_own_destination_without_caller_credentials() {
    use tower::ServiceExt;
    struct Targets(std::sync::Mutex<Vec<String>>);
    impl crate::WorkExecutionBackend for Targets {
        fn backends(&self) -> Vec<crate::BackendInfo> {
            ["first", "second"]
                .map(|id| crate::BackendInfo {
                    instance: 1,
                    id: id.into(),
                    evaluator: None,
                    max_in_flight: 2,
                    in_flight: 0,
                    down: false,
                    error: None,
                })
                .into()
        }
        fn fetch(
            &self,
            id: &str,
            job: Arc<crate::jobs::Job>,
            request: WorkFetchRequest,
        ) -> Result<crate::WorkFetchStream, crate::WorkGatewayError> {
            self.0.lock().unwrap().push(id.into());
            assert_eq!(request.service, id);
            let upstream: hellas_rpc::http_fetch::HttpFetchRequest =
                serde_json::from_slice(&request.body).unwrap();
            assert_eq!(
                upstream.url,
                format!("https://{id}.example/v1/responses?stream=true")
            );
            assert!(
                !upstream
                    .headers
                    .iter()
                    .any(|(name, _)| name == "authorization")
            );
            if id == "first" {
                return Err(crate::WorkGatewayError::PreProposal(Box::new(
                    crate::WorkGatewayBusy.into(),
                )));
            }
            ContinuationBackend { calls: 0.into() }.fetch(id, job, request)
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let mut route = http("/v1/responses", Some(vec!["m".into()]));
    let crate::Presentation::Http { targets } = &mut route.presentation else {
        unreachable!()
    };
    let original = targets.remove("test").unwrap();
    for id in ["first", "second"] {
        let mut target = original.clone();
        target.service = id.into();
        target.route.url = format!("https://{id}.example/v1/responses");
        targets.insert(id.into(), target);
    }
    route.backends = vec!["first".into(), "second".into()];
    let work = Arc::new(Targets(Default::default()));
    let app = crate::router::router(
        vec![route],
        work.clone(),
        Arc::new(crate::jobs::Jobs::default()),
        Default::default(),
    )
    .await
    .unwrap();
    let response = app
        .oneshot(
            axum::http::Request::post("/v1/responses?stream=true")
                .header("authorization", "Bearer client-only")
                .body(Body::from(r#"{"model":"m"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(*work.0.lock().unwrap(), ["first", "second"]);
}
