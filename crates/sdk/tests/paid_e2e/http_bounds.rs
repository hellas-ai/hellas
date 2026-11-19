//! Raw response boundaries through the paid seller, buyer and HTTP listener.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt as _;
use hellas_gateway::{HttpRoute, HttpTarget, Presentation, Route, WorkExecutionBackend as _};
use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots};
use hellas_sdk::daemon_config::{Backend, BackendKind, Credential, Upstream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SECRET: &str = "local-mock-seller-secret";
const PATH: &str = "/v1/text-to-speech/voice-a";
const STREAM: &str = "/v1/text-to-speech/voice-a/stream";
const BODY_JSON: &str = r#"{"text":"hello","model_id":"hosted-test","voice_settings":{"speed":1}}"#;

struct Mock {
    origin: String,
    tls: HttpTls,
    seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    async fn start() -> Self {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = key.cert.der().clone();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = seen.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (acceptor, capture) = (acceptor.clone(), capture.clone());
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    let mut request = Vec::new();
                    let mut buf = [0; 8192];
                    let header_end = loop {
                        let n = stream.read(&mut buf).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
                    let length = header
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|n| n.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while request.len() < header_end + length {
                        let n = stream.read(&mut buf).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&buf[..n]);
                    }
                    capture.lock().unwrap().push(request);
                    let target = header.split_whitespace().nth(1).unwrap();
                    let authorized = header
                        .to_ascii_lowercase()
                        .contains(&format!("x-hosted-key: {SECRET}\r\n"));
                    let (status, content, bytes) = if !authorized {
                        (
                            401,
                            "application/json",
                            br#"{"error":"key missing"}"#.to_vec(),
                        )
                    } else if target.starts_with("/v1/voices") {
                        (
                            200,
                            "application/json",
                            br#"{"voices":[{"voice_id":"voice-a"}]}"#.to_vec(),
                        )
                    } else if target.starts_with("/v1/models") {
                        (
                            200,
                            "application/json",
                            br#"[{"model_id":"hosted-test"}]"#.to_vec(),
                        )
                    } else {
                        let size = target
                            .split('?')
                            .nth(1)
                            .unwrap()
                            .split('&')
                            .next()
                            .unwrap()
                            .strip_prefix("bytes=")
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        (200, "audio/mpeg", audio(size))
                    };
                    if target.ends_with("&length") {
                        let head = format!(
                            "HTTP/1.1 {status} Test\r\ncontent-type: {content}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            bytes.len()
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.write_all(&bytes).await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                    let head = format!(
                        "HTTP/1.1 {status} Test\r\ncontent-type: {content}\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                    );
                    if stream.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for chunk in bytes.chunks(16384) {
                        if stream
                            .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if stream.write_all(chunk).await.is_err() {
                            return;
                        }
                        if stream.write_all(b"\r\n").await.is_err() {
                            return;
                        }
                        if stream.flush().await.is_err() {
                            return;
                        }
                    }
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            origin,
            tls: HttpTls {
                roots: HttpTrustRoots::Certificates {
                    der_base64: vec![STANDARD.encode(cert)],
                },
                spki_sha256: vec![],
            },
            seen,
            task,
        }
    }
    fn backend(&self) -> Backend {
        Backend {
            max_in_flight: std::num::NonZeroUsize::MIN,
            kind: BackendKind::Fetch {
                service: "openai".into(),
                method: "responses".into(),
                upstream: Upstream::Http {
                    allowed_hosts: vec!["localhost".into()],
                    allow_private_addresses: true,
                    credentials: vec![Credential {
                        trust_roots: self.tls.roots.clone(),
                        allowed_origins: vec![self.origin.clone()],
                        allowed_paths: [PATH, STREAM, "/v1/voices", "/v1/models"]
                            .map(String::from)
                            .to_vec(),
                        allowed_methods: vec!["GET".into(), "POST".into()],
                        header_name: "x-hosted-key".into(),
                        secret: Some(SECRET.into()),
                    }],
                },
            },
        }
    }
    fn route(&self, path: &str, method: &str) -> Route {
        Route {
            backends: vec!["test".into()],
            presentation: Presentation::Http {
                targets: [(
                    "test".into(),
                    HttpTarget {
                        service: "openai".into(),
                        method: "responses".into(),
                        route: HttpRoute {
                            path: path.into(),
                            method: method.into(),
                            url: format!("{}{path}", self.origin),
                            tls: self.tls.clone(),
                            headers: vec![],
                            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                            models: None,
                        },
                    },
                )]
                .into(),
            },
        }
    }
}
fn audio(size: usize) -> Vec<u8> {
    (0..size).map(|n| (n % 256) as u8).collect()
}

async fn access(root: &std::path::Path) -> (NodeCoordinator, hellas_gateway::GatewayAccess) {
    use auth::*;
    use hellas_authority::{
        node::{GATEWAY_INVOKE, host_resource},
        test_support::{TestClock, common_node, ids::ROOT_GRANT},
    };
    let authority = AuthorityId(Digest::hash(b"audio gateway probe"));
    let now = UnixMillis(1000);
    let spec = common_node::admin_spec(
        authority,
        ROOT.principal(),
        &[(GATEWAY_INVOKE, host_resource(authority))],
        (now, UnixMillis(100_000)),
        (99_000, 0),
        &[],
    );
    let (store, admin) = NodeStore::bootstrap(
        &StoreLocation::for_test(root),
        hellas_authority::model::grant::grant_network(),
        ROOT_GRANT,
        common_node::approval_for(
            Ownership::Bootstrap {
                root: ROOT_GRANT,
                target: None,
            },
            spec.clone(),
            spec,
        ),
        None,
        now,
    )
    .await
    .unwrap();
    let node = NodeCoordinator::new(store, TestClock::new(now).source());
    let caller = hellas_authority::test_support::session(&node, &admin).await;
    let scope = hellas_channel::test_support::Rights::new(authority, ROOT)
        .allow(GATEWAY_INVOKE, host_resource(authority))
        .valid_from(now)
        .valid_until(UnixMillis(90_000))
        .build();
    let grant = GrantId([104; 16]);
    node.grant(
        &caller,
        GrantCommand::Issue {
            authorization: ROOT_GRANT,
            id: grant,
            spec: scope.clone(),
        },
    )
    .await
    .unwrap();
    let (_, credential) = hellas_authority::test_support::credentials::issue_one(
        &node,
        &caller,
        ROOT_GRANT,
        scope,
        CredentialHolder::Bearer,
    )
    .await
    .unwrap();
    let access = hellas_gateway::GatewayAccess::new(node.clone(), grant, credential)
        .await
        .unwrap();
    (node, access)
}

#[test]
fn http_raw_response_bound_is_deliverable_over_paid_fetch() {
    run(|runtime| {
        Box::pin(async move {
            let mock = Mock::start().await;
            let mut case = paid_fixture_for(runtime, Some(mock.backend())).await;
            let gateway = hellas_sdk::ExecutorGateway::new(
                [(
                    "test".into(),
                    hellas_sdk::BackendEntry {
                        backend: hellas_sdk::Backend::paid(
                            Some(case.quote.policy.invocation_policy.clone()),
                            case.options.clone(),
                            case.endpoint.clone(),
                            client_settlement(),
                            case.owner.clone(),
                        ),
                        evaluator: None,
                        max_in_flight: std::num::NonZeroUsize::MIN,
                    },
                )]
                .into(),
                Arc::new(ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap()),
            );
            let (node, access) = access(&case.root.path().join("http-authority")).await;
            let server = hellas_gateway::test_server::serve(
                node,
                access.bearer(),
                hellas_gateway::ArchiveOptions {
                    directory: case.root.path().join("archive"),
                    zdr: true,
                },
                gateway.clone(),
                gateway.jobs.clone(),
                vec![mock.route(PATH, "POST")],
            )
            .await
            .unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let send = |bytes, framing: &str| {
                client
                    .post(format!(
                        "http://{}{PATH}?bytes={bytes}{framing}",
                        server.address()
                    ))
                    .bearer_auth(server.bearer())
                    .header("content-type", "application/json")
                    .body(BODY_JSON)
            };
            let limit = hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES as usize;
            let work = async {
                for size in [limit - 1, limit] {
                    let response = send(size, "").send().await.unwrap();
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.headers()["content-type"], "audio/mpeg");
                    let mut received = Vec::new();
                    let mut body = response.bytes_stream();
                    while let Some(chunk) = body.next().await {
                        received.extend_from_slice(&chunk.unwrap_or_else(|e| {
                            panic!("size={size} received={} error={e}", received.len())
                        }));
                    }
                    assert_eq!(received, audio(size));
                }
                let response = send(limit + 1, "&length").send().await.unwrap();
                assert_eq!(
                    response.status(),
                    502,
                    "known oversize fails before a successful head"
                );
                assert!(!response.bytes().await.unwrap().is_empty());
                let response = send(limit + 1, "").send().await.unwrap();
                assert_eq!(
                    response.status(),
                    200,
                    "an unknown length cannot be refused before streaming"
                );
                assert!(
                    response.bytes().await.is_err(),
                    "the over-limit stream must not complete successfully"
                );
            };
            sealing_while(&mut case.devnet, Duration::from_secs(1), work).await;
            gateway.drain().await.unwrap();
            let seen = mock.seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 4);
            assert!(seen.iter().all(|request| {
                String::from_utf8_lossy(request).contains(&format!("x-hosted-key: {SECRET}"))
            }));
            let endpoint = bind_paid_endpoint(case.client_transport.clone())
                .await
                .unwrap();
            let mut session = PaidWorkSession::open(
                case.options.clone(),
                endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionOpenMode::Retained,
                SessionFundingOptions::default(),
            )
            .await
            .unwrap();
            session
                .with_state(|state| {
                    assert_eq!(state.jobs().count(), 0);
                    assert_eq!(state.terminals().count(), 4);
                    assert_eq!(state.ledger().credited_cumulative(), 2 * PRICE);
                })
                .await
                .unwrap();
            session.shutdown().await;
            drop(session);
            endpoint.close().await;
            server.shutdown().await.unwrap();
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}
