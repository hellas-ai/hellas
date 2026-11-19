//! One bearer and one speech endpoint over paid Fetch and native Compute.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_gateway::{HttpRoute, HttpTarget, Presentation, Route, WorkExecutionBackend as _};
use hellas_rpc::http_fetch::{HttpTls, HttpTrustRoots};
use hellas_sdk::daemon_config::{Backend, BackendKind, Credential, Upstream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SECRET: &str = "local-mock-seller-secret";
const PATH: &str = "/v1/audio/speech";
const UPSTREAM: &str = "/v1/text-to-speech/{voice_id}";

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
                    assert!(authorized);
                    assert!(target.starts_with("/v1/text-to-speech/"));
                    let (status, content, bytes) = (200, "audio/wav", wav());
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
                        allowed_paths: vec![UPSTREAM.into()],
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
                            url: format!("{}{UPSTREAM}", self.origin),
                            tls: self.tls.clone(),
                            headers: vec![],
                            max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                            models: Some(vec!["hosted".into()]),
                            hosted_speech: Some(
                                hellas_adaptors::openai::audio_speech::HostedSpeech {
                                    model_id: "hosted-test".into(),
                                    formats: [("wav".into(), "wav-test".into())].into(),
                                },
                            ),
                        },
                    },
                )]
                .into(),
            },
        }
    }
}
fn wav() -> Vec<u8> {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend(42u32.to_le_bytes());
    bytes.extend(b"WAVEfmt ");
    bytes.extend(16u32.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(16000u32.to_le_bytes());
    bytes.extend(32000u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(16u16.to_le_bytes());
    bytes.extend(b"data");
    bytes.extend(6u32.to_le_bytes());
    for sample in [-16384i16, 0, 16384] {
        bytes.extend(sample.to_le_bytes());
    }
    bytes
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

struct SpeechBackend {
    paid: Arc<hellas_sdk::ExecutorGateway>,
    native_calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl hellas_gateway::WorkExecutionBackend for SpeechBackend {
    fn backends(&self) -> Vec<hellas_gateway::BackendInfo> {
        let mut backends = self.paid.backends();
        backends.push(hellas_gateway::BackendInfo {
            id: "mms".into(),
            instance: 1,
            evaluator: Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            )),
            max_in_flight: 1,
            in_flight: 0,
            down: false,
            error: None,
        });
        backends
    }
    fn fetch(
        &self,
        backend: &str,
        job: Arc<hellas_gateway::jobs::Job>,
        request: hellas_gateway::WorkFetchRequest,
    ) -> Result<hellas_gateway::WorkFetchStream, hellas_gateway::WorkGatewayError> {
        self.paid.fetch(backend, job, request)
    }
    fn run(
        &self,
        backend: &str,
        _request_job: Arc<hellas_gateway::jobs::Job>,
        job: hellas_client::model::ComputeJob,
    ) -> Result<
        hellas_gateway::WorkOutputStream<hellas_gateway::ComputeEvent>,
        hellas_gateway::WorkGatewayError,
    > {
        use hellas_rpc::protocol::invocation::{
            Artifact,
            compute::Arg,
            output::{InvocationOutput, Outcome},
        };
        assert_eq!(backend, "mms");
        assert_eq!(job.plan.calls.len(), 1);
        let call = &job.plan.calls[0];
        assert_eq!(call.entry, "tts.synthesize");
        assert_eq!(call.args[1], Arg::U64(11)); // hello with interleaved blanks
        assert_eq!(call.args[6], Arg::F32Bits(1f32.to_bits()));
        assert_eq!(job.environment.assets[0].object.bytes(), 56_546_102);
        assert_eq!(job.inputs[0].name, "tokens");
        let mut offset = 0;
        for arg in &call.args[7..] {
            let Arg::Asset {
                name,
                offset: start,
                bytes,
            } = arg
            else {
                panic!("MMS weight argument")
            };
            assert_eq!(name, "weights");
            assert_eq!(*start, offset);
            offset += bytes;
        }
        assert_eq!(offset, 56_546_102);
        self.native_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::pin(async_stream::stream! {
            for source in &job.environment.sources {
                let reader = job.content.0.open_verified(&job.content.1, *source, None).await.unwrap().unwrap();
                let bytes = reader.read_all(*source, &job.content.0.ram_pool()).await.unwrap();
                assert!(!bytes.is_empty());
            }
            // This evaluator fixture returns the real MMS ABI without opening a GPU.
            let mut samples = vec![0u8; 480000 * 4];
            for (slot, value) in samples.as_chunks_mut::<4>().0.iter_mut().zip([-0.5f32, 0., 0.5]) { slot.copy_from_slice(&value.to_le_bytes()); }
            yield Ok(hellas_gateway::WorkEvent::Output(hellas_gateway::ComputeEvent::Done {
                output: InvocationOutput { outcome: Outcome::Succeeded, metadata: hellas_rpc::JsonBytes(vec![]), artifacts: vec![
                    Artifact::new("result", "catena.bytes.v1", [3u64.to_le_bytes(), 0u64.to_le_bytes()].concat()),
                    Artifact::new("waveform", "catena.bytes.v1", samples),
                ] },
                provider: ProducerSigningKey::from_secret_bytes([9;32]).unwrap().public_key(),
            }));
        }))
    }
    fn drain(
        &self,
    ) -> futures::future::BoxFuture<'_, Result<(), hellas_gateway::WorkShutdownError>> {
        self.paid.drain()
    }
}

fn native_route(root: &std::path::Path) -> Route {
    let package = root.join("mms-descriptor");
    std::fs::create_dir(&package).unwrap();
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/speech/fixture");
    for name in [
        "config.json",
        "vocab.json",
        "tokenizer_config.json",
        "special_tokens_map.json",
    ] {
        std::fs::copy(fixture.join(name), package.join(name)).unwrap();
    }
    let object = hellas_rpc::ContentRef::new(
        ContentId::hash(b"MMS evaluator fixture weights"),
        56_546_102,
    );
    std::fs::write(
        package.join("descriptor.json"),
        serde_json::to_vec(&serde_json::json!({"weights":object})).unwrap(),
    )
    .unwrap();
    Route {
        backends: vec!["mms".into()],
        presentation: Presentation::Model {
            modality: hellas_client::model::ModelKind::Speech,
            model: "mms".into(),
            package,
            max_tokens: 1,
        },
    }
}

#[test]
fn one_speech_gateway_selects_paid_hosted_or_native_by_model() {
    run(|runtime| {
        Box::pin(async move {
            let mock = Mock::start().await;
            let mut case = paid_fixture_for(runtime, Some(mock.backend())).await;
            let paid = hellas_sdk::ExecutorGateway::new(
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
            let native_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let gateway = Arc::new(SpeechBackend {
                paid: paid.clone(),
                native_calls: native_calls.clone(),
            });
            let (node, access) = access(&case.root.path().join("speech-authority")).await;
            let routes = vec![mock.route(PATH, "POST"), native_route(case.root.path())];
            let server = hellas_gateway::test_server::serve(
                node,
                access.bearer(),
                hellas_gateway::ArchiveOptions {
                    directory: case.root.path().join("archive"),
                    zdr: true,
                },
                gateway.clone(),
                paid.jobs.clone(),
                routes,
            )
            .await
            .unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let send = |body: &serde_json::Value| {
                client
                    .post(format!("http://{}{PATH}", server.address()))
                    .bearer_auth(server.bearer())
                    .json(body)
            };
            let work = async {
                let mut body = serde_json::json!({"model":"hosted","input":"hello","voice":"default","response_format":"wav"});
                for model in ["hosted", "mms"] {
                    body["model"] = model.into();
                    let response = send(&body).send().await.unwrap();
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.headers()["content-type"], "audio/wav");
                    assert_eq!(response.bytes().await.unwrap().as_ref(), wav());
                }
                body["model"] = "hosted".into();
                body["voice"] = "voice two".into();
                assert_eq!(
                    send(&body)
                        .send()
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap()
                        .as_ref(),
                    wav()
                );
                for model in ["hosted", "mms"] {
                    let base = serde_json::json!({"model":model,"input":"hello","voice":"default","response_format":"wav"});
                    for (key, value) in [
                        ("response_format", serde_json::json!("opus")),
                        ("voice", serde_json::json!("../escape")),
                        ("instructions", serde_json::json!("whisper")),
                        ("speed", serde_json::json!(0)),
                    ] {
                        let mut bad = base.clone();
                        bad[key] = value;
                        assert_eq!(send(&bad).send().await.unwrap().status(), 400, "{bad}");
                    }
                }
            };
            sealing_while(&mut case.devnet, Duration::from_secs(1), work).await;
            gateway.drain().await.unwrap();
            assert_eq!(native_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            let seen = mock.seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 2);
            for (request, voice) in seen.iter().zip(["default", "voice%20two"]) {
                let request = String::from_utf8(request.clone()).unwrap();
                assert!(request.starts_with(&format!(
                    "POST /v1/text-to-speech/{voice}?output_format=wav-test HTTP/1.1"
                )));
                assert!(request.contains(&format!("x-hosted-key: {SECRET}")));
                assert!(!request.to_lowercase().contains("authorization:"));
                let body: serde_json::Value =
                    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
                assert_eq!(
                    body,
                    serde_json::json!({"text":"hello","model_id":"hosted-test"})
                );
            }
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
                    assert_eq!(state.terminals().count(), 2);
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
