//! One bearer and one speech endpoint across local and remote execution.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_gateway::{Presentation, Route, WorkExecutionBackend as _};

use super::http_fixture::{Mock, Reply, SECRET, access};
const PATH: &str = "/v1/audio/speech";
const UPSTREAM: &str = "/v1/text-to-speech/{segment}";

fn reply(target: &str) -> Reply {
    assert!(target.starts_with("/v1/text-to-speech/"));
    if target.contains("/error?") {
        Reply {
            status: 422,
            content: "application/json",
            bytes: br#"{"error":"unsupported voice"}"#.to_vec(),
            chunked: true,
        }
    } else {
        Reply {
            status: 200,
            content: "audio/wav",
            bytes: wav(),
            chunked: true,
        }
    }
}
fn route(mock: &Mock) -> Route {
    Route {
        backends: vec!["remote".into(), "local".into()],
        presentation: Presentation::Speech {
            model: "hosted".into(),
            target: hellas_gateway::SpeechTarget::Hosted {
                service: "openai".into(),
                method: "responses".into(),
                adaptor: hellas_adaptors::openai::audio_speech::HostedSpeech {
                    url: format!("{}{UPSTREAM}", mock.origin),
                    tls: mock.tls.clone(),
                    max_response_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES,
                    model_id: "hosted-test".into(),
                    formats: [("wav".into(), "wav-test".into())].into(),
                },
            },
        },
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

struct SpeechBackend {
    fetch: Arc<hellas_sdk::ExecutorGateway>,
    native_calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl hellas_gateway::WorkExecutionBackend for SpeechBackend {
    fn backends(&self) -> Vec<hellas_gateway::BackendInfo> {
        let mut backends = self.fetch.backends();
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
        self.fetch.fetch(backend, job, request)
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
        let fail = call.args[6] == Arg::F32Bits(2f32.to_bits());
        assert!(fail || call.args[6] == Arg::F32Bits(1f32.to_bits()));
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
            yield Ok(hellas_gateway::WorkEvent::Accepted(hellas_rpc::provenance::ExecutionProvenance {
                commitment_id: [0x42; 32],
                provider: ProducerSigningKey::from_secret_bytes([9;32]).unwrap().public_key(),
            }));
            for source in &job.environment.sources {
                let reader = job.content.0.open_verified(&job.content.1, *source, None).await.unwrap().unwrap();
                let bytes = reader.read_all(*source, &job.content.0.ram_pool()).await.unwrap();
                assert!(!bytes.is_empty());
            }
            // This evaluator fixture returns the real MMS ABI without opening a GPU.
            let mut samples = vec![0u8; 480000 * 4];
            for (slot, value) in samples.as_chunks_mut::<4>().0.iter_mut().zip([-0.5f32, 0., 0.5]) { slot.copy_from_slice(&value.to_le_bytes()); }
            yield Ok(hellas_gateway::WorkEvent::Transcript(b"CPU evaluator fixture transcript".to_vec()));
            yield Ok(hellas_gateway::WorkEvent::Output(hellas_gateway::ComputeEvent::Done {
                output: InvocationOutput { outcome: Outcome::Succeeded, metadata: hellas_rpc::JsonBytes(vec![]), artifacts: vec![
                    Artifact::new("result", "catena.bytes.v1", [3u64.to_le_bytes(), u64::from(fail).to_le_bytes()].concat()),
                    Artifact::new("waveform", "catena.bytes.v1", samples),
                ] },
                provider: ProducerSigningKey::from_secret_bytes([9;32]).unwrap().public_key(),
            }));
        }))
    }
    fn drain(
        &self,
    ) -> futures::future::BoxFuture<'_, Result<(), hellas_gateway::WorkShutdownError>> {
        self.fetch.drain()
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
        presentation: Presentation::Speech {
            model: "mms".into(),
            target: hellas_gateway::SpeechTarget::Native { package },
        },
    }
}

fn evidence(response: &reqwest::Response) {
    for name in [
        hellas_rpc::provenance::COMMITMENT_KEY,
        hellas_rpc::provenance::PROVIDER_KEY,
        hellas_rpc::provenance::TRANSCRIPT_KEY,
    ] {
        assert!(response.headers().contains_key(name), "missing {name}");
    }
}

#[test]
fn one_speech_gateway_selects_paid_hosted_or_native_by_model() {
    run(|runtime| {
        Box::pin(async move {
            let mock = Mock::start(reply).await;
            let upstream = mock.backend(&[UPSTREAM]);
            let mut case = paid_fixture_for(runtime, Some(upstream.clone())).await;
            let signer = Arc::new(ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap());
            let local_provider = hellas_rpc::provenance::encode_public_key(&signer.public_key());
            let fetch = hellas_sdk::ExecutorGateway::new(
                [
                    (
                        "remote".into(),
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
                    ),
                    (
                        "local".into(),
                        hellas_sdk::BackendEntry {
                            backend: upstream.open_fetch(signer.clone()).await.unwrap(),
                            evaluator: None,
                            max_in_flight: std::num::NonZeroUsize::MIN,
                        },
                    ),
                ]
                .into(),
                signer,
            );
            let native_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let gateway = Arc::new(SpeechBackend {
                fetch: fetch.clone(),
                native_calls: native_calls.clone(),
            });
            let (node, access) = access(&case.root.path().join("speech-authority")).await;
            let routes = vec![route(&mock), native_route(case.root.path())];
            let server = hellas_gateway::test_server::serve(
                node,
                access.bearer(),
                hellas_gateway::ArchiveOptions {
                    directory: case.root.path().join("archive"),
                    zdr: true,
                },
                gateway.clone(),
                fetch.jobs.clone(),
                routes,
            )
            .await
            .unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let request = || {
                client
                    .post(format!("http://{}{PATH}", server.address()))
                    .bearer_auth(server.bearer())
            };
            let session_header = "x-hellas-session-id";
            let send =
                |body: &serde_json::Value| request().header(session_header, "primary").json(body);
            let work = async {
                let mut body = serde_json::json!({"model":"hosted","input":"hello","voice":"default","response_format":"wav"});
                for model in ["hosted", "mms"] {
                    body["model"] = model.into();
                    let response = send(&body).send().await.unwrap();
                    assert_eq!(response.status(), 200);
                    assert_eq!(response.headers()["content-type"], "audio/wav");
                    evidence(&response);
                    assert_ne!(
                        response.headers()[hellas_rpc::provenance::PROVIDER_KEY],
                        local_provider.as_str()
                    );
                    assert_eq!(response.bytes().await.unwrap().as_ref(), wav());
                    if model == "hosted" {
                        // The first session selects the first backend. A fresh session
                        // selects the next backend through the ordinary route scheduler.
                        let response = request()
                            .header(session_header, "second")
                            .json(&body)
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(response.status(), 200);
                        assert_eq!(response.headers()["content-type"], "audio/wav");
                        evidence(&response);
                        assert_eq!(
                            response.headers()[hellas_rpc::provenance::PROVIDER_KEY],
                            local_provider.as_str()
                        );
                        assert_eq!(response.bytes().await.unwrap().as_ref(), wav());
                    }
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
                // Gzip fixtures for the same two model-selected requests above.
                for wire in [
                    "H4sIAAAAAAAC/xXKQQ6AIAwF0bt07Qm8DCH2E0kKJRRwYby7ZTkv81JRhtBJt9oA00G5tjk2QES9l+YL3owUpwyXDmtaDSFpL3G/T1z0/c5EgYNMAAAA",
                    "H4sIAAAAAAAC/6tWys1PSc1RslLKzS1W0lHKzCsoLQHyMlJzcvKB/LL8zORUID8lNS2xNKcEKFKUWlyQn1ecGp+WX5SbCFJbnlimVAsAqkf9WkkAAAA=",
                ] {
                    let response = request()
                        .header(session_header, "primary")
                        .header("content-type", "application/json")
                        .header("content-encoding", "gzip")
                        .header("x-hosted-key", "buyer-value")
                        .body(STANDARD.decode(wire).unwrap())
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.status(), 200);
                    evidence(&response);
                    assert_eq!(response.bytes().await.unwrap().as_ref(), wav());
                }
                body["model"] = "hosted".into();
                body["voice"] = "error".into();
                let response = send(&body).send().await.unwrap();
                assert_eq!(response.status(), 422);
                evidence(&response);
                assert_eq!(
                    response.json::<serde_json::Value>().await.unwrap(),
                    serde_json::json!({"error":"unsupported voice"})
                );
                body["model"] = "mms".into();
                body["voice"] = "default".into();
                body["speed"] = 2.into(); // evaluator fixture returns a failed MMS status
                let response = send(&body).send().await.unwrap();
                assert_eq!(response.status(), 502);
                evidence(&response);
                assert!(
                    response
                        .json::<serde_json::Value>()
                        .await
                        .unwrap()
                        .get("error")
                        .is_some()
                );
                for model in ["hosted", "mms"] {
                    let base = serde_json::json!({"model":model,"input":"hello","voice":"default","response_format":"wav"});
                    assert_eq!(
                        client
                            .post(format!("http://{}{PATH}?speed=2", server.address()))
                            .bearer_auth(server.bearer())
                            .json(&base)
                            .send()
                            .await
                            .unwrap()
                            .status(),
                        400
                    );
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
            assert_eq!(native_calls.load(std::sync::atomic::Ordering::SeqCst), 3);
            let seen = mock.seen.lock().unwrap().clone();
            assert_eq!(seen.len(), 5);
            for (request, voice) in
                seen.iter()
                    .zip(["default", "default", "voice%20two", "default", "error"])
            {
                let request = String::from_utf8(request.clone()).unwrap();
                assert!(request.starts_with(&format!(
                    "POST /v1/text-to-speech/{voice}?output_format=wav-test HTTP/1.1"
                )));
                assert!(request.contains(&format!("x-hosted-key: {SECRET}")));
                assert!(!request.to_lowercase().contains("authorization:"));
                assert!(!request.to_lowercase().contains("content-encoding:"));
                assert!(!request.contains("buyer-value"));
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
                    assert_eq!(state.terminals().count(), 4);
                    assert_eq!(state.ledger().credited_cumulative(), 4 * PRICE);
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
