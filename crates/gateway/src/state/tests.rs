use super::*;
use crate::WorkExecutionBackend;

/// The tiny Qwen3 GGUF the client text package tests render.
fn text_model() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/model/package/mini-qwen3.gguf")
}

async fn open(work: Arc<dyn WorkExecutionBackend>) -> TextState {
    TextState::open(
        &crate::TextOptions {
            model: text_model(),
            model_name: "mini-qwen3".into(),
            default_max_tokens: 128,
        },
        crate::test_support::execution(
            work,
            crate::Presentation::Model {
                model: "mini-qwen3".into(),
                package: text_model(),
                max_tokens: 128,
            },
        )
        .await,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn authenticated_prefixes_arrive_before_the_paid_terminal() {
    use crate::{ComputeEvent, WorkExecutionBackend};
    use futures::StreamExt;
    use hellas_rpc::protocol::invocation::Artifact;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Paid {
        calls: Arc<AtomicUsize>,
        payment_ack: Arc<tokio::sync::Notify>,
    }
    impl WorkExecutionBackend for Paid {
        fn backends(&self) -> Vec<crate::BackendInfo> {
            crate::test_support::backend({
                Some(hellas_client::model::evaluator(
                    hellas_client::model::GpuDialect::Hip,
                ))
            })
        }
        fn run(
            &self,
            _backend: &str,
            _request_job: Arc<crate::jobs::Job>,
            job: hellas_client::model::ComputeJob,
        ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                job.inputs,
                vec![Artifact::new(
                    "prompt",
                    "catena.u64le.v1",
                    0u64.to_le_bytes().to_vec()
                )]
            );
            assert_eq!(job.plan.step.unwrap().stop.max_steps, 1);
            let payment_ack = self.payment_ack.clone();
            Ok(Box::pin(async_stream::try_stream! {
                yield ComputeEvent::Output(hellas_rpc::protocol::invocation::output::ArtifactChunk { name: "emitted".into(), format: "catena.u64le.v1".into(), offset: 0, bytes: hellas_rpc::JsonBytes(1u64.to_le_bytes().to_vec()) });
                // Match the paid backend contract: an authenticated prefix is
                // available before durable payment, but its terminal is not.
                payment_ack.notified().await;
                yield ComputeEvent::Done {
                    output: hellas_rpc::protocol::invocation::output::InvocationOutput {
                        outcome: hellas_rpc::protocol::invocation::output::Outcome::Succeeded,
                        artifacts: vec![Artifact::new("emitted", "catena.u64le.v1", 1u64.to_le_bytes().to_vec())],
                        metadata: hellas_rpc::JsonBytes(hellas_rpc::canonical_dag_cbor(&hellas_rpc::protocol::invocation::compute::RunMetadata {
                            steps: 1, stop: Some(hellas_rpc::protocol::invocation::compute::StopReason::MaxSteps)
                        }).unwrap()),
                    },
                    provider: hellas_auth::ProducerSigningKey::from_secret_bytes([7; 32]).unwrap().public_key(),
                };

            }.map(|event: Result<_, crate::WorkGatewayError>| event.map(crate::WorkEvent::Output))))
        }

        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let payment_ack = Arc::new(tokio::sync::Notify::new());
    let state = open(Arc::new(Paid {
        calls: calls.clone(),
        payment_ack: payment_ack.clone(),
    }))
    .await;
    let mut live = state
        .prepare_ids(
            vec![0],
            1,
            None,
            &mut crate::test_support::selection(state.execution.work.clone()),
        )
        .await
        .unwrap();
    let prefix = live.prepared.next().await.unwrap().unwrap();
    assert!(matches!(
        prefix,
        crate::WorkEvent::Output(ComputeEvent::Output(
            hellas_rpc::protocol::invocation::output::ArtifactChunk { offset: 0, .. }
        ))
    ));
    let terminal = {
        let terminal = live.prepared.next();
        tokio::pin!(terminal);
        assert!(futures::poll!(terminal.as_mut()).is_pending());
        payment_ack.notify_one();
        terminal.await.unwrap().unwrap()
    };
    assert!(matches!(
        terminal,
        crate::WorkEvent::Output(ComputeEvent::Done { .. })
    ));
    assert!(live.prepared.next().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn paid_capacity_is_a_retryable_error() {
    struct Busy;
    impl crate::WorkExecutionBackend for Busy {
        fn backends(&self) -> Vec<crate::BackendInfo> {
            crate::test_support::backend({
                Some(hellas_client::model::evaluator(
                    hellas_client::model::GpuDialect::Hip,
                ))
            })
        }
        fn run(
            &self,
            _backend: &str,
            _request_job: Arc<crate::jobs::Job>,
            _: hellas_client::model::ComputeJob,
        ) -> Result<crate::WorkOutputStream<crate::ComputeEvent>, crate::WorkGatewayError> {
            Err(crate::WorkGatewayBusy.into())
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let state = open(Arc::new(Busy)).await;
    let error = state
        .prepare_ids(
            vec![0],
            1,
            None,
            &mut crate::test_support::selection(state.execution.work.clone()),
        )
        .await
        .err()
        .expect("busy backend must reject admission");
    assert_eq!(
        crate::backend_status(&error),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(error.to_string().contains("retry later"));
}

/// A provider that accepts every job, emits one token, and signs `transcript`.
struct Accepting {
    provenance: ExecutionProvenance,
    transcript: Vec<u8>,
}

impl WorkExecutionBackend for Accepting {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend({
            Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            ))
        })
    }
    fn run(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        _: hellas_client::model::ComputeJob,
    ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
        use crate::WorkEvent;
        use hellas_rpc::protocol::invocation::{
            Artifact,
            compute::{RunMetadata, StopReason},
            output::{ArtifactChunk, InvocationOutput, Outcome},
        };
        let emitted = Artifact::new("emitted", "catena.u64le.v1", 1u64.to_le_bytes().to_vec());
        Ok(Box::pin(futures::stream::iter([
            Ok(WorkEvent::Accepted(self.provenance.clone())),
            Ok(WorkEvent::Output(ComputeEvent::Output(ArtifactChunk {
                name: emitted.name.clone(),
                format: emitted.format.clone(),
                offset: 0,
                bytes: emitted.bytes.clone(),
            }))),
            Ok(WorkEvent::Transcript(self.transcript.clone())),
            Ok(WorkEvent::Output(ComputeEvent::Done {
                output: InvocationOutput {
                    outcome: Outcome::Succeeded,
                    artifacts: vec![emitted],
                    metadata: hellas_rpc::JsonBytes(
                        hellas_rpc::canonical_dag_cbor(&RunMetadata {
                            steps: 1,
                            stop: Some(StopReason::MaxSteps),
                        })
                        .unwrap(),
                    ),
                },
                provider: self.provenance.provider,
            })),
        ])))
    }

    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

/// The `hellas` object of one rendered JSON body or stream event: at the top
/// level, or on the Responses `response` object.
fn hellas(value: &serde_json::Value) -> &serde_json::Value {
    value
        .get("hellas")
        .or_else(|| value.get("response").and_then(|r| r.get("hellas")))
        .unwrap_or(&serde_json::Value::Null)
}

/// Every text route names the accepted job and its provider in headers, puts
/// them on the stream's first event, and hands over the signed transcript on
/// the last event or in the body.
#[tokio::test]
async fn text_routes_carry_provenance_at_start_and_end() {
    use base64::Engine as _;
    use serde_json::json;
    use tower::ServiceExt as _;

    let provenance = ExecutionProvenance {
        commitment_id: [0x5a; 32],
        provider: hellas_auth::PublicKey::Secp256k1([0x02; 33]),
    };
    let transcript = b"provider-signed transcript".to_vec();
    let commitment = "5a".repeat(32);
    let provider = format!("secp256k1:{}", "02".repeat(33));
    let encoded = base64::engine::general_purpose::STANDARD.encode(&transcript);
    let state = Arc::new(
        open(Arc::new(Accepting {
            provenance,
            transcript,
        }))
        .await,
    );
    let app = test_router(state).layer(crate::provenance_layer::ProvenanceLayer);
    let user = json!([{"role": "user", "content": "hi"}]);
    let routes = [
        (
            "/v1/chat/completions",
            json!({"model": "m", "messages": user, "max_tokens": 1}),
        ),
        (
            "/v1/responses",
            json!({"model": "m", "input": "hi", "max_output_tokens": 1}),
        ),
        (
            "/v1/messages",
            json!({"model": "m", "messages": user, "max_tokens": 1}),
        ),
        (
            "/v1/completions",
            json!({"model": "m", "prompt": "hi", "max_tokens": 1}),
        ),
    ];
    for (path, body) in routes {
        for stream in [false, true] {
            let mut body = body.clone();
            body["stream"] = json!(stream);
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::post(path)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let what = format!("{path} stream={stream}");
            assert_eq!(response.status(), axum::http::StatusCode::OK, "{what}");
            let headers = response.headers();
            assert_eq!(
                headers[hellas_rpc::provenance::COMMITMENT_KEY],
                commitment.as_str(),
                "{what}"
            );
            assert_eq!(
                headers[hellas_rpc::provenance::PROVIDER_KEY],
                provider.as_str(),
                "{what}"
            );
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            if !stream {
                let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    hellas(&body),
                    &json!({"commitment": commitment, "provider": provider, "transcript": encoded}),
                    "{what}"
                );
                continue;
            }
            let events = std::str::from_utf8(&bytes)
                .unwrap()
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .filter_map(|data| serde_json::from_str::<serde_json::Value>(data).ok())
                .collect::<Vec<_>>();
            assert_eq!(
                hellas(&events[0]),
                &json!({"commitment": commitment, "provider": provider}),
                "{what}: first event {}",
                events[0]
            );
            let last = events.last().unwrap();
            assert_eq!(
                hellas(last),
                &json!({"commitment": commitment, "provider": provider, "transcript": encoded}),
                "{what}: last event {last}"
            );
        }
    }
}

struct Capturing {
    jobs: std::sync::Mutex<Vec<hellas_client::model::ComputeJob>>,
}

impl WorkExecutionBackend for Capturing {
    fn backends(&self) -> Vec<crate::BackendInfo> {
        crate::test_support::backend({
            Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            ))
        })
    }
    fn run(
        &self,
        _backend: &str,
        _request_job: Arc<crate::jobs::Job>,
        job: hellas_client::model::ComputeJob,
    ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
        self.jobs.lock().unwrap().push(job);
        Ok(Box::pin(futures::stream::iter([Ok(
            crate::WorkEvent::Accepted(ExecutionProvenance {
                commitment_id: [1; 32],
                provider: hellas_auth::PublicKey::Secp256k1([2; 33]),
            }),
        )])))
    }

    fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Responses string input is a user message, so it must produce the same
/// prepared tokens as the equivalent one-message array.
#[tokio::test]
async fn responses_string_input_matches_a_user_message_array() {
    use hellas_adaptors::{RawRequest, WireAdaptor, openai::responses::OpenAiResponsesAdaptor};
    use serde_json::json;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let state = open(work.clone()).await;
    let adaptor = OpenAiResponsesAdaptor;
    let prepare = async |input: serde_json::Value| {
        let parsed = adaptor
            .parse(
                RawRequest::from_value(
                    json!({"model": "m", "input": input, "max_output_tokens": 1}),
                )
                .unwrap(),
            )
            .unwrap();
        let request = adaptor.to_execution_request(&parsed).unwrap();
        state
            .prepare_wire_execution(
                &request,
                &mut crate::test_support::selection(state.execution.work.clone()),
            )
            .await
            .unwrap();
    };
    prepare(json!("hi")).await;
    prepare(json!([{"role": "user", "content": "hi"}])).await;

    let jobs = work.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].inputs, jobs[1].inputs);
    assert_eq!(jobs[0].plan, jobs[1].plan);
}

/// Every accepted generation control must reach the job or be rejected; none
/// may be silently dropped between the adaptor and native execution.
#[tokio::test]
async fn generation_controls_are_honoured_or_rejected() {
    use hellas_adaptors::{
        RawRequest, WireAdaptor, openai::chat_completions::OpenAiChatCompletionsAdaptor,
        openai::responses::OpenAiResponsesAdaptor,
    };
    use serde_json::json;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let state = open(work.clone()).await;
    let chat = |body: serde_json::Value| {
        let adaptor = OpenAiChatCompletionsAdaptor;
        let parsed = adaptor
            .parse(RawRequest::from_value(body).unwrap())
            .unwrap();
        adaptor.to_execution_request(&parsed).unwrap()
    };
    let responses = |body: serde_json::Value| {
        let adaptor = OpenAiResponsesAdaptor;
        let parsed = adaptor
            .parse(RawRequest::from_value(body).unwrap())
            .unwrap();
        adaptor.to_execution_request(&parsed).unwrap()
    };
    let prepare = async |request: &WireExecutionRequest| {
        state
            .prepare_wire_execution(
                request,
                &mut crate::test_support::selection(state.execution.work.clone()),
            )
            .await
    };

    for (field, value) in [
        ("temperature", json!(0.5)),
        ("top_p", json!(0.9)),
        ("top_logprobs", json!(2)),
    ] {
        let mut body = json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 1
        });
        body[field] = value;
        let error = prepare(&chat(body))
            .await
            .err()
            .expect("unsupported sampling must be rejected");
        assert!(
            matches!(error, BackendError::Rejected(_)),
            "{field}: {error}"
        );
        assert!(error.to_string().contains(field), "{field}: {error}");
    }
    let error = prepare(&responses(json!({
        "model": "m",
        "input": "hello",
        "max_output_tokens": 1,
        "truncation": "auto"
    })))
    .await
    .err()
    .expect("truncation must be rejected");
    assert!(matches!(error, BackendError::Rejected(_)));
    assert!(error.to_string().contains("truncation"), "{error}");

    // `parallel_tool_calls: false` is enforced by the chat turn.
    let prepared = prepare(&chat(json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 1,
        "tools": [{"type": "function", "function": {
            "name": "bash", "parameters": {"type": "object"}
        }}],
        "parallel_tool_calls": false
    })))
    .await
    .unwrap();
    let mut turn = prepared.chat.expect("tool request prepares a chat turn");
    let call = "<tool_call>\n{\"name\":\"bash\",\"arguments\":{}}\n</tool_call>";
    turn.feed(call).unwrap();
    let error = turn.feed(call).unwrap_err();
    assert!(error.to_string().contains("parallel_tool_calls"), "{error}");
}

/// The executor emits the token that matches a stop sequence before it stops,
/// so native execution would decode that token into the returned text. The
/// route must refuse the control instead of returning the stop sequence.
#[tokio::test]
async fn custom_stop_sequences_are_rejected_before_any_output() {
    use serde_json::json;
    use tower::ServiceExt as _;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let state = Arc::new(open(work.clone()).await);
    let response = test_router(state)
        .oneshot(
            axum::http::Request::post("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "model": "m",
                        "messages": [{"role": "user", "content": "hello"}],
                        "max_tokens": 1,
                        "stop": "hi"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let message = body["error"]["message"]
        .as_str()
        .expect("an error body names the refusal");
    assert!(
        message.contains("custom stop sequences are not supported"),
        "{message}"
    );
    assert!(
        work.jobs.lock().unwrap().is_empty(),
        "a rejected request must submit no job"
    );
}

/// Structured output cannot be enforced by native execution yet, so a strict
/// schema must be rejected rather than answered with arbitrary text.
#[tokio::test]
async fn structured_output_is_rejected_before_native_execution() {
    use hellas_adaptors::{
        RawRequest, WireAdaptor, openai::chat_completions::OpenAiChatCompletionsAdaptor,
    };
    use serde_json::json;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let state = open(work.clone()).await;
    let adaptor = OpenAiChatCompletionsAdaptor;
    let request = |body: serde_json::Value| {
        let parsed = adaptor
            .parse(RawRequest::from_value(body).unwrap())
            .unwrap();
        adaptor.to_execution_request(&parsed).unwrap()
    };
    let error = state
        .prepare_wire_execution(
            &request(json!({
                "model": "m",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 1,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "answer",
                        "schema": {"type": "object", "properties": {"answer": {"type": "string"}}},
                        "strict": true
                    }
                }
            })),
            &mut crate::test_support::selection(state.execution.work.clone()),
        )
        .await
        .err()
        .expect("a strict schema must be rejected");
    assert!(matches!(error, BackendError::Rejected(_)));
    assert!(error.to_string().contains("json_schema"), "{error}");

    state
        .prepare_wire_execution(
            &request(json!({
                "model": "m",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 1
            })),
            &mut crate::test_support::selection(state.execution.work.clone()),
        )
        .await
        .unwrap();
    assert_eq!(work.jobs.lock().unwrap().len(), 1);
}

#[test]
fn native_capabilities_reject_every_unimplemented_control() {
    use hellas_adaptors::{Input, ModelRef, ResponseFormat};
    use serde_json::json;

    let base = CanonicalExecution::new(ModelRef::new("m"), Input::Text("hello".into()));
    validate_native_text_request(&base).unwrap();
    for (key, value) in [
        ("temperature", json!(0.4)),
        ("top_p", json!(0.8)),
        ("top_logprobs", json!(2)),
        ("truncation", json!("auto")),
        ("stop", json!(["END"])),
    ] {
        let mut encoded = serde_json::to_value(&base).unwrap();
        encoded["sampling"][key] = value;
        let request = serde_json::from_value(encoded).unwrap();
        assert!(
            matches!(
                validate_native_text_request(&request),
                Err(BackendError::Rejected(_))
            ),
            "accepted {key}"
        );
    }
    for format in [
        ResponseFormat::JsonObject,
        ResponseFormat::JsonSchema {
            name: None,
            schema: json!({"type":"object"}),
            strict: Some(true),
        },
        ResponseFormat::Raw(json!({"type":"custom"})),
    ] {
        let mut request = base.clone();
        request.response_format = Some(format);
        assert!(validate_native_text_request(&request).is_err());
    }
    let mut plain = base;
    plain.response_format = Some(ResponseFormat::Text);
    validate_native_text_request(&plain).unwrap();
}

#[tokio::test]
async fn anthropic_controls_are_rejected_before_submitting_a_job() {
    use serde_json::json;
    use tower::ServiceExt as _;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let router = test_router(Arc::new(open(work.clone()).await));
    for (field, value) in [
        ("temperature", json!(0.4)),
        ("top_p", json!(0.8)),
        ("stop_sequences", json!(["END"])),
    ] {
        let mut body =
            json!({"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hello"}]});
        body[field] = value;
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::post("/v1/messages")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "accepted {field}"
        );
    }
    assert!(work.jobs.lock().unwrap().is_empty());
}

fn test_router(state: Arc<TextState>) -> Router {
    let selection = crate::test_support::selection(state.execution.work.clone());
    super::router(state).layer(axum::Extension(selection))
}
