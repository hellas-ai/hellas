use super::*;

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
        work,
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
        fn evaluator(&self) -> Option<String> {
            Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            ))
        }
        fn run(
            &self,
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
    let mut live = state.prepare_ids(vec![0], 1, None).await.unwrap();
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
async fn paid_capacity_is_a_retryable_error_and_uses_the_pool_deadline() {
    struct Busy;
    impl crate::WorkExecutionBackend for Busy {
        fn evaluator(&self) -> Option<String> {
            Some(hellas_client::model::evaluator(
                hellas_client::model::GpuDialect::Hip,
            ))
        }
        fn timeout(&self) -> Option<Duration> {
            Some(Duration::from_secs(17))
        }
        fn run(
            &self,
            _: hellas_client::model::ComputeJob,
        ) -> Result<crate::WorkOutputStream<crate::ComputeEvent>, crate::WorkGatewayError> {
            Err(crate::WorkGatewayBusy.into())
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let state = open(Arc::new(Busy)).await;
    assert_eq!(state.inference_timeout, Some(Duration::from_secs(17)));
    let error = state
        .prepare_ids(vec![0], 1, None)
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
    fn evaluator(&self) -> Option<String> {
        Some(hellas_client::model::evaluator(
            hellas_client::model::GpuDialect::Hip,
        ))
    }
    fn run(
        &self,
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
    let app = super::router(state).layer(crate::provenance_layer::ProvenanceLayer);
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
                // The response names the model the request named, not the
                // served file, and a spent budget is the format's length stop.
                assert_eq!(body["model"], "m", "{what}");
                let stop = match path {
                    "/v1/messages" => &body["stop_reason"],
                    "/v1/responses" => &body["incomplete_details"]["reason"],
                    _ => &body["choices"][0]["finish_reason"],
                };
                let expected = match path {
                    "/v1/messages" => "max_tokens",
                    "/v1/responses" => "max_output_tokens",
                    _ => "length",
                };
                assert_eq!(stop, expected, "{what}: {body}");
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
    fn evaluator(&self) -> Option<String> {
        Some(hellas_client::model::evaluator(
            hellas_client::model::GpuDialect::Hip,
        ))
    }
    fn run(
        &self,
        job: hellas_client::model::ComputeJob,
    ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
        self.jobs.lock().unwrap().push(job);
        Ok(Box::pin(futures::stream::empty()))
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
        state.prepare_wire_execution(&request).await.unwrap();
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
    let prepare =
        async |request: &WireExecutionRequest| state.prepare_wire_execution(request).await;

    // Native execution decodes greedily: temperature 0 is what it does.
    prepare(&chat(json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 1,
        "temperature": 0
    })))
    .await
    .unwrap();
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
    let response = super::router(state)
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
        .prepare_wire_execution(&request(json!({
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
        })))
        .await
        .err()
        .expect("a strict schema must be rejected");
    assert!(matches!(error, BackendError::Rejected(_)));
    assert!(error.to_string().contains("json_schema"), "{error}");

    state
        .prepare_wire_execution(&request(json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 1
        })))
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
    let router = super::router(Arc::new(open(work.clone()).await));
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

/// A budget beyond the work source's terms is cut to them rather than
/// refused, and the job stops at that bound as at any token budget.
#[tokio::test]
async fn output_budgets_are_cut_to_the_terms() {
    use hellas_adaptors::{RawRequest, WireAdaptor, anthropic::AnthropicMessagesAdaptor};
    use serde_json::json;

    struct Bounded(Capturing);
    impl WorkExecutionBackend for Bounded {
        fn evaluator(&self) -> Option<String> {
            self.0.evaluator()
        }
        fn max_steps(&self) -> Option<u64> {
            Some(3)
        }
        fn run(
            &self,
            job: hellas_client::model::ComputeJob,
        ) -> Result<crate::WorkOutputStream<ComputeEvent>, crate::WorkGatewayError> {
            self.0.run(job)
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            self.0.drain()
        }
    }

    let work = Arc::new(Bounded(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    }));
    let state = open(work.clone()).await;
    let adaptor = AnthropicMessagesAdaptor;
    for max_tokens in [128_000, 2] {
        let parsed = adaptor
            .parse(
                RawRequest::from_value(json!({
                    "model": "m", "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": "hi"}]
                }))
                .unwrap(),
            )
            .unwrap();
        state
            .prepare_wire_execution(&adaptor.to_execution_request(&parsed).unwrap())
            .await
            .unwrap();
    }
    let jobs = work.0.jobs.lock().unwrap();
    let steps = jobs
        .iter()
        .map(|job| job.plan.step.as_ref().unwrap().stop.max_steps)
        .collect::<Vec<_>>();
    assert_eq!(steps, [3, 2]);
}

/// A backend that streams some text, then fails the way an undecodable
/// tool call does.
struct Undecodable;

impl hellas_adaptors::ExecutionBackend for Undecodable {
    fn stream<'a>(
        &'a self,
        _: hellas_adaptors::BackendRequest,
    ) -> hellas_adaptors::BackendFuture<'a, hellas_adaptors::BackendStream> {
        Box::pin(async {
            Ok(hellas_adaptors::BackendStream::new(
                futures::stream::iter([
                    Ok(hellas_adaptors::OutputEvent::TextDelta {
                        index: 0,
                        delta: "Checking".into(),
                        channel: hellas_adaptors::TextChannel::Output,
                    }
                    .into()),
                    Err(BackendError::Output(
                        "model tool call at <tool_call> could not be decoded".into(),
                    )),
                ]),
                None,
            ))
        })
    }
}

/// The same request fails the same way again, so a decode failure is no
/// retryable server error: 422 before the stream, and the matching error type
/// or code once it has begun.
#[tokio::test]
async fn undecodable_output_is_reported_as_unprocessable() {
    use hellas_adaptors::{
        anthropic::AnthropicMessagesAdaptor, openai::responses::OpenAiResponsesAdaptor,
    };
    use serde_json::json;

    async fn body(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }
    let last_event = |sse: &str| -> serde_json::Value {
        sse.lines()
            .rev()
            .filter_map(|line| line.strip_prefix("data: "))
            .find_map(|data| serde_json::from_str(data).ok())
            .unwrap()
    };
    let context = || crate::dispatch::render_context("t");
    let messages = json!({"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]});
    let responses = json!({"model":"m","input":"hi"});
    for stream in [false, true] {
        let mut request = messages.clone();
        request["stream"] = json!(stream);
        let response = crate::dispatch::serve(
            AnthropicMessagesAdaptor,
            "Anthropic Messages",
            context(),
            Undecodable,
            &serde_json::to_vec(&request).unwrap(),
        )
        .await;
        let status = response.status();
        let text = body(response).await;
        let error = if stream {
            assert_eq!(status, axum::http::StatusCode::OK);
            last_event(&text)
        } else {
            assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
            serde_json::from_str(&text).unwrap()
        };
        assert_eq!(error["error"]["type"], "invalid_request_error", "{text}");

        let mut request = responses.clone();
        request["stream"] = json!(stream);
        let response = crate::dispatch::serve(
            OpenAiResponsesAdaptor,
            "OpenAI Responses",
            context(),
            Undecodable,
            &serde_json::to_vec(&request).unwrap(),
        )
        .await;
        let status = response.status();
        let text = body(response).await;
        if stream {
            assert_eq!(status, axum::http::StatusCode::OK);
            assert_eq!(
                last_event(&text)["response"]["error"]["code"],
                "invalid_prompt",
                "{text}"
            );
        } else {
            assert_eq!(
                status,
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "{text}"
            );
        }
    }
}

/// opencode titles a session at temperature 0.5. Greedy decoding cannot
/// honour it, so the request is refused, before any job, as a request error
/// that names the control; a session's own requests carry no temperature.
#[tokio::test]
async fn sampled_temperatures_are_refused_by_name() {
    use tower::ServiceExt as _;

    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let response = super::router(Arc::new(open(work.clone()).await))
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    &include_bytes!(
                        "../../../adaptors/tests/fixtures/agents/opencode-responses-title.json"
                    )[..],
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
    let message = body["error"]["message"].as_str().unwrap();
    assert!(message.contains("`temperature` 0.5"), "{message}");
    assert!(work.jobs.lock().unwrap().is_empty());
}

/// A captured session request must reach the work backend with its tools and
/// structured input accepted, rather than just surviving adaptor parsing.
#[tokio::test]
async fn opencode_session_creates_a_job() {
    use tower::ServiceExt as _;
    let work = Arc::new(Capturing {
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    // The packaging fixture's 128-token context cannot fit the captured
    // tool schemas plus the default output budget. Enlarge its context only.
    let mut model = std::fs::read(text_model()).unwrap();
    let key = b"qwen3.context_length";
    let offset = model
        .windows(key.len())
        .position(|bytes| bytes == key)
        .unwrap()
        + key.len()
        + 4;
    assert_eq!(&model[offset..offset + 4], &128u32.to_le_bytes());
    model[offset..offset + 4].copy_from_slice(&8192u32.to_le_bytes());
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), model).unwrap();
    let state = TextState::open(
        &crate::TextOptions {
            model: file.path().to_owned(),
            model_name: "mini-qwen3".into(),
            default_max_tokens: 128,
        },
        work.clone(),
    )
    .await
    .unwrap();
    let response = super::router(Arc::new(state))
        .oneshot(
            axum::http::Request::post("/v1/responses")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    &include_bytes!(
                        "../../../adaptors/tests/fixtures/agents/opencode-responses.json"
                    )[..],
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    // Capturing intentionally has no output; request admission already ran.
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let jobs = work.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 1, "{}", String::from_utf8_lossy(&bytes));
    assert!(!jobs[0].inputs[0].bytes.as_bytes().is_empty());
    assert_eq!(jobs[0].plan.step.as_ref().unwrap().stop.max_steps, 128);
}
