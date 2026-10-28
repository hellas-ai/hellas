use super::*;

/// The tiny Qwen3 GGUF the client text package tests render.
fn text_model() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/text/package/mini-qwen3.gguf")
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
    use crate::{ExecutionEvent, Outcome, StopReason, WorkExecutionBackend};
    use futures::StreamExt;
    use hellas_rpc::protocol::invocation::Artifact;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Paid {
        calls: Arc<AtomicUsize>,
        payment_ack: Arc<tokio::sync::Notify>,
    }
    impl WorkExecutionBackend for Paid {
        fn generate(
            &self,
            job: hellas_client::text::TextJob,
        ) -> Result<crate::WorkOutputStream<ExecutionEvent>, crate::WorkGatewayError> {
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
                yield crate::WorkEvent::Output(ExecutionEvent::Chunk {
                    position: 1,
                    tokens: hellas_rpc::encode_token_ids(&[1]),
                });
                // Match the paid backend contract: an authenticated prefix is
                // available before durable payment, but its terminal is not.
                payment_ack.notified().await;
                yield crate::WorkEvent::Output(ExecutionEvent::Done(Outcome::Completed {
                    output_tokens: 1,
                    stop_reason: StopReason::MaxNewTokens,
                    text_artifact: hellas_auth::Digest::from_bytes([7; 32]),
                }));
            }))
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
    let mut live = state.prepare_ids(vec![0], 1, None).unwrap();
    let prefix = live.prepared.next().await.unwrap().unwrap();
    assert!(matches!(
        prefix,
        crate::WorkEvent::Output(ExecutionEvent::Chunk { position: 1, .. })
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
        crate::WorkEvent::Output(ExecutionEvent::Done(Outcome::Completed { .. }))
    ));
    assert!(live.prepared.next().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn paid_capacity_is_a_retryable_error_and_uses_the_pool_deadline() {
    struct Busy;
    impl crate::WorkExecutionBackend for Busy {
        fn timeout(&self) -> Duration {
            Duration::from_secs(17)
        }
        fn generate(
            &self,
            _: hellas_client::text::TextJob,
        ) -> Result<crate::WorkOutputStream<crate::ExecutionEvent>, crate::WorkGatewayError>
        {
            Err(crate::WorkGatewayBusy.into())
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }
    let state = open(Arc::new(Busy)).await;
    assert_eq!(state.inference_timeout, Duration::from_secs(17));
    let error = state
        .prepare_ids(vec![0], 1, None)
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
    fn generate(
        &self,
        _: hellas_client::text::TextJob,
    ) -> Result<crate::WorkOutputStream<ExecutionEvent>, crate::WorkGatewayError> {
        use crate::{Outcome, StopReason, WorkEvent};
        Ok(Box::pin(futures::stream::iter([
            Ok(WorkEvent::Accepted(self.provenance.clone())),
            Ok(WorkEvent::Output(ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[1]),
            })),
            Ok(WorkEvent::Transcript(self.transcript.clone())),
            Ok(WorkEvent::Output(ExecutionEvent::Done(
                Outcome::Completed {
                    output_tokens: 1,
                    stop_reason: StopReason::MaxNewTokens,
                    text_artifact: hellas_auth::Digest::from_bytes([7; 32]),
                },
            ))),
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
