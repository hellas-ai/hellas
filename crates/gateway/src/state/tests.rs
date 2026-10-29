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
        ComputeEvent::Output(hellas_rpc::protocol::invocation::output::ArtifactChunk {
            offset: 0,
            ..
        })
    ));
    let terminal = {
        let terminal = live.prepared.next();
        tokio::pin!(terminal);
        assert!(futures::poll!(terminal.as_mut()).is_pending());
        payment_ack.notify_one();
        terminal.await.unwrap().unwrap()
    };
    assert!(matches!(terminal, ComputeEvent::Done { .. }));
    assert!(live.prepared.next().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn paid_capacity_is_a_retryable_error_and_uses_the_pool_deadline() {
    struct Busy;
    impl crate::WorkExecutionBackend for Busy {
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
        .err()
        .expect("busy backend must reject admission");
    assert_eq!(
        crate::backend_status(&error),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(error.to_string().contains("retry later"));
}
