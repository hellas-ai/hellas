use super::*;
use hellas_client::ProviderTrustAnchor;
use iroh::EndpointId;
use std::str::FromStr;

fn endpoint(byte: u8) -> EndpointId {
    match byte {
        1 => {
            EndpointId::from_str("bb18ebc065d836ecc7e1f33972d2c17eac9894cd33ce4916f66cb1165ccc7550")
                .expect("valid endpoint id")
        }
        2 => {
            EndpointId::from_str("edfadcefb3917925de1111087f11925542c97e14ab00cf42b9447f7567a25b62")
                .expect("valid endpoint id")
        }
        _ => panic!("unknown test endpoint"),
    }
}

/// The tiny Qwen3 GGUF the client text package tests render.
fn text_model() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../client/src/text/package/mini-qwen3.gguf")
}

/// A gateway pointed at one node, which callers then vary.
async fn options(
    provider_trust: Option<ProviderTrustAnchor>,
) -> (tempfile::TempDir, GatewayOptions) {
    let fixture = crate::access::tests::Fixture::new().await;
    (
        fixture.root,
        GatewayOptions {
            archive: super::super::ArchiveOptions {
                directory: "unused-test-archive".into(),
                zdr: true,
            },
            output_cache: Default::default(),
            paid_work: None,
            access: fixture.access,
            allow_remote: false,
            host: "127.0.0.1".to_string(),
            port: None,
            node_id: Some(endpoint(1)),
            node_addrs: Vec::new(),
            retries: 2,
            default_max_tokens: 128,
            model_name: "smollm2-135m".to_string(),
            text_model: Some(text_model()),
            metrics_port: None,
            responses_backend: ResponsesBackend::Hellas,
            responses_proxy_url: String::new(),
            responses_proxy_api_key_env: String::new(),
            responses_fetch_route_service: String::new(),
            responses_fetch_route_method: String::new(),
            responses_fetch_execution_environment: None,
            responses_fetch_request_overrides: Default::default(),
            provider_trust,
            producer_key: hellas_auth::ProducerSigningKey::from_secret_bytes([3; 32])
                .expect("valid test key"),
            assurance: hellas_rpc::Assurance::ProducerSigned,
            secret_key: iroh::SecretKey::from([5; 32]),
            wrap: None,
            wrap_args: Vec::new(),
        },
    )
}

#[cfg(unix)]
#[tokio::test]
async fn proxy_without_text_model_does_not_bind_remote_transport() {
    let (_root, mut options) = options(None).await;
    options.text_model = None;
    options.responses_backend = ResponsesBackend::Proxy;
    options.responses_proxy_url = "http://127.0.0.1:1/v1/responses".into();
    let state = GatewayState::from_options(&options).await.unwrap();
    assert!(state.responses_proxy.is_some());
}

#[tokio::test]
async fn paid_generation_records_after_payment_and_replays_without_a_backend() {
    use crate::{ExecutionEvent, Outcome, StopReason, WorkExecutionBackend};
    use futures::{StreamExt, TryStreamExt};
    use hellas_rpc::cache::{CacheOptions, CachePolicy, CacheStore, MemoryCacheStore};
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
                yield ExecutionEvent::Chunk {
                    position: 1,
                    tokens: hellas_rpc::encode_token_ids(&[1]),
                };
                // Match the paid backend contract: an authenticated prefix is
                // available before durable payment, but its terminal is not.
                payment_ack.notified().await;
                yield ExecutionEvent::Done(Outcome::Completed {
                    output_tokens: 1,
                    stop_reason: StopReason::MaxNewTokens,
                    text_artifact: hellas_auth::Digest::from_bytes([7; 32]),
                    output_events: Vec::new(),
                });
            }))
        }

        fn drain(&self) -> futures::future::BoxFuture<'_, Result<(), crate::WorkShutdownError>> {
            Box::pin(async { Ok(()) })
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let payment_ack = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(MemoryCacheStore::default());
    let (_root, mut options) = options(None).await;
    options.paid_work = Some(Arc::new(Paid {
        calls: calls.clone(),
        payment_ack: payment_ack.clone(),
    }));
    options.output_cache = CacheOptions {
        policy: CachePolicy::Record,
        store: Some(store.clone()),
    };
    let state = GatewayState::from_options(&options).await.unwrap();
    let mut live = state
        .finalize_generation(vec![0], 1, "paid fixture", Retention::Ephemeral)
        .await
        .unwrap();
    let prefix = live.prepared.next().await.unwrap().unwrap();
    assert!(matches!(prefix, ExecutionEvent::Chunk { position: 1, .. }));
    assert!(store.list().unwrap().is_empty());
    let terminal = {
        let terminal = live.prepared.next();
        tokio::pin!(terminal);
        assert!(futures::poll!(terminal.as_mut()).is_pending());
        assert!(
            store.list().unwrap().is_empty(),
            "payment is not acknowledged"
        );
        payment_ack.notify_one();
        terminal.await.unwrap().unwrap()
    };
    assert!(matches!(
        terminal,
        ExecutionEvent::Done(Outcome::Completed { .. })
    ));
    assert!(live.prepared.next().await.is_none());
    assert_eq!(store.list().unwrap().len(), 1);
    let recorded = serde_json::to_value([prefix, terminal]).unwrap();

    let cached = state
        .finalize_generation(vec![0], 1, "paid fixture", Retention::Ephemeral)
        .await
        .unwrap()
        .prepared
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(cached).unwrap(), recorded);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Replay uses the ordinary native path, with no paid backend or remote
    // runtime, and must read exactly the schema recorded by the paid path.
    options.output_cache.policy = CachePolicy::ReplayOnly;
    let offline = GatewayState::from_options(&options).await.unwrap();
    assert!(offline.paid_work.is_none());
    let replayed = offline
        .finalize_generation(vec![0], 1, "paid fixture", Retention::Ephemeral)
        .await
        .unwrap()
        .prepared
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(replayed).unwrap(), recorded);
    let miss = offline
        .finalize_generation(vec![1], 1, "paid fixture", Retention::Ephemeral)
        .await
        .err()
        .expect("changed input must miss without paid execution");
    assert!(miss.message.contains("replay miss"));
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
    let (_root, mut options) = options(None).await;
    options.paid_work = Some(Arc::new(Busy));
    let state = GatewayState::from_options(&options).await.unwrap();
    assert_eq!(state.inference_timeout, Duration::from_secs(17));
    let error = state
        .finalize_generation(vec![0], 1, "capacity", Retention::Ephemeral)
        .await
        .err()
        .expect("busy backend must reject admission");
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.message.contains("retry later"));
}
