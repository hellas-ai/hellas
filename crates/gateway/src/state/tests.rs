use super::*;
use hellas_client::ProviderTrustAnchor;
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

fn anchor() -> ProviderTrustAnchor {
    ProviderTrustAnchor {
        expected_genesis: hellas_rpc::ContentId::from_bytes([9; 32]),
        required_assurance: hellas_rpc::Assurance::ProducerSigned,
        apple_app_attest: None,
    }
}

fn test_environment() -> CausalLmExecutionEnvironment {
    let environment = hellas_rpc::CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(hellas_rpc::ContentId::from_bytes([8; 32]), 1024),
        "model",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        256,
        1024,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 1024,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let manifest = environment.manifest();
    CausalLmExecutionEnvironment::from_canonical_bytes(
        manifest.content_id(),
        manifest.canonical_bytes(),
        environment.canonical_bytes(),
    )
    .unwrap()
}

/// A gateway pointed at one node, which callers then vary.
fn options(provider_trust: Option<ProviderTrustAnchor>) -> GatewayOptions {
    GatewayOptions {
        archive: super::super::ArchiveOptions {
            directory: "unused-test-archive".into(),
            zdr: true,
        },
        http_fetch: None,
        output_cache: Default::default(),
        paid_work: None,
        bearer_token_file: None,
        allow_remote: false,
        host: "127.0.0.1".to_string(),
        port: None,
        node_id: Some(endpoint(1)),
        node_addrs: Vec::new(),
        #[cfg(feature = "evaluate")]
        local: false,
        #[cfg(feature = "evaluate")]
        verify_local: false,
        verify: None,
        #[cfg(feature = "evaluate")]
        queue_size: 1,
        retries: 2,
        default_max_tokens: 128,
        model_name: "smollm2-135m".to_string(),
        causal_lm: Some(test_environment()),
        #[cfg(feature = "evaluate")]
        local_content_store: None,
        tokenizer: Some("tokenizer.json".into()),
        chat_template: None,
        stop_token_ids: Vec::new(),
        metrics_port: None,
        responses_backend: ResponsesBackend::Hellas,
        responses_proxy_url: String::new(),
        responses_proxy_api_key_env: String::new(),
        responses_fetch_route_service: String::new(),
        responses_fetch_route_method: String::new(),
        responses_fetch_execution_environment: None,
        responses_fetch_request_overrides: Default::default(),
        provider_trust,
        producer_key: hellas_rpc::ProducerSigningKey::from_secret_bytes([3; 32])
            .expect("valid test key"),
        #[cfg(feature = "evaluate")]
        provider_genesis: Vec::new(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        secret_key: iroh::SecretKey::from([5; 32]),
        wrap: None,
        wrap_args: Vec::new(),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn local_control_clear_resets_a_running_gateway_cache() {
    use hellas_rpc::cache::control::CacheController;
    use hellas_rpc::cache::{CacheOptions, CachePolicy, MemoryCacheStore};
    use hellas_rpc::pb::host as pb;
    use hellas_rpc::services::cache_control::{CacheControlClientImpl, CacheControlServer};
    use hellas_wire::unix::{LocalControlServer, connect};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = Arc::new(AtomicUsize::new(0));
    let upstream = axum::Router::new().route("/v1/responses", axum::routing::post({
        let calls = calls.clone();
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            async {
                ([("content-type", "text/event-stream")], r#"event: response.output_item.added
data: {"type":"response.output_item.added","item":{"content":[],"id":"msg_1","role":"assistant","status":"in_progress","type":"message"}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","item_id":"msg_1","delta":"hello"}

event: response.output_text.done
data: {"type":"response.output_text.done","item_id":"msg_1","text":"hello"}

event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}

"#)
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let mut options = options(None);
    options.causal_lm = None;
    options.tokenizer = None;
    options.node_id = None;
    options.port = Some(0);
    options.responses_backend = ResponsesBackend::Proxy;
    options.responses_proxy_url = format!("http://{upstream_address}/v1/responses");
    options.output_cache = CacheOptions {
        policy: CachePolicy::Record,
        store: Some(Arc::new(MemoryCacheStore::default())),
    };
    let directory = tempfile::tempdir().unwrap();
    options.archive = crate::ArchiveOptions {
        directory: directory.path().join("archive"),
        zdr: false,
    };
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("control.sock");
    let _control = LocalControlServer::bind(
        &socket,
        CacheControlServer(CacheController::new(&options.output_cache)),
    )
    .unwrap();
    let control = CacheControlClientImpl::new(connect(&socket).await.unwrap());
    let gateway = crate::start(options).await.unwrap();
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    for (index, expected_calls) in [1, 1, 2].into_iter().enumerate() {
        let response = http
            .post(format!("http://{}/v1/responses", gateway.address()))
            .bearer_auth(gateway.bearer())
            .header("content-type", "application/json")
            .body(r#"{"model":"m","input":"hello","stream":false}"#)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["output"][0]["content"][0]["text"], "hello");
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        if index == 1 {
            let mut call = control
                .manage_cache(pb::ManageCacheRequest {
                    operation: Some(pb::manage_cache_request::Operation::Evict(
                        pb::EvictCacheEntries {
                            all: true,
                            ..Default::default()
                        },
                    )),
                })
                .await
                .unwrap();
            while let Some(reply) = futures::StreamExt::next(&mut call).await {
                reply.unwrap();
            }
            call.finish().unwrap();
        }
    }
    gateway.shutdown().await.unwrap();
    upstream.abort();
}

/// Fails the day a remote route becomes constructible without the
/// anchor the provider on it is verified against. Direct dial,
/// discovery, and the verification shadow are each a provider dialled
/// at run time, so each one alone is enough to withhold the strategy.
#[test]
fn every_remote_route_requires_a_provider_trust_anchor() {
    let direct = options(None);
    assert!(configured_strategy(&direct).is_none());

    let mut discovery = options(None);
    discovery.node_id = None;
    assert!(configured_strategy(&discovery).is_none());

    let mut verified = options(None);
    verified.verify = Some(endpoint(2));
    assert!(configured_strategy(&verified).is_none());

    // The same three configurations, with an anchor to dial against.
    assert!(configured_strategy(&options(Some(anchor()))).is_some());
    discovery.provider_trust = Some(anchor());
    assert!(configured_strategy(&discovery).is_some());
    verified.provider_trust = Some(anchor());
    assert!(configured_strategy(&verified).is_some());
}

#[test]
fn execution_strategy_uses_remote_shadow_for_verify_node() {
    let mut options = options(Some(anchor()));
    options.verify = Some(endpoint(2));
    assert_eq!(
        configured_strategy(&options),
        Some(ExecutionStrategy::Verify {
            primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(endpoint(1), anchor(),)),
            shadow: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(endpoint(2), anchor(),)),
        })
    );
}

#[cfg(feature = "evaluate")]
#[test]
fn execution_strategy_uses_local_shadow_for_verify_local() {
    let mut options = options(Some(anchor()));
    options.verify_local = true;
    assert_eq!(
        configured_strategy(&options),
        Some(ExecutionStrategy::Verify {
            primary: ExecutionRoute::RemoteDirect(RemoteNodeTarget::direct(endpoint(1), anchor(),)),
            shadow: ExecutionRoute::Local,
        })
    );
}

/// Local execution dials nobody, so it is the one route that runs
/// without an anchor.
#[cfg(feature = "evaluate")]
#[test]
fn execution_strategy_uses_local_run_when_local_is_enabled() {
    let mut options = options(None);
    options.node_id = None;
    options.local = true;
    assert_eq!(
        configured_strategy(&options),
        Some(ExecutionStrategy::Run(ExecutionRoute::Local))
    );
}

#[cfg(feature = "evaluate")]
#[test]
fn pure_local_runtime_does_not_bind_remote_transport() {
    let mut options = options(None);
    options.local = true;
    assert!(!local_runtime_needs_remote(&options));

    options.verify_local = true;
    assert!(local_runtime_needs_remote(&options));

    options.verify_local = false;
    options.responses_backend = ResponsesBackend::Fetch;
    assert!(local_runtime_needs_remote(&options));
}

#[tokio::test]
async fn proxy_with_causal_lm_keeps_remote_runtime_except_in_replay_only() {
    use hellas_rpc::cache::{CacheOptions, CachePolicy, MemoryCacheStore};

    let tokenizer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tokenizer.path(),
        br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#,
    )
    .unwrap();

    for policy in [
        CachePolicy::Off,
        CachePolicy::Record,
        CachePolicy::ReplayOnly,
    ] {
        let mut options = options(Some(anchor()));
        options.responses_backend = ResponsesBackend::Proxy;
        options.responses_proxy_url = "http://127.0.0.1:1/v1/responses".into();
        options.tokenizer = Some(tokenizer.path().into());
        options.output_cache = CacheOptions {
            policy,
            store: Some(Arc::new(MemoryCacheStore::default())),
        };
        let state = GatewayState::from_options(&options).await.unwrap();
        assert!(state.responses_proxy.is_some());
        assert_eq!(
            state.runtime.remote_registry().is_ok(),
            policy != CachePolicy::ReplayOnly,
            "{policy:?}"
        );
        assert_eq!(
            state.execution_strategy().unwrap(),
            if policy == CachePolicy::ReplayOnly {
                ExecutionStrategy::Replay
            } else {
                configured_strategy(&options).unwrap()
            }
        );
        state.runtime.close_remote().await;
    }
}

#[tokio::test]
async fn proxy_without_causal_lm_does_not_bind_remote_transport() {
    let mut options = options(None);
    options.causal_lm = None;
    options.tokenizer = None;
    options.responses_backend = ResponsesBackend::Proxy;
    options.responses_proxy_url = "http://127.0.0.1:1/v1/responses".into();
    let state = GatewayState::from_options(&options).await.unwrap();
    assert!(state.responses_proxy.is_some());
    assert!(state.runtime.remote_registry().is_err());
}

#[tokio::test]
async fn paid_generation_records_after_payment_and_replays_without_a_backend() {
    use crate::{ExecutionEvent, Outcome, PaidExecutionBackend, PaidExecutionRequest, StopReason};
    use futures::{StreamExt, TryStreamExt};
    use hellas_rpc::cache::{CacheOptions, CachePolicy, CacheStore, MemoryCacheStore};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Paid {
        calls: Arc<AtomicUsize>,
        payment_ack: Arc<tokio::sync::Notify>,
    }
    impl PaidExecutionBackend for Paid {
        fn execute(
            &self,
            request: PaidExecutionRequest,
        ) -> anyhow::Result<futures::stream::BoxStream<'static, anyhow::Result<ExecutionEvent>>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.input_ids, vec![0]);
            assert_eq!(request.max_new_tokens, 1);
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
                    total_tokens: 2,
                    stop_reason: StopReason::MaxNewTokens,
                    text_artifact: hellas_rpc::Digest::from_bytes([7; 32]),
                    output_events: Vec::new(),
                });
            }))
        }

        fn drain(&self) -> futures::future::BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    let tokenizer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tokenizer.path(),
        br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#,
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let payment_ack = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(MemoryCacheStore::default());
    let mut options = options(None);
    options.tokenizer = Some(tokenizer.path().into());
    options.paid_work = Some(Arc::new(Paid {
        calls: calls.clone(),
        payment_ack: payment_ack.clone(),
    }));
    options.output_cache = CacheOptions {
        policy: CachePolicy::Record,
        store: Some(store.clone()),
    };
    let state = GatewayState::from_options(&options).await.unwrap();
    assert!(state.runtime.remote_registry().is_err());
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
    assert!(offline.runtime.remote_registry().is_err());
    assert_eq!(
        offline.execution_strategy().unwrap(),
        ExecutionStrategy::Replay
    );
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
    impl crate::PaidExecutionBackend for Busy {
        fn timeout(&self) -> Duration {
            Duration::from_secs(17)
        }
        fn execute(
            &self,
            _: crate::PaidExecutionRequest,
        ) -> anyhow::Result<
            futures::stream::BoxStream<'static, anyhow::Result<crate::ExecutionEvent>>,
        > {
            Err(crate::PaidGatewayBusy.into())
        }
        fn drain(&self) -> futures::future::BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }
    let tokenizer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tokenizer.path(),
        br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#,
    ).unwrap();
    let mut options = options(None);
    options.tokenizer = Some(tokenizer.path().into());
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
