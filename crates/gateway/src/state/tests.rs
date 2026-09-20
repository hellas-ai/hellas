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

/// A gateway pointed at one node, which callers then vary.
fn options(provider_trust: Option<ProviderTrustAnchor>) -> GatewayOptions {
    GatewayOptions {
        paid_work: None,
        bearer_token_file: None,
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
        causal_lm: crate::execution::test_causal_lm_environment(8),
        #[cfg(feature = "evaluate")]
        local_content_store: None,
        tokenizer: "tokenizer.json".into(),
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
