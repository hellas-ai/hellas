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
async fn proxy_does_not_bind_remote_transport() {
    let (_root, mut options) = options(None).await;
    options.responses_backend = ResponsesBackend::Proxy;
    options.responses_proxy_url = "http://127.0.0.1:1/v1/responses".into();
    let state = GatewayState::from_options(&options).await.unwrap();
    assert!(state.responses_proxy.is_some());
}
