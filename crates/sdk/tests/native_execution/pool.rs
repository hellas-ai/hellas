//! Grant pool composition over independent local providers.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::StreamExt;
use hellas_auth::authority::{GrantId, UnixMillis};
use hellas_authority::grant_service::GrantService;
use hellas_authority::model::grant::{
    budget::{Limit, Meter, Window},
    records::{Offer, SignedOffer},
};
use hellas_authority::test_support::{
    TestClock, chat_resource, common_node, definition, use_https,
};
use hellas_channel::test_support::{
    backend::{Backend, Completion, Reply},
    network, principal, software_enrollment,
};
use hellas_gateway::{WorkExecutionBackend, WorkFetchRequest};
use hellas_sdk::grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Provider {
    options: GrantSessionOptions,
    service: GrantService,
    calls: Arc<AtomicUsize>,
    resource: hellas_auth::authority::ResourceId,
    endpoint: iroh::EndpointId,
}

async fn provider(root: &Path, seed: u8, model: Option<&str>) -> Provider {
    let now = UnixMillis(1000);
    let transport = iroh::SecretKey::from_bytes(&[seed; 32]).public();
    let identity = software_enrollment(seed, *transport.as_bytes());
    let mut grant = definition(GrantId([1; 16]), principal(1).0);
    let mut template = chat_resource("https://provider.fixture", 4);
    template.accounting = hellas_authority::model::grant::resource::AccountingProfile::None;
    if let Some(model) = model {
        template.model_policy = Some(vec![
            hellas_authority::model::grant::resource::PathModelPolicy {
                path: template.paths[0].clone(),
                models: vec![model.into()],
            },
        ]);
    }
    use_https(&mut grant.policies[0], template);
    let resource = grant.policies[0].resource;
    let (store, secret) = common_node::bootstrap_node_with_credential(
        &root.join("provider"),
        network(),
        Some(identity.clone()),
        now,
    )
    .await
    .unwrap();
    let store = common_node::provision(
        &root.join("provider"),
        store,
        &secret,
        principal(seed).1,
        (
            4,
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 4,
            }],
        ),
        grant.clone(),
        (
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 1,
            }],
            2,
        ),
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let service = GrantService::new(
        store,
        Arc::new(principal(seed).1),
        Backend {
            calls: calls.clone(),
            signer: Arc::new(principal(seed).1),
            finish: Completion::Immediate,
            reply: Reply::events(Reply::http(200, "application/json", "{}")),
            ..Backend::default()
        },
        vec![],
        TestClock::default().source(),
    )
    .unwrap();
    let credential =
        common_node::execution_credential(&service.node(), &secret, principal(1).0, grant.id).await;
    let caller = hellas_authority::test_support::session(&service.node(), &secret).await;
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: identity.clone(),
            grant,
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses: vec![],
        },
        &principal(seed).1,
    )
    .unwrap();
    let target = UnpinnedOffer::decode(&offer.encode().unwrap(), now)
        .unwrap()
        .pin(&hellas_client::ProviderTrustAnchor {
            expected_genesis: identity.content_id(),
            required_assurance: hellas_rpc::Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
    let options = GrantSessionOptions {
        target,
        principal: principal(1).0,
        signer: Arc::new(principal(1).1),
        application: Arc::new(hellas_sdk::node_control::profile::ClientProfile {
            authority: caller.authority(),
            authorization: common_node::EXECUTION_AUTHORIZATION,
            credential,
            local: None,
        }),
        journal_root: root.join("client"),
        control_timeout: Duration::from_secs(5),
    };
    Provider {
        options,
        service,
        calls,
        resource,
        endpoint: transport,
    }
}

#[tokio::test]
async fn two_providers_keep_channels_budgets_and_routes_independent() {
    use hellas_sdk::grant_gateway::{GrantPool, GrantPoolChannel, GrantPoolOptions};
    let root = tempfile::tempdir().unwrap();
    let first = provider(&root.path().join("first"), 2, None).await;
    let second = provider(&root.path().join("second"), 3, None).await;
    let pool = GrantPool::open_pool(
        GrantPoolOptions {
            channels: vec![
                GrantPoolChannel {
                    session: first.options.clone(),
                    resources: vec![first.resource],
                },
                GrantPoolChannel {
                    session: second.options.clone(),
                    resources: vec![second.resource],
                },
            ],
        },
        vec![
            GrantTransport::Local(first.service.clone()),
            GrantTransport::Local(second.service.clone()),
        ],
    )
    .await
    .unwrap();
    let routes = pool.fetch_routes();
    assert_eq!(routes.len(), 2);
    assert_ne!(routes[0].channel, routes[1].channel);
    assert_ne!(routes[0].provider, routes[1].provider);
    assert_eq!(pool.http_config().unwrap().unwrap().backends.len(), 2);
    let template = first.options.target.offer().grant.policies[0]
        .https
        .as_ref()
        .unwrap();
    let http = hellas_rpc::http_fetch::HttpFetchRequest {
        url: format!("{}{}", template.origin, template.paths[0]),
        method: "POST".into(),
        headers: vec![],
        body_base64: STANDARD.encode(br#"{"model":"fixture"}"#),
        tls: template.tls.clone(),
        credential: template.credential.clone(),
        max_response_bytes: template.max_response_bytes,
    };
    let request = |provider: &Provider, channel| WorkFetchRequest {
        provider: provider.endpoint,
        resource: Some(provider.resource),
        channel: Some(channel),
        service: "openai".into(),
        method: "responses".into(),
        body: serde_json::to_vec(&http).unwrap(),
    };
    let first_channel = routes
        .iter()
        .find(|route| route.provider == first.endpoint)
        .unwrap()
        .channel
        .unwrap();
    let second_channel = routes
        .iter()
        .find(|route| route.provider == second.endpoint)
        .unwrap()
        .channel
        .unwrap();
    assert!(pool.fetch(request(&first, second_channel)).is_err());
    for (provider, channel) in [(&first, first_channel), (&second, second_channel)] {
        let mut stream = pool.fetch(request(provider, channel)).unwrap();
        while let Some(event) = stream.next().await {
            event.unwrap();
        }
    }
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    let mut exhausted = pool.fetch(request(&first, first_channel)).unwrap();
    assert!(exhausted.next().await.unwrap().is_err());
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    pool.drain().await.unwrap();
}

#[tokio::test]
async fn pool_rejects_a_channel_with_another_providers_credential() {
    use hellas_sdk::grant_gateway::{GrantPool, GrantPoolChannel, GrantPoolOptions};
    let root = tempfile::tempdir().unwrap();
    let first = provider(&root.path().join("first"), 2, None).await;
    let second = provider(&root.path().join("second"), 3, None).await;
    let mut invalid = second.options.clone();
    invalid.application = first.options.application.clone();
    let result = GrantPool::open_pool(
        GrantPoolOptions {
            channels: vec![
                GrantPoolChannel {
                    session: first.options.clone(),
                    resources: vec![first.resource],
                },
                GrantPoolChannel {
                    session: invalid,
                    resources: vec![second.resource],
                },
            ],
        },
        vec![
            GrantTransport::Local(first.service.clone()),
            GrantTransport::Local(second.service.clone()),
        ],
    )
    .await;
    assert!(result.is_err());
    assert_eq!(first.calls.load(Ordering::SeqCst), 0);
    assert_eq!(second.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pool_rejects_mixed_legacy_and_restricted_model_routes() {
    use hellas_sdk::grant_gateway::{GrantPool, GrantPoolChannel, GrantPoolOptions};
    let root = tempfile::tempdir().unwrap();
    let first = provider(&root.path().join("first"), 2, Some("alpha")).await;
    let second = provider(&root.path().join("second"), 3, None).await;
    let pool = GrantPool::open_pool(
        GrantPoolOptions {
            channels: vec![
                GrantPoolChannel {
                    session: first.options.clone(),
                    resources: vec![first.resource],
                },
                GrantPoolChannel {
                    session: second.options.clone(),
                    resources: vec![second.resource],
                },
            ],
        },
        vec![
            GrantTransport::Local(first.service.clone()),
            GrantTransport::Local(second.service.clone()),
        ],
    )
    .await
    .unwrap();
    assert!(pool.http_config().is_err());
    assert_eq!(first.calls.load(Ordering::SeqCst), 0);
    assert_eq!(second.calls.load(Ordering::SeqCst), 0);
    pool.drain().await.unwrap();
}

#[tokio::test]
async fn pool_keeps_each_signed_model_restriction_on_its_exact_resource() {
    use hellas_sdk::grant_gateway::{GrantPool, GrantPoolChannel, GrantPoolOptions};
    let root = tempfile::tempdir().unwrap();
    let first = provider(&root.path().join("first"), 2, Some("alpha")).await;
    let second = provider(&root.path().join("second"), 3, Some("beta")).await;
    let pool = GrantPool::open_pool(
        GrantPoolOptions {
            channels: vec![
                GrantPoolChannel {
                    session: first.options.clone(),
                    resources: vec![first.resource],
                },
                GrantPoolChannel {
                    session: second.options.clone(),
                    resources: vec![second.resource],
                },
            ],
        },
        vec![
            GrantTransport::Local(first.service.clone()),
            GrantTransport::Local(second.service.clone()),
        ],
    )
    .await
    .unwrap();
    let config = pool.http_config().unwrap().unwrap();
    let routes = pool.fetch_routes();
    for (provider, allowed, denied) in [(&first, "alpha", "beta"), (&second, "beta", "alpha")] {
        let backend = config
            .backends
            .values()
            .find(|backend| backend.provider == Some(provider.endpoint))
            .unwrap();
        assert_eq!(
            backend.routes[0].models.as_deref(),
            Some([allowed.to_owned()].as_slice())
        );
        let channel = routes
            .iter()
            .find(|route| route.provider == provider.endpoint)
            .unwrap()
            .channel
            .unwrap();
        let template = provider.options.target.offer().grant.policies[0]
            .https
            .as_ref()
            .unwrap();
        let request = |model: &str| {
            let http = hellas_rpc::http_fetch::HttpFetchRequest {
                url: format!("{}{}", template.origin, template.paths[0]),
                method: "POST".into(),
                headers: vec![],
                body_base64: STANDARD
                    .encode(serde_json::to_vec(&serde_json::json!({"model":model})).unwrap()),
                tls: template.tls.clone(),
                credential: template.credential.clone(),
                max_response_bytes: template.max_response_bytes,
            };
            WorkFetchRequest {
                provider: provider.endpoint,
                resource: Some(provider.resource),
                channel: Some(channel),
                service: "openai".into(),
                method: "responses".into(),
                body: serde_json::to_vec(&http).unwrap(),
            }
        };
        assert!(pool.fetch(request(denied)).is_err());
        let mut stream = pool.fetch(request(allowed)).unwrap();
        while let Some(event) = stream.next().await {
            event.unwrap();
        }
    }
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    pool.drain().await.unwrap();
}
