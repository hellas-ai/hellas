//! Grant session execution through public SDK APIs, without an HTTP listener.
use hellas_auth::authority::{GrantId, UnixMillis};
use hellas_authority::grant_service::GrantService;
use hellas_authority::model::grant::budget::{Limit, Meter, Window};
use hellas_authority::model::grant::records::{Offer, SignedOffer};
use hellas_authority::test_support::{TestClock, common_node, definition};
use hellas_channel::content::InvocationContent;
use hellas_channel::test_support::backend::{Backend, Completion, Reply};
use hellas_channel::test_support::{
    network, principal, software_enrollment, test_responses_contract,
};
use hellas_client::ProviderTrustAnchor;
use hellas_rpc::{Assurance, Retention};
use hellas_sdk::grant_client::{GrantSession, GrantSessionOptions, GrantTransport, UnpinnedOffer};
use hellas_sdk::node_control::profile::ClientProfile;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Semaphore;

#[tokio::test]
async fn local_grant_session_executes_without_http() {
    let root = tempfile::tempdir().unwrap();
    let now = UnixMillis(1000);
    let identity = |seed| {
        software_enrollment(
            seed,
            *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes(),
        )
    };
    let provider = identity(2);
    let grant = definition(GrantId([1; 16]), principal(1).0);
    let (store, secret) = common_node::bootstrap_node_with_credential(
        &root.path().join("provider"),
        network(),
        Some(provider.clone()),
        now,
    )
    .await
    .unwrap();
    let store = common_node::provision(
        &root.path().join("provider"),
        store,
        &secret,
        principal(2).1,
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
                amount: 3,
            }],
            2,
        ),
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Backend {
        slots: Arc::new(Semaphore::new(2)),
        calls: calls.clone(),
        finish: Completion::Immediate,
        reply: Reply::text("fixture output", 1),
        ..Backend::default()
    };
    let clock = TestClock::default();
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        backend,
        vec![],
        clock.source(),
    )
    .unwrap();
    let credential =
        common_node::execution_credential(&service.node(), &secret, principal(1).0, grant.id).await;
    let caller = hellas_authority::test_support::session(&service.node(), &secret).await;
    let profile = Arc::new(ClientProfile {
        authority: caller.authority(),
        authorization: common_node::EXECUTION_AUTHORIZATION,
        credential,
        local: None,
    });
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.clone(),
            grant: grant.clone(),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap();
    let target = UnpinnedOffer::decode(&offer.encode().unwrap(), now)
        .unwrap()
        .pin(&ProviderTrustAnchor {
            expected_genesis: provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
    let mut session = GrantSession::open(
        GrantSessionOptions {
            target,
            principal: principal(1).0,
            signer: Arc::new(principal(1).1),
            application: profile,
            journal_root: root.path().join("client"),
            control_timeout: Duration::from_secs(5),
        },
        GrantTransport::Local(service),
    )
    .await
    .unwrap();
    let contract = test_responses_contract();
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        "openai",
        "responses",
        br#"{"model":"fixture","input":"fixture","max_output_tokens":8}"#,
        contract.manifest_id(),
        Assurance::ProducerSigned,
        &principal(1).1,
        Retention::Ephemeral,
    )
    .unwrap();
    let input = hellas_rpc::protocol::invocation::fetch::prepare(
        &events,
        &contract,
        hellas_auth::PublicKey::Secp256k1(
            hellas_authority::model::grant::records::grant_producer(&provider)
                .unwrap()
                .to_bytes(),
        ),
        grant.policies[0]
            .invocation_policy
            .canonical_bytes()
            .unwrap(),
        [1; 32],
    )
    .unwrap();
    let result = session
        .run(
            "responses",
            input,
            &InvocationContent::Ephemeral(Default::default()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.events.len(), 2);
    session.shutdown().await.unwrap();
}
