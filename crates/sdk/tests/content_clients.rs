//! Native/remote client cutover through the actual generic Content upload path.
use hellas_auth::{
    ProducerSigningKey,
    authority::{GrantId, UnixMillis},
};
use hellas_authority::{
    grant_service::GrantService,
    model::grant::records::{GrantDef, Offer, SignedOffer},
    test_support as common,
};
use hellas_channel::test_support::{
    backend::{Backend, Completion, Reply},
    network, principal,
};
use hellas_rpc::{
    Assurance, Retention,
    protocol::invocation::{PreparedInvocation, compute},
};
use hellas_sdk::{
    grant_client::{GrantSession, GrantSessionOptions, GrantTransport, UnpinnedOffer},
    node_control::profile::ClientProfile,
};
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Fixture {
    root: tempfile::TempDir,
    service: GrantService,
    node_content: hellas_store::content::DiskStore,
    grant: GrantDef,
    enrollment: hellas_rpc::ProviderEnrollmentBundle,
    application: Arc<ClientProfile>,
    calls: Arc<AtomicUsize>,
    now: UnixMillis,
}
impl Fixture {
    async fn new(compute: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let provider_root = root.path().join("provider");
        let enrollment = hellas_channel::test_support::software_enrollment(
            2,
            *iroh::SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
        );
        let (store, secret) = common::common_node::bootstrap_node_with_credential(
            &provider_root,
            network(),
            Some(enrollment.clone()),
            UnixMillis(1000),
        )
        .await
        .unwrap();
        let mut grant = common::definition(GrantId([1; 16]), principal(1).0);
        if compute {
            grant.policies = vec![common::compute::Compute.policy()];
        }
        let store = common::common_node::provision(
            &provider_root,
            store,
            &secret,
            principal(2).1,
            (4, vec![]),
            grant.clone(),
            (vec![], 2),
        )
        .await;
        let now = UnixMillis::now().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Backend {
            calls: calls.clone(),
            finish: Completion::Immediate,
            reply: Reply::text("sdk-private-output", 1),
            ..Backend::default()
        };
        let node_content = common::content_store(&provider_root).await;
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend,
            vec![],
            Arc::new(move || now),
            node_content.clone(),
        )
        .unwrap();
        let credential = common::common_node::execution_credential(
            &service.node(),
            &secret,
            principal(1).0,
            grant.id,
        )
        .await;
        let caller = common::session(&service.node(), &secret).await;
        let application = Arc::new(ClientProfile {
            authority: caller.authority(),
            authorization: common::common_node::EXECUTION_AUTHORIZATION,
            credential,
            local: None,
        });
        Self {
            root,
            service,
            node_content,
            grant,
            enrollment,
            application,
            calls,
            now,
        }
    }
    fn options(&self, addresses: Vec<String>) -> GrantSessionOptions {
        let signed = SignedOffer::sign(
            Offer {
                network: network(),
                provider: self.enrollment.clone(),
                grant: self.grant.clone(),
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(self.now.0 + 1_000_000),
                addresses,
            },
            &principal(2).1,
        )
        .unwrap();
        let target = UnpinnedOffer::decode(&signed.encode().unwrap(), self.now)
            .unwrap()
            .pin(&hellas_client::ProviderTrustAnchor {
                expected_genesis: self.enrollment.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            })
            .unwrap();
        GrantSessionOptions {
            target,
            principal: principal(1).0,
            signer: Arc::new(principal(1).1),
            application: self.application.clone(),
            journal_root: self.root.path().join("client"),
            control_timeout: Duration::from_secs(10),
        }
    }
    fn input(&self) -> PreparedInvocation {
        let contract = hellas_channel::test_support::test_responses_contract();
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            br#"{"model":"fixture","input":"sdk-private-input","max_output_tokens":8}"#,
            contract.manifest_id(),
            Assurance::ProducerSigned,
            &principal(1).1,
            Retention::Ephemeral,
        )
        .unwrap();
        hellas_rpc::protocol::invocation::fetch::prepare(
            &events,
            &contract,
            principal(2).1.public_key(),
            self.grant.policies[0]
                .invocation_policy
                .canonical_bytes()
                .unwrap(),
            [1; 32],
        )
        .unwrap()
    }
    fn scan(&self) {
        for path in common::all_files(self.root.path()) {
            let bytes = std::fs::read(path).unwrap();
            for canary in [
                b"sdk-private-input".as_slice(),
                b"sdk-private-output".as_slice(),
            ] {
                assert!(!bytes.windows(canary.len()).any(|part| part == canary));
            }
        }
    }
}
fn content() -> (LocalStore, Scope) {
    (
        LocalStore::Memory(MemoryStore::new(Reservations::ram(
            hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
        ))),
        Scope::Owner,
    )
}

#[tokio::test]
async fn native_grant_session_transfers_accepts_and_delivers_without_payload_files() {
    let f = Fixture::new(false).await;
    let mut session =
        GrantSession::open(f.options(vec![]), GrantTransport::Local(f.service.clone()))
            .await
            .unwrap();
    let result = session
        .run("responses", f.input(), &content(), None, None, None)
        .await
        .unwrap();
    assert!(result.output.is_success());
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert_eq!(session.store().next_nonce().unwrap(), 2);
    session.shutdown().await.unwrap();
    drop(session);
    assert_eq!(f.node_content.ram_pool().held(), 0);
    f.scan();
}

async fn serve_work(
    f: &Fixture,
    pending: Option<Arc<tokio::sync::Notify>>,
) -> (iroh::Endpoint, Vec<String>, tokio::task::JoinHandle<()>) {
    use hellas_rpc::services::work::Work;
    use hellas_wire::{
        Dispatcher, MethodMarker, ServiceMarker, StreamTransport, iroh::IrohTransport,
    };
    let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&[2; 32]))
        .alpns(vec![Work::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let addresses = server
        .bound_sockets()
        .iter()
        .map(ToString::to_string)
        .collect();
    let router = hellas_sdk::work_router::WorkRouter::grants(f.service.clone());
    let proof = hellas_sdk::ProviderOpen::<ProducerSigningKey>::new(
        Arc::new(principal(2).1),
        f.enrollment.clone(),
        None,
    )
    .unwrap();
    let endpoint = server.clone();
    let serving = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Some(incoming) = endpoint.accept().await {
            let (router, proof, pending) = (router.clone(), proof.clone(), pending.clone());
            connections.spawn(async move {
                let transport = IrohTransport::new(incoming.await.unwrap());
                let connection = Arc::new(router.accept_iroh(&transport, proof).await.unwrap());
                let mut tasks = tokio::task::JoinSet::new();
                while let Ok(Some(inbound)) = transport.accept().await {
                    let connection = connection.clone();
                    let (pending, carrier) = (pending.clone(), transport.connection().clone());
                    tasks.spawn(async move {
                        if inbound.method_id == hellas_rpc::services::work::AcceptWork::METHOD_ID
                            && let Some(pending) = pending
                        {
                            pending.notify_one();
                            carrier.closed().await;
                            return;
                        }
                        let _ = Dispatcher::<IrohTransport>::dispatch(connection.as_ref(), inbound)
                            .await;
                    });
                }
                tasks.shutdown().await;
            });
        }
        connections.shutdown().await;
    });
    (server, addresses, serving)
}

#[tokio::test]
async fn remote_grant_session_routes_generic_upload_through_authenticated_work_connection() {
    let f = Fixture::new(false).await;
    let (server, addresses, serving) = serve_work(&f, None).await;
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut session =
        GrantSession::open(f.options(addresses), GrantTransport::Remote(client.clone()))
            .await
            .unwrap();
    let result = session
        .run("responses", f.input(), &content(), None, None, None)
        .await
        .unwrap();
    assert!(result.output.is_success());
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    session.shutdown().await.unwrap();
    drop(session);
    client.close().await;
    server.close().await;
    common::within(serving).await.unwrap();
    f.service.drain().await.unwrap();
    assert_eq!(f.node_content.ram_pool().held(), 0);
    f.scan();
}

#[tokio::test]
async fn remote_pending_upload_is_released_when_the_authenticated_work_connection_closes() {
    let f = Fixture::new(false).await;
    let pending = Arc::new(tokio::sync::Notify::new());
    let (server, addresses, serving) = serve_work(&f, Some(pending.clone())).await;
    let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut session =
        GrantSession::open(f.options(addresses), GrantTransport::Remote(client.clone()))
            .await
            .unwrap();
    let input = f.input();
    let running = tokio::spawn(async move {
        let result = session
            .run("responses", input, &content(), None, None, None)
            .await;
        let _ = session.shutdown().await;
        result
    });
    // The SDK has completed Content.Upload and is waiting at AcceptWork. The
    // server has not accepted or installed execution; only the connection owns it.
    common::within(pending.notified()).await;
    assert!(f.node_content.ram_pool().held() > 0);
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    client.close().await;
    assert!(common::within(running).await.unwrap().is_err());
    common::within(async {
        while f.node_content.ram_pool().held() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    server.close().await;
    common::within(serving).await.unwrap();
    f.service.drain().await.unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    f.scan();
}

#[tokio::test]
async fn missing_local_compute_root_never_journals_a_grant_proposal() {
    let f = Fixture::new(true).await;
    let mut session =
        GrantSession::open(f.options(vec![]), GrantTransport::Local(f.service.clone()))
            .await
            .unwrap();
    let mut input = hellas_channel::test_support::channel::bundle(1);
    input.request.retain = false;
    input.request.runner_public_key = principal(2).1.public_key();
    input.application_policy = hellas_rpc::JsonBytes(
        f.grant.policies[0]
            .invocation_policy
            .canonical_bytes()
            .unwrap(),
    );
    let result = session
        .run("compute", input, &content(), None, None, None)
        .await;
    assert!(matches!(
        result,
        Err(hellas_sdk::grant_client::GrantClientError::Content(
            hellas_store::content::Error::Missing
        ))
    ));
    assert_eq!(session.store().next_nonce().unwrap(), 1);
    assert!(session.store().book().pending_proposal().is_none());
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn job_loading_reserves_before_opening_oversized_declared_objects() {
    use hellas_rpc::ContentRef;
    use hellas_sdk::job::{Job, JobError};
    let root = tempfile::tempdir().unwrap();
    let environment = hellas_channel::test_support::channel::environment();
    std::fs::write(
        root.path().join("environment.cbor"),
        environment.canonical_bytes().unwrap(),
    )
    .unwrap();
    let object = ContentRef::new(
        ContentRef::for_bytes(b"declared").id(),
        hellas_channel::content::DEFAULT_MAX_STAGING_BYTES + 1,
    );
    let mut doc = serde_json::json!({"format":hellas_sdk::job::FORMAT,"application":{"evaluator":compute::EVALUATOR,"adaptor":compute::ADAPTOR},"payment":{"price":0},"compute":{"environment":"environment.cbor","plan":hellas_channel::test_support::channel::plan(),"inputs":[],"objects":[{"object":object,"path":"must-not-be-opened"}]}});
    doc["compute"]["plan"]
        .as_object_mut()
        .unwrap()
        .remove("step");
    std::fs::write(root.path().join("job.toml"), toml::to_string(&doc).unwrap()).unwrap();
    assert!(matches!(
        Job::load(root.path()).await,
        Err(JobError::Content(hellas_store::content::Error::Capacity))
    ));
}

#[tokio::test]
async fn job_constructor_checks_root_and_streaming_folder_round_trip_keeps_identity() {
    use hellas_sdk::job::{Job, JobError};
    let source_ref = hellas_rpc::ContentRef::for_bytes(b"source bytes");
    let asset = hellas_rpc::ContentRef::for_bytes(b"caller asset");
    let external = hellas_rpc::ContentRef::for_bytes(b"provider-held asset");
    let environment = compute::Environment {
        sources: vec![source_ref],
        assets: vec![
            compute::NamedAsset {
                name: "local".into(),
                object: asset,
            },
            compute::NamedAsset {
                name: "external".into(),
                object: external,
            },
        ],
    };
    let plan = hellas_channel::test_support::channel::plan();
    assert!(matches!(
        Job::compute(1, environment.clone(), plan.clone(), vec![], content()).await,
        Err(JobError::Content(hellas_store::content::Error::Missing))
    ));
    let source = content();
    hellas_channel::content::upload_object(&source.0, b"source bytes")
        .await
        .unwrap();
    hellas_channel::content::upload_object(&source.0, b"caller asset")
        .await
        .unwrap();
    hellas_channel::content::upload_object(&source.0, &environment.canonical_bytes().unwrap())
        .await
        .unwrap();
    let job = Job::compute(1, environment, plan, vec![], source)
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    job.save(root.path()).await.unwrap();
    let loaded = Job::load(root.path()).await.unwrap();
    assert_eq!(loaded.canonical_bytes(), job.canonical_bytes());
}
