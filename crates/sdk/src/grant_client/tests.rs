use super::*;
use hellas_auth::authority::Revision;
use hellas_rpc::pb::work::GrantRefusal;
use hellas_rpc::{Assurance, Retention};
use hellas_wire::{MethodMarker, ServiceMarker, StreamTransport};
use hellas_work::model::grant::records::{GrantDef, Offer};
use hellas_work::model::{fetch::*, grant::budget::*};
use hellas_work::test_support::TestClock;
use hellas_work::test_support::{WAIT, assert_err, definition, network, policy};
use hellas_work::work_store::grant::NodeStore;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
mod connections;

pub use hellas_work::test_support::principal;
pub fn provider_enrollment(seed: u8) -> ProviderEnrollmentBundle {
    hellas_work::test_support::software_enrollment(
        seed,
        *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes(),
    )
}

pub fn pinned_offer(grant: GrantDef, addresses: Vec<String>) -> PinnedOffer {
    let signer = principal(2).1;
    let provider = provider_enrollment(2);
    let signed = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.clone(),
            grant,
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses,
        },
        &signer,
    )
    .unwrap();
    UnpinnedOffer::decode(&signed.encode().unwrap(), UnixMillis(1000))
        .unwrap()
        .pin(&ProviderTrustAnchor {
            allowed_environments: signed
                .offer()
                .grant
                .policies
                .iter()
                .map(|p| p.work.allowed_environment())
                .collect(),
            expected_genesis: provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap()
}
async fn setup(
    path: &std::path::Path,
    grant: GrantDef,
) -> (NodeStore, hellas_auth::authority::CredentialSecret) {
    let now = UnixMillis(1000);
    let (store, secret) = crate::test_node::bootstrap_node_with_credential(
        path,
        network(),
        Some(crate::grant_client::tests::provider_enrollment(2)),
        now,
    )
    .await
    .unwrap();
    let store = crate::test_node::provision(
        path,
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
        grant,
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
    (store, secret)
}

use hellas_work::test_support::backend::{Backend, Completion, Reply};
fn backend(slots: Arc<Semaphore>, calls: Arc<AtomicUsize>) -> Backend {
    Backend {
        slots,
        calls,
        finish: Completion::Immediate,
        reply: Reply::text("sdk-private-output", 1),
        ..Backend::default()
    }
}
struct Fixture {
    root: tempfile::TempDir,
    service: GrantService,
    application: Arc<ClientProfile>,
    administrator: hellas_auth::authority::CredentialSecret,
    clock: TestClock,
    calls: Arc<AtomicUsize>,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_grant(definition(GrantId([1; 16]), principal(1).0)).await
    }
    async fn with_grant(grant: GrantDef) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (subject, allowance) = (principal(1).0, grant.id);
        let (store, secret) = setup(&root.path().join("provider"), grant).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = backend(Arc::new(Semaphore::new(2)), calls.clone());
        let clock = TestClock::default();
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend,
            vec![],
            clock.source(),
        )
        .unwrap();
        let application =
            crate::test_support::application_profile(&service.node(), &secret, subject, allowance)
                .await;
        Self {
            root,
            service,
            application,
            administrator: secret,
            clock,
            calls,
        }
    }
    fn options(&self) -> GrantSessionOptions {
        GrantSessionOptions {
            target: pinned_offer(definition(GrantId([1; 16]), principal(1).0), vec![]),
            principal: principal(1).0,
            signer: Arc::new(principal(1).1),
            application: self.application.clone(),
            journal_root: self.root.path().join("client"),
            // A job deadline below the grant limit leaves room for the client
            // monotonic clock while the injected provider clock stays fixed.
            timeout: std::time::Duration::from_secs(5),
        }
    }
    async fn session(&self) -> crate::grant_client::GrantSession {
        crate::grant_client::GrantSession::open(
            self.options(),
            GrantTransport::Local(self.service.clone()),
        )
        .await
        .unwrap()
    }
    fn input(&self) -> PreparedWorkInput {
        self.input_for_contract(&test_responses_contract())
    }
    fn input_for_contract(&self, contract: &hellas_rpc::FetchContract) -> PreparedWorkInput {
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
        PreparedPaidFetchInputV1::new(&events, contract)
            .unwrap()
            .into()
    }
}
#[tokio::test]
async fn local_sessions_keep_authenticated_payloads_out_of_journals() {
    let f = Fixture::new().await;
    let mut session = f.session().await;
    let progress = Arc::new(AtomicUsize::new(0));
    let seen = progress.clone();
    let result = session
        .run(
            "responses",
            f.input(),
            Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
        )
        .await
        .unwrap();
    assert_eq!(progress.load(Ordering::SeqCst), 1);
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    assert_eq!(session.store().next_nonce().unwrap(), 2);
    assert_eq!(result.events.len(), 2);
    session.shutdown().await.unwrap();
    drop(session);
    fn check(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                check(&path);
            } else {
                let bytes = std::fs::read(path).unwrap();
                for secret in [
                    b"sdk-private-input".as_slice(),
                    b"sdk-private-output".as_slice(),
                ] {
                    assert!(!bytes.windows(secret.len()).any(|window| window == secret));
                }
            }
        }
    }
    check(f.root.path());
}
#[tokio::test]
async fn lost_acceptance_recovers_from_metadata_without_replaying_input() {
    for accepted in [false, true] {
        let f = Fixture::new().await;
        let mut session = f.session().await;
        let input = f.input();
        let offer = session.offer().clone();
        let channel = session.store().channel().id;
        let a = GrantJobAuthorizationV1 {
            channel_id: channel,
            generation: session.store().channel().generation,
            grant_id: GrantId([1; 16]),
            grant_revision: Revision(1),
            resource_id: policy().resource,
            resource_revision: policy().revision,
            pricing_revision: policy().pricing.revision,
            work_policy_digest: policy().work.digest(network(), channel.0),
            prepared_input_digest: input.bound_digest(network(), channel.0).unwrap(),
            proposal_nonce: 1,
            acceptance_deadline_ms: UnixMillis(2000),
            request_commitment: RequestCommitment::from_digest(
                input.input_commitment().unwrap().digest(),
            ),
            environment_commitment: test_responses_contract().manifest_id(),
            terminal_deadline_ms: UnixMillis(4000),
            delivery_deadline_ms: UnixMillis(5000),
        };
        let signature = session
            .store
            .propose(&offer, a, &input, &principal(1).1, UnixMillis(1000))
            .await
            .unwrap();
        let id = grant_work_id(network(), &a);
        if accepted {
            let caller = f
                .service
                .node()
                .authenticate_session(
                    &f.application.credential,
                    hellas_work::node::SessionKey::Node(&principal(1).1),
                )
                .await
                .unwrap();
            let response = f
                .service
                .for_caller(caller, f.application.authorization)
                .accept(&AcceptWorkRequest {
                    route: Some(WorkRoute::grant(channel.0)),
                    authorization: a.encode(),
                    client_signature: signature.bytes().to_vec(),
                    prepared_input: input.encode().unwrap(),
                })
                .await;
            assert!(matches!(
                response.outcome,
                Some(accept_work_response::Outcome::Accepted(_))
            ));
        }
        drop(session); // Crash after proposal fsync, possibly after provider acceptance.
        let mut resumed = f.session().await;
        assert!(matches!(
            resumed.run("responses", f.input(), None).await,
            Err(GrantClientError::RecoveryRequired)
        ));
        assert!(matches!(
            resumed.recover().await,
            Err(GrantClientError::RecoveryTooEarly)
        ));
        f.clock.set(UnixMillis(2500));
        assert_eq!(
            resumed.recover().await.unwrap(),
            if accepted {
                Recovery::Accepted(id)
            } else {
                Recovery::Refused(id)
            }
        );
        assert_eq!(resumed.store().next_nonce().unwrap(), 2);
        assert!(resumed.store().book().pending_proposal().is_none());
        resumed.shutdown().await.unwrap();
        assert!(f.calls.load(Ordering::SeqCst) <= usize::from(accepted));
    }
}

#[tokio::test]
async fn remote_grant_session_authenticates_an_independent_client_transport() {
    use hellas_rpc::services::work::Work;
    use hellas_wire::Dispatcher;
    let f = Fixture::new().await;
    f.clock.set(UnixMillis::now().unwrap_or_default());
    let provider = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&[2; 32]))
        .alpns(vec![Work::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(iroh::SecretKey::from_bytes(&[9; 32]))
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let server_endpoint = provider.clone();
    let service = f.service.clone();
    let serve = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let transport = IrohTransport::new(connection);
        let signer = principal(2).1;
        let provider = provider_enrollment(2);
        let server = crate::work_router::WorkRouter::grants(service)
            .accept_iroh(
                &transport,
                crate::test_identity::OpenProof(provider.clone(), signer),
            )
            .await
            .unwrap();
        while let Some(inbound) = transport.accept().await.unwrap() {
            Dispatcher::<IrohTransport>::dispatch(&server, inbound)
                .await
                .unwrap();
        }
    });
    let mut options = f.options();
    options.target = pinned_offer(
        options.target.offer().grant.clone(),
        provider
            .addr()
            .ip_addrs()
            .map(ToString::to_string)
            .collect(),
    );
    let mut session =
        crate::grant_client::GrantSession::open(options, GrantTransport::Remote(client.clone()))
            .await
            .unwrap();
    let result = session.run("responses", f.input(), None).await.unwrap();
    assert_eq!(result.events.len(), 2);
    session.shutdown().await.unwrap();
    f.service.drain().await.unwrap();
    client.close().await;
    serve.abort();
    let _ = serve.await;
    provider.close().await;
}

#[tokio::test]
async fn completed_jobs_reconcile_ram_before_the_delivery_window_expires() {
    let mut definition = definition(GrantId([1; 16]), principal(1).0);
    let WorkPolicy::Fetch { policy, .. } = &mut definition.policies[0].work else {
        unreachable!()
    };
    policy.max_spool_bytes = 32 << 20;
    let f = Fixture::with_grant(definition).await;
    let mut session = f.session().await;
    for _ in 0..3 {
        assert_eq!(
            session
                .run("responses", f.input(), None)
                .await
                .unwrap()
                .events
                .len(),
            2
        );
    }
    assert_eq!(f.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        f.clock.now().0,
        1000,
        "no expiry was needed to release unused spool capacity"
    );
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn recovered_metadata_is_bound_to_the_requested_job_channel_and_provider() {
    let f = Fixture::new().await;
    let mut session = f.session().await;
    let output = session.run("responses", f.input(), None).await.unwrap();
    let channel = session.store().channel().id;
    let target = GrantTarget::from_offer(&f.options().target).unwrap();
    let signature = principal(2)
        .1
        .sign_digest(bound_result_digest(network(), channel.0, &output.result))
        .unwrap();
    let refused = WorkRefused {
        code: WorkRefusalCode::Declined as i32,
        reason: String::new(),
        grant: Some(GrantRefusal {
            code: GrantRefusalCode::OutputUnavailable as i32,
            current_revision: 0,
            terminal: Some(Box::new(GrantTerminalMetadata {
                work_id: output.work_id.as_bytes().to_vec(),
                state: GrantTerminalState::Finished as i32,
                result: output.result.encode(),
                provider_signature: signature.bytes().to_vec(),
            })),
        }),
    };
    assert!(matches!(
        refusal_error(&refused, Some((&target, channel, output.work_id))).unwrap(),
        GrantClientError::Refused {
            terminal: Some(_),
            ..
        }
    ));
    assert_err!(
        refusal_error(&refused, None),
        GrantClientError::Protocol(GrantProtocolError::UnexpectedTerminalMetadata)
    );
    #[derive(Clone, Copy, Debug)]
    enum Tamper {
        Work,
        Signature,
        State,
        Result,
        Channel,
    }
    for change in [
        Tamper::Work,
        Tamper::Signature,
        Tamper::State,
        Tamper::Result,
        Tamper::Channel,
    ] {
        let mut forged = refused.clone();
        let terminal = forged.grant.as_mut().unwrap().terminal.as_mut().unwrap();
        let mut request_channel = channel;
        match change {
            Tamper::Work => terminal.work_id[0] ^= 1,
            Tamper::Signature => terminal.provider_signature[0] ^= 1,
            Tamper::State => terminal.state = GrantTerminalState::Unspecified as i32,
            Tamper::Result => terminal.result[0] ^= 1,
            Tamper::Channel => request_channel = ChannelId(Digest::hash(b"other-channel")),
        }
        let result = refusal_error(&forged, Some((&target, request_channel, output.work_id)));
        match change {
            Tamper::Work | Tamper::State => assert_err!(
                result,
                GrantClientError::Protocol(GrantProtocolError::TerminalMetadata)
            ),
            Tamper::Signature | Tamper::Channel => {
                assert_err!(result, GrantClientError::Signature(_))
            }
            Tamper::Result => assert_err!(result, GrantClientError::Work(_)),
        }
    }
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_open_never_discloses_standing_or_creates_a_client_journal() {
    use hellas_rpc::services::work::{Open, Work};
    for missing in [false, true] {
        let f = Fixture::new().await;
        let provider = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[2; 32]))
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[1; 32]))
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let endpoint = provider.clone();
        let (finished, client_finished) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let transport = IrohTransport::new(connection);
            let inbound = transport.accept().await.unwrap().unwrap();
            assert_eq!(inbound.method_id, Open::METHOD_ID);
            hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, Open, _, _, _>(
                inbound,
                move |_, _| async move {
                    if missing {
                        Err(hellas_wire::WireStatus::new(
                            hellas_wire::WireCode::Unimplemented,
                            "Open unavailable",
                        ))
                    } else {
                        Ok(hellas_rpc::pb::execute::OpenResponse {
                            provider_genesis: crate::grant_client::tests::provider_enrollment(3)
                                .canonical_bytes(),
                            proof: None,
                        })
                    }
                },
            )
            .await
            .unwrap();
            client_finished.await.unwrap();
            tokio::time::pause();
            if let Ok(Ok(_)) = tokio::time::timeout(WAIT, transport.connection().accept_bi()).await
            {
                panic!("client sent another request after failed Open");
            }
            tokio::time::resume();
        });
        let mut options = f.options();
        options.target = pinned_offer(
            options.target.offer().grant.clone(),
            provider
                .addr()
                .ip_addrs()
                .map(ToString::to_string)
                .collect(),
        );
        let path = options.journal_root.clone();
        let result = GrantSession::open(options, GrantTransport::Remote(client.clone())).await;
        if missing {
            assert_err!(result, GrantClientError::Client(hellas_client::ClientError::Wire { source, .. }) if source.code() == hellas_wire::WireCode::Unimplemented);
        } else {
            assert_err!(result, GrantClientError::Client(hellas_client::ClientError::Protocol(message)) if message.starts_with("provider genesis pin mismatch"));
        }
        finished.send(()).unwrap();
        assert!(!path.exists());
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
        client.close().await;
        provider.close().await;
    }
}

use hellas_work::test_support::test_responses_contract;

#[tokio::test]
async fn current_grant_cannot_disclose_a_new_contract_without_independent_client_approval() {
    let contract = hellas_rpc::FetchContract::new(
        "independent-responses-1",
        hellas_rpc::FetchSchema::StatelessResponsesV1,
        "independent-driver-1",
        hellas_rpc::FetchEgress::FixedHttps("https://example.com/responses".into()),
    )
    .unwrap();
    let mut revised = definition(GrantId([1; 16]), principal(1).0);
    let WorkPolicy::Fetch {
        contract: selected,
        policy,
        ..
    } = &mut revised.policies[0].work
    else {
        panic!("Fetch fixture");
    };
    *selected = contract.clone();
    policy.allowed_environment = contract.manifest_id();
    let f = Fixture::with_grant(revised.clone()).await;
    let mut session = f.session().await;
    let denied = session
        .run("responses", f.input_for_contract(&contract), None)
        .await
        .err()
        .expect("unapproved contract must be denied");
    assert!(
        denied.to_string().contains("not independently approved"),
        "{denied}"
    );
    assert_eq!(f.calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.store().next_nonce().unwrap(), 1);
    assert!(session.store().book().pending_proposal().is_none());
    drop(session);
    let mut options = f.options();
    options.target = pinned_offer(revised, vec![]);
    let mut approved = GrantSession::open(options, GrantTransport::Local(f.service.clone()))
        .await
        .unwrap();
    approved
        .run("responses", f.input_for_contract(&contract), None)
        .await
        .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    approved.shutdown().await.unwrap();
}
