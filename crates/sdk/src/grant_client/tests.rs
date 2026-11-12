use super::*;
use hellas_auth::authority::Revision;
use hellas_authority::model::grant::budget::*;
use hellas_authority::model::grant::records::{GrantDef, Offer};
use hellas_authority::test_support::TestClock;
use hellas_authority::work_store::grant::NodeStore;
use hellas_private::StoreLocation;
use hellas_rpc::pb::work::GrantRefusal;
use hellas_rpc::{Assurance, Retention};
use hellas_wire::{MethodMarker, ServiceMarker, StreamTransport};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use {
    hellas_authority::test_support::HANG_GUARD, hellas_authority::test_support::definition,
    hellas_authority::test_support::policy, hellas_channel::test_support::assert_err,
    hellas_channel::test_support::network,
};
mod connections;

pub use hellas_channel::test_support::principal;
pub fn provider_enrollment(seed: u8) -> ProviderEnrollmentBundle {
    hellas_channel::test_support::software_enrollment(
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
        (4, vec![Limit::new(Meter::Requests, Window::Total, 4)]),
        grant,
        (vec![Limit::new(Meter::Requests, Window::Total, 3)], 2),
    )
    .await;
    (store, secret)
}

use hellas_channel::test_support::backend::{Backend, Completion, Reply};
fn backend(slots: Arc<Semaphore>, calls: Arc<AtomicUsize>) -> Backend {
    Backend {
        slots,
        calls,
        finish: Completion::Immediate,
        reply: Reply::text("sdk-private-output", 1),
        usage: Some(hellas_rpc::output::Usage {
            input_tokens: Some(1),
            output_tokens: Some(1),
            total_tokens: Some(2),
        }),
        ..Backend::default()
    }
}
struct Fixture {
    root: tempfile::TempDir,
    content: hellas_store::content::DiskStore,
    service: GrantService,
    application: Arc<ClientProfile>,
    administrator: hellas_auth::authority::CredentialSecret,
    clock: TestClock,
    calls: Arc<AtomicUsize>,
    grant: GrantDef,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_grant(definition(GrantId([1; 16]), principal(1).0)).await
    }
    async fn with_grant(grant: GrantDef) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (subject, allowance) = (principal(1).0, grant.id);
        let (store, secret) = setup(&root.path().join("provider"), grant.clone()).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = backend(Arc::new(Semaphore::new(2)), calls.clone());
        let clock = TestClock::default();
        let content =
            hellas_authority::test_support::content_store(&root.path().join("provider")).await;
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend,
            vec![],
            clock.source(),
            content.clone(),
        )
        .unwrap();
        let application =
            crate::test_support::application_profile(&service.node(), &secret, subject, allowance)
                .await;
        Self {
            root,
            content,
            service,
            application,
            administrator: secret,
            clock,
            calls,
            grant,
        }
    }
    fn options(&self) -> GrantSessionOptions {
        let location = StoreLocation::for_test(&self.root.path().join("client"));
        GrantSessionOptions {
            target: pinned_offer(self.grant.clone(), vec![]),
            principal: principal(1).0,
            signer: Arc::new(principal(1).1),
            application: self.application.clone(),
            journal_root: location,
            // Control calls stay bounded independently of the signed job limit.
            control_timeout: std::time::Duration::from_secs(5),
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
    fn input(&self) -> PreparedInvocation {
        let contract = &test_responses_contract();
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
            contract,
            hellas_auth::PublicKey::Secp256k1(
                hellas_authority::model::grant::records::grant_producer(&provider_enrollment(2))
                    .unwrap()
                    .to_bytes(),
            ),
            self.grant.policies[0]
                .invocation_policy
                .canonical_bytes()
                .unwrap(),
            [1; 32],
        )
        .unwrap()
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
            &hellas_channel::test_support::channel::program_content().await,
            Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })),
            None,
            None,
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
    for (accepted, interrupted_refusal) in [(false, false), (false, true), (true, false)] {
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
            work_policy_digest: hellas_channel::job::policy_digest(
                network(),
                channel.0,
                &policy().invocation_policy,
            )
            .unwrap(),
            input_content: hellas_rpc::ContentRef::for_bytes(&input.canonical_bytes().unwrap()),
            prepared_input_digest: hellas_channel::job::bound_prepared_input_digest(
                network(),
                channel.0,
                &input,
            )
            .unwrap(),
            proposal_nonce: 1,
            acceptance_deadline_ms: UnixMillis(2000),
            request_commitment: input.request.commitment().unwrap(),
            environment_commitment: test_responses_contract().manifest_id(),
            terminal_deadline_ms: UnixMillis(4000),
            delivery_deadline_ms: UnixMillis(5000),
        };
        let tracking_input = crate::job::JobInput::Fetch {
            contract: test_responses_contract(),
            service: "openai".into(),
            method: "responses".into(),
            request: br#"{"model":"fixture","input":"sdk-private-input","max_output_tokens":8}"#
                .to_vec(),
            assurance: Assurance::ProducerSigned,
        };
        let terms = crate::execution::ExecutionTerms::Grant {
            resource: a.resource_id,
        };
        let path = f.root.path().join("tracked-attempt");
        let mut attempt =
            crate::execution::ExecutionAttempt::open(&path, &tracking_input, terms).unwrap();
        attempt
            .bind_target(crate::execution::ExecutionTarget {
                network: network(),
                provider: hellas_client::ProviderAddress::of(&offer.offer().provider).unwrap(),
            })
            .unwrap();
        drop(attempt);
        let id = grant_work_id(network(), &a);
        let mut marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        marker["channel"] = serde_json::to_value(channel).unwrap();
        marker["authorization"] = serde_json::json!(a.encode());
        marker["work"] = serde_json::json!(id.as_bytes());
        hellas_private::write_atomically(&path, ".writing", &serde_json::to_vec(&marker).unwrap())
            .unwrap();
        let mut attempt =
            crate::execution::ExecutionAttempt::open_existing(&path, &tracking_input, terms)
                .unwrap();
        let signature = session
            .store
            .propose(&offer, a, &input, &principal(1).1, UnixMillis(1000), None)
            .await
            .unwrap();
        if accepted {
            let caller = f
                .service
                .node()
                .authenticate_session(
                    &f.application.credential,
                    hellas_authority::node::SessionKey::Node(&principal(1).1),
                )
                .await
                .unwrap();
            let work = f.service.for_caller(caller, f.application.authorization);
            let request = AcceptWorkRequest {
                route: Some(WorkRoute::grant(channel.0)),
                authorization: a.encode(),
                client_signature: signature.bytes().to_vec(),
                prepared_input: input.canonical_bytes().unwrap(),
            };
            let response =
                hellas_authority::test_support::accept_grant(&work, &request, &principal(1).1)
                    .await;
            assert!(matches!(
                response.outcome,
                Some(accept_work_response::Outcome::Accepted(_))
            ));
        }
        drop(session); // Crash after proposal fsync, possibly after provider acceptance.
        let mut resumed = f.session().await;
        assert!(matches!(
            resumed
                .run(
                    "responses",
                    f.input(),
                    &hellas_channel::test_support::channel::program_content().await,
                    None,
                    None,
                    None,
                )
                .await,
            Err(GrantClientError::RecoveryRequired)
        ));
        assert!(matches!(
            crate::execution::ExecutionSession::Grant(&mut resumed)
                .recover(&mut attempt)
                .await,
            Err(crate::execution::ExecutionError::Grant(
                GrantClientError::RecoveryTooEarly
            ))
        ));
        f.clock.set(UnixMillis(2500));
        if interrupted_refusal {
            // Simulate a crash after persisting the refusal but before clearing
            // the still-pending proposal exchange.
            drop(attempt);
            let mut marker: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            marker["rejected"] = serde_json::json!(true);
            hellas_private::write_atomically(
                &path,
                ".writing",
                &serde_json::to_vec(&marker).unwrap(),
            )
            .unwrap();
            attempt =
                crate::execution::ExecutionAttempt::open_existing(&path, &tracking_input, terms)
                    .unwrap();
        }
        let facts = crate::execution::ExecutionSession::Grant(&mut resumed)
            .recover(&mut attempt)
            .await
            .unwrap();
        assert_eq!(
            facts.acceptance,
            if accepted {
                crate::execution::Acceptance::Accepted
            } else {
                crate::execution::Acceptance::Rejected
            }
        );
        if !accepted {
            let facts = crate::execution::ExecutionSession::Grant(&mut resumed)
                .recover(&mut attempt)
                .await
                .unwrap();
            assert_eq!(facts.acceptance, crate::execution::Acceptance::Rejected);
            assert!(resumed.store.book().pending_proposal().is_none());
            drop(attempt);
            let reopened =
                crate::execution::ExecutionAttempt::open_existing(&path, &tracking_input, terms)
                    .unwrap();
            assert_eq!(
                reopened.inspect().unwrap().terminal,
                crate::execution::Terminal::Rejected
            );
        }
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
    let result = session
        .run(
            "responses",
            f.input(),
            &hellas_channel::test_support::channel::program_content().await,
            None,
            None,
            None,
        )
        .await
        .unwrap();
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
    let hellas_rpc::protocol::invocation::Admission::Fetch { admission } =
        &mut definition.policies[0].invocation_policy.admissions[0]
    else {
        unreachable!()
    };
    admission.limits.max_spool_bytes = 32 << 20;
    let f = Fixture::with_grant(definition).await;
    let mut session = f.session().await;
    for _ in 0..3 {
        assert_eq!(
            session
                .run(
                    "responses",
                    f.input(),
                    &hellas_channel::test_support::channel::program_content().await,
                    None,
                    None,
                    None,
                )
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
    let output = session
        .run(
            "responses",
            f.input(),
            &hellas_channel::test_support::channel::program_content().await,
            None,
            None,
            None,
        )
        .await
        .unwrap();
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
            let response = hellas_rpc::call::dispatch_unary_with_context::<
                IrohTransport,
                Open,
                _,
                _,
                _,
            >(inbound, move |_, _| async move {
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
            })
            .await;
            client_finished.await.unwrap();
            // The client has asserted the exact Open refusal before signaling.
            // Dropping that refused connection may beat the final QUIC ACK on
            // the server, even though the client received the whole response.
            // Only that known close race is benign; retain all other failures.
            assert!(
                response.is_ok()
                    || matches!(&response, Err(hellas_wire::TransportError::Io(message))
                        if message == "close: connection lost"),
                "unexpected Open response failure: {response:?}",
            );
            tokio::time::pause();
            if let Ok(Ok(_)) =
                tokio::time::timeout(HANG_GUARD, transport.connection().accept_bi()).await
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
        assert!(!path.exists());
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        finished.send(()).unwrap();
        server.await.unwrap();
        client.close().await;
        provider.close().await;
    }
}

use hellas_channel::test_support::test_responses_contract;

#[tokio::test]
async fn stalled_transport_setup_keeps_its_control_timeout() {
    use hellas_rpc::services::work::{Open, Work};
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
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let mut options = f.options();
    options.target = pinned_offer(
        options.target.offer().grant.clone(),
        provider
            .addr()
            .ip_addrs()
            .map(ToString::to_string)
            .collect(),
    );
    let journal = options.journal_root.clone();
    let opening = tokio::spawn(GrantSession::open(
        options,
        GrantTransport::Remote(client.clone()),
    ));
    let connection = hellas_authority::test_support::within(async {
        provider.accept().await.unwrap().await.unwrap()
    })
    .await;
    let transport = IrohTransport::new(connection);
    let inbound = hellas_authority::test_support::within(transport.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(inbound.method_id, Open::METHOD_ID);
    // Keep Open unanswered: timing out job execution is not needed to bound setup.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(6)).await;
    let result = tokio::time::timeout(HANG_GUARD, opening)
        .await
        .expect("control deadline must end stalled setup")
        .unwrap();
    tokio::time::resume();
    assert_err!(result, GrantClientError::Timeout);
    assert!(!journal.exists());
    drop(inbound);
    client.close().await;
    provider.close().await;
}

#[tokio::test]
async fn stalled_local_transport_setup_keeps_its_control_timeout() {
    let f = Fixture::new().await;
    let node = f.service.node();
    let held = hellas_authority::test_support::hold_writer(&node).await;
    tokio::time::pause();
    let result = tokio::time::timeout(
        Duration::from_secs(6),
        GrantSession::open(f.options(), GrantTransport::Local(f.service.clone())),
    )
    .await
    .expect("control deadline must end stalled local authentication");
    tokio::time::resume();
    assert_err!(result, GrantClientError::Timeout);
    drop(held);
}

#[tokio::test]
async fn prepared_resource_gets_fresh_admission_standing() {
    let f = Fixture::new().await;
    let mut session = f.session().await;
    let input = f.input();
    // The resource was selected and prepared from the previous standing.
    f.clock.set(UnixMillis(61_000));
    session
        .run_resource(
            f.grant.policies[0].resource,
            input,
            &hellas_channel::test_support::channel::program_content().await,
            Default::default(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(f.calls.load(Ordering::SeqCst), 1);
    session.shutdown().await.unwrap();
}

/// Open while the journal holds its first durable acknowledgement.
pub(crate) async fn delayed_open_keeps_response_arrival_clock(
    arm: impl FnOnce(&std::path::Path) -> hellas_channel::work_store::journal::test_support::AppendHook,
) {
    let f = Fixture::new().await;
    let _hook = arm(&f.options().journal_root);
    let mut session = f.session().await;
    assert!(session.now().0 >= session.standing_now.0 + 500);
    session.shutdown().await.unwrap();
}
