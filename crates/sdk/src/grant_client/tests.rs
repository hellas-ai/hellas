use super::*;
use hellas_kernel::NetworkId;
use hellas_rpc::pb::work::GrantRefusal;
use hellas_rpc::protocol::work_grant::records::{
    GrantDef, GrantKind, GrantPolicy, GrantState, Offer,
};
use hellas_rpc::protocol::{work_fetch::*, work_grant::budget::*};
use hellas_rpc::{
    Assurance, FetchEnvironment, PlatformCredential, PlatformEnrollment, ProviderGenesisStatement,
    Retention, RootKind, RootProof, SignedProviderGenesis,
};
use hellas_wire::{MethodMarker, ServiceMarker};
use hellas_work::work::{
    BackendFault, PreparedFetchInput, WorkBackend,
    admission::{CapacityDomain, WorkPermit},
};
use hellas_work::work_store::grant::GrantStore;
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::Semaphore;
pub fn network() -> NetworkId {
    NetworkId::new("grants-fixture").unwrap()
}
pub fn principal(seed: u8) -> (Principal, ProducerSigningKey) {
    let key = ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: key.public_key(),
        producer_public_key: key.public_key(),
        transport_public_key: PublicKey::Ed25519(
            *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes(),
        ),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [seed; 32],
    };
    let proof = key
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    (
        Principal::verify(ProviderEnrollmentBundle {
            genesis: SignedProviderGenesis {
                statement,
                root_proof: RootProof::Software(proof),
            },
            platform: PlatformEnrollment::Absent,
        })
        .unwrap(),
        key,
    )
}
pub fn policy() -> GrantPolicy {
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    GrantPolicy {
        name: "responses".into(),
        work: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 1_048_576,
                max_spool_bytes: 65_536,
                max_encoded_result_frame: 262_144,
                max_encoded_prepared_input: 1_048_576,
            },
            route,
        },
        https: None,
    }
}
pub fn definition(id: GrantId, client: Principal) -> GrantDef {
    GrantDef {
        id,
        revision: Revision(1),
        kind: GrantKind::Principal(client),
        policies: vec![policy()],
        limits: vec![Limit {
            meter: Meter::Requests,
            window: Window::Total,
            amount: 3,
        }],
        max_job_millis: NonZeroU64::new(10000).unwrap(),
        max_in_flight: NonZeroU16::new(2).unwrap(),
        expires: None,
        state: GrantState::Active,
        allow_account_backed: true,
    }
}
pub fn pinned_offer(grant: GrantDef, addresses: Vec<String>) -> PinnedOffer {
    let (provider, signer) = principal(2);
    let client = grant.kind.principal().id();
    let signed = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.bundle().clone(),
            grant,
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses,
        },
        &signer,
    )
    .unwrap();
    UnpinnedOffer::decode(&signed.encode().unwrap(), client, UnixMillis(1000))
        .unwrap()
        .pin(&ProviderTrustAnchor {
            expected_genesis: provider.bundle().content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap()
}
pub fn setup(path: &std::path::Path) -> GrantStore {
    let mut store = GrantStore::open(
        path,
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1_000),
    )
    .unwrap();
    store
        .configure_machine(
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 4,
            }],
            4,
            UnixMillis(1_000),
        )
        .unwrap();
    store
        .define(
            definition(GrantId([1; 16]), principal(1).0),
            UnixMillis(1_000),
        )
        .unwrap();
    store
}

#[derive(Clone)]
struct Backend {
    slots: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
}
impl WorkBackend for Backend {
    fn try_admit(&self, domain: CapacityDomain) -> std::result::Result<WorkPermit, BackendFault> {
        Ok(WorkPermit::new(
            domain,
            self.slots.clone().try_acquire_owned().map_err(|_| {
                BackendFault::from(hellas_work::work::admission::AdmissionError::Capacity)
            })?,
        ))
    }
    async fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        progress: PaidProgress,
    ) -> std::result::Result<Vec<OutputEventEnvelope>, BackendFault> {
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission
            .reserve(hellas_work::work::admission::CapacityDomain::Fetch, async {
                self.try_admit(hellas_work::work::admission::CapacityDomain::Fetch)
            })
            .await?
            .dispatch()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request =
            hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript).unwrap();
        let key = principal(2).1;
        let mut output = hellas_rpc::fetch::FetchOutputTranscriptBuilder::new(
            request.input_commitment,
            request.assurance,
            &key,
        );
        progress(
            output
                .push_event(
                    hellas_rpc::fetch::encode_fetch_event_payload(
                        &hellas_rpc::output::OutputEvent::TextDelta {
                            index: 0,
                            delta: "sdk-private-output".into(),
                            channel: hellas_rpc::output::TextChannel::Output,
                        },
                    )
                    .unwrap(),
                )
                .unwrap(),
        )?;
        Ok(output
            .finish(
                hellas_rpc::fetch::encode_fetch_terminal_payload(
                    &hellas_rpc::output::OutputEvent::Finished {
                        stop_reason: hellas_rpc::output::StopReason::EndOfText,
                        usage: None,
                    },
                )
                .unwrap(),
            )
            .unwrap())
    }
}
struct Fixture {
    root: tempfile::TempDir,
    service: GrantService,
    clock: Arc<AtomicU64>,
    calls: Arc<AtomicUsize>,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = setup(&root.path().join("provider"));
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Backend {
            slots: Arc::new(Semaphore::new(2)),
            calls: calls.clone(),
        };
        let clock = Arc::new(AtomicU64::new(1000));
        let clock_read = clock.clone();
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend,
            vec![],
            Arc::new(move || UnixMillis(clock_read.load(Ordering::SeqCst))),
        )
        .unwrap();
        Self {
            root,
            service,
            clock,
            calls,
        }
    }
    fn options(&self) -> GrantSessionOptions {
        GrantSessionOptions {
            target: pinned_offer(definition(GrantId([1; 16]), principal(1).0), vec![]),
            client: principal(1).0,
            signer: Arc::new(principal(1).1),
            journal_root: self.root.path().join("client"),
            timeout: Duration::from_secs(5),
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
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            br#"{"input":"sdk-private-input"}"#,
            FetchEnvironment::OpenAiResponses.manifest_id(),
            Assurance::ProducerSigned,
            &principal(1).1,
            Retention::Ephemeral,
        )
        .unwrap();
        PreparedPaidFetchInputV1::new(&events, &FetchEnvironment::OpenAiResponses.manifest())
            .unwrap()
            .into()
    }
}
#[tokio::test]
async fn local_grant_session_verifies_stream_and_keeps_both_journals_metadata_only() {
    let f = Fixture::new();
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
async fn pending_acceptance_survives_restart_and_recovers_without_replaying_body() {
    for accepted in [false, true] {
        let f = Fixture::new();
        let mut session = f.session().await;
        let input = f.input();
        let offer = session.offer().clone();
        let channel = session.store().channel().id;
        let a = GrantJobAuthorizationV1 {
            channel_id: channel,
            grant_id: GrantId([1; 16]),
            grant_revision: Revision(1),
            catalogue_revision: Revision(0),
            work_policy_digest: policy().work.digest(network(), channel.0),
            prepared_input_digest: input.bound_digest(network(), channel.0).unwrap(),
            proposal_nonce: 1,
            acceptance_deadline_ms: UnixMillis(2000),
            request_commitment: RequestCommitment::from_digest(
                input.input_commitment().unwrap().digest(),
            ),
            environment_commitment: FetchEnvironment::OpenAiResponses.manifest_id(),
            terminal_deadline_ms: UnixMillis(4000),
            delivery_deadline_ms: UnixMillis(5000),
        };
        let signature = session
            .store
            .propose(&offer, a, &input, &principal(1).1, UnixMillis(1000))
            .unwrap();
        let id = grant_work_id(network(), &a);
        if accepted {
            let response = f.service.accept(
                &AcceptWorkRequest {
                    route: Some(WorkRoute::grant(channel)),
                    authorization: a.encode(),
                    client_signature: signature.bytes().to_vec(),
                    prepared_input: input.encode().unwrap(),
                },
                &TransportContext {
                    peer: Some(PeerIdentity(principal(1).0.transport())),
                    auth_level: AuthLevel::Vouched,
                    open_exporter: Some([9; 32]),
                    rtt_ms: None,
                },
            );
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
        f.clock.store(2500, Ordering::SeqCst);
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
async fn remote_grant_session_uses_live_exporter_and_pinned_transport() {
    use hellas_rpc::services::work::{Work, WorkServer};
    use hellas_wire::Dispatcher;
    let f = Fixture::new();
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
    let server_endpoint = provider.clone();
    let service = f.service.clone();
    let serve = tokio::spawn(async move {
        let connection = server_endpoint.accept().await.unwrap().await.unwrap();
        let transport = IrohTransport::new(connection);
        let inbound = transport.accept().await.unwrap().unwrap();
        assert_eq!(
            inbound.method_id,
            hellas_rpc::services::work::Open::METHOD_ID
        );
        let exporter = transport.context().open_exporter.unwrap();
        hellas_rpc::call::dispatch_unary_with_context::<
            IrohTransport,
            hellas_rpc::services::work::Open,
            _,
            _,
            _,
        >(inbound, move |request, _| async move {
            let (provider, signer) = principal(2);
            let nonce: [u8; 32] = request.nonce.try_into().unwrap();
            let binding = hellas_rpc::open_proof_binding(
                &exporter,
                &nonce,
                &signer.public_key(),
                provider.bundle().content_id(),
                Work::ALPN.as_bytes(),
            );
            Ok(hellas_rpc::pb::execute::OpenResponse {
                provider_genesis: provider.bundle().canonical_bytes(),
                proof: Some(
                    hellas_rpc::pb::execute::open_response::Proof::ProducerSignature(
                        hellas_rpc::signature_wire::signature_to_pb(
                            &signer.sign_digest(binding).unwrap(),
                        ),
                    ),
                ),
            })
        })
        .await
        .unwrap();
        let server = WorkServer(service);
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
    let f = Fixture::new();
    f.service
        .administer(|store, now| {
            let mut definition = store.state().grant(GrantId([1; 16])).unwrap().clone();
            definition.revision.0 += 1;
            let WorkPolicy::Fetch { policy, .. } = &mut definition.policies[0].work else {
                unreachable!()
            };
            policy.max_spool_bytes = 32 << 20;
            store.define(definition, now)
        })
        .unwrap();
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
        f.clock.load(Ordering::SeqCst),
        1000,
        "no expiry was needed to release unused spool capacity"
    );
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn recovered_metadata_is_bound_to_the_requested_job_channel_and_provider() {
    let f = Fixture::new();
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
    assert!(refusal_error(&refused, None).is_err());
    for change in ["work", "signature", "state", "result", "channel"] {
        let mut forged = refused.clone();
        let terminal = forged.grant.as_mut().unwrap().terminal.as_mut().unwrap();
        let mut request_channel = channel;
        match change {
            "work" => terminal.work_id[0] ^= 1,
            "signature" => terminal.provider_signature[0] ^= 1,
            "state" => terminal.state = GrantTerminalState::Unspecified as i32,
            "result" => terminal.result[0] ^= 1,
            "channel" => request_channel = ChannelId(Digest::hash(b"other-channel")),
            _ => unreachable!(),
        }
        assert!(
            refusal_error(&forged, Some((&target, request_channel, output.work_id))).is_err(),
            "{change}"
        );
    }
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_open_never_discloses_standing_or_creates_a_client_journal() {
    use hellas_rpc::services::work::{Open, Work};
    for missing in [false, true] {
        let f = Fixture::new();
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
                            provider_genesis: principal(3).0.bundle().canonical_bytes(),
                            proof: None,
                        })
                    }
                },
            )
            .await
            .unwrap();
            if let Ok(Ok(Some(_))) =
                tokio::time::timeout(Duration::from_millis(100), transport.accept()).await
            {
                panic!("client sent another request after failed Open");
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
        let path = options.journal_root.clone();
        assert!(
            GrantSession::open(options, GrantTransport::Remote(client.clone()))
                .await
                .is_err()
        );
        assert!(!path.exists());
        assert_eq!(f.calls.load(Ordering::SeqCst), 0);
        server.await.unwrap();
        client.close().await;
        provider.close().await;
    }
}
