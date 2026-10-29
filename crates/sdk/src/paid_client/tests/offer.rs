use super::*;
use crate::test_support::{PaidFixture, enrollment, signer};
use hellas_channel::model::offer::{PaidOffer, SignedPaidOffer};
use hellas_channel::work::ObservationTime;
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_wire::Dispatcher;
use std::sync::Arc;

/// Chain readiness is supplied by the funded-channel fixture. Offer import,
/// Open, acceptance, execution, streamed delivery and payment use real SDK/RPC.
#[tokio::test]
async fn paid_offer_pins_open_and_runs_a_job_while_wrong_pin_and_missing_open_refuse() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = PaidFixture::new();
        let service = fixture.provider().await;
        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let client_endpoint = bind_paid_endpoint(SecretKey::from_bytes(&[1; 32]))
            .await
            .unwrap();
        let (bundle, producer) = enrollment(server.id());
        let signed = SignedPaidOffer::sign(
            PaidOffer {
                provider: bundle.clone(),
                proposal: fixture.proposal.clone(),
                policy: fixture.policy.clone(),
                omission_bond: 601,
                payment_funding: Funding::new(
                    hellas_kernel::List::take([hellas_kernel::CoinId::from_bytes([1; 32]); 4], 1),
                    hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                ),
                addresses: server
                    .bound_sockets()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            },
            &signer(2),
        )
        .unwrap();
        let imported = SignedPaidOffer::decode(&signed.encode().unwrap()).unwrap();
        assert_eq!(
            imported.offer().proposal.bond_edge(),
            fixture.descriptor.bond_edge()
        );
        let trust = hellas_client::ProviderTrustAnchor {
            expected_genesis: imported.offer().provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        };
        trust.verify_enrollment(&imported.offer().provider).unwrap();
        let backend = super::recovery::Backend::default();
        let backend_calls = backend.0.clone();
        let mount = crate::paid_provider::MountedWork::with_backend(backend);
        mount
            .mount(
                hellas_wire::peers::PeerId::from_bytes(*client_endpoint.id().as_bytes()),
                &service,
            )
            .await
            .unwrap();
        use crate::grant_client::tests::principal;
        use crate::grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer};
        use hellas_auth::authority::{GrantId, UnixMillis};
        use hellas_authority::model::grant::{
            budget::{Limit, Meter, Window},
            records::{Offer, SignedOffer},
        };
        use {hellas_authority::test_support::definition, hellas_channel::test_support::network};
        let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
        let grant = definition(GrantId([1; 16]), principal(1).0);
        let grant_policy = grant.policies[0].invocation_policy.clone();
        let grant_runner = hellas_auth::PublicKey::Secp256k1(
            hellas_authority::model::grant::records::grant_producer(&bundle)
                .unwrap()
                .to_bytes(),
        );
        let (store, secret) = crate::test_node::bootstrap_node_with_credential(
            &fixture.root.path().join("grants"),
            network(),
            Some(bundle.clone()),
            now,
        )
        .await
        .unwrap();
        let grants = hellas_authority::grant_service::GrantService::new(
            store,
            Arc::new(producer.clone()),
            super::recovery::Backend::default(),
            vec![],
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        )
        .unwrap();
        let admin =
            crate::test_node::WorkAdmin::new(grants.clone(), &secret, grant.policies.clone()).await;
        admin.capacity(2, vec![]).await;
        admin
            .budgets(
                crate::test_node::POOL,
                principal(1).0,
                vec![Limit {
                    meter: Meter::Requests,
                    window: Window::Total,
                    amount: 3,
                }],
                2,
            )
            .await;
        admin.create(grant.clone()).await;
        let application = crate::test_support::application_profile(
            &grants.node(),
            &secret,
            principal(1).0,
            grant.id,
        )
        .await;
        let mount = crate::work_router::WorkRouter::both(mount, grants.clone());
        let offer = SignedOffer::sign(
            Offer {
                network: network(),
                provider: bundle.clone(),
                grant,
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(now.0 + 60_000),
                addresses: signed.offer().addresses.clone(),
            },
            &producer,
        )
        .unwrap();
        let grant_target = UnpinnedOffer::decode(&offer.encode().unwrap(), now)
            .unwrap()
            .pin(&trust)
            .unwrap();
        let first_upload = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let first_certificate = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let interrupt_payment = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let serving = tokio::spawn({
            let first_upload = first_upload.clone();
            let first_certificate = first_certificate.clone();
            let interrupt_payment = interrupt_payment.clone();
            let server = server.clone();
            async move {
                let mut tasks = tokio::task::JoinSet::new();
                for index in 0..4 {
                    let connection = server.accept().await.unwrap().await.unwrap();
                    let bundle = bundle.clone();
                    let producer = producer.clone();
                    let mount = mount.clone();
                    let first_upload = first_upload.clone();
                    let first_certificate = first_certificate.clone();
                    let interrupt_payment = interrupt_payment.clone();
                    tasks.spawn(async move {
                        let transport = IrohTransport::new(connection);
                        if index == 3 {
                            // A peer that implements Work but has no Open must
                            // receive only the failed authentication request.
                            let inbound = transport.accept().await.unwrap().unwrap();
                            assert_eq!(
                                inbound.method_id,
                                hellas_rpc::services::work::Open::METHOD_ID
                            );
                            let _ = Dispatcher::<IrohTransport>::dispatch(
                                &WorkServer(crate::work_router::UnmountedWork),
                                inbound,
                            )
                            .await;
                            return;
                        }
                        let server = match mount
                            .accept_iroh(
                                &transport,
                                crate::test_identity::OpenProof(bundle, producer),
                            )
                            .await
                        {
                            Ok(server) => server,
                            Err(_) if index >= 2 => return,
                            Err(error) => panic!("Work authentication failed: {error}"),
                        };
                        while let Ok(Some(inbound)) = transport.accept().await {
                            assert!(index < 2, "failed Open must not disclose a Work request");
                            // The client can observe finalized setup before the
                            // provider's clock has mounted its Work channel.
                            if inbound.method_id
                                == hellas_rpc::services::work::UploadContent::METHOD_ID
                                && first_upload.swap(false, std::sync::atomic::Ordering::SeqCst)
                                || inbound.method_id
                                    == hellas_rpc::services::work::AdmitCertificate::METHOD_ID
                                    && first_certificate
                                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                            {
                                let _ = Dispatcher::<IrohTransport>::dispatch(
                                    &WorkServer(crate::work_router::UnmountedWork),
                                    inbound,
                                )
                                .await;
                            } else if inbound.method_id == hellas_rpc::services::work::AdmitCertificate::METHOD_ID
                                && interrupt_payment.swap(false, std::sync::atomic::Ordering::SeqCst) {
                                // A crash can leave the client's certificate
                                // durable while the provider has never seen it.
                                let _ = hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, hellas_rpc::services::work::AdmitCertificate, _, _, _>(
                                    inbound, |_, _| async {
                                        Err::<hellas_rpc::pb::work::AdmitCertificateResponse, _>(WireStatus::new(hellas_wire::WireCode::Cancelled, "interrupted before provider admission"))
                                    },
                                ).await;
                            } else {
                                let _ =
                                    Dispatcher::<IrohTransport>::dispatch(&server, inbound).await;
                            }
                        }
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        });
        let client = ClientService::new(fixture.client().await);
        client
            .observer()
            .observe_ready(
                fixture.ready.clone(),
                ObservationTime::now(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let mut session = PaidWorkSession {
            args: PaidWorkOptions {
                config: fixture.config.clone(),
                journal_root: fixture.root.path().join("client"),
                provider: crate::test_support::address(server.id()),
                provider_addrs: server.bound_sockets(),
                apple_trust: None,
                assurance: Assurance::ProducerSigned,
                expected_price: crate::test_support::PRICE,
                acceptance_blocks: 49,
                terminal_blocks: 99,
                payment_blocks: 199,
                timeout: Some(Duration::from_secs(5)),
            },
            descriptor: fixture.descriptor.clone(),
            policy: fixture.policy.clone(),
            dialer: ProviderDialer::new(
                server.id(),
                server.bound_sockets(),
                client_endpoint.clone(),
                trust.clone(),
            ),
            client,
            observer: None,
            needs_recovery: false,
        };
        let error = session.run(Some(fixture.proposal().prepared_input), &hellas_channel::content::InvocationContent::Ephemeral(Default::default()), false, None).await.err().expect("interrupted before acknowledgement");
        assert!(matches!(error, PaidClientError::Payment(hellas_channel::work::PaymentError::Transport(status)) if status.code() == hellas_wire::WireCode::Cancelled));
        assert!(!first_upload.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!first_certificate.load(std::sync::atomic::Ordering::SeqCst));
        let first = session.with_state(|state| {
            assert_eq!(state.proposal_nonce_high_water(), 1);
            assert_eq!(state.ledger().credited_cumulative(), crate::test_support::PRICE);
            state.last_payment().unwrap().work_id
        }).await.unwrap();
        assert_eq!(service.with_state(|state| state.ledger().credited_cumulative()).await.unwrap(), 0);
        session.shutdown().await;
        let args = session.args.clone();
        let descriptor = session.descriptor.clone();
        let policy = session.policy.clone();
        let dialer = std::mem::replace(&mut session.dialer, ProviderDialer::new(server.id(), server.bound_sockets(), client_endpoint.clone(), trust.clone()));
        drop(session);
        let client = ClientService::new(ClientEndpoint::recover(fixture.store(Role::Client).await, signer(1)).unwrap());
        client.observer().observe_ready(fixture.ready.clone(), ObservationTime::now(), Duration::from_secs(60)).await.unwrap();
        let mut session = PaidWorkSession { args, descriptor, policy, dialer, client, observer: None, needs_recovery: true };
        let job = crate::job::Job::fetch(crate::test_support::PRICE, hellas_channel::test_support::test_responses_contract(), "openai".into(), "responses".into(), crate::test_support::BODY.to_vec(), Assurance::ProducerSigned).unwrap();
        // The acceptance is reported once, before any output, and names the
        // work and the provider whose transcript the result carries.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (on_accept, on_output) = (seen.clone(), seen.clone());
        let options = crate::transact::TransactionOptions {
            new_purchase: true,
            accepted: Some(Arc::new(move |provenance| on_accept.lock().unwrap().push(Some(provenance)))),
            progress: Some(Arc::new(move |_| {
                on_output.lock().unwrap().push(None);
                Ok(())
            })),
            ..Default::default()
        };
        let result = crate::transact::transact(&mut session, &job, &ProducerSigningKey::from_secret_bytes([1; 32]).unwrap(), options).await.unwrap();
        let seen = std::mem::take(&mut *seen.lock().unwrap());
        assert!(seen.len() > 1, "acceptance and output were reported");
        assert_eq!(
            seen[0],
            Some(hellas_rpc::provenance::ExecutionProvenance { commitment_id: *result.work_id.as_bytes(), provider: result.provider_key })
        );
        assert!(seen[1..].iter().all(Option::is_none), "one acceptance, before any output");
        for envelope in hellas_channel::model::work::decode_transcript(&result.transcript, hellas_channel::work_store::journal::MAX_RECORD_BYTES).unwrap() {
            envelope.verify(&result.provider_key).unwrap();
        }
        assert_ne!(result.work_id, first);
        assert_eq!(result.credited_cumulative, 2 * crate::test_support::PRICE);
        assert_eq!(session.with_state(|state| state.proposal_nonce_high_water()).await.unwrap(), 2);
        service.with_state(|state| {
            assert_eq!(state.ledger().credited_cumulative(), 2 * crate::test_support::PRICE);
            for id in [first, result.work_id] {
                assert!(matches!(state.terminal_by_id(id).unwrap().outcome, hellas_channel::work_store::TerminalOutcome::Certified { .. }));
            }
        }).await.unwrap();
        assert_eq!(backend_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        let mut authorized = crate::grant_client::GrantSession::open(
            GrantSessionOptions {
                target: grant_target,
                principal: principal(1).0,
                signer: Arc::new(principal(1).1),
                application,
                journal_root: fixture.root.path().join("grant-client"),
                timeout: Duration::from_secs(5),
            },
            GrantTransport::Remote(client_endpoint.clone()),
        )
        .await
        .unwrap();
        let hellas_rpc::protocol::invocation::Admission::Fetch { admission } =
            &grant_policy.admissions[0]
        else {
            panic!("Fetch grant fixture")
        };
        let grant_input = hellas_rpc::protocol::invocation::fetch::prepare(
            &hellas_rpc::fetch::build_input_events_with_retention(
                "openai",
                "responses",
                crate::test_support::BODY,
                admission.contract.manifest_id(),
                Assurance::ProducerSigned,
                &principal(1).1,
                hellas_rpc::Retention::Ephemeral,
            )
            .unwrap(),
            &admission.contract,
            grant_runner,
            grant_policy.canonical_bytes().unwrap(),
            [3; 32],
        )
        .unwrap();
        let result = authorized
            .run(
                "responses",
                grant_input,
                &hellas_channel::content::InvocationContent::Ephemeral(Default::default()),
                None,
            )
            .await
            .unwrap();
        assert!(!result.events.is_empty());
        authorized.shutdown().await.unwrap();
        grants.drain().await.unwrap();
        session
            .dialer
            .work()
            .await
            .unwrap()
            .connection()
            .close(0u32.into(), b"new connection");
        session.shutdown().await;
        assert!(session.client.readiness().await.is_err());
        drop(session);
        let mut wrong = trust.clone();
        wrong.expected_genesis = hellas_rpc::ContentId::from_bytes([99; 32]);
        let dialer = ProviderDialer::new(
            server.id(),
            server.bound_sockets(),
            client_endpoint.clone(),
            wrong,
        );
        assert!(dialer.work().await.is_err());
        let dialer = ProviderDialer::new(
            server.id(),
            server.bound_sockets(),
            client_endpoint.clone(),
            trust,
        );
        assert!(dialer.work().await.is_err());
        assert_eq!(
            service
                .with_state(|s| s.ledger().credited_cumulative())
                .await
                .unwrap(),
            2 * crate::test_support::PRICE
        );
        client_endpoint.close().await;
        server.close().await;
        serving.await.unwrap();
    })
    .await
    .unwrap();
}
