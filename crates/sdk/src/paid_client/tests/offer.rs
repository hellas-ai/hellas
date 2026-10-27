use super::*;
use crate::test_support::{PaidFixture, enrollment, signer};
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_wire::Dispatcher;
use hellas_work::model::offer::{PaidOffer, SignedPaidOffer};
use hellas_work::work::ObservationTime;
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
            allowed_environments: vec![fixture.policy.work_policy.allowed_environment()],
            expected_genesis: imported.offer().provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        };
        trust.verify_enrollment(&imported.offer().provider).unwrap();
        let mount =
            crate::paid_provider::MountedWork::with_backend(super::recovery::Backend::default());
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
        use hellas_work::model::grant::{
            budget::{Limit, Meter, Window},
            records::{Offer, SignedOffer},
        };
        use hellas_work::test_support::{definition, network};
        let now = hellas_auth::authority::UnixMillis::now().unwrap_or_default();
        let grant = definition(GrantId([1; 16]), principal(1).0);
        let (store, secret) = crate::test_node::bootstrap_node_with_credential(
            &fixture.root.path().join("grants"),
            network(),
            Some(bundle.clone()),
            now,
        )
        .await
        .unwrap();
        let grants = hellas_work::grant_service::GrantService::new(
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
        let serving = tokio::spawn({
            let first_upload = first_upload.clone();
            let server = server.clone();
            async move {
                let mut tasks = tokio::task::JoinSet::new();
                for index in 0..4 {
                    let connection = server.accept().await.unwrap().await.unwrap();
                    let bundle = bundle.clone();
                    let producer = producer.clone();
                    let mount = mount.clone();
                    let first_upload = first_upload.clone();
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
                            {
                                let _ = Dispatcher::<IrohTransport>::dispatch(
                                    &WorkServer(crate::work_router::UnmountedWork),
                                    inbound,
                                )
                                .await;
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
                provider: server.id(),
                provider_addrs: server.bound_sockets(),
                apple_trust: None,
                assurance: Assurance::ProducerSigned,
                expected_price: crate::test_support::PRICE,
                acceptance_blocks: 49,
                terminal_blocks: 99,
                payment_blocks: 199,
                timeout: Duration::from_secs(5),
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
        let result = session
            .run(Some(fixture.proposal().prepared_input), false, None)
            .await
            .unwrap()
            .unwrap();
        assert!(!first_upload.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            session
                .with_state(|state| state.proposal_nonce_high_water())
                .await
                .unwrap(),
            1,
            "mount retry reuses the original authorization"
        );
        assert_eq!(result.credited_cumulative, crate::test_support::PRICE);
        assert_eq!(
            service
                .with_state(|s| s.ledger().credited_cumulative())
                .await
                .unwrap(),
            crate::test_support::PRICE
        );
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
        let result = authorized
            .run("responses", fixture.proposal().prepared_input, None)
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
            crate::test_support::PRICE
        );
        client_endpoint.close().await;
        server.close().await;
        serving.await.unwrap();
    })
    .await
    .unwrap();
}
