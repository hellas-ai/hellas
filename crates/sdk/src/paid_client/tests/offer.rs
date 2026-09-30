use super::*;
use crate::test_support::{PaidFixture, enrollment, signer};
use hellas_rpc::protocol::work_offer::{PaidOffer, SignedPaidOffer};
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_wire::Dispatcher;
use hellas_work::work::ObservationTime;

/// Chain readiness is supplied by the funded-channel fixture. Offer import,
/// Open, acceptance, execution, streamed delivery and payment use real SDK/RPC.
#[tokio::test]
async fn paid_offer_pins_open_and_runs_a_job_while_wrong_pin_and_missing_open_refuse() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = PaidFixture::new();
        let service = fixture.provider();
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
        let mount =
            crate::paid_provider::MountedWork::with_backend(super::recovery::Backend::default());
        assert!(mount.mount(
            hellas_rpc::peers::PeerId::from_bytes(*client_endpoint.id().as_bytes()),
            &service
        ));
        let serving = tokio::spawn({
            let server = server.clone();
            async move {
                let mut tasks = tokio::task::JoinSet::new();
                for index in 0..3 {
                    let connection = server.accept().await.unwrap().await.unwrap();
                    let bundle = bundle.clone();
                    let producer = producer.clone();
                    let mount = mount.clone();
                    tasks.spawn(async move {
                        let transport = IrohTransport::new(connection);
                        if index == 2 {
                            // A peer that implements Work but has no Open must
                            // receive only the failed authentication request.
                            let inbound = transport.accept().await.unwrap().unwrap();
                            assert_eq!(
                                inbound.method_id,
                                hellas_rpc::services::work::Open::METHOD_ID
                            );
                            let _ =
                                Dispatcher::<IrohTransport>::dispatch(&WorkServer(mount), inbound)
                                    .await;
                            return;
                        }
                        serve_open::<hellas_rpc::services::work::Open>(
                            &transport, bundle, producer,
                        )
                        .await;
                        while let Ok(Some(inbound)) = transport.accept().await {
                            assert!(index < 1, "failed Open must not disclose a Work request");
                            let _ = Dispatcher::<IrohTransport>::dispatch(
                                &WorkServer(mount.clone()),
                                inbound,
                            )
                            .await;
                        }
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        });
        let client = ClientService::new(fixture.client());
        client
            .observer()
            .observe_ready(
                fixture.ready.clone(),
                ObservationTime::now(),
                Duration::from_secs(60),
            )
            .unwrap();
        let mut session = PaymentSession {
            args: PaidWorkOptions {
                config: fixture.config.clone(),
                journal_root: fixture.root.path().join("client"),
                provider: server.id(),
                provider_addrs: server.bound_sockets(),
                provider_trust: trust.clone(),
                bond: fixture.descriptor.bond_edge(),
                payment_funding: Funding::new(
                    hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                    hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                ),
                omission_bond: 601,
                acceptance_blocks: 49,
                terminal_blocks: 99,
                payment_blocks: 199,
                timeout: Duration::from_secs(5),
            },
            descriptor: fixture.descriptor.clone(),
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
        assert_eq!(result.credited_cumulative, crate::test_support::PRICE);
        assert_eq!(
            service
                .with_state(|s| s.ledger().credited_cumulative())
                .unwrap(),
            crate::test_support::PRICE
        );
        session
            .dialer
            .work()
            .await
            .unwrap()
            .connection()
            .close(0u32.into(), b"new connection");
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
