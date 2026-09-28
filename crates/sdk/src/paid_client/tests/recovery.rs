use super::*;
use crate::test_support::{BODY, PRICE, PaidFixture, signer};
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, encode_fetch_event_payload, encode_fetch_terminal_payload,
    verify_input_events,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::pb::work::WorkDelivered;
use hellas_rpc::protocol::work::PrivateRecord as _;
use hellas_rpc::services::work::{Work, WorkServer};
use hellas_wire::Dispatcher;
use hellas_work::work::{
    BackendFault, ObservationTime, PaidWorkBackend, PreparedFetchInput, run_accepted_work,
};
use std::sync::atomic::AtomicUsize;

const RESPONSE: &str = "sdk-private-response";

#[derive(Default)]
struct Backend(AtomicUsize);

impl PaidWorkBackend for Backend {
    async fn fetch(
        &self,
        input: PreparedFetchInput,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let request = verify_input_events(&input.into_parts().fetch_input_transcript).unwrap();
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let mut output =
            FetchOutputTranscriptBuilder::new(request.input_commitment, request.assurance, &key);
        output
            .push_event(
                encode_fetch_event_payload(&OutputEvent::TextDelta {
                    index: 0,
                    delta: RESPONSE.into(),
                    channel: TextChannel::Output,
                })
                .unwrap(),
            )
            .unwrap();
        Ok(output
            .finish(
                encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap())
    }
}

fn assert_no_payloads(root: &std::path::Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_payloads(&path);
        } else {
            let bytes = std::fs::read(&path).unwrap();
            for payload in [BODY, RESPONSE.as_bytes()] {
                assert!(
                    !bytes.windows(payload.len()).any(|window| window == payload),
                    "payload in {}",
                    path.display()
                );
            }
        }
    }
}

#[tokio::test]
async fn restart_pays_delivered_fetch_once_and_skips_lost_payload_jobs() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = PaidFixture::new();
        let provider = fixture.provider();
        let mut client = fixture.client();
        let request = client.propose(&fixture.proposal()).unwrap();
        let lost = client.accepted(&provider.accept(&request)).unwrap();
        let request = client.propose(&fixture.proposal()).unwrap();
        let delivered = client.accepted(&provider.accept(&request)).unwrap();
        assert_ne!(lost, delivered);
        let backend = Backend::default();
        run_accepted_work(&provider, &fixture.ready, &backend, delivered)
            .await
            .unwrap();
        let request = client.request_delivery(delivered, &[8; 32]).unwrap();
        let result = provider.deliver(&request, &[8; 32]).unwrap();
        client
            .receive(
                delivered,
                &fixture.ready,
                &WorkDelivered {
                    result: result.result.encode(),
                    provider_signature: result.signature.as_bytes().to_vec(),
                    transcript: result.transcript,
                },
            )
            .unwrap();
        // Crash after verified delivery, before creating any payment certificate.
        assert!(client.state().last_payment().is_none());
        drop(client);
        assert_no_payloads(fixture.root.path());

        let server = Endpoint::builder(presets::Minimal)
            .alpns(vec![Work::ALPN.as_bytes().to_vec()])
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let (bundle, key) = enrollment(server.id());
        let trust = hellas_client::ProviderTrustAnchor {
            expected_genesis: bundle.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        };
        let serving = tokio::spawn({
            let server = server.clone();
            let provider = provider.clone();
            async move {
                let mut tasks = tokio::task::JoinSet::new();
                while let Some(incoming) = server.accept().await {
                    let bundle = bundle.clone();
                    let key = key.clone();
                    let provider = provider.clone();
                    tasks.spawn(async move {
                        let transport = IrohTransport::new(incoming.await.unwrap());
                        serve_open::<hellas_rpc::services::work::Open>(&transport, bundle, key)
                            .await;
                        let handler = WorkServer(provider);
                        while let Ok(Some(inbound)) = transport.accept().await {
                            Dispatcher::<IrohTransport>::dispatch(&handler, inbound)
                                .await
                                .unwrap();
                        }
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.unwrap();
                }
            }
        });
        for restart in 0..2 {
            let store = fixture.store(Role::Client);
            assert!(store.state().job_by_id(lost).is_some());
            assert_eq!(store.state().last_payment().is_some(), restart == 1);
            for job in store.state().jobs() {
                assert!(job.prepared_input().is_empty());
                assert!(job.transcript().is_empty());
                assert_eq!(job.result().is_some(), job.work_id() == delivered);
            }
            if restart == 0 {
                assert!(
                    store
                        .state()
                        .job_by_id(delivered)
                        .unwrap()
                        .result()
                        .is_some()
                );
            }
            let client = ClientService::new(ClientEndpoint::recover(store, signer(1)).unwrap());
            client
                .observer()
                .observe_ready(
                    fixture.ready.clone(),
                    ObservationTime::now(),
                    Duration::from_secs(60),
                )
                .unwrap();
            let endpoint = bind_paid_endpoint(SecretKey::from_bytes(&[5; 32]))
                .await
                .unwrap();
            let mut session = PaidWorkSession {
                args: PaidWorkOptions {
                    config: fixture.config.clone(),
                    journal_root: fixture.root.path().join("client"),
                    provider: server.id(),
                    provider_addrs: server.bound_sockets(),
                    provider_trust: Some(trust.clone()),
                    bond: fixture.descriptor.bond_edge(),
                    payment_funding: Funding::new(
                        hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                        hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
                    ),
                    omission_bond: 601,
                    acceptance_blocks: 50,
                    terminal_blocks: 100,
                    payment_blocks: 200,
                    timeout: Duration::from_secs(5),
                },
                descriptor: fixture.descriptor.clone(),
                dialer: ProviderDialer::new(
                    server.id(),
                    server.bound_sockets(),
                    endpoint.clone(),
                    Some(trust.clone()),
                ),
                client,
                observer: None,
                needs_recovery: true,
            };
            assert!(session.run(None, true, None).await.unwrap().is_none());
            assert!(!session.needs_recovery);
            assert_eq!(
                provider
                    .with_state(|state| state.ledger().credited_cumulative())
                    .unwrap(),
                PRICE
            );
            drop(session);
            endpoint.close().await;
            assert_no_payloads(fixture.root.path());
        }
        assert_eq!(backend.0.load(Ordering::SeqCst), 1);
        server.close().await;
        serving.await.unwrap();
    })
    .await
    .expect("recovery completes without a validator or payload replay");
}
