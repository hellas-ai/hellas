use super::*;
use futures::TryStreamExt as _;
use hellas_gateway::{WorkEvent, WorkExecutionBackend as _};
use hellas_sdk::paid_gateway::{PaidGateway, PaidGatewayOptions};

#[test]
fn gateway_waits_for_slow_funding_finality_within_the_request_deadline() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            case.options.timeout = Some(Duration::from_secs(60));
            case.endpoint.close().await;
            let gateway = PaidGateway::open(
                PaidGatewayOptions {
                    providers: vec![case.options.clone()],
                    max_pending_requests: 1,
                },
                NodeIdentity::from_secret_bytes(case.client_transport.to_bytes(), [0x21; 32])
                    .unwrap(),
                case.owner.clone(),
            )
            .await
            .unwrap();
            let started = tokio::time::Instant::now();
            let request = gateway
                .fetch(hellas_gateway::WorkFetchRequest {
                    provider: case.options.provider.node,
                    service: "openai".into(),
                    method: "responses".into(),
                    body: BODY.to_vec(),
                })
                .unwrap()
                .try_collect::<Vec<_>>();
            tokio::pin!(request);
            // Owner approval follows the authenticated quote. Leave that actual
            // funding transaction unfinalized beyond the connection allowance.
            tokio::select! {
                result = &mut request => panic!("request ended before funding: {result:?}"),
                () = case.approvals.1.notified() => {},
            }
            let height = case.devnet.height();
            let held = tokio::time::timeout(Duration::from_secs(11), &mut request).await;
            let stayed_pending = held.is_err();
            assert_eq!(case.devnet.height(), height);
            let result = if stayed_pending {
                sealing_while(&mut case.devnet, Duration::from_millis(100), &mut request).await
            } else {
                held.unwrap()
            };
            // Clean up even on the pre-fix failure so the real assertion survives
            // the embedded node runtime's shutdown.
            gateway.drain().await.unwrap();
            drop(gateway);
            let elapsed = started.elapsed();
            if stayed_pending && result.is_ok() {
                check_client_funding(&case.devnet, &case.approvals, 1).await;
                let endpoint = bind_paid_endpoint(case.client_transport.clone())
                    .await
                    .unwrap();
                let mut session = PaidWorkSession::open_retained(
                    case.options.clone(),
                    endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                )
                .await
                .unwrap();
                session
                    .with_state(|state| {
                        assert_eq!(state.jobs().count(), 0);
                        assert_eq!(state.terminals().count(), 1);
                        assert_eq!(state.proposal_nonce_high_water(), 1);
                        assert_eq!(state.ledger().credited_cumulative(), PRICE);
                    })
                    .await
                    .unwrap();
                session.shutdown().await;
                drop(session);
                endpoint.close().await;
            }
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
            assert!(
                stayed_pending,
                "funding finality must outlive the connection allowance: {result:?}"
            );
            assert!(elapsed > Duration::from_secs(10));
            assert!(elapsed < Duration::from_secs(60));
            let events =
                result.expect("the same gateway request completes after funding finalizes");
            assert!(
                events
                    .iter()
                    .any(|event| matches!(event, WorkEvent::Output(OutputEvent::Finished { .. })))
            );
        })
    });
}
