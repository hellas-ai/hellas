use super::*;
use futures::TryStreamExt as _;
use hellas_gateway::{WorkEvent, WorkExecutionBackend as _};
use hellas_sdk::paid_client::{SessionFundingOptions, SessionOpenMode};

#[test]
fn gateway_waits_for_slow_funding_finality() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            // The request deadline only has to outlast the connection
            // allowance; size it as a hang guard so load cannot expire it.
            case.options.timeout = Some(HANG_GUARD);
            let quote = hellas_sdk::paid_client::request_paid_quote(
                &case.options,
                &case.endpoint,
                &client_settlement(),
                case.owner.principal(),
            )
            .await
            .unwrap();
            let gateway = hellas_sdk::ExecutorGateway::new(
                [(
                    "test".into(),
                    hellas_sdk::BackendEntry {
                        backend: hellas_sdk::Backend::paid(
                            Some(quote.policy.invocation_policy),
                            case.options.clone(),
                            case.endpoint.clone(),
                            client_settlement(),
                            case.owner.clone(),
                        ),
                        evaluator: None,
                        max_in_flight: std::num::NonZeroUsize::new(32).unwrap(),
                    },
                )]
                .into(),
                Arc::new(ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap()),
            );
            let started = tokio::time::Instant::now();
            let request = gateway
                .fetch(
                    "test",
                    gateway
                        .jobs
                        .admit(&hellas_gateway::jobs::Request {
                            origin: hellas_gateway::jobs::Origin::Local,
                            method: "POST".into(),
                            path: "/v1/responses".into(),
                        })
                        .unwrap(),
                    hellas_gateway::WorkFetchRequest {
                        service: "openai".into(),
                        method: "responses".into(),
                        body: BODY.to_vec(),
                    },
                )
                .unwrap()
                .try_collect::<Vec<_>>();
            tokio::pin!(request);
            // Owner approval follows the authenticated quote. Leave that actual
            // funding transaction unfinalized beyond the connection allowance.
            tokio::select! {
                result = &mut request => panic!("request ended before funding: {result:?}"),
                () = case.approvals.1.notified() => {},
            }
            let held = tokio::time::timeout(Duration::from_secs(11), &mut request).await;
            let stayed_pending = held.is_err();
            let result = if stayed_pending {
                // Keep simulated block time realistic: sealing ten blocks per second
                // can expire the 16-block acceptance window before the provider
                // processes an otherwise timely request.
                sealing_while(&mut case.devnet, Duration::from_secs(1), &mut request).await
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
                let mut session = PaidWorkSession::open(
                    case.options.clone(),
                    endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Retained,
                    SessionFundingOptions::default(),
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
                "the request waits for funding finality: {result:?}"
            );
            assert!(elapsed > Duration::from_secs(10));
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
