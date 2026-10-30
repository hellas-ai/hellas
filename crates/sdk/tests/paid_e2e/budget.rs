use super::*;
use hellas_sdk::paid_client::{
    FundingApproval, PaidClientError, SessionFundingOptions, SessionOpenMode,
};
use std::{collections::BTreeMap, sync::Mutex};

/// Each purchase reopens the retained channel with no fresh funding allowance.
/// The one funding allocation is also the entire lifetime budget.
#[test]
fn consecutive_jobs_reuse_bounded_funding_and_closing_channels_never_refund_it() {
    run(|runtime| {
        Box::pin(async move {
            struct BudgetState {
                reservation: [u8; 16],
                allocations: BTreeMap<[u8; 16], u64>,
                calls: usize,
            }
            struct Budget(Mutex<BudgetState>);
            impl FundingApproval for Budget {
                fn reservation(
                    &self,
                    _: hellas_kernel::NetworkId,
                    _: iroh::EndpointId,
                ) -> [u8; 16] {
                    self.0.lock().unwrap().reservation
                }
                fn reserve(
                    &self,
                    reservation: [u8; 16],
                    amount: u64,
                ) -> futures::future::BoxFuture<'_, Result<(), PaidClientError>> {
                    Box::pin(async move {
                        let mut state = self.0.lock().unwrap();
                        state.calls += 1;
                        if let Some(held) = state.allocations.get(&reservation) {
                            assert_eq!(*held, amount);
                            return Ok(());
                        }
                        let reserved: u64 = state.allocations.values().sum();
                        if amount > CLIENT_FUNDING - reserved {
                            return Err(PaidClientError::InvalidOptions("budget exhausted"));
                        }
                        state.allocations.insert(reservation, amount);
                        Ok(())
                    })
                }
                fn recover(
                    &self,
                    reservation: [u8; 16],
                    amount: u64,
                ) -> futures::future::BoxFuture<'_, Result<(), PaidClientError>> {
                    Box::pin(async move {
                        assert_eq!(
                            self.0.lock().unwrap().allocations.get(&reservation),
                            Some(&amount)
                        );
                        Ok(())
                    })
                }
            }
            let mut case = paid_fixture(runtime).await;
            let job = hellas_sdk::job::Job::fetch(
                PRICE,
                test_responses_contract(),
                "openai".into(),
                "responses".into(),
                BODY.to_vec(),
                Assurance::ProducerSigned,
            )
            .unwrap();
            let producer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
            let budget = Arc::new(Budget(Mutex::new(BudgetState {
                reservation: [7; 16],
                allocations: BTreeMap::new(),
                calls: 0,
            })));
            let mut bond = None;
            for n in 0..10 {
                let mut session =
                    sealing_while(&mut case.devnet, Duration::from_millis(100), async {
                        loop {
                            let opened = PaidWorkSession::open_with_options(
                                case.options.clone(),
                                case.endpoint.clone(),
                                client_settlement(),
                                case.owner.clone(),
                                SessionOpenMode::Job(&job),
                                SessionFundingOptions {
                                    max_funding: Some(if n == 0 { 1000 } else { 0 }),
                                    approval: Some(budget.clone()),
                                },
                            )
                            .await;
                            // The client can verify funding before the provider's
                            // full node applies that block. Resume the signed intent
                            // on the next opening attempt; never reserve/sign twice.
                            match opened {
                                Err(hellas_sdk::paid_client::PaidClientError::OfferRefused(
                                    code,
                                )) if code
                                    == hellas_rpc::pb::work::OfferRefusalCode::NeedsFunding
                                        as i32 =>
                                {
                                    tokio::time::sleep(case.options.config.poll).await;
                                }
                                result => break result,
                            }
                        }
                    })
                    .await
                    .unwrap_or_else(|error| panic!("opening job {n}: {error}"));
                assert_eq!(
                    *bond.get_or_insert(session.descriptor().bond_edge()),
                    session.descriptor().bond_edge()
                );
                let mut purchase = hellas_sdk::transact::Purchase::open(
                    &case.root.path().join(format!("purchase-{n}.json")),
                    &job,
                    false,
                )
                .unwrap();
                let result = tokio::time::timeout(
                    Duration::from_secs(30),
                    hellas_sdk::transact::transact(
                        &mut session,
                        &job,
                        &producer,
                        hellas_sdk::transact::TransactionOptions {
                            purchase: Some(&mut purchase),
                            ..Default::default()
                        },
                    ),
                )
                .await
                .expect("consecutive retained job completes")
                .unwrap();
                assert_eq!(result.credited_cumulative, PRICE * (n + 1));
                purchase.reported().unwrap();
                assert_eq!(
                    budget.0.lock().unwrap().allocations,
                    BTreeMap::from([([7; 16], CLIENT_FUNDING)])
                );
                assert_eq!(budget.0.lock().unwrap().calls, 1);
                assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
                session
                    .with_state(|state| {
                        assert_eq!(state.jobs().len(), 0);
                        assert_eq!(
                            state.ledger().credited_cumulative() + PRICE
                                > state.settlement().capacity(),
                            n == 9
                        );
                    })
                    .await
                    .unwrap();
                session.shutdown().await;
            }
            eprintln!("retained-budget: ten paid jobs used one funding allocation");
            // Exhaustion does not allocate a replacement. Persist a close, interrupt
            // before any block finalizes it, and reopen that same closing channel.
            let mut session = PaidWorkSession::open_retained(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
            )
            .await
            .unwrap();
            // A timeout can fire before the future reaches its durable write
            // when several simulated networks run at once. Retry that same
            // close until the recorded state, rather than elapsed wall time,
            // proves the interruption point was reached.
            let mut closing = false;
            for _ in 0..100 {
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), session.settle())
                        .await
                        .is_err()
                );
                closing = session
                    .with_state(|state| state.is_closing())
                    .await
                    .unwrap();
                if closing {
                    break;
                }
            }
            assert!(
                closing,
                "close intent was not persisted within the fixture bound"
            );
            session.shutdown().await;
            drop(session);
            let mut session = PaidWorkSession::open_with_options(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionOpenMode::Job(&job),
                SessionFundingOptions {
                    max_funding: Some(0),
                    approval: Some(budget.clone()),
                },
            )
            .await
            .unwrap();
            assert_eq!(Some(session.descriptor().bond_edge()), bond);
            assert!(
                session
                    .with_state(|state| state.is_closing())
                    .await
                    .unwrap()
            );
            // The caller settles a closing/exhausted channel
            // before calling transact, which would otherwise save a new intent.
            assert_eq!(
                session
                    .with_state(|state| state.jobs().len())
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(budget.0.lock().unwrap().calls, 1);
            assert_eq!(
                sealing_while(
                    &mut case.devnet,
                    Duration::from_millis(100),
                    session.settle()
                )
                .await
                .unwrap(),
                PRICE * 10
            );
            session.shutdown().await;
            drop(session);
            eprintln!("retained-budget: interrupted close finalized its ten payments");
            // Use a new reservation for a deliberate replacement channel. Closing
            // alone does not release budget: until verified returns are recorded,
            // a fresh quote must fail before signing.
            budget.0.lock().unwrap().reservation = [8; 16];
            let refused = sealing_while(&mut case.devnet, Duration::from_millis(100), async {
                loop {
                    let opened = PaidWorkSession::open_with_options(
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionOpenMode::Job(&job),
                        SessionFundingOptions {
                            max_funding: Some(1000),
                            approval: Some(budget.clone()),
                        },
                    )
                    .await;
                    // The provider must reclaim its old bond before offering a
                    // replacement; that wait must not be mistaken for budget refusal.
                    match opened {
                        Err(hellas_sdk::paid_client::PaidClientError::OfferRefused(code))
                            if code
                                == hellas_rpc::pb::work::OfferRefusalCode::NoStakeAvailable
                                    as i32 =>
                        {
                            tokio::time::sleep(case.options.config.poll).await;
                        }
                        result => break result,
                    }
                }
            })
            .await
            .err()
            .expect("replacement channel exceeds the budget");
            assert!(
                matches!(
                    refused,
                    hellas_sdk::paid_client::PaidClientError::Owner(
                        hellas_sdk::client_owner::ClientOwnerError::Record(
                            "application funding denied"
                        )
                    )
                ),
                "{refused}"
            );
            assert_eq!(budget.0.lock().unwrap().calls, 2);
            assert_eq!(
                budget.0.lock().unwrap().allocations,
                BTreeMap::from([([7; 16], CLIENT_FUNDING)])
            );
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            case.endpoint.close().await;
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}
