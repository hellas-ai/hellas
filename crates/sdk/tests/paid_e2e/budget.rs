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
                // The SDK retries funding visibility on the same connection;
                // a failed session open must fail the test, not start another.
                let open = PaidWorkSession::open(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Job(&job),
                    SessionFundingOptions {
                        max_funding: Some(if n == 0 { 1000 } else { 0 }),
                        approval: Some(budget.clone()),
                    },
                );
                // Only the first opening funds a channel. Reconnecting to it
                // needs no blocks: sealing on a wall-clock timer here would
                // age the bond according to the CI runner's network speed.
                let opened = if n == 0 {
                    sealing_while(&mut case.devnet, Duration::from_millis(100), open).await
                } else {
                    tokio::time::timeout(Duration::from_secs(120), open)
                        .await
                        .expect("retained channel reopens without advancing the chain")
                };
                let mut session = opened.unwrap_or_else(|error| panic!("opening job {n}: {error}"));
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
            let bond = bond.expect("ten jobs used one retained bond");
            let verifier = hellas_kernel::Secp256k1Verifier::new();
            let setup = hellas_channel::work_store::SetupStore::open_existing(
                &case.options.journal_root,
                case.options.config.chain.network,
                bond,
                hellas_channel::work_store::Role::Client,
                &verifier,
            )
            .await
            .unwrap();
            let descriptor = setup.state().close_descriptor().unwrap().clone();
            let origin = setup.state().origin().unwrap();
            drop(setup);
            let channel = hellas_channel::work_store::ChannelStore::open_existing(
                &case.options.journal_root,
                descriptor.channel().clone(),
                descriptor.expected_settlement().unwrap(),
                hellas_channel::work_store::Role::Client,
                origin,
                case.options.content.clone(),
                &verifier,
            )
            .await
            .unwrap();
            let mut endpoint =
                hellas_channel::work::ClientEndpoint::recover(channel, client_settlement())
                    .unwrap();
            endpoint.prepare_close().await.unwrap();
            drop(endpoint); // Crash after the close intent is durable, before submission.
            let mut session = PaidWorkSession::open(
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
            assert_eq!(session.descriptor().bond_edge(), bond);
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
            // Observe reclamation through the provider's finalized view. Opening
            // fresh QUIC connections every poll interval competes with admission
            // limits and tests connection timing instead of the funding budget.
            sealing_while(&mut case.devnet, Duration::from_millis(100), async {
                let mut finalized = case.provider_node.finalized();
                let chain = case.provider_node.wait_ready().await.unwrap().client();
                loop {
                    finalized.borrow_and_update();
                    let snapshot = chain
                        .work_channel_snapshot(hellas_chain::work_view::WorkChannelQuery {
                            bond_edge: bond,
                            payment_edge: Some(descriptor.channel().payment_edge()),
                            funding: Default::default(),
                        })
                        .await;
                    match snapshot {
                        Ok(Some(snapshot))
                            if snapshot.bond().is_none() && snapshot.payment().is_none() =>
                        {
                            break;
                        }
                        Ok(_)
                        | Err(hellas_chain::QueryError::StateUnavailable(_))
                        | Err(hellas_chain::QueryError::NotYetApplied) => {}
                        Err(error) => panic!("reading provider reclamation state: {error}"),
                    }
                    finalized.changed().await.expect("provider remains running");
                }
            })
            .await;
            let refused = PaidWorkSession::open(
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
