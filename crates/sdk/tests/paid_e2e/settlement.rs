use super::*;

/// Application budgets gate the actual owner funding, not quote discovery or
/// reopening a channel that has already been funded.
#[test]
fn empty_channel_settlement_recovers_exact_return_and_rejects_wrong_identity() {
    run(|runtime| {
        Box::pin(async move {
            struct Gate {
                amounts: std::sync::Mutex<Vec<u64>>,
                allow: std::sync::atomic::AtomicBool,
            }
            impl hellas_sdk::paid_client::FundingApproval for Gate {
                fn reservation(
                    &self,
                    _: hellas_kernel::NetworkId,
                    _: iroh::EndpointId,
                ) -> [u8; 16] {
                    [9; 16]
                }
                fn reserve(
                    &self,
                    _: [u8; 16],
                    amount: u64,
                ) -> futures::future::BoxFuture<
                    '_,
                    Result<(), hellas_sdk::paid_client::PaidClientError>,
                > {
                    Box::pin(async move {
                        self.amounts.lock().unwrap().push(amount);
                        if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
                            Ok(())
                        } else {
                            Err(hellas_sdk::paid_client::PaidClientError::InvalidOptions(
                                "budget refused",
                            ))
                        }
                    })
                }
                fn recover(
                    &self,
                    _: [u8; 16],
                    _: u64,
                ) -> futures::future::BoxFuture<
                    '_,
                    Result<(), hellas_sdk::paid_client::PaidClientError>,
                > {
                    Box::pin(async { Ok(()) })
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
            let gate = Arc::new(Gate {
                amounts: std::sync::Mutex::new(vec![]),
                allow: std::sync::atomic::AtomicBool::new(false),
            });
            let error = PaidWorkSession::open_with_options(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                hellas_sdk::paid_client::SessionOpenMode::Job(&job),
                hellas_sdk::paid_client::SessionFundingOptions {
                    max_funding: Some(CLIENT_FUNDING - 1),
                    approval: Some(gate.clone()),
                },
            )
            .await
            .err()
            .expect("over-cap quote refused");
            assert!(matches!(
                error,
                hellas_sdk::paid_client::PaidClientError::InvalidOptions(
                    "quote exceeds caller funding cap"
                )
            ));
            assert!(gate.amounts.lock().unwrap().is_empty());
            let error = PaidWorkSession::open_with_options(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                hellas_sdk::paid_client::SessionOpenMode::Job(&job),
                hellas_sdk::paid_client::SessionFundingOptions {
                    max_funding: Some(CLIENT_FUNDING),
                    approval: Some(gate.clone()),
                },
            )
            .await
            .err()
            .expect("budget refusal prevents funding");
            assert!(matches!(
                error,
                hellas_sdk::paid_client::PaidClientError::Owner(
                    hellas_sdk::client_owner::ClientOwnerError::Record(
                        "application funding denied"
                    )
                )
            ));
            assert_eq!(*gate.amounts.lock().unwrap(), vec![CLIENT_FUNDING]);
            assert!(case.approvals.0.lock().unwrap().is_empty());
            // A crash after target binding cannot authorize fresh funding on reopen.
            let path = case.root.path().join("bound-attempt.json");
            let terms = hellas_sdk::execution::ExecutionTerms::Paid { price: PRICE };
            let mut attempt =
                hellas_sdk::execution::ExecutionAttempt::open(&path, job.input(), terms).unwrap();
            attempt
                .bind_target(hellas_sdk::execution::ExecutionTarget {
                    network: case.options.config.chain.network,
                    provider: case.options.provider,
                })
                .unwrap();
            drop(attempt);
            let mut attempt =
                hellas_sdk::execution::ExecutionAttempt::open_existing(&path, job.input(), terms)
                    .unwrap();
            assert!(
                attempt
                    .open_paid_session(
                        job.input(),
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        hellas_sdk::paid_client::SessionFundingOptions {
                            max_funding: Some(CLIENT_FUNDING),
                            approval: Some(gate.clone()),
                        }
                    )
                    .await
                    .is_err()
            );
            assert_eq!(*gate.amounts.lock().unwrap(), vec![CLIENT_FUNDING]);
            assert!(case.approvals.0.lock().unwrap().is_empty());
            gate.allow.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open_with_options(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    hellas_sdk::paid_client::SessionOpenMode::Job(&job),
                    hellas_sdk::paid_client::SessionFundingOptions {
                        max_funding: Some(CLIENT_FUNDING + 100),
                        approval: Some(gate.clone()),
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                *gate.amounts.lock().unwrap(),
                vec![CLIENT_FUNDING, CLIENT_FUNDING]
            );
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            let bond = session.descriptor().bond_edge();
            session.shutdown().await;
            drop(session);
            let associations =
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .unwrap();
            assert_eq!(associations.len(), 1);
            assert_eq!(associations[0].reservation, [9; 16]);
            assert_eq!(associations[0].bond_edge, bond);
            assert_eq!(associations[0].funding_value, CLIENT_FUNDING);
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .unwrap()
                .is_none(),
                "open funding cannot be recycled"
            );
            gate.allow.store(false, std::sync::atomic::Ordering::SeqCst);
            let mut retained = PaidWorkSession::open_with_options(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                hellas_sdk::paid_client::SessionOpenMode::Job(&job),
                hellas_sdk::paid_client::SessionFundingOptions {
                    max_funding: Some(0),
                    approval: Some(gate.clone()),
                },
            )
            .await
            .unwrap();
            assert_eq!(retained.descriptor().bond_edge(), bond);
            assert_eq!(
                *gate.amounts.lock().unwrap(),
                vec![CLIENT_FUNDING, CLIENT_FUNDING]
            );
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                retained.settle(),
            )
            .await
            .unwrap();
            retained.shutdown().await;
            drop(retained);
            let receipt = hellas_sdk::paid_client::finalized_channel_settlement(
                &case.options,
                bond,
                case.owner.principal(),
                case.owner.delegate(),
            )
            .await
            .unwrap()
            .expect("finalized empty channel return");
            assert_eq!(receipt.funding_value, CLIENT_FUNDING);
            assert_eq!(receipt.client_returned, CLIENT_FUNDING);
            assert_eq!(receipt.provider_payout, 0);
            case.relays
                .source
                .tips_unavailable
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let mut unavailable = case.options.clone();
            unavailable.timeout = Some(Duration::from_millis(100));
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &unavailable,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err(),
                "missing verified chain evidence cannot establish a refund"
            );
            case.relays
                .source
                .tips_unavailable
                .store(false, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .unwrap(),
                associations,
                "closed channel retains its original funding association"
            );
            assert!(
                hellas_sdk::paid_client::recover_funding_channels(
                    &other_provider(&case.options),
                    &case.owner
                )
                .await
                .unwrap()
                .is_empty()
            );
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    bond,
                    ROOT.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &other_provider(&case.options),
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            let mut wrong_node = case.options.clone();
            wrong_node.provider.node = iroh::SecretKey::generate().public();
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &wrong_node,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    provider_settlement().party_key(),
                )
                .await
                .is_err()
            );
            let mut missing = case.options.clone();
            missing.journal_root = case.root.path().join("missing-journals");
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &missing,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            let mut wrong_network = case.options.clone();
            wrong_network.config.chain.network =
                hellas_kernel::NetworkId::new("wrong-network").unwrap();
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &wrong_network,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    hellas_kernel::EdgeId::from_bytes([0; 32]),
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            // Two reservation IDs naming the same signed funding coin must never
            // become two budget returns. Corrupt amounts must fail signature/output
            // validation rather than matching by a nearby quote.
            let funding_root = case.root.path().join("requester/funding");
            let history = std::fs::read_dir(&funding_root)
                .unwrap()
                .map(|entry| entry.unwrap().path().join("funding-intents"))
                .find(|path| path.is_dir())
                .unwrap();
            let archived = history.join(format!("{}.json", hex::encode([9u8; 16])));
            let original = std::fs::read(&archived).unwrap();
            let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
            record["reservation"] = serde_json::json!([8u8; 16].to_vec());
            let duplicate = history.join(format!("{}.json", hex::encode([8u8; 16])));
            std::fs::write(&duplicate, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .is_err()
            );
            std::fs::remove_file(&duplicate).unwrap();
            record = serde_json::from_slice(&original).unwrap();
            record["need"] = serde_json::json!(CLIENT_FUNDING + 1);
            std::fs::write(&archived, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .is_err()
            );
            std::fs::write(&archived, &original).unwrap();
            assert_eq!(
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .unwrap(),
                associations
            );
            assert_eq!(
                case.approvals.0.lock().unwrap().len(),
                1,
                "metadata recovery never requests another signature"
            );
            case.endpoint.close().await;
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}
