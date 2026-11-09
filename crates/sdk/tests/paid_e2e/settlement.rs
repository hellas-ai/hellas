use super::*;
use commonware_cryptography::{Hasher as _, Sha256};
use hellas_private::Durability::Crash;
use hellas_private::StoreLocation;
use hellas_sdk::paid_client::{SessionFundingOptions, SessionOpenMode};

#[test]
fn paid_settlement_finishes_after_full_provider_shutdown() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Any,
                    SessionFundingOptions::default(),
                ),
            )
            .await
            .unwrap();
            let bond = session.descriptor().bond_edge();
            // A job on a ready channel needs no new blocks. Sealing here would
            // only advance the chain past the proposal's acceptance deadline.
            let result = session
                .run(
                    Some(case.prepared_input.clone()),
                    &empty_content(),
                    false,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.credited_cumulative, PRICE);
            session.shutdown().await;
            drop(session);
            let discovered = hellas_sdk::paid_client::retained_settlement_channels(
                &case.options.journal_root(),
                case.options.config.network(),
                case.options.provider,
                case.owner.principal(),
                case.owner.delegate(),
            )
            .await
            .unwrap();
            assert_eq!(discovered.len(), 1);
            assert_eq!(discovered[0].bond, bond);
            assert_eq!(discovered[0].price, PRICE);
            assert_eq!(discovered[0].assurance, Assurance::ProducerSigned);
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &case.options.journal_root(),
                    case.options.config.network(),
                    case.options.provider,
                    ROOT.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &case.options.journal_root(),
                    case.options.config.network(),
                    case.options.provider,
                    case.owner.principal(),
                    provider_settlement().party_key(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &case.options.journal_root(),
                    case.options.config.network(),
                    other_provider(&case.options).provider,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            let location = StoreLocation::for_test(&case.root.path().join("no-journals"));
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &location,
                    case.options.config.network(),
                    case.options.provider,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .unwrap()
                .is_empty()
            );
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &case.options.journal_root(),
                    hellas_kernel::NetworkId::new("wrong-network").unwrap(),
                    case.options.provider,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            let corrupt = case.root.path().join("corrupt");
            std::fs::create_dir_all(corrupt.join("journals")).unwrap();
            std::fs::write(
                corrupt
                    .join("journals")
                    .join(format!("setup-{}.sqlite", "00".repeat(32))),
                b"not a journal",
            )
            .unwrap();
            let other_location = StoreLocation::for_test(&corrupt);
            assert!(
                hellas_sdk::paid_client::retained_settlement_channels(
                    &other_location,
                    case.options.config.network(),
                    case.options.provider,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .is_err()
            );
            case.provider.shutdown().await.unwrap();
            // Use fresh RPC listeners so provider polling and queued requests from
            // the execution phase cannot enter the settlement proof-read count.
            case.relays.shutdown().await;
            case.relays = remote::Relays::start(&case.devnet).await;
            case.options.config.chain = case
                .options
                .config
                .chain
                .with_validators(case.relays.urls.clone())
                .unwrap();
            case.relays
                .source
                .forged
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement()
                )
                .await
                .is_err(),
                "unverified finalized RPC content cannot establish contest state"
            );
            case.relays
                .source
                .forged
                .store(false, std::sync::atomic::Ordering::SeqCst);

            // `sealing_while` bounds a hang; how long settlement takes under
            // load is not the property.
            let receipt = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement(),
                ),
            )
            .await
            .expect("client must finalize settlement after the entire provider stops");
            assert_eq!(receipt.provider_payout, PRICE);
            assert!(
                case.relays
                    .source
                    .attempts
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0,
                "settlement reads the channel by proof"
            );
            assert_eq!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate()
                )
                .await
                .unwrap(),
                Some(receipt),
            );
            case.relays
                .source
                .unavailable
                .store(false, std::sync::atomic::Ordering::SeqCst);
            case.endpoint.close().await;
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

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
            let error = PaidWorkSession::open(
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
            let error = PaidWorkSession::open(
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
            let path = hellas_sdk::transact::PaidAttemptPath::new(
                &case.options.config.chain,
                case.options.provider,
                case.owner.principal(),
                job.digest(),
            );
            let mut attempt =
                hellas_sdk::execution::ExecutionAttempt::open_paid(&path, job.input(), PRICE)
                    .unwrap();
            attempt
                .bind_target(hellas_sdk::execution::ExecutionTarget {
                    network: case.options.config.network(),
                    provider: case.options.provider,
                })
                .unwrap();
            drop(attempt);
            let mut attempt = hellas_sdk::execution::ExecutionAttempt::open_existing_paid(
                &path,
                job.input(),
                PRICE,
            )
            .unwrap();
            assert!(
                open_attempt(
                    &mut attempt,
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
            drop(attempt);
            gate.allow.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open(
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
            // Select another authenticated chain under the same home, then
            // return to the funded one. Its retained journal must be found
            // only after selecting A again.
            let a_chain = case.options.config.chain.clone();
            let a_journals = case.options.journal_root();
            let mut b_genesis = a_chain.genesis().clone();
            b_genesis.allocations[0].balance += 1;
            let b_genesis_json = serde_json::to_string(&b_genesis).unwrap();
            let mut b_trust = a_chain.trust().clone();
            b_trust.genesis_sha256 = hex::encode(Sha256::hash(b_genesis_json.as_bytes()));
            let b_profile = hellas_chain::genesis::ChainProfile::custom(
                hellas_chain::genesis::CustomChainFile {
                    genesis_json: b_genesis_json,
                    trust: b_trust,
                    validators: a_chain.validators().to_vec(),
                },
            )
            .unwrap();
            case.options.config.chain =
                hellas_chain::chain_dir::ChainDir::open(a_chain.home(), &b_profile).unwrap();
            assert_ne!(case.options.journal_root(), a_journals);
            let mut cross_chain_attempt =
                hellas_sdk::execution::ExecutionAttempt::open_existing_paid(
                    &path,
                    job.input(),
                    PRICE,
                )
                .unwrap();
            assert!(matches!(
                open_attempt(
                    &mut cross_chain_attempt,
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    hellas_sdk::paid_client::SessionFundingOptions::default(),
                )
                .await,
                Err(hellas_sdk::execution::ExecutionError::Identity)
            ));
            drop(cross_chain_attempt);
            assert!(
                hellas_sdk::paid_client::recover_funding_channels(&case.options, &case.owner)
                    .await
                    .unwrap()
                    .is_empty(),
                "chain B cannot recover chain A's funded channel"
            );
            case.options.config.chain = a_chain;
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
            let mut retained = PaidWorkSession::open(
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
            retained.shutdown().await;
            drop(retained);
            let journals = case.options.journal_root().join("journals");
            let journal = std::fs::read_dir(&journals)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("channel-")
                        && path
                            .extension()
                            .is_some_and(|extension| extension == "sqlite")
                })
                .unwrap();
            let hidden = journal.with_extension("saved");
            std::fs::rename(&journal, &hidden).unwrap();
            assert!(
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement(),
                )
                .await
                .is_err()
            );
            assert!(
                !journal.exists(),
                "settlement never creates replacement accounting"
            );
            std::fs::rename(hidden, &journal).unwrap();
            assert!(
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    ROOT.principal(),
                    &client_settlement(),
                )
                .await
                .is_err()
            );
            assert!(
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &provider_settlement(),
                )
                .await
                .is_err()
            );
            case.provider.shutdown().await.unwrap();
            // Drain execution-phase RPCs before counting settlement proof reads.
            case.relays.shutdown().await;
            case.relays = remote::Relays::start(&case.devnet).await;
            case.options.config.chain = case
                .options
                .config
                .chain
                .with_validators(case.relays.urls.clone())
                .unwrap();
            assert!(
                tokio::time::timeout(
                    SETTLE_CANCEL_AFTER,
                    hellas_sdk::paid_client::settle_channel(
                        &case.options,
                        bond,
                        case.owner.principal(),
                        &client_settlement(),
                    )
                )
                .await
                .is_err()
            );
            let stem = journal.file_stem().unwrap().to_str().unwrap();
            let (_, replay) = hellas_channel::work_store::journal::Journal::inspect(
                &case.options.journal_root(),
                stem,
            )
            .await
            .unwrap();
            assert!(
                replay.records.iter().any(|bytes| matches!(
                    hellas_channel::work_store::ChannelRecord::decode(bytes).unwrap(),
                    hellas_channel::work_store::ChannelRecord::ClosePrepared { .. }
                )),
                "cancellation retains the signed close intent"
            );
            let closed = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement(),
                ),
            )
            .await
            .unwrap();
            assert_eq!(closed.client_returned, CLIENT_FUNDING);
            assert_eq!(closed.provider_payout, 0);
            assert!(
                case.relays
                    .source
                    .attempts
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0,
                "settlement reads the channel by proof"
            );
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
                .unavailable
                .store(false, std::sync::atomic::Ordering::SeqCst);
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
            missing.config.chain = hellas_chain::chain_dir::ChainDir::open(
                &StoreLocation::from_home(&case.root.path().join("missing-journals"), Crash),
                &missing.config.chain,
            )
            .unwrap();
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
            let mut wrong_genesis = wrong_network.config.chain.genesis().clone();
            wrong_genesis.network_id = "wrong-network".into();
            let wrong_genesis_json = serde_json::to_string(&wrong_genesis).unwrap();
            let mut trust = wrong_network.config.chain.trust().clone();
            trust.network_id = "wrong-network".into();
            trust.genesis_sha256 = hex::encode(Sha256::hash(wrong_genesis_json.as_bytes()));
            let wrong_profile = hellas_chain::genesis::ChainProfile::custom(
                hellas_chain::genesis::CustomChainFile {
                    trust,
                    validators: wrong_network.config.chain.validators().to_vec(),
                    genesis_json: wrong_genesis_json,
                },
            )
            .unwrap();
            wrong_network.config.chain = hellas_chain::chain_dir::ChainDir::open(
                &StoreLocation::from_home(case.root.path(), Crash),
                &wrong_profile,
            )
            .unwrap();
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
            let funding_root = case.owner.chain().client().join("owners");
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
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

/// Run the public CLI against the same locally simulated paid channel used by
/// the SDK tests. The Nix CLI gate builds and supplies the executable.
#[test]
#[ignore = "requires the CLI executable supplied by the CLI integration gate"]
fn cli_settles_paid_channel_without_provider() {
    let binary =
        std::env::var_os("HELLAS_CLI_TEST_BINARY").expect("CLI integration gate supplies binary");
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Any,
                    SessionFundingOptions::default(),
                ),
            )
            .await
            .unwrap();
            let bond = session.descriptor().bond_edge();
            // A job on a ready channel needs no new blocks. Sealing here would
            // only advance the chain past the proposal's acceptance deadline.
            let result = session
                .run(
                    Some(case.prepared_input.clone()),
                    &empty_content(),
                    false,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.credited_cumulative, PRICE);
            let query = hellas_chain::work_view::WorkChannelQuery {
                bond_edge: bond,
                payment_edge: Some(session.descriptor().channel().payment_edge()),
                funding: Default::default(),
            };
            session.shutdown().await;
            drop(session);
            let root = case.root.path();
            let state = root.join("cli-state");
            let cli_chain = hellas_chain::chain_dir::ChainDir::open(
                &StoreLocation::from_home(&state, Crash),
                &case.options.config.chain,
            )
            .unwrap();
            let journals = cli_chain.client_journals(&case.options.provider.to_string());
            std::fs::create_dir_all(journals.parent().unwrap()).unwrap();
            std::fs::rename(case.options.journal_root(), &journals).unwrap();
            case.options.config.chain = cli_chain;

            let (passkey, chain_path) = write_cli_home(&case, &state);
            case.provider.shutdown().await.unwrap();
            // Drain execution-phase RPCs before counting settlement proof reads.
            case.relays.shutdown().await;
            case.relays = remote::Relays::start(&case.devnet).await;
            case.options.config.chain = case
                .options
                .config
                .chain
                .with_validators(case.relays.urls.clone())
                .unwrap();
            assert!(
                tokio::time::timeout(
                    SETTLE_CANCEL_AFTER,
                    hellas_sdk::paid_client::settle_channel(
                        &case.options,
                        bond,
                        case.owner.principal(),
                        &client_settlement(),
                    ),
                )
                .await
                .is_err()
            );
            let journal = std::fs::read_dir(case.options.journal_root().join("journals"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("channel-")
                        && path.extension().is_some_and(|ext| ext == "sqlite")
                })
                .unwrap();
            let stem = journal.file_stem().unwrap().to_str().unwrap();
            let (_, replay) = hellas_channel::work_store::journal::Journal::inspect(
                &case.options.journal_root(),
                stem,
            )
            .await
            .unwrap();
            assert!(
                replay.records.iter().any(|bytes| matches!(
                    hellas_channel::work_store::ChannelRecord::decode(bytes).unwrap(),
                    hellas_channel::work_store::ChannelRecord::ClosePrepared { .. }
                )),
                "CLI must resume an already prepared close"
            );
            let mut command = tokio::process::Command::new(&binary);
            command
                .arg("--home")
                .arg(&state)
                .arg("--passkey")
                .arg(&passkey)
                .arg("--chain-config")
                .arg(&chain_path)
                .arg("transact")
                .arg("--settle")
                .arg("--provider")
                .arg(case.options.provider.to_string())
                .arg("--timeout")
                .arg("60s");
            for validator in &case.relays.urls {
                command.arg("--validator").arg(validator);
            }
            let output = sealing_through_close(&mut case.devnet, query, command.output())
                .await
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains(&format!("provider payout {PRICE}")),
                "{stdout}"
            );
            assert!(
                case.relays
                    .source
                    .attempts
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0,
                "settlement reads the channel by proof"
            );
            // A different owner must not close this channel, even when the
            // journal is present and the provider cannot be contacted.
            let wrong_passkey = root.join("wrong-passkey");
            hellas_private::write_atomically(&wrong_passkey, ".writing", &[0x11; 32]).unwrap();
            let mut wrong = tokio::process::Command::new(&binary);
            wrong
                .arg("--home")
                .arg(&state)
                .arg("--passkey")
                .arg(&wrong_passkey)
                .arg("--chain-config")
                .arg(&chain_path)
                .arg("transact")
                .arg("--settle")
                .arg("--provider")
                .arg(case.options.provider.to_string())
                .arg("--timeout")
                .arg("60s");
            for validator in &case.relays.urls {
                wrong.arg("--validator").arg(validator);
            }
            let wrong = wrong.output().await.unwrap();
            assert!(!wrong.status.success());
            assert!(String::from_utf8_lossy(&wrong.stderr).contains("settlement client identity"));
            let receipt = hellas_sdk::paid_client::finalized_channel_settlement(
                &case.options,
                bond,
                case.owner.principal(),
                case.owner.delegate(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(receipt.provider_payout, PRICE);
            assert_eq!(
                receipt.client_returned + receipt.provider_payout,
                CLIENT_FUNDING
            );
            case.endpoint.close().await;
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

/// The response is finalized while the settlement client is absent. Recovery
/// must use its increased cumulative, omission penalty and contest commitment.
#[test]
fn settlement_replays_a_finalized_response_after_full_provider_shutdown() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Any,
                    SessionFundingOptions::default(),
                ),
            )
            .await
            .unwrap();
            // A job on a ready channel needs no new blocks. Sealing here would
            // only advance the chain past the proposal's acceptance deadline.
            let result = session
                .run(
                    Some(case.prepared_input.clone()),
                    &empty_content(),
                    false,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.credited_cumulative, PRICE);
            let certificate = session
                .with_state(|state| state.executable_certificate())
                .await
                .unwrap()
                .unwrap();
            let channel = session.descriptor().channel().clone();
            let bond = session.descriptor().bond_edge();
            session.shutdown().await;
            drop(session);
            case.provider.shutdown().await.unwrap();
            // Drain execution-phase RPCs before counting settlement proof reads.
            case.relays.shutdown().await;
            case.relays = remote::Relays::start(&case.devnet).await;
            case.options.config.chain = case
                .options
                .config
                .chain
                .with_validators(case.relays.urls.clone())
                .unwrap();

            // A client-signed understatement is answered by the certificate actually
            // earned above. Both moves pass through the real consensus kernel.
            let start = hellas_channel::work_close::close_start(
                &channel,
                hellas_kernel::Party::Maker,
                case.devnet.height(),
                None,
                &client_settlement(),
            )
            .unwrap();
            let tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(
                start.clone(),
            ));
            case.relays
                .source
                .local
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx.clone()))
                .await
                .unwrap();
            let block = case.devnet.seal().await;
            assert!(
                block
                    .txs()
                    .iter()
                    .any(|found| matches!(found, hellas_chain::domain::Transaction::Kernel(found) if *found == tx))
            );
            let pending = hellas_kernel::PendingPaymentClose::from_accepted_start(
                case.options.config.network(),
                case.devnet.height(),
                block.timestamp(),
                &start,
            )
            .unwrap();
            let response = hellas_channel::work_close::close_response(
                &channel,
                pending.start_id(),
                certificate,
                &provider_settlement(),
            )
            .unwrap();
            let tx =
                hellas_kernel::Tx::move_action(hellas_kernel::Move::RespondPaymentClose(response));
            case.relays
                .source
                .local
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx.clone()))
                .await
                .unwrap();
            let block = case.devnet.seal().await;
            assert!(
                block
                    .txs()
                    .iter()
                    .any(|found| matches!(found, hellas_chain::domain::Transaction::Kernel(found) if *found == tx))
            );
            assert!(block.timestamp() < pending.response_deadline_ms());

            let receipt = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement(),
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                receipt.provider_payout,
                PRICE + channel.payment_terms().omission_bond
            );
            assert_eq!(
                receipt.client_returned + receipt.provider_payout,
                CLIENT_FUNDING
            );
            assert!(
                case.relays
                    .source
                    .attempts
                    .load(std::sync::atomic::Ordering::SeqCst)
                    > 0,
                "settlement reads the channel by proof"
            );
            assert_eq!(
                hellas_sdk::paid_client::finalized_channel_settlement(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    case.owner.delegate(),
                )
                .await
                .unwrap(),
                Some(receipt)
            );
            case.endpoint.close().await;
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

/// When the settlement-cancellation tests drop an in-flight settlement. It
/// journals its prepared close within about a second on an idle machine and
/// cannot finish while no block is sealed to include it; 20 s falls between
/// the two even on a loaded machine.
const SETTLE_CANCEL_AFTER: Duration = Duration::from_secs(20);

/// A client that opens a close below what it already signed for is answered
/// by the running provider's own clock, inside the response window: the
/// provider follows the channel by proof reads alone, sees the contest in
/// the pending-close slot, and its answer lands before the deadline's block
/// time. Settlement then pays the earned amount and the omission penalty,
/// read back from the two payout coins.
#[test]
fn a_client_understatement_is_answered_by_the_provider_clock_within_the_window() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let mut session = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                PaidWorkSession::open(
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionOpenMode::Any,
                    SessionFundingOptions::default(),
                ),
            )
            .await
            .unwrap();
            let result = session
                .run(
                    Some(case.prepared_input.clone()),
                    &empty_content(),
                    false,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.credited_cumulative, PRICE);
            let channel = session.descriptor().channel().clone();
            let bond = session.descriptor().bond_edge();
            session.shutdown().await;
            drop(session);

            // The client claims nothing, although it signed for PRICE.
            let start = hellas_channel::work_close::close_start(
                &channel,
                hellas_kernel::Party::Maker,
                case.devnet.height(),
                None,
                &client_settlement(),
            )
            .unwrap();
            let tx = hellas_kernel::Tx::move_action(hellas_kernel::Move::StartPaymentClose(start));
            case.devnet
                .validator_light_client(0)
                .submit_tx(hellas_chain::domain::Transaction::Kernel(tx))
                .await
                .unwrap();
            let opened = case.devnet.seal().await;
            let deadline = opened.timestamp() + hellas_kernel::RESPONSE_WINDOW_MS;

            // Blocks keep coming, one second of block time apiece, until the
            // provider's answer is in the slot. Nothing here answers for it.
            let query = hellas_chain::work_view::WorkChannelQuery {
                bond_edge: channel.payment_terms().bond_edge,
                payment_edge: Some(channel.payment_edge()),
                funding: Default::default(),
            };
            let local = hellas_chain::WorkBlocks::new(case.devnet.validator_light_client(0));
            let answered = sealing_while(&mut case.devnet, Duration::from_millis(500), async {
                loop {
                    let snapshot = local
                        .work_channel_snapshot(query.clone())
                        .await
                        .unwrap()
                        .unwrap();
                    if let hellas_kernel::PendingSlot::Present(pending) = snapshot.pending()
                        && pending.responded()
                    {
                        return (pending, snapshot.certified_at_ms());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await;
            let (pending, seen_at) = answered;
            assert_eq!(pending.response_deadline_ms(), deadline);
            assert!(
                seen_at < deadline,
                "the answer is in a block stamped before the deadline"
            );
            assert_eq!(
                pending.final_cumulative(),
                PRICE,
                "the answer spends the certificate the client left out"
            );
            assert!(
                pending.penalty_due(),
                "the understatement forfeits the bond"
            );

            let receipt = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                hellas_sdk::paid_client::settle_channel(
                    &case.options,
                    bond,
                    case.owner.principal(),
                    &client_settlement(),
                ),
            )
            .await
            .unwrap();
            assert_eq!(
                receipt.provider_payout,
                PRICE + channel.payment_terms().omission_bond,
                "the provider's payout coin holds the earned amount and the penalty"
            );
            assert_eq!(
                receipt.client_returned + receipt.provider_payout,
                CLIENT_FUNDING
            );
            case.provider.shutdown().await.unwrap();
            case.endpoint.close().await;
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

/// Writes the CLI's view of this scenario into `state`: the client identity
/// whose node signer ([0x21; 32]) already holds the funding delegation, the
/// owner passkey, and a custom chain file naming this devnet and its relays.
/// Returns the passkey path and the chain file path.
fn write_cli_home(
    case: &PaidScenario<()>,
    state: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let root = case.root.path();
    // The client's already-funded node signer is [0x21; 32]. Encode a
    // normal private identity containing exactly that signer for the CLI.
    let root_key = ProducerSigningKey::from_secret_bytes([0x41; 32]).unwrap();
    let node_key = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let transport = iroh::SecretKey::from_bytes(&[0x42; 32]);
    let enrollment = enrollment(
        &root_key,
        &node_key,
        *transport.public().as_bytes(),
        [0x43; 32],
    );
    let mut identity = hellas_rpc::DagCborEncoder::new();
    identity.array(6);
    identity.str("hellas.provider.identity.persistence.v3");
    identity.u64(3);
    identity.array(2);
    identity.u64(0);
    identity.bytes(&[0x41; 32]);
    identity.bytes(&[0x21; 32]);
    identity.bytes(&[0x42; 32]);
    identity.bytes(&enrollment.canonical_bytes());
    let identity_path = state.join("identity");
    hellas_private::write_atomically(&identity_path, ".writing", &identity.into_bytes()).unwrap();
    let passkey = root.join("cli-passkey");
    hellas_private::write_atomically(&passkey, ".writing", &[0x13; 32]).unwrap();
    let genesis = serde_json::to_vec(case.devnet.genesis()).unwrap();
    let trust = serde_json::json!({
        "schema_version": 1,
        "network_id": case.devnet.network().as_str(),
        "genesis_sha256": hex::encode(Sha256::hash(&genesis)),
        "epochs": [{"epoch":0,"start_height":0,"end_height":null,
                    "threshold_identity":hex::encode(&case.devnet.consensus_info().threshold_identity)}],
    });
    let chain_path = root.join("cli-chain.json");
    std::fs::write(
        &chain_path,
        serde_json::to_vec(&serde_json::json!({
            "trust": trust,
            "validators": case.relays.urls,
            "genesis_json": String::from_utf8(genesis).unwrap(),
        }))
        .unwrap(),
    )
    .unwrap();
    (passkey, chain_path)
}

/// Run the public CLI's paid purchase end to end: quote, fund a channel
/// with the owner passkey, upload, execute, verify and pay, all from one
/// `hellas transact --job` process against the simulated chain.
#[test]
#[ignore = "requires the CLI executable supplied by the CLI integration gate"]
fn cli_buys_a_paid_job_end_to_end() {
    let binary =
        std::env::var_os("HELLAS_CLI_TEST_BINARY").expect("CLI integration gate supplies binary");
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let root = case.root.path().to_path_buf();
            let state = root.join("cli-buyer");
            std::fs::create_dir_all(&state).unwrap();
            let (passkey, chain_path) = write_cli_home(&case, &state);
            let job = hellas_sdk::job::Job::fetch(
                PRICE,
                test_responses_contract(),
                "openai".into(),
                "responses".into(),
                BODY.to_vec(),
                Assurance::ProducerSigned,
            )
            .unwrap();
            let job_dir = root.join("cli-job");
            job.save(&job_dir).await.unwrap();
            let mut command = tokio::process::Command::new(&binary);
            command
                .arg("--home")
                .arg(&state)
                .arg("--passkey")
                .arg(&passkey)
                .arg("--chain-config")
                .arg(&chain_path)
                .arg("transact")
                .arg("--job")
                .arg(&job_dir)
                .arg("--provider")
                .arg(case.options.provider.to_string())
                .arg("--timeout")
                .arg("120s")
                // Inside the fixture bond's short admission horizon.
                .args(["--acceptance-blocks", "60"])
                .args(["--terminal-blocks", "40"])
                .args(["--payment-blocks", "40"]);
            for address in &case.options.provider_addrs {
                command.arg("--address").arg(address.to_string());
            }
            for validator in &case.relays.urls {
                command.arg("--validator").arg(validator);
            }
            let output = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                command.output(),
            )
            .await
            .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "stdout: {stdout}\nstderr: {stderr}"
            );
            assert!(
                stdout.contains(&format!("paid {PRICE}"))
                    || stderr.contains(&format!("paid {PRICE}")),
                "the CLI paid the job's price\nstdout: {stdout}\nstderr: {stderr}"
            );
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}
