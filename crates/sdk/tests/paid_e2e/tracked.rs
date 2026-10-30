use super::*;
use hellas_sdk::execution::{
    Acceptance, ExecutionAttempt, ExecutionError, ExecutionObservers, ExecutionResult,
    ExecutionSession, ExecutionTerms, Payment, Terminal,
};
use hellas_sdk::paid_client::{PaidClientError, SessionFundingOptions};

fn job() -> hellas_sdk::job::Job {
    hellas_sdk::job::Job::fetch(
        PRICE,
        test_responses_contract(),
        "openai".into(),
        "responses".into(),
        BODY.to_vec(),
        Assurance::ProducerSigned,
    )
    .unwrap()
}

// Establish fixture funding separately from the tracked attempts under test.
async fn fund(case: &mut PaidScenario<()>) {
    let mut session = sealing_while(&mut case.devnet, Duration::from_millis(100), async {
        loop {
            match PaidWorkSession::open(
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
            )
            .await
            {
                Err(PaidClientError::OfferRefused(code))
                    if code == hellas_rpc::pb::work::OfferRefusalCode::NeedsFunding as i32 =>
                {
                    tokio::time::sleep(case.options.config.poll).await;
                }
                result => break result,
            }
        }
    })
    .await
    .unwrap();
    session.shutdown().await;
}

#[test]
fn tracked_attempts_reuse_retained_policy_with_zero_funding_cap() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            let job = job();
            let terms = ExecutionTerms::Paid { price: PRICE };
            let gate = Arc::new(RetryFunding::default());
            let mut mismatch = ExecutionAttempt::open(
                &case.root.path().join("target-mismatch"),
                job.input(),
                terms,
            )
            .unwrap();
            mismatch
                .bind_target(hellas_sdk::execution::ExecutionTarget {
                    network: case.options.config.chain.network,
                    provider: case.options.provider,
                })
                .unwrap();
            let mut elsewhere = case.options.clone();
            elsewhere.provider.node = iroh::SecretKey::from_bytes(&[0x77; 32]).public();
            assert!(matches!(
                mismatch
                    .open_paid_session(
                        job.input(),
                        elsewhere,
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionFundingOptions {
                            max_funding: Some(CLIENT_FUNDING),
                            approval: Some(gate.clone())
                        }
                    )
                    .await,
                Err(ExecutionError::Identity)
            ));
            assert_eq!(gate.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            drop(mismatch);
            let mut unfunded =
                ExecutionAttempt::open(&case.root.path().join("unfunded"), job.input(), terms)
                    .unwrap();
            assert!(matches!(
                unfunded
                    .open_paid_session(
                        job.input(),
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionFundingOptions {
                            max_funding: Some(0),
                            approval: None
                        },
                    )
                    .await,
                Err(ExecutionError::Paid(PaidClientError::InvalidOptions(_)))
            ));
            assert!(case.approvals.0.lock().unwrap().is_empty());
            assert!(!unfunded.inspect().unwrap().target_bound);
            assert!(
                unfunded
                    .open_paid_session(
                        job.input(),
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionFundingOptions {
                            max_funding: Some(CLIENT_FUNDING),
                            approval: Some(gate.clone())
                        }
                    )
                    .await
                    .is_err()
            );
            assert!(!unfunded.inspect().unwrap().target_bound);
            assert!(case.approvals.0.lock().unwrap().is_empty());
            assert_eq!(gate.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            gate.allow.store(true, std::sync::atomic::Ordering::SeqCst);
            drop(unfunded);
            // Correcting a non-spending preflight failure on this same marker
            // can still open a fresh funded channel, including after restart.
            let mut unfunded = ExecutionAttempt::open_existing(
                &case.root.path().join("unfunded"),
                job.input(),
                terms,
            )
            .unwrap();
            let mut funded = sealing_while(
                &mut case.devnet,
                Duration::from_millis(100),
                unfunded.open_paid_session(
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionFundingOptions {
                        max_funding: Some(CLIENT_FUNDING),
                        approval: Some(gate.clone()),
                    },
                ),
            )
            .await
            .unwrap();
            assert!(unfunded.inspect().unwrap().target_bound);
            assert_eq!(gate.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
            funded.shutdown().await;
            drop(funded);
            drop(unfunded);
            let signer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
            let mut bond = None;
            for n in 0..2 {
                let attempt_path = case.root.path().join(format!("tracked-{n}"));
                let lost_path = case.root.path().join(format!("terminal-prefix-{n}"));
                let marker_path = attempt_path.clone();
                let prefix_path = lost_path.clone();
                let mut attempt =
                    ExecutionAttempt::open(&attempt_path, job.input(), terms).unwrap();
                let mut session = attempt
                    .open_paid_session(
                        job.input(),
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionFundingOptions {
                            max_funding: Some(if n == 0 { CLIENT_FUNDING } else { 0 }),
                            approval: None,
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    *bond.get_or_insert(session.descriptor().bond_edge()),
                    session.descriptor().bond_edge()
                );
                let ExecutionResult::Paid(result) = ExecutionSession::Paid(&mut session)
                    .execute(
                        job.input().clone(),
                        terms,
                        &signer,
                        ExecutionObservers {
                            accepted: Some(Arc::new(move |_| {
                                // Save the caller's interrupted acceptance prefix;
                                // channel processing then continues to a paid terminal.
                                let mut prefix: serde_json::Value =
                                    serde_json::from_slice(&std::fs::read(&marker_path).unwrap())
                                        .unwrap();
                                prefix["work"] = serde_json::Value::Null;
                                write_marker(&prefix_path, &prefix);
                            })),
                            ..Default::default()
                        },
                        Some(&mut attempt),
                    )
                    .await
                    .unwrap()
                else {
                    panic!("paid result");
                };
                assert_eq!(result.credited_cumulative, PRICE * (n + 1));
                assert_eq!(attempt.inspect().unwrap().payment, Payment::Paid);
                assert!(
                    session
                        .with_state(|state| state.terminal_by_id(result.work_id).is_some())
                        .await
                        .unwrap()
                );
                let before = std::fs::read(&lost_path).unwrap();
                let mut lost =
                    ExecutionAttempt::open_existing(&lost_path, job.input(), terms).unwrap();
                assert!(matches!(
                    ExecutionSession::Paid(&mut session)
                        .recover(&mut lost)
                        .await,
                    Err(ExecutionError::Purchase(
                        hellas_sdk::transact::PurchaseError::Unfinished {
                            reason: "the proposal nonce was consumed but no active request-bound acceptance remains",
                            ..
                        }
                    ))
                ));
                assert_eq!(std::fs::read(&lost_path).unwrap(), before);
                assert_eq!(lost.inspect().unwrap().work, None);
                assert_eq!(
                    session
                        .with_state(|state| state.ledger().credited_cumulative())
                        .await
                        .unwrap(),
                    PRICE * (n + 1)
                );
                assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
                session.shutdown().await;
            }
            // Selection must validate the job against this channel's signed policy.
            let wrong = other_contract_job();
            let mut attempt = ExecutionAttempt::open(
                &case.root.path().join("wrong-policy"),
                wrong.input(),
                terms,
            )
            .unwrap();
            assert!(
                attempt
                    .open_paid_session(
                        wrong.input(),
                        case.options.clone(),
                        case.endpoint.clone(),
                        client_settlement(),
                        case.owner.clone(),
                        SessionFundingOptions {
                            max_funding: Some(0),
                            approval: None
                        },
                    )
                    .await
                    .is_err()
            );
            assert!(!attempt.inspect().unwrap().target_bound);
            drop(attempt);
            // Retained selection does not require a fresh quote from the provider.
            case.provider.shutdown().await.unwrap();
            let mut attempt = ExecutionAttempt::open(
                &case.root.path().join("provider-offline"),
                job.input(),
                terms,
            )
            .unwrap();
            let mut session = tokio::time::timeout(
                Duration::from_secs(30),
                attempt.open_paid_session(
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionFundingOptions {
                        max_funding: Some(0),
                        approval: None,
                    },
                ),
            )
            .await
            .expect("retained opening does not contact provider")
            .unwrap();
            assert_eq!(Some(session.descriptor().bond_edge()), bond);
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            session.shutdown().await;
            case.endpoint.close().await;
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

#[test]
fn tracked_recovery_requires_request_binding_and_preserves_ambiguous_legacy_intents() {
    run(|runtime| {
        Box::pin(async move {
            let mut case = paid_fixture(runtime).await;
            case.provider.shutdown().await.unwrap();
            let (provider, upstream) = start_provider(
                case.root.path(),
                work_config(&case.devnet, case.root.path().join("provider-journal")),
                case.provider_node.clone(),
                &case.identity,
            )
            .await;
            case.options.provider_addrs = addresses(&provider);
            case.provider = provider;
            fund(&mut case).await;
            let job = job();
            let terms = ExecutionTerms::Paid { price: PRICE };
            let path = case.root.path().join("interrupted");
            let mut attempt = ExecutionAttempt::open(&path, job.input(), terms).unwrap();
            let mut session = attempt
                .open_paid_session(
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionFundingOptions::default(),
                )
                .await
                .unwrap();
            let signer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
            let (work, nonce) =
                accept_paused(&mut session, &mut attempt, &job, &signer, &upstream).await;
            let mut prefix: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(prefix["phase"], "Running");
            prefix["work"] = serde_json::Value::Null;
            assert!(prefix["request_commitment"].is_array());
            assert!(prefix["attempt_nonce"].is_array());
            // A legacy marker with the already-recorded work ID still recovers.
            // Without that ID, even live request bytes cannot distinguish two
            // identical-input intents that reused an unproposed channel nonce.
            let mut legacy = prefix.clone();
            legacy.as_object_mut().unwrap().remove("request_commitment");
            legacy.as_object_mut().unwrap().remove("attempt_nonce");
            let legacy_live_path = case.root.path().join("legacy-live");
            write_marker(&legacy_live_path, &legacy);
            let mut legacy_attempt =
                ExecutionAttempt::open_existing(&legacy_live_path, job.input(), terms).unwrap();
            assert_legacy_unresolved(&mut session, &mut legacy_attempt).await;
            drop(legacy_attempt);
            let mut legacy_known = legacy.clone();
            legacy_known["work"] = serde_json::json!(work.as_bytes());
            let legacy_known_path = case.root.path().join("legacy-known");
            write_marker(&legacy_known_path, &legacy_known);
            let mut legacy_attempt =
                ExecutionAttempt::open_existing(&legacy_known_path, job.input(), terms).unwrap();
            let facts = ExecutionSession::Paid(&mut session)
                .recover(&mut legacy_attempt)
                .await
                .unwrap();
            assert_eq!(facts.work, Some(work));
            assert_eq!(facts.acceptance, Acceptance::Accepted);
            assert_eq!(facts.payment, Payment::Pending);
            drop(legacy_attempt);
            // While input bytes are present, a different caller job must not attach
            // to this acceptance even if its marker names this channel and nonce.
            let other = hellas_sdk::job::Job::fetch(
                PRICE,
                test_responses_contract(),
                "openai".into(),
                "responses".into(),
                br#"{"input":"different"}"#.to_vec(),
                Assurance::ProducerSigned,
            )
            .unwrap();
            let mut wrong_job = prefix.clone();
            wrong_job["job"] = serde_json::json!(other.digest().as_bytes());
            let wrong_path = case.root.path().join("wrong-job");
            write_marker(&wrong_path, &wrong_job);
            let mut wrong_attempt =
                ExecutionAttempt::open_existing(&wrong_path, other.input(), terms).unwrap();
            assert!(
                ExecutionSession::Paid(&mut session)
                    .recover(&mut wrong_attempt)
                    .await
                    .is_err()
            );
            drop(wrong_attempt);
            session.shutdown().await;
            drop(session);
            drop(attempt);
            // The durable prefix after JobAccepted but before purchase.accepting:
            // the original nonce and its request commitment, still no work ID.
            write_marker(&path, &prefix);
            let mut attempt = ExecutionAttempt::open_existing(&path, job.input(), terms).unwrap();
            let mut session = attempt
                .open_paid_session(
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionFundingOptions {
                        max_funding: Some(0),
                        approval: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                session
                    .with_state(|state| state.job_by_id(work).unwrap().prepared_input().is_empty())
                    .await
                    .unwrap(),
                "this restart exercises metadata-only replay"
            );
            let legacy_replay_path = case.root.path().join("legacy-metadata");
            write_marker(&legacy_replay_path, &legacy);
            let mut legacy_attempt =
                ExecutionAttempt::open_existing(&legacy_replay_path, job.input(), terms).unwrap();
            assert_legacy_unresolved(&mut session, &mut legacy_attempt).await;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &std::fs::read(&legacy_replay_path).unwrap()
                )
                .unwrap(),
                legacy
            );
            drop(legacy_attempt);
            for field in ["channel", "bond", "network", "provider"] {
                let mut wrong = prefix.clone();
                match field {
                    "channel" | "bond" => {
                        wrong[field] = serde_json::to_value([0x55u8; 32]).unwrap()
                    }
                    "network" => wrong["target"][field] = serde_json::json!("wrong-network"),
                    "provider" => {
                        let mut provider = case.options.provider;
                        provider.node = iroh::SecretKey::from_bytes(&[0x77; 32]).public();
                        wrong["target"][field] = serde_json::to_value(provider).unwrap();
                    }
                    _ => unreachable!(),
                }
                let wrong_path = case.root.path().join(format!("wrong-{field}"));
                write_marker(&wrong_path, &wrong);
                let mut wrong_attempt =
                    ExecutionAttempt::open_existing(&wrong_path, job.input(), terms).unwrap();
                assert!(
                    ExecutionSession::Paid(&mut session)
                        .recover(&mut wrong_attempt)
                        .await
                        .is_err(),
                    "{field}"
                );
            }
            let pending_path = case.root.path().join("no-proof");
            let mut pending = prefix.clone();
            pending["nonce"] = serde_json::json!(nonce + 1);
            write_marker(&pending_path, &pending);
            let mut pending_attempt =
                ExecutionAttempt::open_existing(&pending_path, job.input(), terms).unwrap();
            assert_pending(&mut session, &mut pending_attempt, &job, &signer).await;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&std::fs::read(&pending_path).unwrap())
                    .unwrap(),
                pending
            );
            drop(pending_attempt);
            let facts = ExecutionSession::Paid(&mut session)
                .recover(&mut attempt)
                .await
                .unwrap();
            assert_eq!(facts.work, Some(work));
            assert_eq!(facts.acceptance, Acceptance::Accepted);
            assert_eq!(facts.terminal, Terminal::Unknown);
            assert_eq!(facts.payment, Payment::Pending);
            assert!(!facts.result_available);
            assert!(matches!(
                ExecutionSession::Paid(&mut session)
                    .execute(
                        job.input().clone(),
                        terms,
                        &signer,
                        Default::default(),
                        Some(&mut attempt),
                    )
                    .await,
                Err(ExecutionError::RecoveryRequired)
            ));
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved["nonce"], nonce);
            assert_eq!(saved["work"], serde_json::json!(work.as_bytes()));
            assert_eq!(
                session
                    .with_state(|state| (
                        state.proposal_nonce_high_water(),
                        state.ledger().credited_cumulative()
                    ))
                    .await
                    .unwrap(),
                (nonce, 0)
            );
            assert_eq!(upstream.calls("openai", "responses", BODY), 1);
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            let bond = session.descriptor().bond_edge();
            session.shutdown().await;
            drop(session);
            drop(attempt);
            // The recovered ID survives another caller reopen without changing nonce.
            let attempt = ExecutionAttempt::open_existing(&path, job.input(), terms).unwrap();
            assert_eq!(attempt.inspect().unwrap().work, Some(work));
            drop(attempt);
            // A client signature alone does not establish provider acceptance.
            let (unsigned, request_commitment) =
                record_unsigned_proposal(&case, &job, &signer, bond, nonce + 1).await;
            pending["request_commitment"] = serde_json::json!(request_commitment.as_bytes());
            let unsigned_path = case.root.path().join("unsigned");
            write_marker(&unsigned_path, &pending);
            let mut attempt =
                ExecutionAttempt::open_existing(&unsigned_path, job.input(), terms).unwrap();
            let mut session = attempt
                .open_paid_session(
                    job.input(),
                    case.options.clone(),
                    case.endpoint.clone(),
                    client_settlement(),
                    case.owner.clone(),
                    SessionFundingOptions {
                        max_funding: Some(0),
                        approval: None,
                    },
                )
                .await
                .unwrap();
            assert!(
                session
                    .with_state(|state| state
                        .job_by_id(unsigned)
                        .unwrap()
                        .provider_signature()
                        .is_none())
                    .await
                    .unwrap()
            );
            assert_pending(&mut session, &mut attempt, &job, &signer).await;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(
                    &std::fs::read(&unsigned_path).unwrap()
                )
                .unwrap(),
                pending
            );
            assert_eq!(
                session
                    .with_state(|state| (
                        state.proposal_nonce_high_water(),
                        state.ledger().credited_cumulative()
                    ))
                    .await
                    .unwrap(),
                (nonce + 1, 0)
            );
            assert_eq!(upstream.calls("openai", "responses", BODY), 1);
            assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
            upstream
                .pause
                .store(false, std::sync::atomic::Ordering::SeqCst);
            upstream.release.notify_one();
            session.shutdown().await;
            case.endpoint.close().await;
            case.provider.shutdown().await.unwrap();
            case.relays.shutdown().await;
            case.devnet.shutdown().await;
        })
    });
}

fn write_marker(path: &std::path::Path, record: &serde_json::Value) {
    hellas_private::write_atomically(path, ".writing", &serde_json::to_vec(record).unwrap())
        .unwrap();
}

async fn assert_pending(
    session: &mut PaidWorkSession,
    attempt: &mut ExecutionAttempt,
    job: &hellas_sdk::job::Job,
    signer: &ProducerSigningKey,
) {
    let facts = ExecutionSession::Paid(session)
        .recover(attempt)
        .await
        .unwrap();
    assert_eq!(facts.work, None);
    assert_eq!(facts.acceptance, Acceptance::Unknown);
    assert_eq!(facts.terminal, Terminal::Unknown);
    assert_eq!(facts.payment, Payment::Pending);
    assert!(!facts.result_available);
    assert!(matches!(
        ExecutionSession::Paid(session)
            .execute(
                job.input().clone(),
                ExecutionTerms::Paid { price: PRICE },
                signer,
                Default::default(),
                Some(attempt),
            )
            .await,
        Err(ExecutionError::RecoveryRequired)
    ));
}

async fn record_unsigned_proposal(
    case: &PaidScenario<()>,
    job: &hellas_sdk::job::Job,
    signer: &ProducerSigningKey,
    bond: hellas_kernel::EdgeId,
    nonce: u64,
) -> (Digest, Digest) {
    use hellas_channel::work_store::{ChannelRecord, ChannelStore, Role, SetupStore};
    let verifier = hellas_kernel::Secp256k1Verifier::new();
    let setup = SetupStore::open_existing(
        &case.options.journal_root,
        case.options.config.chain.network,
        bond,
        Role::Client,
        &verifier,
    )
    .await
    .unwrap();
    let descriptor = setup.state().close_descriptor().unwrap().clone();
    let origin = setup.state().origin().unwrap();
    drop(setup);
    let mut channel = ChannelStore::open_existing(
        &case.options.journal_root,
        descriptor.channel().clone(),
        descriptor.expected_settlement().unwrap(),
        Role::Client,
        origin,
        hellas_store::ContentStore::new(),
        &verifier,
    )
    .await
    .unwrap();
    let input = job
        .prepare(
            signer,
            job.purchase_nonce(descriptor.channel().id(), nonce),
            hellas_auth::PublicKey::Secp256k1(descriptor.channel().provider_key().to_bytes()),
            descriptor.invocation_policy(),
        )
        .unwrap();
    let acceptance = channel.state().cursor().0 + case.options.acceptance_blocks;
    let terminal = acceptance + case.options.terminal_blocks;
    let payment = terminal + case.options.payment_blocks;
    let authorization = hellas_channel::job::propose(
        descriptor.channel(),
        descriptor.invocation_policy(),
        descriptor.payment_policy(),
        &input,
        nonce,
        hellas_channel::model::work::JobDeadlines {
            acceptance,
            terminal,
            payment,
        },
    )
    .unwrap();
    let work = hellas_channel::model::work::work_id(descriptor.channel(), &authorization);
    channel
        .commit(
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client_settlement()
                    .sign(hellas_channel::model::work::signing_hash(work)),
                prepared_input: input.canonical_bytes().unwrap(),
            },
            &verifier,
        )
        .await
        .unwrap();
    (work, authorization.request_commitment.digest())
}

async fn accept_paused(
    session: &mut PaidWorkSession,
    attempt: &mut ExecutionAttempt,
    job: &hellas_sdk::job::Job,
    signer: &ProducerSigningKey,
    upstream: &PausedFetch,
) -> (Digest, u64) {
    upstream
        .pause
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let accepted = Arc::new(tokio::sync::Notify::new());
    let signal = accepted.clone();
    {
        let mut execution = ExecutionSession::Paid(session);
        let running = execution.execute(
            job.input().clone(),
            ExecutionTerms::Paid { price: PRICE },
            signer,
            ExecutionObservers {
                accepted: Some(Arc::new(move |_| signal.notify_one())),
                ..Default::default()
            },
            Some(attempt),
        );
        tokio::pin!(running);
        tokio::select! {
            result = &mut running => panic!("request ended before interruption: {:?}", result.err()),
            () = async { accepted.notified().await; upstream.started.notified().await; } => {},
        }
    }
    session
        .with_state(|state| {
            let job = state.jobs().next().unwrap();
            assert!(job.provider_signature().is_some());
            assert!(!job.prepared_input().is_empty());
            assert_eq!(state.ledger().credited_cumulative(), 0);
            (job.work_id(), job.authorization().proposal_nonce)
        })
        .await
        .unwrap()
}

#[test]
fn tracked_recovery_rejects_different_jobs_at_a_reused_unproposed_nonce() {
    run(|runtime| reused_nonce_scenario(runtime, false));
}

#[test]
fn tracked_recovery_rejects_identical_jobs_at_a_reused_unproposed_nonce() {
    run(|runtime| reused_nonce_scenario(runtime, true));
}

fn reused_nonce_scenario(
    runtime: commonware_runtime::tokio::Context,
    same_input: bool,
) -> impl std::future::Future<Output = ()> {
    Box::pin(async move {
        let mut case = paid_fixture(runtime).await;
        case.provider.shutdown().await.unwrap();
        let (provider, upstream) = start_provider(
            case.root.path(),
            work_config(&case.devnet, case.root.path().join("provider-journal")),
            case.provider_node.clone(),
            &case.identity,
        )
        .await;
        case.options.provider_addrs = addresses(&provider);
        case.provider = provider;
        fund(&mut case).await;
        let first = if same_input {
            job()
        } else {
            hellas_sdk::job::Job::fetch(
                PRICE,
                test_responses_contract(),
                "openai".into(),
                "responses".into(),
                br#"{"model":"fixture","input":"abandoned","max_output_tokens":8}"#.to_vec(),
                Assurance::ProducerSigned,
            )
            .unwrap()
        };
        let terms = ExecutionTerms::Paid { price: PRICE };
        let first_path = case.root.path().join("before-proposal");
        let mut first_attempt = ExecutionAttempt::open(&first_path, first.input(), terms).unwrap();
        let mut session = first_attempt
            .open_paid_session(
                first.input(),
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionFundingOptions {
                    max_funding: Some(0),
                    approval: None,
                },
            )
            .await
            .unwrap();
        // Suspending readiness stops public execution after its durable nonce
        // intent but before JobProposed: the pre-proposal crash prefix.
        session.shutdown().await;
        let signer = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
        assert!(
            ExecutionSession::Paid(&mut session)
                .execute(
                    first.input().clone(),
                    terms,
                    &signer,
                    Default::default(),
                    Some(&mut first_attempt)
                )
                .await
                .is_err()
        );
        let first_record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&first_path).unwrap()).unwrap();
        assert_eq!(first_record["phase"], "Running");
        assert_eq!(first_record["nonce"], 1);
        assert_eq!(first_record["work"], serde_json::Value::Null);
        assert_eq!(
            session
                .with_state(|state| (state.proposal_nonce_high_water(), state.jobs().len()))
                .await
                .unwrap(),
            (0, 0)
        );
        drop(session);
        drop(first_attempt);
        // A deliberate later attempt uses the still-free channel nonce.
        let second = job();
        let mut second_attempt = ExecutionAttempt::open(
            &case.root.path().join("later-attempt"),
            second.input(),
            terms,
        )
        .unwrap();
        let mut session = second_attempt
            .open_paid_session(
                second.input(),
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionFundingOptions {
                    max_funding: Some(0),
                    approval: None,
                },
            )
            .await
            .unwrap();
        let (work, nonce) = accept_paused(
            &mut session,
            &mut second_attempt,
            &second,
            &signer,
            &upstream,
        )
        .await;
        assert_eq!(nonce, 1);
        let second_record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(case.root.path().join("later-attempt")).unwrap())
                .unwrap();
        assert_ne!(
            first_record["attempt_nonce"],
            second_record["attempt_nonce"]
        );
        assert_ne!(
            first_record["request_commitment"],
            second_record["request_commitment"]
        );
        session.shutdown().await;
        drop(session);
        drop(second_attempt);
        let mut first_attempt =
            ExecutionAttempt::open_existing(&first_path, first.input(), terms).unwrap();
        let mut session = first_attempt
            .open_paid_session(
                first.input(),
                case.options.clone(),
                case.endpoint.clone(),
                client_settlement(),
                case.owner.clone(),
                SessionFundingOptions {
                    max_funding: Some(0),
                    approval: None,
                },
            )
            .await
            .unwrap();
        assert!(
            session
                .with_state(|state| state.job_by_id(work).unwrap().prepared_input().is_empty())
                .await
                .unwrap()
        );
        assert!(
            ExecutionSession::Paid(&mut session)
                .recover(&mut first_attempt)
                .await
                .is_err(),
            "another attempt's signed acceptance must not attach to the abandoned nonce intent"
        );
        assert_eq!(first_attempt.inspect().unwrap().work, None);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&first_path).unwrap())
                .unwrap(),
            first_record
        );
        assert_eq!(
            session
                .with_state(|state| (
                    state.proposal_nonce_high_water(),
                    state.ledger().credited_cumulative()
                ))
                .await
                .unwrap(),
            (1, 0)
        );
        assert_eq!(upstream.calls("openai", "responses", BODY), 1);
        assert_eq!(case.approvals.0.lock().unwrap().len(), 1);
        upstream
            .pause
            .store(false, std::sync::atomic::Ordering::SeqCst);
        upstream.release.notify_one();
        session.shutdown().await;
        case.endpoint.close().await;
        case.provider.shutdown().await.unwrap();
        case.relays.shutdown().await;
        case.devnet.shutdown().await;
    })
}

async fn assert_legacy_unresolved(session: &mut PaidWorkSession, attempt: &mut ExecutionAttempt) {
    assert!(matches!(
        ExecutionSession::Paid(session).recover(attempt).await,
        Err(ExecutionError::Purchase(
            hellas_sdk::transact::PurchaseError::Unfinished {
                reason: "legacy marker has no attempt binding; a reused nonce may name another purchase",
                ..
            }
        ))
    ));
    let facts = attempt.inspect().unwrap();
    assert_eq!(facts.work, None);
    assert_eq!(facts.acceptance, Acceptance::Unknown);
    assert_eq!(facts.payment, Payment::Pending);
}

#[derive(Default)]
struct RetryFunding {
    allow: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
impl hellas_sdk::paid_client::FundingApproval for RetryFunding {
    fn reservation(&self, _: hellas_kernel::NetworkId, _: iroh::EndpointId) -> [u8; 16] {
        [0x41; 16]
    }
    fn reserve(
        &self,
        _: [u8; 16],
        _: u64,
    ) -> futures::future::BoxFuture<'_, Result<(), PaidClientError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.allow.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PaidClientError::InvalidOptions("fixture budget denied"))
            }
        })
    }
    fn recover(
        &self,
        _: [u8; 16],
        _: u64,
    ) -> futures::future::BoxFuture<'_, Result<(), PaidClientError>> {
        Box::pin(async { Ok(()) })
    }
}
