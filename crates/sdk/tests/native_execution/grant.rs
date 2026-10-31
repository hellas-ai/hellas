//! Grant session execution through public SDK APIs, without an HTTP listener.
use hellas_auth::authority::{GrantId, UnixMillis};
use hellas_authority::grant_service::GrantService;
use hellas_authority::model::grant::budget::{Limit, Meter, Window};
use hellas_authority::model::grant::records::{Offer, SignedOffer};
use hellas_authority::test_support::{TestClock, common_node, definition};
use hellas_channel::test_support::backend::{Backend, Completion, Reply};
use hellas_channel::test_support::{
    network, principal, software_enrollment, test_responses_contract,
};
use hellas_client::ProviderTrustAnchor;
use hellas_rpc::Assurance;
use hellas_sdk::grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer};
use hellas_sdk::node_control::profile::ClientProfile;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Semaphore;

#[tokio::test]
async fn granted_compute_executes_through_the_native_facade() {
    let root = tempfile::tempdir().unwrap();
    let now = UnixMillis(1000);
    let provider = software_enrollment(
        2,
        *iroh::SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
    );
    let mut grant = definition(GrantId([1; 16]), principal(1).0);
    grant.policies = vec![hellas_authority::test_support::compute::Compute.policy()];
    let (store, secret) = common_node::bootstrap_node_with_credential(
        &root.path().join("provider"),
        network(),
        Some(provider.clone()),
        now,
    )
    .await
    .unwrap();
    let store = common_node::provision(
        &root.path().join("provider"),
        store,
        &secret,
        principal(2).1,
        (
            4,
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 4,
            }],
        ),
        grant.clone(),
        (
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 3,
            }],
            2,
        ),
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        Backend {
            calls: calls.clone(),
            finish: Completion::Immediate,
            ..Backend::default()
        },
        vec![],
        TestClock::default().source(),
    )
    .unwrap();
    let credential =
        common_node::execution_credential(&service.node(), &secret, principal(1).0, grant.id).await;
    let caller = hellas_authority::test_support::session(&service.node(), &secret).await;
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.clone(),
            grant: grant.clone(),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap();
    let target = UnpinnedOffer::decode(&offer.encode().unwrap(), now)
        .unwrap()
        .pin(&ProviderTrustAnchor {
            expected_genesis: provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
    let options = GrantSessionOptions {
        target,
        principal: principal(1).0,
        signer: Arc::new(principal(1).1),
        application: Arc::new(ClientProfile {
            authority: caller.authority(),
            authorization: common_node::EXECUTION_AUTHORIZATION,
            credential,
            local: None,
        }),
        journal_root: root.path().join("client"),
        control_timeout: Duration::from_secs(5),
    };
    let environment = hellas_channel::test_support::channel::environment();
    let mut content = hellas_channel::content::EphemeralContent::default();
    content.insert(environment.canonical_bytes().unwrap());
    let input = hellas_sdk::job::JobInput::Compute {
        environment,
        plan: hellas_channel::test_support::channel::plan(),
        inputs: vec![],
        content: hellas_channel::content::InvocationContent::Ephemeral(content),
    };
    let terms = hellas_sdk::execution::ExecutionTerms::Grant {
        resource: grant.policies[0].resource,
    };
    let mut attempt = hellas_sdk::execution::ExecutionAttempt::open(
        &root.path().join("compute-attempt"),
        &input,
        terms,
    )
    .unwrap();
    let mut session = attempt
        .open_grant_session(options, GrantTransport::Local(service))
        .await
        .unwrap();
    let result = hellas_sdk::execution::ExecutionSession::Grant(&mut session)
        .execute(
            input,
            terms,
            &principal(1).1,
            Default::default(),
            Some(&mut attempt),
        )
        .await
        .unwrap();
    let hellas_sdk::execution::ExecutionResult::Grant(result) = result else {
        panic!("grant result")
    };
    assert_eq!(result.output.artifacts[0].bytes.as_bytes(), &[0]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        attempt.inspect().unwrap().terminal,
        hellas_sdk::execution::Terminal::Verified
    );
    session.shutdown().await.unwrap();
}

#[tokio::test]
async fn local_grant_session_executes_without_http() {
    let root = tempfile::tempdir().unwrap();
    let now = UnixMillis(1000);
    let identity = |seed| {
        software_enrollment(
            seed,
            *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes(),
        )
    };
    let provider = identity(2);
    let grant = definition(GrantId([1; 16]), principal(1).0);
    let (store, secret) = common_node::bootstrap_node_with_credential(
        &root.path().join("provider"),
        network(),
        Some(provider.clone()),
        now,
    )
    .await
    .unwrap();
    let store = common_node::provision(
        &root.path().join("provider"),
        store,
        &secret,
        principal(2).1,
        (
            4,
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 4,
            }],
        ),
        grant.clone(),
        (
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 3,
            }],
            2,
        ),
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let finish = Completion::Permits(Arc::new(Semaphore::new(0)));
    let backend = Backend {
        slots: Arc::new(Semaphore::new(2)),
        calls: calls.clone(),
        finish: finish.clone(),
        reply: Reply::text("fixture output", 1),
        ..Backend::default()
    };
    let clock = TestClock::default();
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        backend,
        vec![],
        clock.source(),
    )
    .unwrap();
    let credential =
        common_node::execution_credential(&service.node(), &secret, principal(1).0, grant.id).await;
    let caller = hellas_authority::test_support::session(&service.node(), &secret).await;
    let profile = Arc::new(ClientProfile {
        authority: caller.authority(),
        authorization: common_node::EXECUTION_AUTHORIZATION,
        credential,
        local: None,
    });
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: provider.clone(),
            grant: grant.clone(),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000_000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap();
    let target = UnpinnedOffer::decode(&offer.encode().unwrap(), now)
        .unwrap()
        .pin(&ProviderTrustAnchor {
            expected_genesis: provider.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        })
        .unwrap();
    let contract = test_responses_contract();
    let input = hellas_sdk::job::JobInput::Fetch {
        contract,
        service: "openai".into(),
        method: "responses".into(),
        request: br#"{"model":"fixture","input":"fixture","max_output_tokens":8}"#.to_vec(),
        assurance: Assurance::ProducerSigned,
    };
    let terms = hellas_sdk::execution::ExecutionTerms::Grant {
        resource: grant.policies[0].resource,
    };
    let path = root.path().join("attempt.json");
    let mut attempt = hellas_sdk::execution::ExecutionAttempt::open(&path, &input, terms).unwrap();
    attempt.retain_results(true);
    let options = GrantSessionOptions {
        target,
        principal: principal(1).0,
        signer: Arc::new(principal(1).1),
        application: profile,
        journal_root: root.path().join("client"),
        control_timeout: Duration::from_secs(5),
    };
    let mut session = attempt
        .open_grant_session(options.clone(), GrantTransport::Local(service.clone()))
        .await
        .unwrap();
    finish.release();
    let result = hellas_sdk::execution::ExecutionSession::Grant(&mut session)
        .execute(
            input.clone(),
            terms,
            &principal(1).1,
            Default::default(),
            Some(&mut attempt),
        )
        .await
        .unwrap();
    let hellas_sdk::execution::ExecutionResult::Grant(result) = result else {
        panic!("grant result")
    };
    hellas_auth::signature::verify_digest_signature(
        &result.provider_key,
        &result.acceptance_signature,
        result.work_id,
    )
    .unwrap();
    hellas_auth::signature::verify_digest_signature(
        &result.provider_key,
        &result.result_signature,
        hellas_channel::model::work::bound_result_digest(
            network(),
            session.store().channel().id.0,
            &result.result,
        ),
    )
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.events.len(), 2);
    assert!(attempt.inspect().unwrap().result_available);
    // Restart after receipt commit but before the caller acknowledges delivery.
    drop(attempt);
    let mut attempt =
        hellas_sdk::execution::ExecutionAttempt::open_existing(&path, &input, terms).unwrap();
    assert!(attempt.retained_result().unwrap().is_some());
    assert!(!attempt.inspect().unwrap().reported);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    attempt.reported().unwrap();
    assert!(attempt.inspect().unwrap().reported);
    assert!(
        hellas_sdk::execution::ExecutionSession::Grant(&mut session)
            .execute(
                input.clone(),
                terms,
                &principal(1).1,
                Default::default(),
                Some(&mut attempt)
            )
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(attempt);
    let reopened = hellas_sdk::execution::ExecutionAttempt::open(&path, &input, terms).unwrap();
    assert!(reopened.inspect().unwrap().reported);
    assert!(reopened.retained_result().unwrap().is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Simulate losing the process after attempt intent was persisted, but
    // before the corresponding proposal was appended to the grant journal.
    use hellas_channel::model::work::PrivateRecord as _;
    let mut orphan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let encoded: Vec<u8> = serde_json::from_value(orphan["authorization"].clone()).unwrap();
    let mut authorization =
        hellas_channel::model::grant::GrantJobAuthorizationV1::decode(&encoded).unwrap();
    authorization.proposal_nonce = 1000;
    let orphan_work = hellas_channel::model::grant::grant_work_id(network(), &authorization);
    orphan["authorization"] = serde_json::json!(authorization.encode());
    orphan["work"] = serde_json::json!(orphan_work.as_bytes());
    let orphan_path = root.path().join("orphan.json");
    hellas_private::write_atomically(
        &orphan_path,
        ".writing",
        &serde_json::to_vec(&orphan).unwrap(),
    )
    .unwrap();
    let mut orphan_attempt =
        hellas_sdk::execution::ExecutionAttempt::open_existing(&orphan_path, &input, terms)
            .unwrap();
    assert!(matches!(
        hellas_sdk::execution::ExecutionSession::Grant(&mut session)
            .execute(
                input.clone(),
                terms,
                &principal(1).1,
                Default::default(),
                Some(&mut orphan_attempt)
            )
            .await,
        Err(hellas_sdk::execution::ExecutionError::RecoveryRequired)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // A durable refusal tombstone also remains terminal after reopening.
    orphan["rejected"] = serde_json::json!(true);
    let rejected_path = root.path().join("rejected.json");
    hellas_private::write_atomically(
        &rejected_path,
        ".writing",
        &serde_json::to_vec(&orphan).unwrap(),
    )
    .unwrap();
    let mut rejected_attempt =
        hellas_sdk::execution::ExecutionAttempt::open_existing(&rejected_path, &input, terms)
            .unwrap();
    assert_eq!(
        rejected_attempt.inspect().unwrap().acceptance,
        hellas_sdk::execution::Acceptance::Rejected
    );
    assert_eq!(
        rejected_attempt.inspect().unwrap().terminal,
        hellas_sdk::execution::Terminal::Rejected
    );
    assert!(matches!(
        hellas_sdk::execution::ExecutionSession::Grant(&mut session)
            .execute(
                input.clone(),
                terms,
                &principal(1).1,
                Default::default(),
                Some(&mut rejected_attempt)
            )
            .await,
        Err(hellas_sdk::execution::ExecutionError::RecoveryRequired)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let artifact = root.path().join(".hellas-execution").join(format!(
        "{}.result",
        hex::encode(hellas_auth::Digest::hash(b"attempt.json").as_bytes())
    ));
    let mut bytes = std::fs::read(&artifact).unwrap();
    bytes.truncate(bytes.len() / 2);
    std::fs::write(&artifact, bytes).unwrap();
    assert!(reopened.retained_result().is_err());
    std::fs::remove_file(&artifact).unwrap();
    let facts = reopened.inspect().unwrap();
    assert!(facts.reported);
    assert!(!facts.result_available);
    assert_eq!(facts.terminal, hellas_sdk::execution::Terminal::Verified);
    let mut second = hellas_sdk::execution::ExecutionAttempt::open(
        &root.path().join("second.json"),
        &input,
        terms,
    )
    .unwrap();
    second
        .bind_target(hellas_sdk::execution::ExecutionTarget {
            network: network(),
            provider: hellas_client::ProviderAddress::of(&provider).unwrap(),
        })
        .unwrap();
    finish.release();
    hellas_sdk::execution::ExecutionSession::Grant(&mut session)
        .execute(
            input.clone(),
            terms,
            &principal(1).1,
            Default::default(),
            Some(&mut second),
        )
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let mut third = hellas_sdk::execution::ExecutionAttempt::open(
        &root.path().join("third.json"),
        &input,
        terms,
    )
    .unwrap();
    third
        .bind_target(hellas_sdk::execution::ExecutionTarget {
            network: network(),
            provider: hellas_client::ProviderAddress::of(&provider).unwrap(),
        })
        .unwrap();
    let accepted = Arc::new(tokio::sync::Notify::new());
    {
        let mut execution = hellas_sdk::execution::ExecutionSession::Grant(&mut session);
        let notified = accepted.clone();
        let signer = principal(1).1;
        let operation = execution.execute(
            input.clone(),
            terms,
            &signer,
            hellas_sdk::execution::ExecutionObservers {
                accepted: Some(Arc::new(move |_| notified.notify_one())),
                ..Default::default()
            },
            Some(&mut third),
        );
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => panic!("held grant ended before cancellation: {:?}", result.err()),
            () = accepted.notified() => (),
        }
    }
    let facts = hellas_sdk::execution::ExecutionSession::Grant(&mut session)
        .recover(&mut third)
        .await
        .unwrap();
    assert_eq!(
        facts.acceptance,
        hellas_sdk::execution::Acceptance::Accepted
    );
    assert_eq!(facts.terminal, hellas_sdk::execution::Terminal::Unknown);
    assert!(!facts.result_available);
    assert!(
        hellas_sdk::execution::ExecutionSession::Grant(&mut session)
            .execute(
                input.clone(),
                terms,
                &principal(1).1,
                Default::default(),
                Some(&mut third)
            )
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while calls.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    finish.release();
    session.shutdown().await.unwrap();
    drop(session);
    let unresolved = orphan_attempt.inspect_grant(&options).await.unwrap();
    assert_eq!(
        unresolved.acceptance,
        hellas_sdk::execution::Acceptance::Unknown
    );
    assert_eq!(
        unresolved.terminal,
        hellas_sdk::execution::Terminal::Unknown
    );
    // Simulate a crash after the signed terminal was journaled but before
    // application completion metadata was committed.
    std::fs::remove_file(root.path().join(".hellas-execution").join(format!(
        "{}.receipt",
        hex::encode(hellas_auth::Digest::hash(b"second.json").as_bytes())
    )))
    .unwrap();
    let attempt_path = root.path().join("second.json");
    let before_inspection = std::fs::read(&attempt_path).unwrap();
    let facts = second.inspect_grant(&options).await.unwrap();
    assert_eq!(std::fs::read(&attempt_path).unwrap(), before_inspection);
    assert_eq!(
        facts.acceptance,
        hellas_sdk::execution::Acceptance::Accepted
    );
    assert_eq!(facts.terminal, hellas_sdk::execution::Terminal::Verified);
    assert!(!facts.result_available);
    let pending = third.inspect_grant(&options).await.unwrap();
    assert_eq!(
        pending.acceptance,
        hellas_sdk::execution::Acceptance::Accepted
    );
    assert_eq!(pending.terminal, hellas_sdk::execution::Terminal::Unknown);
    assert!(!pending.result_available);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let mut recovered_session = third
        .open_grant_session(options.clone(), GrantTransport::Local(service))
        .await
        .unwrap();
    let recovered = hellas_sdk::execution::ExecutionSession::Grant(&mut recovered_session)
        .recover(&mut third)
        .await
        .unwrap();
    assert_eq!(
        recovered.acceptance,
        hellas_sdk::execution::Acceptance::Accepted
    );
    assert!(!recovered.result_available);
    assert!(
        hellas_sdk::execution::ExecutionSession::Grant(&mut recovered_session)
            .execute(
                input,
                terms,
                &principal(1).1,
                Default::default(),
                Some(&mut third)
            )
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    recovered_session.shutdown().await.unwrap();
}

#[test]
fn attempt_identity_and_exclusive_lock_are_enforced() {
    use hellas_sdk::execution::{ExecutionAttempt, ExecutionTerms};
    let root = tempfile::tempdir().unwrap();
    let child_path = std::env::var_os("HELLAS_ATTEMPT_LOCK_TEST_PATH");
    let path = child_path
        .as_ref()
        .map_or_else(|| root.path().join("attempt"), std::path::PathBuf::from);
    let input = hellas_sdk::job::JobInput::Fetch {
        contract: test_responses_contract(),
        service: "fixture".into(),
        method: "responses".into(),
        request: br#"{"model":"fixture","input":"one"}"#.to_vec(),
        assurance: Assurance::ProducerSigned,
    };
    let resource = hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"resource"));
    let terms = ExecutionTerms::Grant { resource };
    if child_path.is_some() {
        assert!(ExecutionAttempt::open(&path, &input, terms).is_err());
        return;
    }
    assert!(ExecutionAttempt::open_existing(&root.path().join("missing"), &input, terms).is_err());
    assert!(!root.path().join("missing").exists());
    assert!(
        ExecutionAttempt::open_existing(
            &root.path().join("missing-paid"),
            &input,
            ExecutionTerms::Paid { price: 1 }
        )
        .is_err()
    );
    assert!(!root.path().join("missing-paid").exists());
    assert!(
        ExecutionAttempt::open(
            &root.path().join(".hellas-execution").join("other"),
            &input,
            terms
        )
        .is_err()
    );
    let mut attempt = ExecutionAttempt::open(&path, &input, terms).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "grant::attempt_identity_and_exclusive_lock_are_enforced",
        ])
        .env("HELLAS_ATTEMPT_LOCK_TEST_PATH", &path)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    attempt
        .bind_target(hellas_sdk::execution::ExecutionTarget {
            network: network(),
            provider: hellas_client::ProviderAddress::of(&software_enrollment(
                2,
                *iroh::SecretKey::from_bytes(&[2; 32]).public().as_bytes(),
            ))
            .unwrap(),
        })
        .unwrap();
    assert!(ExecutionAttempt::open(&path, &input, terms).is_err());
    drop(attempt);
    let mut changed = input.clone();
    if let hellas_sdk::job::JobInput::Fetch { request, .. } = &mut changed {
        *request = br#"{"model":"fixture","input":"two"}"#.to_vec();
    }
    assert!(ExecutionAttempt::open(&path, &changed, terms).is_err());
    assert!(
        ExecutionAttempt::open(
            &path,
            &input,
            ExecutionTerms::Grant {
                resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"other"))
            }
        )
        .is_err()
    );
    assert!(ExecutionAttempt::open(&path, &input, ExecutionTerms::Paid { price: 1 }).is_err());
    let paid_path = root.path().join("paid-attempt");
    drop(ExecutionAttempt::open(&paid_path, &input, ExecutionTerms::Paid { price: 1 }).unwrap());
    assert!(ExecutionAttempt::open(&paid_path, &input, ExecutionTerms::Paid { price: 2 }).is_err());
}
