use super::*;
use crate::model::grant::{
    budget::{BudgetNode, Usage, Window},
    grant_work_id,
};
use crate::test_support::*;
use hellas_auth::Digest;
use hellas_auth::authority::{AdministrationCommand, GrantCommand};
use {
    crate::work_store::grant::GrantOutcome, crate::work_store::grant::NodeStore,
    crate::work_store::grant::state::Change, crate::work_store::grant::state::Frame,
    hellas_channel::work_store::Applied,
};

const ROOT: GrantId = GrantId([0; 16]);
const CHILD: GrantId = GrantId([236; 16]);

#[tokio::test]
async fn reserved_checkpoint_space_covers_maximum_metadata() {
    use crate::work_store::grant::{GrantTerminal, SignedResult};
    use hellas_channel::model::work::PaidJobResultV1;
    use hellas_rpc::{EventCommitment, protocol::value::canonical_dag_cbor};
    let dir = tempfile::tempdir().unwrap();
    let (store, application) = setup(dir.path()).await;
    let (a, signature, _) = proposal(&store, 1);
    let mut execution = ExecutionRecord::capture(
        store.state(),
        (&application, JOURNAL_AUTHORIZATION),
        a.grant_id,
        UnixMillis(1000),
    )
    .unwrap();
    let mut caller = serde_json::to_value(&execution.caller).unwrap();
    for field in ["generation", "before", "credential_revision", "at"] {
        caller[field] = serde_json::json!(u64::MAX);
    }
    caller["credential"] = serde_json::json!(vec![255u8; 16]);
    execution.caller = serde_json::from_value(caller).unwrap();
    execution.lineage = (0..=MAX_DELEGATION_DEPTH)
        .map(|n| (GrantId([255 - n; 16]), Revision(u64::MAX)))
        .collect();
    let terminal = GrantTerminal {
        outcome: GrantOutcome::Finished,
        authorization: a,
        client_signature: signature,
        provider_signature: signature,
        result: Some(SignedResult {
            result: PaidJobResultV1 {
                work_id: grant_work_id(network(), &a),
                terminal_transcript_commitment: EventCommitment::from_digest(Digest::hash(
                    b"terminal",
                )),
                canonical_output_digest: Digest::hash(b"output"),
            },
            signature,
        }),
    };
    // Count the entire terminal even though it replaces an existing job. Each
    // ancestor's used/window counters may grow to a nine-byte CBOR integer.
    let counters = crate::model::grant::budget::MAX_BUDGET_PATH_LEN
        * Meter::ALL.len()
        * Window::ALL.len()
        * 2
        * 8;
    let other_metadata = 64;
    let growth = canonical_dag_cbor(&execution).unwrap().len()
        + canonical_dag_cbor(&terminal).unwrap().len()
        + counters
        + other_metadata;
    assert!(
        growth <= super::super::store::TERMINAL_HEADROOM,
        "required growth: {growth}"
    );
}

#[tokio::test]
async fn execution_audit_retains_the_lineage_at_each_effect() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(dir.path()).await;
    let application = execution_caller(&mut store, &secret, ROOT).await;
    let administrator =
        crate::test_support::passkey_caller(store.state().authority(), &secret, UnixMillis(1000));
    let parent = store
        .state()
        .authority()
        .grant(JOURNAL_AUTHORIZATION)
        .unwrap()
        .spec()
        .clone();
    let mut child = parent.clone();
    child.delegation_depth = 0;
    store
        .administer_authority(
            &application,
            AdministrationCommand::Grant(GrantCommand::Delegate {
                parent: JOURNAL_AUTHORIZATION,
                id: CHILD,
                spec: child,
            }),
            UnixMillis(1000),
        )
        .await
        .unwrap();
    let (a, signature, input) = proposal(&store, 1);
    let work = grant_work_id(network(), &a);
    let expected = store
        .state()
        .authority()
        .record_caller(&application, UnixMillis(1000))
        .unwrap();
    store
        .accept(
            (&application, CHILD),
            a,
            signature,
            &input,
            &principal(2).1,
            UnixMillis(1000),
        )
        .await
        .unwrap();
    let admitted = store.state().admission(a.channel_id, work).unwrap().clone();
    assert_eq!(admitted.accepted().caller(), &expected);
    assert_eq!(
        admitted.accepted().lineage(),
        &[CHILD, JOURNAL_AUTHORIZATION]
            .map(|id| (id, store.state().authority().grant(id).unwrap().revision()))
    );
    assert_eq!(admitted.reserved(), Charge([1, 0, 8, 0, 0]));
    assert!(admitted.dispatched().is_none());
    let [(_, child_revision), (_, journal_revision)] = admitted.accepted().lineage()[..] else {
        panic!("two-grant lineage");
    };
    let revised = store
        .administer_authority(
            &administrator,
            AdministrationCommand::Grant(GrantCommand::Revise {
                authorization: ROOT,
                id: JOURNAL_AUTHORIZATION,
                expected: journal_revision,
                spec: parent,
            }),
            UnixMillis(1001),
        )
        .await
        .unwrap()
        .revision();
    assert_ne!(revised, journal_revision);
    store
        .dispatch((&application, CHILD), a.channel_id, work, UnixMillis(1001))
        .await
        .unwrap();
    let running = store.state().admission(a.channel_id, work).unwrap().clone();
    assert_eq!(running.accepted(), admitted.accepted());
    assert_eq!(
        running.dispatched().unwrap().lineage(),
        &[(CHILD, child_revision), (JOURNAL_AUTHORIZATION, revised)]
    );
    store
        .administer_authority(
            &administrator,
            AdministrationCommand::Grant(GrantCommand::Revoke {
                authorization: ROOT,
                id: JOURNAL_AUTHORIZATION,
                expected: revised,
            }),
            UnixMillis(1002),
        )
        .await
        .unwrap();
    assert_err!(
        store
            .dispatch((&application, CHILD), a.channel_id, work, UnixMillis(1002))
            .await,
        NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Revoked)
    );
    finish(
        &mut store,
        (a.channel_id, work),
        GrantOutcome::Failed,
        Usage::Unknown,
        1002,
    )
    .await
    .unwrap();
    store.rotate().await.unwrap();
    drop(store);
    let mut store = NodeStore::open(dir.path(), network(), None, UnixMillis(1003))
        .await
        .unwrap();
    assert_eq!(store.state().admission(a.channel_id, work), Some(&running));
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        1
    );
    store
        .tick(UnixMillis(a.delivery_deadline_ms.0 + 1))
        .await
        .unwrap();
    assert!(store.state().admission(a.channel_id, work).is_none());
    assert!(store.state().admissions.is_empty());
}

#[tokio::test]
async fn another_application_can_reconcile_but_cannot_replace_or_dispatch_the_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(dir.path()).await;
    let first = execution_caller(&mut store, &secret, ROOT).await;
    let administrator =
        crate::test_support::passkey_caller(store.state().authority(), &secret, UnixMillis(1000));
    let scope = store
        .state()
        .authority()
        .grant(JOURNAL_AUTHORIZATION)
        .unwrap()
        .spec()
        .clone();
    let [secret] = crate::test_support::credentials::issue(
        crate::test_support::credentials::Issuer::Store(&mut store, UnixMillis(1000)),
        &administrator,
        ROOT,
        None,
        scope,
    )
    .await;
    let second = signed_caller(
        store.state().authority(),
        &secret,
        &principal(1).1,
        UnixMillis(1000),
    );
    let (a, signature, input) = proposal(&store, 1);
    let work = grant_work_id(network(), &a);
    let provider = accept(&mut store, &first, (a, signature, &input), 1000)
        .await
        .unwrap();
    let before = store.state().clone();
    assert_eq!(
        accept(&mut store, &second, (a, signature, &input), 1000)
            .await
            .unwrap(),
        provider
    );
    assert_eq!(store.state(), &before);
    let conflicting = ExecutionRecord::capture(
        store.state(),
        (&second, JOURNAL_AUTHORIZATION),
        a.grant_id,
        UnixMillis(1000),
    )
    .unwrap();
    for change in [
        Change::Accepted {
            authorization: a,
            client_signature: signature,
            provider_signature: provider,
            charge: Charge([1, 0, 0, 0, 0]),
            execution: conflicting.clone(),
        },
        Change::Dispatched {
            channel: a.channel_id,
            work,
            execution: conflicting,
        },
    ] {
        assert_err!(
            before.clone().apply(&Frame {
                namespace: "hellas.node.journal.v2".into(),
                now: UnixMillis(1000),
                changes: vec![change]
            }),
            NodeStoreError::Malformed
        );
    }
    assert_err!(
        dispatch(&mut store, &second, (a.channel_id, work), 1000).await,
        NodeStoreError::Grant(crate::model::grant::records::GrantError::Unauthorized)
    );
    assert_eq!(store.state(), &before);
    dispatch(&mut store, &first, (a.channel_id, work), 1000)
        .await
        .unwrap();
    store
        .bump_generation(a.grant_id, UnixMillis(1000))
        .await
        .unwrap();
    let other = store
        .state()
        .channel_id(
            a.grant_id,
            hellas_channel::test_support::channel_client(principal(1).0),
        )
        .unwrap();
    assert!(store.state().admission(other, work).is_none());
    assert_err!(
        dispatch(&mut store, &first, (other, work), 1000).await,
        NodeStoreError::Grant(crate::model::grant::records::GrantError::Unauthorized)
    );
}

struct Accepted {
    _directory: tempfile::TempDir,
    node: TestNode,
    before: State,
    request: Proposal,
    provider_signature: hellas_auth::Signature,
}
impl Accepted {
    async fn new() -> Self {
        use {crate::test_support::ids, hellas_channel::test_support::actors::FRIEND};
        let directory = tempfile::tempdir().unwrap();
        let mut node = Node::bootstrap(directory.path())
            .with_grant(
                ids::FRIEND_GRANT,
                Rights::new(authority(), FRIEND)
                    .allow(
                        crate::grant_service::WORK_EXECUTE,
                        crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                    )
                    .valid_until(UnixMillis(10_000))
                    .build(),
            )
            .with_allowance(Allowance::responses(ids::ALLOWANCE, FRIEND))
            .build()
            .await;
        let before = node.snapshot();
        let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
        let provider_signature = node
            .accept(FRIEND, ids::FRIEND_GRANT, &request)
            .await
            .unwrap();
        Self {
            _directory: directory,
            node,
            before,
            request,
            provider_signature,
        }
    }
    fn record(&self) -> &AdmissionRecord {
        self.node
            .store
            .state()
            .admission(self.request.authorization.channel_id, self.request.work())
            .unwrap()
    }
    fn frame(&self, execution: ExecutionRecord) -> Frame {
        Frame {
            namespace: "hellas.node.journal.v2".into(),
            now: self.node.clock.now(),
            changes: vec![Change::Accepted {
                authorization: self.request.authorization,
                client_signature: self.request.signature,
                provider_signature: self.provider_signature,
                charge: self.record().reserved,
                execution,
            }],
        }
    }
}

#[tokio::test]
async fn replay_requires_the_exact_authorized_lineage() {
    struct Tamper {
        name: &'static str,
        change: fn(&mut ExecutionRecord),
    }
    let fixture = Accepted::new().await;
    let cases = [
        Tamper {
            name: "revision",
            change: |r| r.lineage[0].1.0 += 1,
        },
        Tamper {
            name: "missing lineage",
            change: |r| r.lineage.clear(),
        },
        Tamper {
            name: "duplicate lineage",
            change: |r| r.lineage.push(r.lineage[0]),
        },
    ];
    for case in cases {
        let mut execution = fixture.record().accepted.clone();
        (case.change)(&mut execution);
        let mut state = fixture.before.clone();
        assert_err!(
            state.apply(&fixture.frame(execution)),
            NodeStoreError::Malformed
        );
        assert_eq!(state, fixture.before, "{}", case.name);
    }
    let mut valid = fixture.before.clone();
    assert_eq!(
        valid
            .apply(&fixture.frame(fixture.record().accepted.clone()))
            .unwrap(),
        Applied::Changed
    );
    assert_eq!(valid, fixture.node.snapshot());
}

#[tokio::test]
async fn replay_cannot_substitute_a_different_authorizing_grant() {
    let fixture = Accepted::new().await;
    let mut execution = fixture.record().accepted.clone();
    execution.lineage[0].0 = crate::test_support::ids::ROOT_GRANT;
    let mut state = fixture.before.clone();
    assert_err!(
        state.apply(&fixture.frame(execution)),
        NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Denied)
    );
    assert_eq!(state, fixture.before);
}

#[tokio::test]
async fn checkpoints_require_complete_bound_admission_history() {
    struct Tamper {
        name: &'static str,
        change: fn(&mut State, Digest),
    }
    let fixture = Accepted::new().await;
    let cases = [
        Tamper {
            name: "missing",
            change: |s, work| {
                s.admissions.remove(&work);
            },
        },
        Tamper {
            name: "orphan",
            change: |s, work| {
                s.admissions
                    .insert(Digest::hash(b"orphan"), s.admissions[&work].clone());
            },
        },
        Tamper {
            name: "long lineage",
            change: |s, work| {
                s.admissions.get_mut(&work).unwrap().accepted.lineage =
                    vec![(crate::test_support::ids::FRIEND_GRANT, Revision(1)); 10];
            },
        },
        Tamper {
            name: "revision",
            change: |s, work| {
                s.admissions.get_mut(&work).unwrap().accepted.lineage[0].1 = Revision(u64::MAX);
            },
        },
        Tamper {
            name: "credential revision",
            change: |s, work| {
                let record = &mut s.admissions.get_mut(&work).unwrap().accepted;
                let mut caller = serde_json::to_value(&record.caller).unwrap();
                caller["credential_revision"] = serde_json::json!(u64::MAX);
                record.caller = serde_json::from_value(caller).unwrap();
            },
        },
        Tamper {
            name: "bound",
            change: |s, work| {
                s.admissions
                    .get_mut(&work)
                    .unwrap()
                    .reserved
                    .set(Meter::OutputTokens, 1);
            },
        },
        Tamper {
            name: "fabricated dispatch",
            change: |s, work| {
                let record = s.admissions.get_mut(&work).unwrap();
                record.dispatched = Some(record.accepted.clone());
            },
        },
        Tamper {
            name: "actor",
            change: |s, work| {
                let record = &mut s.admissions.get_mut(&work).unwrap().accepted;
                let mut caller = serde_json::to_value(&record.caller).unwrap();
                caller["actor"] = serde_json::to_value(
                    hellas_channel::test_support::actors::STRANGER.principal(),
                )
                .unwrap();
                record.caller = serde_json::from_value(caller).unwrap();
            },
        },
    ];
    for case in cases {
        let mut state = fixture.node.snapshot();
        (case.change)(&mut state, fixture.request.work());
        let error = State::restore(state.snapshot().unwrap()).unwrap_err();
        assert_eq!(
            error.kind(),
            super::super::NodeStoreErrorKind::Malformed,
            "{}: {error:?}",
            case.name
        );
    }
}

#[tokio::test]
async fn a_checkpoint_cannot_omit_dispatch_evidence_for_running_work() {
    let mut fixture = Accepted::new().await;
    fixture
        .node
        .dispatch(
            hellas_channel::test_support::actors::FRIEND,
            crate::test_support::ids::FRIEND_GRANT,
            &fixture.request,
        )
        .await
        .unwrap();
    let mut state = fixture.node.snapshot();
    state
        .admissions
        .get_mut(&fixture.request.work())
        .unwrap()
        .dispatched = None;
    assert_err!(
        State::restore(state.snapshot().unwrap()),
        NodeStoreError::Malformed
    );
}
