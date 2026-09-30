//! Grant accounting has no chain fixture. The same signed Fetch input used by
//! Work is admitted here without constructing financial channel terms.
use hellas_rpc::{
    protocol::{
        work_grant::{budget::*, records::*, *},
        work_profile::*,
    },
    *,
};
use hellas_work::work_store::{
    grant::{
        GrantOutcome, GrantStore,
        ledger::{Ledger, LedgerError},
    },
    journal::{Journal, JournalKind},
};
use proptest::prelude::*;

mod common_grant;
use common_grant::*;

fn standing_query(store: &GrantStore) -> hellas_rpc::protocol::work_grant::standing::StandingQuery {
    use hellas_rpc::protocol::work_grant::standing::*;
    let locator = StandingLocator {
        provider: store.state().provider().content_id(),
        grant: GrantId([1; 16]),
        client: principal(1).0.id(),
        generation: 0,
    };
    StandingQuery {
        locator,
        signature: principal(1)
            .1
            .sign_digest(locator.digest(network(), &[7; 32]))
            .unwrap(),
    }
}
fn standing(store: &mut GrantStore) -> hellas_rpc::protocol::work_grant::standing::Standing {
    let query = standing_query(store);
    store
        .standing(
            query,
            hellas_work::work_store::grant::GrantConnection {
                peer: [1; 32],
                exporter: [7; 32],
            },
            &principal(2).1,
            vec![],
            UnixMillis(1_000),
        )
        .unwrap()
}
#[test]
fn standing_is_connection_bound_and_discovers_a_stale_generation_without_resetting_usage() {
    use hellas_rpc::protocol::work_grant::standing::*;
    use hellas_work::work_store::grant::{GrantConnection, GrantStoreError};
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let (a, sig, input) = proposal(&store, 1);
    store
        .accept(a, sig, &input, &principal(2).1, UnixMillis(1_000))
        .unwrap();
    let original = standing(&mut store);
    assert_eq!(original.nodes.len(), 1);
    assert_eq!(original.nodes[0].active, 1);
    assert_eq!(original.nodes[0].counters[0].reserved, 1);
    assert_eq!(original.nodes[0].counters[3].remaining, Some(2));
    assert_eq!(
        Standing::decode(
            &original.encode().unwrap(),
            principal(1).0.id(),
            UnixMillis(1_000)
        )
        .unwrap(),
        original
    );
    let query = standing_query(&store);
    store
        .bump_generation(a.grant_id, UnixMillis(1_000))
        .unwrap();
    let updated = standing(&mut store);
    assert_eq!(updated.offer.offer().generation, 1);
    assert_ne!(
        updated.offer.offer().channel(),
        original.offer.offer().channel()
    );
    assert_eq!(updated.nodes, original.nodes);
    for connection in [
        GrantConnection {
            peer: [3; 32],
            exporter: [7; 32],
        },
        GrantConnection {
            peer: [1; 32],
            exporter: [8; 32],
        },
    ] {
        assert!(matches!(
            store.standing(
                query,
                connection,
                &principal(2).1,
                vec![],
                UnixMillis(1_000)
            ),
            Err(GrantStoreError::Grant(GrantError::Unauthorized))
        ));
    }
    let mut def = store.state().grant(a.grant_id).unwrap().clone();
    def.revision.0 += 1;
    def.state = GrantState::Paused;
    store.define(def, UnixMillis(1_000)).unwrap();
    assert_eq!(
        standing(&mut store).offer.offer().grant.state,
        GrantState::Paused
    );
    assert_eq!(standing(&mut store).nodes[0].active, 0);
    assert_ne!(
        query.locator.digest(network(), &[7; 32]),
        hellas_rpc::protocol::work::bound_delivery_request_digest(
            network(),
            query.locator.channel(network()).0,
            grant_work_id(network(), &a),
            &[7; 32]
        )
    );
    assert_eq!(
        StandingLocator::decode(&query.locator.encode()).unwrap(),
        query.locator
    );
    assert!(StandingLocator::decode(&query.locator.encode()[..87]).is_err());
}
#[test]
fn client_pending_proposal_survives_restart_and_never_journals_bodies() {
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let dir = tempfile::tempdir().unwrap();
    let mut provider = setup(&dir.path().join("provider"));
    let offer = standing(&mut provider).offer;
    let (a, sig, input) = proposal(&provider, 1);
    let channel = GrantChannelState {
        id: a.channel_id,
        grant: a.grant_id,
        generation: 0,
        client: principal(1).0,
    };
    let client_dir = dir.path().join("client");
    let mut client = GrantClientStore::open(
        &client_dir,
        network(),
        principal(2).0.bundle().clone(),
        channel.clone(),
        UnixMillis(1_000),
    )
    .unwrap();
    assert_eq!(
        client
            .propose(&offer, a, &input, &principal(1).1, UnixMillis(1_000))
            .unwrap(),
        sig
    );
    let work = grant_work_id(network(), &a);
    let accepted = provider
        .accept(a, sig, &input, &principal(2).1, UnixMillis(1_000))
        .unwrap();
    assert!(client.next_nonce().is_err());
    client.rotate().unwrap();
    drop(client);
    let mut client = GrantClientStore::open(
        &client_dir,
        network(),
        principal(2).0.bundle().clone(),
        channel,
        UnixMillis(3_000),
    )
    .unwrap();
    assert_eq!(client.book().pending_proposal(), Some(work));
    assert!(client.next_nonce().is_err());
    client.accepted(work, accepted, UnixMillis(3_000)).unwrap();
    client.accepted(work, accepted, UnixMillis(3_000)).unwrap();
    assert_eq!(client.next_nonce().unwrap(), 2);
    assert!(
        client
            .book()
            .job_by_id(work)
            .unwrap()
            .prepared_input()
            .is_empty()
    );
    client.rotate().unwrap();
    for entry in std::fs::read_dir(&client_dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"never-journal-this-body".len())
                .any(|w| w == b"never-journal-this-body")
        );
    }
    client.tick(UnixMillis(6_000)).unwrap();
    assert_eq!(client.book().jobs().len(), 0);
    assert_eq!(client.next_nonce().unwrap(), 2);
}
#[test]
fn client_refusal_keeps_nonce_history_and_recovery_pending_even_beyond_delivery() {
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let dir = tempfile::tempdir().unwrap();
    let mut provider = setup(&dir.path().join("provider"));
    let offer = standing(&mut provider).offer;
    let (a, _, input) = proposal(&provider, 1);
    let channel = GrantChannelState {
        id: a.channel_id,
        grant: a.grant_id,
        generation: 0,
        client: principal(1).0,
    };
    let path = dir.path().join("client");
    let mut client = GrantClientStore::open(
        &path,
        network(),
        principal(2).0.bundle().clone(),
        channel.clone(),
        UnixMillis(1_000),
    )
    .unwrap();
    client
        .propose(&offer, a, &input, &principal(1).1, UnixMillis(1_000))
        .unwrap();
    let id = grant_work_id(network(), &a);
    client.refused(id, UnixMillis(1_000)).unwrap();
    assert_eq!(client.next_nonce().unwrap(), 2);
    client.resume(id, UnixMillis(1_000)).unwrap();
    client.tick(UnixMillis(6_000)).unwrap();
    client.rotate().unwrap();
    drop(client);
    let mut client = GrantClientStore::open(
        &path,
        network(),
        principal(2).0.bundle().clone(),
        channel,
        UnixMillis(1),
    )
    .unwrap();
    assert_eq!(client.now(), UnixMillis(6_000));
    assert_eq!(client.book().pending_proposal(), Some(id));
    assert!(client.next_nonce().is_err());
    client.refused(id, UnixMillis(6_000)).unwrap();
    assert_eq!(client.book().jobs().len(), 0);
    assert_eq!(client.next_nonce().unwrap(), 2);
}
#[test]
fn lost_body_probe_returns_the_old_cosignature_or_a_conclusive_expiry() {
    use hellas_work::work_store::grant::GrantStoreError;
    for accepted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = setup(dir.path());
        let (a, signature, input) = proposal(&store, 1);
        let old = accepted.then(|| {
            store
                .accept(a, signature, &input, &principal(2).1, UnixMillis(1_000))
                .unwrap()
        });
        let reply = store.precheck_acceptance(&a, &signature, UnixMillis(2_001));
        if accepted {
            assert_eq!(reply.unwrap(), old);
        } else {
            assert!(matches!(
                reply,
                Err(GrantStoreError::Grant(GrantError::Expired))
            ));
            assert!(matches!(
                store.precheck_acceptance(&a, &signature, UnixMillis(1)),
                Err(GrantStoreError::Grant(GrantError::Expired))
            ));
        }
    }
}
#[test]
fn acceptance_is_one_atomic_frame_and_recovery_never_reexecutes() {
    for dispatched in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = setup(dir.path());
        let (a, s, input) = proposal(&store, 1);
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let path = files
            .iter()
            .find(|p| p.extension().is_some_and(|e| e == "journal"))
            .unwrap_or(&files[0]);
        let (_, before) = Journal::inspect(path).unwrap();
        let sig = store
            .accept(a, s, &input, &principal(2).1, UnixMillis(1_000))
            .unwrap();
        let (header, after) = Journal::inspect(path).unwrap();
        assert_eq!(header.kind, JournalKind::Grant);
        assert_eq!(after.records.len(), before.records.len() + 1);
        assert_eq!(
            store
                .accept(a, s, &input, &principal(2).1, UnixMillis(1_001))
                .unwrap(),
            sig
        );
        let work = grant_work_id(network(), &a);
        if dispatched {
            store
                .dispatch(a.channel_id, work, UnixMillis(1_002))
                .unwrap();
        }
        store.rotate().unwrap();
        drop(store);
        let mut reopened = GrantStore::open(
            dir.path(),
            network(),
            principal(2).0.bundle().clone(),
            UnixMillis(1_003),
        )
        .unwrap();
        let terminal = &reopened
            .state()
            .channel(a.channel_id)
            .unwrap()
            .job_book()
            .terminal_by_id(work)
            .unwrap()
            .outcome;
        assert_eq!(
            terminal.outcome,
            if dispatched {
                GrantOutcome::Indeterminate
            } else {
                GrantOutcome::Released
            }
        );
        assert_eq!(
            reopened
                .state()
                .ledger()
                .node(BudgetNode::Machine)
                .unwrap()
                .counter(Meter::Requests, Window::Total)
                .used,
            u64::from(dispatched)
        );
        assert_eq!(
            reopened.state().recovery_holds(None, UnixMillis(1_003)),
            usize::from(dispatched)
        );
        assert_eq!(reopened.state().recovery_holds(None, UnixMillis(4_000)), 0);
        assert_eq!(
            reopened
                .accept(a, s, &input, &principal(2).1, UnixMillis(1_004))
                .unwrap(),
            sig
        );
        drop(reopened);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(
                !bytes
                    .windows(b"never-journal-this-body".len())
                    .any(|b| b == b"never-journal-this-body")
            );
        }
    }
}
#[test]
fn revision_pause_revoke_preserve_allowance_and_nonce_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let (a, s, input) = proposal(&store, 1);
    store
        .accept(a, s, &input, &principal(2).1, UnixMillis(1_000))
        .unwrap();
    let mut def = store.state().grant(a.grant_id).unwrap().clone();
    def.revision = Revision(2);
    def.state = GrantState::Paused;
    store.define(def.clone(), UnixMillis(1_100)).unwrap();
    assert_eq!(
        store
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        0
    );
    assert_eq!(
        store
            .state()
            .channel(a.channel_id)
            .unwrap()
            .job_book()
            .proposal_nonce_high_water(),
        1
    );
    let (paused, s2, input2) = proposal(&store, 2);
    assert!(matches!(
        store.accept(paused, s2, &input2, &principal(2).1, UnixMillis(1_100)),
        Err(hellas_work::work_store::grant::GrantStoreError::Grant(
            GrantError::Paused
        ))
    ));
    def.revision = Revision(3);
    def.state = GrantState::Active;
    store.define(def.clone(), UnixMillis(1_101)).unwrap();
    let (a2, s2, input2) = proposal(&store, 2);
    store
        .accept(a2, s2, &input2, &principal(2).1, UnixMillis(1_101))
        .unwrap();
    let work = grant_work_id(network(), &a2);
    store
        .dispatch(a2.channel_id, work, UnixMillis(1_102))
        .unwrap();
    store
        .finish(
            a2.channel_id,
            work,
            GrantOutcome::Failed,
            None,
            Usage::Unknown,
            UnixMillis(1_103),
        )
        .unwrap();
    def.revision = Revision(4);
    def.limits[0].amount = 1;
    store.define(def.clone(), UnixMillis(1_104)).unwrap();
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Grant(a.grant_id))
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        1
    );
    let (a3, s3, input3) = proposal(&store, 3);
    assert!(matches!(
        store.accept(a3, s3, &input3, &principal(2).1, UnixMillis(1_105)),
        Err(hellas_work::work_store::grant::GrantStoreError::Ledger(
            LedgerError::OverBudget { .. }
        ))
    ));
    def.revision = Revision(5);
    def.state = GrantState::Revoked;
    store.define(def.clone(), UnixMillis(1_106)).unwrap();
    def.revision = Revision(6);
    def.state = GrantState::Active;
    assert!(store.define(def, UnixMillis(1_107)).is_err());
}
#[test]
fn active_reserves_cross_windows_and_clock_rollback_cannot_reset_them() {
    let mut l = Ledger::default();
    let grant = BudgetNode::Grant(GrantId([1; 16]));
    for n in [BudgetNode::Machine, grant] {
        l.configure(
            n,
            vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Day,
                amount: 10,
            }],
            4,
        )
        .unwrap();
    }
    let r = l
        .reserve(
            Digest::hash(b"one"),
            vec![BudgetNode::Machine, grant],
            Charge([1, 0, 8, 0]),
            UnixMillis(86_399_999),
        )
        .unwrap();
    l.advance(UnixMillis(86_400_000));
    assert!(
        l.reserve(
            Digest::hash(b"two"),
            vec![BudgetNode::Machine, grant],
            Charge([1, 0, 3, 0]),
            UnixMillis(0)
        )
        .is_err()
    );
    l.settle(r, Usage::Unknown, UnixMillis(0)).unwrap();
    assert_eq!(
        l.node(grant)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Day),
        hellas_work::work_store::grant::ledger::Counter {
            window_id: 1,
            used: 8
        }
    );
    l.configure(
        grant,
        vec![Limit {
            meter: Meter::OutputTokens,
            window: Window::Day,
            amount: 20,
        }],
        4,
    )
    .unwrap();
    assert_eq!(
        l.node(grant)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Day)
            .used,
        8
    );
}
proptest! {
    #[test]
    fn interleaved_siblings_never_exceed_machine_or_parent(actions in prop::collection::vec((0u8..5,1u64..12),1..100)) {
        let mut ledger=Ledger::default();let nodes=[BudgetNode::Machine,BudgetNode::Grant(GrantId([1;16])),BudgetNode::Grant(GrantId([2;16]))];
        for node in nodes {ledger.configure(node,vec![Limit{meter:Meter::OutputTokens,window:Window::Day,amount:50}],8).unwrap();}
        let mut held=vec![];let mut nonce=0u64;let mut time=0u64;
        for (action,tokens) in actions {
            match action {
                0|1=>{nonce+=1;if let Ok(r)=ledger.reserve(Digest::hash(&nonce.to_be_bytes()),vec![nodes[0],nodes[usize::from(action)+1]],Charge([1,0,tokens,0]),UnixMillis(time)){held.push(r);}},
                2=>{if let Some(r)=held.pop(){ledger.settle(r,Usage::Unknown,UnixMillis(time)).unwrap();}},
                3=>{if let Some(r)=held.pop(){ledger.release(r).unwrap();}},
                _=>{time+=86_400_000;ledger.advance(UnixMillis(time));},
            }
            for node in nodes {prop_assert!(ledger.node(node).unwrap().counter(Meter::OutputTokens,Window::Day).used+ledger.reserved(node,Meter::OutputTokens)<=50);}
        }
    }
}

#[test]
fn torn_accept_dispatch_and_terminal_frames_never_create_partial_ancestor_debits() {
    let origin = tempfile::tempdir().unwrap();
    let mut store = setup(origin.path());
    let path = std::fs::read_dir(origin.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before_accept = std::fs::metadata(&path).unwrap().len() as usize;
    let (a, s, input) = proposal(&store, 1);
    let work = grant_work_id(network(), &a);
    store
        .accept(a, s, &input, &principal(2).1, UnixMillis(1_000))
        .unwrap();
    let before_dispatch = std::fs::metadata(&path).unwrap().len() as usize;
    store
        .dispatch(a.channel_id, work, UnixMillis(1_001))
        .unwrap();
    let before_terminal = std::fs::metadata(&path).unwrap().len() as usize;
    store
        .finish(
            a.channel_id,
            work,
            GrantOutcome::Failed,
            None,
            Usage::Observed(Charge([1, 0, 0, 0])),
            UnixMillis(1_002),
        )
        .unwrap();
    drop(store);
    let bytes = std::fs::read(&path).unwrap();
    for cut in [
        before_accept,
        before_accept + 1,
        before_dispatch - 1,
        before_dispatch,
        before_dispatch + 1,
        before_terminal - 1,
        before_terminal,
        before_terminal + 1,
        bytes.len() - 1,
        bytes.len(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(path.file_name().unwrap()), &bytes[..cut]).unwrap();
        let recovered = GrantStore::open(
            dir.path(),
            network(),
            principal(2).0.bundle().clone(),
            UnixMillis(1_010),
        )
        .unwrap();
        let used = u64::from(cut >= before_terminal);
        for node in [BudgetNode::Machine, BudgetNode::Grant(a.grant_id)] {
            assert_eq!(
                recovered
                    .state()
                    .ledger()
                    .node(node)
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                used
            );
            assert_eq!(
                recovered.state().ledger().reserved(node, Meter::Requests),
                0
            );
        }
        let book = recovered.state().channel(a.channel_id).unwrap().job_book();
        assert_eq!(
            book.proposal_nonce_high_water(),
            u64::from(cut >= before_dispatch)
        );
        assert!(book.jobs().next().is_none());
        let terminal = book.terminal_by_id(work);
        let expected = if cut < before_dispatch {
            None
        } else if cut < before_terminal {
            Some(GrantOutcome::Released)
        } else if cut < bytes.len() {
            Some(GrantOutcome::Indeterminate)
        } else {
            Some(GrantOutcome::Failed)
        };
        assert_eq!(terminal.map(|t| t.outcome.outcome), expected);
    }
}

#[test]
fn accepted_policy_revision_and_quarantine_survive_rotation_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let (a, s, input) = proposal(&store, 1);
    let original = store.state().policy_for(&a).unwrap().clone();
    let resource = original.resource_id().unwrap();
    store
        .accept(a, s, &input, &principal(2).1, UnixMillis(1_000))
        .unwrap();
    let mut def = store.state().grant(a.grant_id).unwrap().clone();
    def.revision = Revision(2);
    def.policies[0].name = "renamed".into();
    store.define(def.clone(), UnixMillis(1_010)).unwrap();
    assert_eq!(store.state().policy_for(&a).unwrap(), &original);
    let work = grant_work_id(network(), &a);
    store
        .dispatch(a.channel_id, work, UnixMillis(1_020))
        .unwrap();
    store
        .finish(
            a.channel_id,
            work,
            GrantOutcome::Failed,
            None,
            Usage::Observed(Charge([1, 0, 99, 0])),
            UnixMillis(1_030),
        )
        .unwrap();
    assert!(store.state().resource_health(resource).unwrap().quarantined);
    store.rotate().unwrap();
    drop(store);
    let mut store = GrantStore::open(
        dir.path(),
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1_040),
    )
    .unwrap();
    assert_eq!(store.state().policy_for(&a).unwrap(), &original);
    let (a2, s2, input2) = proposal(&store, 2);
    assert!(matches!(
        store.accept(a2, s2, &input2, &principal(2).1, UnixMillis(1_050)),
        Err(hellas_work::work_store::grant::GrantStoreError::Grant(
            GrantError::Quarantined
        ))
    ));
    def.revision = Revision(3);
    def.limits[0].amount = 100;
    store.define(def, UnixMillis(1_060)).unwrap();
    assert!(store.state().resource_health(resource).unwrap().quarantined);
    store.repair_resource(resource, UnixMillis(1_070)).unwrap();
    assert!(!store.state().resource_health(resource).unwrap().quarantined);
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Total)
            .used,
        99
    );
}

#[test]
fn three_unknown_http_usage_results_quarantine_until_explicit_repair() {
    use hellas_rpc::protocol::work_grant::resource::{AccountingProfile, HttpsResource};
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
    def.revision = Revision(2);
    if let WorkPolicy::Fetch { policy, .. } = &mut def.policies[0].work {
        policy.allowed_environment = FetchEnvironment::Http.manifest_id();
    }
    def.policies[0].https = Some(HttpsResource {
        origin: "https://glm.test".into(),
        paths: vec!["/v1/chat/completions".into()],
        methods: vec!["POST".into()],
        credential: None,
        tls: hellas_rpc::http_fetch::HttpTls {
            roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
            spki_sha256: vec![],
        },
        accounting: AccountingProfile::OpenaiChat,
        max_output_tokens: 8,
        max_response_bytes: 4096,
    });
    let resource = def.policies[0].resource_id().unwrap();
    store.define(def, UnixMillis(1_000)).unwrap();
    for nonce in 1..=3 {
        let (a, s, input) = proposal(&store, nonce);
        store
            .accept(a, s, &input, &principal(2).1, UnixMillis(1_000))
            .unwrap();
        let work = grant_work_id(network(), &a);
        store
            .dispatch(a.channel_id, work, UnixMillis(1_001))
            .unwrap();
        store
            .finish(
                a.channel_id,
                work,
                GrantOutcome::Failed,
                None,
                Usage::Unknown,
                UnixMillis(1_002),
            )
            .unwrap();
        assert_eq!(
            store.state().resource_health(resource).unwrap().quarantined,
            nonce == 3
        );
    }
    let (a, s, input) = proposal(&store, 4);
    assert!(matches!(
        store.accept(a, s, &input, &principal(2).1, UnixMillis(1_002)),
        Err(hellas_work::work_store::grant::GrantStoreError::Grant(
            GrantError::Quarantined
        ))
    ));
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Total)
            .used,
        24
    );
    store.tick(UnixMillis(86_400_000)).unwrap();
    assert!(store.state().resource_health(resource).unwrap().quarantined);
    store.rotate().unwrap();
    drop(store);
    let mut store = GrantStore::open(
        dir.path(),
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(86_400_001),
    )
    .unwrap();
    assert!(store.state().resource_health(resource).unwrap().quarantined);
    store
        .repair_resource(resource, UnixMillis(86_400_002))
        .unwrap();
    assert!(!store.state().resource_health(resource).unwrap().quarantined);
    let now = UnixMillis(86_400_002);
    store.configure_machine(vec![], 4, now).unwrap();
    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
    def.revision = Revision(3);
    def.limits.clear();
    store.define(def, now).unwrap();
    for nonce in 4..=9 {
        let (mut a, _, input) = proposal(&store, nonce);
        a.acceptance_deadline_ms = UnixMillis(now.0 + 1000);
        a.terminal_deadline_ms = UnixMillis(now.0 + 4000);
        a.delivery_deadline_ms = UnixMillis(now.0 + 5000);
        let work = grant_work_id(network(), &a);
        let sig = principal(1).1.sign_digest(work).unwrap();
        store.accept(a, sig, &input, &principal(2).1, now).unwrap();
        store.dispatch(a.channel_id, work, now).unwrap();
        store
            .finish(
                a.channel_id,
                work,
                GrantOutcome::Failed,
                None,
                if nonce == 6 {
                    Usage::Observed(Charge([1, 0, 2, 0]))
                } else {
                    Usage::Unknown
                },
                now,
            )
            .unwrap();
        let health = store.state().resource_health(resource).unwrap();
        assert_eq!(health.quarantined, nonce == 9);
        assert_eq!(
            health.consecutive_faults,
            if nonce < 6 { nonce - 3 } else { nonce - 6 } as u16
        );
    }
}

#[test]
fn failed_rotation_reserves_the_tail_for_all_accepted_jobs_not_clock_queries() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    store
        .configure_machine(vec![], 256, UnixMillis(1000))
        .unwrap();
    let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
    def.revision = Revision(2);
    def.limits.clear();
    def.max_in_flight = std::num::NonZeroU16::new(256).unwrap();
    store.define(def, UnixMillis(1000)).unwrap();
    let mut jobs = vec![];
    for nonce in 1..=32 {
        let (mut a, _, input) = proposal(&store, nonce);
        a.terminal_deadline_ms = UnixMillis(10_000);
        a.delivery_deadline_ms = UnixMillis(11_000);
        let work = grant_work_id(network(), &a);
        let signature = principal(1).1.sign_digest(work).unwrap();
        store
            .accept(a, signature, &input, &principal(2).1, UnixMillis(1000))
            .unwrap();
        jobs.push((a.channel_id, work));
    }
    let blocked = hellas_work::work_store::journal::generation_path(dir.path(), "grants", 1);
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("occupied"), b"rotation obstruction").unwrap();
    let now = (1001..10_000)
        .find(|&t| store.tick(UnixMillis(t)).is_err())
        .expect("soft limit requires rotation");
    let before = store.state().now();
    for _ in 0..20 {
        assert!(store.tick(UnixMillis(now)).is_err());
        assert_eq!(store.state().now(), before);
    }
    for (channel, work) in jobs {
        store.dispatch(channel, work, UnixMillis(now)).unwrap();
        store
            .finish(
                channel,
                work,
                GrantOutcome::Failed,
                None,
                Usage::Unknown,
                UnixMillis(now),
            )
            .unwrap();
    }
    assert_eq!(
        store
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        32
    );
    drop(store);
    std::fs::remove_dir_all(blocked).unwrap();
    let recovered = GrantStore::open(
        dir.path(),
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(now),
    )
    .unwrap();
    assert_eq!(
        recovered
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        0
    );
    assert_eq!(
        recovered
            .state()
            .ledger()
            .node(BudgetNode::Machine)
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        32
    );
}

#[test]
fn new_machine_meters_check_accepted_policy_revisions_but_not_drained_revocations() {
    for revoke in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = setup(dir.path());
        let (a, sig, input) = proposal(&store, 1);
        let work = grant_work_id(network(), &a);
        store
            .accept(a, sig, &input, &principal(2).1, UnixMillis(1000))
            .unwrap();
        store
            .dispatch(a.channel_id, work, UnixMillis(1001))
            .unwrap();
        let mut def = store.state().grant(a.grant_id).unwrap().clone();
        def.revision = Revision(2);
        if revoke {
            def.state = GrantState::Revoked;
        } else {
            def.policies[0].work =
                WorkPolicy::Evaluate(hellas_rpc::protocol::work::EvaluatePolicyV2 {
                    allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
                    generation_policy_digest: Digest::hash(b"native-generation"),
                    identity_source_digest: Digest::hash(b"native-identity"),
                    max_prompt_tokens: 512,
                    max_new_tokens: 128,
                    max_stop_token_ids: 4,
                    max_spool_bytes: 1_048_576,
                    max_encoded_result_frame: 262_144,
                    max_encoded_prepared_input: 1_048_576,
                });
        }
        store.define(def, UnixMillis(1002)).unwrap();
        let limits = vec![Limit {
            meter: Meter::DeviceMillis,
            window: Window::Day,
            amount: 1000,
        }];
        assert!(matches!(
            store.configure_machine(limits.clone(), 4, UnixMillis(1003)),
            Err(hellas_work::work_store::grant::GrantStoreError::Grant(
                GrantError::Limits
            ))
        ));
        store
            .finish(
                a.channel_id,
                work,
                GrantOutcome::Failed,
                None,
                Usage::Unknown,
                UnixMillis(1004),
            )
            .unwrap();
        store
            .configure_machine(limits, 4, UnixMillis(1005))
            .unwrap();
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
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn concurrent_proposals_and_arbitrary_crash_cuts_preserve_ancestor_accounting(
        actions in prop::collection::vec(0u8..4, 1..32), cut_seed in any::<usize>()
    ) {
        let origin = tempfile::tempdir().unwrap();
        let mut store = setup(origin.path());
        let path = std::fs::read_dir(origin.path()).unwrap().next().unwrap().unwrap().path();
        let initial = std::fs::metadata(&path).unwrap().len() as usize;
        // Independent recovery oracle: queued work is free; dispatched work
        // costs one request even if its terminal frame never became durable.
        let mut queued = vec![];
        let mut running = vec![];
        let mut settled = 0u64;
        let mut nonce = 0u64;
        let mut checkpoints = vec![(initial, 0u64, 0u64)];
        for action in actions {
            match action {
                0 => {
                    let (a, sig, input) = proposal(&store, nonce + 1);
                    if store.accept(a, sig, &input, &principal(2).1, UnixMillis(1000)).is_ok() {
                        queued.push((a.channel_id, grant_work_id(network(), &a)));
                        nonce += 1;
                    }
                }
                1 => if let Some((channel, work)) = queued.pop() {
                    store.dispatch(channel, work, UnixMillis(1000)).unwrap();
                    running.push((channel, work));
                },
                2 => if let Some((channel, work)) = running.pop() {
                    store.finish(channel, work, GrantOutcome::Failed, None,
                        Usage::Observed(Charge([1,0,0,0])), UnixMillis(1000)).unwrap();
                    settled += 1;
                },
                _ => if let Some((channel, work)) = queued.pop() {
                    store.release(channel, work, UnixMillis(1000)).unwrap();
                },
            }
            checkpoints.push((std::fs::metadata(&path).unwrap().len() as usize,
                settled + running.len() as u64, nonce));
            for (node, limit) in [(BudgetNode::Machine, 4), (BudgetNode::Grant(GrantId([1;16])), 3)] {
                prop_assert!(store.state().ledger().node(node).unwrap().counter(Meter::Requests, Window::Total).used
                    + store.state().ledger().reserved(node, Meter::Requests) <= limit);
            }
        }
        let bytes = std::fs::read(&path).unwrap();
        let cut = initial + cut_seed % (bytes.len() - initial + 1);
        let (_, expected_used, expected_nonce) = *checkpoints.iter().rev().find(|(end,_,_)| *end <= cut).unwrap();
        let recovered_dir = tempfile::tempdir().unwrap();
        std::fs::write(recovered_dir.path().join(path.file_name().unwrap()), &bytes[..cut]).unwrap();
        let recovered = GrantStore::open(recovered_dir.path(), network(), principal(2).0.bundle().clone(), UnixMillis(1001)).unwrap();
        for node in [BudgetNode::Machine, BudgetNode::Grant(GrantId([1;16]))] {
            prop_assert_eq!(recovered.state().ledger().node(node).unwrap().counter(Meter::Requests, Window::Total).used, expected_used);
            prop_assert_eq!(recovered.state().ledger().reserved(node, Meter::Requests), 0);
        }
        let channel = recovered.state().channel_id(GrantId([1;16])).unwrap();
        let book = recovered.state().channel(channel).unwrap().job_book();
        prop_assert_eq!(book.proposal_nonce_high_water(), expected_nonce);
        prop_assert!(book.jobs().next().is_none());
    }
}

#[test]
fn invalid_initial_revision_and_unsupported_ancestor_paths_are_not_capacity_errors() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let mut def = definition(GrantId([2; 16]), principal(1).0);
    def.revision = Revision(2);
    assert!(matches!(
        store.define(def, UnixMillis(1000)),
        Err(hellas_work::work_store::grant::GrantStoreError::Grant(
            GrantError::Malformed
        ))
    ));
    let mut ledger = Ledger::default();
    assert!(matches!(
        ledger.reserve(
            Digest::hash(b"unsupported-depth"),
            vec![
                BudgetNode::Machine,
                BudgetNode::Grant(GrantId([1; 16])),
                BudgetNode::Grant(GrantId([2; 16]))
            ],
            Charge([1, 0, 0, 0]),
            UnixMillis(1000)
        ),
        Err(LedgerError::InvalidPath)
    ));
}

#[test]
fn retrying_dispatch_does_not_consume_another_journal_duty_frame() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(dir.path());
    let (a, sig, input) = proposal(&store, 1);
    let work = grant_work_id(network(), &a);
    store
        .accept(a, sig, &input, &principal(2).1, UnixMillis(1000))
        .unwrap();
    store
        .dispatch(a.channel_id, work, UnixMillis(1001))
        .unwrap();
    let path = std::fs::read_dir(dir.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before = std::fs::read(&path).unwrap();
    store
        .dispatch(a.channel_id, work, UnixMillis(1002))
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), before);
}
