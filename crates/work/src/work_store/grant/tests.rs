//! Grant accounting has no chain fixture. The same signed Fetch input used by
//! Work is admitted here without constructing financial channel terms.

use crate::model::{
    grant::{budget::*, records::*, *},
    profile::*,
};
use hellas_auth::Digest;
use hellas_auth::authority::{GrantId, ResourceId, Revision, UnixMillis};
use hellas_rpc::*;
use hellas_work::work_store::{
    grant::{
        GrantOutcome, NodeStore, NodeStoreError,
        ledger::{Ledger, LedgerError},
    },
    journal::Journal,
};
use proptest::prelude::*;

use crate::test_support::*;
mod budgets;
mod catalogue;
mod pricing;
mod reservations;
mod resource_health;
#[derive(Clone, Copy, Debug)]
enum PolicyCopy {
    Catalogue,
    Current,
    History,
}
impl PolicyCopy {
    const ALL: [Self; 3] = [Self::Catalogue, Self::Current, Self::History];
    fn get_mut(self, snapshot: &mut serde_json::Value) -> &mut serde_json::Value {
        let pointer = match self {
            Self::Catalogue => "/catalogue/0",
            Self::Current => "/grants/0/policies/0",
            Self::History => "/history/0/policies/0",
        };
        snapshot.pointer_mut(pointer).unwrap()
    }
}

fn standing_query(store: &NodeStore) -> crate::model::grant::standing::StandingLocator {
    use crate::model::grant::standing::*;
    StandingLocator {
        provider: store.state().provider().unwrap().content_id(),
        grant: GrantId([1; 16]),
        client: principal(1).0,
        generation: 0,
    }
}
async fn standing(store: &mut NodeStore) -> crate::model::grant::standing::Standing {
    let query = standing_query(store);
    store
        .standing(query, &principal(2).1, vec![], UnixMillis(1_000))
        .unwrap()
}
#[tokio::test]
async fn standing_discovers_a_stale_generation_without_resetting_usage() {
    use crate::model::grant::standing::*;
    use hellas_work::work_store::grant::NodeStoreError;
    let dir = tempfile::tempdir().unwrap();
    let (mut store, application) = setup(dir.path()).await;
    let (a, sig, input) = proposal(&store, 1);
    accept(&mut store, &application, (a, sig, &input), 1_000)
        .await
        .unwrap();
    let original = standing(&mut store).await;
    assert_eq!(original.nodes.len(), 1);
    assert_eq!(original.nodes[0].active, 1);
    assert_eq!(original.nodes[0].counters[0].reserved, 1);
    assert_eq!(original.nodes[0].counters[3].remaining, Some(2));
    assert_eq!(
        Standing::decode(&original.encode().unwrap(), UnixMillis(1_000)).unwrap(),
        original
    );
    let mut leaking = original.clone();
    let mut machine = leaking.nodes[0].clone();
    machine.node = BudgetNode::Machine;
    leaking.nodes.push(machine);
    assert_eq!(
        Standing::decode(&leaking.encode().unwrap(), UnixMillis(1000)),
        Err(GrantError::Malformed)
    );
    let query = standing_query(&store);
    store
        .bump_generation(a.grant_id, UnixMillis(1_000))
        .await
        .unwrap();
    let updated = standing(&mut store).await;
    assert_eq!(updated.offer.offer().generation, 1);
    assert_ne!(
        updated.offer.offer().channel(principal(1).0),
        original.offer.offer().channel(principal(1).0)
    );
    assert_eq!(updated.nodes, original.nodes);
    assert_err!(
        store.standing(
            StandingLocator {
                generation: 2,
                ..query
            },
            &principal(2).1,
            vec![],
            UnixMillis(1_000)
        ),
        NodeStoreError::Grant(GrantError::Unauthorized)
    );
    let mut def = store.state().grant(a.grant_id).unwrap().clone();
    def.revision.0 += 1;
    def.enabled = false;
    store.define(def, UnixMillis(1_000)).await.unwrap();
    assert!(!standing(&mut store).await.offer.offer().grant.enabled);
    assert_eq!(standing(&mut store).await.nodes[0].active, 0);
}
#[tokio::test]
async fn client_pending_proposal_survives_restart_and_never_journals_bodies() {
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let dir = tempfile::tempdir().unwrap();
    let (mut provider, application) = setup(&dir.path().join("provider")).await;
    let offer = standing(&mut provider).await.offer;
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
        crate::test_support::software_enrollment(2, [2; 32]),
        channel.clone(),
        crate::test_support::node_key(1),
        UnixMillis(1_000),
    )
    .await
    .unwrap();
    assert_eq!(
        client
            .propose(&offer, a, &input, &principal(1).1, UnixMillis(1_000))
            .await
            .unwrap(),
        sig
    );
    let work = grant_work_id(network(), &a);
    let accepted = provider
        .accept(
            (&application, JOURNAL_AUTHORIZATION),
            a,
            sig,
            &input,
            &principal(2).1,
            UnixMillis(1_000),
        )
        .await
        .unwrap();
    assert_err!(
        client.next_nonce(),
        NodeStoreError::Channel(crate::work_store::ChannelStateError::Conflict {
            what: "unanswered proposal"
        })
    );
    client.rotate().await.unwrap();
    drop(client);
    let mut client = GrantClientStore::open(
        &client_dir,
        network(),
        crate::test_support::software_enrollment(2, [2; 32]),
        channel,
        crate::test_support::node_key(1),
        UnixMillis(3_000),
    )
    .await
    .unwrap();
    assert_eq!(client.book().pending_proposal(), Some(work));
    assert_err!(
        client.next_nonce(),
        NodeStoreError::Channel(crate::work_store::ChannelStateError::Conflict {
            what: "unanswered proposal"
        })
    );
    client
        .accepted(work, accepted, UnixMillis(3_000))
        .await
        .unwrap();
    client
        .accepted(work, accepted, UnixMillis(3_000))
        .await
        .unwrap();
    assert_eq!(client.next_nonce().unwrap(), 2);
    assert!(
        client
            .book()
            .job_by_id(work)
            .unwrap()
            .prepared_input()
            .is_empty()
    );
    client.rotate().await.unwrap();
    for path in crate::test_support::all_files(&client_dir) {
        let bytes = std::fs::read(path).unwrap();
        assert!(
            !bytes
                .windows(b"never-journal-this-body".len())
                .any(|w| w == b"never-journal-this-body")
        );
    }
    client.tick(UnixMillis(6_000)).await.unwrap();
    assert_eq!(client.book().jobs().len(), 0);
    assert_eq!(client.next_nonce().unwrap(), 2);
}
#[tokio::test]
async fn client_replays_its_journal_after_a_cancelled_append() {
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let dir = tempfile::tempdir().unwrap();
    let (mut provider, application) = setup(&dir.path().join("provider")).await;
    let offer = standing(&mut provider).await.offer;
    let (a, sig, input) = proposal(&provider, 1);
    let channel = GrantChannelState {
        id: a.channel_id,
        grant: a.grant_id,
        generation: 0,
        client: principal(1).0,
    };
    let mut client = GrantClientStore::open(
        &dir.path().join("client"),
        network(),
        crate::test_support::software_enrollment(2, [2; 32]),
        channel,
        crate::test_support::node_key(1),
        UnixMillis(1_000),
    )
    .await
    .unwrap();
    client
        .propose(&offer, a, &input, &principal(1).1, UnixMillis(1_000))
        .await
        .unwrap();
    let work = grant_work_id(network(), &a);
    let accepted = provider
        .accept(
            (&application, JOURNAL_AUTHORIZATION),
            a,
            sig,
            &input,
            &principal(2).1,
            UnixMillis(1_000),
        )
        .await
        .unwrap();
    // A gateway deadline drops the session future while the append is in flight.
    {
        let mut cancelled = std::pin::pin!(client.accepted(work, accepted, UnixMillis(1_000)));
        assert!(futures::poll!(&mut cancelled).is_pending());
    }
    client
        .accepted(work, accepted, UnixMillis(1_000))
        .await
        .unwrap();
    assert_eq!(client.book().pending_proposal(), None);
    assert_eq!(client.next_nonce().unwrap(), 2);
}
#[tokio::test]
async fn client_refusal_cannot_clear_an_unanswered_proposal() {
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let dir = tempfile::tempdir().unwrap();
    let (mut provider, _application) = setup(&dir.path().join("provider")).await;
    let offer = standing(&mut provider).await.offer;
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
        crate::test_support::software_enrollment(2, [2; 32]),
        channel.clone(),
        crate::test_support::node_key(1),
        UnixMillis(1_000),
    )
    .await
    .unwrap();
    client
        .propose(&offer, a, &input, &principal(1).1, UnixMillis(1_000))
        .await
        .unwrap();
    let id = grant_work_id(network(), &a);
    client.refused(id, UnixMillis(1_000)).await.unwrap();
    assert_eq!(client.next_nonce().unwrap(), 2);
    client.resume(id, UnixMillis(1_000)).await.unwrap();
    client.tick(UnixMillis(6_000)).await.unwrap();
    client.rotate().await.unwrap();
    drop(client);
    let mut client = GrantClientStore::open(
        &path,
        network(),
        crate::test_support::software_enrollment(2, [2; 32]),
        channel,
        crate::test_support::node_key(1),
        UnixMillis(1),
    )
    .await
    .unwrap();
    assert_eq!(client.now(), UnixMillis(6_000));
    assert_eq!(client.book().pending_proposal(), Some(id));
    assert_err!(
        client.next_nonce(),
        NodeStoreError::Channel(crate::work_store::ChannelStateError::Conflict {
            what: "unanswered proposal"
        })
    );
    client.refused(id, UnixMillis(6_000)).await.unwrap();
    assert_eq!(client.book().jobs().len(), 0);
    assert_eq!(client.next_nonce().unwrap(), 2);
}
#[tokio::test]
async fn lost_body_probe_returns_the_old_cosignature_or_a_conclusive_expiry() {
    use hellas_work::work_store::grant::NodeStoreError;
    for accepted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, application) = setup(dir.path()).await;
        let (a, signature, input) = proposal(&store, 1);
        let old = if accepted {
            Some(
                accept(&mut store, &application, (a, signature, &input), 1_000)
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        let reply = store
            .precheck_acceptance(
                &a,
                (
                    principal(1).0,
                    hellas_kernel::Key::from_bytes(*crate::test_support::node_key(1).as_bytes()),
                ),
                &signature,
                UnixMillis(2_001),
            )
            .await;
        if accepted {
            assert_eq!(reply.unwrap(), old);
        } else {
            assert_err!(reply, NodeStoreError::Grant(GrantError::Expired));
            assert_err!(
                store
                    .precheck_acceptance(
                        &a,
                        (
                            principal(1).0,
                            hellas_kernel::Key::from_bytes(
                                *crate::test_support::node_key(1).as_bytes()
                            )
                        ),
                        &signature,
                        UnixMillis(1)
                    )
                    .await,
                NodeStoreError::Grant(GrantError::Expired)
            );
        }
    }
}

fn work_node(path: &std::path::Path) -> Node {
    use crate::test_support::{actors::FRIEND, ids};
    Node::bootstrap(path)
        .with_grant(
            ids::FRIEND_GRANT,
            Rights::new(authority(), FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(100_000))
                .build(),
        )
        .with_allowance(Allowance::responses(ids::ALLOWANCE, FRIEND))
}

#[tokio::test]
async fn acceptance_appends_exactly_one_frame() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    let before = node.store.journal_len();
    let signature = node
        .accept(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    let after = node.store.journal_len();
    assert_eq!(after, before + 1);
    node.clock.set(UnixMillis(1001));
    assert_eq!(
        node.accept(FRIEND, ids::FRIEND_GRANT, &request)
            .await
            .unwrap(),
        signature
    );
    assert_eq!(node.store.journal_len(), after);
}

#[tokio::test]
async fn checkpoint_recovery_retains_the_original_cosignature() {
    use crate::test_support::{actors::FRIEND, ids};
    use crate::work_store::JobPhase;
    for phase in [JobPhase::Accepted, JobPhase::Running] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = work_node(directory.path()).build().await;
        let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
        let signature = node
            .accept(FRIEND, ids::FRIEND_GRANT, &request)
            .await
            .unwrap();
        let dispatched = phase == JobPhase::Running;
        if dispatched {
            node.dispatch(FRIEND, ids::FRIEND_GRANT, &request)
                .await
                .unwrap();
        }
        node.store.rotate().await.unwrap();
        node.clock.set(UnixMillis(1003));
        let mut node = node.reopen().await;
        let book = node
            .store
            .state()
            .channel(request.authorization.channel_id)
            .unwrap()
            .job_book();
        assert!(book.jobs().next().is_none());
        assert_eq!(
            book.terminal_by_id(request.work()).unwrap().outcome.outcome,
            if dispatched {
                GrantOutcome::Indeterminate
            } else {
                GrantOutcome::Released
            }
        );
        assert_eq!(
            node.used(BudgetNode::Machine, Meter::Requests),
            u64::from(dispatched)
        );
        assert_eq!(
            node.store
                .state()
                .recovery_holds(BudgetNode::Machine, UnixMillis(1003))
                .unwrap(),
            usize::from(dispatched)
        );
        assert_eq!(
            node.store
                .state()
                .recovery_holds(BudgetNode::Machine, UnixMillis(4000))
                .unwrap(),
            0
        );
        node.clock.set(UnixMillis(1004));
        assert_eq!(
            node.accept(FRIEND, ids::FRIEND_GRANT, &request)
                .await
                .unwrap(),
            signature
        );
    }
}

#[tokio::test]
async fn request_bodies_never_enter_provider_journals() {
    use crate::test_support::{actors::FRIEND, ids};
    enum Step {
        Accept,
        Dispatch,
        Finish,
        Rotate,
        Reopen,
    }
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    for step in [
        Step::Accept,
        Step::Dispatch,
        Step::Finish,
        Step::Rotate,
        Step::Reopen,
    ] {
        match step {
            Step::Accept => {
                node.accept(FRIEND, ids::FRIEND_GRANT, &request)
                    .await
                    .unwrap();
            }
            Step::Dispatch => node
                .dispatch(FRIEND, ids::FRIEND_GRANT, &request)
                .await
                .unwrap(),
            Step::Finish => {
                node.finish(&request, Usage::Observed(Charge([1, 0, 2, 0, 0])))
                    .await
            }
            Step::Rotate => node.store.rotate().await.unwrap(),
            Step::Reopen => node = node.reopen().await,
        }
        for path in crate::test_support::all_files(directory.path()) {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(b"never-journal-this-body".len())
                    .any(|b| b == b"never-journal-this-body")
            );
        }
    }
}

#[tokio::test]
async fn paused_terms_release_queued_work_without_reusing_its_nonce() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let first = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    node.accept(FRIEND, ids::FRIEND_GRANT, &first)
        .await
        .unwrap();
    let mut terms = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
    terms.revision.0 += 1;
    terms.enabled = false;
    node.store
        .define(terms.clone(), node.clock.now())
        .await
        .unwrap();
    assert_eq!(
        node.store
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        0
    );
    let book = node
        .store
        .state()
        .channel(first.authorization.channel_id)
        .unwrap()
        .job_book();
    assert_eq!(book.proposal_nonce_high_water(), 1);
    assert_eq!(
        book.terminal_by_id(first.work()).unwrap().outcome.outcome,
        GrantOutcome::Released
    );
    let second = node.proposal(FRIEND, ids::ALLOWANCE, 2);
    let before = node.snapshot();
    assert_err!(
        node.accept(FRIEND, ids::FRIEND_GRANT, &second).await,
        NodeStoreError::Grant(GrantError::Paused)
    );
    assert_eq!(node.snapshot(), before);
    terms.revision.0 += 1;
    terms.enabled = true;
    node.store.define(terms, node.clock.now()).await.unwrap();
    let second = node.proposal(FRIEND, ids::ALLOWANCE, 2);
    node.accept(FRIEND, ids::FRIEND_GRANT, &second)
        .await
        .unwrap();
    assert_eq!(
        node.store
            .state()
            .channel(second.authorization.channel_id)
            .unwrap()
            .job_book()
            .proposal_nonce_high_water(),
        2
    );
}

#[tokio::test]
async fn revising_terms_cannot_reset_spending() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let first = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    node.accept(FRIEND, ids::FRIEND_GRANT, &first)
        .await
        .unwrap();
    node.dispatch(FRIEND, ids::FRIEND_GRANT, &first)
        .await
        .unwrap();
    node.finish(&first, Usage::Observed(Charge([1, 0, 2, 0, 0])))
        .await;
    let mut terms = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
    terms.revision.0 += 1;
    let mut budget = node
        .store
        .state()
        .ledger()
        .definition(terms.budget)
        .unwrap();
    budget.revision.0 += 1;
    budget.limits = vec![Limit {
        meter: Meter::Requests,
        window: Window::Total,
        amount: 1,
    }];
    node.store
        .configure_budget(budget, node.clock.now())
        .await
        .unwrap();
    node.store
        .define(terms.clone(), node.clock.now())
        .await
        .unwrap();
    assert_eq!(node.used(terms.budget, Meter::Requests), 1);
    let second = node.proposal(FRIEND, ids::ALLOWANCE, 2);
    let before = node.snapshot();
    assert_err!(node.accept(FRIEND, ids::FRIEND_GRANT, &second).await,
        NodeStoreError::Ledger(LedgerError::OverBudget { node: budget, meter: Meter::Requests, window: Window::Total }) if budget == terms.budget);
    assert_eq!(node.snapshot(), before);
}

fn configured_ledger(limits: Vec<Limit>, concurrent: u16) -> Ledger {
    let mut ledger = Ledger::default();
    ledger
        .configure_machine(limits.clone(), concurrent)
        .unwrap();
    for seed in [1, 3] {
        for definition in common_node::budgets(
            common_node::POOL,
            principal(seed).0,
            limits.clone(),
            concurrent,
        ) {
            if ledger.node(definition.node).is_none() {
                ledger.configure_budget(definition).unwrap();
            }
        }
    }
    ledger
}
#[tokio::test]
async fn new_machine_meters_check_accepted_and_paused_terms() {
    for revoke in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, application) = setup(dir.path()).await;
        let (a, sig, input) = proposal(&store, 1);
        let work = grant_work_id(network(), &a);
        accept(&mut store, &application, (a, sig, &input), 1000)
            .await
            .unwrap();
        dispatch(&mut store, &application, (a.channel_id, work), 1001)
            .await
            .unwrap();
        let mut def = store.state().grant(a.grant_id).unwrap().clone();
        def.revision = Revision(2);
        if revoke {
            def.enabled = false;
        } else {
            def.policies[0].responses = None;
            def.policies[0].work = WorkPolicy::Evaluate(crate::model::work::EvaluatePolicyV2 {
                allowed_environment: test_responses_contract().manifest_id(),
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
        if !revoke {
            def.policies[0].revision.0 += 1;
            store
                .configure_resource(def.policies[0].clone(), UnixMillis(1002))
                .await
                .unwrap();
        }
        store.define(def, UnixMillis(1002)).await.unwrap();
        let limits = vec![Limit {
            meter: Meter::DeviceMillis,
            window: Window::Day,
            amount: 1000,
        }];
        assert_err!(
            store
                .configure_machine(limits.clone(), 4, UnixMillis(1003))
                .await,
            hellas_work::work_store::grant::NodeStoreError::Grant(GrantError::Limits)
        );
        finish(
            &mut store,
            (a.channel_id, work),
            GrantOutcome::Failed,
            Usage::Unknown,
            1004,
        )
        .await
        .unwrap();
        let result = store.configure_machine(limits, 4, UnixMillis(1005)).await;
        if revoke {
            assert_err!(result, NodeStoreError::Grant(GrantError::Limits));
        } else {
            result.unwrap();
        }
        assert_eq!(used(&store, BudgetNode::Machine, Meter::Requests), 1);
    }
}

#[tokio::test]
async fn new_allowances_require_the_initial_revision() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let mut terms = definition(ids::NEW_ALLOWANCE, FRIEND.principal());
    terms.revision = Revision(2);
    let before = node.snapshot();
    assert_err!(
        node.store.define(terms, node.clock.now()).await,
        NodeStoreError::Grant(GrantError::Malformed)
    );
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn retrying_dispatch_does_not_consume_another_journal_duty_frame() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, application) = setup(dir.path()).await;
    let (a, sig, input) = proposal(&store, 1);
    let work = grant_work_id(network(), &a);
    accept(&mut store, &application, (a, sig, &input), 1000)
        .await
        .unwrap();
    dispatch(&mut store, &application, (a.channel_id, work), 1001)
        .await
        .unwrap();
    let before = store.journal_len();
    dispatch(&mut store, &application, (a.channel_id, work), 1002)
        .await
        .unwrap();
    assert_eq!(store.journal_len(), before);
}

#[tokio::test]
async fn ownership_recovery_preserves_spent_usage_pending_jobs_and_nonce_history() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, application) = setup(dir.path()).await;
    let (finished, sig, input) = proposal(&store, 1);
    accept(&mut store, &application, (finished, sig, &input), 1000)
        .await
        .unwrap();
    let finished_id = grant_work_id(network(), &finished);
    dispatch(
        &mut store,
        &application,
        (finished.channel_id, finished_id),
        1000,
    )
    .await
    .unwrap();
    finish(
        &mut store,
        (finished.channel_id, finished_id),
        GrantOutcome::Failed,
        Usage::Observed(Charge([1, 0, 0, 0, 0])),
        1000,
    )
    .await
    .unwrap();
    let (running, sig, input) = proposal(&store, 2);
    accept(&mut store, &application, (running, sig, &input), 1000)
        .await
        .unwrap();
    let running_id = grant_work_id(network(), &running);
    dispatch(
        &mut store,
        &application,
        (running.channel_id, running_id),
        1000,
    )
    .await
    .unwrap();
    let (queued, sig, input) = proposal(&store, 3);
    accept(&mut store, &application, (queued, sig, &input), 1000)
        .await
        .unwrap();
    let admission_history = store.state().admissions.clone();
    let authority = store.state().authority();
    let expected = authority.revision();
    let mut replacement = authority
        .grant(authority.root_grant())
        .unwrap()
        .spec()
        .clone();
    replacement.subject = principal(3).0;
    drop(store);
    let (_, before) = Journal::inspect(dir.path(), "grants").await.unwrap();
    let (receipt, _) = NodeStore::recover_offline(
        dir.path(),
        network(),
        expected,
        crate::test_support::common_node::approval_for(
            hellas_auth::authority::Ownership::Recover { expected },
            replacement.clone(),
            replacement,
        ),
        UnixMillis(1000),
    )
    .await
    .unwrap();
    let (_, after) = Journal::inspect(dir.path(), "grants").await.unwrap();
    assert_eq!(
        after.records.len(),
        before.records.len() + 1,
        "ownership recovery must not finalize jobs"
    );
    let mut store = reopen(dir.path(), 1001).await.unwrap();
    assert_eq!(store.state().authority().last_recovery(), Some(&receipt));
    assert_eq!(store.state().admissions, admission_history);
    let book = store
        .state()
        .channel(running.channel_id)
        .unwrap()
        .job_book();
    assert_eq!(book.proposal_nonce_high_water(), 3);
    assert_eq!(
        book.terminal_by_id(finished_id).unwrap().outcome.outcome,
        GrantOutcome::Failed
    );
    assert_eq!(
        book.terminal_by_id(running_id).unwrap().outcome.outcome,
        GrantOutcome::Indeterminate
    );
    assert_eq!(
        book.terminal_by_id(grant_work_id(network(), &queued))
            .unwrap()
            .outcome
            .outcome,
        GrantOutcome::Released
    );
    assert_eq!(used(&store, BudgetNode::Machine, Meter::Requests), 2);
    assert_eq!(
        store
            .state()
            .recovery_holds(BudgetNode::Machine, UnixMillis(1001))
            .unwrap(),
        1
    );
    let mut replay = queued;
    replay.delivery_deadline_ms.0 += 1;
    let replay_signature = principal(1)
        .1
        .sign_digest(grant_work_id(network(), &replay))
        .unwrap();
    assert_err!(
        accept(
            &mut store,
            &application,
            (replay, replay_signature, &input),
            1001
        )
        .await,
        NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Credential)
    );
    store.rotate().await.unwrap();
    let before = store.state().clone();
    drop(store);
    let store = NodeStore::open(dir.path(), network(), None, UnixMillis(1001))
        .await
        .unwrap();
    assert_eq!(
        store.state(),
        &before,
        "ordinary restart cannot reset ownership or charge twice"
    );
}

// Raw transitions are test fixtures for journal/accounting invariants, never host APIs.
use super::state::Change;
impl NodeStore {
    pub(crate) async fn configure_resource(
        &mut self,
        policy: GrantPolicy,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, super::state::Change::Resource(policy), true)
            .await
    }

    pub(crate) async fn configure_budget(
        &mut self,
        definition: BudgetDef,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, Change::Budget(definition), true).await
    }
    pub(crate) async fn configure_machine(
        &mut self,
        limits: Vec<Limit>,
        concurrent: u16,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, Change::Machine { limits, concurrent }, true)
            .await
    }
    pub(crate) async fn define(
        &mut self,
        definition: GrantDef,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, Change::Define(definition), true).await
    }
    pub(crate) async fn bump_generation(
        &mut self,
        grant: GrantId,
        now: UnixMillis,
    ) -> Result<u64, NodeStoreError> {
        let generation = self
            .state()
            .generation(grant)
            .and_then(|n| n.checked_add(1))
            .ok_or(GrantError::Generation)?;
        self.commit(now, Change::Generation { grant, generation }, true)
            .await?;
        Ok(generation)
    }
    pub(crate) async fn repair_resource(
        &mut self,
        id: ResourceId,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.commit(now, Change::RepairResource(id), true).await
    }
}

use hellas_work::test_support::test_responses_contract;
