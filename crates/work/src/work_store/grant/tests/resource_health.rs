use super::*;
use crate::test_support::{actors::FRIEND, ids};

#[derive(Clone, Copy, Debug)]
enum Profile {
    Responses,
    Http,
}
async fn fixture(path: &std::path::Path, profile: Profile) -> TestNode {
    let mut allowance = Allowance::responses(ids::ALLOWANCE, FRIEND);
    if matches!(profile, Profile::Http) {
        use_https(
            &mut allowance.definition.policies[0],
            chat_resource("https://glm.test", 8),
        );
    }
    Node::bootstrap(path)
        .with_grant(
            ids::FRIEND_GRANT,
            Rights::new(authority(), FRIEND)
                .allow(
                    crate::grant_service::WORK_EXECUTE,
                    crate::grant_service::allowance_resource(authority(), ids::ALLOWANCE),
                )
                .valid_until(UnixMillis(u64::MAX))
                .build(),
        )
        .with_allowance(allowance)
        .build()
        .await
}
async fn settle(node: &mut TestNode, nonce: u64, usage: Usage) {
    let mut request = node.proposal(FRIEND, ids::ALLOWANCE, nonce);
    let now = node.clock.now().0;
    request.authorization.acceptance_deadline_ms = UnixMillis(now + 1000);
    request.authorization.terminal_deadline_ms = UnixMillis(now + 4000);
    request.authorization.delivery_deadline_ms = UnixMillis(now + 5000);
    request.signature = FRIEND.key().sign_digest(request.work()).unwrap();
    node.accept(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    node.dispatch(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    node.finish(&request, usage).await;
}
fn quarantined(node: &TestNode) -> bool {
    node.store
        .state()
        .resource_health(policy().resource)
        .unwrap()
        .quarantined
}
fn assert_spent(node: &TestNode, output: u64) {
    let leaf = BudgetNode::Subject {
        pool: common_node::POOL,
        subject: FRIEND.principal(),
    };
    for ancestor in node.store.state().ledger().path(leaf).unwrap() {
        assert_eq!(
            node.used(ancestor, Meter::OutputTokens),
            output,
            "{ancestor:?}"
        );
    }
}

#[tokio::test]
async fn an_observed_overrun_quarantines_the_resource() {
    for profile in [Profile::Responses, Profile::Http] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = fixture(directory.path(), profile).await;
        settle(&mut node, 1, Usage::Observed(Charge([1, 0, 9, 0, 0]))).await;
        assert!(quarantined(&node), "{profile:?}");
        assert_spent(&node, 9);
        let request = node.proposal(FRIEND, ids::ALLOWANCE, 2);
        let before = node.snapshot();
        assert_err!(
            node.accept(FRIEND, ids::FRIEND_GRANT, &request).await,
            NodeStoreError::Grant(GrantError::Quarantined)
        );
        assert_eq!(node.snapshot(), before);
    }
}

#[tokio::test]
async fn the_third_consecutive_unknown_result_quarantines() {
    for profile in [Profile::Responses, Profile::Http] {
        let directory = tempfile::tempdir().unwrap();
        let mut node = fixture(directory.path(), profile).await;
        for nonce in 1..=3 {
            settle(&mut node, nonce, Usage::Unknown).await;
            assert_eq!(quarantined(&node), nonce == 3, "{profile:?} result {nonce}");
        }
        assert_spent(&node, 24);
        node.store.rotate().await.unwrap();
        let mut node = node.reopen().await;
        let request = node.proposal(FRIEND, ids::ALLOWANCE, 4);
        let before = node.snapshot();
        assert_err!(
            node.accept(FRIEND, ids::FRIEND_GRANT, &request).await,
            NodeStoreError::Grant(GrantError::Quarantined)
        );
        assert_eq!(node.snapshot(), before);
    }
}

#[tokio::test]
async fn observed_usage_resets_the_consecutive_unknown_count() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = fixture(directory.path(), Profile::Http).await;
    for (index, expected) in [1, 2, 0, 1, 2, 3].into_iter().enumerate() {
        let usage = if expected == 0 {
            Usage::Observed(Charge([1, 0, 2, 0, 0]))
        } else {
            Usage::Unknown
        };
        settle(&mut node, index as u64 + 1, usage).await;
        let health = node
            .store
            .state()
            .resource_health(policy().resource)
            .unwrap();
        assert_eq!(health.consecutive_faults, expected);
        assert_eq!(health.quarantined, expected == 3);
    }
}

#[tokio::test]
async fn only_explicit_repair_clears_persisted_quarantine() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = fixture(directory.path(), Profile::Responses).await;
    settle(&mut node, 1, Usage::Observed(Charge([1, 0, 99, 0, 0]))).await;
    let mut terms = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
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
        amount: 100,
    }];
    node.store
        .configure_budget(budget, node.clock.now())
        .await
        .unwrap();
    let mut changed = policy();
    changed.revision.0 += 1;
    changed.name = "renamed".into();
    node.store
        .configure_resource(changed.clone(), node.clock.now())
        .await
        .unwrap();
    assert!(quarantined(&node));
    terms.revision.0 += 1;
    terms.policies = vec![changed.clone()];
    node.store.define(terms, node.clock.now()).await.unwrap();
    assert!(quarantined(&node));
    node.clock.set(UnixMillis(86_400_000));
    node.store.tick(node.clock.now()).await.unwrap();
    assert!(quarantined(&node));
    node.store.rotate().await.unwrap();
    let mut node = node.reopen().await;
    assert_eq!(
        node.store.state().resource(changed.resource),
        Some(&changed)
    );
    assert!(quarantined(&node));
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 2);
    let before = node.snapshot();
    assert_err!(
        node.accept(FRIEND, ids::FRIEND_GRANT, &request).await,
        NodeStoreError::Grant(GrantError::Quarantined)
    );
    assert_eq!(node.snapshot(), before);
    node.store
        .repair_resource(policy().resource, node.clock.now())
        .await
        .unwrap();
    assert!(!quarantined(&node));
    assert_spent(&node, 99);
    settle(&mut node, 2, Usage::Observed(Charge([1, 0, 2, 0, 0]))).await;
    assert!(!quarantined(&node));
    assert_spent(&node, 101);
}

#[tokio::test]
async fn accepted_policy_history_survives_current_policy_changes() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = fixture(directory.path(), Profile::Responses).await;
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    let original = node
        .store
        .state()
        .policy_for(&request.authorization)
        .unwrap()
        .clone();
    node.accept(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    let mut terms = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
    terms.revision.0 += 1;
    terms.max_job_millis = std::num::NonZeroU64::new(9000).unwrap();
    node.store.define(terms, node.clock.now()).await.unwrap();
    assert_eq!(
        node.store
            .state()
            .policy_for(&request.authorization)
            .unwrap(),
        &original
    );
    node.dispatch(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    let mut changed = original.clone();
    changed.revision.0 += 1;
    changed.name = "renamed".into();
    node.store
        .configure_resource(changed, node.clock.now())
        .await
        .unwrap();
    assert_err!(
        node.store.state().check_resource(&request.authorization),
        NodeStoreError::Grant(GrantError::OutOfScope)
    );
    assert_eq!(
        node.store
            .state()
            .ledger()
            .active_count(BudgetNode::Machine),
        1
    );
    assert_eq!(
        node.store
            .state()
            .policy_for(&request.authorization)
            .unwrap(),
        &original
    );
    node.finish(&request, Usage::Observed(Charge([1, 0, 2, 0, 0])))
        .await;
    assert_eq!(node.used(BudgetNode::Machine, Meter::Requests), 1);
    node.store.rotate().await.unwrap();
    let node = node.reopen().await;
    assert_eq!(
        node.store
            .state()
            .policy_for(&request.authorization)
            .unwrap(),
        &original
    );
}
