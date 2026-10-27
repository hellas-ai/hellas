use super::*;
use crate::model::grant::pricing::{Pricing, UnitPrice};
use std::num::NonZeroU64;
use {crate::test_support::ids, hellas_channel::test_support::actors::FRIEND};

fn rate(meter: Meter, usd_micros: u64, units: u64) -> UnitPrice {
    UnitPrice {
        meter,
        usd_micros,
        units: NonZeroU64::new(units).unwrap(),
    }
}
pub(super) fn rates() -> Vec<UnitPrice> {
    vec![rate(Meter::Requests, 2, 1), rate(Meter::OutputTokens, 3, 4)]
}
pub(super) async fn prices(
    store: &mut NodeStore,
    rates: Vec<UnitPrice>,
    grants: &[GrantId],
) -> GrantPolicy {
    let mut configured = store.state().resource(policy().resource).unwrap().clone();
    configured.revision.0 += 1;
    configured.pricing.revision.0 += 1;
    configured.pricing.rates = Some(rates);
    store
        .configure_resource(configured.clone(), UnixMillis(1000))
        .await
        .unwrap();
    for id in grants {
        let mut grant = store.state().grant(*id).unwrap().clone();
        grant.revision.0 += 1;
        grant.policies = vec![configured.clone()];
        store.define(grant, UnixMillis(1000)).await.unwrap();
    }
    configured
}
async fn limit(store: &mut NodeStore, amount: u64) -> Result<(), NodeStoreError> {
    let budget = store.state().grant(ids::ALLOWANCE).unwrap().budget;
    let mut definition = store.state().ledger().definition(budget).unwrap();
    definition.revision.0 += 1;
    definition.limits = vec![Limit {
        meter: Meter::UsdMicros,
        window: Window::Total,
        amount,
    }];
    store.configure_budget(definition, UnixMillis(1000)).await
}
fn counters(node: &TestNode, expected_used: u64, reserved: u64) {
    let budget = node.store.state().grant(ids::ALLOWANCE).unwrap().budget;
    for ancestor in node.store.state().ledger().path(budget).unwrap() {
        assert_eq!(
            node.used(ancestor, Meter::UsdMicros),
            expected_used,
            "{ancestor:?}"
        );
        assert_eq!(
            node.store
                .state()
                .ledger()
                .reserved(ancestor, Meter::UsdMicros),
            reserved,
            "{ancestor:?}"
        );
    }
}
async fn priced_node(path: &std::path::Path, rates: Vec<UnitPrice>) -> TestNode {
    let mut node = work_node(path).build().await;
    prices(&mut node.store, rates, &[ids::ALLOWANCE]).await;
    node
}
async fn accept_request(node: &mut TestNode, nonce: u64) -> Proposal {
    let request = node.proposal(FRIEND, ids::ALLOWANCE, nonce);
    node.accept(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    request
}
async fn running_request(node: &mut TestNode, nonce: u64) -> Proposal {
    let request = accept_request(node, nonce).await;
    node.dispatch(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    request
}

#[tokio::test]
async fn an_unpriced_resource_cannot_supply_a_money_budget() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let before = node.snapshot();
    assert_err!(
        limit(&mut node.store, 100).await,
        NodeStoreError::Grant(GrantError::Limits)
    );
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn prices_require_a_bounded_source_meter() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    for meter in [Meter::InputTokens, Meter::DeviceMillis, Meter::UsdMicros] {
        let mut changed = policy();
        changed.revision.0 += 1;
        changed.pricing = Pricing {
            revision: Revision(2),
            rates: Some(vec![rate(meter, 1, 1)]),
        };
        let before = node.snapshot();
        assert_err!(
            node.store
                .configure_resource(changed, node.clock.now())
                .await,
            NodeStoreError::Grant(GrantError::Limits)
        );
        assert_eq!(node.snapshot(), before);
    }
}

#[tokio::test]
async fn an_explicitly_free_resource_supports_a_zero_money_budget() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(directory.path(), vec![]).await;
    limit(&mut node.store, 0).await.unwrap();
    assert!(
        node.store
            .state()
            .resource(policy().resource)
            .unwrap()
            .supports(Meter::UsdMicros)
    );
}

#[tokio::test]
async fn settlement_uses_the_signed_price() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(directory.path(), vec![rate(Meter::OutputTokens, 2, 1)]).await;
    let request = running_request(&mut node, 1).await;
    let original = node
        .store
        .state()
        .policy_for(&request.authorization)
        .unwrap()
        .clone();
    prices(
        &mut node.store,
        vec![rate(Meter::OutputTokens, 10, 1)],
        &[ids::ALLOWANCE],
    )
    .await;

    // The backend's money field is untrusted; verified token usage is rated locally.
    node.finish(&request, Usage::Observed(Charge([1, 0, 2, 0, 999])))
        .await;

    counters(&node, 4, 0);
    node.store.rotate().await.unwrap();
    let node = node.reopen().await;
    counters(&node, 4, 0);
    assert_eq!(
        node.store
            .state()
            .policy_for(&request.authorization)
            .unwrap(),
        &original
    );
}

#[tokio::test]
async fn recovery_uses_the_newly_signed_money_bound() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(directory.path(), vec![rate(Meter::OutputTokens, 2, 1)]).await;
    let next = prices(
        &mut node.store,
        vec![rate(Meter::OutputTokens, 10, 1)],
        &[ids::ALLOWANCE],
    )
    .await;
    let request = running_request(&mut node, 1).await;
    assert_eq!(
        request.authorization.pricing_revision,
        next.pricing.revision
    );
    counters(&node, 0, 80);

    node.store.rotate().await.unwrap();
    let node = node.reopen().await;

    counters(&node, 80, 0);
}

async fn priced_checkpoint(path: &std::path::Path) -> serde_json::Value {
    let mut node = priced_node(path, rates()).await;
    let request = running_request(&mut node, 1).await;
    prices(
        &mut node.store,
        vec![rate(Meter::OutputTokens, 10, 1)],
        &[ids::ALLOWANCE],
    )
    .await;
    node.finish(&request, Usage::Observed(Charge([1, 0, 2, 0, 0])))
        .await;
    serde_json::to_value(node.store.state().snapshot().unwrap()).unwrap()
}

#[tokio::test]
async fn checkpoints_require_a_positive_price_revision_in_every_policy_copy() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = priced_checkpoint(directory.path()).await;
    for copy in PolicyCopy::ALL {
        let mut corrupt = checkpoint.clone();
        copy.get_mut(&mut corrupt)["pricing"]["revision"] = 0.into();
        assert_err!(
            super::super::State::restore(serde_json::from_value(corrupt).unwrap()),
            NodeStoreError::Grant(GrantError::Limits)
        );
    }
}

#[tokio::test]
async fn checkpoints_bind_the_frozen_money_bound_to_signed_terms() {
    let directory = tempfile::tempdir().unwrap();
    let mut corrupt = priced_checkpoint(directory.path()).await;
    corrupt["admissions"][0][1]["reserved"][4] = 0.into();
    assert_err!(
        super::super::State::restore(serde_json::from_value(corrupt).unwrap()),
        NodeStoreError::Malformed
    );
}

#[tokio::test]
async fn price_changes_require_the_next_revision() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(directory.path(), rates()).await;
    let configured = node
        .store
        .state()
        .resource(policy().resource)
        .unwrap()
        .clone();
    for (revision, rates) in [
        (2, None),
        (1, Some(vec![])),
        (4, Some(vec![])),
        (2, Some(vec![])),
    ] {
        let mut altered = configured.clone();
        altered.revision.0 += 1;
        altered.pricing = Pricing {
            revision: Revision(revision),
            rates,
        };
        let before = node.snapshot();
        assert_err!(node.store.configure_resource(altered, node.clock.now()).await,
            NodeStoreError::Grant(GrantError::Revision(old)) if old == configured.pricing.revision);
        assert_eq!(node.snapshot(), before);
    }
}

#[tokio::test]
async fn a_money_bound_overflow_refuses_admission() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(
        directory.path(),
        vec![rate(Meter::OutputTokens, u64::MAX, 1)],
    )
    .await;
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    let before = node.snapshot();
    assert_err!(
        node.accept(FRIEND, ids::FRIEND_GRANT, &request).await,
        NodeStoreError::Grant(GrantError::Limits)
    );
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn a_verified_money_overflow_saturates_spending() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = priced_node(
        directory.path(),
        vec![rate(Meter::OutputTokens, u64::MAX, 8)],
    )
    .await;
    limit(&mut node.store, u64::MAX).await.unwrap();
    let request = running_request(&mut node, 1).await;
    counters(&node, 0, u64::MAX);

    node.finish(&request, Usage::Observed(Charge([1, 0, 9, 0, 0])))
        .await;

    counters(&node, u64::MAX, 0);
    assert!(
        node.store
            .state()
            .resource_health(policy().resource)
            .unwrap()
            .quarantined
    );
    node.store.rotate().await.unwrap();
    let node = node.reopen().await;
    counters(&node, u64::MAX, 0);
    assert!(
        node.store
            .state()
            .resource_health(policy().resource)
            .unwrap()
            .quarantined
    );
}
