use super::*;
use crate::model::grant::configuration::{ConfiguredBudget, NodeConfiguration};

fn budget(max_in_flight: u16, limits: Vec<Limit>) -> ConfiguredBudget {
    ConfiguredBudget {
        max_in_flight: std::num::NonZeroU16::new(max_in_flight).unwrap(),
        limits,
    }
}

fn configuration(machine: ConfiguredBudget, account: ConfiguredBudget) -> NodeConfiguration {
    let policy = policy();
    NodeConfiguration::new(
        Some(machine),
        [(policy.account, account)].into(),
        vec![policy],
    )
    .unwrap()
}

async fn store(path: &std::path::Path) -> NodeStore {
    let provider = hellas_channel::test_support::software_enrollment(2, [2; 32]);
    common_node::bootstrap_node(path, network(), Some(provider), UnixMillis(1000))
        .await
        .unwrap()
}

#[tokio::test]
async fn the_configuration_builds_the_tree_once_and_replays() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    let requests = vec![Limit {
        meter: Meter::Requests,
        window: Window::Total,
        amount: 9,
    }];
    let configured = configuration(budget(3, requests.clone()), budget(2, vec![]));
    store
        .reconcile(&configured, UnixMillis(1001))
        .await
        .unwrap();
    let account = BudgetNode::Account(policy().account);
    let state = store.state().clone();
    assert_eq!(
        state
            .machine_capacity()
            .unwrap()
            .unwrap()
            .max_in_flight
            .get(),
        3
    );
    assert_eq!(state.machine_capacity().unwrap().unwrap().limits, requests);
    let definition = state.ledger.definition(account).unwrap();
    assert_eq!(
        (
            definition.parent,
            definition.revision,
            definition.max_in_flight.get()
        ),
        (BudgetNode::Machine, Revision(1), 2)
    );
    assert_eq!(state.resource(policy().resource), Some(&policy()));

    // An unchanged configuration commits nothing.
    store
        .reconcile(&configured, UnixMillis(1002))
        .await
        .unwrap();
    assert_eq!(store.state(), &state);

    // A changed account bumps only that node; the machine keeps its revision.
    let changed = configuration(budget(3, requests), budget(5, vec![]));
    store.reconcile(&changed, UnixMillis(1003)).await.unwrap();
    let definition = store.state().ledger.definition(account).unwrap();
    assert_eq!(
        (definition.revision, definition.max_in_flight.get()),
        (Revision(2), 5)
    );
    assert_eq!(
        store.state().machine_capacity().unwrap().unwrap().revision,
        state.machine_capacity().unwrap().unwrap().revision
    );

    // Configuration changes are ordinary journal frames: reopening replays them.
    let owned = |state: &super::super::state::State| {
        (
            state.machine_capacity().unwrap(),
            state.ledger.definition(account),
            state.resource(policy().resource).cloned(),
        )
    };
    let after = owned(store.state());
    drop(store);
    let reopened = NodeStore::open(directory.path(), network(), None, UnixMillis(1004))
        .await
        .unwrap();
    assert_eq!(owned(reopened.state()), after);
}

#[tokio::test]
async fn machine_concurrency_is_bounded_by_open_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    let max = u16::try_from(super::super::store::MAX_OPEN_JOBS).unwrap();
    assert_err!(
        store
            .reconcile(
                &configuration(budget(max + 1, vec![]), budget(1, vec![])),
                UnixMillis(1001)
            )
            .await,
        NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Invalid)
    );
    assert!(store.state().machine_capacity().unwrap().is_none());
    store
        .reconcile(
            &configuration(budget(max, vec![]), budget(1, vec![])),
            UnixMillis(1002),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .state()
            .machine_capacity()
            .unwrap()
            .unwrap()
            .max_in_flight
            .get(),
        max
    );
}
