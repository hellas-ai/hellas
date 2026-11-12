use super::*;
use crate::model::grant::configuration::{ConfiguredBudget, NodeConfiguration};
use hellas_private::StoreLocation;

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

impl NodeStore {
    async fn apply_configuration(
        &mut self,
        configuration: &NodeConfiguration,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        let expected = self
            .state()
            .configuration()
            .map_or(Revision(0), |c| c.revision);
        self.configure(
            expected,
            serde_json::to_string(configuration).unwrap(),
            configuration,
            now,
        )
        .await
    }
}

#[tokio::test]
async fn the_configuration_builds_the_tree_once_and_replays() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    let requests = vec![Limit::new(Meter::Requests, Window::Total, 9)];
    let configured = configuration(budget(3, requests.clone()), budget(2, vec![]));
    store
        .apply_configuration(&configured, UnixMillis(1001))
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
    let definition = ledger::definition(&state.ledger, account).unwrap();
    assert_eq!(
        (
            definition.parent,
            definition.revision,
            definition.max_in_flight.get()
        ),
        (Some(BudgetNode::Machine), Revision(1), 2)
    );
    assert_eq!(state.resource(policy().resource), Some(&policy()));

    // Reapplying a document advances its revision without revising its budgets.
    store
        .apply_configuration(&configured, UnixMillis(1002))
        .await
        .unwrap();
    assert_eq!(store.state().configuration().unwrap().revision, Revision(2));
    assert_eq!(
        store.state().machine_capacity().unwrap(),
        state.machine_capacity().unwrap()
    );
    assert_eq!(
        ledger::definition(&store.state().ledger, account),
        ledger::definition(&state.ledger, account)
    );

    // A changed account bumps only that node; the machine keeps its revision.
    let changed = configuration(budget(3, requests), budget(5, vec![]));
    store
        .apply_configuration(&changed, UnixMillis(1003))
        .await
        .unwrap();
    let definition = ledger::definition(&store.state().ledger, account).unwrap();
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
            ledger::definition(&state.ledger, account),
            state.resource(policy().resource).cloned(),
        )
    };
    let after = owned(store.state());
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    let reopened = NodeStore::open(&location, network(), None, UnixMillis(1004))
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
            .apply_configuration(
                &configuration(budget(max + 1, vec![]), budget(1, vec![])),
                UnixMillis(1001)
            )
            .await,
        NodeStoreError::Authority(hellas_auth::authority::AuthorityError::Invalid)
    );
    assert!(store.state().machine_capacity().unwrap().is_none());
    store
        .apply_configuration(
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

#[tokio::test]
async fn rejected_configuration_changes_nothing_in_memory_or_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    store
        .apply_configuration(
            &configuration(budget(3, vec![]), budget(2, vec![])),
            UnixMillis(1001),
        )
        .await
        .unwrap();
    let before = store.state().clone();
    let frames = store.journal_len();
    let mut invalid_resource = policy();
    invalid_resource.name = "renamed-without-revision".into();
    let candidate = NodeConfiguration::new(
        Some(budget(9, vec![])),
        [(invalid_resource.account, budget(5, vec![]))].into(),
        vec![invalid_resource],
    )
    .unwrap();
    assert!(
        store
            .configure(
                Revision(1),
                "new document".into(),
                &candidate,
                UnixMillis(1002)
            )
            .await
            .is_err()
    );
    assert_eq!(store.state(), &before);
    assert_eq!(store.journal_len(), frames);
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    let reopened = NodeStore::open(&location, network(), None, before.now())
        .await
        .unwrap();
    assert_eq!(reopened.state(), &before);
}

#[tokio::test]
async fn document_and_authority_share_one_commit_and_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    let configured = configuration(budget(3, vec![]), budget(2, vec![]));
    store
        .configure(Revision(0), "first".into(), &configured, UnixMillis(1001))
        .await
        .unwrap();
    let changed = configuration(budget(9, vec![]), budget(5, vec![]));
    let before = store.state().clone();
    assert!(
        store
            .configure(Revision(0), "stale".into(), &changed, UnixMillis(1002))
            .await
            .is_err()
    );
    assert_eq!(store.state(), &before);
    let frames = store.journal_len();
    store
        .configure(Revision(1), "second".into(), &changed, UnixMillis(1002))
        .await
        .unwrap();
    assert_eq!(store.journal_len(), frames + 1);
    let committed = store.state().clone();
    assert_eq!(committed.configuration().unwrap().document, "second");
    assert_eq!(committed.configuration().unwrap().revision, Revision(2));
    assert_eq!(
        committed
            .machine_capacity()
            .unwrap()
            .unwrap()
            .max_in_flight
            .get(),
        9
    );
    let location = StoreLocation::for_test(directory.path());
    drop(store);
    let mut reopened = NodeStore::open(&location, network(), None, committed.now())
        .await
        .unwrap();
    assert_eq!(reopened.state(), &committed);
    reopened.rotate().await.unwrap();
    drop(reopened);
    let reopened = NodeStore::open(&location, network(), None, committed.now())
        .await
        .unwrap();
    assert_eq!(reopened.state(), &committed);
}

#[tokio::test]
async fn interrupted_configuration_reopens_as_one_complete_version() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = store(directory.path()).await;
    let initial = configuration(budget(3, vec![]), budget(2, vec![]));
    store
        .configure(Revision(0), "old".into(), &initial, UnixMillis(1000))
        .await
        .unwrap();
    let before = store.state().clone();
    let mut resource = policy();
    resource.revision.0 += 1;
    resource.name = "new".into();
    let candidate = NodeConfiguration::new(
        Some(budget(9, vec![])),
        [(resource.account, budget(5, vec![]))].into(),
        vec![resource.clone()],
    )
    .unwrap();
    let (started, release) = store.pause_next_statement().await;
    {
        let mut configuring = std::pin::pin!(store.configure(
            Revision(1),
            "new".into(),
            &candidate,
            UnixMillis(1000)
        ));
        tokio::select! {
            entered = started => entered.unwrap(),
            result = &mut configuring => panic!("append completed before interruption: {result:?}"),
        }
    }
    assert_eq!(store.state(), &before);
    drop(release);
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    let reopened = NodeStore::open(&location, network(), None, UnixMillis(1000))
        .await
        .unwrap();
    let state = reopened.state();
    match state.configuration().unwrap().revision {
        Revision(1) => assert_eq!(state, &before),
        Revision(2) => {
            assert_eq!(state.configuration().unwrap().document, "new");
            assert_eq!(
                state
                    .machine_capacity()
                    .unwrap()
                    .unwrap()
                    .max_in_flight
                    .get(),
                9
            );
            assert_eq!(
                ledger::definition(&state.ledger, BudgetNode::Account(resource.account))
                    .unwrap()
                    .max_in_flight
                    .get(),
                5
            );
            assert_eq!(state.resource(resource.resource), Some(&resource));
        }
        other => panic!("unexpected revision {other:?}"),
    }
}
