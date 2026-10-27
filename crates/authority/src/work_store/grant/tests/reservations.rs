use super::*;
use hellas_auth::{Signature, authority::AuthenticatedCaller};
use std::num::NonZeroU16;
use {
    crate::test_support::ids, hellas_channel::test_support::actors::FRIEND,
    hellas_channel::test_support::actors::PROVIDER, hellas_channel::test_support::actors::ROOT,
};

fn shared_budget() -> BudgetNode {
    BudgetNode::Subject {
        pool: common_node::POOL,
        subject: FRIEND.principal(),
    }
}
fn requests(amount: u64) -> Vec<Limit> {
    vec![Limit {
        meter: Meter::Requests,
        window: Window::Total,
        amount,
    }]
}
struct Household {
    node: TestNode,
    desktop: AuthenticatedCaller,
    laptop: AuthenticatedCaller,
}
impl Household {
    async fn new(path: &std::path::Path) -> Self {
        let rights = [ids::ALLOWANCE, ids::LAPTOP_ALLOWANCE]
            .into_iter()
            .fold(
                Rights::new(authority(), FRIEND).valid_until(UnixMillis(u64::MAX)),
                |scope, id| {
                    scope.allow(
                        crate::grant_service::WORK_EXECUTE,
                        crate::grant_service::allowance_resource(authority(), id),
                    )
                },
            )
            .build();
        let mut node = Node::bootstrap(path)
            .with_capacity(Capacity::new(4).with_limits(requests(4)))
            .with_grant(ids::FRIEND_GRANT, rights.clone())
            .with_allowance(
                Allowance::responses(ids::ALLOWANCE, FRIEND)
                    .with_limits(requests(2))
                    .with_concurrency(2),
            )
            .with_allowance(
                Allowance::responses(ids::LAPTOP_ALLOWANCE, FRIEND)
                    .with_limits(requests(2))
                    .with_concurrency(2),
            )
            .build()
            .await;
        let root = node.caller(ROOT);
        let now = node.clock.now();
        let [credential] = credentials::issue(
            credentials::Issuer::Store(&mut node.store, now),
            &root,
            ids::ROOT_GRANT,
            None,
            rights,
        )
        .await;
        let laptop = signed_caller(
            node.store.state().authority(),
            &credential,
            &FRIEND.node_key(),
            now,
        );
        let desktop = node.caller(FRIEND);
        Self {
            node,
            desktop,
            laptop,
        }
    }
    fn proposals(&self) -> [Proposal; 2] {
        [ids::ALLOWANCE, ids::LAPTOP_ALLOWANCE].map(|id| self.node.proposal(FRIEND, id, 1))
    }
}
async fn submit(
    node: &mut TestNode,
    caller: &AuthenticatedCaller,
    request: &Proposal,
) -> Result<Signature, NodeStoreError> {
    node.store
        .accept(
            (caller, ids::FRIEND_GRANT),
            request.authorization,
            request.signature,
            &request.input,
            &PROVIDER.node_key(),
            node.clock.now(),
        )
        .await
}
async fn run(node: &mut TestNode, caller: &AuthenticatedCaller, request: &Proposal) {
    node.store
        .dispatch(
            (caller, ids::FRIEND_GRANT),
            request.authorization.channel_id,
            request.work(),
            node.clock.now(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn distinct_application_credentials_share_one_subject_budget() {
    let directory = tempfile::tempdir().unwrap();
    let mut house = Household::new(directory.path()).await;
    let [desktop, laptop] = house.proposals();
    submit(&mut house.node, &house.desktop, &desktop)
        .await
        .unwrap();
    submit(&mut house.node, &house.laptop, &laptop)
        .await
        .unwrap();
    let records = [&desktop, &laptop].map(|r| {
        house
            .node
            .store
            .state()
            .admission(r.authorization.channel_id, r.work())
            .unwrap()
    });
    assert_ne!(
        records[0].accepted().caller().credential(),
        records[1].accepted().caller().credential()
    );
    assert_eq!(
        house
            .node
            .store
            .state()
            .ledger()
            .reserved(shared_budget(), Meter::Requests),
        2
    );
    let extra = house.node.proposal(FRIEND, ids::LAPTOP_ALLOWANCE, 2);
    let before = house.node.snapshot();
    assert_err!(submit(&mut house.node, &house.laptop, &extra).await,
        NodeStoreError::Ledger(LedgerError::Concurrent(node)) if node == shared_budget());
    assert_eq!(house.node.snapshot(), before);
}

#[tokio::test]
async fn recovery_retains_duties_above_a_narrowed_concurrency_limit() {
    let directory = tempfile::tempdir().unwrap();
    let mut house = Household::new(directory.path()).await;
    let [desktop, laptop] = house.proposals();
    submit(&mut house.node, &house.desktop, &desktop)
        .await
        .unwrap();
    submit(&mut house.node, &house.laptop, &laptop)
        .await
        .unwrap();
    let mut budget = house
        .node
        .store
        .state()
        .ledger()
        .definition(shared_budget())
        .unwrap();
    budget.revision.0 += 1;
    budget.max_in_flight = NonZeroU16::new(1).unwrap();
    budget.limits = requests(1);
    house
        .node
        .store
        .configure_budget(budget, house.node.clock.now())
        .await
        .unwrap();
    run(&mut house.node, &house.desktop, &desktop).await;
    run(&mut house.node, &house.laptop, &laptop).await;
    house.node.store.rotate().await.unwrap();
    house.node.clock.set(UnixMillis(1001));
    house.node = house.node.reopen().await;
    for node in house
        .node
        .store
        .state()
        .ledger()
        .path(shared_budget())
        .unwrap()
    {
        assert_eq!(house.node.used(node, Meter::Requests), 2);
        assert_eq!(
            house
                .node
                .store
                .state()
                .ledger()
                .reserved(node, Meter::Requests),
            0
        );
        assert_eq!(
            house
                .node
                .store
                .state()
                .recovery_holds(node, house.node.clock.now())
                .unwrap(),
            2
        );
    }
    let extra = house.node.proposal(FRIEND, ids::LAPTOP_ALLOWANCE, 2);
    assert_err!(submit(&mut house.node, &house.laptop, &extra).await,
        NodeStoreError::Ledger(LedgerError::Concurrent(node)) if node == shared_budget());
}

#[tokio::test]
async fn creating_an_allowance_cannot_hide_spending_by_the_same_subject() {
    let directory = tempfile::tempdir().unwrap();
    let mut house = Household::new(directory.path()).await;
    let [desktop, laptop] = house.proposals();
    for (caller, request) in [(&house.desktop, &desktop), (&house.laptop, &laptop)] {
        submit(&mut house.node, caller, request).await.unwrap();
        run(&mut house.node, caller, request).await;
        house
            .node
            .finish(request, Usage::Observed(Charge([1, 0, 2, 0, 0])))
            .await;
    }
    house
        .node
        .store
        .define(
            definition(ids::NEW_ALLOWANCE, FRIEND.principal()),
            house.node.clock.now(),
        )
        .await
        .unwrap();
    let mut scope = house
        .node
        .store
        .state()
        .authority()
        .grant(ids::FRIEND_GRANT)
        .unwrap()
        .spec()
        .clone();
    scope
        .permissions
        .insert(hellas_auth::authority::Permission {
            operation: hellas_auth::authority::OperationId::new(crate::grant_service::WORK_EXECUTE)
                .unwrap(),
            resource: crate::grant_service::allowance_resource(authority(), ids::NEW_ALLOWANCE),
        });
    let root = house.node.caller(ROOT);
    let now = house.node.clock.now();
    let expected = house
        .node
        .store
        .state()
        .authority()
        .grant(ids::FRIEND_GRANT)
        .unwrap()
        .revision();
    house
        .node
        .store
        .administer_authority(
            &root,
            hellas_auth::authority::AdministrationCommand::Grant(
                hellas_auth::authority::GrantCommand::Revise {
                    authorization: ids::ROOT_GRANT,
                    id: ids::FRIEND_GRANT,
                    expected,
                    spec: scope.clone(),
                },
            ),
            now,
        )
        .await
        .unwrap();
    let [credential] = credentials::issue(
        credentials::Issuer::Store(&mut house.node.store, now),
        &root,
        ids::ROOT_GRANT,
        None,
        scope,
    )
    .await;
    house.desktop = signed_caller(
        house.node.store.state().authority(),
        &credential,
        &FRIEND.node_key(),
        now,
    );
    let request = house.node.proposal(FRIEND, ids::NEW_ALLOWANCE, 1);
    let before = house.node.snapshot();
    assert_err!(submit(&mut house.node, &house.desktop, &request).await,
        NodeStoreError::Ledger(LedgerError::OverBudget { node, meter: Meter::Requests, window: Window::Total }) if node == shared_budget());
    assert_eq!(house.node.snapshot(), before);
    let mut budget = house
        .node
        .store
        .state()
        .ledger()
        .definition(shared_budget())
        .unwrap();
    budget.revision.0 += 1;
    budget.limits = requests(3);
    house
        .node
        .store
        .configure_budget(budget, house.node.clock.now())
        .await
        .unwrap();
    submit(&mut house.node, &house.desktop, &request)
        .await
        .unwrap();
    assert_eq!(house.node.used(shared_budget(), Meter::Requests), 2);
    assert_eq!(
        house
            .node
            .store
            .state()
            .ledger()
            .reserved(shared_budget(), Meter::Requests),
        1
    );
}
