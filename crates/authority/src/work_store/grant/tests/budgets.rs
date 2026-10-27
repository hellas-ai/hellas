use super::*;
use hellas_auth::authority as auth;
use std::num::NonZeroU16;

fn requests(amount: u64) -> Vec<Limit> {
    vec![Limit {
        meter: Meter::Requests,
        window: Window::Total,
        amount,
    }]
}

#[test]
fn clock_headroom_bounds_checkpoint_growth() {
    use hellas_rpc::protocol::value::canonical_dag_cbor;
    let mut ledger = configured_ledger(vec![], 8);
    for pool in [PoolId([2; 16]), PoolId([3; 16])] {
        for definition in common_node::budgets(pool, principal(1).0, vec![], 8) {
            if ledger.node(definition.node).is_none() {
                ledger.configure_budget(definition).unwrap();
            }
        }
    }
    let maximum = canonical_dag_cbor(&ledger).unwrap().len() + ledger.clock_headroom();
    for time in [1000, 86_400_000, u64::MAX] {
        ledger.advance(UnixMillis(time));
        assert_eq!(
            canonical_dag_cbor(&ledger).unwrap().len() + ledger.clock_headroom(),
            maximum
        );
    }
    assert_eq!(ledger.clock_headroom(), 0);
    let last = ledger.clone();
    ledger.advance(UnixMillis(0));
    assert_eq!(ledger, last);
}

#[tokio::test]
async fn checkpoint_budget_limits_cover_all_retained_policies() {
    for running_paused in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let (mut store, application) = setup(directory.path()).await;
        if running_paused {
            let (a, signature, input) = proposal(&store, 1);
            accept(&mut store, &application, (a, signature, &input), 1000)
                .await
                .unwrap();
            dispatch(
                &mut store,
                &application,
                (a.channel_id, grant_work_id(network(), &a)),
                1000,
            )
            .await
            .unwrap();
            let mut grant = store.state().grant(a.grant_id).unwrap().clone();
            grant.revision.0 += 1;
            grant.enabled = false;
            store.define(grant, UnixMillis(1000)).await.unwrap();
        }
        let mut checkpoint = serde_json::to_value(store.state().snapshot().unwrap()).unwrap();
        let ledger = &mut checkpoint["ledger"];
        let pool = serde_json::to_value(BudgetNode::Pool(common_node::POOL)).unwrap();
        let node = ledger["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|n| n[0] == pool)
            .unwrap();
        node[1]["limits"] = serde_json::to_value(vec![Limit {
            meter: Meter::DeviceMillis,
            window: Window::Total,
            amount: 1000,
        }])
        .unwrap();
        let result = super::super::State::restore(serde_json::from_value(checkpoint).unwrap());
        if running_paused {
            assert_err!(result, NodeStoreError::Grant(GrantError::Limits));
        } else {
            assert_err!(result, NodeStoreError::Ledger(LedgerError::InvalidLimits));
        }
    }
}

pub(super) async fn applications(
    store: &mut NodeStore,
    secret: &auth::CredentialSecret,
) -> [auth::AuthenticatedCaller; 2] {
    let now = UnixMillis(1000);
    let administrator = crate::test_support::passkey_caller(store.state().authority(), secret, now);
    let mut scope = store
        .state()
        .authority()
        .grant(GrantId([0; 16]))
        .unwrap()
        .spec()
        .clone();
    scope.subject = principal(1).0;
    scope.issuance = None;
    scope.permissions = [1, 2, 3]
        .into_iter()
        .map(|n| auth::Permission {
            operation: auth::OperationId::new(crate::grant_service::WORK_EXECUTE).unwrap(),
            resource: crate::grant_service::allowance_resource(scope.authority, GrantId([n; 16])),
        })
        .collect();
    credentials::issue::<2>(
        credentials::Issuer::Store(store, now),
        &administrator,
        GrantId([0; 16]),
        Some(JOURNAL_AUTHORIZATION),
        scope,
    )
    .await
    .map(|secret| signed_caller(store.state().authority(), &secret, &principal(1).1, now))
}

#[test]
fn every_ancestor_cap_is_atomic() {
    for limited in 0..5 {
        let mut ledger = Ledger::default();
        ledger.configure_machine(vec![], 8).unwrap();
        for definition in common_node::budgets(common_node::POOL, principal(1).0, vec![], 8) {
            ledger.configure_budget(definition).unwrap();
        }
        let child = BudgetNode::Subject {
            pool: common_node::POOL,
            subject: principal(3).0,
        };
        ledger
            .configure_budget(BudgetDef {
                node: child,
                parent: budget(),
                revision: Revision(1),
                limits: vec![],
                max_in_flight: NonZeroU16::new(8).unwrap(),
            })
            .unwrap();
        let path = ledger.path(child).unwrap();
        let target = path[limited];
        if target == BudgetNode::Machine {
            ledger.configure_machine(requests(1), 8).unwrap();
        } else {
            let mut definition = ledger.definition(target).unwrap();
            definition.revision.0 += 1;
            definition.limits = requests(1);
            ledger.configure_budget(definition).unwrap();
        }
        let reservation = ledger
            .reserve(
                Digest::hash(b"first"),
                child,
                Charge([1, 0, 0, 0, 0]),
                UnixMillis(1000),
            )
            .unwrap();
        let before = ledger.clone();
        assert_err!(ledger.reserve(Digest::hash(b"second"), child, Charge([1,0,0,0, 0]), UnixMillis(1000)), LedgerError::OverBudget { node, .. } if node == target);
        assert_eq!(
            ledger, before,
            "a refusal cannot debit a partial ancestor path"
        );
        ledger
            .settle(reservation, Usage::Unknown, UnixMillis(1000))
            .unwrap();
        for node in path {
            assert_eq!(
                ledger
                    .node(node)
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            assert_eq!(ledger.reserved(node, Meter::Requests), 0);
        }
    }
}

struct DeepBudget {
    ledger: Ledger,
    leaf: BudgetNode,
}
impl DeepBudget {
    fn new() -> Self {
        use crate::test_support::actors::*;
        let mut ledger = Ledger::default();
        ledger.configure_machine(vec![], 256).unwrap();
        for definition in common_node::budgets(common_node::POOL, ROOT.principal(), vec![], 256) {
            ledger.configure_budget(definition).unwrap();
        }
        let mut leaf = BudgetNode::Subject {
            pool: common_node::POOL,
            subject: ROOT.principal(),
        };
        for actor in [
            OPERATOR,
            FRIEND,
            AGENT,
            PROVIDER,
            STRANGER,
            RECOVERY_OWNER,
            SUCCESSOR,
        ] {
            let child = BudgetNode::Subject {
                pool: common_node::POOL,
                subject: actor.principal(),
            };
            ledger
                .configure_budget(BudgetDef {
                    node: child,
                    parent: leaf,
                    revision: Revision(1),
                    limits: vec![],
                    max_in_flight: NonZeroU16::new(256).unwrap(),
                })
                .unwrap();
            leaf = child;
        }
        Self { ledger, leaf }
    }
}

#[test]
fn a_ninth_subject_exceeds_the_budget_ancestry_limit() {
    let mut tree = DeepBudget::new();
    assert_eq!(
        tree.ledger.path(tree.leaf).unwrap().len(),
        MAX_BUDGET_PATH_LEN
    );
    let before = tree.ledger.clone();
    assert_err!(
        tree.ledger.configure_budget(BudgetDef {
            node: BudgetNode::Subject {
                pool: common_node::POOL,
                subject: crate::test_support::actors::ATTACKER.principal()
            },
            parent: tree.leaf,
            revision: Revision(1),
            limits: vec![],
            max_in_flight: NonZeroU16::new(256).unwrap(),
        }),
        LedgerError::InvalidPath
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_budget_revision_must_follow_the_current_revision() {
    let mut tree = DeepBudget::new();
    let before = tree.ledger.clone();
    assert_err!(
        tree.ledger
            .configure_budget(tree.ledger.definition(tree.leaf).unwrap()),
        LedgerError::Revision
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_budget_parent_cannot_change_on_revision() {
    let mut tree = DeepBudget::new();
    let before = tree.ledger.clone();
    let mut definition = tree.ledger.definition(tree.leaf).unwrap();
    definition.revision.0 += 1;
    definition.parent = BudgetNode::Pool(common_node::POOL);
    assert_err!(
        tree.ledger.configure_budget(definition),
        LedgerError::Revision
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_restored_reservation_must_cover_its_complete_ancestry() {
    let mut tree = DeepBudget::new();
    let work = Digest::hash(b"maximum ancestry");
    let _held = tree
        .ledger
        .reserve(work, tree.leaf, Charge([1, 0, 0, 0, 0]), UnixMillis(1000))
        .unwrap();
    tree.ledger
        .validate_reservations([(work, tree.leaf)].into_iter())
        .unwrap();
    let mut encoded = serde_json::to_value(&tree.ledger).unwrap();
    encoded["held"][0][1]["path"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    let corrupt: Ledger = serde_json::from_value(encoded).unwrap();
    assert_err!(
        corrupt.validate_reservations([(work, tree.leaf)].into_iter()),
        LedgerError::InvalidPath
    );
}

#[test]
fn only_subjects_may_reserve_budget() {
    let mut ledger = Ledger::default();
    assert_err!(
        ledger.reserve(
            Digest::hash(b"unsupported ancestry"),
            BudgetNode::Machine,
            Charge([1, 0, 0, 0, 0]),
            UnixMillis(1000)
        ),
        LedgerError::InvalidPath
    );
    assert_eq!(ledger, Ledger::default());
}

#[test]
fn active_reserves_cross_windows_and_clock_rollback_cannot_reset_them() {
    let limits = vec![Limit {
        meter: Meter::OutputTokens,
        window: Window::Day,
        amount: 10,
    }];
    let mut ledger = configured_ledger(limits, 4);
    let held = ledger
        .reserve(
            Digest::hash(b"one"),
            budget(),
            Charge([1, 0, 8, 0, 0]),
            UnixMillis(86_399_999),
        )
        .unwrap();
    ledger.advance(UnixMillis(86_400_000));
    assert_err!(
        ledger.reserve(
            Digest::hash(b"two"),
            budget(),
            Charge([1, 0, 3, 0, 0]),
            UnixMillis(0)
        ),
        LedgerError::OverBudget { .. }
    );
    ledger.settle(held, Usage::Unknown, UnixMillis(0)).unwrap();
    let counter = ledger
        .node(budget())
        .unwrap()
        .counter(Meter::OutputTokens, Window::Day);
    assert_eq!((counter.window_id, counter.used), (1, 8));
    let mut changed = ledger.definition(budget()).unwrap();
    changed.revision.0 += 1;
    changed.limits[0].amount = 20;
    ledger.configure_budget(changed).unwrap();
    assert_eq!(
        ledger
            .node(budget())
            .unwrap()
            .counter(Meter::OutputTokens, Window::Day)
            .used,
        8
    );
}

proptest! {
    /// Stated from outside the ledger: used plus reserved never exceeds a cap.
    #[test]
    fn interleaved_siblings_never_exceed_machine_or_parent(
        actions in prop::collection::vec((0u8..5, 1u64..12), 1..100)
    ) {
        let cap = 50;
        let mut ledger = configured_ledger(
            vec![Limit { meter: Meter::OutputTokens, window: Window::Day, amount: cap }],
            8,
        );
        let sibling = BudgetNode::Subject { pool: common_node::POOL, subject: principal(3).0 };
        let nodes = [BudgetNode::Machine, budget(), sibling];
        let (mut held, mut nonce, mut time) = (vec![], 0u64, 0u64);
        for (action, tokens) in actions {
            match action {
                0 | 1 => {
                    nonce += 1;
                    let leaf = nodes[usize::from(action) + 1];
                    let bound = Charge([1, 0, tokens, 0, 0]);
                    if let Ok(r) = ledger.reserve(Digest::hash(&nonce.to_be_bytes()), leaf, bound, UnixMillis(time)) {
                        held.push(r);
                    }
                }
                2 => if let Some(r) = held.pop() {
                    ledger.settle(r, Usage::Unknown, UnixMillis(time)).unwrap();
                },
                3 => if let Some(r) = held.pop() {
                    ledger.release(r).unwrap();
                },
                _ => {
                    time += 86_400_000;
                    ledger.advance(UnixMillis(time));
                }
            }
            for node in nodes {
                let used = ledger.node(node).unwrap().counter(Meter::OutputTokens, Window::Day).used;
                prop_assert!(used + ledger.reserved(node, Meter::OutputTokens) <= cap);
            }
        }
    }
}
