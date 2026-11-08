use super::*;
use hellas_auth::authority as auth;
use std::num::NonZeroU16;

fn requests(amount: u64) -> Vec<Limit> {
    vec![Limit::new(Meter::Requests, Window::Total, amount)]
}

#[test]
fn clock_headroom_bounds_checkpoint_growth() {
    use hellas_rpc::protocol::value::canonical_dag_cbor;
    let mut ledger = configured_ledger(vec![], 8);
    for pool in [PoolId([2; 16]), PoolId([3; 16])] {
        for definition in common_node::budgets(pool, principal(1).0, vec![], 8) {
            if ledger.node(definition.node.key()).is_none() {
                ledger::configure(&mut ledger, definition).unwrap();
            }
        }
    }
    let maximum = canonical_dag_cbor(&ledger).unwrap().len() + ledger::clock_headroom(&ledger);
    for time in [1000, 86_400_000, u64::MAX] {
        ledger.advance(time);
        assert_eq!(
            canonical_dag_cbor(&ledger).unwrap().len() + ledger::clock_headroom(&ledger),
            maximum
        );
    }
    assert_eq!(ledger::clock_headroom(&ledger), 0);
    let last = ledger.clone();
    ledger.advance(0);
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
        let pool = serde_json::to_value(BudgetNode::Pool(common_node::POOL).key()).unwrap();
        let node = ledger["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|n| n[0] == pool)
            .unwrap();
        node[1]["spec"]["limits"].as_array_mut().unwrap().push(
            serde_json::to_value(Limit::new(Meter::DeviceMillis, Window::Total, 1000)).unwrap(),
        );
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
        let mut ledger = Book::default();
        configure_machine(&mut ledger, vec![], 8).unwrap();
        for definition in common_node::budgets(common_node::POOL, principal(1).0, vec![], 8) {
            ledger::configure(&mut ledger, definition).unwrap();
        }
        let child = BudgetNode::Subject {
            pool: common_node::POOL,
            subject: principal(3).0,
        };
        ledger::configure(
            &mut ledger,
            BudgetDef {
                node: child,
                parent: Some(budget()),
                revision: Revision(1),
                limits: vec![],
                max_in_flight: NonZeroU16::new(8).unwrap(),
            },
        )
        .unwrap();
        let path = ledger::path(&ledger, child).unwrap();
        let target = path[limited];
        let mut definition = ledger::definition(&ledger, target).unwrap();
        definition.revision.0 += 1;
        definition.limits = requests(1);
        ledger::configure(&mut ledger, definition).unwrap();
        let first = Digest::hash(b"first");
        ledger
            .admit(&ask(first, child, Charge([1, 0, 0, 0, 0])), 1000)
            .unwrap();
        let before = ledger.clone();
        assert_err!(ledger.admit(&ask(Digest::hash(b"second"), child, Charge([1,0,0,0, 0])), 1000), Refusal { at, .. } if at == target.key());
        assert_eq!(
            ledger, before,
            "a refusal cannot debit a partial ancestor path"
        );
        ledger.charge(HoldId(*first.as_bytes()), Usage::Unknown, 1000);
        for node in path {
            assert_eq!(
                ledger
                    .node(node.key())
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            assert_eq!(ledger.reserved(node.key(), Meter::Requests), 0);
        }
    }
}

struct DeepBudget {
    ledger: Book,
    leaf: BudgetNode,
}
impl DeepBudget {
    fn new() -> Self {
        use hellas_channel::test_support::actors::*;
        let mut ledger = Book::default();
        configure_machine(&mut ledger, vec![], 256).unwrap();
        for definition in common_node::budgets(common_node::POOL, ROOT.principal(), vec![], 256) {
            ledger::configure(&mut ledger, definition).unwrap();
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
            ledger::configure(
                &mut ledger,
                BudgetDef {
                    node: child,
                    parent: Some(leaf),
                    revision: Revision(1),
                    limits: vec![],
                    max_in_flight: NonZeroU16::new(256).unwrap(),
                },
            )
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
        ledger::path(&tree.ledger, tree.leaf).unwrap().len(),
        MAX_BUDGET_PATH_LEN
    );
    let before = tree.ledger.clone();
    assert_err!(
        ledger::configure(
            &mut tree.ledger,
            BudgetDef {
                node: BudgetNode::Subject {
                    pool: common_node::POOL,
                    subject: hellas_channel::test_support::actors::ATTACKER.principal()
                },
                parent: Some(tree.leaf),
                revision: Revision(1),
                limits: vec![],
                max_in_flight: NonZeroU16::new(256).unwrap(),
            }
        ),
        LedgerError::InvalidPath
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_budget_revision_must_follow_the_current_revision() {
    let mut tree = DeepBudget::new();
    let before = tree.ledger.clone();
    let current = ledger::definition(&tree.ledger, tree.leaf).unwrap();
    assert_err!(
        ledger::configure(&mut tree.ledger, current),
        LedgerError::Revision
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_budget_parent_cannot_change_on_revision() {
    let mut tree = DeepBudget::new();
    let before = tree.ledger.clone();
    let mut definition = ledger::definition(&tree.ledger, tree.leaf).unwrap();
    definition.revision.0 += 1;
    definition.parent = Some(BudgetNode::Pool(common_node::POOL));
    assert_err!(
        ledger::configure(&mut tree.ledger, definition),
        LedgerError::Revision
    );
    assert_eq!(tree.ledger, before);
}

#[test]
fn a_restored_reservation_must_cover_its_complete_ancestry() {
    let mut tree = DeepBudget::new();
    let work = Digest::hash(b"maximum ancestry");
    tree.ledger
        .admit(&ask(work, tree.leaf, Charge([1, 0, 0, 0, 0])), 1000)
        .unwrap();
    ledger::validate_reservations(&tree.ledger, [(work, tree.leaf)].into_iter()).unwrap();
    let mut encoded = serde_json::to_value(&tree.ledger).unwrap();
    encoded["holds"][0][1]["path"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    let corrupt: Book = serde_json::from_value(encoded).unwrap();
    assert_err!(
        ledger::validate_reservations(&corrupt, [(work, tree.leaf)].into_iter()),
        LedgerError::InvalidPath
    );
}

#[test]
fn active_reserves_cross_windows_and_clock_rollback_cannot_reset_them() {
    let limits = vec![Limit::new(Meter::OutputTokens, Window::Day, 10)];
    let mut ledger = configured_ledger(limits, 4);
    let one = Digest::hash(b"one");
    ledger
        .admit(&ask(one, budget(), Charge([1, 0, 8, 0, 0])), 86_399_999)
        .unwrap();
    ledger.advance(86_400_000);
    assert_err!(
        ledger.admit(
            &ask(Digest::hash(b"two"), budget(), Charge([1, 0, 3, 0, 0])),
            0
        ),
        Refusal {
            why: Why::Limit(..),
            ..
        }
    );
    ledger.charge(HoldId(*one.as_bytes()), Usage::Unknown, 0);
    let counter = ledger
        .node(budget().key())
        .unwrap()
        .counter(Meter::OutputTokens, Window::Day);
    assert_eq!((counter.window_id, counter.used), (1, 8));
    let mut changed = ledger::definition(&ledger, budget()).unwrap();
    changed.revision.0 += 1;
    changed.limits[0].amount = 20;
    ledger::configure(&mut ledger, changed).unwrap();
    assert_eq!(
        ledger
            .node(budget().key())
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
            vec![Limit::new(Meter::OutputTokens, Window::Day, cap)],
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
                    let ask = ask(Digest::hash(&nonce.to_be_bytes()), leaf, bound);
                    if ledger.admit(&ask, time).is_ok() {
                        held.push(ask.id);
                    }
                }
                2 => if let Some(id) = held.pop() {
                    prop_assert_ne!(ledger.charge(id, Usage::Unknown, time), Discharged::Gone);
                },
                3 => if let Some(id) = held.pop() {
                    prop_assert_eq!(ledger.release(id), Discharged::Released);
                },
                _ => {
                    time += 86_400_000;
                    ledger.advance(time);
                }
            }
            for node in nodes {
                let used = ledger.node(node.key()).unwrap().counter(Meter::OutputTokens, Window::Day).used;
                prop_assert!(used + ledger.reserved(node.key(), Meter::OutputTokens) <= cap);
            }
        }
    }
}
