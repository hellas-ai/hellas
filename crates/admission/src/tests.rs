use super::*;
use proptest::prelude::*;

const ACCOUNT: Key = Key::Account([1; 32]);
const SHARED: Key = Key::Pool([1; 16]);
const OWNER: Key = Key::Pool([2; 16]);
const H: Millis = HOUR;

fn id(n: u8) -> HoldId {
    HoldId([n; 32])
}
fn requests(n: u64) -> Charge {
    Charge([n, 0, 0, 0, 0])
}
fn tokens(n: u64) -> Charge {
    Charge([1, 0, n, 0, 0])
}
fn held(n: u64) -> Limit {
    Limit::new(Meter::Requests, Window::Held, n)
}
fn spec(parent: Option<Key>, limits: Vec<Limit>) -> Spec {
    Spec {
        parent,
        revision: 1,
        limits,
        queue: 8,
        owner: false,
    }
}
/// Machine → Account → {SHARED, OWNER}; the account carries `limits`.
fn tree(limits: Vec<Limit>) -> Book {
    let mut book = Book::default();
    book.configure(Key::Machine, Some(spec(None, vec![])))
        .unwrap();
    book.configure(ACCOUNT, Some(spec(Some(Key::Machine), limits)))
        .unwrap();
    book.configure(SHARED, Some(spec(Some(ACCOUNT), vec![])))
        .unwrap();
    let owner = Spec {
        owner: true,
        ..spec(Some(ACCOUNT), vec![])
    };
    book.configure(OWNER, Some(owner)).unwrap();
    book
}
fn now(n: u8, leaf: Key, charge: Charge) -> Ask {
    Ask {
        id: id(n),
        leaf,
        charge,
        wait: false,
        deadline: None,
    }
}
fn wait(n: u8, leaf: Key, charge: Charge, deadline: Option<Millis>) -> Ask {
    Ask {
        wait: true,
        deadline,
        ..now(n, leaf, charge)
    }
}
fn refusal(decision: Decision) -> Refusal {
    match decision {
        Decision::Refuse(refusal) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}
fn over(limit: Limit) -> Why {
    Why::Limit(limit.meter, limit.window)
}
fn never(limit: Limit) -> Why {
    Why::Impossible(limit.meter, limit.window)
}
fn empty() -> Queue {
    Queue::default()
}

#[test]
fn an_expired_deadline_refuses_before_anything_fits() {
    let book = tree(vec![]);
    let ask = Ask {
        deadline: Some(100),
        ..now(1, SHARED, requests(1))
    };
    assert_eq!(
        refusal(decide(&book, &empty(), &ask, 101)).why,
        Why::Deadline
    );
    assert_eq!(decide(&book, &empty(), &ask, 100), Decision::Admit);
    // Immediate is `wait: false`, never a deadline of now.
    assert_eq!(
        decide(&book, &empty(), &now(1, SHARED, requests(1)), 101),
        Decision::Admit
    );
}

#[test]
fn an_unknown_leaf_is_refused() {
    let book = tree(vec![]);
    let leaf = Key::Pool([9; 16]);
    let r = refusal(decide(&book, &empty(), &now(1, leaf, requests(1)), 0));
    assert_eq!((r.at, r.why), (leaf, Why::UnknownKey));
}

#[test]
fn admission_checks_every_ancestor_and_refusal_names_the_first() {
    let mut book = tree(vec![held(1)]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    let before = book.clone();
    let r = book.admit(&now(2, SHARED, requests(1)), 0).unwrap_err();
    assert_eq!((r.at, r.why, r.retry_at), (ACCOUNT, over(held(1)), None));
    assert_eq!(book, before, "a refusal changes nothing");
    assert_eq!(
        book.admit(&now(1, SHARED, requests(1)), 0).unwrap_err().why,
        Why::Duplicate
    );
}

#[test]
fn impossible_charges_never_wait_and_carry_no_retry() {
    let total = Limit::new(Meter::Requests, Window::Total, 2);
    let mut book = tree(vec![total]);
    let r = refusal(decide(
        &book,
        &empty(),
        &wait(1, SHARED, requests(3), None),
        0,
    ));
    assert_eq!((r.why, r.retry_at), (never(total), None));
    book.admit(&now(1, SHARED, requests(2)), 0).unwrap();
    book.charge(id(1), Usage::Unknown, 0);
    let r = refusal(decide(
        &book,
        &empty(),
        &wait(2, SHARED, requests(1), None),
        0,
    ));
    assert_eq!((r.why, r.retry_at), (never(total), None));
}

/// Worked example (c): a grant holder at its daily budget.
#[test]
fn an_exhausted_day_refuses_with_the_next_midnight() {
    let day = Limit::new(Meter::Requests, Window::Day, 1000);
    let mut book = tree(vec![day]);
    book.admit(&now(1, SHARED, requests(1000)), 9 * H).unwrap();
    book.charge(id(1), Usage::Unknown, 9 * H);
    let r = book
        .admit(&now(2, SHARED, requests(1)), 10 * H)
        .unwrap_err();
    assert_eq!((r.why, r.retry_at), (over(day), Some(DAY)));
    assert_eq!(book.admit(&now(2, SHARED, requests(1)), DAY), Ok(()));
}

/// Worked example (a): only owner paths may use the reserve.
#[test]
fn the_owner_reserve_admits_only_owner_paths() {
    let week = Limit {
        reserve: 2_000_000,
        ..Limit::new(Meter::OutputTokens, Window::Week, 10_000_000)
    };
    let mut book = tree(vec![week]);
    let thursday = 0;
    book.admit(&now(1, SHARED, tokens(7_500_000)), thursday)
        .unwrap();
    book.charge(id(1), Usage::Unknown, thursday);
    let r = book
        .admit(&now(2, SHARED, tokens(600_000)), thursday)
        .unwrap_err();
    let monday = 4 * DAY;
    assert_eq!(
        (r.at, r.why, r.retry_at),
        (ACCOUNT, over(week), Some(monday))
    );
    book.admit(&now(3, OWNER, tokens(600_000)), thursday)
        .unwrap();
}

/// Worked example (b): pacing a daily spend.
#[test]
fn pace_refuses_ahead_of_schedule_and_names_the_catch_up_time() {
    let day = Limit {
        pace: Some(500_000),
        ..Limit::new(Meter::OutputTokens, Window::Day, 5_000_000)
    };
    let mut book = tree(vec![day]);
    // Usage from before the pace was configured.
    book.restore(id(1), SHARED, tokens(2_300_000), 0).unwrap();
    book.charge(id(1), Usage::Unknown, 0);
    let nine = 9 * H;
    let t_star = nine + 36 * 60_000;
    let interactive = wait(2, SHARED, tokens(200_000), Some(nine + 30_000));
    let r = refusal(decide(&book, &empty(), &interactive, nine));
    assert_eq!((r.why, r.retry_at), (over(day), Some(t_star)));
    let patient = wait(2, SHARED, tokens(200_000), None);
    assert_eq!(
        decide(&book, &empty(), &patient, nine),
        Decision::Wait {
            not_before: Some(t_star)
        }
    );
    assert_eq!(next_event(&book, &patient, nine), Some(t_star));
    assert_eq!(decide(&book, &empty(), &patient, t_star), Decision::Admit);
    assert_eq!(
        decide(&book, &empty(), &patient, t_star - 1),
        Decision::Wait {
            not_before: Some(t_star)
        }
    );
    // Observed usage below the reservation moves the next catch-up time earlier.
    book.admit(&now(3, SHARED, tokens(200_000)), t_star)
        .unwrap();
    book.charge(id(3), Usage::Observed(tokens(150_000)), t_star);
    let next = wait(4, SHARED, tokens(200_000), None);
    // (2.65M − 0.5M)·86.4M / 5M ms is 10:19:12; charging the full 0.2M would give 10:33:36.
    assert_eq!(
        decide(&book, &empty(), &next, t_star),
        Decision::Wait {
            not_before: Some(10 * H + 19 * 60_000 + 12_000)
        }
    );
}

#[test]
fn a_waiter_past_its_deadline_is_refused_with_the_recheck_time() {
    let day = Limit::new(Meter::Requests, Window::Day, 1);
    let mut book = tree(vec![day]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    book.charge(id(1), Usage::Unknown, 0);
    let r = refusal(decide(
        &book,
        &empty(),
        &wait(2, SHARED, requests(1), Some(H)),
        0,
    ));
    assert_eq!((r.why, r.retry_at), (over(day), Some(DAY)));
    assert_eq!(
        decide(&book, &empty(), &wait(2, SHARED, requests(1), Some(DAY)), 0),
        Decision::Wait {
            not_before: Some(DAY)
        }
    );
}

/// Finding 14: a runnable earlier waiter keeps its place; a re-ask does not
/// count its own place against `queue`.
#[test]
fn earlier_waiters_count_as_reserved_and_a_re_ask_keeps_its_place() {
    let mut book = tree(vec![held(1)]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    let (a, b) = (
        wait(2, SHARED, requests(1), None),
        wait(3, SHARED, requests(1), None),
    );
    let mut queue = empty();
    queue.enter(a);
    queue.enter(b);
    queue.enter(a);
    assert_eq!(queue.waiters(), &[a, b]);
    book.release(id(1));
    assert_eq!(
        decide(&book, &queue, &b, 0),
        Decision::Wait { not_before: None }
    );
    assert_eq!(decide(&book, &queue, &a, 0), Decision::Admit);
    // An ordinary waiter does not hold back the owner.
    assert_eq!(
        decide(&book, &queue, &wait(4, OWNER, requests(1), None), 0),
        Decision::Admit
    );

    book.configure(
        ACCOUNT,
        Some(Spec {
            queue: 1,
            ..spec(Some(Key::Machine), vec![held(1)])
        }),
    )
    .unwrap();
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    let mut queue = empty();
    queue.enter(a);
    assert_eq!(
        decide(&book, &queue, &a, 0),
        Decision::Wait { not_before: None }
    );
    assert_eq!(refusal(decide(&book, &queue, &b, 0)).why, Why::QueueFull);
}

/// Worked example (e) and finding 12: lowering a limit keeps holds and
/// counters; a waiter that can never fit is refused at once.
#[test]
fn lowering_a_limit_live_keeps_duties_and_refuses_the_impossible() {
    let mut book = tree(vec![held(4)]);
    for n in 1..=4 {
        book.admit(&now(n, SHARED, requests(1)), 0).unwrap();
    }
    book.charge(id(4), Usage::Unknown, 0);
    let (holds, used) = (
        book.reserved(ACCOUNT, Meter::Requests),
        book.node(ACCOUNT).unwrap().counters,
    );
    book.configure(ACCOUNT, Some(spec(Some(Key::Machine), vec![held(2)])))
        .unwrap();
    assert_eq!(book.reserved(ACCOUNT, Meter::Requests), holds);
    assert_eq!(book.node(ACCOUNT).unwrap().counters, used);
    assert_eq!(
        decide(&book, &empty(), &wait(5, SHARED, requests(1), None), 0),
        Decision::Wait { not_before: None }
    );
    let r = refusal(decide(
        &book,
        &empty(),
        &wait(5, SHARED, requests(3), None),
        0,
    ));
    assert_eq!(r.why, never(held(2)));
}

/// Finding 9: a bucket bounds bursts; integer refill carries its remainder.
#[test]
fn a_bucket_bounds_bursts_and_refunds_only_on_release() {
    let bucket = Limit::new(Meter::Requests, Window::Bucket { every: 500 }, 8);
    let mut book = tree(vec![bucket]);
    for n in 0..8 {
        book.admit(&now(n, SHARED, requests(1)), 1000).unwrap();
    }
    let r = book.admit(&now(8, SHARED, requests(1)), 1000).unwrap_err();
    assert_eq!((r.why, r.retry_at), (over(bucket), Some(1500)));
    assert_eq!(
        next_event(&book, &now(8, SHARED, requests(1)), 1000),
        Some(1500)
    );
    book.admit(&now(8, SHARED, requests(1)), 1700).unwrap();
    // 1700 carried 200ms: the next token arrives at 2000, not 2200.
    assert!(book.admit(&now(9, SHARED, requests(1)), 1999).is_err());
    book.admit(&now(9, SHARED, requests(1)), 2000).unwrap();
    book.charge(id(0), Usage::Unknown, 2000);
    assert!(book.admit(&now(10, SHARED, requests(1)), 2000).is_err());
    book.release(id(1));
    book.admit(&now(10, SHARED, requests(1)), 2000).unwrap();
    // Over any interval L: at most amount + ⌊L/every⌋.
    let mut book = tree(vec![bucket]);
    let admitted = (0..=200u8)
        .filter(|n| {
            book.admit(&now(*n, SHARED, requests(1)), u64::from(*n) * 50)
                .is_ok()
        })
        .count();
    assert_eq!(admitted, 8 + 10_000 / 500);
}

/// Finding 11A: expiring occupancy is a known wake time.
#[test]
fn occupancy_counts_against_held_until_it_expires_and_is_never_charged() {
    let mut book = tree(vec![held(1)]);
    book.occupy(id(1), SHARED, requests(1), 3000).unwrap();
    let ask = wait(2, SHARED, requests(1), None);
    assert_eq!(
        decide(&book, &empty(), &ask, 1000),
        Decision::Wait {
            not_before: Some(3000)
        }
    );
    assert_eq!(next_event(&book, &ask, 1000), Some(3000));
    assert_eq!(book.charge(id(1), Usage::Unknown, 1000), Discharged::Gone);
    assert_eq!(book.release(id(1)), Discharged::Gone);
    assert_eq!(
        book.node(ACCOUNT)
            .unwrap()
            .counter(Meter::Requests, Window::Total)
            .used,
        0
    );
    book.admit(&ask, 3000).unwrap();
    assert_eq!(book.occupied(ACCOUNT, Meter::Requests, 3000), 0);
}

/// Findings 11B and 20: a block refuses with its status until it expires,
/// and its expiry is a wake time even after a live hold ends.
#[test]
fn a_block_refuses_with_its_status_and_wakes_at_expiry() {
    let mut book = tree(vec![held(1)]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    book.block(ACCOUNT, 5000, 503);
    let ask = wait(2, SHARED, requests(1), None);
    assert_eq!(
        decide(&book, &empty(), &ask, 0),
        Decision::Wait {
            not_before: Some(5000)
        }
    );
    book.release(id(1));
    assert_eq!(next_event(&book, &ask, 0), Some(5000));
    let r = refusal(decide(&book, &empty(), &now(2, SHARED, requests(1)), 0));
    assert_eq!(
        (r.at, r.why, r.retry_at),
        (ACCOUNT, Why::Blocked(503), Some(5000))
    );
    assert_eq!(decide(&book, &empty(), &ask, 5000), Decision::Admit);
}

/// Finding 19A and exactly-once discharge.
#[test]
fn a_hold_is_discharged_exactly_once_at_its_observed_usage() {
    let mut book = tree(vec![]);
    book.admit(&now(1, SHARED, tokens(100)), 0).unwrap();
    assert_eq!(
        book.charge(id(1), Usage::Observed(tokens(10)), 0),
        Discharged::Charged { overrun: false }
    );
    assert_eq!(book.charge(id(1), Usage::Unknown, 0), Discharged::Gone);
    assert_eq!(book.release(id(1)), Discharged::Gone);
    assert_eq!(
        book.node(SHARED)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Total)
            .used,
        10
    );
    book.admit(&now(2, SHARED, tokens(5)), 0).unwrap();
    assert_eq!(
        book.charge(id(2), Usage::Observed(tokens(6)), 0),
        Discharged::Charged { overrun: true }
    );
    assert_eq!(
        book.node(SHARED)
            .unwrap()
            .counter(Meter::OutputTokens, Window::Total)
            .used,
        16
    );
}

/// Ruling 1: replay restores reservations without limit checks, never without
/// identity and path checks.
#[test]
fn restore_skips_limits_but_not_structure() {
    let mut book = tree(vec![held(1)]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    book.restore(id(2), SHARED, requests(1), 0).unwrap();
    assert_eq!(book.reserved(ACCOUNT, Meter::Requests), 2);
    assert_eq!(
        book.restore(id(2), SHARED, requests(1), 0).unwrap_err().why,
        Why::Duplicate
    );
    let unknown = Key::Pool([9; 16]);
    assert_eq!(
        book.restore(id(3), unknown, requests(1), 0)
            .unwrap_err()
            .why,
        Why::UnknownKey
    );
}

#[test]
fn configuration_rejects_undefined_shapes_and_keeps_used_nodes() {
    let mut book = tree(vec![]);
    let paced = |window| Limit {
        pace: Some(1),
        ..Limit::new(Meter::Requests, window, 2)
    };
    for limits in [
        vec![paced(Window::Total)],
        vec![paced(Window::Held)],
        vec![paced(Window::Bucket { every: 1 })],
        vec![Limit::new(Meter::Requests, Window::Bucket { every: 0 }, 1)],
        vec![Limit {
            reserve: 3,
            ..Limit::new(Meter::Requests, Window::Day, 2)
        }],
        vec![held(1), held(2)],
        vec![
            Limit::new(Meter::Requests, Window::Bucket { every: 1 }, 1),
            Limit::new(Meter::Requests, Window::Bucket { every: 2 }, 1),
        ],
    ] {
        assert_eq!(
            book.configure(SHARED, Some(spec(Some(ACCOUNT), limits))),
            Err(ConfigError::Limits)
        );
    }
    assert_eq!(
        book.configure(SHARED, Some(spec(Some(Key::Machine), vec![]))),
        Err(ConfigError::Parent)
    );
    assert_eq!(
        book.configure(
            Key::Pool([9; 16]),
            Some(spec(Some(Key::Pool([8; 16])), vec![]))
        ),
        Err(ConfigError::Parent)
    );
    assert_eq!(
        book.configure(Key::Machine, Some(spec(Some(SHARED), vec![]))),
        Err(ConfigError::Parent)
    );
    assert_eq!(book.configure(ACCOUNT, None), Err(ConfigError::InUse));
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    assert_eq!(book.configure(SHARED, None), Err(ConfigError::InUse));
    book.charge(id(1), Usage::Unknown, 0);
    assert_eq!(book.configure(SHARED, None), Err(ConfigError::InUse));
    book.configure(OWNER, None).unwrap();
    assert!(book.node(OWNER).is_none());
}

#[test]
fn the_view_reports_usage_holds_blocks_and_waiters() {
    let mut book = tree(vec![held(1)]);
    book.admit(&now(1, SHARED, requests(1)), 0).unwrap();
    book.block(SHARED, 10, 429);
    let mut queue = empty();
    queue.enter(wait(2, OWNER, requests(1), None));
    let view = book.view(&queue, 0);
    let account = view.nodes.iter().find(|n| n.key == ACCOUNT).unwrap();
    assert_eq!((account.limits[0].reserved, account.holds.len()), (1, 0));
    let shared = view.nodes.iter().find(|n| n.key == SHARED).unwrap();
    assert_eq!(
        (shared.holds.as_slice(), shared.block),
        (&[id(1)][..], Some((10, 429)))
    );
    assert_eq!(view.waiters[0].1, Decision::Wait { not_before: None });
}

// Property suite: random trees and operation sequences against a naive fold
// over the history. I10 (routing) belongs to the gateway.

#[derive(Clone, Debug)]
enum Op {
    Ask {
        leaf: usize,
        charge: u64,
        deadline: Option<u64>,
        wait: bool,
    },
    Charge {
        hold: usize,
        observed: Option<u64>,
    },
    Release {
        hold: usize,
    },
    Occupy {
        leaf: usize,
        charge: u64,
        ttl: u64,
    },
    Advance(u64),
    Configure {
        node: usize,
        limits: Vec<Limit>,
    },
    Crash,
}
const LEAVES: [Key; 3] = [SHARED, OWNER, Key::Subject([1; 16], Id33([3; 33]))];
const NODES: [Key; 5] = [Key::Machine, ACCOUNT, SHARED, OWNER, LEAVES[2]];
fn limit() -> impl Strategy<Value = Limit> {
    let window = prop_oneof![
        Just(Window::Held),
        Just(Window::Hour),
        Just(Window::Day),
        Just(Window::Total),
        (1u64..2000).prop_map(|every| Window::Bucket { every }),
    ];
    (window, 0u64..12, 0u64..4, proptest::option::of(0u64..6)).prop_map(
        |(window, amount, reserve, pace)| Limit {
            meter: Meter::OutputTokens,
            window,
            amount,
            reserve: reserve.min(amount),
            pace: pace.filter(|_| matches!(window, Window::Hour | Window::Day)),
        },
    )
}
fn limits() -> impl Strategy<Value = Vec<Limit>> {
    proptest::collection::vec(limit(), 0..3).prop_map(|mut limits| {
        limits.sort_by_key(|l| l.window.kind());
        limits.dedup_by_key(|l| l.window.kind());
        limits
    })
}
fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..3usize, 0u64..6, proptest::option::of(0u64..4000), any::<bool>())
            .prop_map(|(leaf, charge, deadline, wait)| Op::Ask { leaf, charge, deadline, wait }),
        2 => (0..8usize, proptest::option::of(0u64..8)).prop_map(|(hold, observed)| Op::Charge { hold, observed }),
        1 => (0..8usize).prop_map(|hold| Op::Release { hold }),
        1 => (0..3usize, 0u64..4, 1u64..5000).prop_map(|(leaf, charge, ttl)| Op::Occupy { leaf, charge, ttl }),
        2 => (0u64..4 * HOUR).prop_map(Op::Advance),
        1 => (1..5usize, limits()).prop_map(|(node, limits)| Op::Configure { node, limits }),
        1 => Just(Op::Crash),
    ]
}

/// The naive reference: every quantity is recomputed from the history.
#[derive(Default)]
struct Model {
    holds: Vec<(HoldId, Key, u64)>,
    charges: Vec<(Key, u64, Millis)>,
    occupancy: Vec<(HoldId, Key, u64, Millis)>,
    now: Millis,
}
impl Model {
    fn under(book: &Book, leaf: Key, key: Key) -> bool {
        book.path(leaf).is_ok_and(|p| p.contains(&key))
    }
    fn reserved(&self, book: &Book, key: Key) -> u64 {
        self.holds
            .iter()
            .filter(|h| Self::under(book, h.1, key))
            .map(|h| h.2)
            .sum()
    }
    fn occupied(&self, book: &Book, key: Key) -> u64 {
        self.occupancy
            .iter()
            .filter(|o| o.3 > self.now && Self::under(book, o.1, key))
            .map(|o| o.2)
            .sum()
    }
    fn used(&self, book: &Book, key: Key, window: Window) -> u64 {
        self.charges
            .iter()
            .filter(|c| window.id(c.2) == window.id(self.now) && Self::under(book, c.0, key))
            .map(|c| c.1)
            .sum()
    }
    /// Whether every non-bucket limit fits, with no queue.
    fn fits(&self, book: &Book, leaf: Key, charge: u64) -> bool {
        let path = book.path(leaf).unwrap();
        let owner = path.iter().any(|k| book.node(*k).unwrap().spec.owner);
        path.iter().all(|key| {
            book.node(*key).unwrap().spec.limits.iter().all(|l| {
                let t = if owner {
                    l.amount
                } else {
                    l.amount - l.reserve
                };
                let held = self.reserved(book, *key);
                match l.window {
                    Window::Held => held + self.occupied(book, *key) + charge <= t,
                    Window::Bucket { .. } => true,
                    window => {
                        let allow = match (l.pace, window.bounds(self.now)) {
                            (Some(b), Some((s, e))) => t.min(b + t * (self.now - s) / (e - s)),
                            _ => t,
                        };
                        self.used(book, *key, window) + held + charge <= allow
                    }
                }
            })
        })
    }
}

fn check(book: &Book, model: &Model) -> Result<(), TestCaseError> {
    for key in NODES {
        // I2: reserved is the sum of live holds; counters are the fold of charges.
        prop_assert_eq!(
            book.reserved(key, Meter::OutputTokens),
            model.reserved(book, key)
        );
        prop_assert_eq!(
            book.occupied(key, Meter::OutputTokens, model.now),
            model.occupied(book, key)
        );
        for window in Window::CALENDAR {
            let used = book
                .node(key)
                .unwrap()
                .counter_at(Meter::OutputTokens, window, model.now)
                .used;
            prop_assert_eq!(used, model.used(book, key, window));
        }
    }
    // I7: serialize → restore → rebuild occupancy gives the same book.
    let mut restored: Book = serde_json::from_str(&serde_json::to_string(book).unwrap()).unwrap();
    for (id, leaf, charge, until) in &model.occupancy {
        restored
            .occupy(*id, *leaf, tokens(*charge), *until)
            .unwrap();
    }
    restored.advance(model.now);
    prop_assert_eq!(&restored, book);
    Ok(())
}

fn run(tree: &[Vec<Limit>; 5], ops: &[Op]) -> Result<Book, TestCaseError> {
    let mut book = Book::default();
    for (n, key) in NODES.into_iter().enumerate() {
        let parent = [
            None,
            Some(Key::Machine),
            Some(ACCOUNT),
            Some(ACCOUNT),
            Some(SHARED),
        ][n];
        let owner = key == OWNER;
        book.configure(
            key,
            Some(Spec {
                owner,
                ..spec(parent, tree[n].clone())
            }),
        )
        .unwrap();
    }
    let mut model = Model::default();
    let mut queue = Queue::default();
    let mut next = 0u8;
    for op in ops {
        match op.clone() {
            Op::Ask {
                leaf,
                charge,
                deadline,
                wait,
            } => {
                next = next.wrapping_add(1);
                let ask = Ask {
                    id: id(next),
                    leaf: LEAVES[leaf],
                    charge: tokens(charge),
                    wait,
                    deadline,
                };
                let mut admitted = book.clone();
                if admitted.admit(&ask, model.now).is_ok() {
                    // I1 and I3: the book admits exactly when the naive model fits.
                    prop_assert!(model.fits(&book, ask.leaf, charge));
                    prop_assert!(deadline.is_none_or(|d| d >= model.now));
                } else {
                    let buckets = book.path(ask.leaf).unwrap().iter().any(|k| {
                        book.node(*k)
                            .unwrap()
                            .spec
                            .limits
                            .iter()
                            .any(|l| matches!(l.window, Window::Bucket { .. }))
                    });
                    let expired = deadline.is_some_and(|d| d < model.now);
                    prop_assert!(buckets || expired || !model.fits(&book, ask.leaf, charge));
                }
                match decide(&book, &queue, &ask, model.now) {
                    Decision::Admit => {
                        // I4: a newcomer never takes capacity an earlier waiter of
                        // the same or higher class could already use.
                        let class = |leaf| book.owner(&book.path(leaf).unwrap());
                        let ahead: Vec<_> = queue
                            .waiters()
                            .iter()
                            .filter(|w| class(w.leaf) >= class(ask.leaf))
                            .filter(|w| {
                                model.fits(&book, w.leaf, w.charge.get(Meter::OutputTokens))
                            })
                            .copied()
                            .collect();
                        book = admitted;
                        model.holds.push((ask.id, ask.leaf, charge));
                        for w in ahead {
                            prop_assert!(model.fits(
                                &book,
                                w.leaf,
                                w.charge.get(Meter::OutputTokens)
                            ));
                        }
                    }
                    Decision::Wait { .. } => queue.enter(ask),
                    Decision::Refuse(_) => {}
                }
            }
            Op::Charge { hold, observed } => {
                if let Some(n) = (hold < model.holds.len()).then_some(hold) {
                    let (id, leaf, reserved) = model.holds.remove(n);
                    let usage = observed.map_or(Usage::Unknown, |o| Usage::Observed(tokens(o)));
                    prop_assert_ne!(book.charge(id, usage, model.now), Discharged::Gone);
                    model
                        .charges
                        .push((leaf, observed.unwrap_or(reserved), model.now));
                    prop_assert_eq!(book.charge(id, usage, model.now), Discharged::Gone);
                }
            }
            Op::Release { hold } => {
                if hold < model.holds.len() {
                    let (id, _, _) = model.holds.remove(hold);
                    prop_assert_eq!(book.release(id), Discharged::Released);
                    prop_assert_eq!(book.release(id), Discharged::Gone);
                }
            }
            Op::Occupy { leaf, charge, ttl } => {
                next = next.wrapping_add(1);
                let until = model.now + ttl;
                book.occupy(id(next), LEAVES[leaf], tokens(charge), until)
                    .unwrap();
                model
                    .occupancy
                    .push((id(next), LEAVES[leaf], charge, until));
            }
            Op::Advance(by) => {
                model.now += by;
                book.advance(model.now);
                model.occupancy.retain(|o| o.3 > model.now);
            }
            Op::Configure { node, limits } => {
                let key = NODES[node];
                let old = book.node(key).unwrap().spec.clone();
                book.configure(key, Some(Spec { limits, ..old })).unwrap();
            }
            Op::Crash => {
                // I8: process-owned holds are charged once at their reservation;
                // occupancy is never charged.
                for (id, leaf, reserved) in model.holds.drain(..) {
                    prop_assert_eq!(
                        book.charge(id, Usage::Unknown, model.now),
                        Discharged::Charged { overrun: false }
                    );
                    prop_assert_eq!(book.charge(id, Usage::Unknown, model.now), Discharged::Gone);
                    model.charges.push((leaf, reserved, model.now));
                }
                queue = Queue::default();
            }
        }
        // I5: after any mutation every waiter re-decides, in order; none
        // that could admit or must refuse stays parked.
        for w in queue.waiters().to_vec() {
            match decide(&book, &queue, &w, model.now) {
                Decision::Admit => {
                    book.admit(&w, model.now).unwrap();
                    model
                        .holds
                        .push((w.id, w.leaf, w.charge.get(Meter::OutputTokens)));
                    queue.withdraw(w.id);
                }
                Decision::Refuse(_) => queue.withdraw(w.id),
                Decision::Wait { .. } => {}
            }
        }
        for w in queue.waiters() {
            // A parked waiter has something that will wake it.
            let path = book.path(w.leaf).unwrap();
            let others = queue.waiters().iter().any(|o| o.id != w.id);
            let live = model
                .holds
                .iter()
                .any(|h| path.iter().any(|k| Model::under(&book, h.1, *k)));
            prop_assert!(others || live || next_event(&book, w, model.now).is_some());
        }
        check(&book, &model)?;
    }
    Ok(book)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn the_book_matches_a_naive_fold_of_its_history(
        tree in [limits(), limits(), limits(), limits(), limits()],
        ops in proptest::collection::vec(op(), 1..60),
    ) {
        let first = run(&tree, &ops)?;
        // I7: the same operations give the same book.
        prop_assert_eq!(first, run(&tree, &ops)?);
    }
}
