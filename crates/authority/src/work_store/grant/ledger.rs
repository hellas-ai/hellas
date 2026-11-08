//! Grant rules over the admission book: the budget tree's shape, revisions,
//! and the checks a restored checkpoint must pass. Accounting is the core's.
use crate::model::grant::budget::{
    BudgetDef, BudgetNode, Limit, MAX_BUDGET_PATH_LEN, Meter, Window,
};
use hellas_admission::{Book, HoldId, Key, Spec};
use hellas_auth::Digest;
use hellas_auth::authority::{Revision, UnixMillis};
use std::collections::BTreeMap;

const MAX_BUDGET_NODES: usize = 1024;
pub(crate) const MAX_CONCURRENT: u16 = 256;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("unknown budget node")]
    UnknownNode,
    #[error("invalid or duplicate budget limit")]
    InvalidLimits,
    #[error("unknown reservation")]
    UnknownReservation,
    #[error("invalid ancestor path")]
    InvalidPath,
    #[error("budget revision or immutable parent does not match")]
    Revision,
    #[error("budget configuration capacity exceeded")]
    Capacity,
}

pub(super) fn hold(work: Digest) -> HoldId {
    HoldId(*work.as_bytes())
}
/// The concurrency limit every grant budget carries first.
pub fn concurrent(spec: &Spec) -> u16 {
    spec.limits
        .first()
        .filter(|l| l.window == Window::Held)
        .map_or(0, |l| u16::try_from(l.amount).unwrap_or(u16::MAX))
}
/// The configured calendar limits, without the concurrency limit.
pub fn limits(spec: &Spec) -> &[Limit] {
    spec.limits.get(1..).unwrap_or_default()
}
pub fn definition(book: &Book, id: BudgetNode) -> Option<BudgetDef> {
    let spec = book.node(id.key())?.spec();
    Some(BudgetDef {
        node: id,
        parent: match spec.parent {
            Some(parent) => Some(BudgetNode::from_key(parent)?),
            None => None,
        },
        revision: Revision(spec.revision),
        limits: limits(spec).to_vec(),
        max_in_flight: std::num::NonZeroU16::new(concurrent(spec))?,
    })
}
/// Machine, account, pool, then at most eight delegated subject budgets.
pub fn path(book: &Book, id: BudgetNode) -> Result<Vec<BudgetNode>, LedgerError> {
    let keys = book.path(id.key()).map_err(|_| LedgerError::UnknownNode)?;
    if keys.len() > MAX_BUDGET_PATH_LEN || keys.first() != Some(&Key::Machine) {
        return Err(LedgerError::InvalidPath);
    }
    let path: Vec<_> = keys
        .into_iter()
        .map(|key| BudgetNode::from_key(key).ok_or(LedgerError::InvalidPath))
        .collect::<Result<_, _>>()?;
    for pair in path.windows(2) {
        if !pair[1].valid_parent(pair[0]) {
            return Err(LedgerError::InvalidPath);
        }
    }
    for node in &path {
        if book
            .node(node.key())
            .ok_or(LedgerError::UnknownNode)?
            .spec()
            .revision
            == 0
        {
            return Err(LedgerError::InvalidPath);
        }
    }
    Ok(path)
}
fn check_spec(spec: &Spec) -> Result<(), LedgerError> {
    let calendar = limits(spec)
        .iter()
        .all(|l| Window::CALENDAR.contains(&l.window) && l.reserve == 0 && l.pace.is_none());
    if spec.revision == 0
        || spec.queue != 0
        || spec.owner
        || concurrent(spec) == 0
        || concurrent(spec) > MAX_CONCURRENT
        || spec.limits[0].meter != Meter::Requests
        || spec.limits[0].reserve != 0
        || !calendar
        || !hellas_rpc::protocol::value::all_distinct(
            spec.limits.iter().map(|l| (l.meter, l.window)),
        )
    {
        return Err(LedgerError::InvalidLimits);
    }
    Ok(())
}
/// A revision changes limits, never counters or live exposure. A lower
/// allowance may block new admission, but cannot erase an existing duty.
pub fn configure(book: &mut Book, definition: BudgetDef) -> Result<(), LedgerError> {
    match definition.parent {
        None if definition.node == BudgetNode::Machine => {}
        Some(parent)
            if definition.node.valid_parent(parent)
                && path(book, parent)?.len() < MAX_BUDGET_PATH_LEN => {}
        _ => return Err(LedgerError::InvalidPath),
    }
    let key = definition.node.key();
    let parent = definition.parent.map(BudgetNode::key);
    match book.node(key) {
        Some(old)
            if old.spec().parent != parent
                || !definition
                    .revision
                    .follows(Some(Revision(old.spec().revision))) =>
        {
            return Err(LedgerError::Revision);
        }
        Some(_) => {}
        None if !definition.revision.follows(None) => return Err(LedgerError::Revision),
        None if book.nodes().count() >= MAX_BUDGET_NODES => return Err(LedgerError::Capacity),
        None => {}
    }
    let mut limits = vec![Limit::new(
        Meter::Requests,
        Window::Held,
        definition.max_in_flight.get().into(),
    )];
    limits.extend(definition.limits);
    let spec = Spec {
        parent,
        revision: definition.revision.0,
        limits,
        queue: 0,
        owner: false,
    };
    check_spec(&spec)?;
    book.configure(key, Some(spec))
        .map_err(|_| LedgerError::InvalidLimits)
}
/// Remaining allowance of one limit at `time`, net of live reservations.
pub fn remaining(book: &Book, node: BudgetNode, limit: Limit, time: UnixMillis) -> Option<u64> {
    let key = node.key();
    let used = book
        .node(key)?
        .counter_at(limit.meter, limit.window, time.0.max(book.high_water()))
        .used;
    Some(
        limit
            .amount
            .saturating_sub(used)
            .saturating_sub(book.reserved(key, limit.meter)),
    )
}
/// Advancing time can widen every persisted window ID, including budgets
/// outside the settling job's ancestry. Keep that growth available globally.
pub(super) fn clock_headroom(book: &Book) -> usize {
    fn remaining(value: u64) -> usize {
        9 - match value {
            0..=23 => 1,
            24..=255 => 2,
            256..=65535 => 3,
            65536..=4294967295 => 5,
            _ => 9,
        }
    }
    remaining(book.high_water())
        + book
            .nodes()
            .map(|(_, node)| {
                Meter::ALL
                    .into_iter()
                    .flat_map(|meter| {
                        [Window::Hour, Window::Day, Window::Week]
                            .map(|window| remaining(node.counter(meter, window).window_id))
                    })
                    .sum::<usize>()
            })
            .sum::<usize>()
}

/// A restored reservation backs exactly one live job, over that job's whole
/// current ancestry. Limits are not checked again: replay is reconstruction.
pub(super) fn validate_reservations(
    book: &Book,
    jobs: impl Iterator<Item = (Digest, BudgetNode)>,
) -> Result<(), LedgerError> {
    let jobs: BTreeMap<_, _> = jobs.map(|(id, node)| (hold(id), node)).collect();
    if jobs.len() != book.holds().count() {
        return Err(LedgerError::UnknownReservation);
    }
    for (id, held, _) in book.holds() {
        let subject = jobs.get(&id).ok_or(LedgerError::UnknownReservation)?;
        let expected: Vec<_> = path(book, *subject)?
            .into_iter()
            .map(BudgetNode::key)
            .collect();
        if !matches!(subject, BudgetNode::Subject { .. }) || held != expected {
            return Err(LedgerError::InvalidPath);
        }
    }
    if book.nodes().count() > MAX_BUDGET_NODES {
        return Err(LedgerError::Capacity);
    }
    for (key, node) in book.nodes() {
        path(
            book,
            BudgetNode::from_key(*key).ok_or(LedgerError::InvalidPath)?,
        )?;
        check_spec(node.spec())?;
        for meter in Meter::ALL {
            for window in Window::CALENDAR {
                if node.counter(meter, window).window_id != window.id(book.high_water()) {
                    return Err(LedgerError::InvalidLimits);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_definitions<'a>(
    book: &Book,
    grants: impl Iterator<Item = &'a crate::model::grant::records::GrantDef>,
) -> Result<(), LedgerError> {
    for grant in grants {
        for id in path(book, grant.budget)? {
            let spec = book.node(id.key()).ok_or(LedgerError::UnknownNode)?.spec();
            if grant
                .policies
                .iter()
                .any(|p| limits(spec).iter().any(|l| !p.supports(l.meter)))
            {
                return Err(LedgerError::InvalidLimits);
            }
        }
    }
    Ok(())
}
