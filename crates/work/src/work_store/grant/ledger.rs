//! Pure ancestor accounting. The journal commits a candidate ledger together
//! with its JobBook transition; a caller cannot publish a partial path debit.
use crate::model::grant::budget::{
    BudgetDef, BudgetNode, Charge, Limit, MAX_BUDGET_PATH_LEN, Meter, Usage, Window,
};
use hellas_auth::Digest;
use hellas_auth::authority::{Revision, UnixMillis};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_BUDGET_NODES: usize = 1024;
pub(crate) const MAX_CONCURRENT: u16 = 256;

/// Capability to discharge one reservation. It cannot be cloned or constructed
/// outside the ledger; settlement and release both consume it.
#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    id: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Held {
    path: Vec<BudgetNode>,
    charge: Charge,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub window_id: u64,
    pub used: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    parent: Option<BudgetNode>,
    revision: Revision,
    limits: Vec<Limit>,
    concurrent: u16,
    counters: [[Counter; 4]; 5],
}
impl Node {
    pub fn limits(&self) -> &[Limit] {
        &self.limits
    }
    pub fn concurrent(&self) -> u16 {
        self.concurrent
    }
    pub fn counter(&self, meter: Meter, window: Window) -> Counter {
        self.counters[meter.index()][window.index()]
    }
    pub(crate) fn counter_at(&self, meter: Meter, window: Window, time: UnixMillis) -> Counter {
        let counter = self.counter(meter, window);
        let next = window.id(time);
        if next > counter.window_id {
            Counter {
                window_id: next,
                used: 0,
            }
        } else {
            counter
        }
    }
    fn advance(&mut self, time: UnixMillis) {
        for meter in Meter::ALL {
            for window in Window::ALL {
                self.counters[meter.index()][window.index()] = self.counter_at(meter, window, time);
            }
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(with = "super::codec::entries")]
    nodes: BTreeMap<BudgetNode, Node>,
    #[serde(with = "super::codec::entries")]
    held: BTreeMap<Digest, Held>,
    high_water: UnixMillis,
}
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("unknown budget node")]
    UnknownNode,
    #[error("invalid or duplicate budget limit")]
    InvalidLimits,
    #[error("budget exceeded at {node:?}: {meter:?}/{window:?}")]
    OverBudget {
        node: BudgetNode,
        meter: Meter,
        window: Window,
    },
    #[error("concurrency limit at {0:?}")]
    Concurrent(BudgetNode),
    #[error("reservation already exists")]
    Duplicate,
    #[error("unknown reservation")]
    UnknownReservation,
    #[error("invalid ancestor path")]
    InvalidPath,
    #[error("budget revision or immutable parent does not match")]
    Revision,
    #[error("budget configuration capacity exceeded")]
    Capacity,
    #[error("budget arithmetic overflow")]
    Overflow,
}
impl Ledger {
    pub fn definition(&self, id: BudgetNode) -> Option<BudgetDef> {
        let node = self.node(id)?;
        Some(BudgetDef {
            node: id,
            parent: node.parent?,
            revision: node.revision,
            limits: node.limits.clone(),
            max_in_flight: std::num::NonZeroU16::new(node.concurrent)?,
        })
    }
    /// Machine, account, pool, then at most eight delegated subject budgets.
    pub fn path(&self, mut id: BudgetNode) -> Result<Vec<BudgetNode>, LedgerError> {
        let mut path = Vec::new();
        loop {
            if path.len() == MAX_BUDGET_PATH_LEN || path.contains(&id) {
                return Err(LedgerError::InvalidPath);
            }
            let node = self.node(id).ok_or(LedgerError::UnknownNode)?;
            path.push(id);
            if id == BudgetNode::Machine {
                if node.parent.is_some() || node.revision != Revision(0) {
                    return Err(LedgerError::InvalidPath);
                }
                path.reverse();
                return Ok(path);
            }
            let parent = node.parent.ok_or(LedgerError::InvalidPath)?;
            if !id.valid_parent(parent) || node.revision.0 == 0 {
                return Err(LedgerError::InvalidPath);
            }
            id = parent;
        }
    }
    pub fn configure_budget(&mut self, definition: BudgetDef) -> Result<(), LedgerError> {
        if !definition.node.valid_parent(definition.parent)
            || self.path(definition.parent)?.len() >= MAX_BUDGET_PATH_LEN
        {
            return Err(LedgerError::InvalidPath);
        }
        if let Some(old) = self.node(definition.node) {
            if old.parent != Some(definition.parent)
                || !definition.revision.follows(Some(old.revision))
            {
                return Err(LedgerError::Revision);
            }
        } else if !definition.revision.follows(None) {
            return Err(LedgerError::Revision);
        } else if self.nodes.len() >= MAX_BUDGET_NODES {
            return Err(LedgerError::Capacity);
        }
        self.configure(
            definition.node,
            definition.limits,
            definition.max_in_flight.get(),
        )?;
        let node = self
            .nodes
            .get_mut(&definition.node)
            .ok_or(LedgerError::UnknownNode)?;
        node.parent = Some(definition.parent);
        node.revision = definition.revision;
        Ok(())
    }
    pub fn configure_machine(
        &mut self,
        limits: Vec<Limit>,
        concurrent: u16,
    ) -> Result<(), LedgerError> {
        self.configure(BudgetNode::Machine, limits, concurrent)
    }
    pub(super) fn reservation_bound(&self, work: Digest) -> Option<Charge> {
        self.held.get(&work).map(|held| held.charge)
    }
    pub fn high_water(&self) -> UnixMillis {
        self.high_water
    }
    /// Advancing time can widen every persisted window ID, including budgets
    /// outside the settling job's ancestry. Keep that growth available globally.
    pub(super) fn clock_headroom(&self) -> usize {
        fn remaining(value: u64) -> usize {
            9 - match value {
                0..=23 => 1,
                24..=255 => 2,
                256..=65535 => 3,
                65536..=4294967295 => 5,
                _ => 9,
            }
        }
        remaining(self.high_water.0)
            + self
                .nodes
                .values()
                .map(|node| {
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
    pub fn node(&self, id: BudgetNode) -> Option<&Node> {
        self.nodes.get(&id)
    }
    pub fn active_count(&self, node: BudgetNode) -> usize {
        self.held
            .values()
            .filter(|h| h.path.contains(&node))
            .count()
    }
    pub fn reserved(&self, node: BudgetNode, meter: Meter) -> u64 {
        self.held
            .values()
            .filter(|h| h.path.contains(&node))
            .fold(0u64, |n, h| n.saturating_add(h.charge.get(meter)))
    }
    pub fn remaining(&self, node: BudgetNode, limit: Limit) -> Option<u64> {
        self.remaining_at(node, limit, self.high_water)
    }
    pub(crate) fn remaining_at(
        &self,
        node: BudgetNode,
        limit: Limit,
        time: UnixMillis,
    ) -> Option<u64> {
        let used = self
            .node(node)?
            .counter_at(limit.meter, limit.window, time.max(self.high_water))
            .used;
        Some(
            limit
                .amount
                .saturating_sub(used)
                .saturating_sub(self.reserved(node, limit.meter)),
        )
    }
    /// A revision changes limits, never counters or live exposure. A lower
    /// allowance may block new admission, but cannot erase an existing duty.
    fn configure(
        &mut self,
        id: BudgetNode,
        limits: Vec<Limit>,
        concurrent: u16,
    ) -> Result<(), LedgerError> {
        if concurrent == 0
            || concurrent > MAX_CONCURRENT
            || limits.len() > Meter::ALL.len() * Window::ALL.len()
            || !hellas_rpc::protocol::value::all_distinct(
                limits.iter().map(|l| (l.meter, l.window)),
            )
        {
            return Err(LedgerError::InvalidLimits);
        }
        if let Some(node) = self.nodes.get_mut(&id) {
            node.limits = limits;
            node.concurrent = concurrent;
        } else {
            let mut node = Node {
                parent: None,
                revision: Revision(0),
                limits,
                concurrent,
                counters: [[Counter::default(); 4]; 5],
            };
            node.advance(self.high_water);
            self.nodes.insert(id, node);
        }
        Ok(())
    }
    pub fn advance(&mut self, time: UnixMillis) {
        self.high_water = self.high_water.max(time);
        for node in self.nodes.values_mut() {
            node.advance(self.high_water);
        }
    }
    /// Checks every ancestor before mutating any reservation. Active charges
    /// are independent of window cursors, so midnight never hides exposure.
    pub fn reserve(
        &mut self,
        id: Digest,
        subject: BudgetNode,
        charge: Charge,
        time: UnixMillis,
    ) -> Result<Reservation, LedgerError> {
        if self.held.contains_key(&id) {
            return Err(LedgerError::Duplicate);
        }
        if !matches!(subject, BudgetNode::Subject { .. }) {
            return Err(LedgerError::InvalidPath);
        }
        let path = self.path(subject)?;
        self.advance(time);
        for id in &path {
            let node = self.nodes.get(id).ok_or(LedgerError::UnknownNode)?;
            if self.active_count(*id) >= usize::from(node.concurrent) {
                return Err(LedgerError::Concurrent(*id));
            }
            // Account all meters even when currently unlimited, for later revisions.
            for meter in Meter::ALL {
                self.reserved(*id, meter)
                    .checked_add(charge.get(meter))
                    .ok_or(LedgerError::Overflow)?;
            }
            for limit in &node.limits {
                let total = node
                    .counter(limit.meter, limit.window)
                    .used
                    .checked_add(self.reserved(*id, limit.meter))
                    .and_then(|n| n.checked_add(charge.get(limit.meter)));
                if total.is_none_or(|n| n > limit.amount) {
                    return Err(LedgerError::OverBudget {
                        node: *id,
                        meter: limit.meter,
                        window: limit.window,
                    });
                }
            }
        }
        self.held.insert(id, Held { path, charge });
        Ok(Reservation { id })
    }
    /// Journal replay owns all capabilities again, after the old process and
    /// its workers have terminated. Not exposed to application callers.
    pub(super) fn recover(&self, id: Digest) -> Result<Reservation, LedgerError> {
        if !self.held.contains_key(&id) {
            return Err(LedgerError::UnknownReservation);
        }
        Ok(Reservation { id })
    }
    /// Returns whether the backend violated its bound. Actual usage is retained
    /// even on overrun; saturation remains permanently exhausted, never wraps.
    pub fn settle(
        &mut self,
        reservation: Reservation,
        usage: Usage,
        time: UnixMillis,
    ) -> Result<bool, LedgerError> {
        let held = self
            .held
            .remove(&reservation.id)
            .ok_or(LedgerError::UnknownReservation)?;
        self.advance(time);
        let actual = match usage {
            Usage::Observed(c) => c,
            Usage::Unknown => held.charge,
        };
        for id in held.path {
            let node = self.nodes.get_mut(&id).ok_or(LedgerError::UnknownNode)?;
            for meter in Meter::ALL {
                for counter in &mut node.counters[meter.index()] {
                    counter.used = counter.used.saturating_add(actual.get(meter));
                }
            }
        }
        Ok(actual.exceeds(held.charge))
    }
    pub fn release(&mut self, reservation: Reservation) -> Result<(), LedgerError> {
        self.held
            .remove(&reservation.id)
            .ok_or(LedgerError::UnknownReservation)?;
        Ok(())
    }
}

impl Ledger {
    pub(super) fn validate_reservations(
        &self,
        jobs: impl Iterator<Item = (Digest, BudgetNode)>,
    ) -> Result<(), LedgerError> {
        let jobs: BTreeMap<_, _> = jobs.collect();
        if jobs.len() != self.held.len() {
            return Err(LedgerError::UnknownReservation);
        }
        for (id, held) in &self.held {
            let subject = jobs.get(id).ok_or(LedgerError::UnknownReservation)?;
            if !matches!(subject, BudgetNode::Subject { .. }) || held.path != self.path(*subject)? {
                return Err(LedgerError::InvalidPath);
            }
        }
        if self.nodes.len() > MAX_BUDGET_NODES {
            return Err(LedgerError::Capacity);
        }
        for (id, node) in &self.nodes {
            self.path(*id)?;
            if node.concurrent == 0
                || node.concurrent > MAX_CONCURRENT
                || node.limits.len() > Meter::ALL.len() * Window::ALL.len()
                || !hellas_rpc::protocol::value::all_distinct(
                    node.limits.iter().map(|l| (l.meter, l.window)),
                )
            {
                return Err(LedgerError::InvalidLimits);
            }
            for meter in Meter::ALL {
                for window in Window::ALL {
                    if node.counter(meter, window).window_id != window.id(self.high_water) {
                        return Err(LedgerError::InvalidLimits);
                    }
                }
            }
        }
        Ok(())
    }
}

impl Ledger {
    pub(super) fn validate_definitions<'a>(
        &self,
        grants: impl Iterator<Item = &'a crate::model::grant::records::GrantDef>,
    ) -> Result<(), LedgerError> {
        for grant in grants {
            for id in self.path(grant.budget)? {
                let node = self.node(id).ok_or(LedgerError::UnknownNode)?;
                if grant
                    .policies
                    .iter()
                    .any(|p| node.limits.iter().any(|l| !p.supports(l.meter)))
                {
                    return Err(LedgerError::InvalidLimits);
                }
            }
        }
        Ok(())
    }
}
