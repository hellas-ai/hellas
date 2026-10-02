//! Pure ancestor accounting. The journal commits a candidate ledger together
//! with its JobBook transition; a caller cannot publish a partial path debit.
use hellas_rpc::Digest;
use hellas_rpc::protocol::work_grant::{
    UnixMillis,
    budget::{BudgetNode, Charge, Limit, Meter, Usage, Window},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
    limits: Vec<Limit>,
    concurrent: u16,
    counters: [[Counter; 4]; 4],
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
    fn advance(&mut self, time: UnixMillis) {
        for meter in Meter::ALL {
            for window in Window::ALL {
                let counter = &mut self.counters[meter.index()][window.index()];
                let next = window.id(time);
                if next > counter.window_id {
                    *counter = Counter {
                        window_id: next,
                        used: 0,
                    };
                }
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
    #[error("budget arithmetic overflow")]
    Overflow,
}
impl Ledger {
    pub fn high_water(&self) -> UnixMillis {
        self.high_water
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
        let used = self.node(node)?.counter(limit.meter, limit.window).used;
        Some(
            limit
                .amount
                .saturating_sub(used)
                .saturating_sub(self.reserved(node, limit.meter)),
        )
    }
    /// A revision changes limits, never counters or live exposure. A lower
    /// allowance may block new admission, but cannot erase an existing duty.
    pub fn configure(
        &mut self,
        id: BudgetNode,
        limits: Vec<Limit>,
        concurrent: u16,
    ) -> Result<(), LedgerError> {
        let unique: BTreeSet<_> = limits.iter().map(|l| (l.meter, l.window)).collect();
        if concurrent == 0 || limits.len() > 16 || unique.len() != limits.len() {
            return Err(LedgerError::InvalidLimits);
        }
        if let Some(node) = self.nodes.get_mut(&id) {
            node.limits = limits;
            node.concurrent = concurrent;
        } else {
            let mut node = Node {
                limits,
                concurrent,
                counters: [[Counter::default(); 4]; 4],
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
        path: Vec<BudgetNode>,
        charge: Charge,
        time: UnixMillis,
    ) -> Result<Reservation, LedgerError> {
        if self.held.contains_key(&id) {
            return Err(LedgerError::Duplicate);
        }
        if !matches!(path.as_slice(), [BudgetNode::Machine, BudgetNode::Grant(_)]) {
            return Err(LedgerError::InvalidPath);
        }
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
        jobs: impl Iterator<Item = (Digest, hellas_rpc::protocol::work_grant::GrantId)>,
    ) -> Result<(), LedgerError> {
        let jobs: BTreeMap<_, _> = jobs.collect();
        if jobs.len() != self.held.len() {
            return Err(LedgerError::UnknownReservation);
        }
        for (id, held) in &self.held {
            let grant = jobs.get(id).ok_or(LedgerError::UnknownReservation)?;
            if held.path != [BudgetNode::Machine, BudgetNode::Grant(*grant)]
                || held.path.iter().any(|id| !self.nodes.contains_key(id))
            {
                return Err(LedgerError::InvalidPath);
            }
        }
        for node in self.nodes.values() {
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
        grants: impl Iterator<Item = &'a hellas_rpc::protocol::work_grant::records::GrantDef>,
    ) -> Result<(), LedgerError> {
        let mut expected = usize::from(self.nodes.contains_key(&BudgetNode::Machine));
        for grant in grants {
            let node = self
                .node(BudgetNode::Grant(grant.id))
                .ok_or(LedgerError::UnknownNode)?;
            if node.limits != grant.limits || node.concurrent != grant.max_in_flight.get() {
                return Err(LedgerError::InvalidLimits);
            }
            expected += 1;
        }
        if expected != self.nodes.len() {
            return Err(LedgerError::UnknownNode);
        }
        Ok(())
    }
}
