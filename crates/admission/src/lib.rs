//! Pure admission accounting over a tree of keys. An ask names a leaf and is
//! admitted only when every limit on the root-to-leaf path fits. The caller
//! passes `now`; nothing here sleeps, locks or performs IO. A reservation ends
//! exactly once: as a charge unless there is conclusive evidence that nothing
//! ran, in which case it is released.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

pub type Millis = u64;
const HOUR: Millis = 3_600_000;
const DAY: Millis = 86_400_000;

/// One reservation. Ids are per role, so one task holding two reservations
/// uses two ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HoldId(pub [u8; 32]);

/// A compressed public key; serde implements no 33-byte array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "(u8, [u8; 32])", into = "(u8, [u8; 32])")]
pub struct Id33(pub [u8; 33]);
impl From<(u8, [u8; 32])> for Id33 {
    fn from((head, tail): (u8, [u8; 32])) -> Self {
        let mut bytes = [head; 33];
        bytes[1..].copy_from_slice(&tail);
        Self(bytes)
    }
}
impl From<Id33> for (u8, [u8; 32]) {
    fn from(id: Id33) -> Self {
        let mut tail = [0; 32];
        tail.copy_from_slice(&id.0[1..]);
        (id.0[0], tail)
    }
}

/// Grant budget nodes: machine, provider account, pool, delegated subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Key {
    Machine,
    Account([u8; 32]),
    Pool([u8; 16]),
    Subject([u8; 16], Id33),
}

/// Counted quantities. Gauges are deliberately not meters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Meter {
    Requests,
    InputTokens,
    OutputTokens,
    DeviceMillis,
    UsdMicros,
}
impl Meter {
    pub const ALL: [Self; 5] = [
        Self::Requests,
        Self::InputTokens,
        Self::OutputTokens,
        Self::DeviceMillis,
        Self::UsdMicros,
    ];
    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Window {
    /// Live holds plus unexpired occupancy.
    Held,
    /// Up to `amount` tokens, one more every `every` ms. Admission takes the
    /// charge; only `release` refunds it.
    Bucket {
        every: Millis,
    },
    Hour,
    Day,
    Week,
    Total,
}
impl Window {
    /// The windows with persisted counters, in counter order.
    pub const CALENDAR: [Self; 4] = [Self::Hour, Self::Day, Self::Week, Self::Total];
    /// ISO weeks start Monday; Unix epoch was Thursday. The offset also handles
    /// the partial first week without negative or wrapping arithmetic.
    pub const fn id(self, time: Millis) -> u64 {
        match self {
            Self::Hour => time / HOUR,
            Self::Day => time / DAY,
            Self::Week => (time / DAY + 3) / 7,
            Self::Held | Self::Bucket { .. } | Self::Total => 0,
        }
    }
    const fn counter(self) -> Option<usize> {
        match self {
            Self::Hour => Some(0),
            Self::Day => Some(1),
            Self::Week => Some(2),
            Self::Total => Some(3),
            Self::Held | Self::Bucket { .. } => None,
        }
    }
    /// Start and end of the calendar window containing `time`.
    fn bounds(self, time: Millis) -> Option<(Millis, Millis)> {
        let id = self.id(time);
        match self {
            Self::Hour => Some((id * HOUR, (id + 1).saturating_mul(HOUR))),
            Self::Day => Some((id * DAY, (id + 1).saturating_mul(DAY))),
            Self::Week => Some((
                (id * 7).saturating_sub(3) * DAY,
                (id * 7 + 4).saturating_mul(DAY),
            )),
            Self::Held | Self::Bucket { .. } | Self::Total => None,
        }
    }
    /// Two limits on one meter must differ in kind; a bucket's rate is not a kind.
    const fn kind(self) -> Self {
        match self {
            Self::Bucket { .. } => Self::Bucket { every: 0 },
            other => other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub meter: Meter,
    pub window: Window,
    pub amount: u64,
    /// Headroom only asks through an owner node may use.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reserve: u64,
    /// Linear schedule for Hour/Day/Week: `min(t, pace + t·elapsed/len)`. It
    /// stops running ahead of the schedule; it does not bound bursts after idleness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pace: Option<u64>,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
impl Limit {
    pub const fn new(meter: Meter, window: Window, amount: u64) -> Self {
        Self {
            meter,
            window,
            amount,
            reserve: 0,
            pace: None,
        }
    }
    const fn threshold(&self, owner: bool) -> u64 {
        if owner {
            self.amount
        } else {
            self.amount.saturating_sub(self.reserve)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charge(pub [u64; 5]);
impl Charge {
    pub const fn get(self, meter: Meter) -> u64 {
        self.0[meter.index()]
    }
    pub fn set(&mut self, meter: Meter, value: u64) {
        self.0[meter.index()] = value;
    }
    pub fn exceeds(self, bound: Self) -> bool {
        self.0
            .iter()
            .zip(bound.0)
            .any(|(actual, reserved)| *actual > reserved)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    Observed(Charge),
    /// Charges the reserved amount.
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    /// Immutable once configured.
    pub parent: Option<Key>,
    /// The configuring caller's version; never interpreted here.
    pub revision: u64,
    pub limits: Vec<Limit>,
    /// Most other waiters a failing node keeps before refusing `QueueFull`.
    pub queue: u16,
    /// Asks through an owner node may use every limit's `reserve`, and go
    /// ahead of ordinary waiters.
    pub owner: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    pub id: HoldId,
    pub leaf: Key,
    pub charge: Charge,
    /// `false` is "immediate only"; never encode it as a deadline of now.
    pub wait: bool,
    pub deadline: Option<Millis>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Admit,
    /// `not_before` is a recheck time, not a promise.
    Wait {
        not_before: Option<Millis>,
    },
    Refuse(Refusal),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub at: Key,
    pub why: Why,
    pub retry_at: Option<Millis>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// The meter and window of the limit that did not fit.
    Limit(Meter, Window),
    Blocked(u16),
    QueueFull,
    Deadline,
    /// The limit can never admit this charge.
    Impossible(Meter, Window),
    UnknownKey,
    /// The id already holds a reservation.
    Duplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discharged {
    /// Unknown id: already discharged, or never held. Nothing changed.
    Gone,
    Released,
    Charged {
        overrun: bool,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Limits,
    /// Missing parent, a cycle, or a changed parent.
    Parent,
    /// Holds, occupancy, children or current usage remain; set limits to 0 instead.
    InUse,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub window_id: u64,
    pub used: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Tokens {
    meter: Meter,
    tokens: u64,
    at: Millis,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    spec: Spec,
    counters: [[Counter; 4]; 5],
    buckets: Vec<Tokens>,
    block: Option<(Millis, u16)>,
}
impl Node {
    pub fn spec(&self) -> &Spec {
        &self.spec
    }
    /// The persisted counter; zero for windows without one.
    pub fn counter(&self, meter: Meter, window: Window) -> Counter {
        window
            .counter()
            .map_or_else(Counter::default, |w| self.counters[meter.index()][w])
    }
    pub fn counter_at(&self, meter: Meter, window: Window, time: Millis) -> Counter {
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
    fn advance(&mut self, time: Millis) {
        for meter in Meter::ALL {
            for (w, window) in Window::CALENDAR.into_iter().enumerate() {
                self.counters[meter.index()][w] = self.counter_at(meter, window, time);
            }
        }
    }
    /// Integer refill; a partial interval carries over until the bucket is full.
    fn tokens(&self, meter: Meter, amount: u64, every: Millis, now: Millis) -> Tokens {
        let t = self
            .buckets
            .iter()
            .find(|b| b.meter == meter)
            .copied()
            .unwrap_or(Tokens {
                meter,
                tokens: amount,
                at: now,
            });
        let count = now.saturating_sub(t.at) / every;
        if count >= amount {
            Tokens {
                tokens: amount,
                at: now,
                ..t
            }
        } else {
            Tokens {
                tokens: t.tokens.saturating_add(count).min(amount),
                at: t.at + count * every,
                ..t
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Held {
    path: Vec<Key>,
    charge: Charge,
}

/// One tree of limits with its live reservations. Waiters live outside it,
/// so a journal can clone, apply and discard a candidate book freely.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Book {
    #[serde(with = "entries")]
    nodes: BTreeMap<Key, Node>,
    #[serde(with = "entries")]
    holds: BTreeMap<HoldId, Held>,
    /// Charged work that still occupies `Held` capacity until its deadline.
    /// The owner derives it again after a restore; it is never charged.
    #[serde(skip)]
    occupancy: BTreeMap<HoldId, (Held, Millis)>,
    high_water: Millis,
}
impl Book {
    pub fn high_water(&self) -> Millis {
        self.high_water
    }
    pub fn node(&self, key: Key) -> Option<&Node> {
        self.nodes.get(&key)
    }
    pub fn nodes(&self) -> impl Iterator<Item = (&Key, &Node)> {
        self.nodes.iter()
    }
    pub fn holds(&self) -> impl Iterator<Item = (HoldId, &[Key], Charge)> {
        self.holds
            .iter()
            .map(|(id, held)| (*id, held.path.as_slice(), held.charge))
    }
    pub fn hold(&self, id: HoldId) -> Option<Charge> {
        self.holds.get(&id).map(|held| held.charge)
    }
    /// Root first. An unknown key or a cycle returns the offending key.
    pub fn path(&self, leaf: Key) -> Result<Vec<Key>, Key> {
        let mut path = Vec::new();
        let mut next = Some(leaf);
        while let Some(key) = next {
            let node = self.nodes.get(&key).ok_or(key)?;
            if path.contains(&key) {
                return Err(key);
            }
            path.push(key);
            next = node.spec.parent;
        }
        path.reverse();
        Ok(path)
    }
    fn owner(&self, path: &[Key]) -> bool {
        path.iter()
            .any(|key| self.nodes.get(key).is_some_and(|n| n.spec.owner))
    }
    /// Live reservations through `key`.
    pub fn reserved(&self, key: Key, meter: Meter) -> u64 {
        self.holds
            .values()
            .filter(|h| h.path.contains(&key))
            .fold(0, |n, h| n.saturating_add(h.charge.get(meter)))
    }
    /// Unexpired occupancy through `key`.
    pub fn occupied(&self, key: Key, meter: Meter, now: Millis) -> u64 {
        self.occupancy
            .values()
            .filter(|(h, until)| *until > now && h.path.contains(&key))
            .fold(0, |n, (h, _)| n.saturating_add(h.charge.get(meter)))
    }
    /// Changes limits only. Counters, holds and occupancy are untouched, so a
    /// lowered limit still counts work already admitted.
    pub fn configure(&mut self, key: Key, spec: Option<Spec>) -> Result<(), ConfigError> {
        let Some(spec) = spec else {
            if !self.nodes.contains_key(&key) {
                return Ok(());
            }
            let at = self.high_water;
            let used = self.nodes[&key].counters.iter().any(|meter| {
                Window::CALENDAR
                    .into_iter()
                    .zip(meter)
                    .any(|(window, c)| c.window_id == window.id(at) && c.used > 0)
            });
            if used
                || self.holds.values().any(|h| h.path.contains(&key))
                || self.occupancy.values().any(|(h, _)| h.path.contains(&key))
                || self.nodes.values().any(|n| n.spec.parent == Some(key))
            {
                return Err(ConfigError::InUse);
            }
            self.nodes.remove(&key);
            return Ok(());
        };
        let valid = |l: &Limit| {
            l.reserve <= l.amount
                && match l.window {
                    Window::Held | Window::Total => l.pace.is_none(),
                    Window::Bucket { every } => every > 0 && l.pace.is_none(),
                    Window::Hour | Window::Day | Window::Week => true,
                }
        };
        let mut kinds: Vec<_> = spec
            .limits
            .iter()
            .map(|l| (l.meter, l.window.kind()))
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        if kinds.len() != spec.limits.len() || !spec.limits.iter().all(valid) {
            return Err(ConfigError::Limits);
        }
        let parent_ok = match (self.nodes.get(&key), spec.parent) {
            (Some(old), _) => old.spec.parent == spec.parent,
            (None, Some(parent)) => self.path(parent).is_ok_and(|path| !path.contains(&key)),
            (None, None) => true,
        };
        if !parent_ok {
            return Err(ConfigError::Parent);
        }
        let at = self.high_water;
        let node = self.nodes.entry(key).or_insert_with(|| {
            let mut node = Node {
                spec: Spec::default(),
                counters: [[Counter::default(); 4]; 5],
                buckets: Vec::new(),
                block: None,
            };
            node.advance(at);
            node
        });
        let bucket = |l: &&Limit| matches!(l.window, Window::Bucket { .. });
        node.buckets.retain(|b| {
            spec.limits
                .iter()
                .filter(bucket)
                .any(|l| l.meter == b.meter)
        });
        for l in spec.limits.iter().filter(bucket) {
            if node.buckets.iter().all(|b| b.meter != l.meter) {
                node.buckets.push(Tokens {
                    meter: l.meter,
                    tokens: l.amount,
                    at,
                });
            }
        }
        node.spec = spec;
        Ok(())
    }
    pub fn advance(&mut self, time: Millis) {
        self.high_water = self.high_water.max(time);
        for node in self.nodes.values_mut() {
            node.advance(self.high_water);
        }
        let now = self.high_water;
        self.occupancy.retain(|_, (_, until)| *until > now);
    }
    /// Records the ask if `decide` admits it immediately against an empty queue.
    pub fn admit(&mut self, ask: &Ask, now: Millis) -> Result<(), Refusal> {
        if self.holds.contains_key(&ask.id) {
            return Err(Refusal {
                at: ask.leaf,
                why: Why::Duplicate,
                retry_at: None,
            });
        }
        let immediate = Ask {
            wait: false,
            ..*ask
        };
        match decide(self, &Queue::default(), &immediate, now) {
            Decision::Admit => self.restore(ask.id, ask.leaf, ask.charge, now),
            Decision::Refuse(refusal) => Err(refusal),
            Decision::Wait { .. } => unreachable!("an immediate ask never waits"),
        }
    }
    /// Replay: record a reservation admitted under earlier limits without
    /// checking them again. Identity and path remain checked.
    pub fn restore(
        &mut self,
        id: HoldId,
        leaf: Key,
        charge: Charge,
        now: Millis,
    ) -> Result<(), Refusal> {
        let refuse = |at, why| Refusal {
            at,
            why,
            retry_at: None,
        };
        if self.holds.contains_key(&id) {
            return Err(refuse(leaf, Why::Duplicate));
        }
        let path = self.path(leaf).map_err(|at| refuse(at, Why::UnknownKey))?;
        self.advance(now);
        let now = self.high_water;
        for key in &path {
            let node = self
                .nodes
                .get_mut(key)
                .ok_or(refuse(*key, Why::UnknownKey))?;
            for limit in &node.spec.limits {
                if let Window::Bucket { every } = limit.window {
                    let mut t = node.tokens(limit.meter, limit.amount, every, now);
                    t.tokens = t.tokens.saturating_sub(charge.get(limit.meter));
                    if let Some(b) = node.buckets.iter_mut().find(|b| b.meter == t.meter) {
                        *b = t;
                    }
                }
            }
        }
        self.holds.insert(id, Held { path, charge });
        Ok(())
    }
    /// Discharges a hold into every counter on its path. Returns whether
    /// observed usage exceeded the reservation; it is retained even then.
    pub fn charge(&mut self, id: HoldId, usage: Usage, now: Millis) -> Discharged {
        let Some(held) = self.holds.remove(&id) else {
            return Discharged::Gone;
        };
        self.advance(now);
        let actual = match usage {
            Usage::Observed(charge) => charge,
            Usage::Unknown => held.charge,
        };
        for key in &held.path {
            if let Some(node) = self.nodes.get_mut(key) {
                for meter in Meter::ALL {
                    for counter in &mut node.counters[meter.index()] {
                        counter.used = counter.used.saturating_add(actual.get(meter));
                    }
                }
            }
        }
        Discharged::Charged {
            overrun: actual.exceeds(held.charge),
        }
    }
    /// Only on conclusive evidence that nothing ran. Refunds bucket tokens.
    pub fn release(&mut self, id: HoldId) -> Discharged {
        let Some(held) = self.holds.remove(&id) else {
            return Discharged::Gone;
        };
        for key in &held.path {
            if let Some(node) = self.nodes.get_mut(key) {
                for limit in &node.spec.limits {
                    if let Some(b) = node.buckets.iter_mut().find(|b| b.meter == limit.meter)
                        && matches!(limit.window, Window::Bucket { .. })
                    {
                        b.tokens = b
                            .tokens
                            .saturating_add(held.charge.get(limit.meter))
                            .min(limit.amount);
                    }
                }
            }
        }
        Discharged::Released
    }
    /// Keeps already-charged work counted against `Held` limits until `until`.
    pub fn occupy(
        &mut self,
        id: HoldId,
        leaf: Key,
        charge: Charge,
        until: Millis,
    ) -> Result<(), Refusal> {
        let path = self.path(leaf).map_err(|at| Refusal {
            at,
            why: Why::UnknownKey,
            retry_at: None,
        })?;
        if until > self.high_water {
            self.occupancy.insert(id, (Held { path, charge }, until));
        }
        Ok(())
    }
    /// Refuses every ask through `key` with `Blocked(status)` until `until`.
    /// An unknown key is ignored.
    pub fn block(&mut self, key: Key, until: Millis, status: u16) {
        if let Some(node) = self.nodes.get_mut(&key) {
            node.block = Some((until, status));
        }
    }
    pub fn view(&self, queue: &Queue, now: Millis) -> View {
        let now = now.max(self.high_water);
        let nodes = self
            .nodes
            .iter()
            .map(|(key, node)| NodeView {
                key: *key,
                spec: node.spec.clone(),
                limits: node
                    .spec
                    .limits
                    .iter()
                    .map(|limit| LimitView {
                        limit: *limit,
                        used: node.counter_at(limit.meter, limit.window, now).used,
                        reserved: self.reserved(*key, limit.meter),
                        occupied: self.occupied(*key, limit.meter, now),
                        tokens: match limit.window {
                            Window::Bucket { every } => {
                                Some(node.tokens(limit.meter, limit.amount, every, now).tokens)
                            }
                            _ => None,
                        },
                    })
                    .collect(),
                block: node.block.filter(|(until, _)| *until > now),
                holds: self
                    .holds
                    .iter()
                    .filter(|(_, h)| h.path.last() == Some(key))
                    .map(|(id, _)| *id)
                    .collect(),
            })
            .collect();
        let waiters = queue
            .0
            .iter()
            .map(|ask| (*ask, decide(self, queue, ask, now)))
            .collect();
        View {
            now,
            nodes,
            waiters,
        }
    }
}

/// Volatile FIFO of asks that chose to wait, kept beside the book. Earlier
/// waiters of the same or higher class count as already reserved. After any
/// change, re-decide every waiter in order until a pass changes nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Queue(Vec<Ask>);
impl Queue {
    /// A re-ask keeps its existing place.
    pub fn enter(&mut self, ask: Ask) {
        if self.0.iter().all(|w| w.id != ask.id) {
            self.0.push(ask);
        }
    }
    /// For a waiter that leaves; never for an admitted hold.
    pub fn withdraw(&mut self, id: HoldId) {
        self.0.retain(|w| w.id != id);
    }
    pub fn waiters(&self) -> &[Ask] {
        &self.0
    }
    fn ahead(&self, book: &Book, id: HoldId, owner: bool) -> Vec<(Vec<Key>, Charge)> {
        let place = self
            .0
            .iter()
            .position(|w| w.id == id)
            .unwrap_or(self.0.len());
        self.0
            .iter()
            .enumerate()
            .filter(|(_, w)| w.id != id)
            .filter_map(|(n, w)| {
                let path = book.path(w.leaf).ok()?;
                let theirs = book.owner(&path);
                ((theirs && !owner) || (theirs == owner && n < place)).then_some((path, w.charge))
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub now: Millis,
    pub nodes: Vec<NodeView>,
    pub waiters: Vec<(Ask, Decision)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeView {
    pub key: Key,
    pub spec: Spec,
    pub limits: Vec<LimitView>,
    pub block: Option<(Millis, u16)>,
    /// Holds whose leaf is this node.
    pub holds: Vec<HoldId>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitView {
    pub limit: Limit,
    pub used: u64,
    pub reserved: u64,
    pub occupied: u64,
    pub tokens: Option<u64>,
}

struct Failure {
    at: Key,
    why: Why,
    recheck: Option<Millis>,
}

/// The admission decision. Pure: the same book, queue, ask and time give the
/// same answer, so every route candidate can be asked independently.
pub fn decide(book: &Book, queue: &Queue, ask: &Ask, now: Millis) -> Decision {
    let now = now.max(book.high_water);
    let refuse = |at, why, retry_at| Decision::Refuse(Refusal { at, why, retry_at });
    if ask.deadline.is_some_and(|deadline| deadline < now) {
        return refuse(ask.leaf, Why::Deadline, None);
    }
    let path = match book.path(ask.leaf) {
        Ok(path) => path,
        Err(at) => return refuse(at, Why::UnknownKey, None),
    };
    let owner = book.owner(&path);
    let ahead = queue.ahead(book, ask.id, owner);
    let mut failures = Vec::new();
    let mut full = None;
    for key in &path {
        let node = &book.nodes[key];
        let before = failures.len();
        if let Some((until, status)) = node.block.filter(|(until, _)| *until > now) {
            failures.push(Failure {
                at: *key,
                why: Why::Blocked(status),
                recheck: Some(until),
            });
        }
        for limit in &node.spec.limits {
            let queued = ahead
                .iter()
                .filter(|(p, _)| p.contains(key))
                .fold(0u64, |n, (_, c)| n.saturating_add(c.get(limit.meter)));
            if let Some((impossible, recheck)) = shortfall(
                book,
                *key,
                node,
                limit,
                owner,
                ask.charge.get(limit.meter),
                queued,
                now,
            ) {
                failures.push(Failure {
                    at: *key,
                    why: if impossible {
                        Why::Impossible(limit.meter, limit.window)
                    } else {
                        Why::Limit(limit.meter, limit.window)
                    },
                    recheck,
                });
            }
        }
        let waiting = queue
            .0
            .iter()
            .filter(|w| w.id != ask.id && book.path(w.leaf).is_ok_and(|p| p.contains(key)))
            .count();
        if failures.len() > before && full.is_none() && waiting >= usize::from(node.spec.queue) {
            full = Some(*key);
        }
    }
    let Some(first) = failures.first() else {
        return Decision::Admit;
    };
    let impossible = failures
        .iter()
        .find(|f| matches!(f.why, Why::Impossible(..)));
    let not_before = failures.iter().filter_map(|f| f.recheck).max();
    match impossible {
        Some(f) if ask.wait => return refuse(f.at, f.why, None),
        Some(_) => return refuse(first.at, first.why, None),
        None => {}
    }
    if !ask.wait || not_before.zip(ask.deadline).is_some_and(|(t, d)| t > d) {
        return refuse(first.at, first.why, not_before);
    }
    if let Some(at) = full {
        return refuse(at, Why::QueueFull, not_before);
    }
    Decision::Wait { not_before }
}

/// `None` when the limit fits; otherwise whether it never can and the
/// earliest known time it might.
#[allow(clippy::too_many_arguments)]
fn shortfall(
    book: &Book,
    key: Key,
    node: &Node,
    limit: &Limit,
    owner: bool,
    charge: u64,
    queued: u64,
    now: Millis,
) -> Option<(bool, Option<Millis>)> {
    let t = limit.threshold(owner);
    let need = |base: u64| base.checked_add(queued).and_then(|n| n.checked_add(charge));
    match limit.window {
        Window::Held => {
            let live = book.reserved(key, limit.meter);
            let occupied = book.occupied(key, limit.meter, now);
            if need(live.saturating_add(occupied)).is_some_and(|n| n <= t) {
                return None;
            }
            // Only expiring occupancy is a known time; a live hold ends whenever it ends.
            let recheck = (live == 0 && queued == 0)
                .then(|| {
                    book.occupancy
                        .values()
                        .filter(|(h, until)| *until > now && h.path.contains(&key))
                        .map(|(_, until)| *until)
                        .max()
                })
                .flatten();
            Some((charge > t, recheck))
        }
        Window::Bucket { every } => {
            let tokens = node.tokens(limit.meter, limit.amount, every, now);
            let want = need(limit.amount - t);
            if want.is_some_and(|n| tokens.tokens >= n) {
                return None;
            }
            let recheck = want.filter(|n| *n <= limit.amount).map(|n| {
                tokens
                    .at
                    .saturating_add((n - tokens.tokens).saturating_mul(every))
            });
            Some((charge > t, recheck))
        }
        window => {
            let used = node.counter_at(limit.meter, window, now).used;
            let reserved = book.reserved(key, limit.meter);
            let bounds = window.bounds(now);
            let allow = match (limit.pace, bounds) {
                (Some(pace), Some((start, end))) => {
                    let ramp = u128::from(t) * u128::from(now - start) / u128::from(end - start);
                    t.min(u64::try_from(ramp).unwrap_or(u64::MAX).saturating_add(pace))
                }
                _ => t,
            };
            let total = need(used.saturating_add(reserved));
            if total.is_some_and(|n| n <= allow) {
                return None;
            }
            let exhausted = used.saturating_add(charge) > t;
            let recheck = if exhausted {
                bounds.map(|(_, end)| end)
            } else {
                match (limit.pace, bounds, total) {
                    (Some(pace), Some((start, end)), Some(n)) if n <= t && n > pace => {
                        let span = u128::from(n - pace) * u128::from(end - start);
                        let elapsed = span.div_ceil(u128::from(t));
                        Some(start.saturating_add(u64::try_from(elapsed).unwrap_or(u64::MAX)))
                    }
                    _ => None,
                }
            };
            Some((
                charge > t || (window == Window::Total && exhausted),
                recheck,
            ))
        }
    }
}

/// The earliest time after `now` at which anything on the ask's path changes
/// without a mutation: occupancy or block expiry, a bucket token, a pace
/// time, a window rollover.
pub fn next_event(book: &Book, ask: &Ask, now: Millis) -> Option<Millis> {
    let now = now.max(book.high_water);
    let path = book.path(ask.leaf).ok()?;
    let mut times = Vec::new();
    for key in &path {
        let node = &book.nodes[key];
        times.extend(node.block.map(|(until, _)| until));
        times.extend(
            book.occupancy
                .values()
                .filter(|(h, _)| h.path.contains(key))
                .map(|(_, until)| *until),
        );
        for limit in &node.spec.limits {
            match limit.window {
                Window::Bucket { every } => {
                    let tokens = node.tokens(limit.meter, limit.amount, every, now);
                    if tokens.tokens < limit.amount {
                        times.push(tokens.at.saturating_add(every));
                    }
                }
                window => times.extend(window.bounds(now).map(|(_, end)| end)),
            }
        }
    }
    let ask = Ask {
        wait: true,
        deadline: None,
        ..*ask
    };
    if let Decision::Wait {
        not_before: Some(time),
    } = decide(book, &Queue::default(), &ask, now)
    {
        times.push(time);
    }
    times.into_iter().filter(|time| *time > now).min()
}

/// Maps as ordered entry lists: DAG-CBOR and JSON maps need string keys.
mod entries {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
    use std::collections::BTreeMap;
    pub fn serialize<K: Serialize + Ord, V: Serialize, S: Serializer>(
        value: &BTreeMap<K, V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        value.iter().collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<
        'de,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    >(
        d: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(d)?;
        if entries.windows(2).any(|p| p[0].0 >= p[1].0) {
            return Err(D::Error::custom("unordered or duplicate map entries"));
        }
        Ok(entries.into_iter().collect())
    }
}
