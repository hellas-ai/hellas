//! The durable grant counter vocabulary. Gauges are deliberately not meters.
use hellas_auth::authority::ResourceId;
use hellas_auth::authority::{PrincipalId, Revision, UnixMillis};
use serde::{Deserialize, Serialize};

/// Machine, account and pool plus at most eight delegated subjects.
pub const MAX_BUDGET_PATH_LEN: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Window {
    Hour,
    Day,
    Week,
    Total,
}
impl Window {
    pub const ALL: [Self; 4] = [Self::Hour, Self::Day, Self::Week, Self::Total];
    /// ISO weeks start Monday; Unix epoch was Thursday. The offset also handles
    /// the partial first week without negative or wrapping arithmetic.
    pub const fn id(self, time: UnixMillis) -> u64 {
        match self {
            Self::Hour => time.0 / 3_600_000,
            Self::Day => time.0 / 86_400_000,
            Self::Week => (time.0 / 86_400_000 + 3) / 7,
            Self::Total => 0,
        }
    }
    pub const fn index(self) -> usize {
        self as usize
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PoolId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BudgetNode {
    Machine,
    Account(ResourceId),
    Pool(PoolId),
    Subject { pool: PoolId, subject: PrincipalId },
}

/// Explicit, revisioned budget configuration. Parentage is immutable; replacing
/// a Work grant or application credential never creates another subject counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDef {
    pub node: BudgetNode,
    pub parent: BudgetNode,
    pub revision: Revision,
    pub limits: Vec<Limit>,
    pub max_in_flight: std::num::NonZeroU16,
}
impl BudgetNode {
    pub fn valid_parent(self, parent: Self) -> bool {
        match (self, parent) {
            (BudgetNode::Account(_), BudgetNode::Machine)
            | (BudgetNode::Pool(_), BudgetNode::Account(_)) => true,
            (BudgetNode::Subject { pool, .. }, BudgetNode::Pool(parent)) => pool == parent,
            (
                BudgetNode::Subject { pool, subject },
                BudgetNode::Subject {
                    pool: parent,
                    subject: ancestor,
                },
            ) => pool == parent && subject != ancestor,
            _ => false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub meter: Meter,
    pub window: Window,
    pub amount: u64,
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
    Unknown,
}
