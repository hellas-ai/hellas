//! The durable grant counter vocabulary. Gauges are deliberately not meters.
use super::{GrantId, UnixMillis};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Meter {
    Requests,
    InputTokens,
    OutputTokens,
    DeviceMillis,
}
impl Meter {
    pub const ALL: [Self; 4] = [
        Self::Requests,
        Self::InputTokens,
        Self::OutputTokens,
        Self::DeviceMillis,
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
pub enum BudgetNode {
    Machine,
    Grant(GrantId),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limit {
    pub meter: Meter,
    pub window: Window,
    pub amount: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charge(pub [u64; 4]);
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
