//! Grant budget identities and their definitions; the counter vocabulary is the admission core's.
use hellas_admission::{Id33, Key};
use hellas_auth::authority::ResourceId;
use hellas_auth::authority::{PrincipalId, Revision};
use serde::{Deserialize, Serialize};

pub use hellas_admission::{Charge, Limit, Meter, Usage, Window};

/// Machine, account and pool plus at most eight delegated subjects.
pub const MAX_BUDGET_PATH_LEN: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoolId(pub [u8; 16]);
impl std::str::FromStr for PoolId {
    type Err = hex::FromHexError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hellas_auth::hex::parse::<16>(text).map(Self)
    }
}
impl std::fmt::Display for PoolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}
hellas_auth::printable_identifier!(PoolId, [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BudgetNode {
    Machine,
    Account(ResourceId),
    Pool(PoolId),
    Subject { pool: PoolId, subject: PrincipalId },
}

/// Explicit, revisioned budget configuration. Parentage is immutable; replacing
/// a Work grant or application credential never creates another subject counter.
/// Only the machine has no parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetDef {
    pub node: BudgetNode,
    pub parent: Option<BudgetNode>,
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
    pub fn key(self) -> Key {
        match self {
            Self::Machine => Key::Machine,
            Self::Account(id) => Key::Account(*id.0.as_bytes()),
            Self::Pool(pool) => Key::Pool(pool.0),
            Self::Subject { pool, subject } => Key::Subject(pool.0, Id33(*subject.as_bytes())),
        }
    }
    pub fn from_key(key: Key) -> Option<Self> {
        Some(match key {
            Key::Machine => Self::Machine,
            Key::Account(id) => Self::Account(ResourceId(hellas_auth::Digest::from_bytes(id))),
            Key::Pool(pool) => Self::Pool(PoolId(pool)),
            Key::Subject(pool, subject) => Self::Subject {
                pool: PoolId(pool),
                subject: PrincipalId::from_public_key(hellas_auth::PublicKey::P256(subject.0))
                    .ok()?,
            },
        })
    }
}
/// Accounting evidence and backend attribution travel together until journal encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UsageObservation {
    Observed(Charge),
    /// Incomplete usage attributable to the caller or upstream rejection.
    Unknown,
    /// Missing, unverifiable or unaccountable provider output.
    BackendFault,
}
impl UsageObservation {
    pub(crate) const fn journal_fields(self) -> (Option<Charge>, bool) {
        match self {
            Self::Observed(charge) => (Some(charge), false),
            Self::Unknown => (None, false),
            Self::BackendFault => (None, true),
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test(usage: Usage, fault: bool) -> Self {
        match usage {
            Usage::Observed(charge) => {
                assert!(
                    !fault,
                    "observed usage cannot be a backend accounting fault"
                );
                Self::Observed(charge)
            }
            Usage::Unknown if fault => Self::BackendFault,
            Usage::Unknown => Self::Unknown,
        }
    }
}
