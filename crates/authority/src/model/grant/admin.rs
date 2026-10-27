//! Typed Work administration. Application authority belongs to hellas-auth.
use super::{
    budget::{BudgetDef, BudgetNode},
    records::*,
    standing::NodeAllowance,
    *,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

pub const MAX_ADMIN_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowanceTerms {
    pub policies: Vec<String>,
    pub budget: BudgetNode,
    pub max_job_millis: NonZeroU64,
    pub enabled: bool,
    pub allow_account_backed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkControlCommand {
    SetPaidPolicy {
        expected_revision: Revision,
        policy: Box<hellas_channel::model::paid_policy::PaidPolicy>,
    },
    ConfigureResource {
        policy: String,
    },
    Catalogue,
    ConfigureBudget {
        definition: BudgetDef,
    },
    InspectBudget {
        node: BudgetNode,
    },
    List,
    Inspect {
        id: GrantId,
    },
    Offers {
        id: Option<GrantId>,
    },
    Create {
        id: GrantId,
        terms: AllowanceTerms,
    },
    Revise {
        id: GrantId,
        expected_revision: Revision,
        terms: AllowanceTerms,
    },
    NewGeneration {
        id: GrantId,
        expected_generation: u64,
    },
    InspectResource {
        policy: String,
    },
    RepairResource {
        policy: String,
        expected_revision: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowanceSummary {
    pub id: GrantId,
    pub budget: BudgetNode,
    pub revision: Revision,
    pub policies: Vec<String>,
    pub enabled: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkControlReply {
    PaidPolicyChanged {
        revision: Revision,
    },
    ResourceChanged {
        resource: ResourceId,
        revision: Revision,
    },
    Catalogue(Vec<GrantPolicy>),
    BudgetChanged {
        node: BudgetNode,
        revision: Revision,
    },
    Budget {
        definition: BudgetDef,
        now: UnixMillis,
        allowance: NodeAllowance,
    },
    Allowances(Vec<AllowanceSummary>),
    Changed {
        id: GrantId,
        revision: Revision,
        generation: u64,
    },
    Status {
        allowance: AllowanceSummary,
        now: UnixMillis,
        nodes: Vec<NodeAllowance>,
    },
    Offers(Vec<SignedOffer>),
    Resource {
        revision: u64,
        consecutive_faults: u16,
        quarantined: bool,
    },
}
