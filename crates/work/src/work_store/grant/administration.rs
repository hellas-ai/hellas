use super::{NodeStore, NodeStoreError, state::Change};
use crate::model::grant::{
    budget::{BudgetDef, Limit},
    records::{GrantDef, GrantPolicy},
};
use hellas_auth::authority::{AuthenticatedCaller, CallerRecord, GrantId as Authorization};
use hellas_auth::authority::{GrantId, ResourceId, Revision, UnixMillis};
use serde::{Deserialize, Serialize};

pub const WORK_ALLOWANCE_READ: &str = "work.allowance.read";
pub const WORK_ALLOWANCE_CONFIGURE: &str = "work.allowance.configure";
pub const WORK_BUDGET_CONFIGURE: &str = "work.budget.configure";
pub const WORK_OFFER_EXPORT: &str = "work.offer.export";
pub const WORK_GENERATION_RESET: &str = "work.generation.reset";
pub const WORK_RESOURCE_CONFIGURE: &str = "work.resource.configure";
pub const WORK_RESOURCE_REPAIR: &str = "work.resource.repair";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WorkMutation {
    Capacity {
        expected: Revision,
        max_in_flight: u16,
        limits: Vec<Limit>,
    },
    Budget(BudgetDef),
    Resource(Box<GrantPolicy>),
    Define(Box<GrantDef>),
    Generation {
        id: GrantId,
        expected: u64,
    },
    Repair {
        resource: ResourceId,
        expected: u64,
    },
}
impl WorkMutation {
    pub(crate) fn operation(&self) -> &'static str {
        match self {
            Self::Capacity { .. } => crate::node::WORK_CAPACITY_CONFIGURE,
            Self::Resource(_) => WORK_RESOURCE_CONFIGURE,
            Self::Budget(_) => WORK_BUDGET_CONFIGURE,
            Self::Define(_) => WORK_ALLOWANCE_CONFIGURE,
            Self::Generation { .. } => WORK_GENERATION_RESET,
            Self::Repair { .. } => WORK_RESOURCE_REPAIR,
        }
    }

    pub(crate) fn valid_capacity(&self) -> bool {
        match self {
            Self::Capacity { max_in_flight, .. } => {
                (1..=super::store::MAX_OPEN_JOBS).contains(&usize::from(*max_in_flight))
            }
            _ => true,
        }
    }
}

/// Trusted journal data constructed under the writer; never caller evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkRecord {
    pub caller: CallerRecord,
    pub authorization: Authorization,
    pub mutation: WorkMutation,
}
impl NodeStore {
    // The entry point checks before inspecting command data; commit rechecks the
    // recorded mutation against the same operation table before appending it.
    pub(crate) async fn commit_work(
        &mut self,
        caller: &AuthenticatedCaller,
        authorization: Authorization,
        mutation: WorkMutation,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_authority()?;
        let authority = self.state().authority();
        if !mutation.valid_capacity() {
            return Err(hellas_auth::authority::AuthorityError::Invalid.into());
        }
        let record = WorkRecord {
            caller: authority.record_caller(caller, now)?,
            authorization,
            mutation,
        };
        self.commit(now, Change::Work(record), true).await
    }
}
