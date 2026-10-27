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
pub const WORK_PAID_POLICY_CONFIGURE: &str = "work.paid.configure";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WorkMutation {
    PaidPolicy {
        expected: Revision,
        policy_salt: [u8; 32],
        policy: Box<hellas_channel::model::paid_policy::PaidPolicy>,
    },
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
            Self::PaidPolicy { .. } => WORK_PAID_POLICY_CONFIGURE,
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
/// The one-time provider binding, journaled with its recorded authority check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindRecord {
    pub caller: CallerRecord,
    pub authorization: Authorization,
    #[serde(with = "crate::model::grant::records::provider_bytes")]
    pub provider: hellas_rpc::ProviderEnrollmentBundle,
}
impl NodeStore {
    /// Callers verify the root proof first. Rebinding the bound enrollment is a
    /// no-op so a lost reply can be retried; any other enrollment is refused.
    pub(crate) async fn bind_provider(
        &mut self,
        caller: &AuthenticatedCaller,
        authorization: Authorization,
        provider: hellas_rpc::ProviderEnrollmentBundle,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_authority()?;
        match &self.state().provider {
            Some(bound) if *bound == provider => return Ok(()),
            Some(_) => return Err(NodeStoreError::ProviderBound),
            None => {}
        }
        let record = BindRecord {
            caller: self.state().authority().record_caller(caller, now)?,
            authorization,
            provider,
        };
        self.commit(now, Change::BindProvider(record), true).await
    }

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
