use super::{NodeStore, NodeStoreError, state::Change};
use crate::model::grant::{budget::BudgetDef, records::GrantDef};
use hellas_auth::authority::{AuthenticatedCaller, CallerRecord, GrantId as Authorization};
use hellas_auth::authority::{GrantId, ResourceId, Revision, UnixMillis};
use serde::{Deserialize, Serialize};

pub const WORK_ALLOWANCE_READ: &str = "work.allowance.read";
pub const WORK_ALLOWANCE_CONFIGURE: &str = "work.allowance.configure";
pub const WORK_BUDGET_CONFIGURE: &str = "work.budget.configure";
pub const WORK_OFFER_EXPORT: &str = "work.offer.export";
pub const WORK_GENERATION_RESET: &str = "work.generation.reset";
pub const WORK_RESOURCE_REPAIR: &str = "work.resource.repair";
pub const WORK_PAID_POLICY_CONFIGURE: &str = "work.paid.configure";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WorkMutation {
    PaidPolicy {
        expected: Revision,
        policy_salt: [u8; 32],
        policy: Box<hellas_channel::model::paid_policy::PaidPolicy>,
    },
    Budget(BudgetDef),
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
            Self::Budget(_) => WORK_BUDGET_CONFIGURE,
            Self::Define(_) => WORK_ALLOWANCE_CONFIGURE,
            Self::Generation { .. } => WORK_GENERATION_RESET,
            Self::Repair { .. } => WORK_RESOURCE_REPAIR,
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

    /// Apply the node's own configuration: the machine budget, then accounts,
    /// then resources. Each change commits separately, so an interrupted pass
    /// resumes at the next start; an unchanged configuration commits nothing.
    pub(crate) async fn reconcile(
        &mut self,
        configuration: &crate::model::grant::configuration::NodeConfiguration,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_authority()?;
        if let Some(machine) = configuration.machine() {
            let concurrent = machine.max_in_flight.get();
            if usize::from(concurrent) > super::store::MAX_OPEN_JOBS {
                return Err(hellas_auth::authority::AuthorityError::Invalid.into());
            }
            let current = self
                .state()
                .ledger
                .node(crate::model::grant::budget::BudgetNode::Machine);
            if current.is_none_or(|node| {
                node.limits() != machine.limits.as_slice() || node.concurrent() != concurrent
            }) {
                let change = Change::Machine {
                    limits: machine.limits.clone(),
                    concurrent,
                };
                self.commit(now, change, true).await?;
            }
        }
        for definition in
            configuration.account_changes(|node| self.state().ledger.definition(node))?
        {
            self.commit(now, Change::Budget(definition), true).await?;
        }
        for policy in configuration.resources() {
            if self.state().resource(policy.resource) != Some(policy) {
                self.commit(now, Change::Resource(policy.clone()), true)
                    .await?;
            }
        }
        Ok(())
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
        let record = WorkRecord {
            caller: authority.record_caller(caller, now)?,
            authorization,
            mutation,
        };
        self.commit(now, Change::Work(record), true).await
    }
}
