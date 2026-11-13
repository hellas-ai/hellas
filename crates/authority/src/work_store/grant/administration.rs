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

    /// Commit the document and every configuration-owned authority change together.
    pub(crate) async fn configure(
        &mut self,
        expected: Revision,
        document: String,
        secrets: crate::model::grant::configuration::ConfigurationSecrets,
        configuration: &crate::model::grant::configuration::NodeConfiguration,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        self.check_authority()?;
        configuration.validate()?;
        let state = self.state();
        let mut changes = vec![Change::Configure {
            expected,
            document,
            secrets,
        }];
        if let Some(machine) = configuration.machine() {
            if usize::from(machine.max_in_flight.get()) > super::store::MAX_OPEN_JOBS {
                return Err(hellas_auth::authority::AuthorityError::Invalid.into());
            }
            let current = super::ledger::definition(
                state.ledger(),
                crate::model::grant::budget::BudgetNode::Machine,
            );
            if current.as_ref().is_none_or(|old| {
                old.limits != machine.limits || old.max_in_flight != machine.max_in_flight
            }) {
                changes.push(Change::Budget(BudgetDef {
                    node: crate::model::grant::budget::BudgetNode::Machine,
                    parent: None,
                    revision: current
                        .map_or(Revision(0), |old| old.revision)
                        .next()
                        .ok_or(NodeStoreError::Malformed)?,
                    limits: machine.limits.clone(),
                    max_in_flight: machine.max_in_flight,
                }));
            }
        }
        changes.extend(
            configuration
                .account_changes(|node| super::ledger::definition(state.ledger(), node))?
                .into_iter()
                .map(Change::Budget),
        );
        for input in configuration.resources() {
            let mut policy = input.clone();
            if let Some(old) = state.resource(policy.resource) {
                policy.revision = old.revision;
                policy.pricing.revision = old.pricing.revision;
                if policy.pricing != old.pricing {
                    policy.pricing.revision = old
                        .pricing
                        .revision
                        .next()
                        .ok_or(NodeStoreError::Malformed)?;
                }
                if policy == *old {
                    if state
                        .resource_health(policy.resource)
                        .is_some_and(|health| !health.configured)
                    {
                        changes.push(Change::ResourceAvailability {
                            resource: policy.resource,
                            available: true,
                        });
                    }
                    continue;
                } else {
                    policy.revision = old.revision.next().ok_or(NodeStoreError::Malformed)?;
                }
            }
            changes.push(Change::Resource(policy));
        }
        changes.extend(
            state
                .catalogue()
                .filter(|old| {
                    !configuration
                        .resources()
                        .iter()
                        .any(|p| p.resource == old.resource)
                })
                .map(|old| Change::ResourceAvailability {
                    resource: old.resource,
                    available: false,
                }),
        );
        self.commit_changes(now, changes, true).await
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
