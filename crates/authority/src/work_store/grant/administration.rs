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
    DisablePaidPolicy {
        expected: Revision,
    },
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
            Self::PaidPolicy { .. } | Self::DisablePaidPolicy { .. } => WORK_PAID_POLICY_CONFIGURE,
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
    pub(crate) async fn configure_paid_policy(
        &mut self,
        caller: &AuthenticatedCaller,
        authorization: Authorization,
        expected: Option<Revision>,
        policy: Option<hellas_channel::model::paid_policy::PaidPolicy>,
        now: UnixMillis,
    ) -> Result<Revision, NodeStoreError> {
        let authority = self.state().authority();
        authority.authorize_caller(
            caller,
            authorization,
            &crate::operations::Operation::named(WORK_PAID_POLICY_CONFIGURE)?
                .permission(authority.authority(), None)?,
            now,
        )?;
        caller.session().step_up()?;
        let owner = authority
            .grant(authority.root_grant())
            .ok_or(NodeStoreError::Malformed)?
            .spec()
            .subject;
        if caller.subject() != owner {
            return Err(hellas_auth::authority::AuthorityError::Denied.into());
        }
        let current = self.state().paid_policy();
        let revision = current.map_or(Revision(0), |current| current.revision);
        if expected.is_some_and(|expected| expected != revision) {
            return Err(hellas_auth::authority::AuthorityError::Revision.into());
        }
        if let Some(policy) = &policy {
            policy.check()?;
        }
        if match (&policy, current) {
            (Some(policy), Some(current)) => current.enabled && &current.policy == policy,
            (None, current) => current.is_none_or(|current| !current.enabled),
            _ => false,
        } {
            return Ok(revision);
        }
        let mutation = match policy {
            Some(policy) => {
                let mut policy_salt = [0; 32];
                getrandom::fill(&mut policy_salt)
                    .map_err(|_| hellas_auth::authority::AuthorityError::Entropy)?;
                WorkMutation::PaidPolicy {
                    expected: revision,
                    policy_salt,
                    policy: Box::new(policy),
                }
            }
            None => WorkMutation::DisablePaidPolicy { expected: revision },
        };
        self.commit_work(caller, authorization, mutation, now)
            .await?;
        revision.next().ok_or(NodeStoreError::Malformed)
    }

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
        if configuration.machine().is_some_and(|machine| {
            usize::from(machine.max_in_flight.get()) > super::store::MAX_OPEN_JOBS
        }) {
            return Err(hellas_auth::authority::AuthorityError::Invalid.into());
        }
        changes.extend(
            configuration
                .budget_changes(|node| super::ledger::definition(state.ledger(), node))?
                .into_iter()
                .map(Change::Budget),
        );
        for input in configuration.resources() {
            if let Some(policy) = input.changed(state.resource(input.resource))? {
                changes.push(Change::Resource(policy));
            } else if state
                .resource_health(input.resource)
                .is_some_and(|health| !health.configured)
            {
                changes.push(Change::ResourceAvailability {
                    resource: input.resource,
                    available: true,
                });
            }
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
