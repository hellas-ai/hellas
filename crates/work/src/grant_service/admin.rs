//! Checked Work administration; user and role administration belongs to Auth.
use hellas_rpc::protocol::value::all_distinct;

use super::{GrantService, NodeStore, NodeStoreError};
use crate::model::grant::{admin::*, records::*, *};
use crate::operations::Operation;
use crate::work_store::grant::{
    WORK_ALLOWANCE_CONFIGURE, WORK_ALLOWANCE_READ, WORK_BUDGET_CONFIGURE, WORK_GENERATION_RESET,
    WORK_OFFER_EXPORT, WORK_RESOURCE_CONFIGURE, WORK_RESOURCE_REPAIR, WorkMutation,
};
use hellas_auth::authority::{AuthenticatedCaller, GrantId as Authorization};
use hellas_auth::authority::{GrantId, Revision, UnixMillis};
use std::{num::NonZeroU64, sync::Arc};

/// One Work administration service assembled with the host's validated resources.
/// Its caller supplies operations, never a replacement resource catalogue or writer.
#[derive(Clone)]
pub struct WorkAdministration {
    service: GrantService,
    resources: Arc<Vec<GrantPolicy>>,
    max_job_millis: NonZeroU64,
}
enum ChangeReply {
    Ready(WorkControlReply),
    Allowance(GrantId),
    ResourceHealth(String),
}

impl WorkAdministration {
    pub fn new(
        service: GrantService,
        resources: Vec<GrantPolicy>,
        max_job_millis: NonZeroU64,
    ) -> Result<Self, NodeStoreError> {
        if resources.len() > MAX_WORK_POLICIES
            || !all_distinct(resources.iter().map(|p| &p.name))
            || !all_distinct(resources.iter().map(|p| p.resource))
        {
            return Err(GrantError::Limits.into());
        }
        for policy in &resources {
            policy.validate()?;
        }
        Ok(Self {
            service,
            resources: Arc::new(resources),
            max_job_millis,
        })
    }
    pub fn node(&self) -> crate::node::NodeCoordinator {
        self.service.node()
    }

    pub async fn execute(
        &self,
        caller: &AuthenticatedCaller,
        authorization: Authorization,
        command: WorkControlCommand,
    ) -> Result<WorkControlReply, NodeStoreError> {
        let operation = match &command {
            WorkControlCommand::List
            | WorkControlCommand::Catalogue
            | WorkControlCommand::InspectBudget { .. }
            | WorkControlCommand::Inspect { .. }
            | WorkControlCommand::InspectResource { .. } => WORK_ALLOWANCE_READ,
            WorkControlCommand::Offers { .. } => WORK_OFFER_EXPORT,
            WorkControlCommand::Create { .. } | WorkControlCommand::Revise { .. } => {
                WORK_ALLOWANCE_CONFIGURE
            }
            WorkControlCommand::NewGeneration { .. } => WORK_GENERATION_RESET,
            WorkControlCommand::RepairResource { .. } => WORK_RESOURCE_REPAIR,
            WorkControlCommand::ConfigureBudget { .. } => WORK_BUDGET_CONFIGURE,
            WorkControlCommand::ConfigureResource { .. } => WORK_RESOURCE_CONFIGURE,
        };
        let mut decision =
            crate::audit::Decision::new(operation, Some(authorization), Some(caller.credential()));
        let result = self
            .service
            .administer(async |store, now| {
                store.check_authority()?;
                decision.observe(store.state().authority(), Some(caller), now);
                let authority = store.state().authority();
                authority.authorize_caller(
                    caller,
                    authorization,
                    &Operation::named(operation)?.permission(authority.authority(), None)?,
                    now,
                )?;
                let (mutation, reply) = match command {
                    WorkControlCommand::ConfigureResource { policy } => {
                        let definition = self.resource(&policy)?.clone();
                        let resource = definition.resource;
                        let revision = definition.revision;
                        let mutation = WorkMutation::Resource(Box::new(definition));
                        (
                            mutation,
                            ChangeReply::Ready(WorkControlReply::ResourceChanged {
                                resource,
                                revision,
                            }),
                        )
                    }
                    WorkControlCommand::Catalogue => {
                        return Ok(WorkControlReply::Catalogue(
                            store.state().catalogue().cloned().collect(),
                        ));
                    }
                    WorkControlCommand::ConfigureBudget { definition } => {
                        let node = definition.node;
                        let revision = definition.revision;
                        let mutation = WorkMutation::Budget(definition);
                        (
                            mutation,
                            ChangeReply::Ready(WorkControlReply::BudgetChanged { node, revision }),
                        )
                    }
                    WorkControlCommand::InspectBudget { node } => {
                        return budget_status(store, node, now);
                    }
                    WorkControlCommand::List => {
                        return Ok(WorkControlReply::Allowances(
                            store
                                .state()
                                .grants()
                                .map(|g| summary(store, g))
                                .collect::<Result<_, _>>()?,
                        ));
                    }
                    WorkControlCommand::Inspect { id } => {
                        return Ok(WorkControlReply::Status {
                            allowance: summary(
                                store,
                                store.state().grant(id).ok_or(GrantError::Unauthorized)?,
                            )?,
                            now,
                            nodes: store.allowances(id, true, now)?,
                        });
                    }
                    WorkControlCommand::Offers { id } => {
                        let offers = store
                            .state()
                            .grants()
                            .filter(|g| id.is_none_or(|id| id == g.id) && g.enabled)
                            .map(|g| {
                                store.offer(
                                    g.id,
                                    &self.service.signer,
                                    self.service.addresses.as_ref().clone(),
                                    now,
                                )
                            })
                            .collect::<Result<_, _>>()?;
                        return Ok(WorkControlReply::Offers(offers));
                    }
                    WorkControlCommand::Create { id, terms } => {
                        if store.state().grant(id).is_some() {
                            return Err(GrantError::Malformed.into());
                        }
                        let definition = self.definition((id, Revision(1)), terms, store)?;
                        let mutation = WorkMutation::Define(Box::new(definition));
                        (mutation, ChangeReply::Allowance(id))
                    }
                    WorkControlCommand::Revise {
                        id,
                        expected_revision,
                        terms,
                    } => {
                        let old = existing(store, id, expected_revision)?;
                        let definition = self.definition(
                            (id, old.revision.next().ok_or(GrantError::StateCapacity)?),
                            terms,
                            store,
                        )?;
                        let mutation = WorkMutation::Define(Box::new(definition));
                        (mutation, ChangeReply::Allowance(id))
                    }
                    WorkControlCommand::NewGeneration {
                        id,
                        expected_generation,
                    } => {
                        let mutation = WorkMutation::Generation {
                            id,
                            expected: expected_generation,
                        };
                        (mutation, ChangeReply::Allowance(id))
                    }
                    WorkControlCommand::InspectResource { policy } => {
                        return self.resource_status(store, &policy);
                    }
                    WorkControlCommand::RepairResource {
                        policy,
                        expected_revision,
                    } => {
                        let resource = configured_resource(store, &policy)?.resource;
                        let mutation = WorkMutation::Repair {
                            resource,
                            expected: expected_revision,
                        };
                        (mutation, ChangeReply::ResourceHealth(policy))
                    }
                };
                store
                    .commit_work(caller, authorization, mutation, now)
                    .await?;
                match reply {
                    ChangeReply::Ready(reply) => Ok(reply),
                    ChangeReply::ResourceHealth(policy) => self.resource_status(store, &policy),
                    ChangeReply::Allowance(id) => Ok(WorkControlReply::Changed {
                        id,
                        revision: store
                            .state()
                            .grant(id)
                            .ok_or(GrantError::Unauthorized)?
                            .revision,
                        generation: store
                            .state()
                            .generation(id)
                            .ok_or(NodeStoreError::Malformed)?,
                    }),
                }
            })
            .await;
        decision.finish(result)
    }

    fn resource(&self, name: &str) -> Result<&GrantPolicy, GrantError> {
        self.resources
            .iter()
            .find(|p| p.name == name)
            .ok_or(GrantError::OutOfScope)
    }
    fn resource_status(
        &self,
        store: &NodeStore,
        name: &str,
    ) -> Result<WorkControlReply, NodeStoreError> {
        let health = store
            .state()
            .resource_health(configured_resource(store, name)?.resource)
            .ok_or(GrantError::OutOfScope)?;
        Ok(WorkControlReply::Resource {
            revision: health.revision,
            consecutive_faults: health.consecutive_faults,
            quarantined: health.quarantined,
        })
    }
    fn definition(
        &self,
        identity: (GrantId, Revision),
        terms: AllowanceTerms,
        store: &NodeStore,
    ) -> Result<GrantDef, NodeStoreError> {
        let (id, revision) = identity;
        if terms.policies.len() > MAX_WORK_POLICIES || terms.max_job_millis > self.max_job_millis {
            return Err(GrantError::Limits.into());
        }
        let policies = terms
            .policies
            .iter()
            .map(|name| configured_resource(store, name).cloned())
            .collect::<Result<_, _>>()?;
        let definition = GrantDef {
            id,
            revision,
            policies,
            budget: terms.budget,
            max_job_millis: terms.max_job_millis,
            allow_account_backed: terms.allow_account_backed,
            enabled: terms.enabled,
        };
        definition.validate()?;
        Ok(definition)
    }
}
fn existing(
    store: &NodeStore,
    id: GrantId,
    expected: Revision,
) -> Result<GrantDef, NodeStoreError> {
    let definition = store.state().grant(id).ok_or(GrantError::Unauthorized)?;
    if definition.revision != expected {
        return Err(GrantError::Revision(definition.revision).into());
    }
    Ok(definition.clone())
}
fn budget_status(
    store: &NodeStore,
    node: budget::BudgetNode,
    now: UnixMillis,
) -> Result<WorkControlReply, NodeStoreError> {
    Ok(WorkControlReply::Budget {
        definition: store
            .state()
            .ledger()
            .definition(node)
            .ok_or(GrantError::OutOfScope)?,
        now,
        allowance: store.allowance(node, now)?,
    })
}
fn summary(store: &NodeStore, g: &GrantDef) -> Result<AllowanceSummary, NodeStoreError> {
    Ok(AllowanceSummary {
        id: g.id,
        budget: g.budget,
        revision: g.revision,
        policies: g.policies.iter().map(|p| p.name.clone()).collect(),
        enabled: g.enabled,
        generation: store
            .state()
            .generation(g.id)
            .ok_or(NodeStoreError::Malformed)?,
    })
}

fn configured_resource<'a>(
    store: &'a NodeStore,
    name: &str,
) -> Result<&'a GrantPolicy, GrantError> {
    store
        .state()
        .catalogue()
        .find(|p| p.name == name)
        .ok_or(GrantError::OutOfScope)
}

#[cfg(test)]
mod tests;
