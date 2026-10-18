//! The first checked host read and Work setting. No transport or owner shortcuts.
use super::*;
use crate::model::grant::budget::{BudgetNode, Limit};
use crate::operations::Operation;
use crate::work_store::grant::State;
use hellas_auth::hash_tuple;
use std::num::NonZeroU16;

pub const HOST_STATUS: &str = "host.status";
pub const HOST_PROVIDER_CONFIGURE: &str = "host.provider.configure";
pub const HOST_GATEWAY_CONFIGURE: &str = "host.gateway.configure";
pub const HOST_GATEWAY_ACCESS: &str = "host.gateway.access";
pub const GATEWAY_INVOKE: &str = "gateway.invoke";
pub const WORK_CAPACITY_CONFIGURE: &str = "work.capacity.configure";

pub fn host_resource(authority: AuthorityId) -> ResourceId {
    ResourceId(hash_tuple(
        "hellas.host.resource.v1",
        &[authority.0.as_bytes()],
    ))
}

pub fn machine_resource(authority: AuthorityId) -> ResourceId {
    ResourceId(hash_tuple(
        "hellas.work.machine.v1",
        &[authority.0.as_bytes()],
    ))
}

/// Persisted machine-wide concurrency and budgets. Changes retain usage and duties.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineCapacity {
    pub revision: Revision,
    pub max_in_flight: NonZeroU16,
    pub limits: Vec<Limit>,
}

/// Private node status; even a providerless node requires an explicit read grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub authority: AuthorityId,
    pub authority_revision: Revision,
    pub generation: u64,
    pub provider_configured: bool,
    pub machine: Option<MachineCapacity>,
}

impl NodeCoordinator {
    /// HTTP admission accepts only a self-issued credential restricted to this
    /// operation. An administrator credential must never become an HTTP bearer.
    pub async fn authorize_gateway(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
    ) -> Result<(), NodeStoreError> {
        self.checked(caller, authorization, GATEWAY_INVOKE, async |store, now| {
            let authority = store.state().authority();
            let permission =
                Operation::named(GATEWAY_INVOKE)?.permission(authority.authority(), None)?;
            authority.authorize_caller(caller, authorization, &permission, now)?;
            let credential = authority
                .credential(caller.credential())
                .ok_or(AuthorityError::Denied)?;
            let scope = credential.scope();
            if !credential.bearer()
                || scope.issuance.is_some()
                || scope.delegation_depth != 0
                || scope.permissions.len() != 1
                || !scope.permissions.contains(&permission)
            {
                return Err(AuthorityError::Denied.into());
            }
            Ok(())
        })
        .await
    }

    pub async fn status(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
    ) -> Result<NodeStatus, NodeStoreError> {
        self.host_action(caller, authorization, HOST_STATUS, |status| status)
            .await
    }

    /// Check the exact host right and perform a synchronous read or enqueue at
    /// the same writer boundary. Network startup and shutdown run outside it.
    pub async fn host_action<T>(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        operation: &'static str,
        action: impl FnOnce(NodeStatus) -> T,
    ) -> Result<T, NodeStoreError> {
        if !matches!(
            operation,
            HOST_STATUS | HOST_PROVIDER_CONFIGURE | HOST_GATEWAY_CONFIGURE | HOST_GATEWAY_ACCESS
        ) {
            return Err(AuthorityError::Denied.into());
        }
        self.checked(caller, authorization, operation, async |store, now| {
            let state = store.state();
            let authority = state.authority();
            authority.authorize_caller(
                caller,
                authorization,
                &Operation::named(operation)?.permission(authority.authority(), None)?,
                now,
            )?;
            Ok(action(NodeStatus {
                authority: authority.authority(),
                authority_revision: authority.revision(),
                generation: authority.generation(),
                provider_configured: state.provider().is_ok(),
                machine: state.machine_capacity()?,
            }))
        })
        .await
    }

    /// Replaces machine concurrency and budgets, preserving counters and held work.
    /// Revision zero explicitly initializes an unconfigured provider machine.
    /// The expected revision makes lost replies reconcilable without blind retries.
    pub async fn set_machine_capacity(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        expected: Revision,
        max_in_flight: u16,
        limits: Vec<Limit>,
    ) -> Result<MachineCapacity, NodeStoreError> {
        let _changed = ChangeNotification(self.changed.clone());
        self.checked(
            caller,
            authorization,
            WORK_CAPACITY_CONFIGURE,
            async |store, now| {
                let authority = store.state().authority();
                authority.authorize_caller(
                    caller,
                    authorization,
                    &Operation::named(WORK_CAPACITY_CONFIGURE)?
                        .permission(authority.authority(), None)?,
                    now,
                )?;
                store
                    .commit_work(
                        caller,
                        authorization,
                        crate::work_store::grant::WorkMutation::Capacity {
                            expected,
                            max_in_flight,
                            limits,
                        },
                        now,
                    )
                    .await?;
                store
                    .state()
                    .machine_capacity()?
                    .ok_or(NodeStoreError::MissingMachine)
            },
        )
        .await
    }
}

impl State {
    pub(crate) fn machine_capacity(&self) -> Result<Option<MachineCapacity>, NodeStoreError> {
        self.ledger()
            .node(BudgetNode::Machine)
            .map(|node| {
                Ok(MachineCapacity {
                    revision: self.machine_revision,
                    limits: node.limits().to_vec(),
                    max_in_flight: NonZeroU16::new(node.concurrent())
                        .ok_or(NodeStoreError::Malformed)?,
                })
            })
            .transpose()
    }
}
