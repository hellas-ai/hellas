//! The mounted Work/Host operations and their exact authority resource scopes.
use crate::{
    grant_service, node,
    work_store::grant::{self, State},
};
use hellas_auth::authority::*;

#[derive(Clone, Copy)]
pub enum Scope {
    Host,
    Machine,
    Allowance,
}
#[derive(Clone, Copy)]
pub enum Mount {
    Host,
    Machine,
    Work,
}

pub struct Operation {
    pub name: &'static str,
    pub scope: Scope,
    pub mount: Mount,
}

pub const OPERATIONS: &[Operation] = &[
    Operation::new(node::HOST_STATUS, Scope::Host, Mount::Host),
    Operation::new(node::HOST_PROVIDER_CONFIGURE, Scope::Host, Mount::Host),
    Operation::new(node::HOST_PROVIDER_BIND, Scope::Host, Mount::Host),
    Operation::new(node::HOST_GATEWAY_CONFIGURE, Scope::Host, Mount::Host),
    Operation::new(node::HOST_GATEWAY_ACCESS, Scope::Host, Mount::Host),
    Operation::new(node::GATEWAY_INVOKE, Scope::Host, Mount::Host),
    Operation::new(
        node::WORK_CAPACITY_CONFIGURE,
        Scope::Machine,
        Mount::Machine,
    ),
    Operation::new(grant::WORK_ALLOWANCE_READ, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_ALLOWANCE_CONFIGURE, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_BUDGET_CONFIGURE, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_OFFER_EXPORT, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_GENERATION_RESET, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_RESOURCE_CONFIGURE, Scope::Machine, Mount::Work),
    Operation::new(grant::WORK_RESOURCE_REPAIR, Scope::Machine, Mount::Work),
    Operation::new(
        grant::WORK_PAID_POLICY_CONFIGURE,
        Scope::Machine,
        Mount::Work,
    ),
    Operation::new(grant_service::WORK_EXECUTE, Scope::Allowance, Mount::Work),
];
impl Operation {
    const fn new(name: &'static str, scope: Scope, mount: Mount) -> Self {
        Self { name, scope, mount }
    }
    pub fn named(name: &str) -> Result<&'static Self, AuthorityError> {
        OPERATIONS
            .iter()
            .find(|op| op.name == name)
            .ok_or(AuthorityError::Denied)
    }
    pub fn permission(
        &self,
        authority: AuthorityId,
        allowance: Option<GrantId>,
    ) -> Result<Permission, AuthorityError> {
        let resource = match self.scope {
            Scope::Host => node::host_resource(authority),
            Scope::Machine => node::machine_resource(authority),
            Scope::Allowance => grant_service::allowance_resource(
                authority,
                allowance.ok_or(AuthorityError::Denied)?,
            ),
        };
        if allowance.is_some() && !matches!(self.scope, Scope::Allowance) {
            return Err(AuthorityError::Denied);
        }
        Ok(Permission {
            operation: OperationId::new(self.name)?,
            resource,
        })
    }
    fn mounted(&self, state: &State) -> bool {
        match self.mount {
            Mount::Host => true,
            Mount::Machine => {
                state.provider().is_ok()
                    || state
                        .ledger()
                        .node(crate::model::grant::budget::BudgetNode::Machine)
                        .is_some()
            }
            Mount::Work => state.provider().is_ok(),
        }
    }
    fn resources(&self, state: &State) -> impl Iterator<Item = ResourceId> {
        let authority = state.authority().authority();
        let fixed = self.permission(authority, None).ok().map(|p| p.resource);
        fixed.into_iter().chain(
            state
                .grants()
                .filter(|_| matches!(self.scope, Scope::Allowance))
                .map(move |g| grant_service::allowance_resource(authority, g.id)),
        )
    }
}

// Only mounted, typed operations may be granted. Implementations still validate
// settings at the effect point; accepting a name creates no execution bypass.
pub(crate) fn validate_scope(state: &State, scope: &GrantSpec) -> Result<(), AuthorityError> {
    let authority = state.authority().authority();
    let authority_operations = [
        GRANT_ISSUE,
        GRANT_REVOKE,
        GRANT_ADMINISTER,
        CREDENTIAL_ISSUE,
        CREDENTIAL_REVOKE,
    ];
    let mounted = || OPERATIONS.iter().filter(|op| op.mounted(state));
    let valid = |p: &Permission| {
        (authority_operations.contains(&p.operation.as_str()) && p.resource == authority.resource())
            || mounted().any(|op| {
                op.name == p.operation.as_str() && op.resources(state).any(|r| r == p.resource)
            })
    };
    let known_resource = |id: &ResourceId| {
        *id == authority.resource() || mounted().any(|op| op.resources(state).any(|r| r == *id))
    };
    if scope.authority != authority || scope.permissions.iter().any(|p| !valid(p)) {
        return Err(AuthorityError::Denied);
    }
    if let Some(ceiling) = &scope.issuance {
        let known_resources = match &ceiling.resources {
            CeilingResources::Authority => true,
            CeilingResources::Named(ids) => ids.iter().all(known_resource),
        };
        if !known_resources
            || ceiling.operations.iter().any(|op| {
                !authority_operations.contains(&op.as_str())
                    && !mounted().any(|entry| entry.name == op.as_str())
            })
        {
            return Err(AuthorityError::Denied);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
