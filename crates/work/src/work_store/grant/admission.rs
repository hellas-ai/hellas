//! Persisted execution authority is audit data, never a reusable permission.
use super::{NodeStoreError, State};
use crate::model::grant::{
    GrantJobAuthorizationV1,
    budget::{Charge, Meter},
};
use hellas_auth::authority::UnixMillis;
use hellas_auth::authority::{
    AuthenticatedCaller, CallerRecord, GrantId, MAX_DELEGATION_DEPTH, Permission, Revision,
};
use serde::{Deserialize, Serialize};

/// The exact caller and live grant lineage checked for one journal transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRecord {
    caller: CallerRecord,
    lineage: Vec<(GrantId, Revision)>,
}
impl ExecutionRecord {
    pub fn caller(&self) -> &CallerRecord {
        &self.caller
    }
    pub fn lineage(&self) -> &[(GrantId, Revision)] {
        &self.lineage
    }

    pub(super) fn capture(
        state: &State,
        application: (&AuthenticatedCaller, GrantId),
        allowance: GrantId,
        now: UnixMillis,
    ) -> Result<Self, NodeStoreError> {
        let (caller, grant) = application;
        let permission = permission(state, allowance)?;
        let lineage = state
            .authority
            .authorize_caller(caller, grant, &permission, now)?;
        Ok(Self {
            caller: state.authority.record_caller(caller, now)?,
            lineage,
        })
    }
    pub(super) fn replay(
        &self,
        state: &State,
        allowance: GrantId,
        now: UnixMillis,
    ) -> Result<(), NodeStoreError> {
        let grant = self.lineage.first().ok_or(NodeStoreError::Malformed)?.0;
        if self.caller.at() != now
            || state.authority.authorize_recorded(
                &self.caller,
                grant,
                &permission(state, allowance)?,
            )? != self.lineage
        {
            return Err(NodeStoreError::Malformed);
        }
        Ok(())
    }
    pub(super) fn same_application(&self, other: &Self) -> bool {
        self.caller.authority() == other.caller.authority()
            && self.caller.generation() == other.caller.generation()
            && self.caller.actor() == other.caller.actor()
            && self.caller.credential() == other.caller.credential()
            && self.lineage.first().map(|g| g.0) == other.lineage.first().map(|g| g.0)
    }
    fn validate_history(&self, state: &State) -> Result<(), NodeStoreError> {
        // Recovery may have replaced authority or revoked every referenced credential.
        // A checkpoint retains the old evidence without turning it into live authority.
        if self.caller.authority() != state.authority.authority()
            || self.caller.generation() == 0
            || self.caller.generation() > state.authority.generation()
            || self.caller.before().0 == 0
            || self.caller.before() > state.authority.revision()
            || self.caller.credential_revision().0 == 0
            || self.caller.credential_revision() > self.caller.before()
            || self.caller.at() > state.now()
            || self.lineage.is_empty()
            || self.lineage.len() > usize::from(MAX_DELEGATION_DEPTH) + 1
            || self
                .lineage
                .iter()
                .any(|(_, revision)| revision.0 == 0 || *revision > self.caller.before())
            || !hellas_rpc::protocol::value::all_distinct(self.lineage.iter().map(|(id, _)| *id))
        {
            return Err(NodeStoreError::Malformed);
        }
        Ok(())
    }
}
fn permission(state: &State, allowance: GrantId) -> Result<Permission, NodeStoreError> {
    Ok(
        crate::operations::Operation::named(crate::grant_service::WORK_EXECUTE)?
            .permission(state.authority.authority(), Some(allowance))?,
    )
}

/// Provider-local metadata bound to the existing signed job identity. Its lifetime
/// follows that job and its terminal receipt; it contains no request or response body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRecord {
    pub(super) accepted: ExecutionRecord,
    pub(super) dispatched: Option<ExecutionRecord>,
    pub(super) reserved: Charge,
}
impl AdmissionRecord {
    pub fn accepted(&self) -> &ExecutionRecord {
        &self.accepted
    }
    pub fn dispatched(&self) -> Option<&ExecutionRecord> {
        self.dispatched.as_ref()
    }
    pub fn reserved(&self) -> Charge {
        self.reserved
    }
    pub(super) fn validate_history(
        &self,
        state: &State,
        a: &GrantJobAuthorizationV1,
        dispatched: bool,
    ) -> Result<(), NodeStoreError> {
        self.accepted.validate_history(state)?;
        if self.accepted.caller.at() > a.acceptance_deadline_ms
            || self.reserved.get(Meter::Requests) != 1
            || state
                .policy_for(a)?
                .pricing
                .reserve(self.reserved)
                .map_err(|_| NodeStoreError::Malformed)?
                != self.reserved
            || self.dispatched.is_some() != dispatched
        {
            return Err(NodeStoreError::Malformed);
        }
        if let Some(dispatch) = &self.dispatched {
            dispatch.validate_history(state)?;
            if !self.accepted.same_application(dispatch)
                || dispatch.caller.at() < self.accepted.caller.at()
                || dispatch.caller.at() > a.terminal_deadline_ms
                || dispatch.caller.before() < self.accepted.caller.before()
            {
                return Err(NodeStoreError::Malformed);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
