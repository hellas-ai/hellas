//! Body-free decision events. The host's configured log sink owns their retention;
//! successful mutations retain their separate atomic journal audit records.
use crate::work_store::grant::NodeStoreError;
use hellas_auth::authority::{
    AuthenticatedCaller, AuthorityError, AuthorityId, AuthorityState, CallerRecord, CredentialId,
    GrantId, Revision, UnixMillis,
};
use hellas_rpc::pb::work::{GrantRefusalCode, WorkRefused};

pub(crate) struct Decision {
    action: &'static str,
    authorization: Option<GrantId>,
    credential_claimed: Option<CredentialId>,
    authority: Option<AuthorityId>,
    generation: Option<u64>,
    revision: Option<Revision>,
    at: Option<UnixMillis>,
    caller: Option<CallerRecord>,
    outcome: &'static str,
    reason: &'static str,
}
impl Decision {
    pub(crate) fn new(
        action: &'static str,
        authorization: Option<GrantId>,
        credential_claimed: Option<CredentialId>,
    ) -> Self {
        Self {
            action,
            authorization,
            credential_claimed,
            authority: None,
            generation: None,
            revision: None,
            at: None,
            caller: None,
            outcome: "cancelled",
            reason: "request_dropped",
        }
    }
    pub(crate) fn observe(
        &mut self,
        authority: &AuthorityState,
        caller: Option<&AuthenticatedCaller>,
        now: UnixMillis,
    ) {
        self.authority = Some(authority.authority());
        self.generation = Some(authority.generation());
        self.revision = Some(authority.revision());
        self.at = Some(now);
        if let Some(caller) = caller {
            self.credential_claimed.get_or_insert(caller.credential());
        }
        // A failed request can carry a caller minted by another authority, or
        // stale/forged evidence. Only this authority's current proof permits attribution.
        self.caller = caller.and_then(|caller| authority.record_caller(caller, now).ok());
    }
    pub(crate) fn finish<T>(
        mut self,
        result: Result<T, NodeStoreError>,
    ) -> Result<T, NodeStoreError> {
        (self.outcome, self.reason) = match &result {
            Ok(_) => ("allowed", "ok"),
            Err(NodeStoreError::Authority(error)) => (
                "denied",
                match error {
                    AuthorityError::Audience => "authority_mismatch",
                    AuthorityError::Denied => "permission_denied",
                    AuthorityError::Credential => "credential_invalid",
                    AuthorityError::StepUp => "passkey_required",
                    AuthorityError::Missing => "grant_missing",
                    AuthorityError::Revoked => "grant_revoked",
                    AuthorityError::Expired => "expired",
                    AuthorityError::Revision => "stale_revision",
                    AuthorityError::Duplicate => "duplicate",
                    AuthorityError::Capacity => "authority_capacity",
                    AuthorityError::Clock => "clock_rollback",
                    AuthorityError::Entropy => "randomness_unavailable",
                    AuthorityError::Invalid => "invalid_scope",
                },
            ),
            Err(NodeStoreError::ClockJump) => ("unavailable", "clock_jump"),
            Err(NodeStoreError::Grant(_)) => ("denied", "work_policy"),
            Err(NodeStoreError::Ledger(_)) => ("denied", "budget_policy"),
            Err(NodeStoreError::Resource(_)) => ("denied", "resource_policy"),
            Err(NodeStoreError::Input(_) | NodeStoreError::Malformed) => {
                ("denied", "invalid_request")
            }
            Err(_) => ("unavailable", "service_unavailable"),
        };
        result
    }
    pub(crate) fn finish_work<T>(
        mut self,
        result: Result<T, WorkRefused>,
    ) -> Result<T, WorkRefused> {
        (self.outcome, self.reason) = match &result {
            Ok(_) => ("allowed", "ok"),
            Err(refusal) => {
                let code = refusal
                    .grant
                    .as_ref()
                    .and_then(|grant| GrantRefusalCode::try_from(grant.code).ok());
                (
                    if code == Some(GrantRefusalCode::StorageUnavailable) {
                        "unavailable"
                    } else {
                        "denied"
                    },
                    code.map_or("work_refused", |code| code.as_str_name()),
                )
            }
        };
        result
    }
}
impl Drop for Decision {
    fn drop(&mut self) {
        macro_rules! emit {
            ($level:expr) => {
                tracing::event!(target: "hellas_authority_audit", $level,
                    action = self.action, outcome = self.outcome, reason = self.reason,
                    authority = ?self.authority, generation = ?self.generation,
                    revision = ?self.revision, at = ?self.at,
                    authorization = ?self.authorization,
                    credential_claimed = ?self.credential_claimed,
                    verified = self.caller.is_some(),
                    actor = ?self.caller.as_ref().map(CallerRecord::actor),
                    credential_revision = ?self.caller.as_ref().map(CallerRecord::credential_revision),
                    "authority decision");
            }
        }
        if self.outcome == "allowed" {
            emit!(tracing::Level::INFO);
        } else {
            emit!(tracing::Level::WARN);
        }
    }
}

#[cfg(test)]
mod tests;
