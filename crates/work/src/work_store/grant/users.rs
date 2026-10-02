use super::{
    GrantStore, GrantStoreError,
    state::{Change, State},
};
use hellas_rpc::protocol::work_grant::{
    admin::{User, UserPermissions},
    records::*,
    *,
};

impl State {
    pub(super) fn validate_user(&self, user: &User) -> Result<(), GrantStoreError> {
        let id = user.principal.id();
        // A vouched transport key must identify exactly one journal principal.
        if self.users().any(|old| {
            old.principal.id() != id && old.principal.transport() == user.principal.transport()
        }) {
            return Err(GrantError::Audience.into());
        }
        if user.permissions == UserPermissions::Owner
            && (user.principal.transport() != self.provider().grant_transport()?
                || user.principal.producer() != self.provider().grant_producer()?)
        {
            return Err(GrantError::Audience.into());
        }
        Ok(())
    }
    pub(super) fn apply_user(&mut self, user: &User) -> Result<(), GrantStoreError> {
        self.validate_user(user)?;
        if let Some(old) = self.user(user.principal.id()) {
            if (old.permissions == UserPermissions::Owner
                && user.permissions != UserPermissions::Owner)
                || old.principal != user.principal
                || user.revision.0
                    != old
                        .revision
                        .0
                        .checked_add(1)
                        .ok_or(GrantError::StateCapacity)?
            {
                return Err(GrantError::Revision(old.revision).into());
            }
        } else if user.revision != Revision(1) || self.users.len() >= 256 {
            return Err(GrantError::StateCapacity.into());
        }
        self.users.insert(user.principal.id(), user.clone());
        Ok(())
    }
}
impl GrantStore {
    /// The host binds a software contact for its own keys, independently of its
    /// provider's platform attestation. Reopening cannot change this identity.
    pub fn bind_owner(
        &mut self,
        principal: Principal,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        if self
            .state()
            .user(principal.id())
            .is_some_and(|u| u.permissions == UserPermissions::Owner)
        {
            return Ok(());
        }
        self.commit(
            now,
            Change::User {
                user: User {
                    principal,
                    revision: Revision(1),
                    permissions: UserPermissions::Owner,
                },
                grants: vec![],
            },
            true,
        )
    }
    pub(crate) fn set_user(
        &mut self,
        user: User,
        grants: Vec<GrantDef>,
        now: UnixMillis,
    ) -> Result<(), GrantStoreError> {
        self.commit(now, Change::User { user, grants }, true)
    }
}
