use super::{
    GrantDef, GrantError, GrantId, GrantKind, GrantPolicy, GrantService, GrantState, GrantStore,
    GrantStoreError, Revision, UnixMillis,
};
use hellas_rpc::protocol::work_grant::{
    PrincipalId,
    admin::{
        GrantCommand, GrantReply, GrantSummary, GrantTerms, User, UserCommand, UserPermissions,
        UserStatus, UserSummary, UserWork,
    },
};
use std::num::NonZeroU64;

impl GrantService {
    /// Host-owned administration; network callers use `control_as`.
    pub fn control(
        &self,
        command: GrantCommand,
        resources: &[GrantPolicy],
        max_job_millis: NonZeroU64,
    ) -> Result<GrantReply, GrantStoreError> {
        self.control_as(
            command,
            resources,
            max_job_millis,
            &hellas_wire::TransportContext {
                auth_level: hellas_wire::AuthLevel::LocalOwner,
                ..Default::default()
            },
        )
    }
    pub fn control_as(
        &self,
        command: GrantCommand,
        resources: &[GrantPolicy],
        max_job_millis: NonZeroU64,
        context: &hellas_wire::TransportContext,
    ) -> Result<GrantReply, GrantStoreError> {
        self.administer(|store, now| {
            if !store.state().allows_admin(context) {
                return Err(GrantError::Unauthorized.into());
            }
            store.tick(now)?;
            let id = match command {
                GrantCommand::Users(UserCommand::Offer { id, grant }) => {
                    let user = store.state().user(id).ok_or(GrantError::Unauthorized)?;
                    if !user.is_active()
                        || store.state().grant(grant).is_none_or(|g| {
                            g.kind.principal().id() != id || g.state == GrantState::Revoked
                        })
                    {
                        return Err(GrantError::Unauthorized.into());
                    }
                    grant
                }
                GrantCommand::Users(command) => {
                    return users(store, now, command, resources, max_job_millis);
                }
                GrantCommand::Inspect { id } => id,
                GrantCommand::NewGeneration {
                    id,
                    expected_revision,
                } => {
                    existing(store, id, expected_revision)?;
                    store.bump_generation(id, now)?;
                    id
                }
                GrantCommand::RepairResource { policy } => {
                    let policy = resources
                        .iter()
                        .find(|p| p.name == policy)
                        .ok_or(GrantError::OutOfScope)?;
                    store.repair_resource(policy.resource_id()?, now)?;
                    return Ok(GrantReply::Repaired);
                }
            };
            Ok(GrantReply::Status {
                offer: Box::new(store.offer(id, &self.signer, self.addresses.as_ref().clone())?),
                now: store.state().now(),
                nodes: store.allowances(id, true)?,
            })
        })
    }
}
fn existing(
    store: &GrantStore,
    id: GrantId,
    expected: Revision,
) -> Result<GrantDef, GrantStoreError> {
    let definition = store.state().grant(id).ok_or(GrantError::Unauthorized)?;
    if definition.revision != expected {
        return Err(GrantError::Revision(definition.revision).into());
    }
    Ok(definition.clone())
}
fn next_revision(revision: Revision) -> Result<Revision, GrantStoreError> {
    Ok(Revision(
        revision.0.checked_add(1).ok_or(GrantError::StateCapacity)?,
    ))
}
fn summary(store: &GrantStore, g: &GrantDef) -> GrantSummary {
    GrantSummary {
        id: g.id,
        principal: g.kind.principal().id(),
        owner: matches!(g.kind, GrantKind::Owner(_)),
        revision: g.revision,
        state: g.state,
        policies: g.policies.iter().map(|p| p.name.clone()).collect(),
        expires: g.expires,
        generation: store.state().generation(g.id).expect("grant has channel"),
    }
}
fn user_status(store: &GrantStore, id: PrincipalId) -> Result<GrantReply, GrantStoreError> {
    let user = store
        .state()
        .user(id)
        .ok_or(GrantError::Unauthorized)?
        .clone();
    Ok(GrantReply::User(Box::new(UserStatus {
        user,
        grants: store
            .state()
            .grants()
            .filter(|g| g.kind.principal().id() == id)
            .map(|g| summary(store, g))
            .collect(),
    })))
}
fn users(
    store: &mut GrantStore,
    now: UnixMillis,
    command: UserCommand,
    resources: &[GrantPolicy],
    maximum: NonZeroU64,
) -> Result<GrantReply, GrantStoreError> {
    let (mut user, work, remove) = match command {
        UserCommand::List => {
            return Ok(GrantReply::Users(
                store
                    .state()
                    .users()
                    .map(|u| UserSummary {
                        id: u.principal.id(),
                        revision: u.revision,
                        permissions: u.permissions.clone(),
                        grants: store
                            .state()
                            .grants()
                            .filter(|g| g.kind.principal().id() == u.principal.id())
                            .count(),
                    })
                    .collect(),
            ));
        }
        UserCommand::Show { id } => return user_status(store, id),
        UserCommand::Add {
            principal,
            expected_revision,
            admin,
            work,
        } => {
            let revision = match (store.state().user(principal.id()), expected_revision) {
                (None, None) => Revision(1),
                (Some(old), Some(expected)) if !old.is_active() && old.revision == expected => {
                    next_revision(expected)?
                }
                _ => return Err(GrantError::Unauthorized.into()),
            };
            (
                User {
                    principal: *principal,
                    revision,
                    permissions: UserPermissions::Active { admin },
                },
                work.map(|(id, terms)| UserWork::Create { id, terms }),
                false,
            )
        }
        UserCommand::Update {
            id,
            expected_revision,
            admin,
            work,
        } => {
            let mut user = checked_user(store, id, expected_revision)?;
            match &mut user.permissions {
                UserPermissions::Owner if admin.is_some() => {
                    return Err(GrantError::Unauthorized.into());
                }
                UserPermissions::Active { admin: permission } => {
                    if let Some(value) = admin {
                        *permission = value;
                    }
                }
                _ => {}
            }
            // Owner permissions are implicit; changing its Work terms is still allowed.
            if user.permissions == UserPermissions::Owner && work.is_none() {
                return user_status(store, id);
            }
            (user, work, false)
        }
        UserCommand::Remove {
            id,
            expected_revision,
        } => {
            let mut user = checked_user(store, id, expected_revision)?;
            if user.permissions == UserPermissions::Owner {
                return Err(GrantError::Unauthorized.into());
            }
            user.permissions = UserPermissions::Removed;
            (user, None, true)
        }
        UserCommand::Offer { .. } => unreachable!("offer is handled with the signer"),
    };
    let mut definitions = vec![];
    if remove {
        for g in store.state().grants().filter(|g| {
            g.kind.principal().id() == user.principal.id() && g.state != GrantState::Revoked
        }) {
            let mut g = g.clone();
            g.revision = next_revision(g.revision)?;
            g.state = GrantState::Revoked;
            definitions.push(g);
        }
    }
    if let Some(work) = work {
        definitions.push(match work {
            UserWork::Create { id, terms } => {
                if store.state().grant(id).is_some() {
                    return Err(GrantError::Malformed.into());
                }
                terms.definition(
                    id,
                    Revision(1),
                    GrantKind::Principal(user.principal.clone()),
                    GrantState::Active,
                    resources,
                    maximum,
                    now,
                )?
            }
            UserWork::Revise {
                id,
                expected_revision,
                terms,
                keep_expiry,
            } => {
                let old = existing(store, id, expected_revision)?;
                if old.kind.principal() != &user.principal {
                    return Err(GrantError::Audience.into());
                }
                let mut def = terms.definition(
                    id,
                    next_revision(old.revision)?,
                    old.kind,
                    old.state,
                    resources,
                    maximum,
                    now,
                )?;
                if keep_expiry {
                    def.expires = old.expires;
                }
                def
            }
            UserWork::SetState {
                id,
                expected_revision,
                state,
            } => {
                let mut def = existing(store, id, expected_revision)?;
                if def.kind.principal() != &user.principal {
                    return Err(GrantError::Audience.into());
                }
                def.revision = next_revision(def.revision)?;
                def.state = state;
                def
            }
        });
    }
    if let Some(old) = store.state().user(user.principal.id()) {
        user.revision = next_revision(old.revision)?;
    }
    let id = user.principal.id();
    store.set_user(user, definitions, now)?;
    user_status(store, id)
}
fn checked_user(
    store: &GrantStore,
    id: PrincipalId,
    revision: Revision,
) -> Result<User, GrantStoreError> {
    let user = store.state().user(id).ok_or(GrantError::Unauthorized)?;
    if user.revision != revision {
        return Err(GrantError::Revision(user.revision).into());
    }
    if !user.is_active() {
        return Err(GrantError::Revoked.into());
    }
    Ok(user.clone())
}
trait Definition {
    #[allow(clippy::too_many_arguments)]
    fn definition(
        self,
        id: GrantId,
        revision: Revision,
        kind: GrantKind,
        state: GrantState,
        resources: &[GrantPolicy],
        maximum: NonZeroU64,
        now: UnixMillis,
    ) -> Result<GrantDef, GrantStoreError>;
}
impl Definition for GrantTerms {
    fn definition(
        self,
        id: GrantId,
        revision: Revision,
        kind: GrantKind,
        state: GrantState,
        resources: &[GrantPolicy],
        maximum: NonZeroU64,
        now: UnixMillis,
    ) -> Result<GrantDef, GrantStoreError> {
        if self.policies.len() > 16 || self.max_job_millis > maximum {
            return Err(GrantError::Limits.into());
        }
        let policies = self
            .policies
            .iter()
            .map(|name| {
                resources
                    .iter()
                    .find(|p| &p.name == name)
                    .cloned()
                    .ok_or(GrantError::OutOfScope)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let definition = GrantDef {
            id,
            revision,
            kind,
            state,
            policies,
            limits: self.limits,
            max_job_millis: self.max_job_millis,
            max_in_flight: self.max_in_flight,
            allow_account_backed: self.allow_account_backed,
            expires: self
                .expires_in_millis
                .map(|n| {
                    now.0
                        .checked_add(n.get())
                        .map(UnixMillis)
                        .ok_or(GrantError::Limits)
                })
                .transpose()?,
        };
        definition.validate()?;
        Ok(definition)
    }
}
