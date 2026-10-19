use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
mod administration;
mod credentials;
mod recovery;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityState {
    authority: AuthorityId,
    revision: Revision,
    now: UnixMillis,
    root_grant: GrantId,
    generation: u64,
    last_recovery: Option<RecoveryRecord>,
    grants: BTreeMap<GrantId, Grant>,
    credentials: BTreeMap<CredentialId, Credential>,
}

/// Hosts bound the encoded bytes before decoding and validate with `restore`.
/// A snapshot is persisted state, never authority supplied by a remote caller.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    pub(super) authority: AuthorityId,
    pub(super) revision: Revision,
    pub(super) now: UnixMillis,
    pub(super) root_grant: GrantId,
    pub(super) generation: u64,
    pub(super) last_recovery: Option<RecoveryRecord>,
    pub(super) grants: Vec<Grant>,
    pub(super) credentials: Vec<Credential>,
}

impl AuthorityState {
    pub fn apply(
        &mut self,
        actor: PrincipalId,
        command: &GrantCommand,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        match command {
            GrantCommand::Issue {
                authorization,
                id,
                spec,
            } => self.issue(actor, *authorization, *id, spec.clone(), now),
            GrantCommand::Delegate { parent, id, spec } => {
                self.delegate(actor, *parent, *id, spec.clone(), now)
            }
            GrantCommand::Revise {
                authorization,
                id,
                expected,
                spec,
            } => self.revise(actor, *authorization, *id, *expected, spec.clone(), now),
            GrantCommand::Revoke {
                authorization,
                id,
                expected,
            } => self.revoke(actor, *authorization, *id, *expected, now),
        }
    }

    /// Used only by the host's explicit offline initialization of an empty store.
    /// Ordinary startup must restore existing state, never call this on failure.
    /// `owner` is the administrator's assertion over the bootstrap digest.
    pub fn bootstrap(
        id: GrantId,
        admin: GrantSpec,
        credential: Credential,
        owner: &PasskeyAssertion,
        now: UnixMillis,
    ) -> Result<Self, AuthorityError> {
        Self::validate_administrator(&admin, now)?;
        Self::validate_initial_credential(&admin, &credential, 1, now)?;
        Self::check_owner(
            Ownership::Bootstrap { root: id },
            &admin,
            &credential,
            owner,
        )?;
        Ok(Self {
            authority: admin.authority,
            revision: Revision(1),
            now,
            root_grant: id,
            generation: 1,
            last_recovery: None,
            credentials: [(credential.id, credential)].into(),
            grants: [(
                id,
                Grant {
                    id,
                    revision: Revision(1),
                    origin: GrantOrigin::Node {
                        issuer: admin.subject,
                    },
                    spec: admin,
                    revoked: false,
                },
            )]
            .into(),
        })
    }

    /// The administrator's passkey must approve the exact ownership change,
    /// including the node key that will hold the initial credential.
    fn check_owner(
        ownership: Ownership,
        admin: &GrantSpec,
        credential: &Credential,
        owner: &PasskeyAssertion,
    ) -> Result<(), AuthorityError> {
        let CredentialHolder::Node(holder) = credential.holder else {
            return Err(AuthorityError::Invalid);
        };
        owner
            .verify(
                admin.subject,
                ownership_digest(ownership, admin, &credential.scope, holder),
            )
            .map_err(|_| AuthorityError::Denied)
    }

    fn validate_administrator(admin: &GrantSpec, now: UnixMillis) -> Result<(), AuthorityError> {
        if !admin.validate()
            || admin.not_before > now
            || admin.expires <= now
            || ![
                GRANT_ISSUE,
                GRANT_REVOKE,
                GRANT_ADMINISTER,
                CREDENTIAL_ISSUE,
                CREDENTIAL_REVOKE,
            ]
            .iter()
            .all(|op| admin.has(op, admin.authority.resource()))
            || !admin
                .issuance
                .as_ref()
                .is_some_and(|c| c.covers(admin, now))
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }

    pub const fn authority(&self) -> AuthorityId {
        self.authority
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn now(&self) -> UnixMillis {
        self.now
    }
    /// Credentials and sessions must match this generation at every use.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn root_grant(&self) -> GrantId {
        self.root_grant
    }
    pub fn last_recovery(&self) -> Option<&RecoveryRecord> {
        self.last_recovery.as_ref()
    }
    pub fn grant(&self, id: GrantId) -> Option<&Grant> {
        self.grants.get(&id)
    }
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    pub fn snapshot(&self) -> AuthoritySnapshot {
        AuthoritySnapshot {
            authority: self.authority,
            revision: self.revision,
            now: self.now,
            root_grant: self.root_grant,
            generation: self.generation,
            last_recovery: self.last_recovery.clone(),
            grants: self.grants.values().cloned().collect(),
            credentials: self.credentials.values().cloned().collect(),
        }
    }

    pub fn restore(snapshot: AuthoritySnapshot) -> Result<Self, AuthorityError> {
        if snapshot.grants.is_empty() || snapshot.grants.len() > MAX_GRANTS {
            return Err(AuthorityError::Invalid);
        }
        if snapshot.credentials.is_empty() || snapshot.credentials.len() > MAX_CREDENTIALS {
            return Err(AuthorityError::Invalid);
        }
        let mut credentials = BTreeMap::new();
        for credential in snapshot.credentials {
            if credentials.insert(credential.id, credential).is_some() {
                return Err(AuthorityError::Invalid);
            }
        }
        let mut grants = BTreeMap::new();
        for grant in snapshot.grants {
            if grant.spec.authority != snapshot.authority
                || !grant.spec.validate()
                || grant.revision.0 == 0
                || grant.revision > snapshot.revision
                || grants.insert(grant.id, grant).is_some()
            {
                return Err(AuthorityError::Invalid);
            }
        }
        let state = Self {
            authority: snapshot.authority,
            revision: snapshot.revision,
            now: snapshot.now,
            root_grant: snapshot.root_grant,
            generation: snapshot.generation,
            last_recovery: snapshot.last_recovery,
            grants,
            credentials,
        };
        state.validate_recovery()?;
        for credential in state.credentials.values() {
            state.validate_credential(credential)?;
        }
        for id in state.grants.keys() {
            state.lineage(*id)?;
        }
        Ok(state)
    }

    /// Returns the exact current lineage revisions for the node's admission record.
    /// The coordinator rechecks this at dispatch/delivery; this is not a lease.
    pub fn authorize(
        &self,
        actor: PrincipalId,
        id: GrantId,
        permission: &Permission,
        now: UnixMillis,
    ) -> Result<Vec<(GrantId, Revision)>, AuthorityError> {
        let lineage = self.live_lineage(id, now)?;
        let grant = &self.grants[&id];
        if grant.spec.subject != actor || !grant.spec.permissions.contains(permission) {
            return Err(AuthorityError::Denied);
        }
        Ok(lineage
            .into_iter()
            .map(|id| (id, self.grants[&id].revision))
            .collect())
    }

    pub fn issue(
        &mut self,
        actor: PrincipalId,
        authorization: GrantId,
        id: GrantId,
        spec: GrantSpec,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_spec(&spec, now)?;
        self.administrator(actor, authorization, GRANT_ISSUE, &spec, now, true)?;
        self.check_self_assignment(actor, authorization, &spec)?;
        self.insert(id, spec, GrantOrigin::Node { issuer: actor }, now)
    }

    pub fn delegate(
        &mut self,
        actor: PrincipalId,
        parent: GrantId,
        id: GrantId,
        spec: GrantSpec,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_spec(&spec, now)?;
        let lineage = self.live_lineage(parent, now)?;
        let parent_spec = &self.grants[&parent].spec;
        if parent_spec.subject != actor
            || !spec.narrows(parent_spec)
            || lineage.len() > MAX_DELEGATION_DEPTH as usize
            || (spec.administrative()
                && !parent_spec.has(GRANT_ADMINISTER, self.authority.resource()))
        {
            return Err(AuthorityError::Denied);
        }
        // Future or temporarily narrowed descendants still occupy slots and can
        // become usable later. Only revoked or expired lineages release capacity.
        let assignment = lineage.last().copied().ok_or(AuthorityError::Invalid)?;
        let retained = self
            .grants
            .keys()
            .filter(|id| {
                !self.dead(**id, now)
                    && self
                        .lineage(**id)
                        .is_ok_and(|l| l.last() == Some(&assignment))
            })
            .count();
        if retained > MAX_DELEGATIONS {
            return Err(AuthorityError::Capacity);
        }
        self.insert(id, spec, GrantOrigin::Delegated { parent }, now)
    }

    /// Update an assignment without changing its origin or resetting its ID.
    /// Node grants remain independent of the original issuer's later privileges.
    pub fn revise(
        &mut self,
        actor: PrincipalId,
        authorization: GrantId,
        id: GrantId,
        expected: Revision,
        spec: GrantSpec,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_spec(&spec, now)?;
        let old = self.target(id, expected)?;
        self.administrator(actor, authorization, GRANT_ISSUE, &spec, now, true)?;
        self.check_self_assignment(actor, authorization, &spec)?;
        if old.spec.subject == actor {
            self.check_self_assignment(actor, authorization, &old.spec)?;
        }
        // Updating cannot use a small new scope to take over a wider existing grant.
        self.administrator(actor, authorization, GRANT_ISSUE, &old.spec, now, false)?;
        if let GrantOrigin::Delegated { parent } = old.origin {
            self.live_lineage(parent, now)?;
            if !spec.narrows(&self.grants[&parent].spec) {
                return Err(AuthorityError::Denied);
            }
        }
        let updated = Grant {
            spec,
            revision: self.revision.next().ok_or(AuthorityError::Capacity)?,
            ..old.clone()
        };
        self.replace(updated, now)
    }

    pub fn revoke(
        &mut self,
        actor: PrincipalId,
        authorization: GrantId,
        id: GrantId,
        expected: Revision,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_time(now)?;
        let old = self.target(id, expected)?;
        self.live_lineage(authorization, now)?;
        let authorizer = &self.grants[&authorization].spec;
        let own_delegation = old.origin
            == (GrantOrigin::Delegated {
                parent: authorization,
            })
            && authorizer.subject == actor
            && authorizer.delegation_depth > 0
            && (!old.spec.administrative()
                || authorizer.has(GRANT_ADMINISTER, self.authority.resource()));
        if !own_delegation {
            self.administrator(actor, authorization, GRANT_REVOKE, &old.spec, now, false)?;
        }
        let updated = Grant {
            revoked: true,
            revision: self.revision.next().ok_or(AuthorityError::Capacity)?,
            ..old.clone()
        };
        self.replace(updated, now)
    }

    fn target(&self, id: GrantId, expected: Revision) -> Result<&Grant, AuthorityError> {
        // The ownership slot changes only through offline recovery, so no
        // command can remove or reassign the last guaranteed administrator.
        if id == self.root_grant {
            return Err(AuthorityError::Denied);
        }
        let grant = self.grants.get(&id).ok_or(AuthorityError::Missing)?;
        if grant.revoked {
            return Err(AuthorityError::Revoked);
        }
        if grant.revision != expected {
            return Err(AuthorityError::Revision);
        }
        Ok(grant)
    }

    fn check_time(&self, now: UnixMillis) -> Result<(), AuthorityError> {
        if now < self.now {
            Err(AuthorityError::Clock)
        } else {
            Ok(())
        }
    }

    fn check_spec(&self, spec: &GrantSpec, now: UnixMillis) -> Result<(), AuthorityError> {
        self.check_time(now)?;
        if spec.authority != self.authority {
            return Err(AuthorityError::Audience);
        }
        if !spec.validate() {
            return Err(AuthorityError::Invalid);
        }
        if spec.expires <= now {
            return Err(AuthorityError::Expired);
        }
        Ok(())
    }

    fn administrator(
        &self,
        actor: PrincipalId,
        id: GrantId,
        operation: &str,
        target: &GrantSpec,
        now: UnixMillis,
        issuance: bool,
    ) -> Result<(), AuthorityError> {
        self.live_lineage(id, now)?;
        let authorization = &self.grants[&id];
        let grant = &authorization.spec;
        // Delegated rights cascade with their parent, so they cannot mint
        // independent node assignments or credentials.
        if (issuance && matches!(authorization.origin, GrantOrigin::Delegated { .. }))
            || grant.subject != actor
        {
            return Err(AuthorityError::Denied);
        }
        self.admin_scope(grant, operation, target, now, issuance)
    }

    /// An administrator may hold execution rights it assigned itself only within
    /// its own validity, and can never extend or recreate its administrative rights.
    fn check_self_assignment(
        &self,
        actor: PrincipalId,
        authorization: GrantId,
        spec: &GrantSpec,
    ) -> Result<(), AuthorityError> {
        if spec.subject == actor
            && (spec.administrative() || spec.expires > self.grants[&authorization].spec.expires)
        {
            return Err(AuthorityError::Denied);
        }
        Ok(())
    }

    fn insert(
        &mut self,
        id: GrantId,
        spec: GrantSpec,
        origin: GrantOrigin,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        if self.grants.contains_key(&id) {
            return Err(AuthorityError::Duplicate);
        }
        // Refusing an exhausted revision must not first prune committed state.
        let revision = self.revision.next().ok_or(AuthorityError::Capacity)?;
        if self.grants.len() >= MAX_GRANTS {
            let dead: Vec<_> = self
                .grants
                .keys()
                .copied()
                .filter(|id| *id != self.root_grant && self.dead(*id, now))
                .collect();
            if self.grants.len() - dead.len() >= MAX_GRANTS {
                return Err(AuthorityError::Capacity);
            }
            for id in dead {
                self.grants.remove(&id);
            }
        }
        self.replace(
            Grant {
                id,
                // Revisions are unique across the authority, so a pruned ID that is
                // issued again can never match evidence recorded for its predecessor.
                revision,
                spec,
                origin,
                revoked: false,
            },
            now,
        )
    }

    fn replace(&mut self, grant: Grant, now: UnixMillis) -> Result<(), AuthorityError> {
        let revision = self.revision.next().ok_or(AuthorityError::Capacity)?;
        self.grants.insert(grant.id, grant);
        self.revision = revision;
        self.now = now;
        Ok(())
    }

    /// Revoked or expired anywhere in its lineage; never usable again without a revision.
    fn dead(&self, id: GrantId, now: UnixMillis) -> bool {
        self.lineage(id).map_or(true, |lineage| {
            lineage.iter().any(|id| {
                let grant = &self.grants[id];
                grant.revoked || now.max(self.now) >= grant.spec.expires
            })
        })
    }

    fn lineage(&self, mut id: GrantId) -> Result<Vec<GrantId>, AuthorityError> {
        let mut seen = BTreeSet::new();
        let mut lineage = Vec::new();
        loop {
            if !seen.insert(id) || lineage.len() > MAX_DELEGATION_DEPTH as usize {
                return Err(AuthorityError::Invalid);
            }
            let grant = self.grants.get(&id).ok_or(AuthorityError::Missing)?;
            lineage.push(id);
            match grant.origin {
                GrantOrigin::Node { .. } => return Ok(lineage),
                GrantOrigin::Delegated { parent } => id = parent,
            }
        }
    }

    fn live_lineage(&self, id: GrantId, now: UnixMillis) -> Result<Vec<GrantId>, AuthorityError> {
        let now = now.max(self.now);
        let lineage = self.lineage(id)?;
        for id in &lineage {
            let grant = &self.grants[id];
            if grant.revoked {
                return Err(AuthorityError::Revoked);
            }
            if now < grant.spec.not_before || now >= grant.spec.expires {
                return Err(AuthorityError::Expired);
            }
            if let GrantOrigin::Delegated { parent } = grant.origin
                && !grant.spec.narrows(&self.grants[&parent].spec)
            {
                return Err(AuthorityError::Denied);
            }
        }
        Ok(lineage)
    }
}
