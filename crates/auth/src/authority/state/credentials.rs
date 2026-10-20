use super::*;
use subtle::ConstantTimeEq as _;

impl AuthorityState {
    pub fn credential(&self, id: CredentialId) -> Option<&Credential> {
        self.credentials.get(&id)
    }
    pub fn credentials(&self) -> impl Iterator<Item = &Credential> {
        self.credentials.values()
    }

    /// Secret-only authentication, accepted only for bearer credentials.
    pub fn authenticate(
        &self,
        secret: &CredentialSecret,
        now: UnixMillis,
    ) -> Result<AuthenticatedCaller, AuthorityError> {
        if !self.live_credential(secret.id(), now)?.bearer() {
            return Err(AuthorityError::Credential);
        }
        self.authenticate_secret(secret, SessionKind::Bearer, now)
    }

    /// The session handshake adds a passkey or node-key proof to this check.
    pub(in crate::authority) fn authenticate_secret(
        &self,
        secret: &CredentialSecret,
        session: SessionKind,
        now: UnixMillis,
    ) -> Result<AuthenticatedCaller, AuthorityError> {
        let credential = self.live_credential(secret.id(), now)?;
        let proof = secret.verifier(self.authority, self.generation);
        if !bool::from(proof.as_bytes().ct_eq(credential.verifier.as_bytes())) {
            return Err(AuthorityError::Credential);
        }
        Ok(AuthenticatedCaller {
            authority: self.authority,
            subject: credential.scope.subject,
            credential: credential.id,
            holder: credential.holder,
            session,
            revision: credential.revision,
            generation: self.generation,
            authenticated_at: now,
            expires: credential.scope.expires,
            proof,
        })
    }

    /// Rechecks revocation, generation, expiry and both exact permission sets.
    /// The returned lineage is evidence for this instant, never future access.
    pub fn authorize_caller(
        &self,
        caller: &AuthenticatedCaller,
        grant: GrantId,
        permission: &Permission,
        now: UnixMillis,
    ) -> Result<Vec<(GrantId, Revision)>, AuthorityError> {
        let credential = self.check_caller(caller, now)?;
        if !credential.scope.permissions.contains(permission) {
            return Err(AuthorityError::Denied);
        }
        self.authorize(caller.subject, grant, permission, now)
    }

    pub fn apply_credential(
        &mut self,
        actor: PrincipalId,
        command: &CredentialCommand,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_time(now)?;
        let revision = self.revision.next().ok_or(AuthorityError::Capacity)?;
        match command {
            CredentialCommand::Issue {
                authorization,
                credential,
            } => {
                self.validate_credential(credential)?;
                if credential.revoked || credential.revision != Revision(1) {
                    return Err(AuthorityError::Invalid);
                }
                if self.credentials.contains_key(&credential.id) {
                    return Err(AuthorityError::Duplicate);
                }
                self.administrator(
                    actor,
                    *authorization,
                    CREDENTIAL_ISSUE,
                    &credential.scope,
                    now,
                    true,
                )?;
                // Unusable credentials are reclaimed only when space is needed.
                let generation = self.generation;
                let unusable = |c: &Credential| {
                    c.revoked || c.generation != generation || now >= c.scope.expires
                };
                let live = self.credentials.values().filter(|c| !unusable(c)).count();
                if live >= MAX_CREDENTIALS {
                    return Err(AuthorityError::Capacity);
                }
                if self.credentials.len() >= MAX_CREDENTIALS {
                    self.credentials.retain(|_, c| !unusable(c));
                }
                self.credentials
                    .insert(credential.id, credential.as_ref().clone());
            }
            CredentialCommand::Revoke {
                authorization,
                id,
                expected,
            } => {
                let credential = self.credentials.get(id).ok_or(AuthorityError::Missing)?;
                self.administrator(
                    actor,
                    *authorization,
                    CREDENTIAL_REVOKE,
                    &credential.scope,
                    now,
                    false,
                )?;
                if credential.revision != *expected {
                    return Err(AuthorityError::Revision);
                }
                if credential.revoked {
                    return Err(AuthorityError::Revoked);
                }
                let mut revoked = credential.clone();
                revoked.revision = revoked.revision.next().ok_or(AuthorityError::Capacity)?;
                revoked.revoked = true;
                self.credentials.insert(*id, revoked);
            }
        }
        self.revision = revision;
        self.now = now;
        Ok(())
    }

    pub(in crate::authority) fn check_caller(
        &self,
        caller: &AuthenticatedCaller,
        now: UnixMillis,
    ) -> Result<&Credential, AuthorityError> {
        let credential = self.live_credential(caller.credential, now)?;
        if caller.authority != self.authority
            || caller.subject != credential.scope.subject
            || caller.holder != credential.holder
            || caller.generation != self.generation
            || caller.revision != credential.revision
            || now < caller.authenticated_at
            || now >= caller.expires
            || !bool::from(
                caller
                    .proof
                    .as_bytes()
                    .ct_eq(credential.verifier.as_bytes()),
            )
        {
            return Err(AuthorityError::Credential);
        }
        Ok(credential)
    }

    fn live_credential(
        &self,
        id: CredentialId,
        now: UnixMillis,
    ) -> Result<&Credential, AuthorityError> {
        self.check_time(now)?;
        let credential = self
            .credentials
            .get(&id)
            .ok_or(AuthorityError::Credential)?;
        if credential.revoked
            || credential.generation != self.generation
            || now < credential.scope.not_before
            || now >= credential.scope.expires
        {
            return Err(AuthorityError::Credential);
        }
        Ok(credential)
    }

    pub(super) fn validate_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), AuthorityError> {
        if credential.scope.authority != self.authority
            || credential.generation != self.generation
            || !credential.scope.validate()
            || !credential.holder.admits(&credential.scope)
            || credential.revision.0 == 0
            || credential.revision > self.revision
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }

    pub(super) fn validate_initial_credential(
        admin: &GrantSpec,
        credential: &Credential,
        generation: u64,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        let scope = &credential.scope;
        if !scope.validate()
            || credential.generation != generation
            || credential.revision != Revision(1)
            || credential.revoked
            || credential.bearer()
            || scope.authority != admin.authority
            || scope.subject != admin.subject
            || !scope.permissions.is_subset(&admin.permissions)
            || scope.not_before < admin.not_before
            || scope.not_before > now
            || scope.expires <= now
            || scope.expires > admin.expires
            || scope.delegation_depth > admin.delegation_depth
            || !admin
                .issuance
                .as_ref()
                .is_some_and(|ceiling| ceiling.covers_scope(scope))
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(())
    }
}
