use super::*;

impl AuthorityState {
    /// Capture current authenticated caller metadata for the host's journal.
    /// This is not a permission check; the service must also authorize its effect.
    pub fn record_caller(
        &self,
        caller: &AuthenticatedCaller,
        now: UnixMillis,
    ) -> Result<CallerRecord, AuthorityError> {
        self.check_caller(caller, now)?;
        Ok(CallerRecord {
            authority: self.authority,
            generation: self.generation,
            before: self.revision,
            actor: caller.subject,
            credential: caller.credential,
            credential_revision: caller.revision,
            holder: caller.holder,
            session: caller.session,
            at: now,
        })
    }

    /// Validate a persisted service effect during trusted journal replay only.
    /// Live service requests must use `authorize_caller`, never a recorded actor.
    pub fn authorize_recorded(
        &self,
        record: &CallerRecord,
        grant: GrantId,
        permission: &Permission,
    ) -> Result<Vec<(GrantId, Revision)>, AuthorityError> {
        if !self
            .recorded_scope(record)?
            .permissions
            .contains(permission)
        {
            return Err(AuthorityError::Denied);
        }
        self.authorize(record.actor, grant, permission, record.at)
    }

    fn recorded_scope(&self, record: &CallerRecord) -> Result<&GrantSpec, AuthorityError> {
        self.check_time(record.at)?;
        if record.authority != self.authority || record.generation != self.generation {
            return Err(AuthorityError::Audience);
        }
        if record.before != self.revision {
            return Err(AuthorityError::Revision);
        }
        let credential = self
            .credentials
            .get(&record.credential)
            .ok_or(AuthorityError::Credential)?;
        if credential.revoked
            || credential.generation != self.generation
            || credential.revision != record.credential_revision
            || credential.scope.subject != record.actor
            || credential.holder != record.holder
            || (record.session == SessionKind::Bearer) != credential.bearer()
            || record.at < credential.scope.not_before
            || record.at >= credential.scope.expires
        {
            return Err(AuthorityError::Credential);
        }
        Ok(&credential.scope)
    }

    /// Authenticate against this state and validate both credential and grant
    /// bounds. This is a journal record for one exact revision, not a permit.
    /// Service-owned restrictions must be checked by the coordinator as well.
    pub fn record_administration(
        &self,
        caller: &AuthenticatedCaller,
        command: AdministrationCommand,
        now: UnixMillis,
    ) -> Result<AdministrationRecord, AuthorityError> {
        let record = AdministrationRecord {
            caller: self.record_caller(caller, now)?,
            command,
        };
        self.clone().apply_administration(&record)?;
        Ok(record)
    }

    /// Replay a record from the trusted journal, never from an RPC request.
    /// The host authenticates first through `record_administration`; replay
    /// rechecks the recorded credential scope, exact revision and grant rules.
    pub fn apply_administration(
        &mut self,
        record: &AdministrationRecord,
    ) -> Result<(), AuthorityError> {
        let scope = self.recorded_scope(&record.caller)?;
        if self.step_up(record.caller.actor, &record.command) {
            record.caller.session.step_up()?;
        }
        match &record.command {
            AdministrationCommand::Grant(command) => {
                self.check_credential_grant(scope, command, record.caller.at())?;
                self.apply(record.caller.actor(), command, record.caller.at())
            }
            AdministrationCommand::Credential(command) => {
                match command {
                    CredentialCommand::Issue { credential, .. } => self.admin_scope(
                        scope,
                        CREDENTIAL_ISSUE,
                        &credential.scope,
                        record.caller.at(),
                        true,
                    )?,
                    CredentialCommand::Revoke { id, .. } => {
                        let target = self.credentials.get(id).ok_or(AuthorityError::Missing)?;
                        self.admin_scope(
                            scope,
                            CREDENTIAL_REVOKE,
                            &target.scope,
                            record.caller.at(),
                            false,
                        )?;
                    }
                }
                self.apply_credential(record.caller.actor(), command, record.caller.at())
            }
        }
    }

    /// The step-up set within the authority: every credential issue or
    /// revocation, and any grant change that names another principal (a
    /// contact) or administrative rights. A principal's own execution grants
    /// remain daily operations.
    fn step_up(&self, actor: PrincipalId, command: &AdministrationCommand) -> bool {
        let sensitive = |spec: &GrantSpec| spec.subject != actor || spec.administrative();
        let existing = |id: &GrantId| self.grants.get(id).is_none_or(|g| sensitive(&g.spec));
        match command {
            AdministrationCommand::Credential(_) => true,
            AdministrationCommand::Grant(
                GrantCommand::Issue { spec, .. } | GrantCommand::Delegate { spec, .. },
            ) => sensitive(spec),
            AdministrationCommand::Grant(GrantCommand::Revise { id, spec, .. }) => {
                sensitive(spec) || existing(id)
            }
            AdministrationCommand::Grant(GrantCommand::Revoke { id, .. }) => existing(id),
        }
    }

    fn check_credential_grant(
        &self,
        scope: &GrantSpec,
        command: &GrantCommand,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        match command {
            GrantCommand::Issue { spec, .. } => {
                self.admin_scope(scope, GRANT_ISSUE, spec, now, true)
            }
            GrantCommand::Revise { id, spec, .. } => {
                let old = self.grants.get(id).ok_or(AuthorityError::Missing)?;
                self.admin_scope(scope, GRANT_ISSUE, &old.spec, now, false)?;
                self.admin_scope(scope, GRANT_ISSUE, spec, now, true)
            }
            GrantCommand::Delegate { spec, .. } => self.credential_delegation(scope, spec),
            GrantCommand::Revoke {
                authorization, id, ..
            } => {
                let old = self.grants.get(id).ok_or(AuthorityError::Missing)?;
                let parent = self
                    .grants
                    .get(authorization)
                    .ok_or(AuthorityError::Missing)?;
                if old.origin
                    == (GrantOrigin::Delegated {
                        parent: *authorization,
                    })
                    && parent.spec.subject == scope.subject
                    && parent.spec.delegation_depth > 0
                {
                    self.credential_delegation(scope, &old.spec)
                } else {
                    self.admin_scope(scope, GRANT_REVOKE, &old.spec, now, false)
                }
            }
        }
    }

    fn credential_delegation(
        &self,
        scope: &GrantSpec,
        target: &GrantSpec,
    ) -> Result<(), AuthorityError> {
        if !target.narrows(scope)
            || (target.administrative() && !scope.has(GRANT_ADMINISTER, self.authority.resource()))
        {
            return Err(AuthorityError::Denied);
        }
        Ok(())
    }

    pub(super) fn admin_scope(
        &self,
        scope: &GrantSpec,
        operation: &str,
        target: &GrantSpec,
        now: UnixMillis,
        issuance: bool,
    ) -> Result<(), AuthorityError> {
        if !scope.has(operation, self.authority.resource())
            || (target.administrative() && !scope.has(GRANT_ADMINISTER, self.authority.resource()))
            || !scope.issuance.as_ref().is_some_and(|ceiling| {
                if issuance {
                    ceiling.covers(target, now)
                } else {
                    ceiling.covers_scope(target)
                }
            })
        {
            return Err(AuthorityError::Denied);
        }
        Ok(())
    }
}
