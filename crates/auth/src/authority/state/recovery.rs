use super::*;

impl AuthorityState {
    /// Explicit offline ownership replacement. The host must hold its exclusive
    /// writer lock, include service administrative grants in `revoke`, and commit
    /// this with its other state before acknowledging recovery. Normal grant
    /// commands can never revive a revoked grant; only this operation replaces the
    /// reserved bootstrap slot, after permanently revoking its old descendants.
    pub fn recover(
        &mut self,
        command: &RecoveryCommand,
        now: UnixMillis,
    ) -> Result<(), AuthorityError> {
        self.check_spec(&command.administrator, now)?;
        if command.expected != self.revision {
            return Err(AuthorityError::Revision);
        }
        Self::validate_administrator(&command.administrator, now)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(AuthorityError::Capacity)?;
        Self::validate_initial_credential(
            &command.administrator,
            &command.credential,
            generation,
            now,
        )?;
        Self::check_owner(
            Ownership::Recover {
                expected: command.expected,
            },
            &command.administrator,
            &command.credential,
            &command.owner,
        )?;
        if command.revoke.len() > MAX_GRANTS {
            return Err(AuthorityError::Capacity);
        }
        let mut revoke = command.revoke.clone();
        for grant in self.grants.values() {
            if !grant.revoked
                && (grant.spec.administrative()
                    || self.lineage(grant.id)?.contains(&self.root_grant))
            {
                revoke.insert(grant.id);
            }
        }
        revoke.insert(self.root_grant);
        let previous = &self.grants[&self.root_grant];
        let receipt = RecoveryRecord {
            generation,
            revision: self.revision.next().ok_or(AuthorityError::Capacity)?,
            at: now,
            previous_administrator: previous.spec.subject,
            administrator: command.administrator.subject,
            revoked: revoke,
        };
        let root = Grant {
            id: self.root_grant,
            revision: receipt.revision,
            origin: GrantOrigin::Node {
                issuer: command.administrator.subject,
            },
            spec: command.administrator.clone(),
            revoked: false,
        };
        // Apply to a candidate so an unknown ID leaves the original state unchanged.
        let mut candidate = self.clone();
        for id in &receipt.revoked {
            let grant = candidate
                .grants
                .get_mut(id)
                .ok_or(AuthorityError::Missing)?;
            if !grant.revoked && *id != self.root_grant {
                grant.revision = receipt.revision;
                grant.revoked = true;
            }
        }
        candidate.grants.insert(self.root_grant, root);
        candidate.generation = receipt.generation;
        candidate.credentials.clear();
        candidate
            .credentials
            .insert(command.credential.id, command.credential.clone());
        candidate.revision = receipt.revision;
        candidate.now = now;
        candidate.last_recovery = Some(receipt);
        *self = candidate;
        Ok(())
    }

    pub(super) fn validate_recovery(&self) -> Result<(), AuthorityError> {
        if self.generation == 0
            || self.generation > self.revision.0
            || self
                .grants
                .get(&self.root_grant)
                .is_none_or(|g| g.revision.0 < self.generation)
            || !matches!(
                self.grants.get(&self.root_grant).map(|g| g.origin),
                Some(GrantOrigin::Node { .. })
            )
        {
            return Err(AuthorityError::Invalid);
        }
        match &self.last_recovery {
            None if self.generation == 1 => Ok(()),
            Some(record)
                if self.generation > 1
                    && record.generation == self.generation
                    && record.revision.0 >= record.generation
                    && record.revision <= self.revision
                    && record.at <= self.now
                    && record.revoked.contains(&self.root_grant)
                    && record.revoked.len() <= MAX_GRANTS
                    && record.revoked.iter().all(|id| {
                        // A pruned ID may name a new grant. Its authority-wide
                        // revision must be newer than this recovery receipt.
                        *id == self.root_grant
                            || self
                                .grants
                                .get(id)
                                .is_none_or(|g| g.revoked || g.revision > record.revision)
                    }) =>
            {
                Ok(())
            }
            _ => Err(AuthorityError::Invalid),
        }
    }
}
