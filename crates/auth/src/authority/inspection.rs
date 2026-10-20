//! Bounded administration views. Credential verifiers never enter these types.
use super::*;
use serde::{Deserialize, Serialize};

pub const INSPECTION_PAGE_SIZE: usize = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum InspectionQuery {
    Grant { id: GrantId },
    Credential { id: CredentialId },
    Grants { after: Option<GrantId> },
    Credentials { after: Option<CredentialId> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub scope: GrantSpec,
    pub holder: CredentialHolder,
    pub generation: u64,
    pub revision: Revision,
    pub revoked: bool,
}
impl From<&Credential> for CredentialMetadata {
    fn from(value: &Credential) -> Self {
        Self {
            id: value.id,
            scope: value.scope.clone(),
            holder: value.holder,
            generation: value.generation,
            revision: value.revision,
            revoked: value.revoked,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum InspectionRecords {
    Grants {
        records: Vec<Grant>,
        next: Option<GrantId>,
    },
    Credentials {
        records: Vec<CredentialMetadata>,
        next: Option<CredentialId>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInspection {
    pub authority: AuthorityId,
    pub revision: Revision,
    pub generation: u64,
    pub root_grant: GrantId,
    pub records: InspectionRecords,
}

impl AuthorityState {
    /// The selected live grant and credential must both authorize administration
    /// and cover each returned scope. Expired/revoked targets remain visible for
    /// reconciliation. Missing and out-of-scope individual targets are identical.
    pub fn inspect(
        &self,
        caller: &AuthenticatedCaller,
        authorization: GrantId,
        query: &InspectionQuery,
        now: UnixMillis,
    ) -> Result<AuthorityInspection, AuthorityError> {
        let permission = Permission {
            operation: OperationId::new(GRANT_ADMINISTER)?,
            resource: self.authority().resource(),
        };
        self.authorize_caller(caller, authorization, &permission, now)
            .map_err(|_| AuthorityError::Denied)?;
        let credential = self
            .credential(caller.credential())
            .ok_or(AuthorityError::Denied)?;
        let grant = self.grant(authorization).ok_or(AuthorityError::Denied)?;
        self.inspect_visible(query, |target| {
            self.admin_scope(&credential.scope, GRANT_ADMINISTER, target, now, false)
                .is_ok()
                && self
                    .admin_scope(&grant.spec, GRANT_ADMINISTER, target, now, false)
                    .is_ok()
        })
    }

    /// For a trusted local owner holding the exclusive journal identity lock.
    /// Hosts must use `inspect` for every request from an authenticated caller.
    pub fn inspect_offline(
        &self,
        query: &InspectionQuery,
    ) -> Result<AuthorityInspection, AuthorityError> {
        self.inspect_visible(query, |_| true)
    }

    fn inspect_visible(
        &self,
        query: &InspectionQuery,
        visible: impl Fn(&GrantSpec) -> bool,
    ) -> Result<AuthorityInspection, AuthorityError> {
        let records = match query {
            InspectionQuery::Grant { id } => {
                let grant = self
                    .grant(*id)
                    .filter(|g| visible(&g.spec))
                    .ok_or(AuthorityError::Denied)?;
                InspectionRecords::Grants {
                    records: vec![grant.clone()],
                    next: None,
                }
            }
            InspectionQuery::Credential { id } => {
                let credential = self
                    .credential(*id)
                    .filter(|c| visible(&c.scope))
                    .ok_or(AuthorityError::Denied)?;
                InspectionRecords::Credentials {
                    records: vec![credential.into()],
                    next: None,
                }
            }
            InspectionQuery::Grants { after } => {
                let mut records: Vec<_> = self
                    .grants()
                    .filter(|g| after.is_none_or(|id| g.id > id) && visible(&g.spec))
                    .take(INSPECTION_PAGE_SIZE + 1)
                    .cloned()
                    .collect();
                let next = if records.len() > INSPECTION_PAGE_SIZE {
                    records.pop();
                    records.last().map(|g| g.id)
                } else {
                    None
                };
                InspectionRecords::Grants { records, next }
            }
            InspectionQuery::Credentials { after } => {
                let mut records: Vec<_> = self
                    .credentials()
                    .filter(|c| after.is_none_or(|id| c.id > id) && visible(&c.scope))
                    .take(INSPECTION_PAGE_SIZE + 1)
                    .map(CredentialMetadata::from)
                    .collect();
                let next = if records.len() > INSPECTION_PAGE_SIZE {
                    records.pop();
                    records.last().map(|c| c.id)
                } else {
                    None
                };
                InspectionRecords::Credentials { records, next }
            }
        };
        Ok(AuthorityInspection {
            authority: self.authority(),
            revision: self.revision(),
            generation: self.generation(),
            root_grant: self.root_grant(),
            records,
        })
    }
}
