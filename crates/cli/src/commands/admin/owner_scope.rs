//! Default permissions for the owner explicitly pairing a fresh node.
use hellas_auth::{Digest, authority::*};

pub(super) fn administrator(
    public: hellas_authority::authenticator::PublicKey,
) -> anyhow::Result<GrantSpec> {
    let authority = AuthorityId(Digest::from_bytes(rand::random()));
    let subject =
        PrincipalId::from_public_key(hellas_auth::PublicKey::P256(public.to_compressed()))?;
    let permissions: std::collections::BTreeSet<_> = [
        GRANT_ISSUE,
        GRANT_REVOKE,
        GRANT_ADMINISTER,
        CREDENTIAL_ISSUE,
        CREDENTIAL_REVOKE,
    ]
    .into_iter()
    .map(|name| {
        Ok(Permission {
            operation: OperationId::new(name)?,
            resource: authority.resource(),
        })
    })
    .chain(
        hellas_authority::operations::OPERATIONS
            .iter()
            .filter(|operation| {
                !matches!(
                    operation.scope,
                    hellas_authority::operations::Scope::Allowance
                )
            })
            .map(|operation| operation.permission(authority, None)),
    )
    .collect::<Result<_, AuthorityError>>()?;
    let now = UnixMillis::now()?;
    let year = 365 * 24 * 60 * 60 * 1000;
    Ok(GrantSpec {
        authority,
        subject,
        issuance: Some(IssuanceCeiling {
            operations: permissions
                .iter()
                .map(|p| p.operation.clone())
                .chain([OperationId::new("work.execute")?])
                .collect(),
            resources: CeilingResources::Authority,
            max_validity_ms: year,
            max_delegation_depth: MAX_DELEGATION_DEPTH,
        }),
        permissions,
        not_before: now,
        expires: UnixMillis(now.0.checked_add(year).ok_or(AuthorityError::Invalid)?),
        delegation_depth: 0,
    })
}
