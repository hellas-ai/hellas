//! Application credentials share the authority snapshot and revision. Only
//! verifiers are persisted; hosts release a prepared secret after durable commit.
use super::*;
use crate::{Digest, hash_tuple};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub [u8; 16]);

/// Client-owned material, deliberately neither serializable nor printable.
/// Transport/wallet code must explicitly expose the secret to encode or save it.
pub struct CredentialSecret {
    id: CredentialId,
    secret: Zeroizing<[u8; 32]>,
}

impl CredentialSecret {
    pub fn from_parts(id: CredentialId, secret: [u8; 32]) -> Self {
        Self {
            id,
            secret: Zeroizing::new(secret),
        }
    }

    pub const fn id(&self) -> CredentialId {
        self.id
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub(super) fn verifier(&self, authority: AuthorityId, generation: u64) -> Digest {
        hash_tuple(
            "hellas.auth.bearer.v1",
            &[
                authority.0.as_bytes(),
                &generation.to_be_bytes(),
                &self.id.0,
                self.secret.as_ref(),
            ],
        )
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialSecret(redacted)")
    }
}

/// Trusted persisted record, never a public catalogue or authentication input.
/// `scope` reuses grant bounds, including delegation and administrative issuance
/// ceilings; possessing a credential does not itself assign any grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub(super) id: CredentialId,
    pub(super) scope: GrantSpec,
    pub(super) generation: u64,
    pub(super) revision: Revision,
    pub(super) verifier: Digest,
    pub(super) revoked: bool,
    /// Issued to the issuer's own subject, so its secret alone authenticates.
    /// Otherwise the holder must also sign a session with the subject's key:
    /// an issuer must never be able to act as another subject.
    pub(super) bearer: bool,
}

impl Credential {
    /// Prepare new material without granting access. The host must include this
    /// record in an authorized command or offline ownership transition, persist
    /// it, and only then release the secret. A failed commit never releases it.
    pub fn prepare(
        scope: GrantSpec,
        generation: u64,
    ) -> Result<(Self, CredentialSecret), AuthorityError> {
        if !scope.validate() || generation == 0 {
            return Err(AuthorityError::Invalid);
        }
        let mut id = [0; 16];
        let mut secret = CredentialSecret::from_parts(CredentialId(id), [0; 32]);
        getrandom::fill(&mut id).map_err(|_| AuthorityError::Entropy)?;
        getrandom::fill(secret.secret.as_mut()).map_err(|_| AuthorityError::Entropy)?;
        secret.id = CredentialId(id);
        Ok((
            Self {
                id: secret.id,
                verifier: secret.verifier(scope.authority, generation),
                scope,
                generation,
                revision: Revision(1),
                revoked: false,
                bearer: false,
            },
            secret,
        ))
    }

    pub const fn id(&self) -> CredentialId {
        self.id
    }
    pub fn scope(&self) -> &GrantSpec {
        &self.scope
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
    pub const fn bearer(&self) -> bool {
        self.bearer
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .field("bearer", &self.bearer)
            .finish_non_exhaustive()
    }
}

/// Pure journal command. As with `GrantCommand`, hosts authenticate the actor
/// and enforce its credential ceiling before committing through the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CredentialCommand {
    Issue {
        authorization: GrantId,
        credential: Box<Credential>,
    },
    Revoke {
        authorization: GrantId,
        id: CredentialId,
        expected: Revision,
    },
}

/// Authentication evidence only. Every protected effect must recheck this
/// against the coordinator's current authority; it is not a reusable permit.
/// No deserializer or constructor accepts a caller-supplied principal.
pub struct AuthenticatedCaller {
    pub(super) authority: AuthorityId,
    pub(super) subject: PrincipalId,
    pub(super) credential: CredentialId,
    pub(super) revision: Revision,
    pub(super) generation: u64,
    pub(super) authenticated_at: UnixMillis,
    pub(super) expires: UnixMillis,
    pub(super) proof: Digest,
}

impl AuthenticatedCaller {
    pub const fn authority(&self) -> AuthorityId {
        self.authority
    }
    pub const fn subject(&self) -> PrincipalId {
        self.subject
    }
    pub const fn credential(&self) -> CredentialId {
        self.credential
    }
    /// The credential or authenticated session deadline, whichever is earlier.
    pub const fn expires(&self) -> UnixMillis {
        self.expires
    }
}

impl fmt::Debug for AuthenticatedCaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedCaller")
            .field("subject", &self.subject)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl std::str::FromStr for CredentialId {
    type Err = AuthorityError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = crate::hex::parse::<16>(text).map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(bytes))
    }
}
impl TryFrom<&[u8]> for CredentialId {
    type Error = AuthorityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 16] = value.try_into().map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(bytes))
    }
}
impl std::fmt::Display for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&::hex::encode(self.0))
    }
}
