use super::*;
use crate::{Digest, PublicKey, hash_tuple};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::collections::BTreeSet;

/// A validated identity key, independent of enrollment and transport keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId([u8; 33]);

impl PrincipalId {
    pub fn from_public_key(key: PublicKey) -> Result<Self, AuthorityError> {
        let PublicKey::Secp256k1(bytes) = key else {
            return Err(AuthorityError::Invalid);
        };
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub const fn public_key(self) -> PublicKey {
        PublicKey::Secp256k1(self.0)
    }

    /// A 60-bit display fingerprint for comparison over an independent channel.
    /// Hash the complete identity key before shortening it: compressed key prefixes
    /// are not uniform. This display value never replaces the full identity key.
    pub fn fingerprint(self) -> String {
        const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let digest = hash_tuple("hellas.principal.fingerprint.v1", &[&self.0]);
        let prefix = digest
            .as_bytes()
            .iter()
            .take(8)
            .fold(0u64, |word, byte| (word << 8) | u64::from(*byte));
        let mut display = String::with_capacity(14);
        for n in 0..12 {
            if n == 4 || n == 8 {
                display.push('-');
            }
            let symbol = ((prefix >> (59 - 5 * n)) & 31) as usize;
            display.push(char::from(BASE32[symbol]));
        }
        display
    }
}

impl Serialize for PrincipalId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        Self::try_from(bytes.as_ref()).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityId(pub Digest);

impl AuthorityId {
    /// Resource used by the authority's own grant administration operations.
    pub fn resource(self) -> ResourceId {
        ResourceId(hash_tuple(
            "hellas.authority.resource.v1",
            &[self.0.as_bytes()],
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ResourceId(pub Digest);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GrantId(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Revision(pub u64);

impl Revision {
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    /// A new record starts at one; updates advance exactly once without wrapping.
    pub fn follows(self, previous: Option<Self>) -> bool {
        previous.unwrap_or(Self(0)).next() == Some(self)
    }
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct UnixMillis(pub u64);

impl UnixMillis {
    /// Wall time since the Unix epoch, saturated at the largest millisecond value.
    /// Callers decide whether a pre-epoch clock is an error or should use zero.
    pub fn now() -> Result<Self, std::time::SystemTimeError> {
        let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        Ok(Self(elapsed.as_millis().min(u128::from(u64::MAX)) as u64))
    }
}

/// Exact operation name; this is not a pattern or a policy expression.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    pub fn new(name: impl Into<String>) -> Result<Self, AuthorityError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 96
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
            || name.split('.').any(str::is_empty)
        {
            return Err(AuthorityError::Invalid);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub operation: OperationId,
    pub resource: ResourceId,
}

/// Only issuance ceilings can cover all resources in this one authority.
/// Execution grants always contain exact operation/resource pairs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeilingResources {
    Named(BTreeSet<ResourceId>),
    Authority,
}

impl CeilingResources {
    fn contains(&self, resource: &ResourceId) -> bool {
        match self {
            Self::Named(ids) => ids.contains(resource),
            Self::Authority => true,
        }
    }

    fn subset(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::Authority) => true,
            (Self::Named(ids), Self::Named(outer)) => ids.is_subset(outer),
            _ => false,
        }
    }
}

/// Generic issuance envelope. The node coordinator additionally checks typed
/// service limit maxima and existing sharing pools in the same transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceCeiling {
    pub operations: BTreeSet<OperationId>,
    pub resources: CeilingResources,
    /// Maximum time from this issuance/update until the assignment expires.
    pub max_validity_ms: u64,
    pub max_delegation_depth: u8,
}

impl IssuanceCeiling {
    pub(super) fn validate(&self) -> bool {
        !self.operations.is_empty()
            && self.operations.len() <= MAX_PERMISSIONS
            && self.max_validity_ms > 0
            && self.max_delegation_depth <= MAX_DELEGATION_DEPTH
            && match &self.resources {
                CeilingResources::Named(ids) => !ids.is_empty() && ids.len() <= MAX_PERMISSIONS,
                CeilingResources::Authority => true,
            }
    }

    pub(super) fn subset(&self, outer: &Self) -> bool {
        self.operations.is_subset(&outer.operations)
            && self.resources.subset(&outer.resources)
            && self.max_validity_ms <= outer.max_validity_ms
            && self.max_delegation_depth <= outer.max_delegation_depth
    }

    pub(super) fn covers_scope(&self, spec: &GrantSpec) -> bool {
        spec.permissions
            .iter()
            .all(|p| self.operations.contains(&p.operation) && self.resources.contains(&p.resource))
            && spec
                .issuance
                .as_ref()
                .is_none_or(|ceiling| ceiling.subset(self))
    }

    pub(super) fn covers(&self, spec: &GrantSpec, now: UnixMillis) -> bool {
        self.covers_scope(spec)
            && spec.delegation_depth <= self.max_delegation_depth
            && spec
                .expires
                .0
                .checked_sub(now.0)
                .is_some_and(|ms| ms > 0 && ms <= self.max_validity_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    pub authority: AuthorityId,
    pub subject: PrincipalId,
    pub permissions: BTreeSet<Permission>,
    pub not_before: UnixMillis,
    pub expires: UnixMillis,
    /// Explicit permission to delegate, bounded by both depth and live parents.
    pub delegation_depth: u8,
    pub issuance: Option<IssuanceCeiling>,
}

impl GrantSpec {
    pub(super) fn validate(&self) -> bool {
        !self.permissions.is_empty()
            && self.permissions.len() <= MAX_PERMISSIONS
            && self.not_before < self.expires
            && self.delegation_depth <= MAX_DELEGATION_DEPTH
            && self.issuance.as_ref().is_none_or(IssuanceCeiling::validate)
    }

    pub(super) fn has(&self, operation: &str, resource: ResourceId) -> bool {
        self.permissions
            .iter()
            .any(|p| p.operation.as_str() == operation && p.resource == resource)
    }

    pub(super) fn administrative(&self) -> bool {
        self.issuance.is_some()
            || self.permissions.iter().any(|p| {
                matches!(
                    p.operation.as_str(),
                    GRANT_ISSUE
                        | GRANT_REVOKE
                        | GRANT_ADMINISTER
                        | CREDENTIAL_ISSUE
                        | CREDENTIAL_REVOKE
                )
            })
    }

    pub(super) fn narrows(&self, parent: &Self) -> bool {
        self.authority == parent.authority
            && self.permissions.is_subset(&parent.permissions)
            && self.not_before >= parent.not_before
            && self.expires <= parent.expires
            && self.delegation_depth < parent.delegation_depth
            && self
                .issuance
                .as_ref()
                .is_none_or(|child| parent.issuance.as_ref().is_some_and(|p| child.subset(p)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantOrigin {
    Node { issuer: PrincipalId },
    Delegated { parent: GrantId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub(super) id: GrantId,
    pub(super) revision: Revision,
    pub(super) spec: GrantSpec,
    pub(super) origin: GrantOrigin,
    pub(super) revoked: bool,
}

impl Grant {
    pub const fn id(&self) -> GrantId {
        self.id
    }
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    pub fn spec(&self) -> &GrantSpec {
        &self.spec
    }
    pub const fn origin(&self) -> GrantOrigin {
        self.origin
    }
    pub const fn revoked(&self) -> bool {
        self.revoked
    }
}

/// The portable mutation recorded by the node's composite journal and encoded
/// by service adapters. The actor comes from authentication, not this request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GrantCommand {
    Issue {
        authorization: GrantId,
        id: GrantId,
        spec: GrantSpec,
    },
    Delegate {
        parent: GrantId,
        id: GrantId,
        spec: GrantSpec,
    },
    Revise {
        authorization: GrantId,
        id: GrantId,
        expected: Revision,
        spec: GrantSpec,
    },
    Revoke {
        authorization: GrantId,
        id: GrantId,
        expected: Revision,
    },
}

/// Offline host operation, deliberately absent from the service command enum.
/// `revoke` adds service-owned administrative grants to the mandatory authority
/// administrators and bootstrap descendants revoked by the pure transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommand {
    pub credential: Credential,
    pub expected: Revision,
    pub administrator: GrantSpec,
    pub revoke: BTreeSet<GrantId>,
}

/// The latest durable ownership recovery receipt. Journal rotation retains this
/// receipt and the monotonic generation; it does not retain unlimited audit history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecord {
    pub generation: u64,
    pub revision: Revision,
    pub at: UnixMillis,
    pub previous_administrator: PrincipalId,
    pub administrator: PrincipalId,
    pub revoked: BTreeSet<GrantId>,
}

impl std::str::FromStr for AuthorityId {
    type Err = AuthorityError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = crate::hex::parse::<32>(text).map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(Digest::from_bytes(bytes)))
    }
}
impl TryFrom<&[u8]> for AuthorityId {
    type Error = AuthorityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(Digest::from_bytes(bytes)))
    }
}
impl std::fmt::Display for AuthorityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&::hex::encode(self.0.as_bytes()))
    }
}

impl std::str::FromStr for ResourceId {
    type Err = AuthorityError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = crate::hex::parse::<32>(text).map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(Digest::from_bytes(bytes)))
    }
}
impl TryFrom<&[u8]> for ResourceId {
    type Error = AuthorityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(Digest::from_bytes(bytes)))
    }
}
impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&::hex::encode(self.0.as_bytes()))
    }
}

impl std::str::FromStr for GrantId {
    type Err = AuthorityError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = crate::hex::parse::<16>(text).map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(bytes))
    }
}
impl TryFrom<&[u8]> for GrantId {
    type Error = AuthorityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 16] = value.try_into().map_err(|_| AuthorityError::Invalid)?;
        Ok(Self(bytes))
    }
}
impl std::fmt::Display for GrantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&::hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for PrincipalId {
    type Error = AuthorityError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_public_key(PublicKey::Secp256k1(
            value.try_into().map_err(|_| AuthorityError::Invalid)?,
        ))
    }
}
impl std::str::FromStr for PrincipalId {
    type Err = AuthorityError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(
            crate::hex::parse::<33>(text)
                .map_err(|_| AuthorityError::Invalid)?
                .as_slice(),
        )
    }
}
impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&::hex::encode(self.as_bytes()))
    }
}
