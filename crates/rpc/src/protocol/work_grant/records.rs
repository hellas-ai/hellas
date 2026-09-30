//! Private grant terms and signed Offers. Decoding is bounded, canonical and
//! revalidates enrollment; no discovery record confers grant authority.
use super::{budget::*, *};
use crate::protocol::value::{canonical_dag_cbor, decode_canonical_dag_cbor};
use crate::protocol::work_profile::WorkPolicy;
use crate::{
    PlatformCredential, PlatformEnrollment, ProducerSigningKey, ProviderEnrollmentBundle,
    PublicKey, RootKind, RootProof, Signature,
};
use hellas_kernel::{Key, NetworkId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::num::{NonZeroU16, NonZeroU64};

pub const MAX_OFFER_BYTES: usize = 256 * 1024;
pub const MAX_PRINCIPAL_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("malformed grant record")]
    Malformed,
    #[error("grant principal requires a secp256k1 producer and Ed25519 transport")]
    UnsupportedKey,
    #[error("grant enrollment requires a verifiable software root")]
    UnsupportedRoot,
    #[error("invalid enrollment or record signature")]
    Signature,
    #[error("offer is addressed to another principal")]
    Audience,
    #[error("grant or offer has expired")]
    Expired,
    #[error("grant is paused")]
    Paused,
    #[error("grant is revoked")]
    Revoked,
    #[error("stale grant revision; current revision is {0:?}")]
    Revision(Revision),
    #[error("grant policy is outside scope")]
    OutOfScope,
    #[error("invalid grant limits or unsupported meter")]
    Limits,
    #[error("account-backed resource requires explicit consent")]
    AccountBacked,
    #[error("grant state capacity exhausted")]
    StateCapacity,
    #[error("unauthorized grant operation")]
    Unauthorized,
    #[error("invalid grant generation")]
    Generation,
    #[error("resource is quarantined")]
    Quarantined,
}

/// Only verified public enrollment can become a grant principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    bundle: ProviderEnrollmentBundle,
}
impl Principal {
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        if bytes.len() > MAX_PRINCIPAL_BYTES {
            return Err(GrantError::Malformed);
        }
        let bundle = ProviderEnrollmentBundle::from_canonical_bytes(bytes)
            .map_err(|_| GrantError::Malformed)?;
        Self::verify(bundle)
    }
    pub fn verify(bundle: ProviderEnrollmentBundle) -> Result<Self, GrantError> {
        let statement = &bundle.genesis.statement;
        let (PublicKey::Secp256k1(producer), PublicKey::Ed25519(_)) = (
            statement.producer_public_key,
            statement.transport_public_key,
        ) else {
            return Err(GrantError::UnsupportedKey);
        };
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&producer)
            .map_err(|_| GrantError::UnsupportedKey)?;
        let RootProof::Software(signature) = &bundle.genesis.root_proof else {
            return Err(GrantError::UnsupportedRoot);
        };
        if statement.root_kind != RootKind::Software
            || bundle.platform != PlatformEnrollment::Absent
            || statement.platform_credential != PlatformCredential::Absent
        {
            return Err(GrantError::UnsupportedRoot);
        }
        crate::signature::verify_digest_signature(
            &statement.root_public_key,
            signature,
            Digest::hash(&statement.canonical_bytes()),
        )
        .map_err(|_| GrantError::Signature)?;
        Ok(Self { bundle })
    }
    pub fn bundle(&self) -> &ProviderEnrollmentBundle {
        &self.bundle
    }
    pub fn id(&self) -> PrincipalId {
        PrincipalId(self.bundle.content_id())
    }
    pub fn producer(&self) -> Key {
        match self.bundle.genesis.statement.producer_public_key {
            PublicKey::Secp256k1(bytes) => Key::from_bytes(bytes),
            _ => unreachable!("verified principal"),
        }
    }
    pub fn transport(&self) -> [u8; 32] {
        match self.bundle.genesis.statement.transport_public_key {
            PublicKey::Ed25519(bytes) => bytes,
            _ => unreachable!("verified principal"),
        }
    }
}
impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.bundle.canonical_bytes())
    }
}
impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        Self::decode(&bytes).map_err(D::Error::custom)
    }
}

/// Provider records constrain key shapes, not platform roots. Trust is checked
/// by the client against its enrollment pin before a session is constructed.
impl ProviderEnrollmentBundle {
    pub fn grant_producer(&self) -> Result<Key, GrantError> {
        let PublicKey::Secp256k1(bytes) = self.genesis.statement.producer_public_key else {
            return Err(GrantError::UnsupportedKey);
        };
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| GrantError::UnsupportedKey)?;
        Ok(Key::from_bytes(bytes))
    }
    pub fn grant_transport(&self) -> Result<[u8; 32], GrantError> {
        match self.genesis.statement.transport_public_key {
            PublicKey::Ed25519(bytes) => Ok(bytes),
            _ => Err(GrantError::UnsupportedKey),
        }
    }
    pub fn check_grant_provider(&self) -> Result<(), GrantError> {
        if self.canonical_bytes().len() > MAX_PRINCIPAL_BYTES {
            return Err(GrantError::Malformed);
        }
        self.grant_producer()?;
        self.grant_transport()?;
        Ok(())
    }
}
/// Enrollment bytes retain the same journal representation as software Principals.
pub mod provider_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &ProviderEnrollmentBundle, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.canonical_bytes())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<ProviderEnrollmentBundle, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        if bytes.len() > MAX_PRINCIPAL_BYTES {
            return Err(D::Error::custom(GrantError::Malformed));
        }
        let provider =
            ProviderEnrollmentBundle::from_canonical_bytes(&bytes).map_err(D::Error::custom)?;
        provider.check_grant_provider().map_err(D::Error::custom)?;
        Ok(provider)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantState {
    Active,
    Paused,
    Revoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantKind {
    Owner(Principal),
    Principal(Principal),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantClass {
    Interactive,
    Granted,
}
impl GrantKind {
    pub fn principal(&self) -> &Principal {
        match self {
            Self::Owner(p) | Self::Principal(p) => p,
        }
    }
    pub fn class(&self) -> GrantClass {
        match self {
            Self::Owner(_) => GrantClass::Interactive,
            Self::Principal(_) => GrantClass::Granted,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPolicy {
    pub name: String,
    #[serde(with = "policy_bytes")]
    pub work: WorkPolicy,
    pub https: Option<super::resource::HttpsResource>,
}
impl GrantPolicy {
    /// Provider-local resource identity shared by grants. Limits and revisions
    /// cannot clear a quarantine on the same underlying configured resource.
    pub fn resource_id(&self) -> Result<Digest, GrantError> {
        let body = if let Some(resource) = &self.https {
            canonical_dag_cbor(resource).map_err(|_| GrantError::Malformed)?
        } else {
            self.work.encode()
        };
        Ok(super::super::work::xfh(
            b"hellas.work.resource.v1",
            &[&body],
        ))
    }

    pub fn validate(&self) -> Result<(), GrantError> {
        if self.name.is_empty() || self.name.len() > 64 {
            return Err(GrantError::Malformed);
        }
        self.work.check().map_err(|_| GrantError::Malformed)?;
        if matches!(&self.work, WorkPolicy::Fetch { policy, .. }
            if policy.allowed_environment == crate::FetchEnvironment::Http.manifest_id())
            && self.https.is_none()
        {
            return Err(GrantError::Malformed);
        }
        if let Some(resource) = &self.https {
            if !matches!(
                &self.work,
                WorkPolicy::Fetch {
                    route: super::super::work_fetch::FetchRoutePolicy::SealedRoute { .. },
                    ..
                }
            ) {
                return Err(GrantError::OutOfScope);
            }
            if !matches!(&self.work, WorkPolicy::Fetch { policy, .. }
                if policy.allowed_environment == crate::FetchEnvironment::Http.manifest_id())
            {
                return Err(GrantError::Malformed);
            }
            resource.validate().map_err(|_| GrantError::Malformed)?;
        }
        Ok(())
    }
    pub fn supports(&self, meter: Meter) -> bool {
        match &self.work {
            WorkPolicy::Evaluate(_) => true,
            WorkPolicy::Fetch { .. } => match meter {
                Meter::Requests => true,
                Meter::OutputTokens => self
                    .https
                    .as_ref()
                    .is_some_and(|r| r.accounting != super::resource::AccountingProfile::None),
                Meter::InputTokens | Meter::DeviceMillis => false,
            },
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantDef {
    pub id: GrantId,
    pub revision: Revision,
    pub kind: GrantKind,
    pub policies: Vec<GrantPolicy>,
    pub limits: Vec<Limit>,
    pub weight: NonZeroU16,
    pub max_job_millis: NonZeroU64,
    pub max_in_flight: NonZeroU16,
    pub expires: Option<UnixMillis>,
    pub state: GrantState,
    pub allow_account_backed: bool,
}
impl GrantDef {
    pub fn validate(&self) -> Result<(), GrantError> {
        if self.revision.0 == 0
            || (self.policies.is_empty() && !matches!(self.kind, GrantKind::Owner(_)))
            || self.policies.len() > 16
            || self.max_in_flight.get() > 256
            || self.limits.len() > 16
        {
            return Err(GrantError::Limits);
        }
        let mut names = std::collections::BTreeSet::new();
        let mut policies = std::collections::BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !names.insert(&policy.name) || !policies.insert(policy.work.encode()) {
                return Err(GrantError::Malformed);
            }
            let account_backed = match &policy.work {
                WorkPolicy::Evaluate(_) => false,
                WorkPolicy::Fetch { .. } => {
                    policy.https.as_ref().is_none_or(|r| r.credential.is_some())
                }
            };
            if !self.allow_account_backed && account_backed {
                return Err(GrantError::AccountBacked);
            }
        }
        let mut limits = std::collections::BTreeSet::new();
        for l in &self.limits {
            if !limits.insert((l.meter, l.window))
                || self.policies.iter().any(|p| !p.supports(l.meter))
            {
                return Err(GrantError::Limits);
            }
        }
        Ok(())
    }
    pub fn admits(&self, now: UnixMillis) -> Result<(), GrantError> {
        match self.state {
            GrantState::Paused => return Err(GrantError::Paused),
            GrantState::Revoked => return Err(GrantError::Revoked),
            GrantState::Active => {}
        }
        if self.expires.is_some_and(|t| t <= now) {
            return Err(GrantError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    #[serde(with = "network")]
    pub network: NetworkId,
    #[serde(with = "provider_bytes")]
    pub provider: ProviderEnrollmentBundle,
    pub grant: GrantDef,
    pub generation: u64,
    pub sequence: u64,
    pub valid_until: UnixMillis,
    pub addresses: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOffer {
    offer: Offer,
    signature: Signature,
}
impl SignedOffer {
    pub fn sign(offer: Offer, key: &ProducerSigningKey) -> Result<Self, GrantError> {
        offer.validate()?;
        if key.public_key() != PublicKey::Secp256k1(offer.provider.grant_producer()?.to_bytes()) {
            return Err(GrantError::Signature);
        }
        let signature = key
            .sign_digest(offer.digest()?)
            .map_err(|_| GrantError::Signature)?;
        let signed = Self { offer, signature };
        if signed.encode()?.len() > MAX_OFFER_BYTES {
            return Err(GrantError::StateCapacity);
        }
        Ok(signed)
    }
    pub fn offer(&self) -> &Offer {
        &self.offer
    }
    pub fn encode(&self) -> Result<Vec<u8>, GrantError> {
        canonical_dag_cbor(self).map_err(|_| GrantError::Malformed)
    }
    pub fn decode(
        bytes: &[u8],
        audience: PrincipalId,
        now: UnixMillis,
    ) -> Result<Self, GrantError> {
        if bytes.len() > MAX_OFFER_BYTES {
            return Err(GrantError::StateCapacity);
        }
        let signed: Self = decode_canonical_dag_cbor(bytes).map_err(|_| GrantError::Malformed)?;
        signed.offer.validate()?;
        crate::signature::verify_digest_signature(
            &PublicKey::Secp256k1(signed.offer.provider.grant_producer()?.to_bytes()),
            &signed.signature,
            signed.offer.digest()?,
        )
        .map_err(|_| GrantError::Signature)?;
        if signed.offer.grant.kind.principal().id() != audience {
            return Err(GrantError::Audience);
        }
        if signed.offer.valid_until <= now {
            return Err(GrantError::Expired);
        }
        Ok(signed)
    }
}
impl Offer {
    fn validate(&self) -> Result<(), GrantError> {
        self.provider.check_grant_provider()?;
        self.grant.validate()?;
        if self.addresses.len() > 16
            || self.addresses.iter().any(|a| a.len() > 512)
            || self.sequence == 0
        {
            return Err(GrantError::Malformed);
        }
        Ok(())
    }
    fn digest(&self) -> Result<Digest, GrantError> {
        let body = canonical_dag_cbor(self).map_err(|_| GrantError::Malformed)?;
        Ok(super::super::work::xfh(b"hellas.work.offer.v1", &[&body]))
    }
    pub fn channel(&self) -> ChannelId {
        grant_channel_id(
            self.network,
            self.provider.content_id(),
            self.grant.id,
            self.grant.kind.principal().id(),
            self.generation,
        )
    }
}

mod policy_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &WorkPolicy, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.encode())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<WorkPolicy, D::Error> {
        WorkPolicy::decode(&serde_bytes::ByteBuf::deserialize(d)?).map_err(D::Error::custom)
    }
}
pub mod network {
    use super::*;
    pub fn serialize<S: Serializer>(n: &NetworkId, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(n.as_str())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NetworkId, D::Error> {
        NetworkId::new(&String::deserialize(d)?).ok_or_else(|| D::Error::custom("invalid network"))
    }
}
