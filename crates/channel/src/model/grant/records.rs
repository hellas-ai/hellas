use hellas_auth::PublicKey;
use hellas_auth::authority::Revision;
use hellas_kernel::{Key, NetworkId};
use hellas_rpc::ProviderEnrollmentBundle;
use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

pub const MAX_OFFER_BYTES: usize = 256 * 1024;

pub const MAX_ENROLLMENT_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("malformed grant record")]
    Malformed,
    #[error("grant enrollment requires a secp256k1 producer and Ed25519 transport")]
    UnsupportedKey,
    #[error("grant enrollment requires a verifiable software root")]
    UnsupportedRoot,
    #[error("invalid enrollment or record signature")]
    Signature,
    #[error("identity or offer binding mismatch")]
    Audience,
    #[error("job or offer has expired")]
    Expired,
    #[error("grant is paused")]
    Paused,
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

pub fn grant_producer(provider: &ProviderEnrollmentBundle) -> Result<Key, GrantError> {
    let PublicKey::Secp256k1(bytes) = provider.genesis.statement.producer_public_key else {
        return Err(GrantError::UnsupportedKey);
    };
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| GrantError::UnsupportedKey)?;
    Ok(Key::from_bytes(bytes))
}

pub fn grant_transport(provider: &ProviderEnrollmentBundle) -> Result<[u8; 32], GrantError> {
    match provider.genesis.statement.transport_public_key {
        PublicKey::Ed25519(bytes) => Ok(bytes),
        _ => Err(GrantError::UnsupportedKey),
    }
}

/// Checks enrollment bounds and key shapes; callers separately verify root trust.
pub fn check_grant_provider(provider: &ProviderEnrollmentBundle) -> Result<(), GrantError> {
    if provider.canonical_bytes().len() > MAX_ENROLLMENT_BYTES {
        return Err(GrantError::Malformed);
    }
    grant_producer(provider)?;
    grant_transport(provider)?;
    Ok(())
}

/// Canonical, bounded provider enrollment bytes.
pub mod provider_bytes {
    use super::*;
    pub fn serialize<S: Serializer>(p: &ProviderEnrollmentBundle, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&p.canonical_bytes())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<ProviderEnrollmentBundle, D::Error> {
        let bytes = serde_bytes::ByteBuf::deserialize(d)?;
        if bytes.len() > MAX_ENROLLMENT_BYTES {
            return Err(D::Error::custom(GrantError::Malformed));
        }
        let provider =
            ProviderEnrollmentBundle::from_canonical_bytes(&bytes).map_err(D::Error::custom)?;
        check_grant_provider(&provider).map_err(D::Error::custom)?;
        Ok(provider)
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
