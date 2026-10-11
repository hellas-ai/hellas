use k256::ecdsa::signature::hazmat::{PrehashSigner as _, PrehashVerifier as _};
use k256::ecdsa::{Signature as K256Signature, SigningKey};
use k256::elliptic_curve::Generate as _;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::digest::Digest;
use crate::{hash_tuple, tags};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SignatureKind {
    Secp256k1 = tags::SIGNATURE_SECP256K1,
    Ed25519 = tags::SIGNATURE_ED25519,
    P256 = tags::SIGNATURE_P256,
}

impl SignatureKind {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Result<Self, SignatureError> {
        match byte {
            tags::SIGNATURE_SECP256K1 => Ok(Self::Secp256k1),
            tags::SIGNATURE_ED25519 => Ok(Self::Ed25519),
            tags::SIGNATURE_P256 => Ok(Self::P256),
            _ => Err(SignatureError::UnknownSignatureKind(byte)),
        }
    }
}

impl Serialize for SignatureKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_byte())
    }
}

impl<'de> Deserialize<'de> for SignatureKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let byte = u8::deserialize(deserializer)?;
        Self::from_byte(byte).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKey {
    Secp256k1([u8; 33]),
    Ed25519([u8; 32]),
    P256([u8; 33]),
}

impl PublicKey {
    pub const fn kind(&self) -> SignatureKind {
        match self {
            Self::Secp256k1(_) => SignatureKind::Secp256k1,
            Self::Ed25519(_) => SignatureKind::Ed25519,
            Self::P256(_) => SignatureKind::P256,
        }
    }

    pub const fn bytes(&self) -> &[u8] {
        match self {
            Self::Secp256k1(bytes) | Self::P256(bytes) => bytes,
            Self::Ed25519(bytes) => bytes,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("kind", &self.kind())
            .field("producer_id", &ProducerId::from_public_key(self))
            .finish()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.kind(), serde_bytes::Bytes::new(self.bytes())).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (kind, bytes): (SignatureKind, serde_bytes::ByteBuf) =
            Deserialize::deserialize(deserializer)?;
        match kind {
            SignatureKind::Secp256k1 => fixed(bytes.as_ref(), "secp256k1 public key")
                .map(Self::Secp256k1)
                .map_err(D::Error::custom),
            SignatureKind::Ed25519 => fixed(bytes.as_ref(), "Ed25519 public key")
                .map(Self::Ed25519)
                .map_err(D::Error::custom),
            SignatureKind::P256 => fixed(bytes.as_ref(), "P-256 public key")
                .map(Self::P256)
                .map_err(D::Error::custom),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signature {
    Secp256k1([u8; 64]),
    Ed25519([u8; 64]),
    P256([u8; 64]),
}

impl Signature {
    pub const LEN: usize = 64;

    pub const fn kind(&self) -> SignatureKind {
        match self {
            Self::Secp256k1(_) => SignatureKind::Secp256k1,
            Self::Ed25519(_) => SignatureKind::Ed25519,
            Self::P256(_) => SignatureKind::P256,
        }
    }

    pub const fn bytes(&self) -> &[u8; Self::LEN] {
        match self {
            Self::Secp256k1(bytes) | Self::Ed25519(bytes) | Self::P256(bytes) => bytes,
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.kind(), serde_bytes::Bytes::new(self.bytes())).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (kind, bytes): (SignatureKind, serde_bytes::ByteBuf) =
            Deserialize::deserialize(deserializer)?;
        let bytes = fixed(bytes.as_ref(), "signature").map_err(D::Error::custom)?;
        Ok(match kind {
            SignatureKind::Secp256k1 => Self::Secp256k1(bytes),
            SignatureKind::Ed25519 => Self::Ed25519(bytes),
            SignatureKind::P256 => Self::P256(bytes),
        })
    }
}

fn fixed<const N: usize>(bytes: &[u8], name: &str) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes, got {}", bytes.len()))
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProducerId(Digest);

impl ProducerId {
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let kind = [public_key.kind().to_byte()];
        Self(hash_tuple(
            tags::PRODUCER_ID_V2,
            &[&kind, public_key.bytes()],
        ))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ProducerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProducerId").field(&self.0).finish()
    }
}

#[derive(Clone)]
pub struct ProducerSigningKey {
    inner: SigningKey,
}

impl ProducerSigningKey {
    pub fn generate() -> Self {
        let inner = SigningKey::generate();
        Self { inner }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Result<Self, SignatureError> {
        let field_bytes = k256::FieldBytes::from(bytes);
        let inner = SigningKey::from_bytes(&field_bytes).map_err(SignatureError::from)?;
        Ok(Self { inner })
    }

    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }

    pub fn public_key(&self) -> PublicKey {
        let point = self.inner.verifying_key().to_sec1_point(true);
        PublicKey::Secp256k1(
            point
                .as_bytes()
                .try_into()
                .expect("compressed secp256k1 public key is 33 bytes"),
        )
    }

    pub fn producer_id(&self) -> ProducerId {
        ProducerId::from_public_key(&self.public_key())
    }

    pub fn sign_digest(&self, digest: Digest) -> Result<Signature, SignatureError> {
        let signature: K256Signature = self.inner.sign_prehash(digest.as_bytes())?;
        let signature = signature.normalize_s();
        Ok(Signature::Secp256k1(signature.to_bytes().into()))
    }

    #[cfg(test)]
    pub(crate) fn deterministic_for_tests() -> Self {
        Self::from_secret_bytes([1; 32]).expect("valid deterministic test key")
    }
}

pub fn verify_digest_signature(
    public_key: &PublicKey,
    signature: &Signature,
    digest: Digest,
) -> Result<(), SignatureError> {
    match (public_key, signature) {
        (PublicKey::Secp256k1(key), Signature::Secp256k1(signature)) => {
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(key)?;
            let signature = K256Signature::from_slice(signature)?;
            if signature.normalize_s() != signature {
                return Err(SignatureError::HighS);
            }
            key.verify_prehash(digest.as_bytes(), &signature)?;
        }
        (PublicKey::Ed25519(key), Signature::Ed25519(signature)) => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(key)
                .map_err(|error| SignatureError::Ed25519(error.to_string()))?;
            key.verify_strict(
                digest.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(signature),
            )
            .map_err(|error| SignatureError::Ed25519(error.to_string()))?;
        }
        (PublicKey::P256(key), Signature::P256(signature)) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                .map_err(|error| SignatureError::P256(error.to_string()))?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|error| SignatureError::P256(error.to_string()))?;
            if signature.normalize_s() != signature {
                return Err(SignatureError::HighS);
            }
            key.verify_prehash(digest.as_bytes(), &signature)
                .map_err(|error| SignatureError::P256(error.to_string()))?;
        }
        _ => {
            return Err(SignatureError::KindMismatch {
                public_key: public_key.kind(),
                signature: signature.kind(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("unknown signature kind byte 0x{0:02x}")]
    UnknownSignatureKind(u8),
    #[error("public key kind {public_key:?} does not match signature kind {signature:?}")]
    KindMismatch {
        public_key: SignatureKind,
        signature: SignatureKind,
    },
    #[error("ECDSA signature is not normalized to low-S form")]
    HighS,
    #[error("secp256k1 error: {0}")]
    Secp256k1(String),
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
    #[error("P-256 error: {0}")]
    P256(String),
}

impl From<k256::ecdsa::Error> for SignatureError {
    fn from(error: k256::ecdsa::Error) -> Self {
        Self::Secp256k1(error.to_string())
    }
}

impl From<k256::elliptic_curve::Error> for SignatureError {
    fn from(error: k256::elliptic_curve::Error) -> Self {
        Self::Secp256k1(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn all_schemes_verify_protocol_digest() {
        let digest = hash_tuple("test.digest", &[b"payload"]);
        let secp = ProducerSigningKey::deterministic_for_tests();
        verify_digest_signature(
            &secp.public_key(),
            &secp.sign_digest(digest).unwrap(),
            digest,
        )
        .unwrap();

        let ed = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let ed_signature = ed.sign(digest.as_bytes()).to_bytes();
        verify_digest_signature(
            &PublicKey::Ed25519(ed.verifying_key().to_bytes()),
            &Signature::Ed25519(ed_signature),
            digest,
        )
        .unwrap();

        let p256 = p256::ecdsa::SigningKey::from_bytes(&[3; 32].into()).unwrap();
        let p256_signature: p256::ecdsa::Signature = p256.sign_prehash(digest.as_bytes()).unwrap();
        verify_digest_signature(
            &PublicKey::P256(
                p256.verifying_key()
                    .to_sec1_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            ),
            &Signature::P256(p256_signature.normalize_s().to_bytes().into()),
            digest,
        )
        .unwrap();
    }

    #[test]
    fn tag_mismatch_fails() {
        let key = ProducerSigningKey::deterministic_for_tests();
        let digest = hash_tuple("test.digest", &[b"payload"]);
        let signature = Signature::P256(*key.sign_digest(digest).unwrap().bytes());
        assert!(matches!(
            verify_digest_signature(&key.public_key(), &signature, digest),
            Err(SignatureError::KindMismatch { .. })
        ));
    }
}
