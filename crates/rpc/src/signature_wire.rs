//! Canonical key/signature conversion at the protobuf boundary.
use crate::pb::execute::{
    PublicKey as PbPublicKey, Signature as PbSignature, public_key, signature,
};
use crate::{Assurance, PublicKey, Signature};
pub fn public_key_to_pb(key: &PublicKey) -> PbPublicKey {
    let kind = match key {
        PublicKey::Secp256k1(bytes) => public_key::Kind::Secp256k1(bytes.to_vec()),
        PublicKey::Ed25519(bytes) => public_key::Kind::Ed25519(bytes.to_vec()),
        PublicKey::P256(bytes) => public_key::Kind::P256(bytes.to_vec()),
    };
    PbPublicKey { kind: Some(kind) }
}

pub fn public_key_from_pb(key: PbPublicKey) -> Result<PublicKey, SignatureWireError> {
    match key.kind.ok_or(SignatureWireError::MissingPublicKeyKind)? {
        public_key::Kind::Secp256k1(bytes) => {
            Ok(PublicKey::Secp256k1(fixed("secp256k1 public key", &bytes)?))
        }
        public_key::Kind::Ed25519(bytes) => {
            Ok(PublicKey::Ed25519(fixed("Ed25519 public key", &bytes)?))
        }
        public_key::Kind::P256(bytes) => Ok(PublicKey::P256(fixed("P-256 public key", &bytes)?)),
    }
}

pub fn signature_to_pb(value: &Signature) -> PbSignature {
    let kind = match value {
        Signature::Secp256k1(bytes) => signature::Kind::Secp256k1(bytes.to_vec()),
        Signature::Ed25519(bytes) => signature::Kind::Ed25519(bytes.to_vec()),
        Signature::P256(bytes) => signature::Kind::P256(bytes.to_vec()),
    };
    PbSignature { kind: Some(kind) }
}

pub fn signature_from_pb(value: PbSignature) -> Result<Signature, SignatureWireError> {
    match value.kind.ok_or(SignatureWireError::MissingSignatureKind)? {
        signature::Kind::Secp256k1(bytes) => {
            Ok(Signature::Secp256k1(fixed("secp256k1 signature", &bytes)?))
        }
        signature::Kind::Ed25519(bytes) => {
            Ok(Signature::Ed25519(fixed("Ed25519 signature", &bytes)?))
        }
        signature::Kind::P256(bytes) => Ok(Signature::P256(fixed("P-256 signature", &bytes)?)),
    }
}

pub fn assurance_from_pb(value: i32) -> Result<Assurance, SignatureWireError> {
    let byte = u8::try_from(value).map_err(|_| SignatureWireError::UnknownAssurance(value))?;
    Assurance::from_byte(byte).map_err(|_| SignatureWireError::UnknownAssurance(value))
}

fn fixed<const N: usize>(field: &'static str, bytes: &[u8]) -> Result<[u8; N], SignatureWireError> {
    bytes
        .try_into()
        .map_err(|_| SignatureWireError::WrongLength {
            field,
            expected: N,
            actual: bytes.len(),
        })
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureWireError {
    #[error("public key has no kind")]
    MissingPublicKeyKind,
    #[error("signature has no kind")]
    MissingSignatureKind,
    #[error("{field} must be {expected} bytes, got {actual}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("unknown assurance tag {0}")]
    UnknownAssurance(i32),
}
