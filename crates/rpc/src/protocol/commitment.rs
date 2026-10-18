use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::tags;
use hellas_auth::Digest;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Assurance {
    #[default]
    ProducerSigned = tags::ASSURANCE_PRODUCER_SIGNED,
    AppleAppAttest = tags::ASSURANCE_APPLE_APP_ATTEST,
}

impl Assurance {
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Result<Self, TagError> {
        match byte {
            tags::ASSURANCE_PRODUCER_SIGNED => Ok(Self::ProducerSigned),
            tags::ASSURANCE_APPLE_APP_ATTEST => Ok(Self::AppleAppAttest),
            _ => Err(TagError::UnknownAssurance(byte)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Evaluate,
    Fetch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemeId(u8);

impl SchemeId {
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    pub fn from_byte(byte: u8) -> Result<Self, TagError> {
        match byte {
            tags::SCHEME_EVALUATE_PRODUCER_SIGNED
            | tags::SCHEME_FETCH_PRODUCER_SIGNED
            | tags::SCHEME_EVALUATE_APPLE_APP_ATTEST
            | tags::SCHEME_FETCH_APPLE_APP_ATTEST => Ok(Self(byte)),
            _ => Err(TagError::UnknownScheme(byte)),
        }
    }
}

pub const fn scheme_id(operation: Operation, assurance: Assurance) -> SchemeId {
    let tag = match (operation, assurance) {
        (Operation::Evaluate, Assurance::ProducerSigned) => tags::SCHEME_EVALUATE_PRODUCER_SIGNED,
        (Operation::Fetch, Assurance::ProducerSigned) => tags::SCHEME_FETCH_PRODUCER_SIGNED,
        (Operation::Evaluate, Assurance::AppleAppAttest) => tags::SCHEME_EVALUATE_APPLE_APP_ATTEST,
        (Operation::Fetch, Assurance::AppleAppAttest) => tags::SCHEME_FETCH_APPLE_APP_ATTEST,
    };
    SchemeId(tag)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TagError {
    #[error("unknown assurance tag byte 0x{0:02x}")]
    UnknownAssurance(u8),
    #[error("unknown scheme id byte 0x{0:02x}")]
    UnknownScheme(u8),
}

macro_rules! impl_u8_serde {
    ($ty:ty, $from:expr) => {
        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u8(self.to_byte())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct ByteVisitor;

                impl Visitor<'_> for ByteVisitor {
                    type Value = $ty;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a one-byte protocol tag")
                    }

                    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        $from(v).map_err(E::custom)
                    }

                    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        let byte = u8::try_from(v).map_err(E::custom)?;
                        self.visit_u8(byte)
                    }
                }

                deserializer.deserialize_u8(ByteVisitor)
            }
        }
    };
}

impl_u8_serde!(Assurance, Assurance::from_byte);
impl_u8_serde!(SchemeId, SchemeId::from_byte);

macro_rules! digest_commitment {
    ($ty:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $ty(pub Digest);

        impl $ty {
            pub fn from_canonical_bytes(canonical_bytes: &[u8]) -> Self {
                Self(Digest::hash(canonical_bytes))
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
    };
}

digest_commitment!(RequestCommitment);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_newtypes_hash_exact_canonical_bytes() {
        let bytes = b"\x82x\x19hellas.example.object.v1Ddata";
        assert_eq!(
            RequestCommitment::from_canonical_bytes(bytes).as_bytes(),
            Digest::hash(bytes).as_bytes()
        );
    }

    #[test]
    fn assurance_and_scheme_tags_are_pinned() {
        assert_eq!(Assurance::default(), Assurance::ProducerSigned);
        assert_eq!(Assurance::ProducerSigned.to_byte(), 0x00);
        assert_eq!(Assurance::AppleAppAttest.to_byte(), 0x01);
        assert_eq!(
            scheme_id(Operation::Evaluate, Assurance::ProducerSigned).to_byte(),
            0x00
        );
        assert_eq!(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned).to_byte(),
            0x01
        );
        assert_eq!(
            scheme_id(Operation::Evaluate, Assurance::AppleAppAttest).to_byte(),
            0x02
        );
        assert_eq!(
            scheme_id(Operation::Fetch, Assurance::AppleAppAttest).to_byte(),
            0x03
        );
    }
}
