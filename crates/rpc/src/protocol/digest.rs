use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use hellas_xet::XetHashError;

pub use hellas_auth::{Digest, hash_tuple};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentId(Digest);

impl ContentId {
    pub fn hash(bytes: &[u8]) -> Self {
        Self(Digest::hash(bytes))
    }

    pub const fn from_bytes(bytes: [u8; Digest::LEN]) -> Self {
        Self(Digest::from_bytes(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, XetHashError> {
        Digest::from_slice(bytes).map(Self)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

impl FromStr for ContentId {
    type Err = XetHashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ContentId").field(&self.0).finish()
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_tuple_is_length_delimited() {
        let a = hash_tuple("tag", &[b"ab", b"c"]);
        let b = hash_tuple("tag", &[b"a", b"bc"]);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_hash_is_xet_file_hash() {
        assert_eq!(
            Digest::hash(b"abc"),
            hellas_xet::file_hash(&hellas_xet::chunk(b"abc"))
        );
    }

    #[test]
    fn digest_serializes_as_bytes() {
        let digest = Digest::from_bytes([7; 32]);
        let bytes = serde_ipld_dagcbor::to_vec(&digest).unwrap();
        assert_eq!(bytes, [&[0x58, 0x20][..], &[7; 32][..]].concat());
        let decoded: Digest = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
        assert_eq!(decoded, digest);
    }
}
