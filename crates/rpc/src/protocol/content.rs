//! Content identities and lengths shared by execution applications.
use crate::ContentId;

/// An exact Xet-addressed content object and its expected byte length.
///
/// Acquisition must verify both before the object is compiled or lent to the
/// execution runtime.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct ContentRef {
    id: ContentId,
    bytes: u64,
}

impl ContentRef {
    /// Names content together with the length its verified handle must expose.
    #[must_use]
    pub const fn new(id: ContentId, bytes: u64) -> Self {
        Self { id, bytes }
    }

    #[must_use]
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self::new(ContentId::hash(bytes), bytes.len() as u64)
    }

    /// Returns the Xet content identifier.
    #[must_use]
    pub const fn id(self) -> ContentId {
        self.id
    }

    /// Returns the exact expected object length.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

pub const CONTENT_REF_BYTES: usize = std::mem::size_of::<[u8; 32]>() + std::mem::size_of::<u64>();

pub fn encode_reference(reference: ContentRef) -> Vec<u8> {
    let mut bytes = reference.id().as_bytes().to_vec();
    bytes.extend_from_slice(&reference.bytes().to_be_bytes());
    bytes
}

pub fn decode_reference(bytes: &[u8]) -> Option<ContentRef> {
    if bytes.len() != CONTENT_REF_BYTES {
        return None;
    }
    Some(ContentRef::new(
        ContentId::from_bytes(bytes[..32].try_into().ok()?),
        u64::from_be_bytes(bytes[32..].try_into().ok()?),
    ))
}
