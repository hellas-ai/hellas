//! Content references and connection-bound upload signatures.
use hellas_auth::Digest;
use hellas_xet::XetFileHasher;

use crate::{ContentId, ContentRef};

pub const CONTENT_CHUNK_BYTES: usize = 64 * 1024;
pub const CONTENT_REF_BYTES: usize = 40;

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

pub fn chunk_digest(
    channel: Digest,
    work: Digest,
    object: ContentRef,
    offset: u64,
    chunk: &[u8],
    exporter: &[u8; 32],
) -> Digest {
    let mut hash = XetFileHasher::new();
    for part in [
        b"hellas.work.content-chunk.v1".as_slice(),
        channel.as_bytes(),
        work.as_bytes(),
        &encode_reference(object),
        &offset.to_be_bytes(),
        ContentId::hash(chunk).as_bytes(),
        exporter,
    ] {
        hash.update(part);
    }
    hash.finalize()
}
