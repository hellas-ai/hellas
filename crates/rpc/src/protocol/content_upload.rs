//! Content references and connection-bound upload signatures.
use hellas_auth::Digest;
use hellas_xet::XetFileHasher;

use super::content::encode_reference;
use crate::{ContentId, ContentRef};

pub const CONTENT_CHUNK_BYTES: usize = 64 * 1024;
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
