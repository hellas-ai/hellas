use hellas_rpc::{ContentRef, pb::content as pb};
use hellas_xet::Chunk;
use prost::Message;

use super::{ChunkPage, Cursor, Error, Result};

pub fn body_limit() -> usize {
    (hellas_wire::mux::DEFAULT_STREAM_WINDOW as usize).min(hellas_wire::frame::MAX_FRAME_BYTES)
}

pub(crate) fn wire_ref(object: ContentRef) -> pb::ContentRef {
    pb::ContentRef {
        id: object.id().as_bytes().to_vec(),
        bytes: object.bytes(),
    }
}
pub(crate) fn wire_chunk(chunk: &Chunk) -> pb::Chunk {
    pb::Chunk {
        hash: chunk.hash.as_bytes().to_vec(),
        bytes: chunk.data_len,
    }
}

pub fn chunk_page(object: ContentRef, chunks: &[Chunk], cursor: Cursor) -> Result<ChunkPage> {
    if cursor.object.is_some_and(|old| old != object)
        || (cursor.offset != 0 && cursor.object.is_none())
    {
        return Err(Error::Conflict);
    }
    let start = usize::try_from(cursor.offset).map_err(|_| Error::Invalid("chunk cursor"))?;
    if start > chunks.len() {
        return Err(Error::Invalid("chunk cursor"));
    }
    // Reserve the complete largest cursor envelope, including its protobuf tags.
    let base = pb::ChunksResponse {
        object: Some(wire_ref(object)),
        chunks: Vec::new(),
        next: Some(pb::Cursor {
            offset: u64::MAX,
            object: Some(wire_ref(object)),
            generation: u64::MAX,
        }),
    };
    let mut size = base.encoded_len();
    let mut end = start;
    for chunk in &chunks[start..] {
        let item = pb::ChunksResponse {
            chunks: vec![wire_chunk(chunk)],
            ..Default::default()
        }
        .encoded_len();
        if size
            .checked_add(item)
            .is_none_or(|next| next > body_limit())
        {
            break;
        }
        size += item;
        end += 1;
    }
    let next = (end < chunks.len()).then_some(Cursor {
        offset: end as u64,
        object: Some(object),
        generation: cursor.generation,
    });
    Ok(ChunkPage {
        object,
        chunks: chunks[start..end].to_vec(),
        next,
    })
}
