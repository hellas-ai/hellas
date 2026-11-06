use hellas_rpc::ContentRef;
use hellas_xet::{Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, file_hash};

use super::{Error, Result};
use prost::Message;

/// Declare-then-fill verification. Payload is accepted only after the complete
/// descriptor commitment; one preceding chunk suffices to verify CDC boundaries.
pub struct UploadSession {
    object: ContentRef,
    chunks: Vec<Chunk>,
    declared_bytes: u64,
    declared: bool,
    next: usize,
    previous: Vec<u8>,
    failed: bool,
}
impl UploadSession {
    pub fn new(object: ContentRef) -> Self {
        Self {
            object,
            chunks: Vec::new(),
            declared_bytes: 0,
            declared: false,
            next: 0,
            previous: Vec::new(),
            failed: false,
        }
    }
    pub fn object(&self) -> ContentRef {
        self.object
    }
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }
    pub fn next_chunk(&self) -> usize {
        self.next
    }
    pub fn complete(&self) -> bool {
        !self.failed && self.declared && self.next == self.chunks.len()
    }
    pub fn declare(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        let result = self.declare_inner(chunks, complete);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn declare_inner(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        if self.failed || self.declared {
            return Err(Error::Invalid("upload declaration state"));
        }
        let count = self
            .chunks
            .len()
            .checked_add(chunks.len())
            .ok_or(Error::Invalid("chunk count overflow"))?;
        if count as u64 > self.object.bytes() / MIN_CHUNK_SIZE as u64 + 1 {
            return Err(Error::Invalid("chunk count"));
        }
        let mut total = self.declared_bytes;
        for chunk in chunks {
            if chunk.data_len == 0 || chunk.data_len > MAX_CHUNK_SIZE as u64 {
                return Err(Error::Invalid("chunk length"));
            }
            total = total
                .checked_add(chunk.data_len)
                .ok_or(Error::Invalid("chunk length overflow"))?;
        }
        if total > self.object.bytes() {
            return Err(Error::Invalid("object length"));
        }
        // Measure the real protobuf page without cloning a caller-sized list.
        use hellas_rpc::pb::content::{ChunkList, UploadRequest, upload_request::Part};
        let mut list_size = ChunkList {
            chunks: Vec::new(),
            complete,
        }
        .encoded_len();
        for chunk in chunks {
            let item_size = ChunkList {
                chunks: vec![super::page::wire_chunk(chunk)],
                complete: false,
            }
            .encoded_len();
            list_size = list_size
                .checked_add(item_size)
                .ok_or(Error::Invalid("chunk page size"))?;
            if list_size > super::body_limit() {
                return Err(Error::Invalid("chunk page body"));
            }
        }
        let tag_size = UploadRequest {
            part: Some(Part::List(ChunkList::default())),
        }
        .encoded_len()
            - prost::length_delimiter_len(0);
        if tag_size + prost::length_delimiter_len(list_size) + list_size > super::body_limit() {
            return Err(Error::Invalid("chunk page body"));
        }
        self.chunks.extend_from_slice(chunks);
        self.declared_bytes = total;
        if complete {
            if total != self.object.bytes() || file_hash(&self.chunks) != self.object.id().digest()
            {
                return Err(Error::Invalid("descriptor commitment"));
            }
            if self
                .chunks
                .iter()
                .rev()
                .skip(1)
                .any(|chunk| chunk.data_len < MIN_CHUNK_SIZE as u64)
            {
                return Err(Error::Invalid("short nonfinal chunk"));
            }
            self.declared = true;
        }
        Ok(())
    }
    pub fn accept_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.accept_inner(bytes);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn accept_inner(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed || !self.declared {
            return Err(Error::Invalid("payload before declaration"));
        }
        let expected = self
            .chunks
            .get(self.next)
            .ok_or(Error::Invalid("extra payload"))?;
        if bytes.len() as u64 != expected.data_len
            || hellas_xet::chunk(bytes).as_slice() != [*expected]
        {
            return Err(Error::Invalid("chunk hash or canonical partition"));
        }
        if !self.previous.is_empty() {
            self.previous.push(bytes[0]);
            if hellas_xet::chunk(&self.previous)
                .first()
                .is_none_or(|chunk| chunk.data_len != (self.previous.len() - 1) as u64)
            {
                return Err(Error::Invalid("noncanonical chunk boundary"));
            }
        }
        self.previous.clear();
        self.previous.extend_from_slice(bytes);
        self.next += 1;
        Ok(())
    }
}
