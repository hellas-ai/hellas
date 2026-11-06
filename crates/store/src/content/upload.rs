use hellas_rpc::ContentRef;
use hellas_xet::{Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, file_hash};

use super::{Error, PinTarget, ReservationId, Result, Scope, core::Core};
use prost::Message;

/// Declare-then-fill verification. Payload is accepted only after the complete
/// descriptor commitment; one preceding chunk suffices to verify CDC boundaries.
pub(crate) struct LocalSession {
    pub store: Core,
    pub scope: Scope,
    pub pin: Option<PinTarget>,
    pub object: ContentRef,
    pub reservation: ReservationId,
    pub bytes: Option<super::storage::Buffer>,
    pub finished: bool,
    pub output: bool,
}
impl Drop for LocalSession {
    fn drop(&mut self) {
        if !self.finished {
            drop(self.bytes.take());
            self.store.abandon(
                self.reservation,
                self.object.id(),
                if self.output { self.object.bytes() } else { 0 },
            );
        }
    }
}
enum Destination {
    Verify,
    Local(Box<LocalSession>),
    Remote(super::remote::RemoteSession),
    Present,
}
pub struct UploadSession {
    destination: Destination,
    object: ContentRef,
    chunks: Vec<Chunk>,
    declared_bytes: u64,
    declared: bool,
    next: usize,
    previous: Vec<u8>,
    failed: bool,
    published: bool,
}
impl UploadSession {
    pub fn new(object: ContentRef) -> Self {
        Self {
            destination: Destination::Verify,
            object,
            chunks: Vec::new(),
            declared_bytes: 0,
            declared: false,
            next: 0,
            previous: Vec::new(),
            failed: false,
            published: false,
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
        !self.failed && self.published
    }
    fn verified(&self) -> bool {
        !self.failed && self.declared && self.next == self.chunks.len()
    }
    fn fail(&mut self) {
        self.failed = true;
        self.published = false;
        self.previous = Vec::new();
        self.chunks = Vec::new();
        self.destination = Destination::Verify;
    }
    pub(crate) fn local(object: ContentRef, destination: LocalSession) -> Self {
        let mut session = Self::new(object);
        session.destination = Destination::Local(Box::new(destination));
        session
    }
    pub(crate) fn remote(object: ContentRef, destination: super::remote::RemoteSession) -> Self {
        let mut session = Self::new(object);
        session.destination = Destination::Remote(destination);
        session
    }
    pub(crate) fn present(object: ContentRef) -> Self {
        let mut session = Self::new(object);
        session.destination = Destination::Present;
        session.published = true;
        session
    }
    pub async fn declare(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        let result = self.declare_checked(chunks, complete).await;
        if result.is_err() {
            self.fail();
        }
        result
    }
    async fn declare_checked(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        if let Destination::Local(local) = &self.destination {
            local.store.check(&local.scope)?;
        }
        self.declare_inner(chunks, complete)?;
        let verified = self.verified();
        if let Destination::Remote(remote) = &mut self.destination {
            // Cancellation leaves this verifier terminal, so a lost acknowledgement
            // cannot be mistaken for accepted remote progress on a retry.
            self.failed = true;
            remote.declare(chunks, complete, verified).await?;
            self.failed = false;
        }
        self.publish().await
    }
    fn declare_inner(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        if self.failed || self.declared || self.published {
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
    pub async fn accept_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.accept_checked(bytes).await;
        if result.is_err() {
            self.fail();
        }
        result
    }
    async fn accept_checked(&mut self, bytes: &[u8]) -> Result<()> {
        if let Destination::Local(local) = &self.destination {
            local.store.check(&local.scope)?;
        }
        self.accept_inner(bytes)?;
        let verified = self.verified();
        match &mut self.destination {
            Destination::Local(local) if local.store.disk.is_none() => {
                use std::io::Write;
                local
                    .bytes
                    .as_mut()
                    .ok_or(Error::Invalid("upload already published"))?
                    .write_all(bytes)?;
            }
            Destination::Local(_) => {
                let Destination::Local(local) =
                    std::mem::replace(&mut self.destination, Destination::Verify)
                else {
                    unreachable!()
                };
                let core = local.store.clone();
                let charge = core.pool.reserve(bytes.len() as u64)?;
                let bytes = super::storage::charged(bytes::Bytes::copy_from_slice(bytes), charge);
                self.failed = true;
                self.destination =
                    Destination::Local(Box::new(core.write_local(*local, bytes).await?));
                self.failed = false;
            }
            Destination::Remote(remote) => {
                self.failed = true;
                remote.chunk(bytes, self.next, verified).await?;
                self.failed = false;
            }
            _ => {}
        }
        self.publish().await
    }
    async fn publish(&mut self) -> Result<()> {
        if !self.verified() {
            return Ok(());
        }
        if matches!(&self.destination, Destination::Local(_)) {
            let Destination::Local(mut local) =
                std::mem::replace(&mut self.destination, Destination::Verify)
            else {
                unreachable!()
            };
            let chunks = self.chunks.clone();
            self.failed = true;
            local
                .store
                .clone()
                .effect(move |core| core.publish(&mut local, chunks))
                .await?;
            self.failed = false;
        }
        self.published = true;
        self.previous = Vec::new();
        Ok(())
    }
    fn accept_inner(&mut self, bytes: &[u8]) -> Result<()> {
        if self.failed || !self.declared || self.published {
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
