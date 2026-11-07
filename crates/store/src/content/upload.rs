use hellas_rpc::ContentRef;
use hellas_xet::{Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, file_hash};

use super::{Cursor, Error, PinTarget, ReservationId, Result, Scope, chunk_page, core::Core};
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
pub(super) fn verify_list(object: ContentRef, chunks: &[Chunk]) -> Result<()> {
    if chunks
        .iter()
        .try_fold(0u64, |bytes, chunk| bytes.checked_add(chunk.data_len))
        != Some(object.bytes())
        || file_hash(chunks) != object.id().digest()
        || chunks
            .iter()
            .any(|chunk| chunk.data_len == 0 || chunk.data_len > MAX_CHUNK_SIZE as u64)
        || chunks
            .iter()
            .rev()
            .skip(1)
            .any(|chunk| chunk.data_len < MIN_CHUNK_SIZE as u64)
    {
        return Err(Error::Invalid("descriptor commitment"));
    }
    Ok(())
}
enum Destination {
    Verify,
    Local(Box<LocalSession>),
    Remote(super::remote::RemoteSession),
    Present,
}
pub struct UploadSession {
    destination: Destination,
    copy_charge: Option<std::sync::Arc<super::reservation::Reservation>>,
    ram: Option<super::Reservations>,
    descriptor_charge: Option<std::sync::Arc<super::reservation::Reservation>>,
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
            copy_charge: None,
            ram: None,
            descriptor_charge: None,
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
        self.copy_charge = None;
        self.descriptor_charge = None;
        self.destination = Destination::Verify;
    }
    pub(crate) fn local(object: ContentRef, destination: LocalSession) -> Self {
        let mut session = Self::new(object);
        session.ram = Some(destination.store.pool.clone());
        session.destination = Destination::Local(Box::new(destination));
        session
    }
    pub(crate) fn remote(
        object: ContentRef,
        destination: super::remote::RemoteSession,
        ram: super::Reservations,
    ) -> Self {
        let mut session = Self::new(object);
        session.ram = Some(ram);
        session.destination = Destination::Remote(destination);
        session
    }
    pub(crate) fn present(object: ContentRef) -> Self {
        let mut session = Self::new(object);
        session.destination = Destination::Present;
        session.published = true;
        session
    }
    /// Hash a verified owned reader with bounded scratch, then send canonical
    /// descriptor pages and chunks through this session's ordinary verifier.
    pub async fn copy_from(
        &mut self,
        mut reader: impl std::io::Read + std::io::Seek + Send + 'static,
        pool: &super::Reservations,
    ) -> Result<()> {
        let object = self.object;
        if self.complete() {
            return Ok(());
        }
        let descriptor_bytes = (object.bytes() / MIN_CHUNK_SIZE as u64 + 1)
            .checked_mul(std::mem::size_of::<Chunk>() as u64)
            .ok_or(Error::Capacity)?;
        // Source descriptors, the verifier's list, and the current page coexist;
        // the current read and previous CDC chunk each need one chunk of scratch.
        let charge = pool.reserve(
            descriptor_bytes
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add((MAX_CHUNK_SIZE * 2) as u64))
                .ok_or(Error::Capacity)?,
        )?;
        let (mut reader, chunks, mut charge) = tokio::task::spawn_blocking(move || {
            let mut hash = hellas_xet::XetFileHasher::new();
            let mut remaining = object.bytes();
            let mut scratch = vec![0; MAX_CHUNK_SIZE];
            while remaining != 0 {
                let len = remaining.min(scratch.len() as u64) as usize;
                reader.read_exact(&mut scratch[..len])?;
                hash.update(&scratch[..len]);
                remaining -= len as u64;
            }
            if reader.read(&mut [0])? != 0 {
                return Err(Error::Invalid("upload source grew"));
            }
            let chunks = hash.finalize_chunks();
            verify_list(object, &chunks)?;
            reader.rewind()?;
            Ok((reader, chunks, charge))
        })
        .await
        .map_err(|_| Error::Invalid("upload source worker"))??;
        self.copy_charge = Some(charge.clone());
        let mut cursor = Cursor::default();
        loop {
            let page = chunk_page(object, &chunks, cursor)?;
            self.declare(&page.chunks, page.next.is_none()).await?;
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        for chunk in chunks {
            let (returned, bytes, returned_charge) = tokio::task::spawn_blocking(move || {
                let mut bytes = vec![0; chunk.data_len as usize];
                reader.read_exact(&mut bytes)?;
                Ok::<_, Error>((reader, bytes, charge))
            })
            .await
            .map_err(|_| Error::Invalid("upload source worker"))??;
            reader = returned;
            charge = returned_charge;
            self.accept_chunk(&bytes).await?;
        }
        if !self.complete() {
            return Err(Error::Missing);
        }
        Ok(())
    }
    pub async fn declare(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        let result = self.declare_checked(chunks, complete).await;
        if result.is_err() {
            self.fail();
        }
        result
    }
    async fn declare_checked(&mut self, chunks: &[Chunk], complete: bool) -> Result<()> {
        let gate = if let Destination::Local(local) = &self.destination {
            let gate = local.store.effect_gate(&local.scope).await?;
            local.store.check(&local.scope)?;
            Some(gate)
        } else {
            None
        };
        self.declare_inner(chunks, complete)?;
        drop(gate);
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
        if self.copy_charge.is_none()
            && let Some(ram) = &self.ram
            && !chunks.is_empty()
        {
            let bytes = std::mem::size_of_val(chunks) as u64;
            if let Some(charge) = &self.descriptor_charge {
                charge.extend(bytes)?;
            } else {
                self.descriptor_charge = Some(ram.reserve(bytes)?);
            }
        }
        self.chunks
            .try_reserve_exact(chunks.len())
            .map_err(|_| Error::Capacity)?;
        self.chunks.extend_from_slice(chunks);
        self.declared_bytes = total;
        if complete {
            verify_list(self.object, &self.chunks)?;
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
        let gate = if let Destination::Local(local) = &self.destination {
            let gate = local.store.effect_gate(&local.scope).await?;
            local.store.check(&local.scope)?;
            Some(gate)
        } else {
            None
        };
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
                drop(gate);
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
                return self.publish().await;
            }
            Destination::Remote(remote) => {
                self.failed = true;
                remote.chunk(bytes, self.next, verified).await?;
                self.failed = false;
            }
            _ => {}
        }
        drop(gate);
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
            let charges = (self.descriptor_charge.take(), self.copy_charge.take());
            let chunks = std::mem::take(&mut self.chunks);
            self.failed = true;
            local
                .store
                .clone()
                .effect(&local.scope.clone(), move |core| {
                    core.publish(&mut local, chunks)?;
                    Ok(charges)
                })
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
