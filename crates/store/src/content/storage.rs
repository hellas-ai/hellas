//! The byte-storage difference between the shared RAM and disk core.
use super::{core::Core, disk::FileObject, reservation::Reservation, *};
use bytes::Bytes;
use hellas_rpc::ContentRef;
use hellas_xet::Chunk;
use std::{
    io::{Read, Seek, Write},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) enum Data {
    Ram(Bytes),
    File(Arc<FileObject>),
}
impl Data {
    pub fn len(&self) -> u64 {
        match self {
            Self::Ram(bytes) => bytes.len() as u64,
            Self::File(file) => file.object.bytes(),
        }
    }
    pub fn load(&self, object: ContentRef) -> Result<Bytes> {
        if self.len() != object.bytes() {
            return Err(Error::Invalid("content length contract"));
        }
        match self {
            Self::Ram(bytes) => Ok(bytes.clone()),
            Self::File(file) => file.load(),
        }
    }
    pub fn stream(
        &self,
        object: ContentRef,
        chunks: &[Chunk],
        range: std::ops::Range<u64>,
    ) -> Result<std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Bytes>> + Send>>> {
        if self.len() != object.bytes() {
            return Err(Error::Invalid("content length contract"));
        }
        match self {
            Self::File(file) => file.stream(chunks, range),
            Self::Ram(bytes) => {
                let mut selected = Vec::new();
                let mut offset = 0;
                for chunk in chunks {
                    let end = offset + chunk.data_len;
                    if offset < range.end && end > range.start {
                        selected.push(Ok(bytes
                            .slice(offset.max(range.start) as usize..end.min(range.end) as usize)));
                    }
                    offset = end;
                }
                Ok(Box::pin(futures::stream::iter(selected)))
            }
        }
    }
    pub fn merge(&self, older: &Data) {
        if let (Self::File(new), Self::File(old)) = (self, older) {
            new.merge(old);
        }
    }
    pub fn check(&self, object: ContentRef) -> Result<()> {
        if self.len() != object.bytes() {
            return Err(Error::Invalid("content length contract"));
        }
        if !self.available() {
            return Err(Error::Missing);
        }
        Ok(())
    }
    pub fn available(&self) -> bool {
        match self {
            Self::Ram(_) => true,
            Self::File(file) => file.open().is_ok(),
        }
    }
    pub fn publish(&self) -> Result<()> {
        if let Self::File(file) = self {
            file.publish()?;
        }
        Ok(())
    }
}
struct ChargedBytes {
    bytes: Bytes,
    _charge: Arc<Reservation>,
}
impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
pub(crate) fn charged(bytes: Bytes, charge: Arc<Reservation>) -> Bytes {
    Bytes::from_owner(ChargedBytes {
        bytes,
        _charge: charge,
    })
}

pub(crate) struct Buffer {
    body: Option<Body>,
    charge: Arc<Reservation>,
    limit: u64,
    len: u64,
}
enum Body {
    Ram(Vec<u8>),
    File(tempfile::NamedTempFile, Arc<super::disk::Disk>),
}
impl Buffer {
    pub fn new(core: &Core, limit: u64, charge: Arc<Reservation>) -> Result<Self> {
        let body = if let Some(disk) = &core.disk {
            Body::File(
                tempfile::NamedTempFile::new_in(disk.root.join("staging"))?,
                disk.clone(),
            )
        } else {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(usize::try_from(limit).map_err(|_| Error::Capacity)?)
                .map_err(|_| Error::Capacity)?;
            Body::Ram(bytes)
        };
        Ok(Self {
            body: Some(body),
            charge,
            limit,
            len: 0,
        })
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn fill(
        &mut self,
        mut source: impl Read,
        sha: Option<[u8; 32]>,
        scratch: &Reservations,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        match self.body.as_mut().unwrap() {
            Body::Ram(bytes) => {
                bytes.resize(self.limit as usize, 0);
                while self.len < self.limit {
                    let end = (self.len as usize + hellas_xet::MAX_CHUNK_SIZE).min(bytes.len());
                    let count = source.read(&mut bytes[self.len as usize..end])?;
                    if count == 0 {
                        return Err(Error::Invalid("source shorter than declared bytes"));
                    }
                    hash.update(&bytes[self.len as usize..self.len as usize + count]);
                    self.len += count as u64;
                }
            }
            Body::File(_, _) => {
                let _scratch = scratch.reserve(hellas_xet::MAX_CHUNK_SIZE as u64)?;
                let mut bytes = vec![0; hellas_xet::MAX_CHUNK_SIZE];
                while self.len < self.limit {
                    let wanted = (self.limit - self.len).min(bytes.len() as u64) as usize;
                    let count = source.read(&mut bytes[..wanted])?;
                    if count == 0 {
                        return Err(Error::Invalid("source shorter than declared bytes"));
                    }
                    hash.update(&bytes[..count]);
                    self.write_all(&bytes[..count])?;
                }
            }
        }
        let mut sentinel = [0];
        if source.read(&mut sentinel)? != 0
            || sha.is_some_and(|expected| hash.finalize().as_slice() != expected)
        {
            return Err(Error::Invalid("source length or SHA-256"));
        }
        Ok(())
    }
    pub fn canonical(&mut self) -> Result<Vec<Chunk>> {
        if self.len != self.limit {
            return Err(Error::Invalid("incomplete object"));
        }
        match self.body.as_mut().unwrap() {
            Body::Ram(bytes) => Ok(hellas_xet::chunk(bytes)),
            Body::File(file, disk) => {
                let _scratch = disk.ram.reserve(crate::STREAM_BUFFER as u64)?;
                file.rewind()?;
                let indexed = crate::hash_exact_length(file, self.len)?
                    .ok_or(Error::Invalid("staging changed"))?;
                Ok(indexed.chunks)
            }
        }
    }
    pub fn finish(mut self, object: ContentRef, chunks: Vec<Chunk>) -> Result<Data> {
        if self.len != object.bytes() {
            return Err(Error::Invalid("incomplete object"));
        }
        Ok(match self.body.take().unwrap() {
            Body::Ram(bytes) => Data::Ram(charged(Bytes::from(bytes), self.charge.clone())),
            Body::File(file, disk) => {
                match FileObject::staged(disk, file, object, chunks, self.charge.clone()) {
                    Ok(file) => Data::File(Arc::new(file)),
                    Err(error) => {
                        self.charge.rewind(self.len);
                        return Err(error);
                    }
                }
            }
        })
    }
}
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.limit - self.len {
            return Err(std::io::Error::other("source exceeds reservation"));
        }
        let count = match self.body.as_mut().unwrap() {
            Body::Ram(buffer) => {
                buffer.extend_from_slice(bytes);
                bytes.len()
            }
            Body::File(file, _) => {
                let count = file.write(bytes)?;
                self.charge
                    .written(count as u64)
                    .map_err(std::io::Error::other)?;
                count
            }
        };
        self.len += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.body.as_mut().unwrap() {
            Body::Ram(_) => Ok(()),
            Body::File(file, _) => file.flush(),
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if matches!(self.body, Some(Body::File(_, _))) {
            self.charge.rewind(self.len);
        }
    }
}
