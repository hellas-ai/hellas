//! Proposal-scoped content transport. Only compute content may reach disk.
use std::{
    collections::BTreeMap,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use hellas_auth::Digest;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::content_upload::{CONTENT_CHUNK_BYTES, decode_reference, encode_reference},
};
use hellas_store::ContentStore;

pub const MAX_CONTENT_BYTES: usize = crate::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES as usize;
pub const DEFAULT_MAX_STAGING_BYTES: u64 = MAX_CONTENT_BYTES as u64;

#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("invalid content reference, offset or chunk")]
    Invalid,
    #[error("another unaccepted proposal occupies this channel")]
    ProposalLimit,
    #[error("upload exceeds max_upload_bytes ({0})")]
    UploadLimit(u64),
    #[error("upload exceeds node max_staging_bytes ({0})")]
    StagingLimit(u64),
    #[error("content does not match its declared hash")]
    Hash,
    #[error("the proposal's complete content is unavailable")]
    Missing,
    #[error("content storage failed: {0}")]
    Storage(String),
}
impl From<std::io::Error> for ContentError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

/// Shared by every upload channel served by one node, including ephemeral ones.
#[derive(Clone, Debug)]
pub struct UploadQuota {
    max_staging_bytes: u64,
    held: Arc<Mutex<BTreeMap<Digest, u64>>>,
}
impl Default for UploadQuota {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_STAGING_BYTES)
    }
}
impl UploadQuota {
    pub fn new(max_staging_bytes: u64) -> Self {
        Self {
            max_staging_bytes,
            held: Default::default(),
        }
    }
    fn reserve(&self, channel: Digest, bytes: u64) -> Result<(), ContentError> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| ContentError::Storage("quota lock poisoned".into()))?;
        let total = held
            .iter()
            .filter(|(id, _)| **id != channel)
            .try_fold(bytes, |total, (_, amount)| total.checked_add(*amount))
            .ok_or(ContentError::StagingLimit(self.max_staging_bytes))?;
        if total > self.max_staging_bytes {
            return Err(ContentError::StagingLimit(self.max_staging_bytes));
        }
        held.insert(channel, bytes);
        Ok(())
    }
    fn release(&self, channel: Digest) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(&channel);
        }
    }
}

#[derive(Debug)]
struct Stage {
    work: Digest,
    object: ContentRef,
    deadline: u64,
    bytes: Vec<u8>,
}

pub struct UploadStore {
    directory: Option<PathBuf>,
    content_root: Option<PathBuf>,
    channel: Digest,
    quota: UploadQuota,
    stage: Option<Stage>,
    content: ContentStore,
}
impl std::fmt::Debug for UploadStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadStore")
            .field("directory", &self.directory)
            .field("channel", &self.channel)
            .field("staged", &self.stage.is_some())
            .finish()
    }
}
impl UploadStore {
    pub fn memory(channel: Digest, quota: UploadQuota) -> Self {
        Self {
            directory: None,
            content_root: None,
            channel,
            quota,
            stage: None,
            content: ContentStore::new(),
        }
    }
    pub fn durable(root: &Path, stem: &str, channel: Digest) -> Result<Self, ContentError> {
        let directory = root.join(format!("{stem}.staging"));
        let mut store = Self::memory(channel, UploadQuota::default());
        store.directory = Some(directory.clone());
        store.content_root = Some(root.join("content"));
        if directory.try_exists()? {
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(".proposal.") && name.ends_with(".pending") {
                    std::fs::remove_file(entry.path())?;
                }
            }
            hellas_private::sync_directory(&directory)?;
        }
        let path = directory.join("proposal");
        if path.try_exists()? {
            let bytes = hellas_private::read_bounded_regular_file(&path, MAX_CONTENT_BYTES + 80)?;
            if bytes.len() < 80 {
                return Err(ContentError::Invalid);
            }
            let work =
                Digest::from_bytes(bytes[..32].try_into().map_err(|_| ContentError::Invalid)?);
            let object = decode_reference(&bytes[32..72]).ok_or(ContentError::Invalid)?;
            let deadline = u64::from_be_bytes(
                bytes[72..80]
                    .try_into()
                    .map_err(|_| ContentError::Invalid)?,
            );
            if object.bytes() > MAX_CONTENT_BYTES as u64 || bytes.len() as u64 - 80 > object.bytes()
            {
                return Err(ContentError::Invalid);
            }
            store.quota.reserve(channel, store.missing_bytes(object)?)?;
            store.stage = Some(Stage {
                work,
                object,
                deadline,
                bytes: bytes[80..].to_vec(),
            });
        }
        Ok(store)
    }
    pub fn set_quota(&mut self, quota: UploadQuota) -> Result<(), ContentError> {
        if Arc::ptr_eq(&self.quota.held, &quota.held) {
            return Ok(());
        }
        if let Some(stage) = &self.stage {
            quota.reserve(self.channel, self.missing_bytes(stage.object)?)?;
        }
        self.quota.release(self.channel);
        self.quota = quota;
        Ok(())
    }
    pub fn content_store(&self) -> ContentStore {
        self.content.clone()
    }
    pub fn is_staged(&self) -> bool {
        self.stage.is_some()
    }
    pub fn directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }
    pub fn gc(&mut self, now: u64, closed: bool) -> Result<(), ContentError> {
        if self
            .stage
            .as_ref()
            .is_some_and(|stage| closed || now > stage.deadline)
        {
            self.clear()?;
        }
        Ok(())
    }
    pub fn clear(&mut self) -> Result<(), ContentError> {
        if let Some(directory) = &self.directory
            && directory.try_exists()?
        {
            for entry in std::fs::read_dir(directory)? {
                std::fs::remove_file(entry?.path())?;
            }
            hellas_private::sync_directory(directory)?;
        }
        self.stage = None;
        self.quota.release(self.channel);
        Ok(())
    }
    fn held(&self, object: ContentRef) -> Result<Option<Vec<u8>>, ContentError> {
        let Some(root) = &self.content_root else {
            return Ok(None);
        };
        if !self.content.have(object.id().digest()) {
            let path = root.join("objects").join(object.id().to_string());
            if !path.try_exists()? {
                return Ok(None);
            }
            let indexed = self
                .content
                .index(&path)
                .map_err(|error| ContentError::Storage(error.to_string()))?;
            if indexed.id != object.id().digest() {
                return Err(ContentError::Hash);
            }
        }
        let Some(file) = self
            .content
            .open_verified(object.id().digest(), object.bytes())
            .map_err(|error| ContentError::Storage(error.to_string()))?
        else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.into_file()
            .take(object.bytes() + 1)
            .read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }
    pub fn read(&self, work: Digest, object: ContentRef) -> Result<Vec<u8>, ContentError> {
        if let Some(stage) = &self.stage
            && stage.work == work
            && stage.object == object
            && stage.bytes.len() as u64 == object.bytes()
        {
            if ContentId::hash(&stage.bytes) != object.id() {
                return Err(ContentError::Hash);
            }
            return Ok(stage.bytes.clone());
        }
        self.held(object)?.ok_or(ContentError::Missing)
    }
    pub fn stage(
        &mut self,
        work: Digest,
        object: ContentRef,
        deadline: u64,
        max_upload_bytes: u64,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, ContentError> {
        if object.bytes() == 0
            || object.bytes() > MAX_CONTENT_BYTES as u64
            || chunk.len() > CONTENT_CHUNK_BYTES
            || offset
                .checked_add(chunk.len() as u64)
                .is_none_or(|end| end > object.bytes())
        {
            return Err(ContentError::Invalid);
        }
        if self.stage.as_ref().is_some_and(|stage| {
            stage.work != work || stage.object != object || stage.deadline != deadline
        }) {
            return Err(ContentError::ProposalLimit);
        }
        if self.stage.is_none() && offset != 0 {
            return Err(ContentError::Invalid);
        }
        if self.held(object)?.is_some() {
            if self.stage.is_none() {
                self.quota.reserve(self.channel, 0)?;
                self.stage = Some(Stage {
                    work,
                    object,
                    deadline,
                    bytes: Vec::new(),
                });
            }
            self.persist()?;
            return Ok(object.bytes());
        }
        if object.bytes() > max_upload_bytes {
            return Err(ContentError::UploadLimit(max_upload_bytes));
        }
        if self.stage.is_none() {
            self.quota.reserve(self.channel, object.bytes())?;
            self.stage = Some(Stage {
                work,
                object,
                deadline,
                bytes: Vec::new(),
            });
        }
        let stage = self.stage.as_mut().ok_or(ContentError::Missing)?;
        if !chunk.is_empty() {
            if offset < stage.bytes.len() as u64 {
                let end = offset as usize + chunk.len();
                if stage.bytes.get(offset as usize..end) != Some(chunk) {
                    return Err(ContentError::Invalid);
                }
            } else if offset == stage.bytes.len() as u64 {
                stage.bytes.extend_from_slice(chunk);
            } else {
                return Err(ContentError::Invalid);
            }
        }
        let next = stage.bytes.len() as u64;
        if next == object.bytes() && ContentId::hash(&stage.bytes) != object.id() {
            self.clear()?;
            return Err(ContentError::Hash);
        }
        self.persist()?;
        Ok(next)
    }
    pub fn staged_bytes(&self) -> usize {
        self.stage.as_ref().map_or(0, |stage| stage.bytes.len())
    }
    fn persist(&self) -> Result<(), ContentError> {
        if let Some(directory) = &self.directory {
            hellas_private::create_dir_all_durable(directory)?;
            let stage = self.stage.as_ref().ok_or(ContentError::Missing)?;
            let mut bytes = stage.work.as_bytes().to_vec();
            bytes.extend_from_slice(&encode_reference(stage.object));
            bytes.extend_from_slice(&stage.deadline.to_be_bytes());
            bytes.extend_from_slice(&stage.bytes);
            hellas_private::write_atomically(&directory.join("proposal"), ".pending", &bytes)?;
        }
        Ok(())
    }
    pub fn missing_bytes(&self, object: ContentRef) -> Result<u64, ContentError> {
        Ok(if self.held(object)?.is_some() {
            0
        } else {
            object.bytes()
        })
    }
    pub fn publish_accepted(&mut self, work: Digest, bytes: &[u8]) -> Result<(), ContentError> {
        if let Some(root) = &self.content_root {
            self.content
                .put(root, bytes)
                .map_err(|error| ContentError::Storage(error.to_string()))?;
        }
        if self.stage.as_ref().is_some_and(|stage| stage.work == work) {
            self.clear()?;
        }
        Ok(())
    }
}
impl Drop for UploadStore {
    fn drop(&mut self) {
        if self.directory.is_none() {
            self.quota.release(self.channel);
        }
    }
}
