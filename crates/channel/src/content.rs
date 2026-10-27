//! Proposal-scoped content transport. Only compute content may reach disk.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use hellas_auth::Digest;
use hellas_rpc::{
    ContentId, ContentRef, Retention,
    protocol::content_upload::{CONTENT_CHUNK_BYTES, decode_reference, encode_reference},
};
use hellas_store::ContentStore;

mod view;
pub use view::{EphemeralContent, InvocationContent};

pub const MAX_PROGRAM_ROOT_BYTES: usize = 1 << 20;
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
    // Replay restores a reservation previously admitted under the node's configured cap.
    // The shared cap is rechecked when that quota is attached before new uploads.
    fn restore(&self, channel: Digest, bytes: u64) -> Result<(), ContentError> {
        self.held
            .lock()
            .map_err(|_| ContentError::Storage("quota lock poisoned".into()))?
            .insert(channel, bytes);
        Ok(())
    }
    fn release_to(&self, channel: Digest, bytes: u64) -> Result<(), ContentError> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| ContentError::Storage("quota lock poisoned".into()))?;
        if bytes > held.get(&channel).copied().unwrap_or(0) {
            return Err(ContentError::Invalid);
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct UploadMeta {
    work: Digest,
    deadline: u64,
    objects: BTreeMap<ContentId, ContentRef>,
}
impl UploadMeta {
    fn new(work: Digest, deadline: u64, objects: &[ContentRef]) -> Result<Self, ContentError> {
        if objects.is_empty() || objects.len() > MAX_PROGRAM_ROOT_BYTES / 32 + 2 {
            return Err(ContentError::Invalid);
        }
        let mut unique = BTreeMap::new();
        for reference in objects {
            if let Some(old) = unique.insert(reference.id(), *reference)
                && old != *reference
            {
                return Err(ContentError::Invalid);
            }
        }
        Ok(Self {
            work,
            deadline,
            objects: unique,
        })
    }
    fn object(&self, reference: ContentRef) -> Result<(), ContentError> {
        if self.objects.get(&reference.id()) != Some(&reference) {
            return Err(ContentError::Invalid);
        }
        Ok(())
    }
}

// This type has no durable context. Its insertion path can only change RAM.
#[derive(Debug)]
struct MemoryUpload {
    meta: UploadMeta,
    objects: BTreeMap<ContentId, Arc<Vec<u8>>>,
}
impl MemoryUpload {
    fn stage(
        &mut self,
        object: ContentRef,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, ContentError> {
        self.meta.object(object)?;
        let bytes = self.objects.entry(object.id()).or_default();
        if offset < bytes.len() as u64 {
            if bytes.get(offset as usize..offset as usize + chunk.len()) != Some(chunk) {
                return Err(ContentError::Invalid);
            }
        } else if offset == bytes.len() as u64 {
            Arc::make_mut(bytes).extend_from_slice(chunk);
        } else {
            return Err(ContentError::Invalid);
        }
        let next = bytes.len() as u64;
        if next == object.bytes() && ContentId::hash(bytes) != object.id() {
            return Err(ContentError::Hash);
        }
        Ok(next)
    }
    fn read(&self, object: ContentRef) -> Result<Arc<Vec<u8>>, ContentError> {
        self.meta.object(object)?;
        let bytes = self
            .objects
            .get(&object.id())
            .ok_or(ContentError::Missing)?;
        if bytes.len() as u64 != object.bytes() {
            return Err(ContentError::Missing);
        }
        if ContentId::hash(bytes) != object.id() {
            return Err(ContentError::Hash);
        }
        Ok(bytes.clone())
    }
    fn snapshot(&self, objects: &[ContentRef]) -> Result<EphemeralContent, ContentError> {
        let mut content = EphemeralContent::default();
        for object in objects {
            content.insert_verified(*object, self.read(*object)?)?;
        }
        Ok(content)
    }
}

#[derive(Clone, Debug)]
struct DurableFiles {
    directory: PathBuf,
    content_root: PathBuf,
}
#[derive(Debug)]
struct DurableUpload {
    meta: UploadMeta,
    files: DurableFiles,
    persisted: bool,
}
impl DurableUpload {
    fn ticket(&self) -> PathBuf {
        self.files
            .directory
            .join(format!("{}.ticket", hex::encode(self.meta.work.as_bytes())))
    }
    fn part(&self, id: ContentId) -> PathBuf {
        self.files.directory.join(format!(
            "{}-{}.part",
            hex::encode(self.meta.work.as_bytes()),
            hex::encode(id.as_bytes())
        ))
    }
    fn persist(&mut self) -> Result<(), ContentError> {
        if self.persisted {
            return Ok(());
        }
        hellas_private::create_dir_all_durable(&self.files.directory)?;
        let mut bytes = self.meta.work.as_bytes().to_vec();
        bytes.extend_from_slice(&self.meta.deadline.to_be_bytes());
        for object in self.meta.objects.values() {
            bytes.extend_from_slice(&encode_reference(*object));
        }
        hellas_private::write_atomically(&self.ticket(), ".pending", &bytes)?;
        self.persisted = true;
        Ok(())
    }
    fn stage(&self, object: ContentRef, offset: u64, chunk: &[u8]) -> Result<u64, ContentError> {
        use std::io::{Seek as _, SeekFrom, Write as _};
        self.meta.object(object)?;
        let path = self.part(object.id());
        if !path.try_exists()? {
            if offset != 0 {
                return Err(ContentError::Invalid);
            }
            hellas_private::write_atomically(&path, ".pending", &[])?;
        }
        let mut file = hellas_private::open_nofollow_rw(&path)?;
        if !hellas_private::is_private(&file)? {
            return Err(ContentError::Invalid);
        }
        let current = file.metadata()?.len();
        if current > object.bytes() {
            return Err(ContentError::Invalid);
        }
        if offset < current {
            let mut previous = vec![0; chunk.len()];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut previous)?;
            if previous != chunk {
                return Err(ContentError::Invalid);
            }
        } else if offset == current {
            file.seek(SeekFrom::End(0))?;
            file.write_all(chunk)?;
            file.sync_all()?;
        } else {
            return Err(ContentError::Invalid);
        }
        let next = file.metadata()?.len();
        if next == object.bytes() {
            verify_file(&path, object)?;
        }
        Ok(next)
    }
    fn read(&self, object: ContentRef) -> Result<Vec<u8>, ContentError> {
        self.meta.object(object)?;
        let path = self.part(object.id());
        if !path.try_exists()? {
            return Err(ContentError::Missing);
        }
        let maximum = usize::try_from(object.bytes()).map_err(|_| ContentError::Invalid)?;
        let bytes = hellas_private::read_bounded_regular_file(&path, maximum)?;
        if bytes.len() as u64 != object.bytes() {
            return Err(ContentError::Missing);
        }
        if ContentId::hash(&bytes) != object.id() {
            return Err(ContentError::Hash);
        }
        Ok(bytes)
    }
    fn actual_bytes(&self, object: ContentRef) -> Result<u64, ContentError> {
        match hellas_private::open_nofollow(&self.part(object.id())) {
            Ok(file) if hellas_private::is_private(&file)? => {
                let len = file.metadata()?.len();
                if len > object.bytes() {
                    return Err(ContentError::Invalid);
                }
                Ok(len)
            }
            Ok(_) => Err(ContentError::Invalid),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(e.into()),
        }
    }
    fn remove_parts(&self) -> Result<(), ContentError> {
        for object in self.meta.objects.values() {
            let path = self.part(object.id());
            if path.try_exists()? {
                std::fs::remove_file(path)?;
            }
        }
        if self.files.directory.try_exists()? {
            hellas_private::sync_directory(&self.files.directory)?;
        }
        if self.ticket().try_exists()? {
            std::fs::remove_file(self.ticket())?;
        }
        if self.files.directory.try_exists()? {
            hellas_private::sync_directory(&self.files.directory)?;
        }
        Ok(())
    }
}
#[derive(Debug)]
enum Upload {
    Ephemeral(MemoryUpload),
    Retained(DurableUpload),
}
impl Upload {
    fn meta(&self) -> &UploadMeta {
        match self {
            Self::Ephemeral(u) => &u.meta,
            Self::Retained(u) => &u.meta,
        }
    }
    fn retention(&self) -> Retention {
        match self {
            Self::Ephemeral(_) => Retention::Ephemeral,
            Self::Retained(_) => Retention::Retain,
        }
    }
}

pub struct UploadStore {
    files: Option<DurableFiles>,
    channel: Digest,
    quota: UploadQuota,
    uploads: BTreeMap<Digest, Upload>,
    content: ContentStore,
}
impl std::fmt::Debug for UploadStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadStore")
            .field("channel", &self.channel)
            .field("uploads", &self.uploads.len())
            .finish()
    }
}
impl UploadStore {
    pub fn memory(channel: Digest, quota: UploadQuota) -> Self {
        Self {
            files: None,
            channel,
            quota,
            uploads: BTreeMap::new(),
            content: ContentStore::new(),
        }
    }
    pub fn durable(
        root: &Path,
        stem: &str,
        channel: Digest,
        content: ContentStore,
    ) -> Result<Self, ContentError> {
        let files = DurableFiles {
            directory: root.join(format!("{stem}.staging")),
            content_root: root.join("content"),
        };
        let mut store = Self::memory(channel, UploadQuota::default());
        store.content = content;
        store.files = Some(files.clone());
        if files.directory.try_exists()? {
            let mut parts = Vec::new();
            for entry in std::fs::read_dir(&files.directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.') && name.ends_with(".pending") {
                    std::fs::remove_file(entry.path())?;
                    continue;
                }
                if name.ends_with(".part") {
                    parts.push(entry.path());
                    continue;
                }
                if !name.ends_with(".ticket") || store.uploads.len() >= 256 {
                    return Err(ContentError::Invalid);
                }
                let bytes = hellas_private::read_bounded_regular_file(
                    &entry.path(),
                    MAX_PROGRAM_ROOT_BYTES * 2,
                )?;
                if bytes.len() < 80 || (bytes.len() - 40) % 40 != 0 {
                    return Err(ContentError::Invalid);
                }
                let work =
                    Digest::from_bytes(bytes[..32].try_into().map_err(|_| ContentError::Invalid)?);
                if name != format!("{}.ticket", hex::encode(work.as_bytes())) {
                    return Err(ContentError::Invalid);
                }
                let deadline = u64::from_be_bytes(
                    bytes[32..40]
                        .try_into()
                        .map_err(|_| ContentError::Invalid)?,
                );
                let objects = bytes[40..]
                    .as_chunks::<40>()
                    .0
                    .iter()
                    .map(|b| decode_reference(b).ok_or(ContentError::Invalid))
                    .collect::<Result<Vec<_>, _>>()?;
                let meta = UploadMeta::new(work, deadline, &objects)?;
                if store
                    .uploads
                    .insert(
                        work,
                        Upload::Retained(DurableUpload {
                            meta,
                            files: files.clone(),
                            persisted: true,
                        }),
                    )
                    .is_some()
                {
                    return Err(ContentError::Invalid);
                }
            }
            let expected: BTreeSet<_> = store
                .uploads
                .values()
                .flat_map(|upload| match upload {
                    Upload::Retained(upload) => upload
                        .meta
                        .objects
                        .keys()
                        .map(|id| upload.part(*id))
                        .collect::<Vec<_>>(),
                    Upload::Ephemeral(_) => Vec::new(),
                })
                .collect();
            for part in parts {
                if !expected.contains(&part) {
                    return Err(ContentError::Invalid);
                }
            }
            hellas_private::sync_directory(&files.directory)?;
            store.quota.restore(channel, store.reserved_bytes()?)?;
        }
        Ok(store)
    }
    pub fn set_quota(&mut self, quota: UploadQuota) -> Result<(), ContentError> {
        if Arc::ptr_eq(&self.quota.held, &quota.held) {
            return Ok(());
        }
        quota.reserve(self.channel, self.reserved_bytes()?)?;
        self.quota.release(self.channel);
        self.quota = quota;
        Ok(())
    }
    fn held_file(
        &self,
        object: ContentRef,
    ) -> Result<Option<hellas_store::VerifiedFile>, ContentError> {
        let Some(files) = &self.files else {
            return Ok(None);
        };
        if !self.content.have(object.id().digest()) {
            let path = files
                .content_root
                .join("objects")
                .join(object.id().to_string());
            if !path.try_exists()? {
                return Ok(None);
            }
            let indexed = self
                .content
                .index(&path)
                .map_err(|e| ContentError::Storage(e.to_string()))?;
            if indexed.id != object.id().digest() {
                return Err(ContentError::Hash);
            }
        }
        self.content
            .open_verified(object.id().digest(), object.bytes())
            .map_err(|e| ContentError::Storage(e.to_string()))
    }
    pub fn missing_bytes(
        &self,
        object: ContentRef,
        retention: Retention,
    ) -> Result<u64, ContentError> {
        match retention {
            Retention::Ephemeral => Ok(object.bytes()),
            Retention::Retain => Ok(if self.held_file(object)?.is_some() {
                0
            } else {
                object.bytes()
            }),
        }
    }
    fn reserved_upload(&self, upload: &Upload) -> Result<u64, ContentError> {
        upload
            .meta()
            .objects
            .values()
            .try_fold(0u64, |sum, object| {
                let bytes = match upload {
                    Upload::Ephemeral(_) => object.bytes(),
                    Upload::Retained(u) => self
                        .missing_bytes(*object, Retention::Retain)?
                        .max(u.actual_bytes(*object)?),
                };
                sum.checked_add(bytes)
                    .ok_or(ContentError::StagingLimit(self.quota.max_staging_bytes))
            })
    }
    fn reserved_bytes(&self) -> Result<u64, ContentError> {
        self.uploads.values().try_fold(0u64, |n, u| {
            n.checked_add(self.reserved_upload(u)?)
                .ok_or(ContentError::StagingLimit(self.quota.max_staging_bytes))
        })
    }
    pub fn declare_closure(
        &mut self,
        work: Digest,
        objects: &[ContentRef],
        deadline: u64,
        retention: Retention,
        max_upload_bytes: u64,
    ) -> Result<(), ContentError> {
        self.declare(work, objects, deadline, retention, max_upload_bytes, false)
    }
    fn declare(
        &mut self,
        work: Digest,
        objects: &[ContentRef],
        deadline: u64,
        retention: Retention,
        max_upload_bytes: u64,
        journaled: bool,
    ) -> Result<(), ContentError> {
        let meta = UploadMeta::new(work, deadline, objects)?;
        if !journaled && self.uploads.keys().any(|id| *id != work) {
            return Err(ContentError::ProposalLimit);
        }
        if let Some(upload) = self.uploads.get(&work) {
            if upload.meta() != &meta || upload.retention() != retention {
                return Err(ContentError::ProposalLimit);
            }
        } else if self.uploads.len() >= 256 {
            return Err(ContentError::ProposalLimit);
        }
        let missing = meta.objects.values().try_fold(0u64, |n, reference| {
            n.checked_add(self.missing_bytes(*reference, retention)?)
                .ok_or(ContentError::UploadLimit(max_upload_bytes))
        })?;
        if missing > max_upload_bytes {
            return Err(ContentError::UploadLimit(max_upload_bytes));
        }
        if !self.uploads.contains_key(&work) {
            let upload = match retention {
                Retention::Ephemeral => Upload::Ephemeral(MemoryUpload {
                    meta,
                    objects: BTreeMap::new(),
                }),
                Retention::Retain => Upload::Retained(DurableUpload {
                    meta,
                    files: self.files.clone().ok_or(ContentError::Invalid)?,
                    persisted: false,
                }),
            };
            let reservation = self
                .reserved_bytes()?
                .checked_add(self.reserved_upload(&upload)?)
                .ok_or(ContentError::StagingLimit(self.quota.max_staging_bytes))?;
            self.quota.reserve(self.channel, reservation)?;
            self.uploads.insert(work, upload);
        }
        if let Some(Upload::Retained(upload)) = self.uploads.get_mut(&work) {
            upload.persist()?;
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The signed upload scope accompanies each offset and chunk."
    )]
    pub fn stage(
        &mut self,
        work: Digest,
        object: ContentRef,
        deadline: u64,
        retention: Retention,
        max_upload_bytes: u64,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, ContentError> {
        self.stage_inner(
            work,
            object,
            deadline,
            retention,
            max_upload_bytes,
            offset,
            chunk,
            false,
        )
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Public and journaled uploads share the same admission checks."
    )]
    fn stage_inner(
        &mut self,
        work: Digest,
        object: ContentRef,
        deadline: u64,
        retention: Retention,
        max_upload_bytes: u64,
        offset: u64,
        chunk: &[u8],
        journaled: bool,
    ) -> Result<u64, ContentError> {
        if chunk.len() > CONTENT_CHUNK_BYTES
            || offset
                .checked_add(chunk.len() as u64)
                .is_none_or(|end| end > object.bytes())
        {
            return Err(ContentError::Invalid);
        }
        let objects = self
            .uploads
            .get(&work)
            .map(|u| u.meta().objects.values().copied().collect())
            .unwrap_or_else(|| vec![object]);
        self.declare(
            work,
            &objects,
            deadline,
            retention,
            max_upload_bytes,
            journaled,
        )?;
        self.uploads
            .get(&work)
            .ok_or(ContentError::Missing)?
            .meta()
            .object(object)?;
        let held = match self.uploads.get(&work) {
            Some(Upload::Retained(_)) => self.held_file(object)?.is_some(),
            _ => false,
        };
        if held {
            return Ok(object.bytes());
        }
        let outcome = match self.uploads.get_mut(&work).ok_or(ContentError::Missing)? {
            Upload::Ephemeral(u) => u.stage(object, offset, chunk),
            Upload::Retained(u) => u.stage(object, offset, chunk),
        };
        if matches!(outcome, Err(ContentError::Hash)) {
            self.discard(work)?;
        }
        outcome
    }
    pub fn stage_complete(
        &mut self,
        work: Digest,
        object: ContentRef,
        deadline: u64,
        retention: Retention,
        max_upload_bytes: u64,
        bytes: &[u8],
    ) -> Result<(), ContentError> {
        if ContentRef::for_bytes(bytes) != object {
            return Err(ContentError::Hash);
        }
        let mut offset = self.stage_inner(
            work,
            object,
            deadline,
            retention,
            max_upload_bytes,
            0,
            &[],
            true,
        )?;
        while offset < object.bytes() {
            let end = (offset as usize + CONTENT_CHUNK_BYTES).min(bytes.len());
            offset = self.stage_inner(
                work,
                object,
                deadline,
                retention,
                max_upload_bytes,
                offset,
                &bytes[offset as usize..end],
                true,
            )?;
        }
        Ok(())
    }
    pub fn read(
        &self,
        work: Digest,
        object: ContentRef,
        retention: Retention,
    ) -> Result<Vec<u8>, ContentError> {
        if let Some(upload) = self.uploads.get(&work) {
            if upload.retention() != retention {
                return Err(ContentError::Invalid);
            }
            match upload {
                Upload::Ephemeral(u) => return Ok(u.read(object)?.as_ref().clone()),
                Upload::Retained(u) => {
                    u.meta.object(object)?;
                    if self.held_file(object)?.is_some() {
                        return self.retained(object);
                    }
                    if u.part(object.id()).try_exists()? {
                        return u.read(object);
                    }
                }
            }
        }
        if retention == Retention::Ephemeral {
            return Err(ContentError::Missing);
        }
        self.retained(object)
    }
    pub fn root(
        &self,
        work: Digest,
        id: ContentId,
        retention: Retention,
    ) -> Result<Vec<u8>, ContentError> {
        if let Some(upload) = self.uploads.get(&work)
            && let Some(object) = upload.meta().objects.get(&id)
        {
            if object.bytes() > MAX_PROGRAM_ROOT_BYTES as u64 {
                return Err(ContentError::Invalid);
            }
            return self.read(work, *object, retention);
        }
        if retention == Retention::Ephemeral {
            return Ok(Vec::new());
        }
        match InvocationContent::Retained(self.content.clone())
            .read_bounded(id, MAX_PROGRAM_ROOT_BYTES as u64)
        {
            Ok(bytes) => return Ok(bytes.as_ref().clone()),
            Err(ContentError::Missing) => (),
            Err(error) => return Err(error),
        }
        let Some(files) = &self.files else {
            return Ok(Vec::new());
        };
        let path = files.content_root.join("objects").join(id.to_string());
        if !path.try_exists()? {
            return Ok(Vec::new());
        }
        let indexed = self
            .content
            .index(&path)
            .map_err(|e| ContentError::Storage(e.to_string()))?;
        if indexed.id != id.digest() || indexed.len > MAX_PROGRAM_ROOT_BYTES as u64 {
            return Err(ContentError::Hash);
        }
        self.retained(ContentRef::new(id, indexed.len))
    }
    pub fn invocation_content(
        &self,
        work: Digest,
        objects: &[ContentRef],
        retention: Retention,
    ) -> Result<InvocationContent, ContentError> {
        match retention {
            Retention::Ephemeral => match self.uploads.get(&work) {
                Some(Upload::Ephemeral(upload)) => {
                    Ok(InvocationContent::Ephemeral(upload.snapshot(objects)?))
                }
                _ if objects.is_empty() => {
                    Ok(InvocationContent::Ephemeral(EphemeralContent::default()))
                }
                _ => Err(ContentError::Missing),
            },
            Retention::Retain => {
                for object in objects {
                    if let Some(Upload::Retained(upload)) = self.uploads.get(&work) {
                        upload.meta.object(*object)?;
                        if self.held_file(*object)?.is_none() {
                            verify_file(&upload.part(object.id()), *object)?;
                        }
                    } else if self.held_file(*object)?.is_none() {
                        return Err(ContentError::Missing);
                    }
                }
                Ok(InvocationContent::Retained(self.content.clone()))
            }
        }
    }
    pub fn publish_accepted(
        &mut self,
        work: Digest,
        bytes: &[u8],
        retention: Retention,
    ) -> Result<(), ContentError> {
        if retention == Retention::Ephemeral {
            return self.discard(work);
        }
        if let Some(Upload::Retained(upload)) = self.uploads.get(&work) {
            let mut published = Vec::new();
            for object in upload.meta.objects.values() {
                let directory = upload.files.content_root.join("objects");
                let destination = directory.join(object.id().to_string());
                if self.held_file(*object)?.is_none() {
                    let source = upload.part(object.id());
                    verify_file(&source, *object)?;
                    hellas_private::create_dir_all_durable(&directory)?;
                    install_part(&source, &destination, *object)?;
                }
                if destination.try_exists()? {
                    // Presence alone does not prove a previous publication finished its flush.
                    finalize_publication(&destination)?;
                    published.push((destination, *object));
                }
            }
            // Unlinking the staged hard links changes each object's ctime,
            // which the index treats as a different file. Index afterwards.
            self.discard(work)?;
            for (destination, object) in published {
                let indexed = self
                    .content
                    .index(&destination)
                    .map_err(|e| ContentError::Storage(e.to_string()))?;
                if indexed.id != object.id().digest() || indexed.len != object.bytes() {
                    return Err(ContentError::Hash);
                }
            }
            return Ok(());
        }
        self.retain(bytes)?;
        self.discard(work)
    }
    pub fn retained(&self, object: ContentRef) -> Result<Vec<u8>, ContentError> {
        let file = self.held_file(object)?.ok_or(ContentError::Missing)?;
        let mut bytes = Vec::new();
        file.into_file()
            .take(object.bytes() + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != object.bytes() {
            return Err(ContentError::Hash);
        }
        Ok(bytes)
    }
    pub fn retain(&self, bytes: &[u8]) -> Result<ContentRef, ContentError> {
        let files = self.files.as_ref().ok_or(ContentError::Invalid)?;
        self.content
            .put(&files.content_root, bytes)
            .map_err(|e| ContentError::Storage(e.to_string()))?;
        Ok(ContentRef::for_bytes(bytes))
    }
    pub fn discard(&mut self, work: Digest) -> Result<(), ContentError> {
        if let Some(Upload::Retained(upload)) = self.uploads.get(&work) {
            upload.remove_parts()?;
        }
        self.uploads.remove(&work);
        self.quota
            .release_to(self.channel, self.reserved_bytes()?)?;
        Ok(())
    }
    pub fn clear(&mut self) -> Result<(), ContentError> {
        let ids: Vec<_> = self.uploads.keys().copied().collect();
        for id in ids {
            self.discard(id)?;
        }
        Ok(())
    }
    pub fn gc(&mut self, now: u64, closed: bool) -> Result<(), ContentError> {
        let expired: Vec<_> = self
            .uploads
            .iter()
            .filter(|(_, u)| closed || now > u.meta().deadline)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.discard(id)?;
        }
        Ok(())
    }
    pub fn is_staged(&self) -> bool {
        !self.uploads.is_empty()
    }
    pub fn has_stage(&self, work: Digest) -> bool {
        self.uploads.contains_key(&work)
    }
    pub fn directory(&self) -> Option<&Path> {
        self.files.as_ref().map(|f| f.directory.as_path())
    }
    pub fn staged_bytes(&self) -> usize {
        self.uploads
            .values()
            .map(|u| match u {
                Upload::Ephemeral(u) => u.objects.values().map(|b| b.len()).sum::<usize>(),
                Upload::Retained(u) => u
                    .meta
                    .objects
                    .values()
                    .map(|o| u.actual_bytes(*o).unwrap_or(0) as usize)
                    .sum::<usize>(),
            })
            .sum()
    }
    pub fn content_store(&self) -> ContentStore {
        self.content.clone()
    }
}
impl Drop for UploadStore {
    fn drop(&mut self) {
        let retained = self
            .uploads
            .values()
            .filter(|u| matches!(u, Upload::Retained(_)))
            .try_fold(0u64, |n, u| n.checked_add(self.reserved_upload(u).ok()?));
        if retained == Some(0) {
            self.quota.release(self.channel);
        } else if let Some(bytes) = retained {
            let _ = self.quota.release_to(self.channel, bytes);
        }
    }
}
#[cfg(test)]
thread_local! { static FAIL_PUBLICATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn finalize_publication(destination: &Path) -> Result<(), ContentError> {
    #[cfg(test)]
    if FAIL_PUBLICATION.with(|failure| failure.replace(false)) {
        return Err(ContentError::Storage(
            "injected publication flush failure".into(),
        ));
    }
    let file = hellas_private::open_nofollow(destination)?;
    if !hellas_private::is_private(&file)? {
        return Err(ContentError::Invalid);
    }
    if !file.metadata()?.permissions().readonly() {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(true);
        file.set_permissions(permissions)?;
    }
    file.sync_all()?;
    hellas_private::sync_directory(destination.parent().ok_or(ContentError::Invalid)?)?;
    Ok(())
}

fn install_part(
    source: &Path,
    destination: &Path,
    _object: ContentRef,
) -> Result<(), ContentError> {
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn verify_file(path: &Path, object: ContentRef) -> Result<(), ContentError> {
    let mut file = match hellas_private::open_nofollow(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ContentError::Missing),
        Err(e) => return Err(e.into()),
    };
    if !hellas_private::is_private(&file)? || file.metadata()?.len() != object.bytes() {
        return Err(ContentError::Missing);
    }
    let mut hasher = hellas_xet::XetFileHasher::new();
    let mut buffer = [0; 65536];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(ContentError::Invalid)?;
        if total > object.bytes() {
            return Err(ContentError::Hash);
        }
        hasher.update(&buffer[..n]);
    }
    if total != object.bytes() || hasher.finalize() != object.id().digest() {
        return Err(ContentError::Hash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(byte: u8) -> Digest {
        Digest::from_bytes([byte; 32])
    }
    fn all_bytes(root: &Path) -> Vec<Vec<u8>> {
        let mut bytes = Vec::new();
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                bytes.extend(all_bytes(&path));
            } else {
                bytes.push(std::fs::read(path).unwrap());
            }
        }
        bytes
    }
    #[test]
    fn ephemeral_uploads_never_consult_or_write_the_shared_content_store() {
        let root = tempfile::tempdir().unwrap();
        let secret = b"customer-private-payload";
        let object = ContentRef::for_bytes(secret);
        let mut store = UploadStore::durable(
            root.path(),
            "mixed",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store.retain(secret).unwrap();
        assert_eq!(
            store.missing_bytes(object, Retention::Ephemeral).unwrap(),
            object.bytes()
        );
        assert!(matches!(
            store.read(id(2), object, Retention::Ephemeral),
            Err(ContentError::Missing)
        ));
        store
            .stage_complete(id(2), object, 100, Retention::Ephemeral, 1024, secret)
            .unwrap();
        assert!(!store.directory().unwrap().exists());
        assert_eq!(
            store.read(id(2), object, Retention::Ephemeral).unwrap(),
            secret
        );
        drop(store);
        let recovered = UploadStore::durable(
            root.path(),
            "mixed",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        assert!(matches!(
            recovered.read(id(2), object, Retention::Ephemeral),
            Err(ContentError::Missing)
        ));
        assert_eq!(recovered.retained(object).unwrap(), secret);
    }
    #[test]
    fn memory_retention_on_a_durable_channel_releases_node_quota_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let quota = UploadQuota::new(16);
        let mut first = UploadStore::durable(
            root.path(),
            "first",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        first.set_quota(quota.clone()).unwrap();
        let bytes = b"private-payload!";
        let object = ContentRef::for_bytes(bytes);
        first
            .stage(id(3), object, 100, Retention::Ephemeral, 16, 0, &bytes[..3])
            .unwrap();
        assert!(all_bytes(root.path()).is_empty());
        let mut second = UploadStore::memory(id(2), quota);
        assert!(matches!(
            second.stage(id(4), object, 100, Retention::Ephemeral, 16, 0, &[]),
            Err(ContentError::StagingLimit(16))
        ));
        drop(first);
        second
            .stage_complete(id(4), object, 100, Retention::Ephemeral, 16, bytes)
            .unwrap();
        assert_eq!(
            second.read(id(4), object, Retention::Ephemeral).unwrap(),
            bytes
        );
    }
    #[test]
    fn staged_retained_content_survives_restart_and_cannot_switch_retention() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"retained-compute-input";
        let object = ContentRef::for_bytes(bytes);
        let adopted_bytes = b"adopted-environment-root";
        let adopted_path = root.path().join("adopted.hex");
        std::fs::write(&adopted_path, adopted_bytes).unwrap();
        let adopted = ContentRef::for_bytes(adopted_bytes);
        let content = ContentStore::new();
        content.index(&adopted_path).unwrap();
        let mut store = UploadStore::durable(root.path(), "compute", id(1), content).unwrap();
        store
            .declare_closure(
                id(2),
                &[object, adopted],
                100,
                Retention::Retain,
                object.bytes(),
            )
            .unwrap();
        assert_eq!(store.missing_bytes(adopted, Retention::Retain).unwrap(), 0);
        store
            .stage(id(2), object, 100, Retention::Retain, 1024, 0, &bytes[..5])
            .unwrap();
        assert!(matches!(
            store.stage(
                id(2),
                object,
                100,
                Retention::Ephemeral,
                1024,
                5,
                &bytes[5..]
            ),
            Err(ContentError::ProposalLimit)
        ));
        drop(store);
        let content = ContentStore::new();
        content.index(&adopted_path).unwrap();
        let mut recovered = UploadStore::durable(root.path(), "compute", id(1), content).unwrap();
        assert_eq!(
            recovered
                .stage(id(2), object, 100, Retention::Retain, 1024, 0, &[])
                .unwrap(),
            5
        );
        recovered
            .stage_complete(id(2), object, 100, Retention::Retain, 1024, bytes)
            .unwrap();
        recovered
            .publish_accepted(id(2), bytes, Retention::Retain)
            .unwrap();
        assert_eq!(recovered.retained(object).unwrap(), bytes);
        assert_eq!(
            recovered
                .root(id(2), adopted.id(), Retention::Retain)
                .unwrap(),
            adopted_bytes
        );
        let content = recovered
            .invocation_content(id(2), &[object, adopted], Retention::Retain)
            .unwrap();
        assert_eq!(content.read(adopted).unwrap().as_slice(), adopted_bytes);
        assert!(
            !root
                .path()
                .join("content/objects")
                .join(adopted.id().to_string())
                .exists()
        );
        recovered.gc(101, true).unwrap();
        assert_eq!(recovered.retained(object).unwrap(), bytes);
    }
    #[test]
    fn retained_transcripts_reopen_by_exact_reference_and_refuse_corruption() {
        let root = tempfile::tempdir().unwrap();
        let store = UploadStore::durable(
            root.path(),
            "result",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        let reference = store.retain(b"complete-signed-transcript").unwrap();
        drop(store);
        let reopened = UploadStore::durable(
            root.path(),
            "result",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        assert_eq!(
            reopened.retained(reference).unwrap(),
            b"complete-signed-transcript"
        );
        assert!(
            reopened
                .retained(ContentRef::new(reference.id(), reference.bytes() + 1))
                .is_err()
        );
        std::fs::write(
            root.path()
                .join("content/objects")
                .join(reference.id().to_string()),
            b"corrupted-signed-transcript",
        )
        .unwrap();
        assert!(reopened.retained(reference).is_err());
    }
    #[test]
    fn a_partial_upload_uses_an_identical_object_published_by_another_channel() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"shared-closure-object";
        let object = ContentRef::for_bytes(bytes);
        let mut first = UploadStore::durable(
            root.path(),
            "first",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        first
            .stage(id(3), object, 50, Retention::Retain, 1024, 0, &bytes[..3])
            .unwrap();
        let mut second = UploadStore::durable(
            root.path(),
            "second",
            id(2),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        second
            .stage_complete(id(4), object, 50, Retention::Retain, 1024, bytes)
            .unwrap();
        second
            .publish_accepted(id(4), bytes, Retention::Retain)
            .unwrap();
        assert_eq!(
            first
                .stage(id(3), object, 50, Retention::Retain, 1024, 0, &[])
                .unwrap(),
            object.bytes()
        );
        assert_eq!(first.read(id(3), object, Retention::Retain).unwrap(), bytes);
        first
            .invocation_content(id(3), &[object], Retention::Retain)
            .unwrap();
        first
            .publish_accepted(id(3), bytes, Retention::Retain)
            .unwrap();
        assert!(!first.has_stage(id(3)));
        assert_eq!(first.retained(object).unwrap(), bytes);
    }

    #[test]
    fn proposals_restart_and_promote_in_reverse_order_without_losing_each_other() {
        let root = tempfile::tempdir().unwrap();
        let a = b"first complete proposal";
        let b = b"second complete proposal";
        let ar = ContentRef::for_bytes(a);
        let br = ContentRef::for_bytes(b);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store
            .stage_complete(id(2), ar, 50, Retention::Retain, 1024, a)
            .unwrap();
        store
            .stage_complete(id(3), br, 100, Retention::Retain, 1024, b)
            .unwrap();
        drop(store);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        assert_eq!(store.read(id(2), ar, Retention::Retain).unwrap(), a);
        assert_eq!(store.read(id(3), br, Retention::Retain).unwrap(), b);
        store.publish_accepted(id(3), b, Retention::Retain).unwrap();
        assert!(store.has_stage(id(2)));
        assert!(!store.has_stage(id(3)));
        drop(store);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        assert_eq!(store.read(id(2), ar, Retention::Retain).unwrap(), a);
        store.publish_accepted(id(2), a, Retention::Retain).unwrap();
        store.gc(101, true).unwrap();
        assert_eq!(store.retained(ar).unwrap(), a);
        assert_eq!(store.retained(br).unwrap(), b);
    }

    #[test]
    fn deadlines_and_invalid_chunks_affect_only_their_own_proposal() {
        let root = tempfile::tempdir().unwrap();
        let a = b"deadline first";
        let b = b"deadline second";
        let ar = ContentRef::for_bytes(a);
        let br = ContentRef::for_bytes(b);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store
            .stage_complete(id(2), ar, 50, Retention::Retain, 1024, a)
            .unwrap();
        store
            .stage_complete(id(3), br, 100, Retention::Retain, 1024, b)
            .unwrap();
        assert!(
            store
                .stage(
                    id(4),
                    ContentRef::for_bytes(b"foreign"),
                    100,
                    Retention::Retain,
                    1024,
                    1,
                    b"wrong"
                )
                .is_err()
        );
        assert_eq!(store.read(id(2), ar, Retention::Retain).unwrap(), a);
        assert_eq!(store.read(id(3), br, Retention::Retain).unwrap(), b);
        store.gc(51, false).unwrap();
        assert!(!store.has_stage(id(2)));
        assert!(store.has_stage(id(3)));
        assert_eq!(store.read(id(3), br, Retention::Retain).unwrap(), b);
    }

    #[test]
    fn closure_budget_is_checked_before_any_files_or_memory_are_staged() {
        let root = tempfile::tempdir().unwrap();
        for retention in [Retention::Retain, Retention::Ephemeral] {
            let mut store = UploadStore::durable(
                root.path(),
                "channel",
                id(1),
                hellas_store::ContentStore::new(),
            )
            .unwrap();
            let objects = [
                ContentRef::for_bytes(b"first"),
                ContentRef::for_bytes(b"second"),
            ];
            assert!(matches!(
                store.declare_closure(id(2), &objects, 100, retention, 10),
                Err(ContentError::UploadLimit(10))
            ));
            assert!(!store.is_staged());
            assert!(all_bytes(root.path()).is_empty());
        }
    }

    #[test]
    fn configured_quota_above_default_survives_reopen_without_allocating_bodies() {
        let root = tempfile::tempdir().unwrap();
        let bytes = DEFAULT_MAX_STAGING_BYTES + 1;
        let object = ContentRef::new(ContentId::from_bytes([9; 32]), bytes);
        let quota = UploadQuota::new(bytes * 2);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store.set_quota(quota.clone()).unwrap();
        store
            .stage(id(2), object, 100, Retention::Retain, bytes, 0, &[])
            .unwrap();
        drop(store);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store.set_quota(quota).unwrap();
        assert_eq!(
            store
                .stage(id(2), object, 100, Retention::Retain, bytes, 0, &[])
                .unwrap(),
            0
        );
        assert!(store.has_stage(id(2)));
    }

    #[test]
    fn interrupted_publication_retries_its_flush_before_removing_the_stage() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"accepted closure survives a publication flush failure";
        let object = ContentRef::for_bytes(bytes);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store
            .stage_complete(id(2), object, 50, Retention::Retain, 1024, bytes)
            .unwrap();
        for _ in 0..2 {
            FAIL_PUBLICATION.with(|failure| failure.set(true));
            assert!(
                store
                    .publish_accepted(id(2), bytes, Retention::Retain)
                    .is_err()
            );
            assert!(store.has_stage(id(2)));
            assert_eq!(store.read(id(2), object, Retention::Retain).unwrap(), bytes);
        }
        drop(store);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store
            .publish_accepted(id(2), bytes, Retention::Retain)
            .unwrap();
        assert!(!store.has_stage(id(2)));
        assert_eq!(store.retained(object).unwrap(), bytes);
    }

    #[test]
    fn duplicate_content_stages_keep_their_actual_bytes_charged_after_one_promotion() {
        let root = tempfile::tempdir().unwrap();
        let quota = UploadQuota::new(20);
        let bytes = b"0123456789";
        let object = ContentRef::for_bytes(bytes);
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        store.set_quota(quota.clone()).unwrap();
        store
            .stage_complete(id(2), object, 50, Retention::Retain, 1024, bytes)
            .unwrap();
        store
            .stage_complete(id(3), object, 50, Retention::Retain, 1024, bytes)
            .unwrap();
        store
            .publish_accepted(id(3), bytes, Retention::Retain)
            .unwrap();
        let mut other = UploadStore::memory(id(4), quota);
        let reference = ContentRef::for_bytes(b"elevenbytes");
        assert!(matches!(
            other.stage(id(5), reference, 50, Retention::Ephemeral, 1024, 0, &[]),
            Err(ContentError::StagingLimit(20))
        ));
        store.discard(id(2)).unwrap();
        other
            .stage_complete(
                id(5),
                reference,
                50,
                Retention::Ephemeral,
                1024,
                b"elevenbytes",
            )
            .unwrap();
    }

    #[test]
    fn publication_copy_debris_is_scavenged_from_its_job_staging_namespace() {
        let root = tempfile::tempdir().unwrap();
        let mut store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        let bytes = b"closure object";
        let object = ContentRef::for_bytes(bytes);
        store
            .stage_complete(id(2), object, 50, Retention::Retain, 1024, bytes)
            .unwrap();
        let directory = store.directory().unwrap().to_path_buf();
        std::fs::write(
            directory.join(".object.interrupted.pending"),
            b"partial publication copy",
        )
        .unwrap();
        drop(store);
        let store = UploadStore::durable(
            root.path(),
            "channel",
            id(1),
            hellas_store::ContentStore::new(),
        )
        .unwrap();
        assert!(!directory.join(".object.interrupted.pending").exists());
        assert_eq!(store.read(id(2), object, Retention::Retain).unwrap(), bytes);
    }

    #[tokio::test]
    async fn durable_acceptance_protects_its_closure_from_expiry_gc_after_publication_failure() {
        use crate::model::work::{signing_hash, work_id};
        use crate::{
            test_support::channel as fixture,
            work_store::{ChannelRecord, JobPhase, Role},
        };
        use hellas_kernel::Secp256k1Verifier;
        let root = tempfile::tempdir().unwrap();
        let ready = fixture::ready();
        let input = fixture::bundle(1);
        let mut deadlines = fixture::deadlines();
        deadlines.acceptance = fixture::CURSOR;
        let authorization = crate::job::propose(
            ready.channel(),
            &fixture::work_policy(),
            &fixture::payment_policy(),
            &input,
            1,
            deadlines,
        )
        .unwrap();
        let id = work_id(ready.channel(), &authorization);
        let mut store =
            fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await;
        fixture::commit(
            &mut store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: fixture::client().sign(signing_hash(id)),
                prepared_input: input.canonical_bytes().unwrap(),
            },
        )
        .await;
        FAIL_PUBLICATION.with(|failure| failure.set(true));
        assert!(
            store
                .commit(
                    ChannelRecord::JobAccepted {
                        work_id: id,
                        provider_signature: fixture::provider().sign(signing_hash(id))
                    },
                    &Secp256k1Verifier::new()
                )
                .await
                .is_err()
        );
        assert_eq!(
            store.state().job_by_id(id).unwrap().phase(),
            JobPhase::Accepted
        );
        assert!(store.uploads.has_stage(id));
        FAIL_PUBLICATION.with(|failure| failure.set(true));
        assert!(
            store
                .commit(
                    ChannelRecord::CursorAdvanced {
                        height: fixture::CURSOR + 1,
                        parent: fixture::payload_at(fixture::CURSOR),
                        payload: fixture::payload_at(fixture::CURSOR + 1)
                    },
                    &Secp256k1Verifier::new()
                )
                .await
                .is_err()
        );
        assert_eq!(store.state().cursor().0, fixture::CURSOR);
        assert!(store.uploads.has_stage(id));
        drop(store);
        let reopened =
            fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR + 1).await;
        assert_eq!(
            reopened.state().job_by_id(id).unwrap().phase(),
            JobPhase::Accepted
        );
        assert!(!reopened.uploads.has_stage(id));
        assert_eq!(
            reopened
                .uploads
                .retained(authorization.input_content)
                .unwrap(),
            input.canonical_bytes().unwrap()
        );
        let root_bytes = fixture::program_root(&input);
        assert_eq!(
            reopened
                .uploads
                .retained(ContentRef::for_bytes(&root_bytes))
                .unwrap(),
            root_bytes
        );
    }
}
