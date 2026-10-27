//! Immutable compute input objects installed before journal references.
use super::*;
use crate::content::{ContentError, MAX_CONTENT_BYTES};
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::content_upload::{decode_reference, encode_reference},
};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug)]
pub(super) struct PayloadStore {
    root: PathBuf,
}
impl PayloadStore {
    pub(super) fn new(root: &Path, stem: &str) -> Self {
        Self {
            root: root.join(format!("{stem}.payloads")),
        }
    }
    pub(super) fn reference(bytes: &[u8]) -> Vec<u8> {
        encode_reference(ContentRef::new(ContentId::hash(bytes), bytes.len() as u64))
    }
    pub(super) fn read(&self, reference: &[u8]) -> Result<Vec<u8>, ContentError> {
        let reference = decode_reference(reference).ok_or(ContentError::Invalid)?;
        if reference.bytes() > MAX_CONTENT_BYTES as u64 {
            return Err(ContentError::Invalid);
        }
        let path = self.root.join(reference.id().to_string());
        let bytes = hellas_private::read_bounded_regular_file(&path, MAX_CONTENT_BYTES)?;
        if bytes.len() as u64 != reference.bytes() || ContentId::hash(&bytes) != reference.id() {
            return Err(ContentError::Hash);
        }
        Ok(bytes)
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<Vec<u8>, ContentError> {
        if bytes.len() > MAX_CONTENT_BYTES {
            return Err(ContentError::Invalid);
        }
        let reference = Self::reference(bytes);
        let object = decode_reference(&reference).ok_or(ContentError::Invalid)?;
        hellas_private::create_dir_all_durable(&self.root)?;
        let path = self.root.join(object.id().to_string());
        if path.try_exists()? {
            self.read(&reference)?;
        } else {
            hellas_private::write_atomically(&path, ".pending", bytes)?;
        }
        Ok(reference)
    }
    pub(super) fn prune(&self, state: &Channel) -> Result<(), ContentError> {
        if !self.root.try_exists()? {
            return Ok(());
        }
        let live: BTreeSet<_> = state
            .jobs()
            .map(|job| ContentId::hash(job.prepared_input()).to_string())
            .collect();
        self.prune_ids(&live)
    }
    pub(super) fn prune_ids(&self, live: &BTreeSet<String>) -> Result<(), ContentError> {
        if !self.root.try_exists()? {
            return Ok(());
        }
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if !live.contains(&entry.file_name().to_string_lossy().into_owned()) {
                std::fs::remove_file(entry.path())?;
            }
        }
        hellas_private::sync_directory(&self.root)?;
        Ok(())
    }
}

pub(super) fn checkpoint(state: &Channel, metadata_only: bool) -> Vec<u8> {
    if metadata_only {
        return state.checkpoint_for_storage(true);
    }
    let mut referenced = state.clone();
    for job in referenced.book.jobs.values_mut() {
        job.prepared_input = PayloadStore::reference(&job.prepared_input);
    }
    referenced.checkpoint_for_storage(false)
}
