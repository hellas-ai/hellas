use super::{ContentError, ContentId, ContentRef, ContentStore};
use std::{collections::BTreeMap, io::Read as _, sync::Arc};

/// Job-owned bytes with no file paths, durable index or substituters. Objects
/// the provider already holds may be read from `held`; nothing is written there.
#[derive(Clone, Default)]
pub struct EphemeralContent {
    objects: BTreeMap<ContentId, Arc<Vec<u8>>>,
    held: Option<ContentStore>,
}
impl std::fmt::Debug for EphemeralContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralContent")
            .field("objects", &self.objects.len())
            .field("bytes", &self.bytes())
            .finish()
    }
}
impl EphemeralContent {
    /// Reads objects this job did not upload from the provider's held content.
    pub fn with_held(mut self, held: ContentStore) -> Self {
        self.held = Some(held);
        self
    }
    fn held_file(&self, reference: ContentRef) -> Result<hellas_store::VerifiedFile, ContentError> {
        self.held
            .as_ref()
            .ok_or(ContentError::Missing)?
            .open_verified(reference.id().digest(), reference.bytes())
            .map_err(|e| ContentError::Storage(e.to_string()))?
            .ok_or(ContentError::Missing)
    }
    pub fn insert(&mut self, bytes: Vec<u8>) -> ContentRef {
        let reference = ContentRef::for_bytes(&bytes);
        self.objects.insert(reference.id(), Arc::new(bytes));
        reference
    }
    pub(super) fn insert_verified(
        &mut self,
        reference: ContentRef,
        bytes: Arc<Vec<u8>>,
    ) -> Result<(), ContentError> {
        if bytes.len() as u64 != reference.bytes() || ContentId::hash(&bytes) != reference.id() {
            return Err(ContentError::Hash);
        }
        self.objects.insert(reference.id(), bytes);
        Ok(())
    }
    pub fn read(&self, reference: ContentRef) -> Result<Arc<Vec<u8>>, ContentError> {
        let Some(bytes) = self.objects.get(&reference.id()) else {
            return read_file(self.held_file(reference)?);
        };
        if bytes.len() as u64 != reference.bytes() {
            return Err(ContentError::Hash);
        }
        Ok(bytes.clone())
    }
    pub fn read_bounded(&self, id: ContentId, maximum: u64) -> Result<Arc<Vec<u8>>, ContentError> {
        let Some(bytes) = self.objects.get(&id) else {
            let file = self
                .held
                .as_ref()
                .ok_or(ContentError::Missing)?
                .open_verified_bounded(id.digest(), maximum)
                .map_err(|e| ContentError::Storage(e.to_string()))?
                .ok_or(ContentError::Missing)?;
            return read_file(file);
        };
        if bytes.len() as u64 > maximum {
            return Err(ContentError::Invalid);
        }
        Ok(bytes.clone())
    }
    pub fn bytes(&self) -> u64 {
        self.objects.values().map(|b| b.len() as u64).sum()
    }
}

/// Retained content and ephemeral content use distinct insertion paths.
#[derive(Clone)]
pub enum InvocationContent {
    Retained(ContentStore),
    Ephemeral(EphemeralContent),
}
impl std::fmt::Debug for InvocationContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retained(_) => f.write_str("Retained"),
            Self::Ephemeral(objects) => objects.fmt(f),
        }
    }
}
impl InvocationContent {
    pub const fn retention(&self) -> hellas_rpc::Retention {
        match self {
            Self::Retained(_) => hellas_rpc::Retention::Retain,
            Self::Ephemeral(_) => hellas_rpc::Retention::Ephemeral,
        }
    }
    pub fn retained_store(&self) -> Option<&ContentStore> {
        match self {
            Self::Retained(store) => Some(store),
            Self::Ephemeral(_) => None,
        }
    }
    pub fn read(&self, reference: ContentRef) -> Result<Arc<Vec<u8>>, ContentError> {
        match self {
            Self::Ephemeral(store) => store.read(reference),
            Self::Retained(store) => {
                let file = store
                    .open_verified(reference.id().digest(), reference.bytes())
                    .map_err(|e| ContentError::Storage(e.to_string()))?
                    .ok_or(ContentError::Missing)?;
                read_file(file)
            }
        }
    }
    pub fn read_bounded(&self, id: ContentId, maximum: u64) -> Result<Arc<Vec<u8>>, ContentError> {
        match self {
            Self::Ephemeral(store) => store.read_bounded(id, maximum),
            Self::Retained(store) => {
                let file = store
                    .open_verified_bounded(id.digest(), maximum)
                    .map_err(|e| ContentError::Storage(e.to_string()))?
                    .ok_or(ContentError::Missing)?;
                read_file(file)
            }
        }
    }
    pub fn read_chunk(
        &self,
        reference: ContentRef,
        offset: u64,
        maximum: usize,
    ) -> Result<Vec<u8>, ContentError> {
        use std::io::{Seek as _, SeekFrom};
        let len = reference
            .bytes()
            .checked_sub(offset)
            .ok_or(ContentError::Invalid)?
            .min(maximum as u64) as usize;
        match self {
            Self::Ephemeral(store) if store.objects.contains_key(&reference.id()) => {
                let bytes = store.read(reference)?;
                Ok(bytes
                    .get(offset as usize..offset as usize + len)
                    .ok_or(ContentError::Invalid)?
                    .to_vec())
            }
            Self::Ephemeral(_) | Self::Retained(_) => {
                let file = match self {
                    Self::Ephemeral(store) => store.held_file(reference)?,
                    Self::Retained(store) => store
                        .open_verified(reference.id().digest(), reference.bytes())
                        .map_err(|e| ContentError::Storage(e.to_string()))?
                        .ok_or(ContentError::Missing)?,
                };
                let mut file = file.into_file();
                file.seek(SeekFrom::Start(offset))?;
                let mut bytes = vec![0; len];
                file.read_exact(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
    pub fn ephemeral_bytes(&self) -> u64 {
        match self {
            Self::Retained(_) => 0,
            Self::Ephemeral(store) => store.bytes(),
        }
    }
}
fn read_file(file: hellas_store::VerifiedFile) -> Result<Arc<Vec<u8>>, ContentError> {
    let len = file.len();
    let mut bytes = Vec::new();
    file.into_file().take(len + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != len {
        return Err(ContentError::Hash);
    }
    Ok(Arc::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_reads_are_hash_derived_bounded_and_never_expose_a_retained_store() {
        let mut memory = EphemeralContent::default();
        let bytes = b"private-view-bytes".to_vec();
        let reference = memory.insert(bytes.clone());
        assert_eq!(reference, ContentRef::for_bytes(&bytes));
        let view = InvocationContent::Ephemeral(memory);
        assert!(view.retained_store().is_none());
        assert_eq!(view.retention(), hellas_rpc::Retention::Ephemeral);
        assert_eq!(view.read(reference).unwrap().as_ref(), &bytes);
        assert!(
            view.read(ContentRef::new(reference.id(), reference.bytes() + 1))
                .is_err()
        );
        assert!(
            view.read_bounded(reference.id(), reference.bytes() - 1)
                .is_err()
        );
        assert_eq!(view.read_chunk(reference, 2, 4).unwrap(), bytes[2..6]);
        assert!(
            view.read_chunk(reference, reference.bytes() + 1, 1)
                .is_err()
        );
        assert!(!format!("{view:?}").contains("private-view-bytes"));
    }

    #[test]
    fn ephemeral_verified_insertion_refuses_a_false_reference() {
        let mut memory = EphemeralContent::default();
        let bytes = Arc::new(b"verified memory object".to_vec());
        assert!(
            memory
                .insert_verified(ContentRef::for_bytes(b"other"), bytes.clone())
                .is_err()
        );
        assert_eq!(memory.bytes(), 0);
        let reference = ContentRef::for_bytes(&bytes);
        memory.insert_verified(reference, bytes).unwrap();
        assert_eq!(
            memory.read(reference).unwrap().as_slice(),
            b"verified memory object"
        );
    }

    #[test]
    fn retained_reads_use_verified_files_and_keep_the_file_fast_path() {
        let root = tempfile::tempdir().unwrap();
        let store = ContentStore::new();
        let bytes = b"retained-view-bytes";
        store.put(root.path(), bytes).unwrap();
        let reference = ContentRef::for_bytes(bytes);
        let view = InvocationContent::Retained(store);
        assert!(view.retained_store().is_some());
        assert_eq!(view.retention(), hellas_rpc::Retention::Retain);
        assert_eq!(view.read(reference).unwrap().as_slice(), bytes);
        assert!(
            view.read_bounded(reference.id(), reference.bytes() - 1)
                .is_err()
        );
        assert_eq!(view.read_chunk(reference, 3, 5).unwrap(), bytes[3..8]);
        assert!(
            view.read(ContentRef::new(reference.id(), reference.bytes() + 1))
                .is_err()
        );
    }
}
