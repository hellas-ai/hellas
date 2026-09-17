//! Inference index over the node's content store. The index maps input
//! identities to immutable objects; listing never reads transcript bodies.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hellas_rpc::cache::{CacheEntry, CacheKey, CacheResult, CacheStore, Eviction};
use serde::{Deserialize, Serialize};

use crate::ContentStore;

const INDEX: &str = "inference-index.dagcbor";

#[derive(Serialize, Deserialize)]
struct Index {
    version: u32,
    entries: Vec<CacheEntry>,
    #[serde(skip)]
    generation: u64,
}

pub struct FsCacheStore {
    root: PathBuf,
    content: ContentStore,
    writer: Option<File>,
    index: Mutex<Index>,
}

impl FsCacheStore {
    pub fn open(root: &Path, writable: bool) -> CacheResult<Self> {
        if writable {
            fs::create_dir_all(root)?;
        }
        let writer = if writable {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(root.join(".inference-writer.lock"))?;
            lock.try_lock()
                .map_err(|error| format!("inference index already has a writer; use output-cache --socket or --node-id to manage the live node: {error}"))?;
            Some(lock)
        } else {
            None
        };
        let (index, initialize) = match fs::read(root.join(INDEX)) {
            Ok(bytes) => {
                let index: Index = serde_ipld_dagcbor::from_slice(&bytes)?;
                if index.version != 1 {
                    return Err("unsupported inference index version".into());
                }
                let mut keys = std::collections::BTreeSet::new();
                for entry in &index.entries {
                    entry.key.validate()?;
                    if !keys.insert(entry.key.clone()) {
                        return Err("duplicate inference index key".into());
                    }
                }
                (index, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
                Index {
                    version: 1,
                    entries: Vec::new(),
                    generation: 0,
                },
                writable,
            ),
            Err(error) => return Err(error.into()),
        };
        let store = Self {
            root: root.to_owned(),
            content: ContentStore::new(),
            writer,
            index: Mutex::new(index),
        };
        if initialize {
            store.write_index(&store.index.lock().unwrap())?;
        }
        Ok(store)
    }

    fn write_index(&self, index: &Index) -> CacheResult<()> {
        if self.writer.is_none() {
            return Err("inference index is read-only".into());
        }
        let bytes = serde_ipld_dagcbor::to_vec(index)?;
        crate::objects::publish(&self.root.join(INDEX), &bytes, false).map_err(Into::into)
    }
}

impl CacheStore for FsCacheStore {
    fn evict(&self, eviction: &Eviction) -> CacheResult<Vec<CacheKey>> {
        let mut index = self.index.lock().unwrap();
        let removed = eviction.select(index.entries.clone())?;
        if eviction.dry_run {
            return Ok(removed);
        }
        if self.writer.is_none() {
            return Err("inference index is read-only".into());
        }
        let keys: std::collections::BTreeSet<_> = removed.iter().collect();
        let next = Index {
            version: 1,
            entries: index
                .entries
                .iter()
                .filter(|entry| !keys.contains(&entry.key))
                .cloned()
                .collect(),
            generation: index
                .generation
                .checked_add(1)
                .ok_or("cache generation overflow")?,
        };
        if !removed.is_empty() {
            self.write_index(&next)?;
        }
        *index = next;
        Ok(removed)
    }
    fn get(&self, key: &CacheKey) -> CacheResult<Option<Vec<u8>>> {
        let index = self.index.lock().unwrap();
        let Some(entry) = index.entries.iter().find(|entry| &entry.key == key) else {
            return Ok(None);
        };
        let path = self.root.join("objects").join(entry.output.to_string());
        self.content.index(&path)?;
        let file = self
            .content
            .open_verified(entry.output.digest(), entry.bytes)?
            .ok_or_else(|| format!("missing or corrupt output object {}", entry.output))?;
        let mut bytes = Vec::new();
        file.into_file().read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn generation(&self) -> CacheResult<u64> {
        Ok(self.index.lock().unwrap().generation)
    }

    fn insert_at_generation(
        &self,
        key: &CacheKey,
        bytes: &[u8],
        recorded_at: u64,
        generation: u64,
    ) -> CacheResult<bool> {
        key.validate()?;
        let mut index = self.index.lock().unwrap();
        if self.writer.is_none() {
            return Err("inference index is read-only".into());
        }
        if index.generation != generation {
            return Ok(false);
        }
        if index.entries.iter().any(|entry| &entry.key == key) {
            return Ok(true);
        }
        let output = self.content.put(&self.root, bytes)?;
        let mut next = Index {
            version: 1,
            entries: index.entries.clone(),
            generation,
        };
        next.entries.push(CacheEntry {
            key: key.clone(),
            output: hellas_rpc::ContentId::from_bytes(*output.id.as_bytes()),
            recorded_at,
            bytes: output.len,
        });
        next.entries.sort_by(|a, b| a.key.cmp(&b.key));
        self.write_index(&next)?;
        *index = next;
        Ok(true)
    }

    fn list(&self) -> CacheResult<Vec<CacheEntry>> {
        Ok(self.index.lock().unwrap().entries.clone())
    }
}
#[cfg(test)]
mod tests;
