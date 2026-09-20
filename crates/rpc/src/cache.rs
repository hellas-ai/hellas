//! Storage contract for first-use inference results. Input identities index
//! immutable output objects; neither identity depends on where bytes live.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use serde::{Deserialize, Serialize};

use crate::{ContentId, Digest};

mod manage;
pub use manage::{CacheFilter, CachePrune, CacheStats, Eviction};
#[cfg(feature = "host-control")]
pub mod control;

pub type CacheError = Box<dyn std::error::Error + Send + Sync>;
pub type CacheResult<T> = Result<T, CacheError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript<E, P> {
    pub version: u32,
    pub key: CacheKey,
    pub initial_provenance: Option<P>,
    pub events: Vec<E>,
}

impl<E, P> Transcript<E, P> {
    pub fn validate(
        &self,
        key: &CacheKey,
        terminal: impl Fn(&E) -> Option<bool>,
    ) -> CacheResult<()> {
        if self.version != 1 || &self.key != key {
            return Err("unsupported transcript version or identity mismatch".into());
        }
        if self.events.last().and_then(&terminal) != Some(true) {
            return Err("transcript has no successful terminal event".into());
        }
        if self.events[..self.events.len() - 1]
            .iter()
            .any(|event| terminal(event).is_some())
        {
            return Err("invalid transcript prefix".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvaluateEvent {
    Chunk { position: u64, tokens: Vec<u8> },
    Done(EvaluateOutcome),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvaluateOutcome {
    Completed {
        total_tokens: u64,
        stop_reason: EvaluateStop,
        text_artifact: Digest,
        output_events: Vec<crate::OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluateStop {
    StopToken(u32),
    MaxNewTokens,
}

impl EvaluateEvent {
    pub fn terminal(&self) -> Option<bool> {
        match self {
            Self::Chunk { .. } => None,
            Self::Done(EvaluateOutcome::Completed { .. }) => Some(true),
            Self::Done(EvaluateOutcome::Failed { .. }) => Some(false),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CachePolicy {
    #[default]
    Off,
    Record,
    ReplayOnly,
}

impl std::str::FromStr for CachePolicy {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "record" => Ok(Self::Record),
            "replay-only" => Ok(Self::ReplayOnly),
            _ => Err("expected off, record, or replay-only".into()),
        }
    }
}

#[derive(Clone, Default)]
pub struct CacheOptions {
    pub policy: CachePolicy,
    pub store: Option<std::sync::Arc<dyn CacheStore + Send + Sync>>,
}

impl CacheOptions {
    pub fn recording(&self) -> CacheResult<Option<CacheRecording>> {
        if self.policy != CachePolicy::Record {
            return Ok(None);
        }
        CacheRecording::new(self.store.clone().ok_or("enabled cache has no store")?).map(Some)
    }
}

/// A publication permit captured before inference starts. Index mutations
/// invalidate older permits without cancelling callers' running inference.
#[derive(Clone)]
pub struct CacheRecording {
    store: Arc<dyn CacheStore + Send + Sync>,
    generation: u64,
}

impl CacheRecording {
    pub fn new(store: Arc<dyn CacheStore + Send + Sync>) -> CacheResult<Self> {
        let generation = store.generation()?;
        Ok(Self { store, generation })
    }

    pub fn insert(&self, key: &CacheKey, bytes: &[u8], recorded_at: u64) -> CacheResult<()> {
        self.store
            .insert_at_generation(key, bytes, recorded_at, self.generation)
            .map(|_| ())
    }
}

/// Stable lowercase names are part of cache identities and the stored format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheKind {
    // Preserve the original lexicographic order for listing and prune ties.
    Evaluate,
    Fetch,
    Proxy,
}

impl CacheKind {
    pub const ALL: [Self; 3] = [Self::Evaluate, Self::Fetch, Self::Proxy];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evaluate => "evaluate",
            Self::Fetch => "fetch",
            Self::Proxy => "proxy",
        }
    }
}

impl std::fmt::Display for CacheKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CacheKind {
    type Err = CacheError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| format!("unknown cache kind: {value}").into())
    }
}

fn validate_identity(identity: &str) -> CacheResult<()> {
    if identity.len() != 64
        || !identity
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("cache identity must be 64 lowercase hex characters".into());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CacheKey {
    pub kind: CacheKind,
    pub identity: String,
}

impl CacheKey {
    pub fn new(kind: CacheKind, identity: &str) -> CacheResult<Self> {
        validate_identity(identity)?;
        Ok(Self {
            kind,
            identity: identity.into(),
        })
    }

    pub fn evaluate(execution: Digest) -> Self {
        Self::new(CacheKind::Evaluate, &execution.to_string()).expect("digest identity")
    }

    /// Only sealed inference adaptors are reusable. General Fetch operations
    /// may have side effects and must never be memoized implicitly.
    #[cfg(feature = "fetch")]
    pub fn fetch(
        environment: ContentId,
        service: &str,
        method: &str,
        body: &[u8],
    ) -> CacheResult<Self> {
        if ![
            crate::FetchEnvironment::OpenAiResponses,
            crate::FetchEnvironment::CodexResponses,
        ]
        .iter()
        .any(|known| known.manifest_id() == environment)
        {
            return Err(
                "output caching requires a built-in Responses inference environment".into(),
            );
        }
        Ok(Self::hash(
            CacheKind::Fetch,
            &[
                environment.as_bytes(),
                service.as_bytes(),
                method.as_bytes(),
                body,
            ],
        ))
    }

    /// Non-inference routes bypass recording, but must not execute in an
    /// offline replay-only run. Do not turn unrelated Fetch work into a cache.
    #[cfg(feature = "fetch")]
    pub fn fetch_for_policy(
        policy: CachePolicy,
        environment: ContentId,
        service: &str,
        method: &str,
        body: &[u8],
    ) -> CacheResult<Option<Self>> {
        match Self::fetch(environment, service, method, body) {
            Ok(key) => Ok(Some(key)),
            Err(_) if policy == CachePolicy::Record => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn hash(kind: CacheKind, fields: &[&[u8]]) -> Self {
        let identity = crate::hash_tuple(&format!("hellas.inference-cache.v1.{kind}"), fields);
        Self::new(kind, &identity.to_string()).expect("digest identity")
    }

    pub fn validate(&self) -> CacheResult<()> {
        validate_identity(&self.identity)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: CacheKey,
    pub output: ContentId,
    pub recorded_at: u64,
    pub bytes: u64,
}

/// Publish the object before its index entry, and never replace an existing
/// input mapping. Removing a mapping must not remove objects used elsewhere.
/// No filesystem or executor dependency is required to implement this trait.
pub trait CacheStore {
    fn get(&self, key: &CacheKey) -> CacheResult<Option<Vec<u8>>>;
    fn generation(&self) -> CacheResult<u64>;
    /// Check the generation and publish under the same lock as eviction.
    /// False means an administrative mutation superseded this recording.
    fn insert_at_generation(
        &self,
        key: &CacheKey,
        bytes: &[u8],
        recorded_at: u64,
        generation: u64,
    ) -> CacheResult<bool>;
    fn insert(&self, key: &CacheKey, bytes: &[u8], recorded_at: u64) -> CacheResult<()> {
        self.insert_at_generation(key, bytes, recorded_at, self.generation()?)
            .map(|_| ())
    }
    fn list(&self) -> CacheResult<Vec<CacheEntry>>;
    /// Select and remove mappings atomically. Every non-dry-run mutation,
    /// including clearing an empty index, invalidates outstanding recordings.
    fn evict(&self, eviction: &Eviction) -> CacheResult<Vec<CacheKey>>;
    fn remove(&self, key: &CacheKey) -> CacheResult<bool> {
        Ok(!self
            .evict(&Eviction {
                filter: CacheFilter::exact(key),
                ..Default::default()
            })?
            .is_empty())
    }
    fn query(&self, filter: &CacheFilter) -> CacheResult<Vec<CacheEntry>> {
        filter.validate()?;
        Ok(self
            .list()?
            .into_iter()
            .filter(|entry| filter.matches(&entry.key))
            .collect())
    }
    fn stats(&self, filter: &CacheFilter) -> CacheResult<CacheStats> {
        CacheStats::from_entries(&self.query(filter)?)
    }
}

/// Per-input coordination without imposing an async runtime on the storage
/// contract. Callers hold an owned lock through publication and recheck after
/// acquiring it. Idle keys do not accumulate indefinitely.
pub struct CacheLocks<L>(Mutex<BTreeMap<CacheKey, Weak<L>>>);

impl<L> Default for CacheLocks<L> {
    fn default() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }
}

impl<L: Default> CacheLocks<L> {
    pub fn for_key(&self, key: &CacheKey) -> Arc<L> {
        let mut locks = self.0.lock().unwrap();
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(L::default());
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }
}

#[derive(Default)]
pub struct MemoryCacheStore(Mutex<MemoryIndex>);

#[derive(Default)]
struct MemoryIndex {
    generation: u64,
    entries: BTreeMap<CacheKey, (CacheEntry, Vec<u8>)>,
}

impl CacheStore for MemoryCacheStore {
    fn get(&self, key: &CacheKey) -> CacheResult<Option<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .entries
            .get(key)
            .map(|(_, bytes)| bytes.clone()))
    }

    fn generation(&self) -> CacheResult<u64> {
        Ok(self.0.lock().unwrap().generation)
    }

    fn insert_at_generation(
        &self,
        key: &CacheKey,
        bytes: &[u8],
        recorded_at: u64,
        generation: u64,
    ) -> CacheResult<bool> {
        key.validate()?;
        let mut index = self.0.lock().unwrap();
        if index.generation != generation {
            return Ok(false);
        }
        index.entries.entry(key.clone()).or_insert_with(|| {
            (
                CacheEntry {
                    key: key.clone(),
                    output: ContentId::hash(bytes),
                    recorded_at,
                    bytes: bytes.len() as u64,
                },
                bytes.to_vec(),
            )
        });
        Ok(true)
    }

    fn list(&self) -> CacheResult<Vec<CacheEntry>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .entries
            .values()
            .map(|(entry, _)| entry.clone())
            .collect())
    }

    fn evict(&self, eviction: &Eviction) -> CacheResult<Vec<CacheKey>> {
        let mut index = self.0.lock().unwrap();
        let keys = eviction.select(
            index
                .entries
                .values()
                .map(|(entry, _)| entry.clone())
                .collect(),
        )?;
        if !eviction.dry_run {
            index.generation = index
                .generation
                .checked_add(1)
                .ok_or("cache generation overflow")?;
            for key in &keys {
                index.entries.remove(key);
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct LegacyKey<'a> {
        kind: &'a str,
        identity: &'a str,
    }

    #[test]
    fn closed_kinds_preserve_stored_bytes_hash_domains_and_sort_order() {
        let names = ["evaluate", "fetch", "proxy"];
        for (kind, name) in CacheKind::ALL.into_iter().zip(names) {
            assert_eq!(kind.to_string(), name);
            assert_eq!(name.parse::<CacheKind>().unwrap(), kind);
            let key = CacheKey::hash(kind, &[b"request"]);
            assert_eq!(
                key.identity,
                crate::hash_tuple(&format!("hellas.inference-cache.v1.{name}"), &[b"request"])
                    .to_string()
            );
            let legacy = serde_ipld_dagcbor::to_vec(&LegacyKey {
                kind: name,
                identity: &key.identity,
            })
            .unwrap();
            assert_eq!(serde_ipld_dagcbor::to_vec(&key).unwrap(), legacy);
            assert_eq!(
                serde_ipld_dagcbor::from_slice::<CacheKey>(&legacy).unwrap(),
                key
            );
        }
        assert!(CacheKind::ALL.windows(2).all(|pair| pair[0] < pair[1]));
        for kind in ["unknown", "Proxy", "../proxy", ""] {
            assert!(kind.parse::<CacheKind>().is_err());
            let bytes = serde_ipld_dagcbor::to_vec(&LegacyKey {
                kind,
                identity: &"0".repeat(64),
            })
            .unwrap();
            assert!(serde_ipld_dagcbor::from_slice::<CacheKey>(&bytes).is_err());
        }
    }
}
