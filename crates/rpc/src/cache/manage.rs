use super::{CacheEntry, CacheKey, CacheKind, CacheResult, validate_identity};

#[derive(Clone, Debug, Default)]
pub struct CacheFilter {
    pub kind: Option<CacheKind>,
    pub identity: Option<String>,
}

impl CacheFilter {
    pub fn exact(key: &CacheKey) -> Self {
        Self {
            kind: Some(key.kind),
            identity: Some(key.identity.clone()),
        }
    }

    pub fn validate(&self) -> CacheResult<()> {
        if let Some(identity) = &self.identity {
            validate_identity(identity)?;
        }
        Ok(())
    }

    pub fn matches(&self, key: &CacheKey) -> bool {
        self.kind.as_ref().is_none_or(|kind| kind == &key.kind)
            && self
                .identity
                .as_ref()
                .is_none_or(|identity| identity == &key.identity)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CachePrune {
    /// Exclusive Unix timestamp cutoff.
    pub recorded_before: Option<u64>,
    pub max_entries: Option<u64>,
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Eviction {
    pub filter: CacheFilter,
    /// None clears all matching mappings.
    pub prune: Option<CachePrune>,
    pub dry_run: bool,
}

impl Eviction {
    /// Shared selection policy, evaluated under each store's index lock.
    pub fn select(&self, mut entries: Vec<CacheEntry>) -> CacheResult<Vec<CacheKey>> {
        self.filter.validate()?;
        entries.retain(|entry| self.filter.matches(&entry.key));
        let Some(prune) = self.prune else {
            return Ok(entries.into_iter().map(|entry| entry.key).collect());
        };
        if prune.recorded_before.is_none()
            && prune.max_entries.is_none()
            && prune.max_bytes.is_none()
        {
            return Err("prune requires an age, count, or byte limit".into());
        }
        entries.sort_by(|a, b| (a.recorded_at, &a.key).cmp(&(b.recorded_at, &b.key)));
        let CacheStats {
            entries: mut remaining,
            mut bytes,
        } = CacheStats::from_entries(&entries)?;
        let mut removed = Vec::new();
        for entry in entries {
            if prune
                .recorded_before
                .is_some_and(|before| entry.recorded_at < before)
                || prune.max_entries.is_some_and(|limit| remaining > limit)
                || prune.max_bytes.is_some_and(|limit| bytes > limit)
            {
                bytes -= entry.bytes;
                remaining -= 1;
                removed.push(entry.key);
            }
        }
        Ok(removed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: u64,
    pub bytes: u64,
}

impl CacheStats {
    pub fn from_entries(entries: &[CacheEntry]) -> CacheResult<Self> {
        let bytes = entries
            .iter()
            .try_fold(0_u64, |sum, entry| sum.checked_add(entry.bytes))
            .ok_or("cache size overflow")?;
        Ok(Self {
            entries: entries.len() as u64,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheRecording, CacheStore, MemoryCacheStore};
    use std::sync::Arc;

    #[test]
    fn prune_combines_limits_and_keeps_newest() {
        let entries: Vec<_> = (1..=4)
            .map(|n| CacheEntry {
                key: CacheKey::new(CacheKind::Proxy, &format!("{n:064x}")).unwrap(),
                output: crate::ContentId::from_bytes([0; 32]),
                recorded_at: n,
                bytes: 10,
            })
            .collect();
        for (prune, count) in [
            (
                CachePrune {
                    recorded_before: Some(3),
                    ..Default::default()
                },
                2,
            ),
            (
                CachePrune {
                    max_entries: Some(3),
                    max_bytes: Some(15),
                    ..Default::default()
                },
                3,
            ),
            (
                CachePrune {
                    max_entries: Some(0),
                    ..Default::default()
                },
                4,
            ),
            (
                CachePrune {
                    max_entries: Some(5),
                    max_bytes: Some(40),
                    ..Default::default()
                },
                0,
            ),
        ] {
            let keys = Eviction {
                prune: Some(prune),
                ..Default::default()
            }
            .select(entries.clone())
            .unwrap();
            assert_eq!(
                keys,
                entries[..count]
                    .iter()
                    .map(|e| e.key.clone())
                    .collect::<Vec<_>>()
            );
        }
        assert!(
            Eviction {
                prune: Some(CachePrune::default()),
                ..Default::default()
            }
            .select(entries)
            .is_err()
        );
    }

    #[test]
    fn clear_empty_store_invalidates_inflight_recording_but_dry_run_does_not() {
        let store = Arc::new(MemoryCacheStore::default());
        let key = CacheKey::hash(CacheKind::Proxy, &[b"request"]);
        let before_clear = CacheRecording::new(store.clone()).unwrap();
        store.evict(&Eviction::default()).unwrap();
        before_clear.insert(&key, b"old", 0).unwrap();
        assert!(store.list().unwrap().is_empty());

        let after_clear = CacheRecording::new(store.clone()).unwrap();
        store
            .evict(&Eviction {
                dry_run: true,
                ..Default::default()
            })
            .unwrap();
        after_clear.insert(&key, b"new", 1).unwrap();
        assert_eq!(store.get(&key).unwrap().unwrap(), b"new");
    }

    #[test]
    fn filtered_clear_preserves_other_kinds_and_rejects_invalid_filters() {
        let store = MemoryCacheStore::default();
        let proxy = CacheKey::hash(CacheKind::Proxy, &[b"one"]);
        let fetch = CacheKey::hash(CacheKind::Fetch, &[b"two"]);
        store.insert(&proxy, b"one", 1).unwrap();
        store.insert(&fetch, b"two", 2).unwrap();
        let filter = CacheFilter {
            kind: Some(CacheKind::Proxy),
            ..Default::default()
        };
        assert_eq!(
            store.stats(&filter).unwrap(),
            CacheStats {
                entries: 1,
                bytes: 3
            }
        );
        assert_eq!(
            store
                .evict(&Eviction {
                    filter,
                    ..Default::default()
                })
                .unwrap(),
            [proxy]
        );
        assert!(store.get(&fetch).unwrap().is_some());
        let generation = store.generation().unwrap();
        assert!(
            store
                .evict(&Eviction {
                    filter: CacheFilter {
                        identity: Some("invalid identity".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .is_err()
        );
        assert_eq!(store.generation().unwrap(), generation);
    }
}
