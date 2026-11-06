use super::{Scope, Source};
use hellas_rpc::{ContentId, ContentRef};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default)]
pub struct StoreStats {
    pub used: u64,
    pub outstanding: u64,
    pub free: u64,
}
pub struct Miss {
    pub scope: Scope,
    pub object: ContentRef,
}
pub enum MissDecision {
    Refuse,
    Acquire { source: Source },
}
pub trait OnMiss: Send + Sync {
    fn decide(&self, miss: &Miss, stats: &StoreStats) -> MissDecision;
}
pub struct Refuse;
impl OnMiss for Refuse {
    fn decide(&self, _: &Miss, _: &StoreStats) -> MissDecision {
        MissDecision::Refuse
    }
}
pub struct AllowList(pub BTreeMap<ContentId, (u64, Source)>);
impl OnMiss for AllowList {
    fn decide(&self, miss: &Miss, _: &StoreStats) -> MissDecision {
        self.0
            .get(&miss.object.id())
            .filter(|(bytes, _)| *bytes == miss.object.bytes())
            .map_or(MissDecision::Refuse, |(_, source)| MissDecision::Acquire {
                source: source.clone(),
            })
    }
}
pub struct Unpinned {
    pub id: ContentId,
    pub bytes: u64,
    pub last_read: u64,
}
pub trait Eviction: Send + Sync {
    fn order(&self, unpinned: &[Unpinned], stats: &StoreStats) -> Vec<ContentId>;
}
/// Least-recently read first, with byte thresholds for the host eviction loop.
pub struct Lru {
    pub high_water: u64,
    pub low_water: u64,
}
impl Eviction for Lru {
    fn order(&self, unpinned: &[Unpinned], _: &StoreStats) -> Vec<ContentId> {
        let mut objects: Vec<_> = unpinned.iter().collect();
        objects.sort_by_key(|object| (object.last_read, object.id));
        objects.into_iter().map(|object| object.id).collect()
    }
}
