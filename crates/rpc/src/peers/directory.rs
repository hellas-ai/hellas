use std::sync::Arc;
use std::time::Duration;

use super::{AuthLevel, PeerEntry, PeerId, PeerManager, PeerManagerError, PeerRegistryConfig};

const DEFAULT_MAX_TRACKED_PEERS: usize = 2048;
const DEFAULT_MAX_KNOWN_PEERS_RESPONSE: usize = 64;
const DEFAULT_STALE_PEER_AFTER_MS: u64 = 15 * 60 * 1000;
const DEFAULT_LATENCY_SCORE: i64 = 450;
const DEFAULT_MAX_SERVICE_FILTER_LEN: usize = 128;
const DEFAULT_GLOBAL_BUCKET_CAPACITY: f64 = 16.0;
const DEFAULT_GLOBAL_BUCKET_REFILL_PER_SEC: f64 = 4.0;

/// Alias accepted by peer-disclosure service filters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceAlias {
    pub query: &'static str,
    pub service: &'static str,
}

impl ServiceAlias {
    pub const fn new(query: &'static str, service: &'static str) -> Self {
        Self { query, service }
    }
}

/// Policy and bounds for serving peer-disclosure APIs.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerDirectoryConfig {
    pub registry: PeerRegistryConfig,
    pub max_known_peers_response: usize,
    pub stale_peer_after_ms: u64,
    pub default_latency_score: i64,
    pub max_service_filter_len: usize,
    pub global_known_peers_bucket_capacity: f64,
    pub global_known_peers_bucket_refill_per_sec: f64,
    /// ALPN/FQN aliases the directory accepts in service-filter queries.
    /// Empty unless the owning crate injects its service catalogue.
    pub service_aliases: Vec<ServiceAlias>,
    /// Minimum `AuthLevel` a peer must hold to appear in
    /// [`PeerDirectory::ranked_known_peers`]. Default is `Untrusted` (no
    /// filtering); set higher to gate disclosure on transport-authenticated
    /// or operator-trusted peers only.
    pub min_disclosed_auth_level: AuthLevel,
}

impl Default for PeerDirectoryConfig {
    fn default() -> Self {
        Self {
            registry: PeerRegistryConfig {
                max_peers: DEFAULT_MAX_TRACKED_PEERS,
                bucket_capacity: 24.0,
                bucket_refill_per_sec: 2.0,
                ..PeerRegistryConfig::default()
            },
            max_known_peers_response: DEFAULT_MAX_KNOWN_PEERS_RESPONSE,
            stale_peer_after_ms: DEFAULT_STALE_PEER_AFTER_MS,
            default_latency_score: DEFAULT_LATENCY_SCORE,
            max_service_filter_len: DEFAULT_MAX_SERVICE_FILTER_LEN,
            global_known_peers_bucket_capacity: DEFAULT_GLOBAL_BUCKET_CAPACITY,
            global_known_peers_bucket_refill_per_sec: DEFAULT_GLOBAL_BUCKET_REFILL_PER_SEC,
            // Empty by default: p2p does not know the concrete protocol
            // services. The owning crate (hellas-rpc) populates this from its
            // generated service catalogue via `hellas_rpc::peer_service_aliases`.
            service_aliases: Vec::new(),
            min_disclosed_auth_level: AuthLevel::Untrusted,
        }
    }
}

impl PeerDirectoryConfig {
    fn normalized(mut self) -> Self {
        if !self.global_known_peers_bucket_capacity.is_finite()
            || self.global_known_peers_bucket_capacity < 0.0
        {
            self.global_known_peers_bucket_capacity = 0.0;
        }
        if !self.global_known_peers_bucket_refill_per_sec.is_finite()
            || self.global_known_peers_bucket_refill_per_sec < 0.0
        {
            self.global_known_peers_bucket_refill_per_sec = 0.0;
        }
        self.registry = self.registry.normalized();
        self
    }

    /// Combinations that would make the directory behave nonsensically.
    /// Bubbles up the per-peer registry's reasons plus the directory's
    /// own global-disclosure-bucket check, so a config check at startup
    /// reports every violation at once.
    pub fn validate(&self) -> Vec<String> {
        let mut reasons = self.registry.validate();
        if self.global_known_peers_bucket_capacity > 0.0
            && self.global_known_peers_bucket_capacity < 1.0
        {
            reasons.push(format!(
                "global_known_peers_bucket_capacity {:.3} is in (0, 1): the \
                 shared disclosure bucket can never hold a full token, so \
                 every rate-limited disclosure-style request would be \
                 rejected. Set it >= 1.0 or 0.0.",
                self.global_known_peers_bucket_capacity
            ));
        }
        reasons
    }
}

/// Shared peer directory for server-side peer exchange and recommendation.
///
/// Wraps `PeerManager` with ranking/filtering policy for `get_known_peers`-
/// style responses.
#[derive(Clone, Debug)]
pub struct PeerDirectory {
    local_peer: PeerId,
    manager: PeerManager,
    config: Arc<PeerDirectoryConfig>,
}

impl PeerDirectory {
    pub fn new(local_peer: PeerId) -> Self {
        Self::with_config(local_peer, PeerDirectoryConfig::default())
    }

    pub fn with_config(local_peer: PeerId, config: PeerDirectoryConfig) -> Self {
        let config = config.normalized();
        let reasons = config.validate();
        assert!(
            reasons.is_empty(),
            "PeerDirectoryConfig is invalid:\n  - {}",
            reasons.join("\n  - "),
        );
        let manager = PeerManager::with_config(config.registry);
        Self {
            local_peer,
            manager,
            config: Arc::new(config),
        }
    }

    /// Cheap (`Arc<Mutex<_>>`) clone of the underlying `PeerManager`,
    /// for callers — chiefly `AccountingDispatcher` — that need to
    /// write inbound observations into the same registry this
    /// directory will later rank from.
    pub fn manager(&self) -> PeerManager {
        self.manager.clone()
    }

    pub fn ranked_known_peers(
        &self,
        requester: PeerId,
        requested_service_filter: &str,
        disclosure_limit: usize,
    ) -> Result<Vec<PeerId>, PeerManagerError> {
        let now = self.manager.now_ms();
        let response_limit = disclosure_limit.min(self.config.max_known_peers_response);
        let config = self.config.as_ref();
        self.manager.with_registry(|registry| {
            let mut candidates: Vec<(PeerId, i64)> = registry
                .iter()
                .filter_map(|peer| {
                    if peer.id == self.local_peer || peer.id == requester {
                        return None;
                    }
                    if !peer
                        .auth_level
                        .allows_at_least(config.min_disclosed_auth_level)
                    {
                        return None;
                    }
                    let age_ms = now.saturating_sub(peer.last_seen_ms);
                    if age_ms > config.stale_peer_after_ms {
                        return None;
                    }
                    if !matches_service_filter(peer, requested_service_filter, config) {
                        return None;
                    }
                    let score = recommendation_score(peer, now, config);
                    if score <= 0 {
                        return None;
                    }
                    Some((peer.id, score))
                })
                .collect();

            // Higher score first; PeerId ascending tie-breaks. The PeerId
            // disambiguator is load-bearing — without it, equal-score peers
            // came back in HashMap iteration order, leaking randomness into
            // a public response that callers (and tests) rely on being
            // deterministic.
            candidates.sort_by(|(left_id, left_score), (right_id, right_score)| {
                right_score
                    .cmp(left_score)
                    .then_with(|| left_id.cmp(right_id))
            });
            candidates
                .into_iter()
                .take(response_limit)
                .map(|(peer_id, _)| peer_id)
                .collect()
        })
    }
}

fn matches_service_filter(
    peer: &PeerEntry,
    requested_service_filter: &str,
    config: &PeerDirectoryConfig,
) -> bool {
    if requested_service_filter.is_empty() {
        return !peer.services.is_empty();
    }
    service_for_filter(requested_service_filter, config).map_or_else(
        || peer.has_service(requested_service_filter),
        |service| peer.has_service(service),
    )
}

fn service_for_filter(
    requested_service_filter: &str,
    config: &PeerDirectoryConfig,
) -> Option<&'static str> {
    config
        .service_aliases
        .iter()
        .find(|alias| alias.query == requested_service_filter)
        .map(|alias| alias.service)
}

fn recommendation_score(peer: &PeerEntry, now_ms: u64, config: &PeerDirectoryConfig) -> i64 {
    let age_ms = now_ms.saturating_sub(peer.last_seen_ms);
    let age_secs = age_ms as f64 / 1000.0;
    let stale_after_secs = Duration::from_millis(config.stale_peer_after_ms).as_secs_f64();
    let recency_score = ((1.0 - (age_secs / stale_after_secs)).clamp(0.0, 1.0) * 1000.0) as i64;

    let latency_score = peer
        .rtt
        .get()
        .map(latency_score)
        .unwrap_or(config.default_latency_score);

    let lifespan_secs = now_ms.saturating_sub(peer.first_seen_ms) as f64 / 1000.0;
    let stability_score = ((lifespan_secs / 60.0).clamp(0.0, 20.0) * 50.0) as i64;

    let request_score = (peer.total_requests.min(60) as i64) * 8;
    let behavior_penalty = bounded_penalty(peer.invalid_request_count, 350)
        + bounded_penalty(peer.rate_limited_count, 110);

    (latency_score * 4) + (recency_score * 3) + (stability_score * 2) + request_score
        - behavior_penalty
}

fn latency_score(rtt_ms: f64) -> i64 {
    if rtt_ms <= 5.0 {
        return 1000;
    }
    if rtt_ms >= 2_500.0 {
        return 0;
    }
    (((2_500.0 - rtt_ms) / 2_495.0) * 1000.0) as i64
}

fn bounded_penalty(count: u64, weight: i64) -> i64 {
    count.saturating_mul(weight as u64).min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::DiscoverySource;
    use crate::peers::TransportSecurity;
    use crate::peers::test_markers::TestService as NodeService;
    use hellas_wire::ServiceMarker;

    fn peer(byte: u8) -> PeerId {
        PeerId::from([byte; 32])
    }

    /// Record a peer at a caller-chosen timestamp instead of the manager's
    /// clock, so that several peers can share one `last_seen_ms`.
    ///
    /// `recommendation_score` derives recency from `now_ms - last_seen_ms` and
    /// truncates with `as i64`, so a peer observed in the query's own
    /// millisecond scores 1000 while one observed a single millisecond earlier
    /// scores 999 — the next honest decrement is ~0.9 s away. Marking peers
    /// through the wall clock therefore produces unequal scores whenever the
    /// loop straddles a millisecond, which is exactly what a loaded CI runner
    /// does. Those runs never reach the PeerId tie-break this test exists to
    /// pin.
    fn mark_node_at(directory: &PeerDirectory, id: PeerId, now_ms: u64) {
        directory
            .manager
            .with_registry_mut(|registry| {
                registry.observe_discovered_service(
                    now_ms,
                    id,
                    DiscoverySource::Transport("test"),
                    <NodeService as ServiceMarker>::NAME,
                    TransportSecurity::Untrusted,
                )
            })
            .expect("service should be recorded");
    }

    #[test]
    fn ranked_known_peers_tie_breaks_on_peer_id_for_determinism() {
        // Equal recommendation scores must not surface in random
        // HashMap-iteration order. The sort uses PeerId ascending as a
        // tiebreaker so the public response is deterministic — repeated
        // calls against the same state return the same vector, even when
        // the registry contains many peers with identical scores.
        // Every peer is observed at this one instant. Non-zero so the entries
        // are not sitting on the manager's own epoch, and far enough below
        // `stale_peer_after_ms` that nothing is filtered as stale.
        const SHARED_OBSERVATION_MS: u64 = 1_000;

        let local = peer(0);
        let requester = peer(99);
        let mut ids = vec![peer(5), peer(2), peer(7), peer(1), peer(3)];

        // p2p ships an empty alias table (it does not know concrete
        // services); inject the test service so ALPN queries resolve.
        let config = PeerDirectoryConfig {
            service_aliases: vec![ServiceAlias::new(
                <NodeService as ServiceMarker>::ALPN,
                <NodeService as ServiceMarker>::NAME,
            )],
            ..Default::default()
        };
        let mut expected: Option<Vec<PeerId>> = None;
        let id_count = ids.len();
        for trial in 0..8 {
            let directory = PeerDirectory::with_config(local, config.clone());
            ids.rotate_left(trial % id_count);
            for id in &ids {
                // One shared timestamp for every peer: the scores are then
                // equal by construction and the PeerId tie-break is the only
                // thing that can order them.
                mark_node_at(&directory, *id, SHARED_OBSERVATION_MS);
            }
            let peers = directory
                .ranked_known_peers(requester, <NodeService as ServiceMarker>::ALPN, 64)
                .expect("ranked");
            match &expected {
                None => expected = Some(peers),
                Some(prev) => assert_eq!(&peers, prev, "must be deterministic"),
            }
        }
        // PeerId ascending: 1, 2, 3, 5, 7.
        assert_eq!(
            expected.unwrap(),
            vec![peer(1), peer(2), peer(3), peer(5), peer(7)]
        );
    }
}
