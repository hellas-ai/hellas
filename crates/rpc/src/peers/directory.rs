use std::sync::Arc;

use super::{AuthLevel, PeerId, PeerManager, PeerManagerError, PeerRegistryConfig};

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
    /// ALPN/FQN aliases the directory accepts in service-filter queries.
    pub service_aliases: Vec<ServiceAlias>,
    /// Minimum authentication level for disclosure; defaults to `Untrusted`.
    pub min_disclosed_auth_level: AuthLevel,
}

impl Default for PeerDirectoryConfig {
    fn default() -> Self {
        Self {
            registry: PeerRegistryConfig::default(),
            max_known_peers_response: 64,
            stale_peer_after_ms: 15 * 60 * 1000,
            service_aliases: Vec::new(),
            min_disclosed_auth_level: AuthLevel::Untrusted,
        }
    }
}

/// Shared peer directory for server-side peer exchange.
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
        Self {
            local_peer,
            manager: PeerManager::with_config(config.registry),
            config: Arc::new(config),
        }
    }

    /// Shares the registry used for disclosure.
    pub fn manager(&self) -> PeerManager {
        self.manager.clone()
    }

    /// Eligible peers in ascending PeerId order, capped by both response limits.
    pub fn known_peers(
        &self,
        requester: PeerId,
        requested_service_filter: &str,
        disclosure_limit: usize,
    ) -> Result<Vec<PeerId>, PeerManagerError> {
        self.known_peers_at(
            requester,
            requested_service_filter,
            disclosure_limit,
            self.manager.now_ms(),
        )
    }

    fn known_peers_at(
        &self,
        requester: PeerId,
        requested_service_filter: &str,
        disclosure_limit: usize,
        now: u64,
    ) -> Result<Vec<PeerId>, PeerManagerError> {
        let response_limit = disclosure_limit.min(self.config.max_known_peers_response);
        let config = self.config.as_ref();
        let service = config
            .service_aliases
            .iter()
            .find(|alias| alias.query == requested_service_filter)
            .map_or(requested_service_filter, |alias| alias.service);
        self.manager.with_registry(|registry| {
            let mut candidates: Vec<PeerId> = registry
                .iter()
                .filter(|peer| {
                    peer.id != self.local_peer
                        && peer.id != requester
                        && peer
                            .auth_level
                            .allows_at_least(config.min_disclosed_auth_level)
                        && now.saturating_sub(peer.last_seen_ms) <= config.stale_peer_after_ms
                        && if requested_service_filter.is_empty() {
                            !peer.services.is_empty()
                        } else {
                            peer.has_service(service)
                        }
                })
                .map(|peer| peer.id)
                .collect();
            // Order by XOR distance from this node's own id, not by id.
            // A plain id sort makes the lowest ids win truncation at every
            // responder, so once a network exceeds the disclosure limit a
            // high-id peer is never disclosed by anyone and can never be
            // discovered -- which defeats the point of peer exchange.
            // Distance from the responder gives each node a different
            // deterministic permutation of the same candidates, so every
            // peer is near the front for someone.
            candidates.sort_unstable_by_key(|peer| distance(self.local_peer, *peer));
            candidates.truncate(response_limit);
            candidates
        })
    }
}

/// XOR distance between two ids.
///
/// Not a routing metric here, and it makes no claim about proximity: it is
/// just a deterministic permutation of the candidate set that differs per
/// responder. A peer cannot improve its place by behaving differently, and
/// grinding an id buys a place at one responder rather than at all of them.
fn distance(a: PeerId, b: PeerId) -> [u8; 32] {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    std::array::from_fn(|index| a[index] ^ b[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::{DiscoverySource, PeerEvent, TransportSecurity};
    use TransportSecurity::{Authenticated, ChannelEncrypted, LocalCredential, Untrusted};

    fn peer(byte: u8) -> PeerId {
        PeerId::from([byte; 32])
    }

    #[test]
    fn known_peers_filter_then_truncate_deterministically() {
        let mut observations = [
            (0, 1_000, Authenticated, "node"), // self
            (1, 1_000, Authenticated, "node"), // requester
            (2, 1_000, Untrusted, "node"),
            (3, 1_000, LocalCredential, "node"),
            (4, 1_000, ChannelEncrypted, "node"),
            (5, 899, Authenticated, "node"), // stale by 1 ms
            (6, 1_000, Authenticated, "other"),
            (8, 900, Authenticated, "node"), // age == cutoff
            (9, 1_000, Authenticated, "node"),
        ];
        // Rebuild independently seeded HashMaps in different insertion orders.
        for _ in 0..observations.len() {
            observations.rotate_left(1);
            let mut directory = PeerDirectory::with_config(
                peer(0),
                PeerDirectoryConfig {
                    stale_peer_after_ms: 100,
                    service_aliases: vec![ServiceAlias::new("/node/1", "node")],
                    ..Default::default()
                },
            );
            directory
                .manager
                .with_registry_mut(|registry| {
                    for &(id, seen, security, service) in &observations {
                        registry.observe_discovered_service(
                            seen,
                            peer(id),
                            DiscoverySource::Manual,
                            service,
                            security,
                        );
                    }
                    registry.apply(
                        1_000,
                        peer(7),
                        PeerEvent::Discovered {
                            source: DiscoverySource::Manual,
                            transport_security: Authenticated,
                        },
                    ); // authenticated, but no service
                    // Counters and RTT vary without changing eligibility.
                    for _ in 0..100 {
                        registry
                            .observe_inbound_request(1_000, peer(9), Some(1.0))
                            .unwrap();
                    }
                })
                .unwrap();
            for (auth, expected) in [
                (AuthLevel::Untrusted, vec![2, 3, 4, 8, 9]),
                (AuthLevel::Local, vec![3, 8, 9]),
                (AuthLevel::Authenticated, vec![8, 9]),
            ] {
                Arc::make_mut(&mut directory.config).min_disclosed_auth_level = auth;
                for (filter, mut ids) in [
                    ("/node/1", expected.clone()),
                    ("node", expected.clone()),
                    ("", [expected, vec![6]].concat()),
                    ("other", vec![6]),
                    ("unknown", vec![]),
                ] {
                    ids.sort_unstable();
                    for cap in [0, 2, 64] {
                        Arc::make_mut(&mut directory.config).max_known_peers_response = cap;
                        for limit in 0..=6 {
                            let expected: Vec<_> =
                                ids.iter().copied().take(limit.min(cap)).map(peer).collect();
                            for _ in 0..2 {
                                assert_eq!(
                                    directory
                                        .known_peers_at(peer(1), filter, limit, 1_000)
                                        .unwrap(),
                                    expected,
                                    "auth={auth:?}, filter={filter:?}, cap={cap}, limit={limit}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn truncation_discloses_a_different_slice_at_each_responder() {
        // The property XOR ordering exists for. Sorting candidates by id
        // alone would hand every responder the same lowest-N peers, so once
        // a network exceeds the disclosure limit a high-id peer would never
        // be disclosed by anyone and could never be discovered. Distance
        // from the responder's own id puts every candidate near the front
        // for someone.
        const CANDIDATES: u8 = 24;
        const LIMIT: usize = 3;

        let mut disclosed = std::collections::BTreeSet::new();
        for responder in 200u8..240 {
            let directory = PeerDirectory::with_config(
                peer(responder),
                PeerDirectoryConfig {
                    stale_peer_after_ms: 100,
                    service_aliases: vec![ServiceAlias::new("/node/1", "node")],
                    ..Default::default()
                },
            );
            directory
                .manager
                .with_registry_mut(|registry| {
                    for id in 0..CANDIDATES {
                        registry.observe_discovered_service(
                            1_000,
                            peer(id),
                            DiscoverySource::Manual,
                            "node",
                            Authenticated,
                        );
                    }
                })
                .unwrap();
            let peers = directory
                .known_peers_at(peer(255), "/node/1", LIMIT, 1_000)
                .expect("known peers");
            assert_eq!(
                peers.len(),
                LIMIT,
                "responder {responder} truncated wrongly"
            );
            disclosed.extend(peers);
        }

        // A plain id sort would make this set exactly the lowest LIMIT ids.
        assert!(
            disclosed.len() > LIMIT * 4,
            "40 responders disclosed only {} of {CANDIDATES} candidates: {disclosed:?}",
            disclosed.len()
        );
    }
}
