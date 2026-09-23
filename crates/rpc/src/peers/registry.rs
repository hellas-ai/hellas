use std::collections::HashMap;

use hellas_wire::latency::EwmaLatency;

use super::RpcService;
use super::admission::{AcquireDenied, Outcome, Permit, RequestKind, TokenBucket};
use super::id::PeerId;
use super::security::{AuthLevel, TransportSecurity};

const DEFAULT_MAX_PEERS: usize = 2048;
const DEFAULT_MAX_SERVICES_PER_PEER: usize = 32;
const DEFAULT_MAX_IN_FLIGHT_PER_PEER: usize = 16;
const DEFAULT_MAX_IN_FLIGHT_TOTAL: usize = 256;
const DEFAULT_BUCKET_CAPACITY: f64 = 24.0;
const DEFAULT_BUCKET_REFILL_PER_SEC: f64 = 2.0;
const DEFAULT_RTT_EMA_ALPHA: f64 = 0.2;
const DEFAULT_MAX_LABEL_LEN: usize = 128;

/// Memory and admission bounds for a peer registry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeerRegistryConfig {
    pub max_peers: usize,
    pub max_services_per_peer: usize,
    pub max_in_flight_per_peer: usize,
    pub max_in_flight_total: usize,
    pub bucket_capacity: f64,
    pub bucket_refill_per_sec: f64,
    pub rtt_ema_alpha: f64,
    pub max_label_len: usize,
}

impl Default for PeerRegistryConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            max_services_per_peer: DEFAULT_MAX_SERVICES_PER_PEER,
            max_in_flight_per_peer: DEFAULT_MAX_IN_FLIGHT_PER_PEER,
            max_in_flight_total: DEFAULT_MAX_IN_FLIGHT_TOTAL,
            bucket_capacity: DEFAULT_BUCKET_CAPACITY,
            bucket_refill_per_sec: DEFAULT_BUCKET_REFILL_PER_SEC,
            rtt_ema_alpha: DEFAULT_RTT_EMA_ALPHA,
            max_label_len: DEFAULT_MAX_LABEL_LEN,
        }
    }
}

impl PeerRegistryConfig {
    pub(super) fn normalized(mut self) -> Self {
        if !self.bucket_capacity.is_finite() || self.bucket_capacity < 0.0 {
            self.bucket_capacity = 0.0;
        }
        if !self.bucket_refill_per_sec.is_finite() || self.bucket_refill_per_sec < 0.0 {
            self.bucket_refill_per_sec = 0.0;
        }
        if !self.rtt_ema_alpha.is_finite() {
            self.rtt_ema_alpha = DEFAULT_RTT_EMA_ALPHA;
        }
        self.rtt_ema_alpha = self.rtt_ema_alpha.clamp(0.0, 1.0);
        self
    }

    /// Combinations that would make the registry behave nonsensically.
    /// Distinct from [`Self::normalized`], which silently clamps NaN /
    /// negative inputs into sane defaults — `validate` rejects internally
    /// consistent but operationally broken combinations the caller must
    /// fix at the config layer.
    ///
    /// Returns the list of reasons the config is invalid (empty when ok),
    /// so [`PeerRegistry::with_config`] can surface every violation at
    /// once instead of forcing the operator to fix and re-run.
    pub fn validate(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.bucket_capacity > 0.0 && self.bucket_capacity < 1.0 {
            reasons.push(format!(
                "bucket_capacity {:.3} is in (0, 1): the bucket can never hold \
                 a full token, so every rate-limited request would be rejected \
                 with no path to recovery. Set bucket_capacity >= 1.0 (or 0.0 \
                 to reject everything explicitly).",
                self.bucket_capacity
            ));
        }
        if self.max_in_flight_per_peer == 0 {
            reasons.push("max_in_flight_per_peer is 0: no peer can ever be admitted.".into());
        }
        if self.max_in_flight_total == 0 {
            reasons
                .push("max_in_flight_total is 0: the registry can never admit a request.".into());
        }
        reasons
    }
}

/// Where a peer observation came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    Manual,
    StaticConfig,
    PeerExchange,
    Mdns,
    Dht,
    Transport(&'static str),
}

/// Pure input event for peer state.
#[derive(Clone, Debug, PartialEq)]
pub enum PeerEvent {
    Discovered {
        source: DiscoverySource,
        transport_security: TransportSecurity,
    },
    ServiceObserved {
        service: &'static str,
        transport_security: TransportSecurity,
    },
    RttSample {
        rtt_ms: f64,
    },
    LabelSet {
        label: String,
    },
    Forgotten,
}

/// Coarse change summary returned from registry mutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerChange {
    pub peer: PeerId,
    pub inserted: bool,
    pub updated: bool,
    pub removed: bool,
    pub evicted: Option<PeerId>,
    pub dropped: bool,
}

impl PeerChange {
    const fn updated(peer: PeerId) -> Self {
        Self {
            peer,
            inserted: false,
            updated: true,
            removed: false,
            evicted: None,
            dropped: false,
        }
    }

    const fn dropped(peer: PeerId) -> Self {
        Self {
            peer,
            inserted: false,
            updated: false,
            removed: false,
            evicted: None,
            dropped: true,
        }
    }
}

/// Result of recording that a discovered peer offers a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceObservation {
    pub peer: PeerId,
    pub peer_inserted: bool,
    pub service_inserted: bool,
    pub evicted: Option<PeerId>,
    pub dropped: bool,
}

/// Last-known state for a service on a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Observed,
    Healthy,
    Failed,
}

/// Per-service facts tracked by the registry.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceState {
    pub service: &'static str,
    pub status: ServiceStatus,
    pub last_seen_ms: u64,
    pub transport_security: TransportSecurity,
    pub success_count: u64,
}

impl ServiceState {
    fn observed(service: &'static str, now_ms: u64, transport_security: TransportSecurity) -> Self {
        Self {
            service,
            status: ServiceStatus::Observed,
            last_seen_ms: now_ms,
            transport_security,
            success_count: 0,
        }
    }

    fn observe(&mut self, now_ms: u64, transport_security: TransportSecurity) {
        self.last_seen_ms = now_ms;
        self.transport_security = self.transport_security.strongest(transport_security);
    }

    fn record_success(&mut self, now_ms: u64) {
        self.status = ServiceStatus::Healthy;
        self.last_seen_ms = now_ms;
        self.success_count = self.success_count.saturating_add(1);
    }

    fn record_error(&mut self, now_ms: u64) {
        self.status = ServiceStatus::Failed;
        self.last_seen_ms = now_ms;
    }
}

/// Per-peer facts and counters.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerEntry {
    pub id: PeerId,
    pub last_seen_ms: u64,
    pub transport_security: TransportSecurity,
    pub auth_level: AuthLevel,
    pub label: Option<String>,
    pub services: HashMap<&'static str, ServiceState>,
    pub rtt: EwmaLatency,
    pub success_count: u64,
    pub in_flight: usize,
    /// Set by `PeerEvent::Forgotten` when the peer still has outstanding
    /// permits. The entry is excluded from public queries (`get`, `iter`,
    /// `with_service`) but stays in the underlying map so the `release`
    /// path for the in-flight permits keeps decrementing counts correctly.
    /// The entry is removed for real once `in_flight` reaches zero.
    tombstoned: bool,
    bucket: TokenBucket,
}

impl PeerEntry {
    fn new(id: PeerId, now_ms: u64, bucket_capacity: f64, rtt_alpha: f64) -> Self {
        Self {
            id,
            last_seen_ms: now_ms,
            transport_security: TransportSecurity::Untrusted,
            auth_level: AuthLevel::Untrusted,
            label: None,
            services: HashMap::new(),
            rtt: EwmaLatency {
                alpha: rtt_alpha,
                est_ms: None,
            },
            success_count: 0,
            in_flight: 0,
            tombstoned: false,
            bucket: TokenBucket::new(now_ms, bucket_capacity),
        }
    }

    pub fn has_service(&self, service: &str) -> bool {
        self.services.contains_key(service)
    }

    pub fn has_service_key<S: RpcService>(&self) -> bool {
        self.has_service(S::NAME)
    }

    pub fn service_state(&self, service: &'static str) -> Option<&ServiceState> {
        self.services.get(service)
    }

    pub fn service<S: RpcService>(&self) -> Option<&ServiceState> {
        self.service_state(S::NAME)
    }

    pub fn latency_ms(&self) -> Option<f64> {
        self.rtt.get()
    }

    fn observe_transport(&mut self, transport_security: TransportSecurity) {
        self.transport_security = self.transport_security.strongest(transport_security);
        self.auth_level = AuthLevel::from_transport(self.transport_security);
    }

    /// Record a service observation. When the per-peer service cap is hit,
    /// evict the lowest-value service (fewest successes, oldest last_seen,
    /// then alphabetical name) to make room — silent drop-on-cap would
    /// silently lose per-service accounting for the *new* service every
    /// time, which is the wrong tradeoff. Returns `Some(evicted_name)` if
    /// an eviction occurred, `None` otherwise.
    fn observe_service(
        &mut self,
        service: &'static str,
        now_ms: u64,
        transport_security: TransportSecurity,
        max_services: usize,
    ) -> Option<&'static str> {
        if let Some(state) = self.services.get_mut(service) {
            state.observe(now_ms, transport_security);
            return None;
        }

        let max = max_services.max(1);
        let evicted = if self.services.len() >= max {
            let evict = self
                .services
                .values()
                .min_by_key(|s| (s.success_count, s.last_seen_ms, s.service))
                .map(|s| s.service);
            if let Some(name) = evict {
                self.services.remove(name);
                Some(name)
            } else {
                None
            }
        } else {
            None
        };

        self.services.insert(
            service,
            ServiceState::observed(service, now_ms, transport_security),
        );
        evicted
    }

    /// Order: transport security < #services < successes < last_seen
    /// < PeerId. The trailing `PeerId` is a stable tie-breaker so eviction
    /// stays deterministic even when every other key matches — HashMap
    /// iteration order is randomized and would otherwise leak into output.
    fn eviction_key(&self) -> (u8, usize, u64, u64, PeerId) {
        (
            self.transport_security.strength(),
            self.services.len(),
            self.success_count,
            self.last_seen_ms,
            self.id,
        )
    }
}

/// How `apply_inner` should treat a tombstoned peer when handling a
/// non-`Forgotten` event.
#[derive(Clone, Copy, Debug)]
enum TombstoneAction {
    /// Clear `tombstoned` — the event is fresh observed activity overriding
    /// the operator's earlier `forget`.
    Revive,
    /// Leave `tombstoned` alone — the event is a completion notification
    /// from an RPC that started before the forget; should record stats but
    /// not un-forget.
    Preserve,
}

/// Bounded, sans-io registry for peer facts and request admission.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerRegistry {
    config: PeerRegistryConfig,
    peers: HashMap<PeerId, PeerEntry>,
    total_in_flight: usize,
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::with_config(PeerRegistryConfig::default())
    }
}

impl PeerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PeerRegistryConfig) -> Self {
        let config = config.normalized();
        let reasons = config.validate();
        assert!(
            reasons.is_empty(),
            "PeerRegistryConfig is invalid:\n  - {}",
            reasons.join("\n  - "),
        );
        Self {
            config,
            peers: HashMap::with_capacity(config.max_peers.min(1024)),
            total_in_flight: 0,
        }
    }

    pub const fn config(&self) -> PeerRegistryConfig {
        self.config
    }

    /// Visible peer count — matches what `get`/`iter`/`with_service` would
    /// see. Tombstoned entries (still bookkeeping their in-flight permits)
    /// are excluded so an operator counting "how many peers do I know?"
    /// after a `forget_peer` doesn't see the leftover state.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    pub const fn total_in_flight(&self) -> usize {
        self.total_in_flight
    }

    pub fn get(&self, peer: PeerId) -> Option<&PeerEntry> {
        self.peers.get(&peer).filter(|e| !e.tombstoned)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PeerEntry> {
        self.peers.values().filter(|e| !e.tombstoned)
    }

    pub fn latency(&self, peer: PeerId) -> Option<f64> {
        self.get(peer).and_then(PeerEntry::latency_ms)
    }

    /// Record an inbound request from a peer. Ensures the peer is
    /// tracked, bumps `last_seen_ms`, and records
    /// any observed RTT into the EMA. No rate-limit decision is made
    /// here; admission-policy logic lives at the caller's middleware
    /// layer when it exists (today: only esp32 calls this directly,
    /// at connection-establishment time, before per-method dispatch).
    pub fn observe_inbound_request(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        rtt_ms: Option<f64>,
    ) -> Result<PeerChange, AcquireDenied> {
        let (inserted, evicted) =
            self.ensure_peer(now_ms, peer)
                .map_err(|_| AcquireDenied::PeerLimit {
                    peer,
                    max_peers: self.config.max_peers,
                })?;
        let Some(entry) = self.peers.get_mut(&peer) else {
            return Err(AcquireDenied::PeerLimit {
                peer,
                max_peers: self.config.max_peers,
            });
        };
        entry.last_seen_ms = now_ms;
        if let Some(rtt_ms) = rtt_ms {
            entry.rtt.record(rtt_ms);
        }
        Ok(PeerChange {
            peer,
            inserted,
            updated: !inserted,
            removed: false,
            evicted,
            dropped: false,
        })
    }

    pub fn observe_discovered_service(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> ServiceObservation {
        let service_was_known = self
            .get(peer)
            .is_some_and(|entry| entry.has_service(service));

        let discovery_change = self.apply(
            now_ms,
            peer,
            PeerEvent::Discovered {
                source,
                transport_security,
            },
        );
        if discovery_change.dropped {
            return ServiceObservation {
                peer,
                peer_inserted: false,
                service_inserted: false,
                evicted: discovery_change.evicted,
                dropped: true,
            };
        }

        let service_change = self.apply(
            now_ms,
            peer,
            PeerEvent::ServiceObserved {
                service,
                transport_security,
            },
        );

        ServiceObservation {
            peer,
            peer_inserted: discovery_change.inserted,
            service_inserted: !service_was_known && !service_change.dropped,
            evicted: discovery_change.evicted.or(service_change.evicted),
            dropped: service_change.dropped,
        }
    }

    pub fn apply(&mut self, now_ms: u64, peer: PeerId, event: PeerEvent) -> PeerChange {
        self.apply_inner(now_ms, peer, event, TombstoneAction::Revive)
    }

    /// Apply a completion-side observation (a successful or failed RPC) to
    /// the registry *without* reviving a tombstoned peer. The
    /// `RpcPermitGuard` finishers call this so that an in-flight RPC
    /// completing after `forget_peer` still credits stats correctly but
    /// doesn't undo the operator's forget — otherwise the subsequent
    /// `release` would no longer purge the entry.
    pub fn apply_completion(&mut self, now_ms: u64, peer: PeerId, event: PeerEvent) -> PeerChange {
        self.apply_inner(now_ms, peer, event, TombstoneAction::Preserve)
    }

    fn apply_inner(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        event: PeerEvent,
        tombstone: TombstoneAction,
    ) -> PeerChange {
        if matches!(event, PeerEvent::Forgotten) {
            // Defer removal while permits are still in flight so the release
            // path doesn't try to decrement counts on a missing entry. The
            // peer is excluded from `get`/`iter`/`with_service` immediately
            // (tombstoned), and the final `release` that drops in_flight to
            // zero purges the entry for real.
            let removed = match self.peers.get_mut(&peer) {
                Some(entry) if entry.in_flight == 0 => {
                    self.peers.remove(&peer);
                    true
                }
                Some(entry) => {
                    entry.tombstoned = true;
                    true
                }
                None => false,
            };
            return PeerChange {
                peer,
                inserted: false,
                updated: false,
                removed,
                evicted: None,
                dropped: false,
            };
        }

        let Ok((inserted, evicted)) = self.ensure_peer(now_ms, peer) else {
            return PeerChange::dropped(peer);
        };

        let max_services = self.config.max_services_per_peer;
        let max_label_len = self.config.max_label_len;
        let Some(entry) = self.peers.get_mut(&peer) else {
            return PeerChange::dropped(peer);
        };

        // Apply-side events revive a tombstoned peer (fresh observation
        // overrides operator's forget); completion-side events preserve the
        // tombstone so the subsequent release still purges the entry.
        if matches!(tombstone, TombstoneAction::Revive) {
            entry.tombstoned = false;
        }
        entry.last_seen_ms = now_ms;

        match event {
            PeerEvent::Discovered {
                transport_security, ..
            } => {
                entry.observe_transport(transport_security);
            }
            PeerEvent::ServiceObserved {
                service,
                transport_security,
            } => {
                entry.observe_transport(transport_security);
                let _ = entry.observe_service(service, now_ms, transport_security, max_services);
            }
            PeerEvent::RttSample { rtt_ms } => {
                entry.rtt.record(rtt_ms);
            }
            PeerEvent::LabelSet { label } => {
                entry.label = Some(truncate_string(label, max_label_len));
            }
            PeerEvent::Forgotten => unreachable!("forgotten events are handled before insert"),
        }

        PeerChange {
            peer,
            inserted,
            updated: !inserted,
            removed: false,
            evicted,
            dropped: false,
        }
    }

    pub fn try_acquire(
        &mut self,
        now_ms: u64,
        peer: PeerId,
        kind: RequestKind,
    ) -> Result<Permit, AcquireDenied> {
        if self.total_in_flight >= self.config.max_in_flight_total {
            return Err(AcquireDenied::InFlightTotal {
                limit: self.config.max_in_flight_total,
            });
        }

        self.ensure_peer(now_ms, peer)
            .map_err(|_| AcquireDenied::PeerLimit {
                peer,
                max_peers: self.config.max_peers,
            })?;

        let Some(entry) = self.peers.get_mut(&peer) else {
            return Err(AcquireDenied::PeerLimit {
                peer,
                max_peers: self.config.max_peers,
            });
        };

        if entry.in_flight >= self.config.max_in_flight_per_peer {
            return Err(AcquireDenied::InFlightPeer {
                peer,
                limit: self.config.max_in_flight_per_peer,
            });
        }

        if let Err(retry_after_ms) = entry.bucket.try_take(
            now_ms,
            self.config.bucket_capacity,
            self.config.bucket_refill_per_sec,
        ) {
            return Err(AcquireDenied::RateLimited {
                peer,
                retry_after_ms,
            });
        }

        entry.in_flight += 1;
        entry.last_seen_ms = now_ms;
        self.total_in_flight += 1;

        Ok(Permit::new(peer, kind))
    }

    pub fn release(&mut self, now_ms: u64, mut permit: Permit, outcome: Outcome) -> PeerChange {
        permit.disarm();
        self.total_in_flight = self.total_in_flight.saturating_sub(1);

        let peer = permit.peer();
        let max_services = self.config.max_services_per_peer;

        let Some(entry) = self.peers.get_mut(&peer) else {
            return PeerChange::dropped(peer);
        };

        entry.in_flight = entry.in_flight.saturating_sub(1);
        entry.last_seen_ms = now_ms;

        match outcome {
            Outcome::Ok { rtt_ms } => {
                entry.success_count = entry.success_count.saturating_add(1);
                entry.rtt.record(rtt_ms);
                let _ = entry.observe_service(
                    permit.kind().service,
                    now_ms,
                    entry.transport_security,
                    max_services,
                );
                if let Some(service) = entry.services.get_mut(permit.kind().service) {
                    service.record_success(now_ms);
                }
            }
            Outcome::Err { rtt_ms, .. } => {
                if let Some(rtt_ms) = rtt_ms {
                    entry.rtt.record(rtt_ms);
                }
                if let Some(service) = entry.services.get_mut(permit.kind().service) {
                    service.record_error(now_ms);
                }
            }
            Outcome::Cancelled => {}
        }

        // Final-release purge for tombstoned peers: once the last in-flight
        // permit clears, the entry is gone.
        if entry.tombstoned && entry.in_flight == 0 {
            self.peers.remove(&peer);
            return PeerChange {
                peer,
                inserted: false,
                updated: false,
                removed: true,
                evicted: None,
                dropped: false,
            };
        }

        PeerChange::updated(peer)
    }

    fn ensure_peer(&mut self, now_ms: u64, peer: PeerId) -> Result<(bool, Option<PeerId>), ()> {
        if self.peers.contains_key(&peer) {
            return Ok((false, None));
        }

        if self.config.max_peers == 0 {
            return Err(());
        }

        let evicted = if self.peers.len() >= self.config.max_peers {
            let Some(evicted) = self.eviction_candidate() else {
                return Err(());
            };
            self.peers.remove(&evicted);
            Some(evicted)
        } else {
            None
        };

        self.peers.insert(
            peer,
            PeerEntry::new(
                peer,
                now_ms,
                self.config.bucket_capacity,
                self.config.rtt_ema_alpha,
            ),
        );
        Ok((true, evicted))
    }

    fn eviction_candidate(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.in_flight == 0)
            .min_by_key(|(_, peer)| peer.eviction_key())
            .map(|(id, _)| *id)
    }
}

fn truncate_string(mut value: String, max_len: usize) -> String {
    if value.len() <= max_len {
        return value;
    }

    value.truncate(max_len);
    while !value.is_char_boundary(value.len()) {
        value.pop();
    }
    value
}

#[cfg(test)]
mod tests;
