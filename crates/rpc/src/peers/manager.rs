use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use web_time::Instant;

use thiserror::Error;

use super::admission::{Outcome, Permit, RequestKind};
use super::{
    AcquireDenied, DiscoverySource, PeerChange, PeerEvent, PeerId, PeerRegistry,
    PeerRegistryConfig, RpcMethod, RpcService, ServiceObservation, TransportSecurity,
};

/// Shared peer-state owner for application code.
///
/// `PeerRegistry` stays the deterministic sans-io state machine. `PeerManager`
/// is the small ergonomic wrapper used by clients, servers, and discovery
/// drivers that want shared state, monotonic timestamps, and Drop-based
/// request release.
///
/// Timestamps are milliseconds since the manager was constructed — not wall
/// clock. This means age and latency arithmetic is immune to NTP/manual clock
/// changes. Absolute calendar timestamps must be carried in caller-owned
/// fields, not derived from `PeerEntry::{first_seen_ms, last_seen_ms}`.
#[derive(Clone, Debug)]
pub struct PeerManager {
    registry: Arc<Mutex<PeerRegistry>>,
    base: Instant,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        Self::with_config(PeerRegistryConfig::default())
    }

    pub fn with_config(config: PeerRegistryConfig) -> Self {
        Self {
            registry: Arc::new(Mutex::new(PeerRegistry::with_config(config))),
            base: Instant::now(),
        }
    }

    /// Milliseconds since this manager was constructed.
    ///
    /// Monotonic: never goes backward, never jumps forward across NTP / DST /
    /// manual clock changes. All timestamps stored in `PeerEntry` and used
    /// for admission/EMA/eviction are produced by this method.
    pub fn now_ms(&self) -> u64 {
        u64::try_from(Instant::now().duration_since(self.base).as_millis()).unwrap_or(u64::MAX)
    }

    pub fn snapshot(&self) -> Result<PeerRegistry, PeerManagerError> {
        Ok(self.lock()?.clone())
    }

    pub fn with_registry<R>(
        &self,
        read: impl FnOnce(&PeerRegistry) -> R,
    ) -> Result<R, PeerManagerError> {
        let registry = self.lock()?;
        Ok(read(&registry))
    }

    /// Mutable registry access for tests that need explicit observation times,
    /// e.g. to exercise exact disclosure freshness boundaries. Production code
    /// uses the clock wrappers so timestamps share one monotonic source.
    #[cfg(test)]
    pub(crate) fn with_registry_mut<R>(
        &self,
        write: impl FnOnce(&mut PeerRegistry) -> R,
    ) -> Result<R, PeerManagerError> {
        let mut registry = self.lock()?;
        Ok(write(&mut registry))
    }

    pub fn peer(&self, peer: PeerId) -> PeerSession {
        PeerSession {
            manager: self.clone(),
            peer,
        }
    }

    pub fn service_session<S: RpcService>(&self, peer: PeerId) -> PeerServiceSession<S> {
        self.peer(peer).service::<S>()
    }

    fn apply(&self, peer: PeerId, event: PeerEvent) -> Result<PeerChange, PeerManagerError> {
        let now = self.now_ms();
        Ok(self.lock()?.apply(now, peer, event))
    }

    pub fn observe_discovered_peer(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<PeerChange, PeerManagerError> {
        self.apply(
            peer,
            PeerEvent::Discovered {
                source,
                transport_security,
            },
        )
    }

    pub fn observe_discovered_service_name(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        service: &'static str,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        let now = self.now_ms();
        Ok(self
            .lock()?
            .observe_discovered_service(now, peer, source, service, transport_security))
    }

    pub fn observe_discovered_service<S: RpcService>(
        &self,
        peer: PeerId,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.observe_discovered_service_name(peer, source, S::NAME, transport_security)
    }

    /// Record that a peer just made an inbound request. Bumps the
    /// per-peer `total_requests` + `last_seen_ms` + RTT EMA; ensures
    /// the peer exists in the registry. No rate-limit policy lives
    /// here — callers that need to reject abusive peers wrap their
    /// dispatch in middleware that consults their own bucket. Handler
    /// methods receive decoded request bodies, so transport identity is
    /// accounted before dispatch.
    pub fn observe_inbound_request(
        &self,
        peer: PeerId,
        rtt_ms: Option<f64>,
    ) -> Result<PeerChange, PeerManagerError> {
        let now = self.now_ms();
        Ok(self.lock()?.observe_inbound_request(now, peer, rtt_ms)?)
    }

    pub fn forget_peer(&self, peer: PeerId) -> Result<PeerChange, PeerManagerError> {
        self.apply(peer, PeerEvent::Forgotten)
    }

    pub fn set_peer_label(
        &self,
        peer: PeerId,
        label: impl Into<String>,
    ) -> Result<PeerChange, PeerManagerError> {
        self.apply(
            peer,
            PeerEvent::LabelSet {
                label: label.into(),
            },
        )
    }

    pub fn acquire_rpc(
        &self,
        peer: PeerId,
        kind: RequestKind,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        let now = self.now_ms();
        let mut registry = self.lock()?;
        registry.apply(
            now,
            peer,
            PeerEvent::Discovered {
                source: observation.source,
                transport_security: observation.initial_security,
            },
        );
        let permit = registry.try_acquire(now, peer, kind)?;
        drop(registry);

        Ok(RpcPermitGuard {
            manager: self.clone(),
            permit: Some(permit),
            started: Instant::now(),
            observation,
        })
    }

    pub fn acquire_method<M: RpcMethod>(
        &self,
        peer: PeerId,
        observation: RpcObservation,
    ) -> Result<RpcPermitGuard, PeerManagerError> {
        self.acquire_rpc(peer, RequestKind::for_method::<M>(), observation)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, PeerRegistry>, PeerManagerError> {
        self.registry
            .lock()
            .map_err(|_| PeerManagerError::Unavailable)
    }
}

/// Logical session view for one remote peer.
///
/// This is not a transport connection handle. It is a typed view over shared
/// peer facts. A transport may have zero, one, or many physical links for the
/// peer while all observations still converge here.
#[derive(Clone, Debug)]
pub struct PeerSession {
    manager: PeerManager,
    peer: PeerId,
}

impl PeerSession {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub fn observe_discovered(
        &self,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<PeerChange, PeerManagerError> {
        self.manager
            .observe_discovered_peer(self.peer, source, transport_security)
    }

    pub fn forget(&self) -> Result<PeerChange, PeerManagerError> {
        self.manager.forget_peer(self.peer)
    }

    pub fn set_label(&self, label: impl Into<String>) -> Result<PeerChange, PeerManagerError> {
        self.manager.set_peer_label(self.peer, label)
    }

    pub fn service<S: RpcService>(&self) -> PeerServiceSession<S> {
        PeerServiceSession {
            manager: self.manager.clone(),
            peer: self.peer,
            _service: PhantomData,
        }
    }
}

/// Logical session view for one `(peer, service)` pair.
///
/// This is the API shape application and generated client code should prefer.
/// It keeps service capability explicit while preserving the global peer state
/// underneath.
#[derive(Clone, Debug)]
pub struct PeerServiceSession<S: RpcService> {
    manager: PeerManager,
    peer: PeerId,
    _service: PhantomData<fn() -> S>,
}

impl<S: RpcService> PeerServiceSession<S> {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub fn observe_discovered(
        &self,
        source: DiscoverySource,
        transport_security: TransportSecurity,
    ) -> Result<ServiceObservation, PeerManagerError> {
        self.manager
            .observe_discovered_service::<S>(self.peer, source, transport_security)
    }
}

/// How an outbound RPC should update peer facts around transport security.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcObservation {
    pub source: DiscoverySource,
    pub initial_security: TransportSecurity,
    pub completion_security: TransportSecurity,
}

impl RpcObservation {
    pub const fn new(
        source: DiscoverySource,
        initial_security: TransportSecurity,
        completion_security: TransportSecurity,
    ) -> Self {
        Self {
            source,
            initial_security,
            completion_security,
        }
    }

    /// A transport that proves peer identity only after the channel/RPC has
    /// completed far enough to bind bytes to the remote peer.
    pub const fn authenticated_transport(name: &'static str) -> Self {
        Self::new(
            DiscoverySource::Transport(name),
            TransportSecurity::Untrusted,
            TransportSecurity::Authenticated,
        )
    }

    pub const fn untrusted_transport(name: &'static str) -> Self {
        Self::new(
            DiscoverySource::Transport(name),
            TransportSecurity::Untrusted,
            TransportSecurity::Untrusted,
        )
    }
}

/// RAII request permit returned by [`PeerManager::acquire_rpc`].
///
/// Dropping the guard records a cancellation and releases the in-flight slot.
/// Call `finish_ok`, `finish_err`, or `finish_connect_err` exactly once when the
/// request reaches a terminal state.
#[derive(Debug)]
pub struct RpcPermitGuard {
    manager: PeerManager,
    permit: Option<Permit>,
    started: Instant,
    observation: RpcObservation,
}

impl RpcPermitGuard {
    pub fn finish_ok(&mut self) {
        self.observe_completed_service();
        self.release(Outcome::ok(duration_ms(self.started.elapsed())));
    }

    pub fn finish_err(&mut self, error: impl Into<String>) {
        self.observe_completed_service();
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error: error.into(),
        });
    }

    /// Record failure before the transport established a peer-authenticated RPC.
    pub fn finish_connect_err(&mut self, error: impl Into<String>) {
        self.release(Outcome::Err {
            rtt_ms: Some(duration_ms(self.started.elapsed())),
            error: error.into(),
        });
    }

    fn observe_completed_service(&self) {
        let Some(permit) = self.permit.as_ref() else {
            return;
        };
        let now = self.manager.now_ms();
        let Ok(mut registry) = self.manager.lock() else {
            return;
        };
        // Completion notifications go via `apply_completion` so a peer
        // forgotten mid-RPC stays tombstoned — the subsequent `release`
        // must be free to purge the entry. Plain `apply` would revive.
        registry.apply_completion(
            now,
            permit.peer(),
            PeerEvent::Discovered {
                source: self.observation.source,
                transport_security: self.observation.completion_security,
            },
        );
        registry.apply_completion(
            now,
            permit.peer(),
            PeerEvent::ServiceObserved {
                service: permit.kind().service,
                transport_security: self.observation.completion_security,
            },
        );
    }

    fn release(&mut self, outcome: Outcome) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let now = self.manager.now_ms();
        if let Ok(mut registry) = self.manager.lock() {
            registry.release(now, permit, outcome);
        }
    }
}

impl Drop for RpcPermitGuard {
    fn drop(&mut self) {
        self.release(Outcome::Cancelled);
    }
}

#[derive(Debug, Error)]
pub enum PeerManagerError {
    #[error("peer registry is unavailable")]
    Unavailable,
    #[error(transparent)]
    Admission(#[from] AcquireDenied),
}

pub(super) fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests;
