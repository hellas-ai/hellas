//! Sans-io peer registry and admission policy primitives.
//!
//! This module is the pure state engine for peer facts. It intentionally has no
//! transport, runtime, clock, or storage dependencies. Callers pass timestamps
//! and observations in, and the registry returns deterministic state changes and
//! admission decisions.
//!
//! Most application code should use [`PeerManager`] instead of calling
//! [`PeerRegistry::apply`] directly. The intended layering is:
//!
//! - a transport/discovery driver owns discovery streams and records facts here
//!   before notifying application code;
//! - generated or hand-written RPC clients acquire/release request permits here
//!   around actual RPC calls;
//! - RPC servers record inbound calls with `observe_inbound_request` for
//!   accounting and admission, but do not infer service capabilities from those
//!   calls;
//! - application code queries the current registry view, usually through a
//!   manager snapshot/view API, rather than hand-feeding events.
//!
//! In other words, the registry is the source of truth, not the discovery task
//! and not an event stream. Events are useful for notification, but polling
//! events should never be required to keep peer state correct.

mod admission;
mod directory;
mod id;
mod manager;
mod registry;
mod security;

pub use admission::{AcquireDenied, RequestKind, TokenBucket};
pub use directory::{PeerDirectory, PeerDirectoryConfig, ServiceAlias};
pub use id::PeerId;
pub use manager::{
    PeerManager, PeerManagerError, PeerServiceSession, PeerSession, RpcObservation, RpcPermitGuard,
};
pub use registry::{
    DiscoverySource, PeerChange, PeerEntry, PeerEvent, PeerRegistry, PeerRegistryConfig,
    ServiceObservation, ServiceState, ServiceStatus,
};
pub use security::{AuthLevel, TransportSecurity};

// The codegen-emitted service and method markers implement
// `hellas_wire::ServiceMarker` and `MethodMarker` directly. The peer
// registry consumes those traits — no separate `RpcService` /
// `RpcMethod` here.
pub use hellas_wire::{MethodMarker as RpcMethod, ServiceMarker as RpcService};

/// Fake service/method markers for tests, standing in for the codegen
/// markers the peer engine consumes at runtime. Kept here so the three
/// test modules share one definition instead of each re-declaring it.
#[cfg(test)]
pub(crate) mod test_markers {
    use hellas_wire::{MethodMarker, ServiceMarker};

    pub struct TestService;
    impl ServiceMarker for TestService {
        const NAME: &'static str = "hellas.swarm.v1.Node";
        const ALPN: &'static str = "/hellas.swarm.v1.Node/2.0";
        const SERVICE_ID: u32 = 1;
    }

    pub struct GetNodeInfo;
    impl MethodMarker for GetNodeInfo {
        type Service = TestService;
        type Request = ();
        type Response = ();
        const NAME: &'static str = "GetNodeInfo";
        const METHOD_ID: u32 = 1;
        const REQUEST_STREAMING: bool = false;
        const RESPONSE_STREAMING: bool = false;
    }
}
