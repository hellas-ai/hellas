//! Server-side middleware over generated `Dispatcher` impls.
//!
//! The codegen-emitted `XServer<H>: Dispatcher<T>` types are intentionally
//! transport-agnostic and accounting-agnostic — they own only the
//! method-id match + the user's handler. Cross-cutting concerns
//! (per-peer accounting, admission policy, tracing, OTel) belong in
//! middleware wrappers around them, not in the codegen output.
//!
//! [`AccountingDispatcher`] is the first such wrapper: every inbound
//! that carries a peer identity bumps the corresponding `PeerManager`
//! record. That's the producer side of the data flow that
//! `PeerDirectory::ranked_known_peers` consumes when emitting
//! `Node::get_known_peers` responses — without this middleware, that
//! consumer is forever surfacing an empty directory.

use std::marker::PhantomData;

use hellas_wire::transport::{Inbound, StreamTransport};
use hellas_wire::{Dispatcher, MethodMarker};

use crate::peers::{PeerId, PeerManager};

/// Administrative grants are distinct from transport authentication and
/// execution permissions. Empty/default policy denies every caller.
#[derive(Clone, Default)]
pub struct AdminPolicy {
    pub local_owner: bool,
    pub peers: Vec<hellas_wire::PeerIdentity>,
}

impl AdminPolicy {
    pub fn allows(&self, context: &hellas_wire::TransportContext) -> bool {
        (self.local_owner && context.auth_level == hellas_wire::AuthLevel::LocalOwner)
            || context
                .vouched_peer()
                .is_some_and(|peer| self.peers.contains(&peer))
    }
}

/// Apply the same authorization before dispatch on every carrier. The policy
/// consumes live transport evidence, never caller-supplied headers or peer
/// registry observations from a different connection.
pub struct Authorized<S> {
    pub service: S,
    pub policy: AdminPolicy,
}

impl<T, S> Dispatcher<T> for Authorized<S>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T, Error = hellas_wire::TransportError> + Send + Sync,
{
    type Error = hellas_wire::TransportError;

    async fn dispatch(&self, inbound: Inbound<T::Stream>) -> Result<(), Self::Error> {
        if !self.policy.allows(&inbound.context) {
            use hellas_wire::{SendHalf, Stream, WireCode, WireStatus};
            let (mut send, _recv) = inbound.stream.split();
            return send
                .close_send(Some(
                    WireStatus::new(
                        WireCode::PermissionDenied,
                        "administrative access is not granted",
                    )
                    .into(),
                ))
                .await
                .map_err(|e| hellas_wire::TransportError::Io(e.to_string()));
        }
        self.service.dispatch(inbound).await
    }
}

/// Routes one method to `selected` and every other method to `fallback`.
///
/// This lets one connection-bound service carry a method whose protobuf
/// service marker is different without opening a second transport. In
/// particular, confidential Open, quote, and RunTicket can remain on the
/// exact same QUIC connection and exporter binding.
pub struct MethodDispatcher<S, F, M> {
    selected: S,
    fallback: F,
    marker: PhantomData<fn() -> M>,
}

impl<S, F, M> MethodDispatcher<S, F, M> {
    pub fn new(selected: S, fallback: F) -> Self {
        Self {
            selected,
            fallback,
            marker: PhantomData,
        }
    }
}

impl<T, S, F, M> Dispatcher<T> for MethodDispatcher<S, F, M>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T> + Send + Sync,
    F: Dispatcher<T, Error = S::Error> + Send + Sync,
    M: MethodMarker + Send + Sync,
{
    type Error = S::Error;

    async fn dispatch(&self, inbound: Inbound<T::Stream>) -> Result<(), Self::Error> {
        if inbound.method_id == M::METHOD_ID {
            self.selected.dispatch(inbound).await
        } else {
            self.fallback.dispatch(inbound).await
        }
    }
}

/// Wraps any `Dispatcher<T>` and records each inbound on a
/// `PeerManager` before forwarding to the inner dispatch.
///
/// The accounting call is fire-and-forget — its result is discarded.
/// Failure modes (peer-table full, etc.) do not block dispatch; the
/// peer is still served, the operator just won't see its counters
/// bumped. That trade-off matches the policy split: this middleware
/// is observability, not admission. An admission-policy middleware
/// (rate-limit / authz) would be a separate wrapper composed on top
/// of this one.
pub struct AccountingDispatcher<S> {
    inner: S,
    manager: PeerManager,
}

impl<S> AccountingDispatcher<S> {
    pub fn new(inner: S, manager: PeerManager) -> Self {
        Self { inner, manager }
    }
}

impl<T, S> Dispatcher<T> for AccountingDispatcher<S>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    S: Dispatcher<T> + Send + Sync,
{
    type Error = S::Error;

    async fn dispatch(&self, inbound: Inbound<T::Stream>) -> Result<(), Self::Error> {
        if let Some(peer) = inbound.context.peer {
            // Best-effort; ignore the PeerChange + any Err. Admission
            // policy lives in a separate middleware when needed.
            let _ = self
                .manager
                .observe_inbound_request(PeerId::from_bytes(peer.0), inbound.context.rtt_ms);
        }
        self.inner.dispatch(inbound).await
    }
}
