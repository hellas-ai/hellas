//! Server-side middleware over generated `Dispatcher` impls.
//!
//! The codegen-emitted `XServer<H>: Dispatcher<T>` types are intentionally
//! transport-agnostic and accounting-agnostic — they own only the
//! method-id match + the user's handler. Cross-cutting concerns
//! (per-peer accounting, admission policy, tracing, OTel) belong in
//! middleware wrappers around them, not in the codegen output.
//!
//! [`AccountingDispatcher`] records inbound requests and refreshes
//! `last_seen_ms` in the shared peer registry.

use hellas_wire::Dispatcher;
use hellas_wire::transport::{Inbound, StreamTransport};

use crate::peers::{PeerId, PeerManager};

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
