//! Transport-trait surface.
//!
//! `StreamTransport` is the per-connection abstraction (open new
//! streams, accept inbound). `Stream` / `SendHalf` / `RecvHalf` are the
//! per-RPC view.

use std::future::Future;

use bytes::Bytes;
use futures_core::Stream as FuturesStream;

use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

/// Peer identity as the canonical 32-byte form. Transports that have a
/// real identity (iroh `EndpointId`, mTLS-bound 32-byte key, handshake-
/// agreed cookie) populate this. Transports that don't (browser WS,
/// CF DO inbound before challenge) leave it `None`.
///
/// Byte-shaped, not string-shaped, so consumers — the
/// `AccountingDispatcher` in particular — can construct a
/// `hellas_rpc::peers::PeerId` directly without a hex round-trip.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerIdentity(pub [u8; 32]);

impl std::fmt::Display for PeerIdentity {
    /// Short hex (8 chars … 8 chars), matching `hellas_rpc::peers::PeerId`'s
    /// log format. Use `{:#}` for the full 64-char form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            for b in &self.0 {
                write!(f, "{b:02x}")?;
            }
            return Ok(());
        }
        for b in &self.0[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")?;
        for b in &self.0[28..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// What kind of authentication the transport itself vouches for. Apps
/// layer their own auth on top via metadata.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthLevel {
    /// Transport offers no identity (browser WS).
    #[default]
    None,
    /// Transport-vouched identity (iroh NodeId, mTLS subject).
    Vouched,
    /// The carrier checked that the caller is this process's OS owner.
    /// Never set from RPC metadata, discovery, or a claimed remote identity.
    LocalOwner,
}

/// Transport-provided context for an inbound stream.
#[derive(Clone, Default)]
pub struct TransportContext {
    pub peer: Option<PeerIdentity>,
    pub rtt_ms: Option<f64>,
    pub auth_level: AuthLevel,
    /// TLS exporter derived from the live connection for the confidential
    /// open handshake. Transports without a TLS/QUIC exporter leave it absent.
    pub open_exporter: Option<[u8; 32]>,
}

impl std::fmt::Debug for TransportContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportContext")
            .field("peer", &self.peer)
            .field("rtt_ms", &self.rtt_ms)
            .field("auth_level", &self.auth_level)
            .field("open_exporter", &self.open_exporter.map(|_| "<redacted>"))
            .finish()
    }
}

impl TransportContext {
    /// Returns the peer identity only when the transport vouches for it.
    ///
    /// A populated peer field is not by itself an authenticated identity:
    /// transports may carry a claimed or otherwise untrusted peer while
    /// leaving [`Self::auth_level`] at [`AuthLevel::None`]. Connection-bound
    /// routing must use this pair as one fact and fail closed on either half.
    #[must_use]
    pub const fn vouched_peer(&self) -> Option<PeerIdentity> {
        match (self.auth_level, self.peer) {
            (AuthLevel::Vouched, Some(peer)) => Some(peer),
            _ => None,
        }
    }
}

pub struct Inbound<S> {
    pub method_id: u32,
    pub headers: Metadata,
    pub stream: S,
    pub context: TransportContext,
}

/// Per-connection transport abstraction.
pub trait StreamTransport {
    type Stream: Stream;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Connection-level context available to outbound callers. Inbound calls
    /// receive the same values on [`Inbound::context`].
    fn context(&self) -> TransportContext {
        TransportContext::default()
    }

    /// Open a new outbound stream for this method. Headers go on the
    /// `OpenFrame`; body follows via `SendHalf::send_body`.
    fn open(
        &self,
        method_id: u32,
        headers: Metadata,
    ) -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;

    /// Accept the next inbound stream. Returns `None` when the
    /// transport is closed.
    fn accept(
        &self,
    ) -> impl Future<Output = Result<Option<Inbound<Self::Stream>>, Self::Error>> + Send;
}

/// Per-RPC bidi handle. Split into send/recv halves for concurrent use.
pub trait Stream: Send {
    type SendError: std::error::Error + Send + Sync + 'static;
    type RecvError: std::error::Error + Send + Sync + 'static;

    type SendHalf: SendHalf<Error = Self::SendError>;
    type RecvHalf: RecvHalf<Error = Self::RecvError>;

    /// Consume into independent halves. Both halves carry a shared
    /// reset capability (see `SendHalf::reset` / `RecvHalf::reset`).
    fn split(self) -> (Self::SendHalf, Self::RecvHalf);

    /// Cancel both directions. Idempotent.
    fn reset(&mut self, code: WireCode);
}

/// Send half. `Sink<Bytes>` ergonomics; single-frame internal buffer so
/// callers manage their own outbound queue if they want to coalesce.
pub trait SendHalf: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Send a body chunk. Resolves when the chunk has been handed off
    /// to the transport (not necessarily flushed to the wire).
    fn send_body(&mut self, payload: Bytes)
    -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Close the send direction, optionally with a trailer.
    fn close_send(
        &mut self,
        trailer: Option<Trailer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Cancel both directions of the underlying stream. Idempotent.
    fn reset(&mut self, code: WireCode);
}

/// Recv half. Yields body chunks; trailer is available after the
/// stream terminates.
///
/// `Unpin` is required so consumers can hold a `&mut RecvHalf` and
/// poll it without manual projection. In practice every impl in this
/// workspace is structurally Unpin (no self-referential fields); the
/// bound makes that explicit at the trait level.
pub trait RecvHalf:
    FuturesStream<Item = Result<Bytes, <Self as RecvHalf>::Error>> + Send + Unpin
{
    type Error: std::error::Error + Send + Sync + 'static;

    /// Available after `next()` has returned `None`. Carries the
    /// terminal status (Ok / reset code / etc.).
    fn trailer(&self) -> Option<&Trailer>;

    /// Cancel both directions of the underlying stream. Idempotent.
    fn reset(&mut self, code: WireCode);
}

// -- Codegen marker traits ---------------------------------------------------
//
// The `hellas-rpc` build script emits one marker type per proto service and
// one per proto method. The markers carry compile-time identity (name, id,
// streaming flags, request/response types) so call sites never spell wire
// names as strings.

/// Compile-time identity of a proto service. The build script emits one
/// implementor per `service` block.
pub trait ServiceMarker {
    /// Fully-qualified service name (`package.Service`).
    const NAME: &'static str;
    /// Wire ALPN derived from `NAME` (e.g. `/hellas.swarm.v1.Node/2.0`).
    const ALPN: &'static str;
    /// Truncated 32-bit service id (Xet hash of schema, low 4 bytes LE).
    const SERVICE_ID: u32;
}

/// Compile-time identity of a proto rpc method. The build script emits one
/// implementor per `rpc` line.
pub trait MethodMarker {
    type Service: ServiceMarker;
    /// Wire-decodable request type (prost message).
    type Request;
    /// Wire-decodable response type (prost message).
    type Response;

    /// Method name as it appears in the `.proto` (e.g. `"GetNodeInfo"`).
    const NAME: &'static str;
    /// Truncated 32-bit method id (Xet hash of `MethodSchema`, low 4 bytes LE).
    const METHOD_ID: u32;
    /// True for `stream Foo` requests.
    const REQUEST_STREAMING: bool;
    /// True for `stream Foo` responses.
    const RESPONSE_STREAMING: bool;
}

/// Server-side dispatch entry point. Concrete implementors (the
/// `<Service>Server<H>` types emitted by codegen) match on `method_id` and
/// route to the relevant handler.
///
/// The shape here is intentionally minimal — the v2 wire layer is still
/// settling. Once handler ergonomics stabilize, this trait will gain
/// proper request/response stream types. For now it exists so the codegen
/// has a stable hook to implement.
pub trait Dispatcher<T: StreamTransport> {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Dispatch a single inbound stream to the matching method handler.
    /// `method_id` selects the handler; `inbound` carries headers and the
    /// raw byte stream.
    fn dispatch(
        &self,
        inbound: Inbound<T::Stream>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
