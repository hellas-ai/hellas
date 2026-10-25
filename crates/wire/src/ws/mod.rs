//! WebSocket transports — share the sans-io `mux` state machine and
//! differ only in their I/O glue.
//!
//! - `native` (feature `ws`): tokio-tungstenite adapter for native hosts.
//! - `wasm` (feature `ws-wasm`): ws_stream_wasm adapter for browsers.

#[cfg(all(feature = "ws", not(target_family = "wasm")))]
pub mod native;

#[cfg(all(feature = "ws", not(target_family = "wasm")))]
pub use native::{WsError, WsPipe, accept_upgraded, connect, connect_server, websocket_config};

#[cfg(all(feature = "ws-wasm", target_family = "wasm"))]
pub mod wasm;

/// WebSocket transport handle. Just a `MuxTransport`; the WS-specific
/// adapter feeds the mux's I/O driver via the [`crate::mux::MessagePipe`]
/// trait. Created via [`native::connect`], [`native::connect_server`], or
/// [`native::accept_upgraded`].
#[cfg(all(feature = "mux", not(target_family = "wasm")))]
pub type WsTransport = crate::mux::MuxTransport;
