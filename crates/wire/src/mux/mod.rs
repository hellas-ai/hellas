//! Sans-io multiplexer state machine.
//!
//! One `Multiplexer<N, C>` per underlying byte pipe. Slot index doubles
//! as stream id. Per-slot `gen: u16` defeats stale-frame races across
//! re-use. Credit-based per-stream flow control. Single pending wire
//! write so applications drive their own outbound queues.
//!
//! `recv(bytes) -> Vec<Event>` and `poll_send() -> Option<EncodedFrame>`
//! are the entire I/O-shaped surface; transports glue them to actual
//! sockets.

pub(crate) mod slot;
mod state;
mod wire;

pub mod stream;
pub mod transport;

pub use slot::{Role, SlotIndex, SlotState, StreamSlot};
pub use state::{Event, Multiplexer, MuxConfig, MuxError, SendBodyOutcome};
pub use stream::{MuxRecvHalf, MuxSendHalf, MuxStream, MuxStreamError};
pub use transport::{MessagePipe, MuxTransport, MuxTransportError};
pub use wire::{
    KeyedFrame, MAX_KEYED_FRAME_BYTES, StreamKey, decode_keyed_frame, encode_keyed_frame,
};

/// Default maximum unconsumed body bytes per direction per stream.
///
/// A body is atomic at the RPC layer, so the window is also the maximum
/// body-frame size. Keeping those as one value makes it impossible to
/// configure a body that can never acquire enough credit to be sent.
pub const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024; // 1 MiB
