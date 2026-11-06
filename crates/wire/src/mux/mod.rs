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

pub use crate::transport::DEFAULT_STREAM_WINDOW;
