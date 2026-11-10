//! WebSocket transport for `wasm32-unknown-unknown` (browser).
//!
//! Mirrors `native.rs` but uses `ws_stream_wasm` for the WebSocket I/O
//! and `wasm_bindgen_futures::spawn_local` for the mux driver task
//! (no tokio runtime on wasm32).

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use ws_stream_wasm::{WsMessage, WsMeta, WsStream};

use crate::clock::DefaultClock;
use crate::mux::{MessagePipe, MuxConfig, MuxTransport, Role};

/// Default const-N for browser-facing WS muxes.
pub const WASM_MUX_N: usize = 64;

/// `MessagePipe` over a `ws_stream_wasm` `WsStream`. One inbound binary
/// WS message → one inbound mux frame.
pub struct WsPipe {
    stream: WsStream,
}

impl WsPipe {
    fn new(stream: WsStream) -> Self {
        Self { stream }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("ws stream error: {0}")]
    Stream(String),
}

impl MessagePipe for WsPipe {
    type SendError = WsError;
    type RecvError = WsError;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.stream
            .send(WsMessage::Binary(bytes.to_vec()))
            .await
            .map_err(|e| WsError::Stream(e.to_string()))
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        loop {
            match self.stream.next().await {
                Some(WsMessage::Binary(bytes)) => return Ok(Some(Bytes::from(bytes))),
                // Text frames + protocol-level frames are not part of the
                // mux protocol — drop and keep reading.
                Some(WsMessage::Text(_)) => continue,
                None => return Ok(None),
            }
        }
    }
}

/// Connect to `url` (wss:// or ws://) and return a `MuxTransport`
/// ready for outbound RPCs. The handshake and the mux driver run as
/// `spawn_local` tasks on the wasm task queue, so the returned future is
/// `Send` even though `ws_stream_wasm`'s connect future is not.
pub async fn connect(url: &str) -> Result<MuxTransport, WsError> {
    let (reply, connected) = futures::channel::oneshot::channel();
    let url = url.to_owned();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = reply.send(WsMeta::connect(url, None).await);
    });
    let (_meta, stream) = connected
        .await
        .map_err(|e| WsError::Connect(e.to_string()))?
        .map_err(|e| WsError::Connect(e.to_string()))?;
    let pipe = WsPipe::new(stream);
    Ok(MuxTransport::spawn_with::<WASM_MUX_N, _, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        pipe,
        crate::TransportContext::default(),
        |fut| {
            wasm_bindgen_futures::spawn_local(fut);
        },
    ))
}
