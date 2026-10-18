//! Native WebSocket transport via `tokio-tungstenite`.
//!
//! The WebSocket layer is message-oriented: each binary WS message is
//! exactly one mux keyed frame ("one Frame = one WebSocket message"
//! invariant from the wire plan). All non-binary control frames
//! (Ping/Pong/Text) are dropped — keepalives are handled by the
//! WebSocket layer itself, and we don't emit text.

use std::error::Error as StdError;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::Request};

use crate::clock::DefaultClock;
use crate::mux::{MessagePipe, MuxConfig, MuxTransport, Role};
use crate::transport::{AuthLevel, PeerIdentity, TransportContext};

use super::WsTransport;

/// Mux slot capacity for ordinary native WebSocket connections.
const NATIVE_MUX_N: usize = 128;

/// Mux slot capacity for a validator's aggregated relay connection.
///
/// A relay folds streams from many browser connections into this one mux, so
/// sizing it like one browser would cap the entire validator at 64 concurrent
/// requests. The relay-facing transport gets 1,024 client-owned (even) slots.
const RELAY_MUX_N: usize = 2048;

/// Errors surfaced by the WS adapter. Wrap tungstenite's error type
/// (which is not `Send + Sync + 'static` by accident — it is) so the
/// `MessagePipe` associated-error bounds are satisfied.
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("websocket: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("connect: {0}")]
    Connect(String),
}

/// `MessagePipe` adapter over a tokio-tungstenite `WebSocketStream`.
///
/// Generic over the underlying byte stream so the same pipe works for
/// `connect_async` (which yields `MaybeTlsStream<TcpStream>`) and for
/// upgraded server sockets (`hyper::upgrade::Upgraded`, plain
/// `TcpStream`, etc.).
pub struct WsPipe<S> {
    ws: WebSocketStream<S>,
}

impl<S> WsPipe<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self { ws }
    }

    pub fn into_inner(self) -> WebSocketStream<S> {
        self.ws
    }
}

impl<S> MessagePipe for WsPipe<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type SendError = WsError;
    type RecvError = WsError;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.ws.send(Message::Binary(bytes)).await?;
        Ok(())
    }

    async fn send_message_authorized(
        &mut self,
        bytes: Bytes,
        authority: &crate::WriteAuthority,
    ) -> std::io::Result<()> {
        use futures::Sink;
        use std::{pin::Pin, task::Poll};
        futures::future::poll_fn(|cx| {
            authority.poll_write(cx, &mut |cx| {
                std::task::ready!(Pin::new(&mut self.ws).poll_ready(cx))
                    .map_err(std::io::Error::other)?;
                Pin::new(&mut self.ws)
                    .start_send(Message::Binary(bytes.clone()))
                    .map_err(std::io::Error::other)?;
                Poll::Ready(Ok(bytes.len()))
            })
        })
        .await?;
        self.ws.flush().await.map_err(std::io::Error::other)
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        while let Some(msg) = self.ws.next().await {
            match msg? {
                Message::Binary(data) => return Ok(Some(data)),
                // Control frames + text: skip silently. tungstenite
                // auto-replies to pings, so we only see the trace.
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Text(_) => continue,
                Message::Frame(_) => continue,
                Message::Close(_) => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// Dial a WebSocket URL and bring up a `WsTransport` (== `MuxTransport`)
/// in client role. The caller polls `transport.open(...)` / `accept()`
/// as usual; the mux's spawned I/O loop drives the WebSocket.
pub async fn connect(url: &str) -> Result<WsTransport, WsError> {
    connect_with_role::<NATIVE_MUX_N>(url, Role::Client).await
}

/// Dial a WebSocket as the HTTP client while serving inbound mux streams.
///
/// Transport direction and mux role are deliberately separate concepts. A
/// validator connecting out to a relay is the HTTP/WebSocket client, but the
/// relay opens RPC streams toward it, so the validator must own the mux server
/// role. The request form lets callers add authenticated-upgrade headers before
/// dialing.
pub async fn connect_server(request: Request<()>) -> Result<WsTransport, WsError> {
    connect_with_role::<RELAY_MUX_N>(request, Role::Server).await
}

async fn connect_with_role<const N: usize>(
    request: impl IntoClientRequest + Unpin,
    role: Role,
) -> Result<WsTransport, WsError> {
    #[cfg(feature = "ws-rustls")]
    ensure_rustls_crypto_provider()?;

    let (ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| WsError::Connect(format!("{e}")))?;
    let pipe = WsPipe::new(ws);
    // A WebSocket mux vouches for nothing on its own: the TLS below it
    // is the browser's or the runtime's, and this layer can neither
    // name the peer nor export the session's keying material.
    let transport = MuxTransport::spawn::<N, DefaultClock, _>(
        role,
        DefaultClock,
        MuxConfig::default(),
        pipe,
        TransportContext::default(),
    );
    Ok(transport)
}

#[cfg(feature = "ws-rustls")]
fn ensure_rustls_crypto_provider() -> Result<(), WsError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A larger application may link both Rustls backends through unrelated
        // dependencies. Rustls deliberately refuses to guess in that case, so
        // install one explicitly unless the application already chose one.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    rustls::crypto::CryptoProvider::get_default()
        .map(|_| ())
        .ok_or_else(|| WsError::Connect("failed to install a Rustls crypto provider".to_string()))
}

/// Wrap an already-upgraded `WebSocketStream` as a server-side
/// `WsTransport`. The caller is responsible for performing the
/// HTTP/1.1 → WebSocket handshake (e.g. via `hyper`'s upgrade machinery
/// + `tokio_tungstenite::WebSocketStream::from_raw_socket(_, Server, _)`
///   or by accepting on a listener with `tokio_tungstenite::accept_async`).
///
/// `peer` is the optional transport-vouched identity (e.g. extracted
/// from a TLS client cert or an upstream auth header); pass `None` if
/// the transport itself has nothing to vouch for.
pub fn accept_upgraded<S>(ws: WebSocketStream<S>, peer: Option<PeerIdentity>) -> WsTransport
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pipe = WsPipe::new(ws);
    MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        pipe,
        TransportContext {
            auth_level: if peer.is_some() {
                AuthLevel::Vouched
            } else {
                AuthLevel::None
            },
            peer,
            ..TransportContext::default()
        },
    )
}

// Compile-time assertion: keep our error type compatible with the
// `MessagePipe::*Error` bounds (Send + Sync + 'static + Error).
const _: fn() = || {
    fn assert_pipe_error<T: StdError + Send + Sync + 'static>() {}
    assert_pipe_error::<WsError>();
};

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn write_authority_is_checked_before_handing_a_message_to_websocket() {
        use super::*;
        use crate::write_authority::tests::Gate;
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (local, remote) = tokio::io::duplex(512);
        let mut pipe =
            WsPipe::new(WebSocketStream::from_raw_socket(local, Role::Server, None).await);
        let mut peer = WebSocketStream::from_raw_socket(remote, Role::Client, None).await;
        let gate = Gate::default();
        let authority = gate.authority();
        pipe.send_message_authorized(Bytes::from_static(b"accepted"), &authority)
            .await
            .unwrap();
        assert_eq!(
            peer.next().await.unwrap().unwrap(),
            Message::Binary(Bytes::from_static(b"accepted"))
        );
        gate.revoke();
        assert_eq!(
            pipe.send_message_authorized(Bytes::from_static(b"unsent secret"), &authority)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        drop(pipe);
        assert!(!matches!(peer.next().await, Some(Ok(Message::Binary(_)))));
    }
    use super::*;
    use crate::{Metadata, StreamTransport};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    #[cfg(feature = "ws-rustls")]
    #[test]
    fn tls_feature_installs_a_process_crypto_provider() {
        ensure_rustls_crypto_provider().unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[tokio::test]
    async fn dialed_server_accepts_stream_opened_by_websocket_acceptor() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = accept_async(stream).await.unwrap();
            let transport = MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
                Role::Client,
                DefaultClock,
                MuxConfig::default(),
                WsPipe::new(ws),
                TransportContext::default(),
            );
            transport.open(0xfeed_beef, Metadata::new()).await.unwrap()
        });

        let request = format!("ws://{addr}").into_client_request().unwrap();
        let validator = connect_server(request).await.unwrap();
        let inbound = validator.accept().await.unwrap().unwrap();

        assert_eq!(inbound.method_id, 0xfeed_beef);
        drop(inbound);
        relay.await.unwrap();
    }
}
