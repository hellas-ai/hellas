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

/// Configure both complete messages and individual fragments before any reads.
pub fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(crate::mux::MAX_KEYED_FRAME_BYTES))
        .max_frame_size(Some(crate::mux::MAX_KEYED_FRAME_BYTES))
}

/// `MessagePipe` adapter over a tokio-tungstenite `WebSocketStream`.
///
/// Generic over the underlying byte stream so the same pipe works for
/// outbound TCP/TLS connections and for
/// upgraded server sockets (`hyper::upgrade::Upgraded`, plain
/// `TcpStream`, etc.).
pub struct WsPipe<S> {
    ws: WebSocketStream<S>,
}

impl<S> WsPipe<S> {
    pub fn new(ws: WebSocketStream<S>) -> Result<Self, WsError> {
        let config = ws.get_config();
        let cap = crate::mux::MAX_KEYED_FRAME_BYTES;
        if config.max_message_size.is_none_or(|size| size > cap)
            || config.max_frame_size.is_none_or(|size| size > cap)
        {
            return Err(WsError::Connect(
                "WebSocket exceeds the wire frame cap".into(),
            ));
        }
        Ok(Self { ws })
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
    connect_with_role::<NATIVE_MUX_N>(
        url,
        Role::Client,
        #[cfg(feature = "ws-rustls")]
        websocket_tls_config()?,
    )
    .await
}

/// Dial a WebSocket as the HTTP client while serving inbound mux streams.
///
/// Transport direction and mux role are deliberately separate concepts. A
/// validator connecting out to a relay is the HTTP/WebSocket client, but the
/// relay opens RPC streams toward it, so the validator must own the mux server
/// role. The request form lets callers add authenticated-upgrade headers before
/// dialing.
pub async fn connect_server(request: Request<()>) -> Result<WsTransport, WsError> {
    connect_with_role::<RELAY_MUX_N>(
        request,
        Role::Server,
        #[cfg(feature = "ws-rustls")]
        websocket_tls_config()?,
    )
    .await
}

async fn connect_with_role<const N: usize>(
    request: impl IntoClientRequest + Unpin,
    role: Role,
    #[cfg(feature = "ws-rustls")] tls_config: std::sync::Arc<rustls::ClientConfig>,
) -> Result<WsTransport, WsError> {
    let request = request
        .into_client_request()
        .map_err(|e| WsError::Connect(e.to_string()))?;
    let secure = match request.uri().scheme_str() {
        Some("ws") => false,
        Some("wss") => true,
        _ => return Err(WsError::Connect("unsupported WebSocket URL scheme".into())),
    };
    #[cfg(not(feature = "ws-rustls"))]
    if secure {
        return Err(WsError::Connect("WebSocket TLS support is disabled".into()));
    }
    let host = request
        .uri()
        .host()
        .ok_or_else(|| WsError::Connect("WebSocket URL has no host".into()))?;
    // http::Uri retains IPv6 brackets; socket lookup and Rustls names do not.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = request
        .uri()
        .port_u16()
        .unwrap_or(if secure { 443 } else { 80 });
    let stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| WsError::Connect(e.to_string()))?;
    #[cfg(feature = "ws-rustls")]
    if secure {
        let server = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| WsError::Connect(e.to_string()))?;
        let stream = tokio_rustls::TlsConnector::from(tls_config)
            .connect(server, stream)
            .await
            .map_err(|e| WsError::Connect(e.to_string()))?;
        return connect_stream::<N, _>(request, stream, role).await;
    }
    connect_stream::<N, _>(request, stream, role).await
}

async fn connect_stream<const N: usize, S>(
    request: Request<()>,
    stream: S,
    role: Role,
) -> Result<WsTransport, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ws, _resp) =
        tokio_tungstenite::client_async_with_config(request, stream, Some(websocket_config()))
            .await
            .map_err(|e| WsError::Connect(e.to_string()))?;
    let pipe = WsPipe::new(ws)?;
    // HTTPS certificate validation does not establish a Hellas principal.
    // WebSocket connections carry no protocol service binding or exporter.
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
fn websocket_tls_config() -> Result<std::sync::Arc<rustls::ClientConfig>, WsError> {
    use std::sync::{Arc, OnceLock};
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map(|builder| Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
            .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(WsError::Connect)
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
pub fn accept_upgraded<S>(
    ws: WebSocketStream<S>,
    peer: Option<PeerIdentity>,
) -> Result<WsTransport, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let pipe = WsPipe::new(ws)?;
    Ok(MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
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
    ))
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
    async fn websocket_parser_rejects_an_oversized_frame_header_before_its_payload() {
        use tokio::io::AsyncWriteExt as _;
        use tokio_tungstenite::tungstenite::{Error, protocol::Role};
        let (local, mut remote) = tokio::io::duplex(512);
        let ws =
            WebSocketStream::from_raw_socket(local, Role::Client, Some(websocket_config())).await;
        let mut pipe = WsPipe::new(ws).unwrap();
        let mut header = vec![0x82, 0x7f];
        header.extend_from_slice(&((crate::mux::MAX_KEYED_FRAME_BYTES + 1) as u64).to_be_bytes());
        remote.write_all(&header).await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), pipe.recv_message())
            .await
            .expect("the frame length is refused without waiting for any payload");
        assert!(matches!(result, Err(WsError::Ws(Error::Capacity(_)))));
    }

    #[tokio::test]
    async fn pipe_rejects_unbounded_websocket_parsers() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (local, _remote) = tokio::io::duplex(512);
        let ws = WebSocketStream::from_raw_socket(local, Role::Server, None).await;
        assert!(WsPipe::new(ws).is_err());
    }

    #[tokio::test]
    async fn websocket_parser_rejects_oversized_messages_and_fragments() {
        use tokio_tungstenite::tungstenite::{
            Error,
            protocol::{
                Role,
                frame::{
                    Frame,
                    coding::{Data, OpCode},
                },
            },
        };
        let cap = crate::mux::MAX_KEYED_FRAME_BYTES;
        for fragmented in [false, true] {
            let (local, remote) = tokio::io::duplex(64 * 1024);
            let ws =
                WebSocketStream::from_raw_socket(local, Role::Server, Some(websocket_config()))
                    .await;
            let mut pipe = WsPipe::new(ws).unwrap();
            let sending = tokio::spawn(async move {
                let mut peer = WebSocketStream::from_raw_socket(remote, Role::Client, None).await;
                if fragmented {
                    let half = Bytes::from(vec![0; cap / 2 + 1]);
                    peer.send(Message::Frame(Frame::message(
                        half.clone(),
                        OpCode::Data(Data::Binary),
                        false,
                    )))
                    .await?;
                    peer.send(Message::Frame(Frame::message(
                        half,
                        OpCode::Data(Data::Continue),
                        true,
                    )))
                    .await?;
                } else {
                    peer.send(Message::Binary(Bytes::from(vec![0; cap + 1])))
                        .await?;
                }
                Ok::<_, Error>(peer)
            });
            assert!(
                matches!(
                    pipe.recv_message().await,
                    Err(WsError::Ws(Error::Capacity(_)))
                ),
                "the WS parser must reject excess bytes before mux decoding"
            );
            drop(pipe);
            let _ = sending.await;
        }
    }

    #[tokio::test]
    async fn write_authority_is_checked_before_handing_a_message_to_websocket() {
        use super::*;
        use crate::write_authority::tests::Gate;
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (local, remote) = tokio::io::duplex(512);
        let mut pipe = WsPipe::new(
            WebSocketStream::from_raw_socket(local, Role::Server, Some(websocket_config())).await,
        )
        .unwrap();
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

    #[cfg(feature = "ws-rustls")]
    #[test]
    fn tls_config_is_shared_and_does_not_require_alpn() {
        let first = websocket_tls_config().unwrap();
        let second = websocket_tls_config().unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        assert!(first.alpn_protocols.is_empty());
    }

    #[tokio::test]
    async fn unsupported_scheme_is_rejected_before_dialing() {
        let error = connect("https://127.0.0.1:1/").await.err().unwrap();
        assert!(
            error
                .to_string()
                .contains("unsupported WebSocket URL scheme")
        );
    }

    #[cfg(not(feature = "ws-rustls"))]
    #[tokio::test]
    async fn wss_without_tls_is_rejected_before_dialing() {
        let error = connect("wss://127.0.0.1:1/").await.err().unwrap();
        assert!(error.to_string().contains("TLS support is disabled"));
    }

    #[allow(
        clippy::result_large_err,
        reason = "tungstenite fixes its upgrade callback error type"
    )]
    fn assert_upgrade_request(
        request: &tokio_tungstenite::tungstenite::handshake::server::Request,
        response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/relay?node=1"
        );
        assert_eq!(request.headers()["authorization"], "Bearer local-test");
        Ok(response)
    }

    #[tokio::test]
    async fn ipv6_websocket_dial_preserves_upgrade_headers() {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_hdr_async_with_config(
                tcp,
                assert_upgrade_request,
                Some(websocket_config()),
            )
            .await
            .unwrap();
            let transport = MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
                Role::Client,
                DefaultClock,
                MuxConfig::default(),
                WsPipe::new(ws).unwrap(),
                TransportContext::default(),
            );
            let _stream = transport.open(42, Metadata::new()).await.unwrap();
        });
        let mut request = format!("ws://{addr}/relay?node=1")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("authorization", "Bearer local-test".parse().unwrap());
        let transport = connect_server(request).await.unwrap();
        assert_eq!(transport.accept().await.unwrap().unwrap().method_id, 42);
        peer.await.unwrap();
    }

    #[cfg(feature = "ws-rustls")]
    fn local_tls_server(
        version: &'static rustls::SupportedProtocolVersion,
    ) -> (
        std::sync::Arc<rustls::ServerConfig>,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.cert.der().clone();
        let server = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        (std::sync::Arc::new(server), certificate)
    }

    #[cfg(feature = "ws-rustls")]
    #[tokio::test]
    async fn local_wss_supports_tls12_and_tls13_without_alpn() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let (server, certificate) = local_tls_server(version);
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = tokio_rustls::TlsAcceptor::from(server)
                    .accept(tcp)
                    .await
                    .unwrap();
                assert_eq!(tls.get_ref().1.protocol_version(), Some(version.version));
                assert!(tls.get_ref().1.alpn_protocol().is_none());
                let ws = tokio_tungstenite::accept_hdr_async_with_config(
                    tls,
                    assert_upgrade_request,
                    Some(websocket_config()),
                )
                .await
                .unwrap();
                let transport = accept_upgraded(ws, None).unwrap();
                let inbound = transport.accept().await.unwrap().unwrap();
                assert_eq!(inbound.method_id, 42);
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate).unwrap();
            let config = rustls::ClientConfig::builder_with_provider(
                websocket_tls_config().unwrap().crypto_provider().clone(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let mut request = format!("wss://localhost:{}/relay?node=1", addr.port())
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("authorization", "Bearer local-test".parse().unwrap());
            let client = connect_with_role::<NATIVE_MUX_N>(
                request,
                Role::Client,
                std::sync::Arc::new(config),
            )
            .await
            .unwrap();
            let _stream = client.open(42, Metadata::new()).await.unwrap();
            peer.await.unwrap();
        }
    }

    #[cfg(feature = "ws-rustls")]
    #[tokio::test]
    async fn trusted_certificate_with_wrong_hostname_is_rejected() {
        let (server, certificate) = local_tls_server(&rustls::version::TLS13);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(
                tokio_rustls::TlsAcceptor::from(server)
                    .accept(tcp)
                    .await
                    .is_err()
            );
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let config = rustls::ClientConfig::builder_with_provider(
            websocket_tls_config().unwrap().crypto_provider().clone(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let error = connect_with_role::<NATIVE_MUX_N>(
            format!("wss://{addr}"),
            Role::Client,
            std::sync::Arc::new(config),
        )
        .await
        .err()
        .unwrap();
        assert!(
            error.to_string().contains("certificate not valid for name"),
            "{error}"
        );
        peer.await.unwrap();
    }

    #[cfg(feature = "ws-rustls")]
    #[tokio::test]
    async fn public_wss_dial_rejects_an_untrusted_certificate() {
        let (server, _) = local_tls_server(&rustls::version::TLS13);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(
                tokio_rustls::TlsAcceptor::from(server)
                    .accept(tcp)
                    .await
                    .is_err()
            );
        });
        let error = connect(&format!("wss://localhost:{}", addr.port()))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("UnknownIssuer"), "{error}");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn dialed_server_accepts_stream_opened_by_websocket_acceptor() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async_with_config(stream, Some(websocket_config()))
                .await
                .unwrap();
            let transport = MuxTransport::spawn::<NATIVE_MUX_N, DefaultClock, _>(
                Role::Client,
                DefaultClock,
                MuxConfig::default(),
                WsPipe::new(ws).unwrap(),
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
