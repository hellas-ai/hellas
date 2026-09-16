//! `StreamTransport` impl over an iroh `Connection`.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use bytes::BytesMut;
use futures::{StreamExt, stream::FuturesUnordered};
use iroh::endpoint::Connection;
use tokio::sync::Mutex;

use crate::frame::{Frame, OpenFrame, bounded_frame_len, decode_frame, read_varint_partial};
use crate::metadata::Metadata;
use crate::transport::{AuthLevel, Inbound, PeerIdentity, StreamTransport, TransportContext};

use super::stream::{IrohStream, STREAM_ERROR_CODE};

pub const OPEN_EXPORTER_LABEL: &[u8] = b"hellas/attest/open/v1";
pub const OPEN_EXPORTER_LEN: usize = 32;

// These are phase deadlines, not RPC deadlines. In particular, no timer runs
// while an accepted request is executing or between response-stream items.
const OPEN_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_REQUEST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const WRITE_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum Open frames parsed concurrently on one QUIC connection. This is
/// deliberately the same order as the server's per-connection dispatch bound:
/// enough to let a valid stream pass stalled siblings without allowing one
/// peer to create an unbounded set of parser tasks and buffers.
const MAX_PENDING_OPEN_FRAMES: usize = 16;

#[derive(Clone, Copy)]
struct PhaseTimeouts {
    open_frame: Duration,
    first_request_frame: Duration,
    partial_frame: Duration,
    write_frame: Duration,
}

impl Default for PhaseTimeouts {
    fn default() -> Self {
        Self {
            open_frame: OPEN_FRAME_TIMEOUT,
            first_request_frame: FIRST_REQUEST_FRAME_TIMEOUT,
            partial_frame: PARTIAL_FRAME_TIMEOUT,
            write_frame: WRITE_FRAME_TIMEOUT,
        }
    }
}

struct AcceptedOpen {
    method_id: u32,
    headers: Metadata,
    stream: IrohStream,
}

type PendingOpen =
    Pin<Box<dyn Future<Output = Result<AcceptedOpen, IrohTransportError>> + Send + 'static>>;

#[derive(Default)]
struct AcceptState {
    pending: FuturesUnordered<PendingOpen>,
    connection_error: Option<IrohTransportError>,
}

pub struct IrohTransport {
    connection: Arc<Connection>,
    accept_state: Arc<Mutex<AcceptState>>,
    timeouts: PhaseTimeouts,
}

impl IrohTransport {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection: Arc::new(connection),
            accept_state: Arc::new(Mutex::new(AcceptState::default())),
            timeouts: PhaseTimeouts::default(),
        }
    }

    #[cfg(test)]
    fn with_timeouts(connection: Connection, timeouts: PhaseTimeouts) -> Self {
        Self {
            connection: Arc::new(connection),
            accept_state: Arc::new(Mutex::new(AcceptState::default())),
            timeouts,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Derive the confidential-open exporter from this exact QUIC connection.
    pub fn open_exporter(&self) -> Result<[u8; OPEN_EXPORTER_LEN], IrohTransportError> {
        let mut exporter = [0; OPEN_EXPORTER_LEN];
        self.connection
            .export_keying_material(&mut exporter, OPEN_EXPORTER_LABEL, b"")
            .map_err(|_| {
                IrohTransportError::Connection(
                    "failed to export confidential-open keying material".into(),
                )
            })?;
        Ok(exporter)
    }

    fn transport_context(&self) -> Result<TransportContext, IrohTransportError> {
        Ok(TransportContext {
            peer: self.peer_identity(),
            rtt_ms: None,
            auth_level: AuthLevel::Vouched,
            open_exporter: Some(self.open_exporter()?),
        })
    }

    fn peer_identity(&self) -> Option<PeerIdentity> {
        Some(PeerIdentity(*self.connection.remote_id().as_bytes()))
    }

    fn finish_open(
        &self,
        open: Result<AcceptedOpen, IrohTransportError>,
    ) -> Result<Option<Inbound<IrohStream>>, IrohTransportError> {
        let AcceptedOpen {
            method_id,
            headers,
            stream,
        } = open?;
        Ok(Some(Inbound {
            method_id,
            headers,
            stream,
            context: self.transport_context()?,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IrohTransportError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("unexpected first frame")]
    UnexpectedFirstFrame,
    #[error("open frame timed out")]
    OpenFrameTimeout,
}

impl StreamTransport for IrohTransport {
    type Stream = IrohStream;
    type Error = IrohTransportError;

    fn context(&self) -> TransportContext {
        self.transport_context()
            .unwrap_or_else(|_| TransportContext {
                peer: self.peer_identity(),
                rtt_ms: None,
                auth_level: AuthLevel::Vouched,
                open_exporter: None,
            })
    }

    async fn open(&self, method_id: u32, headers: Metadata) -> Result<Self::Stream, Self::Error> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| IrohTransportError::Connection(e.to_string()))?;
        let mut stream = IrohStream::new(
            send,
            recv,
            self.timeouts.partial_frame,
            self.timeouts.write_frame,
        );
        stream.write_open(method_id, headers).await?;
        Ok(stream)
    }

    async fn accept(&self) -> Result<Option<Inbound<Self::Stream>>, Self::Error> {
        // One caller owns the queue, but Open parsing itself is concurrent.
        // Pending parsers stay in this state across calls, so returning a ready
        // stream never cancels or discards its siblings.
        let mut state = self.accept_state.lock().await;
        loop {
            if state.pending.is_empty()
                && let Some(error) = state.connection_error.take()
            {
                return Err(error);
            }

            if state.pending.len() >= MAX_PENDING_OPEN_FRAMES || state.connection_error.is_some() {
                let completed = state
                    .pending
                    .next()
                    .await
                    .expect("a non-empty Open parser set has a next result");
                drop(state);
                return self.finish_open(completed);
            }

            if state.pending.is_empty() {
                match self.connection.accept_bi().await {
                    Ok((send, recv)) => {
                        state
                            .pending
                            .push(Box::pin(read_open_stream(send, recv, self.timeouts)))
                    }
                    Err(error) => {
                        return Err(IrohTransportError::Connection(error.to_string()));
                    }
                }
                continue;
            }

            tokio::select! {
                completed = state.pending.next() => {
                    let completed = completed
                        .expect("a non-empty Open parser set has a next result");
                    drop(state);
                    return self.finish_open(completed);
                }
                accepted = self.connection.accept_bi() => {
                    match accepted {
                        Ok((send, recv)) => state.pending.push(Box::pin(read_open_stream(
                            send,
                            recv,
                            self.timeouts,
                        ))),
                        Err(error) => {
                            // QUIC may close while already-accepted streams are
                            // still readable. Drain those before surfacing the
                            // connection error so no completed RPC is lost.
                            state.connection_error = Some(IrohTransportError::Connection(
                                error.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }
}

async fn read_open_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    timeouts: PhaseTimeouts,
) -> Result<AcceptedOpen, IrohTransportError> {
    // The deadline covers the complete Open frame, rather than each read, so
    // a peer cannot keep one parser slot alive by trickling bytes.
    let read_open = async {
        let mut read_buf = BytesMut::new();
        let parsed = loop {
            if !read_buf.is_empty() {
                match try_peek_open(&read_buf) {
                    Ok(Some((method_id, headers, consumed))) => {
                        break (method_id, headers, consumed);
                    }
                    Ok(None) => {}
                    Err(error) => return Err(error),
                }
            }
            let mut tmp = [0u8; 4096];
            match recv.read(&mut tmp).await {
                Ok(Some(0)) | Ok(None) => {
                    return Err(IrohTransportError::UnexpectedFirstFrame);
                }
                Ok(Some(n)) => read_buf.extend_from_slice(&tmp[..n]),
                Err(error) => {
                    return Err(IrohTransportError::Connection(error.to_string()));
                }
            }
        };
        Ok::<_, IrohTransportError>((parsed, read_buf))
    };

    let ((method_id, headers, consumed), mut read_buf) =
        match n0_future::time::timeout(timeouts.open_frame, read_open).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                abort_raw_stream(&mut send, &mut recv);
                return Err(error);
            }
            Err(_) => {
                abort_raw_stream(&mut send, &mut recv);
                return Err(IrohTransportError::OpenFrameTimeout);
            }
        };

    // Drop the Open frame's bytes; any residual is request data that the
    // IrohStream recv-half consumes before pulling more off the wire.
    let residual = read_buf.split_off(consumed);
    Ok(AcceptedOpen {
        method_id,
        headers,
        stream: IrohStream::with_prefix(
            send,
            recv,
            residual,
            timeouts.first_request_frame,
            timeouts.partial_frame,
            timeouts.write_frame,
        ),
    })
}

fn abort_raw_stream(send: &mut iroh::endpoint::SendStream, recv: &mut iroh::endpoint::RecvStream) {
    let _ = send.reset(STREAM_ERROR_CODE.into());
    let _ = recv.stop(STREAM_ERROR_CODE.into());
}

/// Tri-state parse of the next length-prefixed frame as an OpenFrame.
///
/// - `Ok(Some(...))` — frame ready; caller advances `consumed` bytes.
/// - `Ok(None)` — need more bytes; varint or body is truncated.
/// - `Err(_)` — fatal: corrupt varint, oversized announced length, or
///   the frame doesn't decode as Open. Caller must abort the stream
///   rather than retry, because none of these are recoverable by
///   buffering more bytes.
fn try_peek_open(buf: &[u8]) -> Result<Option<(u32, Metadata, usize)>, IrohTransportError> {
    let (len, consumed) = match read_varint_partial(buf)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let len = bounded_frame_len(len)?;
    if buf.len() < consumed + len {
        return Ok(None);
    }
    let frame = decode_frame(&buf[consumed..consumed + len])?;
    match frame {
        Frame::Open(OpenFrame { method_id, headers }) => {
            Ok(Some((method_id, headers, consumed + len)))
        }
        _ => Err(IrohTransportError::UnexpectedFirstFrame),
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    use bytes::{Bytes, BytesMut};
    use futures::{StreamExt, poll};
    use iroh::{
        Endpoint, EndpointAddr, SecretKey, TransportAddr,
        endpoint::{RecvStream, SendStream, presets},
    };

    use crate::{
        frame::{Frame, OpenFrame, encode_frame, write_varint},
        metadata::Metadata,
        transport::{SendHalf as _, Stream as _},
    };

    const TEST_ALPN: &[u8] = b"/hellas.wire.timeout-test/1";
    const OUTER_TIMEOUT: Duration = Duration::from_secs(5);

    async fn connected_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[0x91; 32]))
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback address"),
            )
            .expect("valid server bind address")
            .bind()
            .await
            .expect("server binds");
        let target = EndpointAddr::from_parts(
            server.id(),
            server.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[0x92; 32]))
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("loopback address"),
            )
            .expect("valid client bind address")
            .bind()
            .await
            .expect("client binds");

        let accepting_server = server.clone();
        let accept = async move {
            let incoming = accepting_server
                .accept()
                .await
                .expect("server receives dial");
            incoming
                .accept()
                .expect("server accepts dial")
                .await
                .expect("server handshake completes")
        };
        let connect = client.connect(target, TEST_ALPN);
        let (client_connection, server_connection) = tokio::join!(connect, accept);
        (
            client,
            server,
            client_connection.expect("client handshake completes"),
            server_connection,
        )
    }

    fn timeouts(
        open_frame: Duration,
        first_request_frame: Duration,
        write_frame: Duration,
    ) -> PhaseTimeouts {
        PhaseTimeouts {
            open_frame,
            first_request_frame,
            partial_frame: first_request_frame,
            write_frame,
        }
    }

    fn framed(frame: Frame) -> Vec<u8> {
        let mut frame_bytes = BytesMut::new();
        encode_frame(&frame, &mut frame_bytes);
        let mut bytes = BytesMut::new();
        write_varint(frame_bytes.len() as u64, &mut bytes);
        bytes.extend_from_slice(&frame_bytes);
        bytes.to_vec()
    }

    fn open_frame(method_id: u32) -> Frame {
        Frame::Open(OpenFrame {
            method_id,
            headers: Metadata::default(),
        })
    }

    #[test]
    fn non_open_first_frame_has_a_truthful_transport_error() {
        let bytes = framed(Frame::Body(Bytes::from_static(b"not an Open")));
        assert!(matches!(
            try_peek_open(&bytes),
            Err(IrohTransportError::UnexpectedFirstFrame)
        ));
    }

    async fn raw_stream(connection: &Connection, bytes: &[u8]) -> (SendStream, RecvStream) {
        let (mut send, recv) = connection.open_bi().await.expect("client opens stream");
        send.write_all(bytes).await.expect("client writes prefix");
        (send, recv)
    }

    #[tokio::test]
    async fn only_end_accepts_a_graceful_peer_stop() {
        use crate::metadata::Trailer;
        use crate::transport::RecvHalf as _;

        for (stop_code, closing) in [(0_u32, true), (1, true), (0, false)] {
            let (client, server, client_connection, server_connection) = connected_pair().await;
            let transport = IrohTransport::new(server_connection);
            let mut bytes = framed(open_frame(10));
            bytes.extend_from_slice(&framed(Frame::Body(Bytes::from_static(b"request"))));
            let (client_send, client_recv) = raw_stream(&client_connection, &bytes).await;
            let inbound = transport
                .accept()
                .await
                .expect("transport accepts Open")
                .expect("stream is present");
            let (mut send, mut recv) = inbound.stream.split();
            assert_eq!(recv.next().await.unwrap().unwrap(), b"request"[..]);
            send.send_body(Bytes::from_static(b"response"))
                .await
                .unwrap();
            send.close_send(Some(Trailer::ok())).await.unwrap();
            if stop_code != 0 {
                recv.reset(crate::status::WireCode::Cancelled);
            }
            // Normal handlers drop their receive half after the single body.
            // Wait for the resulting stop so End always encounters the race.
            drop(recv);
            assert_eq!(
                tokio::time::timeout(OUTER_TIMEOUT, client_send.stopped())
                    .await
                    .expect("the peer observes STOP_SENDING")
                    .expect("the connection remains live"),
                Some(stop_code.into()),
            );
            let (mut send, mut recv) =
                IrohStream::new(client_send, client_recv, OUTER_TIMEOUT, OUTER_TIMEOUT).split();
            let written = if closing {
                send.close_send(None).await
            } else {
                send.send_body(Bytes::from_static(b"another body")).await
            };
            if stop_code == 0 && closing {
                written.expect("a normal peer stop already closed the send direction");
                assert_eq!(recv.next().await.unwrap().unwrap(), b"response"[..]);
                assert!(recv.next().await.is_none());
                assert_eq!(
                    recv.trailer().expect("response trailer").status,
                    crate::status::WireCode::Ok
                );
            } else {
                written.expect_err("body writes and peer resets remain errors");
            }
            drop((send, recv));
            client.close().await;
            server.close().await;
        }
    }

    #[tokio::test]
    async fn incomplete_open_is_reset_and_accept_capacity_is_released() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
        );

        // An unterminated varint used to retain `accept_lock` forever.
        let (stalled_send, mut stalled_recv) = raw_stream(&client_connection, &[0x80]).await;
        let result = tokio::time::timeout(OUTER_TIMEOUT, transport.accept())
            .await
            .expect("the Open deadline fires");
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("the partial Open was accepted"),
        };
        assert!(matches!(error, IrohTransportError::OpenFrameTimeout));
        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, stalled_send.stopped())
                .await
                .expect("the peer observes STOP_SENDING")
                .expect("the connection remains live")
                .is_some(),
            "the timed-out request direction is reset",
        );
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, stalled_recv.read(&mut byte))
                .await
                .expect("the peer observes the response reset")
                .is_err(),
            "the timed-out response direction is reset",
        );

        // The guard was released with the failed accept: a following stream
        // can be accepted on the same connection.
        let next_open = framed(open_frame(42));
        let (_next_send, _next_recv) = raw_stream(&client_connection, &next_open).await;
        let inbound = tokio::time::timeout(OUTER_TIMEOUT, transport.accept())
            .await
            .expect("a later accept is not locked out")
            .expect("the connection remains usable")
            .expect("the next stream is accepted");
        assert_eq!(inbound.method_id, 42);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn stalled_open_does_not_block_a_later_valid_open() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(1),
            ),
        );

        // Keep the first stream alive with an incomplete length prefix. A
        // serialized parser would hold the only accept path for ten seconds.
        let (_stalled_send, _stalled_recv) = raw_stream(&client_connection, &[0x80]).await;
        let valid = framed(open_frame(43));
        let (_valid_send, _valid_recv) = raw_stream(&client_connection, &valid).await;

        let inbound = tokio::time::timeout(Duration::from_secs(2), transport.accept())
            .await
            .expect("the valid Open bypasses its stalled sibling")
            .expect("the connection remains live")
            .expect("the valid stream is accepted");
        assert_eq!(inbound.method_id, 43);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn trickled_first_request_frame_is_reset_on_the_total_deadline() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let request_timeout = Duration::from_secs(10);
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::from_secs(1),
                request_timeout,
                Duration::from_secs(1),
            ),
        );

        let mut prefix = framed(open_frame(7));
        let body = framed(Frame::Body(Bytes::from_static(b"slow request")));
        prefix.extend_from_slice(&body[..body.len() - 2]);
        let (mut stalled_send, _stalled_recv) = raw_stream(&client_connection, &prefix).await;
        let inbound = tokio::time::timeout(OUTER_TIMEOUT, transport.accept())
            .await
            .expect("Open is complete")
            .expect("transport accepts Open")
            .expect("stream is present");
        let (server_send, recv) = inbound.stream.split();
        let mut recv = Box::pin(recv);

        tokio::time::pause();
        assert!(poll!(recv.next()).is_pending());
        tokio::time::advance(request_timeout - Duration::from_secs(1)).await;
        // Progress immediately before the deadline must not buy a fresh
        // timeout: the complete frame has one total budget.
        stalled_send
            .write_all(&body[body.len() - 2..body.len() - 1])
            .await
            .expect("peer trickles one more byte");
        assert!(poll!(recv.next()).is_pending());
        tokio::time::advance(Duration::from_secs(2)).await;
        let error = recv
            .next()
            .await
            .expect("the deadline yields one error")
            .expect_err("the incomplete body is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        tokio::time::resume();
        drop(server_send);
        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, stalled_send.stopped())
                .await
                .expect("the peer observes STOP_SENDING")
                .expect("the connection remains live")
                .is_some(),
            "timing out the recv half resets its paired send half too",
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn client_partial_response_frame_is_reset_on_deadline() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let partial_timeout = Duration::ZERO;
        let transport = IrohTransport::with_timeouts(
            client_connection,
            timeouts(
                Duration::from_secs(1),
                partial_timeout,
                Duration::from_secs(1),
            ),
        );

        let stream = transport
            .open(44, Metadata::new())
            .await
            .expect("client opens a stream");
        let (mut server_send, server_recv) = server_connection
            .accept_bi()
            .await
            .expect("server accepts the client stream");
        // An unterminated response-frame length used to wait forever on every
        // client-opened stream. One byte arms a total framing-phase deadline.
        server_send
            .write_all(&[0x80])
            .await
            .expect("server writes a partial response prefix");

        let (client_send, recv) = stream.split();
        let mut recv = Box::pin(recv);
        let error = tokio::time::timeout(OUTER_TIMEOUT, recv.next())
            .await
            .expect("the partial-response deadline fires")
            .expect("the partial-frame deadline yields one error")
            .expect_err("the incomplete response frame is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(client_send);
        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, server_send.stopped())
                .await
                .expect("the server observes STOP_SENDING")
                .expect("the connection remains live")
                .is_some(),
        );
        drop(server_recv);

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn malformed_request_resets_both_stream_directions() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
        );

        let mut bytes = framed(open_frame(10));
        bytes.extend_from_slice(&[0xff; 10]);
        let (client_send, mut client_recv) = raw_stream(&client_connection, &bytes).await;
        let inbound = transport
            .accept()
            .await
            .expect("transport accepts Open")
            .expect("stream is present");
        let (server_send, recv) = inbound.stream.split();
        let mut recv = Box::pin(recv);
        recv.next()
            .await
            .expect("the malformed frame yields one error")
            .expect_err("a malformed varint is rejected");
        drop(server_send);

        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, client_send.stopped())
                .await
                .expect("the peer observes STOP_SENDING")
                .expect("the connection remains live")
                .is_some(),
        );
        let mut byte = [0u8; 1];
        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, client_recv.read(&mut byte))
                .await
                .expect("the peer observes the response reset")
                .is_err(),
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn completed_first_request_disarms_the_deadline() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let request_timeout = Duration::from_secs(10);
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::from_secs(1),
                request_timeout,
                Duration::from_secs(1),
            ),
        );

        let mut bytes = framed(open_frame(8));
        bytes.extend_from_slice(&framed(Frame::Body(Bytes::from_static(b"first"))));
        let (mut client_send, _client_recv) = raw_stream(&client_connection, &bytes).await;
        let inbound = transport
            .accept()
            .await
            .expect("transport accepts Open")
            .expect("stream is present");
        let (_server_send, recv) = inbound.stream.split();
        let mut recv = Box::pin(recv);
        assert_eq!(
            recv.next()
                .await
                .expect("first body arrives")
                .expect("body"),
            Bytes::from_static(b"first"),
        );

        tokio::time::pause();
        tokio::time::advance(request_timeout * 2).await;
        assert!(
            poll!(recv.next()).is_pending(),
            "there is no overall request or RPC deadline",
        );
        tokio::time::resume();
        let second = framed(Frame::Body(Bytes::from_static(b"second")));
        client_send
            .write_all(&second)
            .await
            .expect("a later streaming body is allowed");
        assert_eq!(
            tokio::time::timeout(OUTER_TIMEOUT, recv.next())
                .await
                .expect("later body is not timed out")
                .expect("later body arrives")
                .expect("later body decodes"),
            Bytes::from_static(b"second"),
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn blocked_response_frame_is_reset_on_deadline() {
        let (client, server, client_connection, server_connection) = connected_pair().await;
        let write_timeout = Duration::from_secs(10);
        let transport = IrohTransport::with_timeouts(
            server_connection,
            timeouts(
                Duration::from_secs(1),
                Duration::from_secs(1),
                write_timeout,
            ),
        );

        let mut bytes = framed(open_frame(9));
        bytes.extend_from_slice(&framed(Frame::Body(Bytes::from_static(b"request"))));
        let (_client_send, mut client_recv) = raw_stream(&client_connection, &bytes).await;
        let inbound = transport
            .accept()
            .await
            .expect("transport accepts Open")
            .expect("stream is present");
        let (mut send, recv) = inbound.stream.split();
        let mut recv = Box::pin(recv);
        assert_eq!(
            recv.next().await.expect("request arrives").expect("body"),
            Bytes::from_static(b"request"),
        );

        // The default QUIC per-stream receive window is smaller than this
        // frame. A peer that never reads therefore forces the write to block.
        tokio::time::pause();
        let error = {
            let write = send.send_body(Bytes::from(vec![0u8; 2 * 1024 * 1024]));
            tokio::pin!(write);
            assert!(poll!(write.as_mut()).is_pending());
            tokio::time::advance(write_timeout).await;
            write.await.expect_err("the frame write is bounded")
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        tokio::time::resume();
        drop(recv);
        drop(send);

        assert!(
            tokio::time::timeout(OUTER_TIMEOUT, client_recv.read_to_end(4 * 1024 * 1024))
                .await
                .expect("the peer observes the reset")
                .is_err(),
            "the blocked response stream is reset instead of retaining a dispatch slot",
        );

        client.close().await;
        server.close().await;
    }
}
