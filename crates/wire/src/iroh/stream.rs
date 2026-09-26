//! `Stream` impl over an iroh QUIC substream (Send + Recv).

use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_core::Stream as FuturesStream;
use iroh::endpoint::{RecvStream, SendStream};

use crate::frame::{
    EndFrame, Frame, FrameError, MAX_FRAME_BYTES, OpenFrame, bounded_frame_len, decode_frame,
    encode_frame, encoded_frame_len, read_varint_partial, write_varint,
};
use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

pub(super) const STREAM_ERROR_CODE: u32 = 1;

/// Bidi RPC stream over an iroh substream. Frames inside use a
/// `[varint len][frame_kind][body]` framing because iroh streams
/// are byte-oriented (not message-oriented).
pub struct IrohStream {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
    /// Bytes already read off the wire that haven't been consumed yet —
    /// happens when the OPEN frame and the first Body frame arrive in
    /// the same TCP segment and the accept loop reads past OPEN.
    prefix: BytesMut,
    reset_flag: Arc<AtomicBool>,
    first_frame_deadline: Option<n0_future::time::Instant>,
    partial_frame_timeout: Duration,
    write_timeout: Duration,
}

impl IrohStream {
    pub(crate) fn new(
        send: SendStream,
        recv: RecvStream,
        partial_frame_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            prefix: BytesMut::new(),
            reset_flag: Arc::new(AtomicBool::new(false)),
            first_frame_deadline: None,
            partial_frame_timeout,
            write_timeout,
        }
    }

    /// Construct with bytes already pre-read off the wire. The recv-half
    /// will yield these bytes before pulling anything new from the
    /// underlying RecvStream.
    pub(crate) fn with_prefix(
        send: SendStream,
        recv: RecvStream,
        prefix: BytesMut,
        first_frame_timeout: Duration,
        partial_frame_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            send: Some(send),
            recv: Some(recv),
            prefix,
            reset_flag: Arc::new(AtomicBool::new(false)),
            first_frame_deadline: Some(n0_future::time::Instant::now() + first_frame_timeout),
            partial_frame_timeout,
            write_timeout,
        }
    }

    pub(crate) async fn write_open(
        &mut self,
        method_id: u32,
        headers: Metadata,
    ) -> std::io::Result<()> {
        let buf = encode_outbound_frame(&Frame::Open(OpenFrame { method_id, headers }))?;
        self.write_framed(&buf).await
    }

    async fn write_framed(&mut self, frame_bytes: &[u8]) -> std::io::Result<()> {
        let mut len_buf = BytesMut::with_capacity(10);
        write_varint(frame_bytes.len() as u64, &mut len_buf);
        let result = match self.send.as_mut() {
            Some(send) => {
                write_frame_with_timeout(send, &len_buf, frame_bytes, self.write_timeout).await
            }
            None => Err(std::io::Error::other("send half closed")),
        };
        if result.is_err() {
            self.abort();
        }
        result
    }

    fn abort(&mut self) {
        self.reset_flag.store(true, Ordering::Release);
        if let Some(mut send) = self.send.take() {
            let _ = send.reset(STREAM_ERROR_CODE.into());
        }
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(STREAM_ERROR_CODE.into());
        }
    }
}

impl crate::transport::Stream for IrohStream {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    type SendHalf = IrohSendHalf;
    type RecvHalf = IrohRecvHalf;

    fn split(mut self) -> (Self::SendHalf, Self::RecvHalf) {
        let send = self.send.take().expect("send already taken");
        let recv = self.recv.take().expect("recv already taken");
        let flag = self.reset_flag.clone();
        let flag2 = self.reset_flag.clone();
        (
            IrohSendHalf {
                send: Some(send),
                reset_flag: flag,
                write_timeout: self.write_timeout,
            },
            IrohRecvHalf {
                recv: Some(recv),
                read_buf: std::mem::take(&mut self.prefix),
                trailer: None,
                reset_flag: flag2,
                done: false,
                first_frame_deadline: self
                    .first_frame_deadline
                    .take()
                    .map(n0_future::time::sleep_until)
                    .map(Box::pin),
                partial_frame_timeout: self.partial_frame_timeout,
                partial_frame_deadline: None,
            },
        )
    }

    fn reset(&mut self, _code: WireCode) {
        self.abort();
    }
}

pub struct IrohSendHalf {
    send: Option<SendStream>,
    reset_flag: Arc<AtomicBool>,
    write_timeout: Duration,
}

impl IrohSendHalf {
    async fn write_framed(&mut self, frame: Frame) -> std::io::Result<()> {
        let frame_bytes = encode_outbound_frame(&frame)?;
        let write_timeout = self.write_timeout;
        let mut len_buf = BytesMut::with_capacity(10);
        write_varint(frame_bytes.len() as u64, &mut len_buf);
        let result = match self.send.as_mut() {
            Some(send) => {
                write_frame_with_timeout(send, &len_buf, &frame_bytes, write_timeout).await
            }
            None => Err(std::io::Error::other("send half closed")),
        };
        // A handler can finish after reading the request body, before the
        // caller writes End. Dropping its QUIC receive stream sends
        // STOP_SENDING(0): the send direction is already closed normally.
        // Only End may accept this; body writes and nonzero stops still fail.
        if matches!(frame, Frame::End(_))
            && matches!(
                result.as_ref().err().and_then(|error| error.get_ref())
                    .and_then(|error| error.downcast_ref::<iroh::endpoint::WriteError>()),
                Some(iroh::endpoint::WriteError::Stopped(code)) if *code == 0_u32.into()
            )
        {
            self.send.take();
            return Ok(());
        }
        if result.is_err() {
            self.reset_flag.store(true, Ordering::Release);
            if let Some(mut send) = self.send.take() {
                let _ = send.reset(STREAM_ERROR_CODE.into());
            }
        }
        result
    }
}

impl Drop for IrohSendHalf {
    fn drop(&mut self) {
        if self.reset_flag.load(Ordering::Acquire)
            && let Some(mut send) = self.send.take()
        {
            let _ = send.reset(STREAM_ERROR_CODE.into());
        }
    }
}

impl crate::transport::SendHalf for IrohSendHalf {
    type Error = std::io::Error;

    async fn stopped(&mut self) {
        if let Some(send) = self.send.as_mut() {
            let _ = send.stopped().await;
        }
    }

    async fn send_body(&mut self, payload: Bytes) -> Result<(), Self::Error> {
        self.write_framed(Frame::Body(payload)).await
    }

    async fn close_send(&mut self, trailer: Option<Trailer>) -> Result<(), Self::Error> {
        let trailer = trailer.unwrap_or_default();
        self.write_framed(Frame::End(EndFrame {
            status: trailer.status,
            trailer,
        }))
        .await?;
        if let Some(mut s) = self.send.take() {
            let _ = s.finish();
        }
        Ok(())
    }

    fn reset(&mut self, _code: WireCode) {
        if let Some(mut s) = self.send.take() {
            let _ = s.reset(STREAM_ERROR_CODE.into());
        }
        self.reset_flag.store(true, Ordering::Release);
    }
}

pub struct IrohRecvHalf {
    recv: Option<RecvStream>,
    read_buf: BytesMut,
    trailer: Option<Trailer>,
    reset_flag: Arc<AtomicBool>,
    done: bool,
    first_frame_deadline: Option<Pin<Box<n0_future::time::Sleep>>>,
    partial_frame_timeout: Duration,
    partial_frame_deadline: Option<Pin<Box<n0_future::time::Sleep>>>,
}

impl IrohRecvHalf {
    fn abort(&mut self, code: WireCode, message: &'static str) {
        self.done = true;
        self.first_frame_deadline = None;
        self.partial_frame_deadline = None;
        self.reset_flag.store(true, Ordering::Release);
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(STREAM_ERROR_CODE.into());
        }
        self.trailer = Some(Trailer::from_status(code, message));
    }
}

impl FuturesStream for IrohRecvHalf {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            // Try to decode a frame from the buffer.
            match try_pop_frame(&mut this.read_buf) {
                Ok(Some(frame)) => {
                    // Only an accepted stream has the first-frame deadline.
                    // Once a complete frame arrives, handler time and idle
                    // time between frames remain unrestricted. The separate
                    // partial-frame deadline only runs while an incomplete
                    // frame is buffered, on both client and server streams.
                    this.first_frame_deadline = None;
                    this.partial_frame_deadline = (!this.read_buf.is_empty())
                        .then(|| Box::pin(n0_future::time::sleep(this.partial_frame_timeout)));
                    match frame {
                        Frame::Body(b) => return Poll::Ready(Some(Ok(b))),
                        Frame::End(end) => {
                            this.trailer = Some(end.trailer);
                            this.done = true;
                            return Poll::Ready(None);
                        }
                        Frame::Reset(r) => {
                            this.abort(r.code, "reset");
                            return Poll::Ready(None);
                        }
                        Frame::Open(_) | Frame::Credit(_) => {
                            this.abort(WireCode::Internal, "unexpected frame");
                            return Poll::Ready(Some(Err(std::io::Error::other(
                                "unexpected frame on iroh stream",
                            ))));
                        }
                    }
                }
                Ok(None) => { /* fall through to read more bytes */ }
                Err(e) => {
                    // Fatal parse error (malformed varint, oversized
                    // length, decode failure). The wire is poisoned;
                    // stop reading, signal end, and stash a synthetic
                    // trailer so trailer-aware consumers see the
                    // protocol failure rather than a silent close.
                    this.abort(WireCode::Internal, "frame decode error");
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "frame decode: {e}"
                    )))));
                }
            }

            if this
                .first_frame_deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
            {
                this.abort(WireCode::DeadlineExceeded, "first request frame timed out");
                return Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "first request frame timed out",
                ))));
            }

            if this
                .partial_frame_deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
            {
                this.abort(WireCode::DeadlineExceeded, "incomplete frame timed out");
                return Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "incomplete frame timed out",
                ))));
            }

            let mut tmp_box: Box<[u8; 8192]> = Box::new([0u8; 8192]);
            let read = {
                let Some(recv) = this.recv.as_mut() else {
                    this.done = true;
                    return Poll::Ready(None);
                };
                let read_fut = recv.read(&mut *tmp_box);
                tokio::pin!(read_fut);
                match read_fut.as_mut().poll(cx) {
                    Poll::Ready(result) => result,
                    Poll::Pending => return Poll::Pending,
                }
            };
            let n = match read {
                Ok(Some(n)) => n,
                Ok(None) => {
                    this.abort(WireCode::Internal, "stream ended without End frame");
                    return Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "iroh stream ended without End frame",
                    ))));
                }
                Err(error) => {
                    this.abort(WireCode::Internal, "iroh receive error");
                    return Poll::Ready(Some(Err(std::io::Error::other(format!(
                        "iroh recv: {error}"
                    )))));
                }
            };
            this.read_buf.extend_from_slice(&tmp_box[..n]);
            if this.partial_frame_deadline.is_none() {
                this.partial_frame_deadline =
                    Some(Box::pin(n0_future::time::sleep(this.partial_frame_timeout)));
            }
        }
    }
}

impl Drop for IrohRecvHalf {
    fn drop(&mut self) {
        if self.reset_flag.load(Ordering::Acquire)
            && let Some(mut recv) = self.recv.take()
        {
            let _ = recv.stop(STREAM_ERROR_CODE.into());
        }
    }
}

impl crate::transport::RecvHalf for IrohRecvHalf {
    type Error = std::io::Error;

    fn trailer(&self) -> Option<&Trailer> {
        self.trailer.as_ref()
    }

    fn reset(&mut self, _code: WireCode) {
        if let Some(mut r) = self.recv.take() {
            let _ = r.stop(STREAM_ERROR_CODE.into());
        }
        self.reset_flag.store(true, Ordering::Release);
        self.done = true;
        if self.trailer.is_none() {
            self.trailer = Some(Trailer::from_status(WireCode::Cancelled, "local reset"));
        }
    }
}

/// Tri-state parse of the next length-prefixed frame.
///
/// - `Ok(Some(frame))` — decoded; the bytes have been split off `buf`.
/// - `Ok(None)` — need more bytes; varint or body is truncated.
/// - `Err(_)` — fatal: corrupt varint or oversized announced length.
///   Caller must abort the stream; buffering more bytes cannot recover.
fn try_pop_frame(buf: &mut BytesMut) -> Result<Option<Frame>, FrameError> {
    let (len, consumed) = match read_varint_partial(buf)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let len = bounded_frame_len(len)?;
    if buf.len() < consumed + len {
        return Ok(None);
    }
    let frame_bytes = buf.split_to(consumed + len);
    let frame = decode_frame(&frame_bytes[consumed..])?;
    Ok(Some(frame))
}

fn encode_outbound_frame(frame: &Frame) -> std::io::Result<BytesMut> {
    let len = encoded_frame_len(frame).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid outbound iroh frame: {error}"),
        )
    })?;
    let mut encoded = BytesMut::with_capacity(len);
    encode_frame(frame, &mut encoded);
    debug_assert_eq!(encoded.len(), len);
    Ok(encoded)
}

async fn write_frame_with_timeout(
    send: &mut SendStream,
    length: &[u8],
    frame: &[u8],
    timeout: Duration,
) -> std::io::Result<()> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "iroh frame length {} exceeds wire cap {MAX_FRAME_BYTES}",
                frame.len()
            ),
        ));
    }
    let write = async {
        send.write_all(length).await?;
        send.write_all(frame).await
    };
    match n0_future::time::timeout(timeout, write).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(std::io::Error::other(error)),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "iroh frame write timed out",
        )),
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn malformed_varint_is_fatal_not_buffer_growth() {
        // Old behaviour: every varint error collapsed to Ok(None), so
        // the recv loop kept extending the read buffer waiting for
        // more bytes — a peer could send 0xFF repeatedly and OOM us.
        // New behaviour: 10 continuation bytes is fatal.
        let mut buf = BytesMut::from(&[0xFFu8; 10][..]);
        let err = try_pop_frame(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::BadVarint));
        // Buffer is NOT consumed on fatal error — the caller decides
        // to abort, no point in advancing.
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn oversized_announced_length_is_fatal_before_buffering() {
        // A peer announces u64::MAX as the frame length. We must reject
        // BEFORE attempting to wait for that many bytes.
        let mut buf = BytesMut::new();
        write_varint(u64::MAX, &mut buf);
        let err = try_pop_frame(&mut buf).unwrap_err();
        assert!(matches!(err, FrameError::OversizedFrame { len: _, cap: _ }));
    }

    #[test]
    fn truncated_varint_is_recoverable() {
        // A varint can legitimately straddle a TCP/QUIC read boundary.
        // ≤ 9 continuation bytes is "need more bytes", not fatal.
        for n in 1usize..=9 {
            let buf_data = vec![0xFFu8; n];
            let mut buf = BytesMut::from(&buf_data[..]);
            let out = try_pop_frame(&mut buf).unwrap();
            assert!(out.is_none(), "n={n} should be recoverable");
            // Buffer is preserved across the partial read.
            assert_eq!(buf.len(), n);
        }
    }
}
