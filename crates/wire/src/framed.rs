//! Length-delimited byte-stream carrier for the existing message multiplexer.
//! Usable with serial, duplex streams, or Unix sockets implementing Tokio I/O.

use std::io;

use bytes::{Buf as _, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::mux::MessagePipe;

/// Default maximum encoded mux frame accepted on a byte stream (2 MiB).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// A bounded message pipe over an asynchronous byte stream.
pub struct LengthDelimitedMessagePipe<S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    max_message_bytes: usize,
    /// Bytes read but not yet returned as a message. Keeping them here, not
    /// in a future's locals, is what makes `recv_message` cancel-safe.
    read_buffer: BytesMut,
}

impl<S> LengthDelimitedMessagePipe<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, max_message_bytes: usize) -> io::Result<Self> {
        if max_message_bytes == 0 || max_message_bytes > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "framed message limit must be in 1..=u32::MAX",
            ));
        }
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader,
            writer,
            max_message_bytes,
            read_buffer: BytesMut::with_capacity(8 * 1024),
        })
    }

    fn checked_len(&self, len: usize) -> io::Result<u32> {
        if len > self.max_message_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "framed message is {len} bytes, limit is {}",
                    self.max_message_bytes
                ),
            ));
        }
        u32::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "framed message length exceeds u32",
            )
        })
    }
}

impl<S> MessagePipe for LengthDelimitedMessagePipe<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type SendError = io::Error;
    type RecvError = io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> io::Result<()> {
        let len = self.checked_len(bytes.len())?;
        self.writer.write_all(&len.to_be_bytes()).await?;
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await
    }

    /// Cancel-safe: the mux driver polls this inside `select!`, so it is
    /// routinely dropped mid-frame when a command wins the race. Every byte
    /// read goes straight into `read_buffer`, so a dropped call loses
    /// nothing; the next call resumes the same frame. (A `read_exact` into a
    /// local lost the partial frame and desynchronized the stream whenever a
    /// frame spanned more than one read -- small socket or pipe buffers, or a
    /// slow link -- killing the transport mid-response.)
    async fn recv_message(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            if self.read_buffer.len() >= 4 {
                let prefix: [u8; 4] = self.read_buffer[..4].try_into().expect("four bytes");
                let len = u32::from_be_bytes(prefix) as usize;
                self.checked_len(len)?;
                if self.read_buffer.len() >= 4 + len {
                    self.read_buffer.advance(4);
                    return Ok(Some(self.read_buffer.split_to(len).freeze()));
                }
                self.read_buffer.reserve(4 + len - self.read_buffer.len());
            }
            if self.reader.read_buf(&mut self.read_buffer).await? == 0 {
                return if self.read_buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream ended inside a framed message",
                    ))
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_message_boundaries() {
        let (left, right) = tokio::io::duplex(128);
        let mut sender = LengthDelimitedMessagePipe::new(left, 64).unwrap();
        let mut receiver = LengthDelimitedMessagePipe::new(right, 64).unwrap();

        sender
            .send_message(Bytes::from_static(b"first"))
            .await
            .unwrap();
        sender
            .send_message(Bytes::from_static(b"second"))
            .await
            .unwrap();

        assert_eq!(receiver.recv_message().await.unwrap().unwrap(), "first");
        assert_eq!(receiver.recv_message().await.unwrap().unwrap(), "second");
    }

    /// A receive dropped mid-frame (as `select!` does in the mux driver)
    /// must not lose the bytes it already read.
    #[tokio::test]
    async fn a_cancelled_receive_resumes_the_same_frame() {
        let (mut left, right) = tokio::io::duplex(1024);
        let mut receiver = LengthDelimitedMessagePipe::new(right, 1024).unwrap();
        let message = b"a frame split across two reads";
        let mut framed = (message.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(message);

        left.write_all(&framed[..7]).await.unwrap();
        // Poll once so the partial frame is read, then drop the future.
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            receiver.recv_message(),
        )
        .await;
        assert!(cancelled.is_err(), "the frame is incomplete");

        left.write_all(&framed[7..]).await.unwrap();
        assert_eq!(
            receiver.recv_message().await.unwrap().unwrap(),
            &message[..]
        );
    }

    #[tokio::test]
    async fn eof_inside_a_frame_is_an_error_not_a_clean_close() {
        let (mut left, right) = tokio::io::duplex(1024);
        let mut receiver = LengthDelimitedMessagePipe::new(right, 1024).unwrap();
        left.write_all(&[0, 0, 0, 9, b'x']).await.unwrap();
        drop(left);
        let error = receiver.recv_message().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn rejects_oversized_outbound_messages() {
        let (left, _right) = tokio::io::duplex(128);
        let mut pipe = LengthDelimitedMessagePipe::new(left, 3).unwrap();
        let error = pipe
            .send_message(Bytes::from_static(b"four"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_oversized_inbound_prefix_before_allocating() {
        let (mut left, right) = tokio::io::duplex(128);
        let mut pipe = LengthDelimitedMessagePipe::new(right, 3).unwrap();
        left.write_all(&4_u32.to_be_bytes()).await.unwrap();
        let error = pipe.recv_message().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn clean_eof_is_not_a_truncated_frame() {
        let (left, right) = tokio::io::duplex(128);
        drop(left);
        let mut pipe = LengthDelimitedMessagePipe::new(right, 64).unwrap();
        assert!(pipe.recv_message().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_prefix_is_an_error() {
        let (mut left, right) = tokio::io::duplex(128);
        let mut pipe = LengthDelimitedMessagePipe::new(right, 64).unwrap();
        left.write_all(&[0, 0]).await.unwrap();
        left.shutdown().await.unwrap();
        let error = pipe.recv_message().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
