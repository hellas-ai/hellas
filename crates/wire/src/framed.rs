//! Length-delimited byte-stream carrier for the existing message multiplexer.
//! Usable with serial, duplex streams, or Unix sockets implementing Tokio I/O.

use std::io;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::mux::MessagePipe;

/// Default maximum encoded mux frame accepted on a byte stream (2 MiB).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// A bounded message pipe over an asynchronous byte stream.
pub struct LengthDelimitedMessagePipe<S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    max_message_bytes: usize,
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

    async fn recv_message(&mut self) -> io::Result<Option<Bytes>> {
        let mut prefix = [0_u8; 4];
        if self.reader.read(&mut prefix[..1]).await? == 0 {
            return Ok(None);
        }
        self.reader.read_exact(&mut prefix[1..]).await?;
        let len = u32::from_be_bytes(prefix) as usize;
        self.checked_len(len)?;
        let mut body = vec![0; len];
        self.reader.read_exact(&mut body).await?;
        Ok(Some(Bytes::from(body)))
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
