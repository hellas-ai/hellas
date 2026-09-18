//! Unix socket adapter over the shared length-delimited message pipe.

pub use crate::framed::{DEFAULT_MAX_MESSAGE_BYTES, LengthDelimitedMessagePipe};
use std::{io, path::Path};
use tokio::net::UnixStream;
mod server;
pub use server::{LOCAL_MUX_SLOTS, LocalControlServer, connect, transport};

pub type UnixMessagePipe = LengthDelimitedMessagePipe<UnixStream>;

impl LengthDelimitedMessagePipe<UnixStream> {
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::new(UnixStream::connect(path).await?, DEFAULT_MAX_MESSAGE_BYTES)
    }
}
