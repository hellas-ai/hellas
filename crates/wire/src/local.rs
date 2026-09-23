//! The owner-only local-control transport for this platform: a Unix socket
//! ([`crate::unix`]) or a named pipe on Windows ([`crate::pipe`]).
//!
//! Everything but accepting and authenticating a peer lives here, once: the
//! mux over the byte stream, the per-connection dispatch loop, and the
//! connection limit. The backends supply only the OS-specific accept.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::framed::{DEFAULT_MAX_MESSAGE_BYTES, LengthDelimitedMessagePipe};
use crate::mux::{MuxConfig, MuxTransport, Role};
use crate::{AuthLevel, DefaultClock, Dispatcher, StreamTransport, TransportContext};

#[cfg(windows)]
pub use crate::pipe::{LocalControlServer, connect, pipe_name};
#[cfg(unix)]
pub use crate::unix::{LocalControlServer, connect};

pub const LOCAL_MUX_SLOTS: usize = 32;

/// Concurrent connections one local-control server serves.
const MAX_CONNECTIONS: usize = 16;

/// The mux over any local byte stream: a socket, a pipe, or an in-memory
/// duplex in tests.
pub fn transport<S>(stream: S, role: Role, context: TransportContext) -> io::Result<MuxTransport>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(MuxTransport::spawn::<LOCAL_MUX_SLOTS, _, _>(
        role,
        DefaultClock,
        MuxConfig::default(),
        LengthDelimitedMessagePipe::new(stream, DEFAULT_MAX_MESSAGE_BYTES)?,
        context,
    ))
}

/// Serves one connection whose peer is already known to be this user, until
/// it closes or a dispatch fails.
pub async fn serve_connection<S, D>(stream: S, dispatcher: Arc<D>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: Dispatcher<MuxTransport> + Send + Sync + 'static,
{
    let Ok(transport) = transport(
        stream,
        Role::Server,
        TransportContext {
            auth_level: AuthLevel::LocalOwner,
            ..TransportContext::default()
        },
    ) else {
        return;
    };
    while let Ok(Some(inbound)) = transport.accept().await {
        if dispatcher.dispatch(inbound).await.is_err() {
            break;
        }
    }
}

/// Accepts until `accept` fails, serving each admitted peer. `accept` yields
/// `Ok(None)` for a peer it refused; at the connection limit an admitted
/// peer is dropped too.
pub(crate) async fn serve_accepted<S, D>(
    mut accept: impl AsyncFnMut() -> io::Result<Option<S>>,
    dispatcher: D,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: Dispatcher<MuxTransport> + Send + Sync + 'static,
{
    let dispatcher = Arc::new(dispatcher);
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = accept() => match accepted {
                Ok(Some(stream)) if connections.len() < MAX_CONNECTIONS => {
                    connections.spawn(serve_connection(stream, dispatcher.clone()));
                }
                Ok(_) => {}
                Err(_) => break,
            },
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}
