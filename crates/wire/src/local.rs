//! Private local carriers: a Unix socket or Windows named pipe.
//!
//! OS ownership limits admission, not application permissions. The host's
//! per-connection handler owns authentication and dispatch. The backends share
//! bounded connection ownership and shutdown here.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::framed::{DEFAULT_MAX_MESSAGE_BYTES, LengthDelimitedMessagePipe};
use crate::mux::{MuxConfig, MuxTransport, Role};
use crate::{DefaultClock, TransportContext};

#[cfg(windows)]
pub use crate::pipe::{LocalControlServer, connect, connect_stream, pipe_name};
#[cfg(unix)]
pub use crate::unix::{LocalControlServer, connect, connect_stream};
#[cfg(unix)]
pub use tokio::net::UnixStream as LocalStream;
#[cfg(windows)]
pub use tokio::net::windows::named_pipe::NamedPipeServer as LocalStream;

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

/// Accepts until `accept` fails, serving each admitted peer. `accept` yields
/// `Ok(None)` for a peer it refused; at the connection limit an admitted
/// peer is dropped too. Completion means every connection task has ended.
pub(crate) async fn serve_accepted<S, F>(
    mut accept: impl AsyncFnMut() -> io::Result<Option<S>>,
    handler: impl Fn(S) -> F,
    mut stopped: oneshot::Receiver<bool>,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mut connections = tokio::task::JoinSet::new();
    let mut drain = false;
    let mut result = loop {
        tokio::select! {
            biased;
            stopped = &mut stopped => {
                drain = stopped.unwrap_or_default();
                break Ok(());
            },
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    break Err(io::Error::other(error));
                }
            }
            accepted = accept() => match accepted {
                Ok(Some(stream)) if connections.len() < MAX_CONNECTIONS => {
                    connections.spawn(handler(stream));
                }
                Ok(_) => {}
                Err(error) => break Err(error),
            },
        }
    };
    if drain {
        while let Some(joined) = connections.join_next().await {
            if let Err(error) = joined {
                result = Err(io::Error::other(error));
            }
        }
    } else {
        connections.shutdown().await;
    }
    result
}

pub(crate) struct ListenerTask {
    pub stop: Option<oneshot::Sender<bool>>,
    pub task: JoinHandle<io::Result<()>>,
}
impl ListenerTask {
    pub async fn wait(&mut self) -> io::Result<()> {
        (&mut self.task).await.map_err(io::Error::other)?
    }
    pub async fn drain(&mut self) -> io::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        self.wait().await
    }
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stop.take();
        self.wait().await
    }
}

impl Drop for ListenerTask {
    fn drop(&mut self) {
        // Cancellation fallback; hosts needing a completed shutdown must await
        // shutdown(), which also joins the connection tasks.
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{pin_mut, poll};

    #[tokio::test]
    async fn draining_finishes_accepted_work_before_returning() {
        let (incoming, mut accepted) = tokio::sync::mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let (started, start) = oneshot::channel();
        let (finish, finishing) = oneshot::channel();
        let (completed, completion) = oneshot::channel();
        incoming.send((started, finishing, completed)).unwrap();
        let server = serve_accepted(
            async move || Ok(accepted.recv().await),
            |(started, finishing, completed): (
                oneshot::Sender<()>,
                oneshot::Receiver<()>,
                oneshot::Sender<()>,
            )| async move {
                started.send(()).unwrap();
                finishing.await.unwrap();
                completed.send(()).unwrap();
            },
            stopped,
        );
        pin_mut!(server);
        assert!(poll!(&mut server).is_pending());
        start.await.unwrap();
        stop.send(true).unwrap();
        assert!(poll!(&mut server).is_pending());
        finish.send(()).unwrap();
        server.await.unwrap();
        completion.await.unwrap();
    }
}
