//! Private Unix listener; the host authenticates each admitted connection.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::future::Future;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::TransportContext;
use crate::local::{ListenerTask, serve_accepted, transport};
use crate::mux::{MuxTransport, Role};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

/// Open a byte stream for the caller's application authentication. The socket
/// path supplies neither server trust nor application permission.
pub async fn connect_stream(path: impl AsRef<Path>) -> io::Result<UnixStream> {
    UnixStream::connect(path).await
}

pub async fn connect(path: impl AsRef<Path>) -> io::Result<MuxTransport> {
    transport(
        connect_stream(path).await?,
        Role::Client,
        TransportContext::default(),
    )
}

/// Dropping this handle closes the listener/connections and unlinks only the
/// socket it created. Existing paths are never overwritten, including stale
/// sockets left by a crashed process.
pub struct LocalControlServer {
    task: ListenerTask,
    _socket: SocketPath,
}

struct SocketPath {
    socket: PathBuf,
    device: u64,
    inode: u64,
}

impl LocalControlServer {
    pub fn bind<H, F>(path: impl AsRef<Path>, handler: H) -> io::Result<Self>
    where
        H: Fn(UnixStream) -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = std::fs::symlink_metadata(parent)?;
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let uid = unsafe { libc::geteuid() };
        if !parent.is_dir() || parent.uid() != uid || parent.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control socket parent must be owned by this user with mode 0700",
            ));
        }
        let listener = UnixListener::bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        let socket = SocketPath {
            socket: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve_accepted(
            async move || {
                let (stream, _) = listener.accept().await?;
                Ok(stream
                    .peer_cred()
                    .is_ok_and(|cred| cred.uid() == uid)
                    .then_some(stream))
            },
            handler,
            stopped,
        ));
        Ok(Self {
            task: ListenerTask {
                stop: Some(stop),
                task,
            },
            _socket: socket,
        })
    }

    /// Stop admission, cancel and join every connection, then unlink this socket.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.task.shutdown().await
    }

    /// Wait for listener failure or completion. Cancellation leaves the listener running.
    pub async fn wait(&mut self) -> io::Result<()> {
        self.task.wait().await
    }

    /// Stop admission and finish every accepted handler. Hosts must bound their
    /// own request/idle lifetime; unlike shutdown, this does not cancel work.
    pub async fn drain(mut self) -> io::Result<()> {
        self.task.drain().await
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.socket)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}
