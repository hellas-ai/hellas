//! Owner-authenticated Unix carrier for ordinary RPC dispatchers.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::local::{serve_accepted, transport};
use crate::mux::{MuxTransport, Role};
use crate::{Dispatcher, TransportContext};
use tokio::net::{UnixListener, UnixStream};

pub async fn connect(path: impl AsRef<Path>) -> io::Result<MuxTransport> {
    transport(
        UnixStream::connect(path).await?,
        Role::Client,
        TransportContext::default(),
    )
}

/// Dropping this handle closes the listener/connections and unlinks only the
/// socket it created. Existing paths are never overwritten, including stale
/// sockets left by a crashed process.
pub struct LocalControlServer {
    task: tokio::task::JoinHandle<()>,
    socket: PathBuf,
    device: u64,
    inode: u64,
}

impl LocalControlServer {
    pub fn bind<D>(path: impl AsRef<Path>, dispatcher: D) -> io::Result<Self>
    where
        D: Dispatcher<MuxTransport> + Send + Sync + 'static,
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
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(path)?;
        let task = tokio::spawn(serve_accepted(
            async move || {
                let (stream, _) = listener.accept().await?;
                Ok(stream
                    .peer_cred()
                    .is_ok_and(|cred| cred.uid() == uid)
                    .then_some(stream))
            },
            dispatcher,
        ));
        Ok(Self {
            task,
            socket: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for LocalControlServer {
    fn drop(&mut self) {
        self.task.abort();
        if let Ok(metadata) = std::fs::symlink_metadata(&self.socket)
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.socket);
        }
    }
}
