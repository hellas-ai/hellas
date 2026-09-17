//! Owner-authenticated Unix carrier for ordinary RPC dispatchers.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::mux::{MuxConfig, MuxTransport, Role};
use crate::unix::{DEFAULT_MAX_MESSAGE_BYTES, UnixMessagePipe};
use crate::{AuthLevel, DefaultClock, Dispatcher, StreamTransport, TransportContext};
use tokio::net::{UnixListener, UnixStream};

pub const LOCAL_MUX_SLOTS: usize = 32;

pub fn transport(
    stream: UnixStream,
    role: Role,
    context: TransportContext,
) -> io::Result<MuxTransport> {
    Ok(MuxTransport::spawn::<LOCAL_MUX_SLOTS, _, _>(
        role,
        DefaultClock,
        MuxConfig::default(),
        UnixMessagePipe::new(stream, DEFAULT_MAX_MESSAGE_BYTES)?,
        context,
    ))
}

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
        let dispatcher = Arc::new(dispatcher);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Ok((stream, _)) = incoming else {
                            break;
                        };
                        if connections.len() >= 16
                            || !stream.peer_cred().is_ok_and(|cred| cred.uid() == uid)
                        {
                            continue;
                        }
                        let dispatcher = dispatcher.clone();
                        connections.spawn(async move {
                            let Ok(transport) = transport(
                                stream, Role::Server, TransportContext {
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
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
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
