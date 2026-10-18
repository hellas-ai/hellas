//! Private named-pipe carrier, the Windows counterpart of the Unix listener.
//!
//! Unix proves the peer with a 0700 directory, a 0600 socket and the peer's
//! uid. A pipe name is global, so here both ends authenticate each other:
//!
//! - the server creates every instance with an owner-only protected DACL, the
//!   first with `FILE_FLAG_FIRST_PIPE_INSTANCE` (so nobody can hold the name
//!   before us), and rejects remote clients;
//! - the server admits a client only if its process runs as this user;
//! - the client talks only to a server whose process runs as this user.
//!
//! These OS checks limit admission. The host still authenticates the application.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::time::Duration;

use hellas_private::windows::{OwnerOnly, process_is_current_user};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, HANDLE};
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};

use crate::TransportContext;
use crate::local::{ListenerTask, serve_accepted, transport};
use crate::mux::{MuxTransport, Role};

/// How long a client waits for a free server instance.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const PIPE_PREFIX: &str = r"\\.\pipe\";

/// The pipe standing for a local-control `path`: the path itself when it is
/// already `\\.\pipe\...`, otherwise a hash of the absolute path, so a client
/// and a server given the same socket path meet on the same pipe and distinct
/// paths never share one. Windows paths are case-insensitive and accept
/// either separator, so ASCII case and `/` are normalised first; the whole
/// normalised path is hashed, never a lossy rendering of it.
pub fn pipe_name(path: &Path) -> io::Result<OsString> {
    if path.as_os_str().to_string_lossy().starts_with(PIPE_PREFIX) {
        return Ok(path.as_os_str().to_owned());
    }
    let absolute = std::path::absolute(path)?;
    let mut hasher = blake3::Hasher::new();
    for unit in absolute.as_os_str().encode_wide() {
        let unit = match unit {
            0x2f => 0x5c,               // '/' -> '\'
            0x41..=0x5a => unit + 0x20, // ASCII upper -> lower
            _ => unit,
        };
        hasher.update(&unit.to_le_bytes());
    }
    Ok(format!("{PIPE_PREFIX}hellas-{}", hasher.finalize().to_hex()).into())
}

/// Fails unless the process behind `pid` runs as this user.
fn same_user(pid: io::Result<u32>, who: &str) -> io::Result<()> {
    if process_is_current_user(pid?)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("local-control pipe {who} runs as another user"),
        ))
    }
}

fn process_id(
    handle: HANDLE,
    query: unsafe extern "system" fn(HANDLE, *mut u32) -> i32,
) -> io::Result<u32> {
    let mut pid = 0;
    // SAFETY: `handle` is a live pipe handle for the call; `pid` is valid.
    if unsafe { query(handle, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

pub async fn connect(path: impl AsRef<Path>) -> io::Result<MuxTransport> {
    transport(
        connect_stream(path).await?,
        Role::Client,
        TransportContext::default(),
    )
}

/// Open an OS-admitted stream; the caller still authenticates the application.
pub async fn connect_stream(path: impl AsRef<Path>) -> io::Result<NamedPipeClient> {
    let name = pipe_name(path.as_ref())?;
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let client = loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => break client,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => return Err(error),
        }
    };
    same_user(
        process_id(
            client.as_raw_handle() as HANDLE,
            GetNamedPipeServerProcessId,
        ),
        "server",
    )?;
    Ok(client)
}

/// Dropping this handle closes the listener and its connections.
pub struct LocalControlServer {
    task: ListenerTask,
}

impl LocalControlServer {
    pub fn bind<H, F>(path: impl AsRef<Path>, handler: H) -> io::Result<Self>
    where
        H: Fn(NamedPipeServer) -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let name = pipe_name(path.as_ref())?;
        let security = OwnerOnly::new(false)?;
        let create = move |first: bool| -> io::Result<NamedPipeServer> {
            // SAFETY: the attributes point into `security`, which the closure
            // owns for as long as it can be called.
            unsafe {
                ServerOptions::new()
                    .first_pipe_instance(first)
                    .reject_remote_clients(true)
                    .create_with_security_attributes_raw(
                        &name,
                        security.security_attributes().cast(),
                    )
            }
        };
        // Created here, not in the task, so a squatted name fails `bind`.
        let mut listening = create(true)?;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(serve_accepted(
            async move || {
                listening.connect().await?;
                // Keep an instance listening before handing this one over.
                let client = std::mem::replace(&mut listening, create(false)?);
                let peer = process_id(
                    client.as_raw_handle() as HANDLE,
                    GetNamedPipeClientProcessId,
                );
                Ok(same_user(peer, "client").is_ok().then_some(client))
            },
            handler,
            stopped,
        ));
        Ok(Self {
            task: ListenerTask {
                stop: Some(stop),
                task,
            },
        })
    }

    /// Stop admission and cancel and join every connection before returning.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_paths_never_share_a_pipe() {
        // A lossy rendering (separators -> '-') made these collide.
        assert_ne!(
            pipe_name(Path::new(r"C:\Users\me\a\b")).unwrap(),
            pipe_name(Path::new(r"C:\Users\me\a-b")).unwrap()
        );
        assert_ne!(
            pipe_name(Path::new(r"C:\x:y")).unwrap(),
            pipe_name(Path::new(r"C:\x-y")).unwrap()
        );
    }

    #[test]
    fn one_path_spelled_differently_is_one_pipe() {
        let canonical = pipe_name(Path::new(r"C:\Users\Me\gate.sock")).unwrap();
        assert_eq!(
            canonical,
            pipe_name(Path::new(r"c:\users\me\GATE.SOCK")).unwrap()
        );
        assert_eq!(
            canonical,
            pipe_name(Path::new("C:/Users/Me/gate.sock")).unwrap()
        );
        let relative = Path::new("relative.sock");
        assert_eq!(
            pipe_name(relative).unwrap(),
            pipe_name(&std::env::current_dir().unwrap().join(relative)).unwrap()
        );
    }

    #[test]
    fn an_explicit_pipe_name_is_used_verbatim() {
        let explicit = Path::new(r"\\.\pipe\custom");
        assert_eq!(pipe_name(explicit).unwrap(), explicit.as_os_str());
        let name = pipe_name(Path::new(r"C:\a"))
            .unwrap()
            .into_string()
            .unwrap();
        assert!(name.starts_with(r"\\.\pipe\hellas-") && name.len() < 256);
    }
}
