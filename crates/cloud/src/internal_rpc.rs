//! Private Unix-socket JSON-RPC 2.0: one JSON object per line, bounded frames.
//! The socket is an owner-authorized local control surface, never a public service.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

use crate::management::{Request, Service, private_directory};

pub type Result<T> = std::result::Result<T, RpcError>;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Directory(#[from] crate::management::DirectoryError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("unauthorized local user")]
    Unauthorized,
    #[error("invalid RPC frame")]
    Frame,
    #[error("RPC response too large")]
    ResponseBound,
    #[error("refusing to replace a non-socket path")]
    NotSocket,
    #[error("unexpected local server user")]
    ServerUser,
    #[error("RPC request too large")]
    RequestBound,
    #[error("invalid RPC response frame")]
    ResponseFrame,
    #[error("invalid RPC response")]
    Response,
    #[error("socket needs a private directory")]
    SocketParent,
    #[error("RPC result missing")]
    MissingResult,
    #[error("internal management RPC failed: {0}")]
    Remote(String),
}

const MAX_FRAME: u64 = 1024 * 1024;

pub fn default_socket(owner: &str) -> Result<PathBuf> {
    crate::config::validate_hex(owner)?;
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    Ok(base
        .join(format!(
            "hellas-{}-{}",
            unsafe { libc::geteuid() },
            &owner[..16]
        ))
        .join("control.sock"))
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":id, "error":{"code":code, "message":message}})
}

async fn dispatch(service: &Service, input: &[u8]) -> Option<Value> {
    let value: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return Some(error(Value::Null, -32700, "Parse error")),
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    if !value.is_object()
        || value["jsonrpc"] != "2.0"
        || !value["method"].is_string()
        || !(id.is_null() || id.is_string() || id.is_number())
    {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    let notification = value.get("id").is_none();
    let method = value["method"].as_str().unwrap();
    let known = matches!(
        method,
        "machines.list"
            | "machines.status"
            | "machines.resolve"
            | "machines.restart"
            | "machines.configure"
            | "machines.fetch"
            | "machines.prepare"
            | "machines.destroy"
            | "cloud.runpod"
    );
    let result = if !known {
        error(id.clone(), -32601, "Method not found")
    } else {
        let mut request = json!({"method":method});
        if method != "machines.list" {
            request["params"] = value.get("params").cloned().unwrap_or(json!({}));
        }
        match serde_json::from_value::<Request>(request) {
            Err(_) => error(id.clone(), -32602, "Invalid params"),
            Ok(request) => match service.execute(request).await {
                Ok(result) => json!({"jsonrpc":"2.0", "id":id, "result":result}),
                // This typed setup hint contains only public, static text.
                Err(cause) if crate::accounts::AccountError::required(&cause).is_some() => error(
                    id,
                    -32000,
                    &crate::accounts::AccountError::required(&cause)
                        .expect("matched account error")
                        .to_string(),
                ),
                // Provider errors and malformed credential commands must never leak secrets.
                Err(_) => error(
                    id,
                    -32000,
                    "Management operation failed; inspect the machine with the CLI",
                ),
            },
        }
    };
    (!notification).then_some(result)
}

async fn connection(service: Arc<Service>, stream: UnixStream) -> Result<()> {
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Err(RpcError::Unauthorized);
    }
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    loop {
        let mut frame = Vec::new();
        let size = tokio::time::timeout(
            Duration::from_secs(30),
            (&mut read)
                .take(MAX_FRAME + 1)
                .read_until(b'\n', &mut frame),
        )
        .await??;
        if size == 0 {
            break;
        }
        if !(size as u64 <= MAX_FRAME && frame.ends_with(b"\n")) {
            return Err(RpcError::Frame);
        }
        if let Some(response) = dispatch(&service, &frame).await {
            let mut bytes = serde_json::to_vec(&response)?;
            if bytes.len() as u64 > MAX_FRAME {
                return Err(RpcError::ResponseBound);
            }
            bytes.push(b'\n');
            tokio::time::timeout(Duration::from_secs(30), write.write_all(&bytes)).await??;
        }
    }
    Ok(())
}

pub async fn serve(service: Service, socket: &Path) -> Result<()> {
    serve_until(service, socket, async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install management SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    })
    .await
}

pub async fn serve_until(
    service: Service,
    socket: &Path,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    private_directory(socket.parent().ok_or(RpcError::SocketParent)?)?;
    let _lock = crate::config::lock_state(socket)?;
    if socket.try_exists()? {
        if !std::fs::symlink_metadata(socket)?.file_type().is_socket() {
            return Err(RpcError::NotSocket);
        }
        std::fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _cleanup = Cleanup(socket.to_owned());
    let service = Arc::new(service);
    let slots = Arc::new(Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = listener.accept() => {
                let (stream, _) = incoming?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let service = service.clone();
                tasks.spawn(async move { let _permit = permit; let _ = connection(service, stream).await; });
            }
        }
    }
    // Finish in-flight allocations so disconnect/shutdown doesn't abandon a create response.
    // Idle readers time out after 30 seconds; receipts precede all cloud API calls.
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub async fn call(socket: &Path, request: Request) -> Result<Value> {
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Err(RpcError::ServerUser);
    }
    let (read, mut write) = stream.into_split();
    let mut value = serde_json::to_value(request)?;
    value["jsonrpc"] = json!("2.0");
    value["id"] = json!(1);
    let mut bytes = serde_json::to_vec(&value)?;
    if bytes.len() as u64 > MAX_FRAME {
        return Err(RpcError::RequestBound);
    }
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3600),
        BufReader::new(read)
            .take(MAX_FRAME + 1)
            .read_until(b'\n', &mut response),
    )
    .await??;
    if !(response.len() as u64 <= MAX_FRAME && response.ends_with(b"\n")) {
        return Err(RpcError::ResponseFrame);
    }
    let response: Value = serde_json::from_slice(&response)?;
    if !(response["jsonrpc"] == "2.0" && response["id"] == 1) {
        return Err(RpcError::Response);
    }
    if response.get("error").is_some() {
        return Err(RpcError::Remote(
            response["error"]["message"]
                .as_str()
                .unwrap_or("Management operation failed")
                .to_owned(),
        ));
    }
    response
        .get("result")
        .cloned()
        .ok_or(RpcError::MissingResult)
}
