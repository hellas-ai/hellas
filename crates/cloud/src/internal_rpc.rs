//! Private Unix-socket JSON-RPC 2.0: one JSON object per line, bounded frames.
//! The socket is an owner-authorized local control surface, never a public service.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

use crate::management::{Request, Service, private_directory};

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
                Err(cause) if cause.is::<crate::accounts::RunpodAccountRequired>() => error(
                    id,
                    -32000,
                    &crate::accounts::RunpodAccountRequired.to_string(),
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
    ensure!(
        stream.peer_cred()?.uid() == unsafe { libc::geteuid() },
        "unauthorized local user"
    );
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
        ensure!(
            size as u64 <= MAX_FRAME && frame.ends_with(b"\n"),
            "invalid RPC frame"
        );
        if let Some(response) = dispatch(&service, &frame).await {
            let mut bytes = serde_json::to_vec(&response)?;
            ensure!(bytes.len() as u64 <= MAX_FRAME, "RPC response too large");
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
    private_directory(
        socket
            .parent()
            .context("socket needs a private directory")?,
    )?;
    let _lock = crate::config::lock_state(socket)?;
    if socket.try_exists()? {
        ensure!(
            std::fs::symlink_metadata(socket)?.file_type().is_socket(),
            "refusing to replace a non-socket path"
        );
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
    ensure!(
        stream.peer_cred()?.uid() == unsafe { libc::geteuid() },
        "unexpected local server user"
    );
    let (read, mut write) = stream.into_split();
    let mut value = serde_json::to_value(request)?;
    value["jsonrpc"] = json!("2.0");
    value["id"] = json!(1);
    let mut bytes = serde_json::to_vec(&value)?;
    ensure!(bytes.len() as u64 <= MAX_FRAME, "RPC request too large");
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
    ensure!(
        response.len() as u64 <= MAX_FRAME && response.ends_with(b"\n"),
        "invalid RPC response frame"
    );
    let response: Value = serde_json::from_slice(&response)?;
    ensure!(
        response["jsonrpc"] == "2.0" && response["id"] == 1,
        "invalid RPC response"
    );
    if response.get("error").is_some() {
        anyhow::bail!(
            "internal management RPC failed: {}",
            response["error"]["message"]
                .as_str()
                .unwrap_or("Management operation failed")
        );
    }
    response
        .get("result")
        .cloned()
        .context("RPC result missing")
}
