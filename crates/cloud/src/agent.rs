use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{Endpoint, endpoint::presets};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::{Mutex, Semaphore},
};

use crate::{
    config::{Credentials, Enrollment, validate_hex},
    wire::{ALPN, MAX_MESSAGE, Operation, Request, Response},
};

pub struct AgentOptions {
    pub credentials: Credentials,
    pub data: PathBuf,
    pub cli: PathBuf,
    /// Original OCI entrypoint, including `serve` and GPU backend defaults.
    pub launcher: Vec<String>,
    pub serve_args: Vec<String>,
    pub bind: Option<SocketAddr>,
    pub no_relay: bool,
}

struct Process {
    child: Option<Child>,
    launcher: Vec<String>,
    args: Vec<String>,
    identity: PathBuf,
    owner: Option<String>,
    cli: PathBuf,
    configuration: Option<crate::configuration::InstalledConfiguration>,
}

impl Process {
    fn start(&mut self) -> Result<()> {
        let (program, args) = self
            .launcher
            .split_first()
            .context("empty Hellas launcher")?;
        let mut command = Command::new(program);
        command
            .args(args)
            .args(&self.args)
            .arg("--identity")
            .arg(&self.identity)
            .arg("--artifact-store-path")
            .arg(
                self.identity
                    .parent()
                    .context("identity needs a data directory")?
                    .join("artifacts"),
            )
            .args(["--assurance", "producer-signed"])
            .env_remove("HELLAS_REMOTE_KEY")
            .env_remove("HELLAS_REMOTE_TOKEN")
            .env_remove("HELLAS_REMOTE_ARGS")
            .env_remove("HELLAS_REMOTE_OWNER")
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::io::stderr()))
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if let Some(owner) = &self.owner {
            command.args(["--owner", owner]);
        }
        if let Some(configuration) = &self.configuration {
            command
                .arg("--fetch-config")
                .arg(&configuration.fetch_config)
                .envs(&configuration.env);
        }
        #[cfg(unix)]
        command.process_group(0);
        self.child = Some(command.spawn().context("start Hellas")?);
        Ok(())
    }

    fn running(&mut self) -> Result<bool> {
        Ok(match self.child.as_mut() {
            Some(child) => child.try_wait()?.is_none(),
            None => false,
        })
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take()
            && let Some(id) = child.id()
        {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(id as i32), libc::SIGTERM);
            }
            #[cfg(not(unix))]
            child.start_kill()?;
            if tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .is_err()
            {
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(id as i32), libc::SIGKILL);
                }
                child.kill().await?;
            }
        }
        Ok(())
    }

    async fn configure(
        &mut self,
        configuration: crate::configuration::Configuration,
    ) -> Result<(), &'static str> {
        configuration
            .validate()
            .map_err(|_| "invalid worker configuration")?;
        if self
            .args
            .iter()
            .any(|arg| arg.split('=').next() == Some("--fetch-config"))
        {
            return Err("managed configuration conflicts with a launch-time fetch config");
        }
        let parent = self.identity.parent().ok_or("missing data directory")?;
        let (candidate, installed) = configuration
            .stage(parent)
            .map_err(|_| "could not stage private worker configuration")?;
        // The worker's own CLI validates the exact config and credentials before
        // disrupting the running process. Validation output can contain secrets.
        let checked = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(&self.cli)
                .args(["serve", "--check-config", "--fetch-config"])
                .arg(&installed.fetch_config)
                .envs(&configuration.env)
                .env_remove("HELLAS_REMOTE_KEY")
                .env_remove("HELLAS_REMOTE_TOKEN")
                .env_remove("HELLAS_REMOTE_ARGS")
                .env_remove("HELLAS_REMOTE_OWNER")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(|_| "worker configuration validator timed out")?
        .map_err(|_| "could not run worker configuration validator")?;
        if !checked.success() {
            return Err("worker rejected fetch configuration");
        }
        let path = self.identity.with_file_name("configuration.json");
        self.stop()
            .await
            .map_err(|_| "could not stop worker for configuration")?;
        let previous = self.configuration.replace(installed);
        let applied = self
            .start()
            .map_err(|_| "could not start configured worker")
            .and_then(|()| {
                crate::config::save_private(&path, self.configuration.as_ref().unwrap(), false)
                    .map_err(|_| "could not persist worker configuration")
            });
        if let Err(error) = applied {
            self.stop()
                .await
                .map_err(|_| "could not stop worker during configuration rollback")?;
            self.configuration = previous;
            if let Some(previous) = &self.configuration {
                crate::config::save_private(&path, previous, false)
                    .map_err(|_| "could not restore previous worker configuration")?;
            } else {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err("could not remove failed worker configuration"),
                }
            }
            self.start()
                .map_err(|_| "could not restart worker after configuration rollback")?;
            return Err(error);
        }
        let _ = candidate.keep();
        if let Some(previous) = previous
            && let Some(directory) = previous.fetch_config.parent()
            && directory.parent() == self.identity.parent()
            && directory
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".worker-config-"))
        {
            let _ = std::fs::remove_dir_all(directory);
        }
        Ok(())
    }
}

async fn identity_command(cli: &Path, identity: &Path, operation: &str) -> Result<String> {
    let mut command = Command::new(cli);
    command.arg("--identity").arg(identity);
    if operation == "init" {
        command.arg("--software-root");
    }
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        command
            .args(["identity", operation])
            .env_remove("HELLAS_REMOTE_KEY")
            .env_remove("HELLAS_REMOTE_TOKEN")
            .env_remove("HELLAS_REMOTE_ARGS")
            .env_remove("HELLAS_REMOTE_OWNER")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "Hellas identity {operation} failed"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct State {
    token: String,
    owner: Option<iroh::EndpointId>,
    enrollment: Enrollment,
    process: Mutex<Process>,
    downloads: Semaphore,
    content: PathBuf,
}

impl State {
    async fn dispatch(&self, peer: iroh::EndpointId, request: Request) -> Response {
        if self.owner.is_some_and(|owner| owner != peer)
            || !bool::from(self.token.as_bytes().ct_eq(request.token.as_bytes()))
        {
            return Response::Error {
                message: "unauthorized".into(),
            };
        }
        let result: Result<Response> = async {
            match request.operation {
                Operation::Status => Ok(Response::Status {
                    enrollment: self.enrollment.clone(),
                    owner: self.owner.map(|owner| owner.to_string()),
                    running: self.process.lock().await.running()?,
                }),
                Operation::Restart => {
                    let mut process = self.process.lock().await;
                    process.stop().await?;
                    process.start()?;
                    Ok(Response::Status {
                        enrollment: self.enrollment.clone(),
                        owner: self.owner.map(|owner| owner.to_string()),
                        running: process.running()?,
                    })
                }
                Operation::Configure { configuration } => {
                    let mut process = self.process.lock().await;
                    // Only static stage labels cross this boundary, never the
                    // validator's output or errors containing credential paths.
                    if let Err(message) = process.configure(configuration).await {
                        return Ok(Response::Error {
                            message: message.into(),
                        });
                    }
                    Ok(Response::Status {
                        enrollment: self.enrollment.clone(),
                        owner: self.owner.map(|owner| owner.to_string()),
                        running: process.running()?,
                    })
                }
                Operation::Fetch { url, sha256, bytes } => {
                    let _permit = self
                        .downloads
                        .try_acquire()
                        .context("download already in progress")?;
                    fetch_content(&self.content, &url, &sha256, bytes).await?;
                    Ok(Response::Fetched { sha256, bytes })
                }
            }
        }
        .await;
        match result {
            Ok(response) => response,
            // reqwest errors can include signed URLs. Do not reflect them.
            Err(_) => Response::Error {
                message:
                    "operation failed; check arguments, child state, and content digest/length"
                        .into(),
            },
        }
    }
}

pub async fn run(options: AgentOptions) -> Result<()> {
    let secret = options.credentials.secret_key()?;
    tokio::fs::create_dir_all(&options.data).await?;
    // Refuse silent reassignment, including a restart that omits the owner.
    let binding = options.data.join("owner.json");
    let _lease = crate::config::lock_state(&binding)?;
    if binding.exists() {
        let saved: Option<String> = crate::config::read_json(&binding)?;
        ensure!(
            saved == options.credentials.owner,
            "machine owner changed; refusing startup"
        );
    } else {
        crate::config::save_private(&binding, &options.credentials.owner, true)?;
    }
    let content = options.data.join("content");
    tokio::fs::create_dir_all(&content).await?;
    let identity = options.data.join("identity");
    let configuration_path = options.data.join("configuration.json");
    let configuration: Option<crate::configuration::InstalledConfiguration> = configuration_path
        .exists()
        .then(|| crate::config::read_json(&configuration_path))
        .transpose()?;
    identity_command(&options.cli, &identity, "init").await?;
    let enrollment = Enrollment {
        node_id: identity_command(&options.cli, &identity, "show-node-id").await?,
        enrollment_id: identity_command(&options.cli, &identity, "show-enrollment-id").await?,
    };
    enrollment.validate()?;
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()]);
    if let Some(bind) = options.bind {
        builder = builder.bind_addr(bind)?;
    }
    if options.no_relay {
        builder = builder.relay_mode(iroh::RelayMode::Disabled);
    }
    let endpoint = builder.bind().await?;
    let mut process = Process {
        child: None,
        launcher: options.launcher,
        args: options.serve_args,
        identity,
        owner: options.credentials.owner.clone(),
        cli: options.cli,
        configuration,
    };
    process.start()?;
    let state = Arc::new(State {
        token: options.credentials.token,
        owner: options
            .credentials
            .owner
            .map(|owner| owner.parse())
            .transpose()?,
        enrollment,
        process: Mutex::new(process),
        content,
        downloads: Semaphore::new(1),
    });
    eprintln!("admin node: {}", endpoint.id());
    let slots = Arc::new(Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let Ok(permit) = slots.clone().try_acquire_owned() else { incoming.refuse(); continue; };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result: Result<()> = async {
                        let connection = tokio::time::timeout(Duration::from_secs(10), incoming).await??;
                        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), connection.accept_bi()).await??;
                        let bytes = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(MAX_MESSAGE)).await??;
                        let request: Request = serde_json::from_slice(&bytes)?;
                        let response = state.dispatch(connection.remote_id(), request).await;
                        send.write_all(&serde_json::to_vec(&response)?).await?;
                        send.finish()?;
                        // Keep the connection alive until the reply was consumed.
                        let _ = tokio::time::timeout(Duration::from_secs(10), connection.closed()).await;
                        Ok(())
                    }.await;
                    // Invalid unauthenticated traffic is intentionally not logged.
                    let _ = result;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let stopped = state.process.lock().await.stop().await;
    endpoint.close().await;
    stopped
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

pub fn validate_download(url: &str, sha256: &str, bytes: u64) -> Result<reqwest::Url> {
    validate_hex(sha256)?;
    ensure!(
        bytes > 0 && bytes <= 1024 * 1024 * 1024 * 1024,
        "expected size must be 1 byte..1 TiB"
    );
    let url = reqwest::Url::parse(url)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "content URL must be HTTPS without userinfo or fragment"
    );
    Ok(url)
}

pub async fn fetch_content(root: &Path, url: &str, sha256: &str, bytes: u64) -> Result<()> {
    let url = validate_download(url, sha256, bytes)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(3500))
        .build()?;
    let response = client.get(url).send().await?;
    receive_content(root, response, sha256, bytes).await
}

async fn receive_content(
    root: &Path,
    mut response: reqwest::Response,
    sha256: &str,
    bytes: u64,
) -> Result<()> {
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "download requires HTTP 200; redirects are refused"
    );
    if let Some(length) = response.content_length() {
        ensure!(length == bytes, "content length mismatch");
    }
    // Stage outside the indexed content tree. Cancellation/errors remove the temp
    // file; only an exact length+digest match becomes visible to Hellas.
    let temp =
        tempfile::NamedTempFile::new_in(root.parent().context("content root needs a parent")?)?;
    let mut file = tokio::fs::File::from_std(temp.reopen()?);
    let mut hash = Sha256::new();
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await? {
        received = received
            .checked_add(chunk.len() as u64)
            .context("size overflow")?;
        ensure!(received <= bytes, "download exceeds declared size");
        hash.update(&chunk);
        file.write_all(&chunk).await?;
    }
    ensure!(
        received == bytes && hex::encode(hash.finalize()) == sha256,
        "download length or digest mismatch"
    );
    file.sync_all().await?;
    drop(file);
    let destination = root.join(sha256);
    match temp.persist_noclobber(&destination) {
        Ok(_) => {
            std::fs::File::open(root)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!("content already exists; no existing content was replaced")
        }
        Err(error) => Err(error.error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    async fn response(body: &'static [u8]) -> reqwest::Response {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        });
        reqwest::get(format!("http://{addr}")).await.unwrap()
    }

    #[tokio::test]
    async fn only_verified_content_is_published_and_existing_content_is_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("content");
        std::fs::create_dir(&root).unwrap();
        let hash = hex::encode(Sha256::digest(b"hello"));
        assert!(
            receive_content(&root, response(b"hello").await, &"0".repeat(64), 5)
                .await
                .is_err()
        );
        assert!(
            receive_content(&root, response(b"hello").await, &hash, 4)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        receive_content(&root, response(b"hello").await, &hash, 5)
            .await
            .unwrap();
        assert_eq!(std::fs::read(root.join(&hash)).unwrap(), b"hello");
        assert!(
            receive_content(&root, response(b"hello").await, &hash, 5)
                .await
                .is_err()
        );
    }
}
