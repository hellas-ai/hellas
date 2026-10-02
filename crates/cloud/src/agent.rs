use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

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

pub type Result<T> = std::result::Result<T, AgentError>;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Configuration(#[from] crate::configuration::ConfigurationError),
    #[error(transparent)]
    Directory(#[from] crate::management::DirectoryError),
    #[error(transparent)]
    ManagedGrant(#[from] crate::managed_grants::ManagedGrantError),
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[error(transparent)]
    Grant(#[from] hellas_rpc::protocol::work_grant::records::GrantError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Key(#[from] iroh::KeyParsingError),
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    BindAddress(#[from] iroh::endpoint::InvalidSocketAddr),
    #[error(transparent)]
    Connecting(#[from] iroh::endpoint::ConnectingError),
    #[error(transparent)]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error(transparent)]
    Write(#[from] iroh::endpoint::WriteError),
    #[error(transparent)]
    Read(#[from] iroh::endpoint::ReadToEndError),
    #[error(transparent)]
    Closed(#[from] iroh::endpoint::ClosedStream),
    #[error("Hellas exited before grant provider became ready")]
    EarlyExit,
    #[error("worker enrollment exceeds its bound")]
    EnrollmentBound,
    #[error("worker enrollment export failed")]
    EnrollmentExport,
    #[error("machine owner changed; refusing startup")]
    OwnerChanged,
    #[error("empty Hellas launcher")]
    EmptyLauncher,
    #[error("enrollment stdout missing")]
    EnrollmentStdout,
    #[error("managed configuration conflicts with a launch-time fetch config")]
    LaunchConfiguration,
    #[error("worker rejected resource configuration")]
    ConfigurationRejected,
    #[error("start Hellas")]
    Spawn(#[source] std::io::Error),
    #[error("grant provider readiness timed out")]
    ReadinessTimeout(#[source] tokio::time::error::Elapsed),
    #[error("worker enrollment export timed out")]
    EnrollmentTimeout(#[source] tokio::time::error::Elapsed),
    #[error("download already in progress")]
    DownloadBusy(#[source] tokio::sync::TryAcquireError),
    #[error("worker configuration validator timed out")]
    ValidatorTimeout(#[source] tokio::time::error::Elapsed),
    #[error("could not run worker configuration validator")]
    ValidatorSpawn(#[source] std::io::Error),
    #[error("Hellas identity {operation} failed")]
    IdentityCommand { operation: String },
    #[error("worker configuration failed and rollback failed: {rollback}")]
    Rollback {
        source: Box<AgentError>,
        rollback: Box<AgentError>,
    },
}

pub struct AgentOptions {
    pub credentials: Credentials,
    pub data: PathBuf,
    /// Separate private filesystem for credentials when the data volume lacks Unix modes.
    pub configuration_dir: Option<PathBuf>,
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
    owner_enrollment: Option<PathBuf>,
    bootstrap_grants: PathBuf,
    cli: PathBuf,
    configuration: Option<crate::configuration::InstalledConfiguration>,
    configuration_dir: PathBuf,
}

impl Process {
    async fn start(&mut self) -> Result<()> {
        crate::managed_grants::reclaim_socket(&self.configuration_dir.join("control.sock"))?;
        let (program, args) = self
            .launcher
            .split_first()
            .ok_or(AgentError::EmptyLauncher)?;
        let mut command = Command::new(program);
        command
            .args(args)
            .args(&self.args)
            .arg("--identity")
            .arg(&self.identity)
            .args(["--assurance", "producer-signed"])
            .env_remove("HELLAS_REMOTE_KEY")
            .env_remove("HELLAS_REMOTE_TOKEN")
            .env_remove("HELLAS_REMOTE_ARGS")
            .env_remove("HELLAS_REMOTE_OWNER")
            .env_remove("HELLAS_REMOTE_OWNER_ENROLLMENT")
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::io::stderr()))
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if let Some(owner) = &self.owner_enrollment {
            command.arg("--owner-enrollment").arg(owner);
        }
        command.arg("--grant-config").arg(
            self.configuration
                .as_ref()
                .map(|c| &c.grant_config)
                .unwrap_or(&self.bootstrap_grants),
        );
        if let Some(configuration) = &self.configuration {
            command
                .arg("--fetch-config")
                .arg(&configuration.fetch_config)
                .envs(&configuration.env);
        }
        #[cfg(unix)]
        command.process_group(0);
        self.child = Some(command.spawn().map_err(AgentError::Spawn)?);
        let ready = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if !self.running()? {
                    return Err(AgentError::EarlyExit);
                }
                if crate::managed_grants::ready(&self.configuration_dir.join("control.sock"))
                    .await
                    .is_ok()
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(AgentError::ReadinessTimeout)
        .and_then(|result| result);
        if ready.is_err() {
            self.stop().await?;
        }
        ready
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
            match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
                Ok(result) => {
                    result?;
                }
                Err(_) => {
                    #[cfg(unix)]
                    unsafe {
                        libc::kill(-(id as i32), libc::SIGKILL);
                    }
                    child.kill().await?;
                }
            }
        }
        Ok(())
    }

    async fn configure(
        &mut self,
        configuration: crate::configuration::Configuration,
    ) -> Result<()> {
        configuration.validate()?;
        if self
            .args
            .iter()
            .any(|arg| arg.split('=').next() == Some("--fetch-config"))
        {
            return Err(AgentError::LaunchConfiguration);
        }
        let (candidate, installed) = configuration.stage(&self.configuration_dir)?;
        // The worker validates the exact files before disrupting the current process.
        // Its output can contain credentials and must not cross the admin boundary.
        let checked = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(&self.cli)
                .args(["serve", "--check-config", "--fetch-config"])
                .arg(&installed.fetch_config)
                .arg("--grant-config")
                .arg(&installed.grant_config)
                .envs(&configuration.env)
                .env_remove("HELLAS_REMOTE_KEY")
                .env_remove("HELLAS_REMOTE_TOKEN")
                .env_remove("HELLAS_REMOTE_ARGS")
                .env_remove("HELLAS_REMOTE_OWNER")
                .env_remove("HELLAS_REMOTE_OWNER_ENROLLMENT")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .map_err(AgentError::ValidatorTimeout)?
        .map_err(AgentError::ValidatorSpawn)?;
        if !checked.success() {
            return Err(AgentError::ConfigurationRejected);
        }
        let path = self.configuration_dir.join("configuration.json");
        self.stop().await?;
        let previous = self.configuration.replace(installed);
        let applied = self.start().await.and_then(|()| {
            crate::config::save_private(&path, self.configuration.as_ref().unwrap(), false)
                .map_err(AgentError::from)
        });
        if let Err(source) = applied {
            let rollback: Result<()> = async {
                self.stop().await?;
                self.configuration = previous;
                if let Some(previous) = &self.configuration {
                    crate::config::save_private(&path, previous, false)?;
                } else {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                self.start().await
            }
            .await;
            return Err(match rollback {
                Ok(()) => source,
                Err(rollback) => AgentError::Rollback {
                    source: Box::new(source),
                    rollback: Box::new(rollback),
                },
            });
        }
        let _ = candidate.keep();
        if let Some(previous) = previous
            && let Some(directory) = previous.fetch_config.parent()
            && directory.parent() == Some(self.configuration_dir.as_path())
            && directory
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".worker-config-"))
        {
            let _ = std::fs::remove_dir_all(directory);
        }
        Ok(())
    }
}

async fn export_enrollment(
    cli: &Path,
    identity: &Path,
) -> Result<hellas_rpc::protocol::work_grant::records::Principal> {
    use hellas_rpc::protocol::work_grant::records::{MAX_PRINCIPAL_BYTES, Principal};
    use tokio::io::AsyncReadExt;
    let mut command = Command::new(cli);
    command
        .arg("--identity")
        .arg(identity)
        .args(["contact", "export"])
        .env_remove("HELLAS_REMOTE_KEY")
        .env_remove("HELLAS_REMOTE_TOKEN")
        .env_remove("HELLAS_REMOTE_ARGS")
        .env_remove("HELLAS_REMOTE_OWNER")
        .env_remove("HELLAS_REMOTE_OWNER_ENROLLMENT")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut child = command.spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .ok_or(AgentError::EnrollmentStdout)?
            .take((MAX_PRINCIPAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > MAX_PRINCIPAL_BYTES {
            return Err(AgentError::EnrollmentBound);
        }
        if !child.wait().await?.success() {
            return Err(AgentError::EnrollmentExport);
        }
        Ok(Principal::decode(&bytes)?)
    })
    .await
    .map_err(AgentError::EnrollmentTimeout)?
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
            .env_remove("HELLAS_REMOTE_OWNER_ENROLLMENT")
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    if !output.status.success() {
        return Err(AgentError::IdentityCommand {
            operation: operation.to_owned(),
        });
    }
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
                    process.start().await?;
                    Ok(Response::Status {
                        enrollment: self.enrollment.clone(),
                        owner: self.owner.map(|owner| owner.to_string()),
                        running: process.running()?,
                    })
                }
                Operation::Configure { configuration } => {
                    let mut process = self.process.lock().await;
                    process.configure(configuration).await?;
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
                        .map_err(AgentError::DownloadBusy)?;
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
    run_until(options, shutdown_signal()).await
}

pub async fn run_until(
    options: AgentOptions,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let secret = options.credentials.secret_key()?;
    options.credentials.require_owner_enrollment()?;
    crate::config::validate_serve_args(&options.serve_args)?;
    let owner = options.credentials.owner_principal()?;
    tokio::fs::create_dir_all(&options.data).await?;
    // Refuse silent reassignment, including a restart that omits the owner.
    let binding = options.data.join("owner.json");
    let _lease = crate::config::lock_state(&binding)?;
    if binding.exists() {
        let saved: Option<String> = crate::config::read_json(&binding)?;
        if saved != options.credentials.owner {
            return Err(AgentError::OwnerChanged);
        }
    } else {
        crate::config::save_private(&binding, &options.credentials.owner, true)?;
    }
    let content = options.data.join("content");
    tokio::fs::create_dir_all(&content).await?;
    let identity = options.data.join("identity");
    let configuration_dir = options
        .configuration_dir
        .unwrap_or_else(|| options.data.clone());
    crate::management::private_directory(&configuration_dir)?;
    let configuration_dir = configuration_dir.canonicalize()?;
    let configuration_path = configuration_dir.join("configuration.json");
    let configuration: Option<crate::configuration::InstalledConfiguration> = configuration_path
        .exists()
        .then(|| crate::config::read_json(&configuration_path))
        .transpose()?;
    identity_command(&options.cli, &identity, "init").await?;
    let bundle = export_enrollment(&options.cli, &identity).await?;
    let enrollment = Enrollment {
        bundle: Some(hex::encode(bundle.bundle().canonical_bytes())),
        node_id: identity_command(&options.cli, &identity, "show-node-id").await?,
        enrollment_id: identity_command(&options.cli, &identity, "show-enrollment-id").await?,
    };
    enrollment.validate()?;
    let (owner_enrollment, bootstrap_grants) =
        crate::managed_grants::prepare(&options.data, &configuration_dir, bundle, owner.as_ref())?;
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
        owner_enrollment,
        bootstrap_grants,
        cli: options.cli,
        configuration,
        configuration_dir,
    };
    process.start().await?;
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

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("expected size must be 1 byte..1 TiB")]
    SizeBound,
    #[error("content URL must be HTTPS without userinfo or fragment")]
    UrlPolicy,
    #[error("download requires HTTP 200; redirects are refused")]
    HttpStatus,
    #[error("content length mismatch")]
    Length,
    #[error("download exceeds declared size")]
    Exceeded,
    #[error("download length or digest mismatch")]
    Integrity,
    #[error("content root needs a parent")]
    RootParent,
    #[error("size overflow")]
    Overflow,
    #[error("content already exists; no existing content was replaced")]
    AlreadyExists,
}

pub fn validate_download(
    url: &str,
    sha256: &str,
    bytes: u64,
) -> std::result::Result<reqwest::Url, DownloadError> {
    validate_hex(sha256)?;
    if bytes == 0 || bytes > 1024 * 1024 * 1024 * 1024 {
        return Err(DownloadError::SizeBound);
    }
    let url = reqwest::Url::parse(url)?;
    if !(url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    {
        return Err(DownloadError::UrlPolicy);
    }
    Ok(url)
}

pub async fn fetch_content(
    root: &Path,
    url: &str,
    sha256: &str,
    bytes: u64,
) -> std::result::Result<(), DownloadError> {
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
) -> std::result::Result<(), DownloadError> {
    if response.status() != reqwest::StatusCode::OK {
        return Err(DownloadError::HttpStatus);
    }
    if let Some(length) = response.content_length()
        && (length != bytes)
    {
        return Err(DownloadError::Length);
    }
    // Stage outside the indexed content tree. Cancellation/errors remove the temp
    // file; only an exact length+digest match becomes visible to Hellas.
    let temp = tempfile::NamedTempFile::new_in(root.parent().ok_or(DownloadError::RootParent)?)?;
    let mut file = tokio::fs::File::from_std(temp.reopen()?);
    let mut hash = Sha256::new();
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await? {
        received = received
            .checked_add(chunk.len() as u64)
            .ok_or(DownloadError::Overflow)?;
        if received > bytes {
            return Err(DownloadError::Exceeded);
        }
        hash.update(&chunk);
        file.write_all(&chunk).await?;
    }
    if received != bytes || hex::encode(hash.finalize()) != sha256 {
        return Err(DownloadError::Integrity);
    }
    file.sync_all().await?;
    drop(file);
    let destination = root.join(sha256);
    match temp.persist_noclobber(&destination) {
        Ok(_) => {
            std::fs::File::open(root)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(DownloadError::AlreadyExists)
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
