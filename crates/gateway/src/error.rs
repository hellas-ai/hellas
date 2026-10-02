use std::{net::SocketAddr, path::PathBuf, process::ExitStatus};

pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Config(#[from] GatewayConfigError),
    #[error(transparent)]
    Client(#[from] hellas_client::ClientError),
    #[error(transparent)]
    Work(#[from] crate::WorkGatewayError),
    #[error(transparent)]
    Shutdown(#[from] crate::WorkShutdownError),
    #[error("{primary}; cleanup also failed: {cleanup}")]
    Cleanup {
        #[source]
        primary: Box<GatewayError>,
        cleanup: crate::WorkShutdownError,
    },
    #[error("gateway task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("gateway I/O failed")]
    Io(#[from] std::io::Error),
    #[error("failed to bind gateway on {address}")]
    Bind {
        address: SocketAddr,
        source: std::io::Error,
    },
    #[error("failed to resolve gateway bind address {host}:{port}")]
    Resolve {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("gateway bind address {host}:{port} resolved to no address")]
    NoAddress { host: String, port: u16 },
    #[error("failed to {operation} gateway credential at {}", path.display())]
    Credential {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to spawn {command}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },
    #[error("wrapped command exited with status {0}")]
    WrappedCommand(ExitStatus),
    #[error("text presentation failed: {0}")]
    Presentation(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    Routing(#[from] crate::RoutingError),
    #[error(transparent)]
    HttpRequest(#[from] hellas_rpc::http_fetch::HttpRequestError),
    #[error(transparent)]
    Header(#[from] axum::http::header::ToStrError),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayConfigError {
    #[error("configure either HTTP backends or opaque routes")]
    RouteMode,
    #[error("invalid HTTP concurrency limit")]
    HttpConcurrency,
    #[error("too many HTTP backends")]
    BackendCount,
    #[error("invalid backend name")]
    BackendName,
    #[error("backend needs explicit model names")]
    ModelNames,
    #[error("invalid backend concurrency limit")]
    BackendConcurrency,
    #[error("set the credential on the backend, not its routes")]
    BackendCredential,
    #[error("HTTP backend needs at least one route")]
    EmptyRoutes,
    #[error("HTTP routes must be exact paths")]
    RoutePath,
    #[error("duplicate HTTP route")]
    DuplicateRoute,
    #[error("use a provider credential alias for authentication")]
    CredentialAlias,
    #[error("default maximum tokens must be greater than zero")]
    MaxTokens,
    #[error("causal-LM environment and tokenizer must be supplied together")]
    TokenizerPair,
    #[error("Hellas backend requires an environment and tokenizer")]
    MissingEnvironment,
    #[error("gateway credential must be a private regular file owned by the gateway user")]
    CredentialPermissions,
    #[error("invalid gateway credential length")]
    CredentialLength,
    #[error("gateway credential must be lowercase hex")]
    CredentialEncoding,
    #[error("non-loopback gateway binding requires --allow-remote and --bearer-token-file")]
    RemoteBinding,
}
