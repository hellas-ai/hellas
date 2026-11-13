pub type GatewayResult<T> = Result<T, GatewayError>;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Config(#[from] GatewayConfigError),
    #[error(transparent)]
    Work(#[from] crate::WorkGatewayError),
    #[error(transparent)]
    Shutdown(#[from] crate::WorkShutdownError),
    #[error(transparent)]
    Authority(#[from] hellas_authority::work_store::grant::NodeStoreError),
    #[error("gateway task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error("gateway I/O failed")]
    Io(#[from] std::io::Error),
    #[error("model presentation failed: {0}")]
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
    #[error("invalid backend model names")]
    ModelNames,
    #[error("HTTP routes must be exact paths")]
    RoutePath,
    #[error("duplicate HTTP route")]
    DuplicateRoute,
    #[error("use a provider credential alias for authentication")]
    CredentialAlias,
    #[error("default maximum tokens must be positive and fit the model capacity")]
    MaxTokens,
    #[error("the gateway serves no presentation")]
    NoPresentation,
}
