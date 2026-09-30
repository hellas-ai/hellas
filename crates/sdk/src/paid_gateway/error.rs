use std::{path::PathBuf, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error(transparent)]
    Gateway(#[from] hellas_gateway::WorkGatewayError),
    #[error("invalid paid pool: {0}")]
    Invalid(&'static str),
    #[error("paid gateway repeats provider {0}")]
    DuplicateProvider(iroh::EndpointId),
    #[error("no provider policy matches this environment, token limit, and stop token list")]
    NoMatchingPolicy,
    #[error("no eligible paid provider could start this request: {0:?}")]
    ProvidersUnavailable(Vec<String>),
    #[error("retained paid work did not recover within its deadline")]
    RecoveryTimeout,
    #[error("paid provider connection exceeded its {0:?} limit")]
    ConnectionTimeout(Duration),
    #[error("paid output consumer is too slow; accepted work continues settlement")]
    SlowConsumer,
    #[error("{0}")]
    MissingOutput(&'static str),
    #[error("paid provider {provider}: {source}")]
    Provider {
        provider: iroh::EndpointId,
        source: Box<Self>,
    },
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid paid gateway config {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid {field}: {source}")]
    Hex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error(transparent)]
    Stopped(#[from] super::RequestStopped),
    #[error(transparent)]
    Busy(#[from] hellas_gateway::WorkGatewayBusy),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[error(transparent)]
    Client(#[from] crate::paid_client::PaidClientError),
    #[error(transparent)]
    Canonical(#[from] hellas_rpc::protocol::value::CanonicalDecodeError),
    #[error(transparent)]
    Work(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error(transparent)]
    Store(#[from] hellas_work::work_store::WorkStoreError),
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
    #[error(transparent)]
    FetchPayload(#[from] hellas_rpc::fetch::FetchPayloadError),
    #[error(transparent)]
    Evaluate(#[from] hellas_rpc::evaluate::EvaluateProtocolError),
    #[error(transparent)]
    Remote(#[from] hellas_client::ClientError),
}
