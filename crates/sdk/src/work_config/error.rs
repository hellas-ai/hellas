use std::path::PathBuf;

/// Configuration errors retain the field, route or file that failed.
#[derive(Debug, thiserror::Error)]
pub enum WorkConfigError {
    #[error("failed to read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("invalid work config {}: {source}", path.display())]
    File { path: PathBuf, source: Box<Self> },
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("chain.threshold_identity is not usable: {0}")]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error("validators entry {entry:?} is not a URL: {source}")]
    ValidatorUrl {
        entry: String,
        source: url::ParseError,
    },
    #[error("validators entry {0:?} names no host to dial")]
    ValidatorHost(String),
    #[error("validators names {0} twice")]
    DuplicateValidator(String),
    #[error("validators must name exactly {expected} validator URLs, found {actual}")]
    ValidatorCount { expected: usize, actual: usize },
    #[error(transparent)]
    Resource(#[from] crate::ResourceConfigError),
    #[error("paid execution policy is not usable: {0}")]
    Policy(#[from] hellas_work::model::work::PaidWorkError),
}
