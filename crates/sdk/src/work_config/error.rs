use std::path::PathBuf;

/// Configuration errors retain the field or file that failed.
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
    #[error(transparent)]
    Profile(#[from] hellas_chain::genesis::ChainProfileError),
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("chain.threshold_identity is not usable: {0}")]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
}
