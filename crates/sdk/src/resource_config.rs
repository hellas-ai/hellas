//! Execution policy parsing shared by payment and grant configuration.
use hellas_rpc::ContentId;

#[derive(Debug, thiserror::Error)]
pub enum ResourceConfigError {
    #[error("{field} is not a ContentId: {source}")]
    ContentId {
        field: &'static str,
        source: <ContentId as std::str::FromStr>::Err,
    },
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
    #[error("{field} is not hexadecimal: {source}")]
    Hex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("execution policy is not usable: {0}")]
    Policy(#[from] hellas_channel::model::work::PaidWorkError),
}
