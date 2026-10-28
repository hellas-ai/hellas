//! Execution policy parsing shared by payment and grant configuration.
use hellas_auth::Digest;
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
type Result<T> = std::result::Result<T, ResourceConfigError>;

pub(crate) fn parse_hex(field: &'static str, raw: &str) -> Result<Vec<u8>> {
    let bytes =
        hex::decode(raw.trim()).map_err(|source| ResourceConfigError::Hex { field, source })?;
    Ok(bytes)
}

pub(crate) fn parse_fixed_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N]> {
    hellas_auth::hex::parse(raw.trim()).map_err(|source| ResourceConfigError::Hex { field, source })
}

pub(crate) fn parse_digest(field: &'static str, raw: &str) -> Result<Digest> {
    Ok(Digest::from_bytes(parse_fixed_hex(field, raw)?))
}
