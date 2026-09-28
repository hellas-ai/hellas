use super::{ContentId, EdgeId, Key, PeerId};
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
    #[error("routes names peer {0:#} twice; one authenticated peer has one route")]
    DuplicatePeer(PeerId),
    #[error("routes names bond {} twice; one provider journal has one route", hex::encode(.0.to_bytes()))]
    DuplicateBond(EdgeId),
    #[error("provider setup journal for bond {} is not under journal.root {}", hex::encode(bond.to_bytes()), root.display())]
    MissingRoute { bond: EdgeId, root: PathBuf },
    #[error("work journal under {}: {source}", root.display())]
    Journal {
        root: PathBuf,
        source: hellas_work::work_store::WorkStoreError,
    },
    #[error("provider setup journal for bond {} holds no bond proposal", hex::encode(.0.to_bytes()))]
    MissingProposal(EdgeId),
    #[error("route expects client settlement key {}, but provider setup journal for bond {} names {} as its taker", hex::encode(expected.to_bytes()), hex::encode(bond.to_bytes()), hex::encode(actual.to_bytes()))]
    WrongClient {
        bond: EdgeId,
        expected: Key,
        actual: Key,
    },
    #[error("chain.threshold_identity is not usable: {0}")]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error("min_omit_response_blocks {actual} is under the kernel's minimum {minimum}")]
    ResponseWindow { actual: u64, minimum: u64 },
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
    #[error("{field} is not a ContentId: {source}")]
    ContentId {
        field: &'static str,
        source: <ContentId as std::str::FromStr>::Err,
    },
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
    #[error("paid execution policy is not usable: {0}")]
    Policy(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error("{field} is not hexadecimal: {source}")]
    Hex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("{field} must be {expected} bytes, found {actual}")]
    Length {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}
