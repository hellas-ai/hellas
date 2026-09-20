use crate::domain::{Coin, Digest, ObjectId, ObjectKind, SettlementKey, Transaction};
use commonware_codec::EncodeSize;
use hellas_kernel::Encode as _;
use hellas_rpc::SubmitTxOutcome;
use hellas_wire::{WireCode, WireStatus};

pub(crate) fn canonical_submission_size(tx: &Transaction) -> usize {
    match tx {
        Transaction::Kernel(kernel) => kernel.encoded_size(),
        _ => tx.encode_size(),
    }
}

const WRONG_OBJECT_KIND_V1_PREFIX: &str = "hellas.wrong-object-kind.v1;expected=";

fn wrong_object_kind_message(expected: ObjectKind, actual: ObjectKind) -> String {
    format!("{WRONG_OBJECT_KIND_V1_PREFIX}{expected};actual={actual}")
}

/// Parses one kind token out of a wrong-object-kind status message.
///
/// The tokens are exactly what [`ObjectKind`]'s `Display` writes, and the
/// pairing is checked by `wrong_kind_survives_wire_status_mapping` below.
/// An unrecognized token is not guessed at: the status falls back to
/// [`QueryError::Remote`], carrying the message a newer peer sent rather
/// than a kind this build invented.
fn parse_object_kind(value: &str) -> Option<ObjectKind> {
    match value {
        "coin" => Some(ObjectKind::Coin),
        "edge" => Some(ObjectKind::Edge),
        "registry-chunk" => Some(ObjectKind::RegistryChunk),
        "owner-data" => Some(ObjectKind::OwnerData),
        _ => None,
    }
}

fn parse_wrong_object_kind(message: &str) -> Option<QueryError> {
    let fields = message.strip_prefix(WRONG_OBJECT_KIND_V1_PREFIX)?;
    let (expected, actual) = fields.split_once(";actual=")?;
    Some(QueryError::WrongObjectKind {
        expected: parse_object_kind(expected)?,
        actual: parse_object_kind(actual)?,
    })
}

/// Flattened proposal metadata for the activity stream.
#[derive(Clone, Debug)]
pub struct ProposalInfo {
    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    pub parent_payload: Digest,
    pub payload: Digest,
}

/// Structured consensus event for the activity stream.
#[derive(Clone, Debug)]
pub enum ConsensusActivity {
    Notarize {
        proposal: ProposalInfo,
        signer: u32,
        signature: Vec<u8>,
    },
    Notarization {
        proposal: ProposalInfo,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
    Nullify {
        epoch: u64,
        view: u64,
        signer: u32,
        signature: Vec<u8>,
    },
    Nullification {
        epoch: u64,
        view: u64,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
    Finalization {
        proposal: ProposalInfo,
        signers: Vec<u32>,
        certificate: Vec<u8>,
    },
}

/// Summary of the latest finalized block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestBlock {
    pub height: u64,
    pub payload: Digest,
    pub state_root: Digest,
    /// Raw Simplex certificate or a bounded `finality_proof` ancestry envelope.
    pub finalization: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBlock {
    pub snapshot: LatestBlock,
    pub block: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizedBlockQuery {
    Latest,
    Height(u64),
    Payload(Digest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerCoins {
    pub snapshot: LatestBlock,
    pub coins: Vec<(ObjectId, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeState {
    pub value: u64,
    pub reserve: u64,
    pub close_fees: hellas_kernel::Fees,
    pub timeout: hellas_kernel::BlockHeight,
    pub maker: SettlementKey,
    pub taker: SettlementKey,
    pub terms_hash: hellas_kernel::TermsHash,
}

impl From<hellas_kernel::Edge> for EdgeState {
    fn from(edge: hellas_kernel::Edge) -> Self {
        let parties = edge.parties();
        Self {
            value: edge.value(),
            reserve: edge.reserve(),
            close_fees: edge.close_fees(),
            timeout: edge.timeout(),
            maker: SettlementKey::from(parties.maker()),
            taker: SettlementKey::from(parties.taker()),
            terms_hash: edge.terms(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeLookup {
    pub state_root: Digest,
    pub edge: Option<EdgeState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeRecord {
    pub object_id: ObjectId,
    pub maker: SettlementKey,
    pub taker: SettlementKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEdges {
    pub snapshot: LatestBlock,
    pub edges: Vec<EdgeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusInfo {
    pub validators: Vec<String>,
    pub threshold_identity: Vec<u8>,
    /// The network this chain's authorizations are bound to.
    pub network_id: String,
}

/// Errors returned by light-client queries.
#[derive(Debug, Clone, thiserror::Error)]
pub enum QueryError {
    #[error("query channel closed")]
    ChannelClosed,
    #[error("state unavailable: {0}")]
    StateUnavailable(String),
    #[error("wrong object kind: expected {expected}, found {actual}")]
    WrongObjectKind {
        expected: ObjectKind,
        actual: ObjectKind,
    },
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("remote rpc error: {0}")]
    Remote(String),
    #[error("connection failed: {0}")]
    Connect(String),
}

impl From<QueryError> for WireStatus {
    fn from(err: QueryError) -> Self {
        match err {
            QueryError::ChannelClosed => {
                WireStatus::new(WireCode::Unavailable, "query channel closed")
            }
            QueryError::StateUnavailable(message) => {
                WireStatus::new(WireCode::FailedPrecondition, message)
            }
            QueryError::WrongObjectKind { expected, actual } => WireStatus::new(
                WireCode::Aborted,
                wrong_object_kind_message(expected, actual),
            ),
            QueryError::InvalidTransaction(message) => {
                WireStatus::new(WireCode::InvalidArgument, message)
            }
            QueryError::Remote(message) => WireStatus::new(WireCode::Unavailable, message),
            QueryError::Connect(message) => WireStatus::new(WireCode::Unavailable, message),
        }
    }
}

impl From<WireStatus> for QueryError {
    fn from(status: WireStatus) -> Self {
        match status.code() {
            WireCode::FailedPrecondition | WireCode::OutOfRange => {
                QueryError::StateUnavailable(status.message().to_string())
            }
            // Chain RPC reserves Aborted for the versioned wrong-object-kind
            // semantic until a later proto can carry these fields directly.
            WireCode::Aborted => parse_wrong_object_kind(status.message())
                .unwrap_or_else(|| QueryError::Remote(status.to_string())),
            WireCode::InvalidArgument => {
                QueryError::InvalidTransaction(status.message().to_string())
            }
            _ => QueryError::Remote(status.to_string()),
        }
    }
}

/// Transport-agnostic query interface for light clients.
pub trait LightClient: Clone + Send + Sync + 'static {
    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send;

    fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send;

    fn get_coin(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Coin>, QueryError>> + Send;

    fn get_edge(
        &self,
        payload: Digest,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<EdgeLookup>, QueryError>> + Send;

    fn get_finalization(
        &self,
        payload: Digest,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send;

    fn get_latest_block(
        &self,
    ) -> impl Future<Output = Result<Option<LatestBlock>, QueryError>> + Send;

    fn get_finalized_block(
        &self,
        query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send;

    fn submit_tx(
        &self,
        tx: Transaction,
    ) -> impl Future<Output = Result<SubmitTxOutcome, QueryError>> + Send;

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send;

    fn get_consensus_info(&self) -> impl Future<Output = Result<ConsensusInfo, QueryError>> + Send;

    fn get_coins_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerCoins>, QueryError>> + Send;

    fn get_edges_by_owner(
        &self,
        owner: SettlementKey,
    ) -> impl Future<Output = Result<Option<OwnerEdges>, QueryError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_kind_survives_wire_status_mapping() {
        for (expected, actual) in [
            (ObjectKind::Coin, ObjectKind::Edge),
            (ObjectKind::Edge, ObjectKind::Coin),
            (ObjectKind::Edge, ObjectKind::RegistryChunk),
            (ObjectKind::RegistryChunk, ObjectKind::Coin),
        ] {
            let status = WireStatus::from(QueryError::WrongObjectKind { expected, actual });
            assert_eq!(status.code(), WireCode::Aborted);
            assert!(matches!(
                QueryError::from(status),
                QueryError::WrongObjectKind {
                    expected: decoded_expected,
                    actual: decoded_actual,
                } if decoded_expected == expected && decoded_actual == actual
            ));
        }
    }

    #[test]
    fn malformed_aborted_status_is_not_invented_as_a_wrong_kind() {
        let err = QueryError::from(WireStatus::new(WireCode::Aborted, "not structured"));
        assert!(matches!(err, QueryError::Remote(_)));
    }
}
