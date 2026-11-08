use crate::domain::{
    Coin, Digest, Object, ObjectId, ObjectKey, ObjectKind, SettlementKey, Transaction,
};
use hellas_kernel::Encode as _;
use hellas_rpc::SubmitTxOutcome;
use hellas_wire::{WireCode, WireStatus};

pub(crate) fn canonical_submission_size(tx: &Transaction) -> usize {
    match tx {
        Transaction::Kernel(kernel) => kernel.encoded_size(),
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
    /// Bounded finality envelope containing a Simplex certificate and descendants.
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

/// A value read from finalized chain state that this process has checked:
/// a remote reply whose proof verified, or a read of state this process
/// executed itself. Only those two paths construct one, so code that takes a
/// `Verified` cannot be handed an unproven reply.
#[derive(Debug, Clone)]
pub struct Verified<T>(T);

impl<T> Verified<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    /// Test doubles stand in for a verified chain without one.
    #[cfg(any(test, feature = "test-support"))]
    pub fn assume_for_tests(value: T) -> Self {
        Self(value)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// Current objects at one finalized root. Missing keys are absent. An owner
/// read also lists one page of the owner's holdings, whose objects are in
/// `objects`.
#[derive(Debug, Clone)]
pub struct ObjectSnapshot {
    pub network: hellas_kernel::NetworkId,
    pub block: LatestBlock,
    pub objects: std::collections::BTreeMap<ObjectId, Object>,
    pub holdings: Option<Holdings>,
}

/// One page of an owner's holdings in owner-tree order. `next` is the last
/// listed key while more follow, and continues the listing at a later root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holdings {
    pub keys: Vec<ObjectId>,
    pub next: Option<ObjectId>,
}

impl Holdings {
    pub(crate) fn new(keys: Vec<ObjectId>, offset: u64, count: u64) -> Self {
        let more = offset.saturating_add(keys.len() as u64) < count;
        let next = more.then(|| keys.last().copied()).flatten();
        Self { keys, next }
    }
}

impl ObjectSnapshot {
    /// The object at `key`, as the kind `key` names. Kernel derivations are
    /// domain separated per kind, but ids also cross boundaries as bytes, so
    /// an id rebuilt as the wrong kind finds another kind's object: that is
    /// [`QueryError::WrongObjectKind`], not an absent object.
    fn lookup<T>(
        &self,
        key: ObjectKey,
        pick: fn(Object) -> Option<T>,
    ) -> Result<Option<T>, QueryError> {
        let Some(object) = self.objects.get(&key.id()).copied() else {
            return Ok(None);
        };
        pick(object).map(Some).ok_or(QueryError::WrongObjectKind {
            expected: key.kind(),
            actual: object.kind(),
        })
    }

    /// The live coin `id`.
    pub fn coin(&self, id: hellas_kernel::CoinId) -> Result<Option<Coin>, QueryError> {
        self.lookup(ObjectKey::Coin(id), |object| match object {
            Object::Coin(coin) => Some(coin),
            _ => None,
        })
    }

    /// The live edge `id`.
    pub fn edge(
        &self,
        id: hellas_kernel::EdgeId,
    ) -> Result<Option<hellas_kernel::Edge>, QueryError> {
        self.lookup(ObjectKey::Edge(id), |object| match object {
            Object::Edge(edge) => Some(edge),
            _ => None,
        })
    }

    /// The registry chunk in slot `id`.
    pub fn registry_chunk(
        &self,
        id: hellas_kernel::RegistryChunkId,
    ) -> Result<Option<hellas_kernel::RegistryChunk>, QueryError> {
        self.lookup(ObjectKey::RegistryChunk(id), |object| match object {
            Object::RegistryChunk(chunk) => Some(chunk),
            _ => None,
        })
    }

    fn listed(&self) -> impl Iterator<Item = (ObjectId, &Object)> {
        self.holdings
            .iter()
            .flat_map(|holdings| holdings.keys.iter())
            .filter_map(|key| self.objects.get(key).map(|object| (*key, object)))
    }

    /// Listed coins whose owner is `owner`.
    pub fn owned_coins(&self, owner: SettlementKey) -> Vec<(ObjectId, Coin)> {
        self.listed()
            .filter_map(|(key, object)| match object {
                Object::Coin(coin) if coin.owner == owner => Some((key, *coin)),
                _ => None,
            })
            .collect()
    }

    /// Listed coins delegated to `delegate`: spendable funding, not its balance.
    pub fn delegated_coins(&self, delegate: SettlementKey) -> Vec<(ObjectId, Coin)> {
        self.listed()
            .filter_map(|(key, object)| match object {
                Object::Coin(coin) if coin.delegate == Some(delegate) => Some((key, *coin)),
                _ => None,
            })
            .collect()
    }

    /// Listed edges.
    pub fn edges(&self) -> Vec<(ObjectId, EdgeState)> {
        self.listed()
            .filter_map(|(key, object)| match object {
                Object::Edge(edge) => Some((key, EdgeState::from(*edge))),
                _ => None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeState {
    pub value: u64,
    pub reserve: u64,
    pub close_fees: hellas_kernel::Fees,
    pub timeout: hellas_kernel::BlockHeight,
    /// The maker's committed owner.
    pub maker: SettlementKey,
    /// The taker's committed owner.
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
            maker: SettlementKey::from(parties.maker().owner()),
            taker: SettlementKey::from(parties.taker().owner()),
            terms_hash: edge.terms(),
        }
    }
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
    #[error("certified state is not yet applied")]
    NotYetApplied,
    #[error("chain read remained unavailable for {timeout:?}: {reason}")]
    ReadUnavailableTimeout {
        timeout: std::time::Duration,
        reason: String,
    },
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
            QueryError::NotYetApplied => {
                WireStatus::new(WireCode::OutOfRange, "certified state is not yet applied")
            }
            QueryError::ReadUnavailableTimeout { timeout, reason } => WireStatus::new(
                WireCode::Unavailable,
                format!("chain read remained unavailable for {timeout:?}: {reason}"),
            ),
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
            WireCode::Unavailable | WireCode::ResourceExhausted | WireCode::FailedPrecondition => {
                QueryError::StateUnavailable(status.message().to_string())
            }
            // Chain queries reserve OutOfRange for certified state ahead of execution.
            WireCode::OutOfRange => QueryError::NotYetApplied,
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
///
/// Object reads return [`Verified`] values: implementations either verify a
/// proof or read state their own process executed.
pub trait LightClient: Clone + Send + Sync + 'static {
    /// Serves `GetObjectProofs`; only a node holding state answers.
    fn get_object_proofs(
        &self,
        _request: hellas_rpc::pb::chain::GetObjectProofsRequest,
    ) -> impl Future<Output = Result<hellas_rpc::pb::chain::GetObjectProofsResponse, QueryError>> + Send
    {
        async {
            Err(QueryError::StateUnavailable(
                "current object proofs are unavailable".into(),
            ))
        }
    }

    /// Serves `GetObjects`, the same read without proofs.
    fn get_plain_objects(
        &self,
        _request: hellas_rpc::pb::chain::GetObjectProofsRequest,
    ) -> impl Future<Output = Result<hellas_rpc::pb::chain::GetObjectsResponse, QueryError>> + Send
    {
        async {
            Err(QueryError::StateUnavailable(
                "current objects are unavailable".into(),
            ))
        }
    }

    /// At most [`crate::proof_verify::MAX_CURRENT_KEYS`] objects at the latest root.
    fn get_objects(
        &self,
        _keys: Vec<ObjectKey>,
    ) -> impl Future<Output = Result<Option<Verified<ObjectSnapshot>>, QueryError>> + Send {
        async {
            Err(QueryError::StateUnavailable(
                "finalized objects are unavailable".into(),
            ))
        }
    }

    /// One page of `owner`'s holdings after `after`, at the latest root.
    fn get_holdings(
        &self,
        _owner: SettlementKey,
        _after: Option<ObjectId>,
    ) -> impl Future<Output = Result<Option<Verified<ObjectSnapshot>>, QueryError>> + Send {
        async {
            Err(QueryError::StateUnavailable(
                "finalized holdings are unavailable".into(),
            ))
        }
    }

    fn get_state_root(&self) -> impl Future<Output = Result<Option<Digest>, QueryError>> + Send;

    fn get_proof(
        &self,
        object_id: ObjectId,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, QueryError>> + Send;

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

    /// A certified checkpoint whose state the serving node has committed.
    fn get_applied_finalized_block(
        &self,
        _query: FinalizedBlockQuery,
    ) -> impl Future<Output = Result<Option<FinalizedBlock>, QueryError>> + Send {
        std::future::ready(Err(QueryError::Remote(
            "applied finalized checkpoints are not supported".into(),
        )))
    }

    fn submit_tx(
        &self,
        tx: Transaction,
    ) -> impl Future<Output = Result<SubmitTxOutcome, QueryError>> + Send;

    fn get_validators(&self) -> impl Future<Output = Result<Vec<String>, QueryError>> + Send;

    fn get_consensus_info(&self) -> impl Future<Output = Result<ConsensusInfo, QueryError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_yet_applied_survives_wire_status_mapping() {
        let status = WireStatus::from(QueryError::NotYetApplied);
        assert_eq!(status.code(), WireCode::OutOfRange);
        assert!(matches!(
            QueryError::from(status),
            QueryError::NotYetApplied
        ));
    }

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
