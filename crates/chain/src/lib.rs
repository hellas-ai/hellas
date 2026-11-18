#[cfg(any(feature = "indexer", feature = "validator"))]
mod app;
#[cfg(feature = "client-core")]
pub mod block;
#[cfg(feature = "validator")]
mod block_time;
#[cfg(feature = "client-core")]
pub mod block_view;
#[cfg(all(feature = "chain-dir", not(target_arch = "wasm32")))]
pub mod chain_dir;
#[cfg(feature = "client-core")]
pub mod client;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod config;
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
mod consensus;
#[cfg(feature = "domain")]
pub mod domain;
#[cfg(feature = "proof-verify")]
pub mod edge_index;
#[cfg(any(feature = "indexer", feature = "validator"))]
mod execution;
#[cfg(feature = "client-core")]
pub mod finality_proof;
#[cfg(feature = "indexer-api")]
pub(crate) mod http_api;
#[cfg(feature = "indexer-api")]
pub mod indexer_api;
#[cfg(feature = "domain")]
pub mod owner_proof;
#[cfg(feature = "proof-verify")]
pub mod proof_verify;
/// Portable genesis and trust documents supplied by the operator.
#[cfg(feature = "domain")]
pub use hellas_genesis as genesis;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod indexer;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod light_client;
#[cfg(feature = "full-node")]
pub mod node;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod owner_index;
#[cfg(feature = "validator")]
pub mod relay;
#[cfg(any(feature = "validator", feature = "full-node"))]
pub mod rpc;
#[cfg(feature = "server")]
pub mod server;
/// The six-validator devnet harness, for this crate's tests and, behind
/// `test-support`, for other crates' tests.
#[cfg(all(any(test, feature = "test-support"), feature = "validator"))]
pub mod test_support;
#[cfg(feature = "validator")]
pub mod validator;
#[cfg(feature = "work-watcher")]
pub mod work_blocks;
/// The end-to-end money claim, against a real chain. Test-only.
#[cfg(all(
    test,
    feature = "integration-tests",
    feature = "validator",
    feature = "work-watcher"
))]
mod work_e2e;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod work_view;

#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub use consensus::{consensus_namespace, genesis_digest};

#[cfg(any(feature = "indexer", feature = "validator"))]
pub use app::{ActivityReporter, Application, ApplicationConfig};
/// The mempool and its bounds, which only a validator has: nothing on a
/// full-node build puts a transaction into one or takes one out.
#[cfg(feature = "validator")]
pub use app::{GENERAL_MEMPOOL_CAPACITY, GENERAL_MEMPOOL_MAX_STRIKES, Mempool};
#[cfg(feature = "client-core")]
pub use block::{HellasBlock, UtxoSyncTarget};
#[cfg(feature = "client-core")]
pub use block_view::{BlockViewError, FinalizedBlockView};
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub use consensus::{ConsensusVerificationError, ConsensusVerifier, Finalization};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use execution::store::{UtxoDb, utxo_db_config};
#[cfg(feature = "full-node")]
pub use execution::{ChainVerifier, ExecutionError};
#[cfg(any(feature = "client-core", feature = "server"))]
pub use hellas_rpc::{
    MAX_CANONICAL_TRANSACTION_BYTES, MAX_SUBMIT_TX_PROTO_BYTES,
    MAX_SUBMIT_WORK_RESPONSE_PROTO_BYTES, SubmitTxOutcome,
};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use indexer::ChainIndexer;
#[cfg(any(feature = "client-core", feature = "server"))]
pub use light_client::{
    ConsensusActivity, ConsensusInfo, EdgeState, FinalizedBlock, FinalizedBlockQuery, Holdings,
    LatestBlock, LightClient, ObjectSnapshot, ProposalInfo, QueryError, Verified,
};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use owner_index::{ApplyOutcome, OwnerCursor, OwnerIndex, OwnerIndexError};
#[cfg(feature = "server")]
pub use server::{
    LightClientRpc, LightClientRpcState, LightClientServerError, serve_light_client_transport,
    spawn_light_client_server,
};
#[cfg(feature = "work-watcher")]
pub use work_blocks::WorkBlocks;
#[cfg(any(feature = "client-core", feature = "server"))]
pub use work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};

#[cfg(all(test, feature = "indexer"))]
pub(crate) use indexer::fixtures::spawn_archive;
