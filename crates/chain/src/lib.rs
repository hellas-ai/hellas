#[cfg(any(feature = "indexer", feature = "validator"))]
mod app;
#[cfg(feature = "block-view")]
pub mod block;
#[cfg(feature = "block-view")]
pub mod block_view;
#[cfg(feature = "client-core")]
pub mod client;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod config;
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
mod consensus;
#[cfg(feature = "domain")]
pub mod domain;
#[cfg(feature = "verified-explorer")]
pub mod edge_index;
#[cfg(any(feature = "indexer", feature = "validator"))]
mod execution;
#[cfg(feature = "explorer-origin")]
pub mod explorer_origin;
#[cfg(feature = "validator")]
pub mod faucet;
#[cfg(feature = "indexer")]
pub mod follower;
#[cfg(feature = "domain")]
pub mod owner_proof;
#[cfg(feature = "verified-explorer")]
pub mod verified_explorer;
/// The shipped genesis documents and the type that reads them. It is its
/// own `std` crate because a browser build and the relay in another
/// repository read the same bytes a validator does; re-exported whole so
/// `hellas_chain::genesis::*` is the path it always was.
#[cfg(feature = "domain")]
pub use hellas_genesis as genesis;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod indexer;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod light_client;
#[cfg(any(feature = "indexer", feature = "validator"))]
pub mod owner_index;
#[cfg(feature = "validator")]
pub mod relay;
#[cfg(feature = "validator")]
pub mod rpc;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "validator")]
pub mod validator;
#[cfg(feature = "work-watcher")]
pub mod work_blocks;
/// The end-to-end money claim, against a real chain. Test-only.
#[cfg(all(test, feature = "validator", feature = "work-watcher"))]
mod work_e2e;
#[cfg(any(feature = "client-core", feature = "server"))]
pub mod work_view;

#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub const CONSENSUS_NAMESPACE: &[u8] = b"hellas";

#[cfg(any(feature = "indexer", feature = "validator"))]
pub use app::{ActivityReporter, Application, ApplicationConfig};
/// The mempool and its bounds, which only a validator has: nothing on a
/// follower build puts a transaction into one or takes one out.
#[cfg(feature = "validator")]
pub use app::{GENERAL_MEMPOOL_CAPACITY, Mempool};
#[cfg(feature = "block-view")]
pub use block::{HellasBlock, UtxoSyncTarget};
#[cfg(feature = "block-view")]
pub use block_view::{BlockViewError, FinalizedBlockView};
#[cfg(any(feature = "client-core", feature = "indexer", feature = "validator"))]
pub use consensus::{ConsensusVerificationError, ConsensusVerifier, Finalization};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use execution::store::{UtxoDb, utxo_db_config};
#[cfg(feature = "validator")]
pub use execution::{ChainVerifier, ExecutionError};
#[cfg(any(feature = "client-core", feature = "server"))]
pub use hellas_rpc::{
    MAX_CANONICAL_TRANSACTION_BYTES, MAX_SUBMIT_TX_PROTO_BYTES,
    MAX_SUBMIT_WORK_RESPONSE_PROTO_BYTES, SubmitTxOutcome,
};
#[cfg(any(feature = "indexer", feature = "validator"))]
pub use indexer::{
    BlockStore, ChainIndexer, FinalizationStore, IngestError, IngestOutcome, init_block_store,
    init_finalization_store, spawn_follower_indexer,
};
#[cfg(any(feature = "client-core", feature = "server"))]
pub use light_client::{
    ConsensusActivity, ConsensusInfo, EdgeLookup, EdgeRecord, EdgeState, FinalizedBlock,
    FinalizedBlockQuery, LatestBlock, LightClient, OwnerCoins, OwnerEdges, ProposalInfo,
    QueryError,
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

/// `hellas_chain::genesis::*` is a published path: the CLI, the client
/// and the relay in the explorer repository all reach the shipped
/// documents through it. A re-export can be re-pointed without any of
/// them failing to compile, so this walks the path chain publishes and
/// re-checks the reviewed bytes at the far end of it.
#[cfg(all(test, feature = "domain"))]
mod genesis_reexport {
    use sha2::{Digest as _, Sha256};

    #[test]
    fn the_documents_reached_through_chain_are_the_reviewed_bytes() {
        let selector = "devnet";
        let id = crate::genesis::HELLAS_DEVNET_1_ID;
        let json = crate::genesis::HELLAS_DEVNET_1_JSON;
        let expected = "caab04a9350edbe0d50aa9375dcee2742145cf5c24c57f42c844ebf4f27aa4b6";
        let hex: String = Sha256::digest(json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, expected, "{selector}");

        let network = crate::genesis::known_network(selector).expect("shipped network");
        assert_eq!(network.id, id);
        assert_eq!(network.json, json);

        let genesis: crate::genesis::Genesis =
            serde_json::from_str(json).expect("shipped document parses");
        genesis.validate().expect("shipped document validates");
        assert_eq!(genesis.network_id, id);

        assert_eq!(crate::genesis::known_network_names(), vec!["devnet"]);
        assert_eq!(crate::genesis::GENESIS_SCHEMA_VERSION, 1);
    }
}
