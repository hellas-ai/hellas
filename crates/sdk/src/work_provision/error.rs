use hellas_kernel::{CoinId, EdgeId};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error(transparent)]
    Authority(#[from] hellas_authority::work_store::grant::NodeStoreError),
    #[error(transparent)]
    Offer(#[from] hellas_channel::model::offer::PaidOfferError),
    #[error("bond timeout {timeout} must be after finalized height {height}")]
    ExpiredBond { timeout: u64, height: u64 },
    #[error("bond timeout exceeds the chain maximum lifetime")]
    BondLifetime,
    #[error("stake requires between 1 and at most 4 coins, found {0}")]
    StakeCount(usize),
    #[error("duplicate stake coin {}", hex::encode(.0.to_bytes()))]
    DuplicateCoin(CoinId),
    #[error("provider offer over bond {} has no retained revision", hex::encode(.0.to_bytes()))]
    MissingProposal(EdgeId),
    #[error("candidate bond {} collides with an existing provider offer", hex::encode(.0.to_bytes()))]
    BondCollision(EdgeId),
    #[error("candidate stake coin {} is reserved by bond {}", hex::encode(coin.to_bytes()), hex::encode(bond.to_bytes()))]
    ReservedCoin { coin: CoinId, bond: EdgeId },
    #[error("journal under {} replays as revision {revision:?} over floor {floor:?}, not the armed proposal", root.display())]
    JournalReplay {
        root: PathBuf,
        revision: Option<u8>,
        floor: Option<u64>,
    },
    #[error("work journal under {}: {source}", root.display())]
    Journal {
        root: PathBuf,
        source: hellas_channel::work_store::WorkStoreError,
    },
    #[error("setup journal {} cannot be identified: {source}", path.display())]
    Unidentified {
        path: PathBuf,
        source: hellas_channel::work_store::SetupDiscoveryError,
    },
    #[error("the local node is not ready with a finalized block to floor this offer at")]
    NoFinalizedBlock,
    #[error(transparent)]
    Setup(#[from] hellas_channel::work_handshake::SetupExchangeError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[error(transparent)]
    BlockSource(#[from] hellas_channel::work_close::BlockSourceError),
}
