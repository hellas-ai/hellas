use hellas_kernel::{CoinId, EdgeId, Key};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error(transparent)]
    Offer(#[from] hellas_rpc::protocol::work_offer::PaidOfferError),
    #[error("bond timeout {timeout} must be after finalized height {height}")]
    ExpiredBond { timeout: u64, height: u64 },
    #[error("bond timeout exceeds the chain maximum lifetime")]
    BondLifetime,
    #[error("stake requires between 1 and at most 4 coins, found {0}")]
    StakeCount(usize),
    #[error("duplicate stake coin {}", hex::encode(.0.to_bytes()))]
    DuplicateCoin(CoinId),
    #[error("bond {} has no bilateral route in this work configuration", hex::encode(.0.to_bytes()))]
    MissingRoute(EdgeId),
    #[error("provider offer over bond {} has no retained revision", hex::encode(.0.to_bytes()))]
    MissingProposal(EdgeId),
    #[error("candidate bond {} collides with an existing provider offer", hex::encode(.0.to_bytes()))]
    BondCollision(EdgeId),
    #[error("candidate stake coin {} is reserved by bond {}", hex::encode(coin.to_bytes()), hex::encode(bond.to_bytes()))]
    ReservedCoin { coin: CoinId, bond: EdgeId },
    #[error("route for bond {} expects client {}, but the bond names {}", hex::encode(bond.to_bytes()), hex::encode(expected.to_bytes()), hex::encode(actual.to_bytes()))]
    WrongClient {
        bond: EdgeId,
        expected: Key,
        actual: Key,
    },
    #[error("journal under {} replays as revision {revision:?} over floor {floor:?}, not the armed proposal", root.display())]
    JournalReplay {
        root: PathBuf,
        revision: Option<u8>,
        floor: Option<u64>,
    },
    #[error("work journal under {}: {source}", root.display())]
    Journal {
        root: PathBuf,
        source: hellas_work::work_store::WorkStoreError,
    },
    #[error("setup journal {} cannot be identified: {source}", path.display())]
    Unidentified {
        path: PathBuf,
        source: hellas_work::work_store::SetupDiscoveryError,
    },
    #[error("no configured validator answered with a finalized block to floor this offer at")]
    NoFinalizedBlock,
    #[error(transparent)]
    Setup(#[from] hellas_work::work_handshake::SetupExchangeError),
    #[error(transparent)]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error(transparent)]
    BlockSource(#[from] hellas_work::work_close::BlockSourceError),
}
