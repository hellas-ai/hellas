//! Process-owned paid chain configuration.
use hellas_private::StoreLocation;
use std::path::Path;
mod error;
#[cfg(test)]
mod tests;
pub use error::WorkConfigError;
type Result<T> = std::result::Result<T, WorkConfigError>;
use hellas_chain::chain_dir::ChainDir;
use hellas_chain::genesis::{ChainProfile, CustomChainFile};

/// One process chain and where its journals live. How often channels are
/// read and how old a read may be are the channel crate's, derived from
/// the kernel's response window, not settings.
#[derive(Clone, Debug)]
pub struct WorkConfig {
    pub chain: ChainDir,
}

impl WorkConfig {
    pub fn for_chain(chain: ChainProfile, root: &StoreLocation) -> Result<Self> {
        Self::from_chain_dir(ChainDir::open(root, &chain)?)
    }

    pub fn from_chain_dir(chain: ChainDir) -> Result<Self> {
        Self { chain }.validate()
    }

    pub fn network(&self) -> hellas_kernel::NetworkId {
        self.chain.network()
    }

    fn validate(self) -> Result<Self> {
        hellas_chain::proof_verify::ProofVerifier::for_profile(&self.chain).map_err(|_| {
            WorkConfigError::Invalid {
                field: "chain.trust",
                reason: "trusted epoch schedule and consensus digest must be usable",
            }
        })?;
        Ok(self)
    }
}

/// One optional custom file; no remote identity discovery.
pub fn load_chain_profile(path: &Path) -> Result<ChainProfile> {
    let bytes = hellas_private::read_bounded_regular_file(
        path,
        hellas_channel::work_store::journal::MAX_RECORD_BYTES,
    )
    .map_err(|source| WorkConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file: CustomChainFile =
        serde_json::from_slice(&bytes).map_err(|source| WorkConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(ChainProfile::custom(file)?)
}

/// Packs typed funding coins without imposing a provider/client funding policy.
/// Callers retain their nonempty and duplicate-coin checks.
pub fn coin_list(
    ids: &[hellas_kernel::CoinId],
) -> Option<hellas_kernel::List<hellas_kernel::CoinId, { hellas_kernel::MAX_PARTY_INPUTS }>> {
    let slots = std::array::from_fn(|i| {
        ids.get(i)
            .copied()
            .unwrap_or(hellas_kernel::CoinId::from_bytes(
                [0; hellas_kernel::CoinId::LENGTH],
            ))
    });
    hellas_kernel::List::new(slots, ids.len())
}
