//! Process-owned paid chain configuration.
use std::path::Path;
use std::time::Duration;
mod error;
#[cfg(test)]
mod tests;
pub use error::WorkConfigError;
type Result<T> = std::result::Result<T, WorkConfigError>;
use hellas_chain::genesis::{ChainDir, ChainProfile, CustomChainFile};

/// One process chain and its transport, journal and observation settings.
#[derive(Clone, Debug)]
pub struct WorkConfig {
    pub chain: ChainDir,
    pub poll: Duration,
    pub max_observation_age: Duration,
}

impl WorkConfig {
    pub fn for_chain(chain: ChainProfile, root: &Path) -> Result<Self> {
        Self::from_chain_dir(ChainDir::open(root, &chain)?)
    }

    pub fn from_chain_dir(chain: ChainDir) -> Result<Self> {
        Self {
            chain,
            poll: Duration::from_millis(500),
            max_observation_age: hellas_chain::node::RECOVERY_TIMEOUT,
        }
        .validate()
    }

    pub fn network(&self) -> hellas_kernel::NetworkId {
        hellas_kernel::NetworkId::new(self.chain.network_id()).expect("validated chain profile")
    }

    pub fn threshold_identity(&self) -> Result<Vec<u8>> {
        Ok(self.chain.static_threshold_identity()?)
    }

    pub fn validate(self) -> Result<Self> {
        hellas_chain::ConsensusVerifier::new(
            &hellas_chain::light_client::ConsensusInfo {
                validators: self.chain.validators().to_vec(),
                threshold_identity: self.threshold_identity()?,
                network_id: self.chain.network_id().to_owned(),
            },
            self.chain.consensus_digest().into(),
        )?;
        if self.poll.is_zero() {
            return Err(WorkConfigError::Invalid {
                field: "poll_ms",
                reason: "must be greater than zero",
            });
        }
        if self.max_observation_age <= self.poll {
            return Err(WorkConfigError::Invalid {
                field: "max_observation_age_ms",
                reason: "must exceed poll_ms",
            });
        }
        Ok(self)
    }

    pub fn node_config(
        &self,
        archive_blocks: Option<std::num::NonZeroU64>,
    ) -> Result<hellas_chain::node::Config> {
        Ok(
            hellas_chain::node::Config::for_profile(self.chain.clone(), Vec::new(), archive_blocks)
                .map_err(|_| WorkConfigError::Invalid {
                    field: "chain",
                    reason: "full genesis and selected pins are required for execution",
                })?,
        )
    }

    pub fn client_journal_root(&self) -> std::path::PathBuf {
        self.chain.client().join("channels")
    }
    pub fn provider_journal_root(&self) -> std::path::PathBuf {
        self.chain.provider().join("channels")
    }

    pub fn check_node(&self, node: &hellas_chain::node::FullNode) -> Result<()> {
        let (genesis, payload) = self
            .chain
            .execution()
            .map_err(|_| WorkConfigError::Invalid {
                field: "chain",
                reason: "full genesis is required for execution",
            })?;
        let actual = node.config();
        if genesis != actual.genesis()
            || self.threshold_identity()? != actual.threshold_identity()
            || payload.is_some_and(|pin| {
                actual
                    .genesis_payload()
                    .is_none_or(|found| pin.as_slice() != found.as_ref())
            })
        {
            return Err(WorkConfigError::Invalid {
                field: "chain",
                reason: "paid configuration differs from the process's chain node",
            });
        }
        Ok(())
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
