//! Paid-provider process configuration. Paid terms live in the node authority.

use std::path::{Path, PathBuf};
use std::time::Duration;
mod error;
#[cfg(test)]
mod tests;
pub use error::WorkConfigError;
type Result<T> = std::result::Result<T, WorkConfigError>;
use crate::resource_config::{parse_digest, parse_hex};
use hellas_auth::Digest;
use hellas_kernel::NetworkId;
use serde::Deserialize;

/// Number of distinct validator RPC URLs required by this deployment.
pub const VALIDATOR_COUNT: usize = 6;

/// Process-owned chain identity, journal location and observation bounds.
/// [`WorkConfig::validate`] and [`load_work_config`] run the same checks.
#[derive(Clone, Debug)]
pub struct WorkConfig {
    /// The chain this node believes it is configured against.
    pub chain: ChainCrossCheck,
    /// Validator RPC URLs used for chain reads and transaction submission.
    pub validators: Vec<String>,
    /// Directory holding the setup and channel journals.
    pub journal_root: PathBuf,
    /// How often the watcher asks the chain for the next block.
    pub poll: Duration,
    /// Maximum time without new verified finalized progress before admission stops.
    /// Renewal requires an advancing finalized height, so this must also fit
    /// the deployment's block interval, not only the polling interval.
    pub max_observation_age: Duration,
}

impl WorkConfig {
    /// Checks chain identity and timing bounds and normalizes the six distinct
    /// WebSocket validator URLs, as [`load_work_config`] does.
    pub fn validate(mut self) -> Result<Self> {
        self.validators = parse_validators(self.validators)?;
        if self.chain.threshold_identity.is_empty() {
            return Err(crate::ResourceConfigError::Invalid {
                field: "chain.threshold_identity",
                reason: "must not be empty",
            }
            .into());
        }
        // Use the same decoder as finalized-block verification.
        hellas_chain::ConsensusVerifier::new(
            &hellas_chain::light_client::ConsensusInfo {
                validators: self.validators.clone(),
                threshold_identity: self.chain.threshold_identity.clone(),
                network_id: self.chain.network.as_str().to_owned(),
            },
            hellas_chain::genesis_digest(&chain_genesis(self.chain.network, &self.chain.genesis)?),
        )?;
        if self.journal_root.as_os_str().is_empty() {
            return Err(WorkConfigError::Invalid {
                field: "journal.root",
                reason: "must be a path",
            });
        }
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

    /// Builds the process's shared executing node. The host owns its directory
    /// and passes the same node handle to every paid client and provider.
    pub fn node_config(
        &self,
        storage_dir: PathBuf,
        archive_blocks: Option<std::num::NonZeroU64>,
    ) -> Result<hellas_chain::node::Config> {
        let genesis = chain_genesis(self.chain.network, &self.chain.genesis)?;
        Ok(hellas_chain::node::Config {
            genesis,
            threshold_identity: self.chain.threshold_identity.clone(),
            genesis_payload: self
                .chain
                .genesis_payload_digest
                .as_bytes()
                .to_owned()
                .into(),
            storage_dir,
            validators: self.validators.clone(),
            peers: Vec::new(),
            archive_blocks,
        })
    }

    /// Refuses a paid configuration whose execution genesis or finality pins
    /// differ from the process's shared node.
    pub fn check_node(&self, node: &hellas_chain::node::FullNode) -> Result<()> {
        let expected = self.node_config(
            node.config().storage_dir.clone(),
            node.config().archive_blocks,
        )?;
        let actual = node.config();
        if expected.genesis != actual.genesis
            || expected.threshold_identity != actual.threshold_identity
            || expected.genesis_payload != actual.genesis_payload
        {
            return Err(WorkConfigError::Invalid {
                field: "chain",
                reason: "paid configuration differs from the process's chain node",
            });
        }
        Ok(())
    }
}

/// The three fields that say which chain this is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainCrossCheck {
    /// The network every signature on this node's channels is bound to.
    pub network: NetworkId,
    /// Payload digest of the genesis block this deployment began at.
    pub genesis_payload_digest: Digest,
    /// The threshold identity finalized blocks are verified under.
    pub threshold_identity: Vec<u8>,
    /// Execution inputs for a custom network. Shipped networks may omit this.
    pub genesis: Option<hellas_chain::genesis::Genesis>,
}

/// Checks the chain identity and observer bounds and normalizes validator URLs.
pub fn load_work_config(path: &Path) -> Result<WorkConfig> {
    let bytes = hellas_private::read_bounded_regular_file(
        path,
        hellas_work::work_store::journal::MAX_RECORD_BYTES,
    )
    .map_err(|source| WorkConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let file: WorkConfigFile =
        serde_json::from_slice(&bytes).map_err(|source| WorkConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    file.into_config().map_err(|source| WorkConfigError::File {
        path: path.to_path_buf(),
        source: Box::new(source),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkConfigFile {
    chain: ChainFile,
    validators: Vec<String>,
    journal: JournalFile,
    /// How often the watcher asks the chain for the next block.
    poll_ms: u64,
    #[serde(default = "default_observation_age_ms")]
    max_observation_age_ms: u64,
}

pub(crate) fn chain_genesis(
    network: NetworkId,
    genesis: &Option<hellas_chain::genesis::Genesis>,
) -> Result<hellas_chain::genesis::Genesis> {
    let genesis = match genesis {
        Some(genesis) => genesis.clone(),
        None => {
            let network = hellas_chain::genesis::known_network(network.as_str()).ok_or(
                WorkConfigError::Invalid {
                    field: "chain.genesis",
                    reason: "required for a network without a shipped genesis document",
                },
            )?;
            serde_json::from_str(network.json).map_err(|_| WorkConfigError::Invalid {
                field: "chain.genesis",
                reason: "shipped genesis document cannot be decoded",
            })?
        }
    };
    if genesis.network_id != network.as_str() {
        return Err(WorkConfigError::Invalid {
            field: "chain.genesis.network_id",
            reason: "must match chain.network_id",
        });
    }
    Ok(genesis)
}

fn default_observation_age_ms() -> u64 {
    5_000
}

impl WorkConfigFile {
    fn into_config(self) -> Result<WorkConfig> {
        let Some(network) = NetworkId::new(self.chain.network_id.trim()) else {
            return Err(WorkConfigError::Invalid {
                field: "chain.network_id",
                reason: "not a network id",
            });
        };
        WorkConfig {
            chain: ChainCrossCheck {
                network,
                genesis_payload_digest: parse_digest(
                    "chain.genesis_payload_digest",
                    &self.chain.genesis_payload_digest,
                )?,
                threshold_identity: parse_hex(
                    "chain.threshold_identity",
                    &self.chain.threshold_identity,
                )?,
                genesis: self.chain.genesis,
            },
            validators: self.validators,
            journal_root: self.journal.root,
            poll: Duration::from_millis(self.poll_ms),
            max_observation_age: Duration::from_millis(self.max_observation_age_ms),
        }
        .validate()
    }
}

/// Normalizes validator URLs and requires distinct addresses with hosts.
fn parse_validators(entries: Vec<String>) -> Result<Vec<String>> {
    let mut validators: Vec<String> = Vec::with_capacity(VALIDATOR_COUNT);
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(WorkConfigError::Invalid {
                field: "validators",
                reason: "entries must be non-empty",
            });
        }
        let url = url::Url::parse(entry).map_err(|source| WorkConfigError::ValidatorUrl {
            entry: entry.to_owned(),
            source,
        })?;
        if url.host_str().is_none() {
            return Err(WorkConfigError::ValidatorHost(entry.to_owned()));
        }
        if !matches!(url.scheme(), "ws" | "wss") {
            return Err(WorkConfigError::Invalid {
                field: "validators",
                reason: "must use ws:// or wss:// URLs",
            });
        }
        let normalised = url.as_str().to_string();
        if validators.contains(&normalised) {
            return Err(WorkConfigError::DuplicateValidator(normalised));
        }
        validators.push(normalised);
    }
    if validators.len() != VALIDATOR_COUNT {
        return Err(WorkConfigError::ValidatorCount {
            expected: VALIDATOR_COUNT,
            actual: validators.len(),
        });
    }
    Ok(validators)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainFile {
    network_id: String,
    genesis_payload_digest: String,
    threshold_identity: String,
    #[serde(default)]
    genesis: Option<hellas_chain::genesis::Genesis>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    root: PathBuf,
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
