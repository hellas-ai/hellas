//! Paid-work configuration: chain identity, routes, execution policy and funding.
//!
//! The threshold identity authenticates finalized blocks; the network and genesis
//! digest detect configuration mismatches. Unknown fields are rejected. Call
//! `validate_work_routes` before serving to check the configuration against journals.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod error;
pub use error::WorkConfigError;
type Result<T> = std::result::Result<T, WorkConfigError>;
use hellas_kernel::{
    EdgeId, EdgeValues, Fees, Key, MIN_OMIT_RESPONSE_BLOCKS, NetworkId, Secp256k1Verifier,
};
use hellas_rpc::ContentId;
use hellas_rpc::peers::PeerId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, check_execution_policy,
};
use hellas_rpc::protocol::work_fetch::{
    FetchRoutePolicy as PaidFetchRoutePolicy, PaidFetchPolicyV1, fetch_route_commitment,
};
use hellas_rpc::protocol::work_profile::PaidWorkPolicy;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_work::work_store::{Role, SetupStore, discover_setups};
use serde::Deserialize;

/// Number of distinct validator RPC URLs required by this deployment.
pub const VALIDATOR_COUNT: usize = 6;

/// Parsed paid-work configuration. `load_work_config` checks its fields;
/// `validate_work_routes` checks agreement with provider journals at startup.
#[derive(Clone, Debug)]
pub struct WorkConfig {
    /// The chain this node believes it is configured against.
    pub chain: ChainCrossCheck,
    /// Validator RPC URLs used for chain reads and transaction submission.
    pub validators: Vec<String>,
    /// Directory holding the setup and channel journals.
    pub journal_root: PathBuf,
    /// Bilateral setup routes, keyed by the authenticated transport peer.
    pub routes: WorkRoutes,
    /// Salt of the private credit-policy commitment.
    pub policy_salt: [u8; 32],
    /// The credit policy this provider will work under.
    pub channel_policy: PaidChannelPolicyV1,
    /// The execution policy this provider will run jobs under.
    pub execution_policy: PaidWorkPolicy,
    /// How often the watcher asks the chain for the next block.
    pub poll: Duration,
    /// Maximum time without new verified finalized progress before admission stops.
    /// Renewal requires an advancing finalized height, so this must also fit
    /// the deployment's block interval, not only the polling interval.
    pub max_observation_age: Duration,
    /// The payment edge's value, reserve, and close fees as this provider
    /// requires a client to fund them.
    pub expected_payment_values: EdgeValues,
    /// The shortest response window this provider signs terms over.
    pub min_omit_response_blocks: u64,
}

/// Maps an authenticated peer to a bond and its client settlement key.
/// Startup checks the client key against the journal before mounting the route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRoute {
    /// The transport-authenticated peer allowed to reach this bond.
    pub peer: PeerId,
    /// The bond whose provider setup journal this route names.
    pub bond: EdgeId,
    /// The settlement key the bond terms must name as taker.
    pub client: Key,
}

/// Routes indexed by authenticated peer, with duplicate peers and bonds rejected.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkRoutes {
    by_peer: BTreeMap<PeerId, WorkRoute>,
}

impl WorkRoutes {
    /// Returns every configured route in peer order.
    pub fn iter(&self) -> impl Iterator<Item = &WorkRoute> {
        self.by_peer.values()
    }

    /// Returns how many bilateral routes were configured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_peer.len()
    }

    /// Returns whether no bilateral route was configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_peer.is_empty()
    }

    fn from_files(files: Vec<WorkRouteFile>) -> Result<Self> {
        let mut by_peer = BTreeMap::new();
        let mut bonds = BTreeSet::new();
        for file in files {
            let peer = PeerId::from_bytes(parse_fixed_hex("routes[].peer", &file.peer)?);
            let bond = EdgeId::from_bytes(parse_fixed_hex("routes[].bond", &file.bond)?);
            let client = Key::from_bytes(parse_fixed_hex("routes[].client", &file.client)?);
            let route = WorkRoute { peer, bond, client };
            if by_peer.insert(peer, route).is_some() {
                return Err(WorkConfigError::DuplicatePeer(peer));
            }
            if !bonds.insert(bond) {
                return Err(WorkConfigError::DuplicateBond(bond));
            }
        }
        Ok(Self { by_peer })
    }
}

impl WorkConfig {
    /// Builds the policy used by both provisioning and channel admission.
    #[must_use]
    pub fn provider_policy(&self) -> ProviderChannelPolicy {
        ProviderChannelPolicy {
            network: self.chain.network,
            policy_salt: self.policy_salt,
            channel_policy: self.channel_policy,
            execution_policy: self.execution_policy.clone(),
            expected_payment_values: self.expected_payment_values,
            min_omit_response_blocks: self.min_omit_response_blocks,
        }
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
}

/// Loads configuration, checks chain identity and policy bounds, and normalizes
/// validator URLs. Route-to-journal validation is deferred until serve startup.
pub fn load_work_config(path: &Path) -> Result<WorkConfig> {
    let bytes = fs::read(path).map_err(|source| WorkConfigError::Read {
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

/// Checks each route against a provider journal under the configured root,
/// including its bond and client key. Run after provisioning and before serving.
pub fn validate_work_routes(config: &WorkConfig) -> Result<()> {
    if config.routes.is_empty() {
        return Ok(());
    }
    let found = discover_setups(&config.journal_root, config.chain.network).map_err(|source| {
        WorkConfigError::Journal {
            root: config.journal_root.clone(),
            source,
        }
    })?;
    for route in config.routes.iter() {
        if !found
            .setups
            .iter()
            .any(|setup| setup.role == Role::Provider && setup.bond_edge == route.bond)
        {
            return Err(WorkConfigError::MissingRoute {
                bond: route.bond,
                root: config.journal_root.clone(),
            });
        }
        let store = SetupStore::open(
            &config.journal_root,
            config.chain.network,
            route.bond,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .map_err(|source| WorkConfigError::Journal {
            root: config.journal_root.clone(),
            source,
        })?;
        let Some(bundle) = store.state().bundle() else {
            return Err(WorkConfigError::MissingProposal(route.bond));
        };
        let journal_client = bundle.bond_terms().parties.taker();
        if journal_client != route.client {
            return Err(WorkConfigError::WrongClient {
                bond: route.bond,
                expected: route.client,
                actual: journal_client,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkConfigFile {
    chain: ChainFile,
    validators: Vec<String>,
    journal: JournalFile,
    routes: Vec<WorkRouteFile>,
    policies: PoliciesFile,
    /// How often the watcher asks the chain for the next block.
    poll_ms: u64,
    #[serde(default = "default_observation_age_ms")]
    max_observation_age_ms: u64,
    expected_payment_values: PaymentValuesFile,
    min_omit_response_blocks: u64,
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
        let threshold_identity =
            parse_hex("chain.threshold_identity", &self.chain.threshold_identity)?;
        // Parsed before the verifier is built, so the list consensus is
        // handed is the normalised one this node will actually dial.
        let validators = parse_validators(self.validators)?;
        // The same constructor consensus verification uses. A threshold
        // identity that cannot be decoded here is one no finalized block
        // would ever verify under, and the node says so before it serves.
        hellas_chain::ConsensusVerifier::new(&hellas_chain::light_client::ConsensusInfo {
            validators: validators.clone(),
            threshold_identity: threshold_identity.clone(),
            network_id: network.as_str().to_owned(),
        })?;

        let journal_root = self.journal.into_root()?;
        let routes = WorkRoutes::from_files(self.routes)?;
        let policies = self.policies.into_policies()?;
        if self.poll_ms == 0 {
            return Err(WorkConfigError::Invalid {
                field: "poll_ms",
                reason: "must be greater than zero",
            });
        }
        if self.max_observation_age_ms <= self.poll_ms {
            return Err(WorkConfigError::Invalid {
                field: "max_observation_age_ms",
                reason: "must exceed poll_ms",
            });
        }
        // The kernel refuses a shorter window at every payment open, so a
        // configuration under it would sign terms consensus then throws
        // away.
        if self.min_omit_response_blocks < MIN_OMIT_RESPONSE_BLOCKS {
            return Err(WorkConfigError::ResponseWindow {
                actual: self.min_omit_response_blocks,
                minimum: MIN_OMIT_RESPONSE_BLOCKS,
            });
        }

        Ok(WorkConfig {
            chain: ChainCrossCheck {
                network,
                genesis_payload_digest: parse_digest(
                    "chain.genesis_payload_digest",
                    &self.chain.genesis_payload_digest,
                )?,
                threshold_identity,
            },
            validators,
            journal_root,
            routes,
            policy_salt: policies.0,
            channel_policy: policies.1,
            execution_policy: policies.2,
            poll: Duration::from_millis(self.poll_ms),
            max_observation_age: Duration::from_millis(self.max_observation_age_ms),
            expected_payment_values: self.expected_payment_values.into_values(),
            min_omit_response_blocks: self.min_omit_response_blocks,
        })
    }
}

/// Hex-encoded route fields, parsed before duplicate detection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRouteFile {
    peer: String,
    bond: String,
    client: String,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    root: PathBuf,
}

impl JournalFile {
    fn into_root(self) -> Result<PathBuf> {
        if self.root.as_os_str().is_empty() {
            return Err(WorkConfigError::Invalid {
                field: "journal.root",
                reason: "must be a path",
            });
        }
        Ok(self.root)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoliciesFile {
    policy_salt: String,
    channel: ChannelPolicyFile,
    execution: Option<ExecutionPolicyFile>,
    fetch: Option<FetchPolicyFile>,
}

impl PoliciesFile {
    fn into_policies(self) -> Result<([u8; 32], PaidChannelPolicyV1, PaidWorkPolicy)> {
        let salt = parse_fixed_hex("policies.policy_salt", &self.policy_salt)?;
        Ok((
            salt,
            PaidChannelPolicyV1 {
                compute_credit_limit: self.channel.compute_credit_limit,
                delivery_credit_limit: self.channel.delivery_credit_limit,
            },
            match (self.execution, self.fetch) {
                (Some(execution), None) => execution.into_policy()?.into(),
                (None, Some(fetch)) => fetch.into_policy()?,
                _ => {
                    return Err(WorkConfigError::Invalid {
                        field: "policies",
                        reason: "must select exactly one of execution or fetch",
                    });
                }
            },
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelPolicyFile {
    compute_credit_limit: u64,
    delivery_credit_limit: u64,
}

/// Required execution-policy fields. Defaults could change the terms being signed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionPolicyFile {
    allowed_environment: String,
    generation_policy_digest: String,
    identity_source_digest: String,
    max_prompt_tokens: u32,
    max_new_tokens: u32,
    max_stop_token_ids: u16,
    max_spool_bytes: u64,
    max_encoded_result_frame: u32,
    max_encoded_quote_response: u32,
    dispatch_margin_blocks: u64,
    delivery_margin_blocks: u64,
    oracle_grace_blocks: u64,
    fixed_price: u64,
}

impl ExecutionPolicyFile {
    fn into_policy(self) -> Result<PaidExecutionPolicyV1> {
        let allowed_environment: ContentId =
            self.allowed_environment
                .parse()
                .map_err(|source| WorkConfigError::ContentId {
                    field: "policies.execution.allowed_environment",
                    source,
                })?;
        let policy = PaidExecutionPolicyV1 {
            allowed_environment,
            generation_policy_digest: parse_digest(
                "policies.execution.generation_policy_digest",
                &self.generation_policy_digest,
            )?,
            identity_source_digest: parse_digest(
                "policies.execution.identity_source_digest",
                &self.identity_source_digest,
            )?,
            max_prompt_tokens: self.max_prompt_tokens,
            max_new_tokens: self.max_new_tokens,
            max_stop_token_ids: self.max_stop_token_ids,
            max_spool_bytes: self.max_spool_bytes,
            max_encoded_result_frame: self.max_encoded_result_frame,
            max_encoded_quote_response: self.max_encoded_quote_response,
            dispatch_margin_blocks: self.dispatch_margin_blocks,
            delivery_margin_blocks: self.delivery_margin_blocks,
            oracle_grace_blocks: self.oracle_grace_blocks,
            fixed_price: self.fixed_price,
        };
        // Validate with the protocol rules before any channel is proposed.
        check_execution_policy(&policy)?;
        Ok(policy)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchPolicyFile {
    allowed_environment: String,
    service: Option<String>,
    method: Option<String>,
    open_fetch: Option<OpenFetchPolicyFile>,
    max_request_body_bytes: u32,
    max_output_events: u32,
    max_output_bytes: u32,
    max_spool_bytes: u64,
    max_encoded_result_frame: u32,
    max_encoded_prepared_input: u32,
    dispatch_margin_blocks: u64,
    delivery_margin_blocks: u64,
    oracle_grace_blocks: u64,
    fixed_price: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenFetchPolicyFile {
    #[serde(default)]
    require_spki_pin: bool,
    #[serde(default)]
    allowed_hosts: Vec<String>,
}

impl FetchPolicyFile {
    fn into_policy(self) -> Result<PaidWorkPolicy> {
        let route = match (self.service, self.method, self.open_fetch) {
            (Some(service), Some(method), None) => {
                PaidFetchRoutePolicy::sealed_route(service, method)?
            }
            (None, None, Some(open)) => {
                PaidFetchRoutePolicy::open_fetch(open.require_spki_pin, open.allowed_hosts)
            }
            _ => {
                return Err(WorkConfigError::Invalid {
                    field: "policies.fetch",
                    reason: "requires service+method or open_fetch",
                });
            }
        };
        let policy = PaidFetchPolicyV1 {
            allowed_environment: self.allowed_environment.parse().map_err(|source| {
                WorkConfigError::ContentId {
                    field: "policies.fetch.allowed_environment",
                    source,
                }
            })?,
            route_commitment: fetch_route_commitment(&route.canonical_body_bytes())?,
            max_request_body_bytes: self.max_request_body_bytes,
            max_output_events: self.max_output_events,
            max_output_bytes: self.max_output_bytes,
            max_spool_bytes: self.max_spool_bytes,
            max_encoded_result_frame: self.max_encoded_result_frame,
            max_encoded_prepared_input: self.max_encoded_prepared_input,
            dispatch_margin_blocks: self.dispatch_margin_blocks,
            delivery_margin_blocks: self.delivery_margin_blocks,
            oracle_grace_blocks: self.oracle_grace_blocks,
            fixed_price: self.fixed_price,
        };
        let profile = PaidWorkPolicy::Fetch { policy, route };
        profile.check()?;
        Ok(profile)
    }
}

/// Required funding values and close fees.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentValuesFile {
    value: u64,
    reserve: u64,
    close_fees: CloseFeesFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseFeesFile {
    base: u64,
    slot: u64,
    proof: u64,
    lifetime: u64,
}

impl PaymentValuesFile {
    fn into_values(self) -> EdgeValues {
        EdgeValues::new(
            self.value,
            self.reserve,
            Fees::new(
                self.close_fees.base,
                self.close_fees.slot,
                self.close_fees.proof,
                self.close_fees.lifetime,
            ),
        )
    }
}

fn parse_hex(field: &'static str, raw: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(raw.trim()).map_err(|source| WorkConfigError::Hex { field, source })?;
    if bytes.is_empty() {
        return Err(WorkConfigError::Invalid {
            field,
            reason: "must not be empty",
        });
    }
    Ok(bytes)
}

fn parse_fixed_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N]> {
    let bytes = parse_hex(field, raw)?;
    let Ok(bytes) = <[u8; N]>::try_from(bytes.as_slice()) else {
        return Err(WorkConfigError::Length {
            field,
            expected: N,
            actual: bytes.len(),
        });
    };
    Ok(bytes)
}

fn parse_digest(field: &'static str, raw: &str) -> Result<Digest> {
    Ok(Digest::from_bytes(parse_fixed_hex(field, raw)?))
}
