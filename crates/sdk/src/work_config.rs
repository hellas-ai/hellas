//! The paid-work configuration file: what an operator writes down, and
//! what a node refuses to start without.
//!
//! `--work-config` was a path whose *presence* advertised two ALPNs and
//! whose contents were never opened. A node cannot mount a channel from
//! a path, so this is the schema and the loader for what is in it: the
//! three-part chain cross-check, the six validator URLs a write is
//! fanned to, the journal root, the bilateral route table, the two
//! policies this provider works under, the watcher's poll cadence, the
//! funding it expects a payment edge to carry, and the shortest response
//! window it will sign terms over.
//!
//! # The cross-check is not an anchor
//!
//! `(network_id, genesis_payload_digest, threshold_identity)` is a
//! fail-fast configuration cross-check. Only the threshold identity ever
//! authenticates a finalized block; the other two are how a node started
//! against the wrong chain says so at startup instead of at the first
//! settlement. The identity is decoded here, by the same constructor
//! consensus verification uses, so a typo is a startup error and not a
//! block that never verifies.
//!
//! # What is deliberately not here
//!
//! There is no Start-span field, no mutual-margin field, and no journal
//! cap. All were deleted: the Start span is fixed at 64, a work-payment
//! edge has no Mutual route, and the journal's active and checkpoint
//! ceilings are constants it enforces on itself
//! ([`MAX_ACTIVE_JOURNAL_BYTES`]), so any of them appearing in a file is
//! an operator configuring something that does not exist. Every struct
//! below denies unknown fields, which is what turns that into an error
//! naming the field.
//!
//! Nor is there a measured artifact. An earlier design derived the
//! response window and an alarm margin from latencies a bootstrap probe
//! recorded, pinned to the digest of the measuring binary; no deployed
//! node ever carried one, and every rebuild would have invalidated it.
//! The two numbers that design would have produced are written down
//! here instead, by the operator, and [`WorkConfig::provider_policy`] is
//! the whole of what is made from them.
//!
//! [`MAX_ACTIVE_JOURNAL_BYTES`]: hellas_work::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
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

type CliResult<T> = anyhow::Result<T>;

/// How many validator RPCs a write names.
///
/// Reads come from a follower and writes are fanned to all six; a
/// configuration naming five has one validator whose acceptance this
/// node can never win, and one naming seven names something this
/// deployment does not have.
pub const VALIDATOR_COUNT: usize = 6;

/// One operator's complete paid-work configuration, loaded and structurally
/// checked.
///
/// A plain record with public fields, for [`WorkChannelConfig`]'s
/// reason: this is the shape a file fills in. Every file-local gate has
/// already run in [`load_work_config`]; the serve path then runs
/// [`validate_work_routes`] against the journals that must exist when it
/// starts. Provisioning shares the file loader before it creates one, which is
/// why disk agreement is not pretended to be a parse-time fact.
///
/// [`WorkChannelConfig`]: hellas_rpc::protocol::work_setup::WorkChannelConfig
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct WorkConfig {
    /// The chain this node believes it is configured against.
    pub chain: ChainCrossCheck,
    /// The six validator RPC URLs every write is fanned to.
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
    /// The payment edge's value, reserve, and close fees as this provider
    /// requires a client to fund them.
    pub expected_payment_values: EdgeValues,
    /// The shortest response window this provider signs terms over.
    pub min_omit_response_blocks: u64,
}

/// One bilateral setup route written in the paid-work configuration.
///
/// The bond names the provider setup journal under [`WorkConfig::journal_root`].
/// The client key is repeated here deliberately: startup compares it with the
/// taker committed inside that journal, turning a stale or mistyped route into
/// a refusal before the node binds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRoute {
    /// The transport-authenticated peer allowed to reach this bond.
    pub peer: PeerId,
    /// The bond whose provider setup journal this route names.
    pub bond: EdgeId,
    /// The settlement key the bond terms must name as taker.
    pub client: Key,
}

/// Paid-work routes keyed by their authenticated peer.
///
/// Construction is private to the checked file loader. In particular, there
/// is no insertion API through which a caller could recreate last-one-wins
/// handling after duplicate peers and bonds have been refused.
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

    fn from_files(files: Vec<WorkRouteFile>) -> CliResult<Self> {
        let mut by_peer = BTreeMap::new();
        let mut bonds = BTreeSet::new();
        for file in files {
            let peer = PeerId::from_bytes(parse_fixed_hex("routes[].peer", &file.peer)?);
            let bond = EdgeId::from_bytes(parse_fixed_hex("routes[].bond", &file.bond)?);
            let client = Key::from_bytes(parse_fixed_hex("routes[].client", &file.client)?);
            let route = WorkRoute { peer, bond, client };
            if by_peer.insert(peer, route).is_some() {
                bail!("routes names peer {peer:#} twice; one authenticated peer has one route");
            }
            if !bonds.insert(bond) {
                bail!(
                    "routes names bond {} twice; one provider journal has one route",
                    hex::encode(bond.to_bytes()),
                );
            }
        }
        Ok(Self { by_peer })
    }
}

impl WorkConfig {
    /// The provider policy this configuration makes.
    ///
    /// Every field is the operator's: the four the policy commits to,
    /// the funding it expects, and the window it insists on. Nothing is
    /// measured and nothing is inferred, so a node with a configuration
    /// has a policy and countersigns over it.
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
#[allow(
    dead_code,
    reason = "the fields a mount consumes are read by the node runner; loading and checking them is this half"
)]
pub struct ChainCrossCheck {
    /// The network every signature on this node's channels is bound to.
    pub network: NetworkId,
    /// Payload digest of the genesis block this deployment began at.
    pub genesis_payload_digest: Digest,
    /// The threshold identity finalized blocks are verified under.
    pub threshold_identity: Vec<u8>,
}

/// Loads and checks one paid-work configuration file.
///
/// Every failure is a startup failure naming the field that failed, for
/// the reason §4 gives: a node that started with an unreadable
/// configuration would be one whose first symptom is an unsettleable
/// channel.
///
/// # Errors
///
/// The read and the parse, and then: a network id that is not one, a
/// digest that is not thirty-two bytes, a threshold identity consensus
/// cannot decode, a validator list that is not exactly
/// [`VALIDATOR_COUNT`] URLs with distinct normalised forms, an execution
/// policy the protocol's own [`check_execution_policy`] rejects, an
/// empty journal root, a route field of the wrong width, duplicate peers or
/// bonds in the route table, a zero poll cadence, and a response window
/// under the kernel's own minimum.
pub fn load_work_config(path: &Path) -> CliResult<WorkConfig> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let file: WorkConfigFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    file.into_config()
        .with_context(|| format!("invalid work config {}", path.display()))
}

/// Verifies that every configured route names this root's provider journal
/// and the client settlement key committed by its bond terms.
///
/// This is a serve-startup check rather than part of [`load_work_config`]:
/// provisioning uses the same configuration loader before it creates a
/// journal, while a serving node must already have every journal it promises.
/// Discovery comes first so [`SetupStore::open`] is never allowed to create a
/// missing journal merely because a route named its bond.
///
/// # Errors
///
/// The root cannot be enumerated, a route's provider journal is absent from
/// that root or cannot be opened, the journal holds no bond proposal, or its
/// bond names a taker other than the route's configured client.
pub fn validate_work_routes(config: &WorkConfig) -> CliResult<()> {
    if config.routes.is_empty() {
        return Ok(());
    }
    let found = discover_setups(&config.journal_root, config.chain.network).with_context(|| {
        format!(
            "failed to enumerate configured work routes under journal.root {}",
            config.journal_root.display(),
        )
    })?;
    for route in config.routes.iter() {
        if !found
            .setups
            .iter()
            .any(|setup| setup.role == Role::Provider && setup.bond_edge == route.bond)
        {
            bail!(
                "route for peer {:#} names bond {}, but its provider setup journal is not under \
                 journal.root {}",
                route.peer,
                hex::encode(route.bond.to_bytes()),
                config.journal_root.display(),
            );
        }
        let store = SetupStore::open(
            &config.journal_root,
            config.chain.network,
            route.bond,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .with_context(|| {
            format!(
                "route for peer {:#} could not open provider setup journal for bond {} under {}",
                route.peer,
                hex::encode(route.bond.to_bytes()),
                config.journal_root.display(),
            )
        })?;
        let Some(bundle) = store.state().bundle() else {
            bail!(
                "route for peer {:#} names provider setup journal for bond {}, but it holds no \
                 bond proposal",
                route.peer,
                hex::encode(route.bond.to_bytes()),
            );
        };
        let journal_client = bundle.bond_terms().parties.taker();
        if journal_client != route.client {
            bail!(
                "route for peer {:#} expects client settlement key {}, but provider setup journal \
                 for bond {} names {} as its taker",
                route.peer,
                hex::encode(route.client.to_bytes()),
                hex::encode(route.bond.to_bytes()),
                hex::encode(journal_client.to_bytes()),
            );
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
    expected_payment_values: PaymentValuesFile,
    min_omit_response_blocks: u64,
}

impl WorkConfigFile {
    fn into_config(self) -> CliResult<WorkConfig> {
        let Some(network) = NetworkId::new(self.chain.network_id.trim()) else {
            bail!(
                "chain.network_id {:?} is not a network id",
                self.chain.network_id
            );
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
            network_id: self.chain.network_id.clone(),
        })
        .map_err(|error| anyhow::anyhow!("chain.threshold_identity is not usable: {error}"))?;

        let journal_root = self.journal.into_root()?;
        let routes = WorkRoutes::from_files(self.routes)?;
        let policies = self.policies.into_policies()?;
        if self.poll_ms == 0 {
            bail!("poll_ms must be greater than zero");
        }
        // The kernel refuses a shorter window at every payment open, so a
        // configuration under it would sign terms consensus then throws
        // away.
        if self.min_omit_response_blocks < MIN_OMIT_RESPONSE_BLOCKS {
            bail!(
                "min_omit_response_blocks {} is under the kernel's minimum {MIN_OMIT_RESPONSE_BLOCKS}",
                self.min_omit_response_blocks,
            );
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
            expected_payment_values: self.expected_payment_values.into_values(),
            min_omit_response_blocks: self.min_omit_response_blocks,
        })
    }
}

/// One bilateral route exactly as the operator writes it.
///
/// All three values are fixed-width lowercase-or-uppercase hexadecimal on
/// input and canonical byte values after loading. A peer or bond written in a
/// second spelling is therefore still the same key for duplicate detection.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRouteFile {
    peer: String,
    bond: String,
    client: String,
}

/// Parses the six validator RPC URLs, and refuses anything that is not
/// one.
///
/// Both halves matter. A string that is not a URL is not an address this
/// node can ever fan a write to, and "trimmed and non-empty" admits `not
/// a URL` verbatim — a configuration whose first symptom would be five
/// validators answering and one that never does. And uniqueness is a
/// question about *addresses*, not about spellings: `HTTP://Host:443/`
/// and `http://host:443/` are one validator written twice, and a fan-out
/// to five validators is not six however it is spelled. So the
/// comparison is between parsed, normalised URLs, and the normalised
/// forms are what is kept.
///
/// A host is required, because these are dialled: a `mailto:` or a
/// `data:` parses perfectly well and is not a validator.
fn parse_validators(entries: Vec<String>) -> CliResult<Vec<String>> {
    let mut validators: Vec<String> = Vec::with_capacity(VALIDATOR_COUNT);
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() {
            bail!("validators entries must be non-empty");
        }
        let url = url::Url::parse(entry)
            .with_context(|| format!("validators entry {entry:?} is not a URL"))?;
        if url.host_str().is_none() {
            bail!("validators entry {entry:?} names no host to dial");
        }
        let normalised = url.as_str().to_string();
        if validators.contains(&normalised) {
            bail!("validators names {normalised} twice; a fan-out to five validators is not six");
        }
        validators.push(normalised);
    }
    if validators.len() != VALIDATOR_COUNT {
        bail!(
            "validators must name exactly {VALIDATOR_COUNT} validator URLs, found {}",
            validators.len(),
        );
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

/// Where the work journals live.
///
/// A root and nothing else. How large a journal may grow is not an
/// operator's to say: the active and checkpoint ceilings are constants
/// the journal enforces on itself, so a cap here would be a number
/// written down and ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    root: PathBuf,
}

impl JournalFile {
    fn into_root(self) -> CliResult<PathBuf> {
        if self.root.as_os_str().is_empty() {
            bail!("journal.root must be a path");
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
    fn into_policies(self) -> CliResult<([u8; 32], PaidChannelPolicyV1, PaidWorkPolicy)> {
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
                _ => bail!("policies must select exactly one of execution or fetch"),
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

/// The execution policy, field for field.
///
/// Spelled out rather than flattened from some smaller shape because
/// every one of these is a value both parties sign: a default here would
/// be this node quietly proposing a policy its operator never wrote.
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
    fn into_policy(self) -> CliResult<PaidExecutionPolicyV1> {
        let allowed_environment: ContentId =
            self.allowed_environment.parse().with_context(|| {
                format!(
                    "policies.execution.allowed_environment {:?} is not a ContentId",
                    self.allowed_environment
                )
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
        // The protocol's own gate, run here rather than at the first
        // admission. A zero here is not a small bound, it is an absent
        // one — a zero margin gives a deadline no time to be met in, and
        // a zero price is a job nobody is paid for. Copying the fields
        // through unchecked moves that discovery to the moment a
        // counterparty is already waiting on a proposal.
        check_execution_policy(&policy)
            .map_err(|error| anyhow::anyhow!("policies.execution is not usable: {error}"))?;
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
    fn into_policy(self) -> CliResult<PaidWorkPolicy> {
        let route = match (self.service, self.method, self.open_fetch) {
            (Some(service), Some(method), None) => {
                PaidFetchRoutePolicy::sealed_route(service, method)?
            }
            (None, None, Some(open)) => {
                PaidFetchRoutePolicy::open_fetch(open.require_spki_pin, open.allowed_hosts)
            }
            _ => bail!("policies.fetch requires service+method or open_fetch"),
        };
        let policy = PaidFetchPolicyV1 {
            allowed_environment: self
                .allowed_environment
                .parse()
                .context("policies.fetch.allowed_environment is not a ContentId")?,
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
        profile.check().context("policies.fetch is not usable")?;
        Ok(profile)
    }
}

/// The payment edge's funding, field for field, as this provider requires
/// a client to fund it.
///
/// Spelled out for [`ExecutionPolicyFile`]'s reason: every one of these
/// bounds what a certificate on the channel may name, so a default here
/// would be this node quietly accepting funding its operator never
/// priced.
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

fn parse_hex(field: &str, raw: &str) -> CliResult<Vec<u8>> {
    let bytes = hex::decode(raw.trim()).with_context(|| format!("{field} is not hexadecimal"))?;
    if bytes.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(bytes)
}

fn parse_fixed_hex<const N: usize>(field: &str, raw: &str) -> CliResult<[u8; N]> {
    let bytes = parse_hex(field, raw)?;
    let Ok(bytes) = <[u8; N]>::try_from(bytes.as_slice()) else {
        bail!("{field} must be {N} bytes, found {}", bytes.len());
    };
    Ok(bytes)
}

fn parse_digest(field: &str, raw: &str) -> CliResult<Digest> {
    Ok(Digest::from_bytes(parse_fixed_hex(field, raw)?))
}
