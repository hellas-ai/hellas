//! Operator entry points for one paid-work channel and one paid job.
//!
//! This deliberately stays a thin orchestration layer over the setup,
//! journal, light-client, and work APIs.  The durable state remains in the
//! production setup and channel journals; this command does not keep a
//! parallel receipt or invent a second protocol.

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use hellas_chain::client::RemoteLightClient;
use hellas_chain::{ConsensusInfo, FinalizedBlockQuery, FinalizedBlockView, LightClient as _};
use hellas_kernel::{CoinId, Funding, List, MAX_PARTY_INPUTS, Secp256k1Signer};
use hellas_sdk::paid_client::{InputIdentities, PaidWorkOptions, PaidWorkRun, run_paid_work};
use hellas_work::model::fetch::PreparedPaidFetchInputV1;
use hellas_work::model::prepared_input::PreparedPaidInputV1;
use hellas_work::model::profile::PreparedWorkInput;
#[cfg(test)]
use hellas_work::model::work::{JobDeadlines, private_policy_commitment};
use hellas_work::work_store::journal::MAX_RECORD_BYTES;
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::CliResult;
use hellas_sdk::work_config::{ChainCrossCheck, WorkConfig};

/// Paid-work commands intended for deployment bring-up and smoke tests.
#[derive(Debug, Subcommand)]
pub enum PaidWorkCommand {
    /// Build a signed ephemeral Fetch input for a paid channel.
    PrepareFetch(PrepareFetchArgs),
    /// Build canonical paid input from a causal-LM environment and prompt.
    PrepareInput(PrepareInputArgs),
    /// Print the identities a prepared input requires in a provider policy.
    InspectInput(InspectInputArgs),
    /// Read the chain identity and genesis payload from validator RPCs.
    InspectChain(InspectChainArgs),
    /// Open (or resume) a durable channel, run one job, and pay for it.
    Run(Box<RunArgs>),
}

#[derive(Debug, Args)]
pub struct PrepareFetchArgs {
    #[arg(long)]
    service: String,
    #[arg(long)]
    method: String,
    /// JSON descriptor of the approved Fetch execution contract.
    #[arg(long, value_name = "FILE")]
    contract: PathBuf,
    /// Assurance authenticated before the paid request is disclosed.
    #[arg(long, default_value = "producer-signed", value_parser = ["producer-signed", "apple-app-attest"])]
    assurance: String,
    /// Provider-shaped UTF-8 JSON request, read from an ordinary file.
    #[arg(long, value_name = "FILE")]
    payload_file: PathBuf,
    /// Client-owned output file containing the signed request.
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

#[derive(Debug, Args)]
pub struct PrepareInputArgs {
    /// Canonical causal-LM environment file (for example smollm2.environment).
    #[arg(long = "environment", value_name = "FILE")]
    environment: PathBuf,

    /// Tokenizer JSON used to turn the prompt into committed token IDs.
    #[arg(long = "tokenizer", value_name = "FILE")]
    tokenizer: PathBuf,

    /// Plain-text prompt to commit.
    #[arg(long)]
    prompt: String,

    /// Maximum output tokens committed by the generation policy.
    #[arg(long = "max-new-tokens", default_value_t = 32)]
    max_new_tokens: u32,

    /// Caller-selected stop token ID. Repeat or comma-separate.
    #[arg(long = "stop-token", value_delimiter = ',')]
    stop_token_ids: Vec<u32>,

    /// Destination for canonical PreparedPaidInputV1 bytes.
    #[arg(long = "out", value_name = "FILE")]
    out: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectInputArgs {
    /// Canonical PreparedPaidInputV1 bytes.
    #[arg(long = "prepared-input", value_name = "FILE")]
    prepared_input: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectChainArgs {
    /// Validator light-client WebSocket URL. Repeat exactly six times.
    #[arg(long = "validator", value_name = "URL")]
    validators: Vec<String>,
    /// Independently authenticated deployment trust document.
    #[arg(long)]
    trust: PathBuf,
    /// Genesis document; defaults to the shipped devnet.
    #[arg(long)]
    genesis: Option<PathBuf>,
}

#[derive(Clone, Debug, Args)]
pub struct RunArgs {
    /// Existing node grant configuration; its authority must already be bootstrapped.
    #[arg(long = "grant-config")]
    grant_config: PathBuf,
    #[command(flatten)]
    chain_node: super::chain_node::ChainNodeArgs,
    /// Caller-owned private trust directory.
    #[arg(long)]
    trust_store: Option<PathBuf>,
    /// Previously approved local policy ID.
    #[arg(long)]
    trust_policy: Option<String>,
    /// Validator RPC URL. Repeat exactly six times.
    #[arg(long = "validator")]
    validators: Vec<String>,
    /// Independently authenticated chain trust document.
    #[arg(long)]
    trust: PathBuf,
    /// Genesis document; defaults to the shipped devnet.
    #[arg(long)]
    genesis: Option<PathBuf>,
    /// Expected flat price per job.
    #[arg(long = "payment")]
    payment: u64,

    /// Client-owned directory for durable setup and channel journals.
    #[arg(long = "journal-root", value_name = "DIR")]
    journal_root: PathBuf,

    /// Provider's authenticated Iroh endpoint ID.
    #[arg(long = "provider", value_name = "ENDPOINT_ID")]
    provider: EndpointId,

    /// Direct UDP address for the provider. Repeat or comma-separate.
    #[arg(long = "address", value_delimiter = ',', value_name = "IP:PORT")]
    provider_addrs: Vec<SocketAddr>,

    /// Client coin funding the payment edge. Repeat or comma-separate.
    #[arg(long = "payment-coin", value_delimiter = ',', value_name = "HEX")]
    payment_coins: Vec<String>,

    /// Canonical prepared Evaluate or Fetch input to execute.
    #[arg(long = "prepared-input", value_name = "FILE")]
    prepared_input: PathBuf,

    /// Write the authenticated canonical result transcript here.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Blocks from proposal to the last acceptance height.
    #[arg(long = "acceptance-blocks", default_value_t = 16)]
    acceptance_blocks: u64,

    /// Additional blocks from acceptance to the terminal-result deadline.
    #[arg(long = "terminal-blocks", default_value_t = 64)]
    terminal_blocks: u64,

    /// Additional blocks from terminal result to the payment deadline.
    #[arg(long = "payment-blocks", default_value_t = 32)]
    payment_blocks: u64,

    /// Wall-clock limit for setup, execution, collection, and payment.
    #[arg(long = "timeout-secs", default_value_t = 300)]
    timeout_secs: u64,

    /// After payment, open the client close and wait for finalized settlement.
    #[arg(long = "settle", visible_alias = "close-after-payment")]
    settle: bool,
}

/// Runs a paid-work operator command under an existing client identity.
pub async fn run(
    command: PaidWorkCommand,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
    producer_key: hellas_auth::ProducerSigningKey,
    principal: Option<hellas_auth::authority::PrincipalId>,
) -> CliResult<()> {
    match command {
        PaidWorkCommand::PrepareFetch(args) => prepare_fetch(args, &producer_key),
        PaidWorkCommand::PrepareInput(args) => prepare_input(args, &transport_key, &settlement_key),
        PaidWorkCommand::InspectInput(args) => {
            inspect_input(&args.prepared_input, &transport_key, &settlement_key)
        }
        PaidWorkCommand::InspectChain(args) => {
            inspect_chain(&args.validators, &args.trust, args.genesis.as_deref()).await
        }
        PaidWorkCommand::Run(args) => {
            anyhow::ensure!(
                args.timeout_secs > 0,
                "--timeout-secs must be greater than zero"
            );
            let authority = crate::identity::open_authority(&args.grant_config, principal).await?;
            let timeout = Duration::from_secs(args.timeout_secs);
            let config = client_config(&args).await?;
            let node = args.chain_node.start(&config).await?;
            let result = tokio::time::timeout(
                timeout,
                run_one(
                    *args,
                    config,
                    transport_key,
                    settlement_key,
                    node.clone(),
                    authority,
                ),
            )
            .await
            .map_err(|_| anyhow::anyhow!("paid-work run exceeded its {timeout:?} limit"));
            node.shutdown().await?;
            result?
        }
    }
}

fn prepare_fetch(args: PrepareFetchArgs, key: &hellas_auth::ProducerSigningKey) -> CliResult<()> {
    let bytes = super::read_bounded_regular_file(
        &args.contract,
        "--contract",
        hellas_rpc::protocol::fetch_contract::MAX_FETCH_CONTRACT_BYTES,
    )?;
    let environment: hellas_rpc::FetchContract = serde_json::from_slice(&bytes)?;
    let payload = super::read_bounded_regular_file(
        &args.payload_file,
        "--payload-file",
        hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES,
    )?;
    if environment.schema() == hellas_rpc::FetchSchema::HttpV1 {
        hellas_rpc::http_fetch::HttpFetchRequest::decode(&payload)?;
    }
    let assurance = match args.assurance.as_str() {
        "producer-signed" => hellas_rpc::Assurance::ProducerSigned,
        "apple-app-attest" => hellas_rpc::Assurance::AppleAppAttest,
        _ => bail!("unsupported assurance"),
    };
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        &args.service,
        &args.method,
        &payload,
        environment.manifest_id(),
        assurance,
        key,
        hellas_rpc::Retention::Ephemeral,
    )?;
    let prepared = PreparedPaidFetchInputV1::new(&events, &environment)?;
    write_private(&args.out, &prepared.encode()?)?;
    println!("prepared_input: {}", args.out.display());
    println!("allowed_environment: {}", environment.manifest_id());
    println!("provider_payload_retention: memory-only");
    Ok(())
}

fn prepare_input(
    args: PrepareInputArgs,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    let environment_bytes = super::read_bounded_regular_file(
        &args.environment,
        "causal-LM environment",
        hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
    )?;
    let environment = hellas_rpc::CausalLmEnvironment::from_canonical_bytes(&environment_bytes)
        .map_err(|error| {
            anyhow::anyhow!(
                "invalid canonical environment {}: {error}",
                args.environment.display(),
            )
        })?;
    let presentation = hellas_presentation::TextPresentation::load(&args.tokenizer)?;
    let prepared = hellas_sdk::prepare_evaluate(
        hellas_sdk::gateway::WorkExecutionRequest {
            environment,
            input_ids: presentation.encode(&args.prompt)?,
            max_new_tokens: args.max_new_tokens,
            stop_token_ids: args.stop_token_ids,
        },
        hellas_auth::PublicKey::Secp256k1(settlement_key.party_key().to_bytes()),
    )?;
    write_private(&args.out, &prepared.encode()?)?;
    println!("prepared_input: {}", args.out.display());
    println!("prepared_input_bytes: {}", prepared.encode()?.len());
    inspect_prepared(&prepared, transport_key, settlement_key)
}

fn inspect_input(
    path: &Path,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    match read_prepared_work_input(path)? {
        PreparedWorkInput::Evaluate(prepared) => {
            inspect_prepared(&prepared, transport_key, settlement_key)
        }
        PreparedWorkInput::Fetch(prepared) => {
            let parts = prepared.parts()?;
            let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "profile": "fetch",
                    "service": request.service,
                    "method": request.method,
                    "allowed_environment": parts.manifest.content_id().to_string(),
                    "caller_key": hex::encode(request.caller_key.bytes()),
                    "provider_payload_retention": "memory-only",
                }))?
            );
            Ok(())
        }
    }
}

fn inspect_prepared(
    prepared: &PreparedPaidInputV1,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    let identities = InputIdentities::from_prepared(prepared)?;
    let output = serde_json::json!({
        "client_transport_peer": hex::encode(transport_key.public().as_bytes()),
        "client_settlement_key": hex::encode(settlement_key.party_key().to_bytes()),
        // ContentId's textual form is Xet's canonical per-limb hex spelling,
        // which is what WorkConfig parses. Raw digest-byte hex is different
        // for non-uniform hashes and would make the printed JSON unusable.
        "allowed_environment": identities.allowed_environment.to_string(),
        "generation_policy_digest": hex::encode(identities.generation_policy_digest.as_bytes()),
        "identity_source_digest": hex::encode(identities.identity_source_digest.as_bytes()),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn inspect_chain(
    validators: &[String],
    trust_path: &std::path::Path,
    genesis_path: Option<&std::path::Path>,
) -> CliResult<()> {
    let (info, genesis) = read_chain(validators, trust_path, genesis_path).await?;
    let output = serde_json::json!({
        "chain": {
            "network_id": info.network_id,
            "genesis_payload_digest": hex::encode(genesis),
            "threshold_identity": hex::encode(info.threshold_identity),
        },
        "validators": validators,
        "reported_consensus_validators": info.validators,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn read_chain(
    validators: &[String],
    trust_path: &Path,
    genesis_path: Option<&Path>,
) -> CliResult<(ConsensusInfo, [u8; 32])> {
    anyhow::ensure!(
        validators.len() == 6,
        "--validator must be passed exactly six times, got {}",
        validators.len(),
    );
    let trust = serde_json::from_slice(&std::fs::read(trust_path)?)?;
    let genesis_json = match genesis_path {
        Some(path) => std::fs::read(path)?,
        None => hellas_chain::genesis::HELLAS_DEVNET_1_JSON
            .as_bytes()
            .to_vec(),
    };
    let mut observed: Option<(ConsensusInfo, [u8; 32])> = None;
    for url in validators {
        let client = RemoteLightClient::connect(url.clone())
            .await
            .with_context(|| format!("failed to connect to validator {url}"))?;
        let info = client
            .get_consensus_info()
            .await
            .with_context(|| format!("failed to read consensus info from {url}"))?;
        let first = client
            .get_finalized_block(FinalizedBlockQuery::Height(1))
            .await
            .with_context(|| format!("failed to read finalized block 1 from {url}"))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator {url} has no finalized block 1; genesis cannot be authenticated until block 1 is finalized",
                )
            })?;
        super::chain::pinned_consensus_verifier(&trust, &genesis_json, &info)?
            .verify_snapshot(&first.snapshot, &first.block)
            .with_context(|| format!("validator {url} returned an unauthenticated block 1"))?;
        let first = FinalizedBlockView::decode(&first)
            .with_context(|| format!("validator {url} returned malformed finalized block 1"))?;
        anyhow::ensure!(
            first.height() == 1,
            "validator {url} answered the height-1 query with finalized height {}",
            first.height(),
        );
        let genesis: [u8; 32] = first.parent().into();
        match &observed {
            None => observed = Some((info, genesis)),
            Some((expected, payload)) => {
                anyhow::ensure!(
                    info.network_id == expected.network_id
                        && info.threshold_identity == expected.threshold_identity,
                    "validator {url} reports a different consensus identity",
                );
                anyhow::ensure!(
                    genesis == *payload,
                    "validator {url} reports a different genesis payload",
                );
            }
        }
    }
    observed.context("validators produced no observation")
}

async fn client_config(args: &RunArgs) -> CliResult<WorkConfig> {
    let (info, genesis_payload) =
        read_chain(&args.validators, &args.trust, args.genesis.as_deref()).await?;
    let genesis = match &args.genesis {
        Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
        None => serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON)?,
    };
    Ok(WorkConfig {
        chain: ChainCrossCheck {
            network: hellas_kernel::NetworkId::new(&info.network_id)
                .context("invalid chain network")?,
            genesis_payload_digest: genesis_payload.into(),
            threshold_identity: info.threshold_identity,
            genesis: Some(genesis),
        },
        validators: args.validators.clone(),
        journal_root: args.journal_root.clone(),
        poll: Duration::from_millis(100),
        max_observation_age: Duration::from_secs(60),
    })
}

fn paid_options(
    args: &RunArgs,
    config: WorkConfig,
    assurance: hellas_rpc::Assurance,
) -> CliResult<PaidWorkOptions> {
    anyhow::ensure!(
        !args.payment_coins.is_empty(),
        "at least one --payment-coin is required"
    );
    let apple_trust = match (&args.trust_store, &args.trust_policy) {
        (Some(directory), Some(id)) => Some(
            hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                id,
                assurance,
                crate::identity::assertion_counters()?,
            )?,
        ),
        (None, None) if assurance == hellas_rpc::Assurance::ProducerSigned => None,
        _ => anyhow::bail!("Apple providers require --trust-store and --trust-policy"),
    };
    Ok(PaidWorkOptions {
        config,
        journal_root: args.journal_root.clone(),
        provider: args.provider,
        provider_addrs: args.provider_addrs.clone(),
        apple_trust,
        assurance,
        expected_price: args.payment,
        payment_funding: Funding::new(
            coins(&args.payment_coins)?,
            List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        ),
        acceptance_blocks: args.acceptance_blocks,
        terminal_blocks: args.terminal_blocks,
        payment_blocks: args.payment_blocks,
        timeout: Duration::from_secs(args.timeout_secs),
    })
}

async fn run_one(
    args: RunArgs,
    config: WorkConfig,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
    node: hellas_sdk::FullNode,
    authority: hellas_work::node::NodeCoordinator,
) -> CliResult<()> {
    let prepared = read_prepared_work_input(&args.prepared_input)?;
    let result = run_paid_work(
        PaidWorkRun {
            options: paid_options(&args, config, prepared.assurance()?)?,
            prepared_input: prepared,
            settle: args.settle,
        },
        transport_key,
        settlement_key,
        node,
        authority,
    )
    .await?;
    println!("bond_edge: {}", hex::encode(result.bond_edge.to_bytes()));
    println!(
        "payment_edge: {}",
        hex::encode(result.payment_edge.to_bytes())
    );
    println!("channel_id: {}", hex::encode(result.channel_id.as_bytes()));
    println!("work_id: {}", hex::encode(result.work_id.as_bytes()));
    println!("job_price: {}", result.job_price);
    println!("credited_cumulative: {}", result.credited_cumulative);
    println!("authenticated_result: true");
    if let Some(output) = &args.output {
        write_private(output, &result.transcript)?;
    }
    println!("result_bytes: {}", result.transcript.len());
    if let Some(payout) = result.settled_provider_payout {
        println!("settled_provider_payout: {payout}");
    }
    println!("settled: {}", args.settle);
    println!("client_journals: {}", args.journal_root.display());
    Ok(())
}

#[cfg(test)]
fn relative_deadlines(current: u64, args: &RunArgs) -> CliResult<JobDeadlines> {
    hellas_sdk::paid_client::deadlines(
        current,
        args.acceptance_blocks,
        args.terminal_blocks,
        args.payment_blocks,
    )
    .map_err(Into::into)
}

fn read_prepared_work_input(path: &Path) -> CliResult<PreparedWorkInput> {
    let bytes = super::read_bounded_regular_file(path, "prepared paid input", MAX_RECORD_BYTES)?;
    PreparedWorkInput::decode(&bytes, MAX_RECORD_BYTES)
        .map_err(|error| anyhow::anyhow!("invalid prepared paid input {}: {error}", path.display()))
}

fn write_private(path: &Path, bytes: &[u8]) -> CliResult<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    hellas_private::write_atomically(path, ".tmp", bytes)
        .with_context(|| format!("failed to write {}", path.display()))
}

fn coins(values: &[String]) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    let ids = values
        .iter()
        .map(|value| fixed_hex("--payment-coin", value).map(CoinId::from_bytes))
        .collect::<CliResult<Vec<_>>>()?;
    hellas_sdk::work_config::coin_list(&ids).context("too many --payment-coin values")
}

pub(crate) fn fixed_hex<const N: usize>(flag: &str, value: &str) -> CliResult<[u8; N]> {
    hellas_auth::hex::parse(value).with_context(|| {
        if value.len() != N * 2 {
            format!("{flag} has {} bytes; expected {N}", value.len() / 2)
        } else {
            format!("{flag} must be hexadecimal")
        }
    })
}

#[cfg(test)]
mod tests;
