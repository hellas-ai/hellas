//! Operator entry points for one paid-work channel and one paid job.
//!
//! This deliberately stays a thin orchestration layer over the setup,
//! journal, light-client, and work APIs.  The durable state remains in the
//! production setup and channel journals; this command does not keep a
//! parallel receipt or invent a second protocol.

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use hellas_chain::client::RemoteLightClient;
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlockQuery, FinalizedBlockView, LightClient as _,
};
use hellas_kernel::{CoinId, EdgeId, Funding, List, MAX_PARTY_INPUTS, Secp256k1Signer};
use hellas_rpc::protocol::artifacts::PreparedPaidInputV1;
#[cfg(test)]
use hellas_rpc::protocol::work::{JobDeadlines, private_policy_commitment};
use hellas_rpc::protocol::work_fetch::PreparedPaidFetchInputV1;
use hellas_rpc::protocol::work_profile::PreparedPaidWorkInput;
#[cfg(feature = "gateway")]
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
#[cfg(feature = "gateway")]
use hellas_sdk::paid_client::{
    PaidWorkResult as PaidOutput, check_evaluate_input as check_policy_input,
};
use hellas_sdk::paid_client::{PaidWorkSession as OpenPaidChannel, bind_paid_endpoint};
use hellas_work::work_store::journal::MAX_RECORD_BYTES;
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
#[cfg(feature = "gateway")]
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use super::CliResult;
use super::serve::work_config::load_work_config;

#[cfg(feature = "gateway")]
mod gateway;
#[cfg(feature = "gateway")]
pub use gateway::load_gateway_backend;

/// Paid-work commands intended for deployment bring-up and smoke tests.
#[derive(Debug, Subcommand)]
pub enum PaidWorkCommand {
    /// Build a signed ephemeral Fetch input for a paid channel.
    PrepareFetch(PrepareFetchArgs),
    /// Build canonical paid input from a causal-LM environment and prompt.
    #[cfg(feature = "llm")]
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
    /// The trusted transformation to execute.
    #[arg(long, value_parser = ["openai-responses", "codex-responses", "http"])]
    execution_environment: String,
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

#[cfg(feature = "llm")]
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
}

#[derive(Clone, Debug, Args)]
pub struct RunArgs {
    /// Out-of-band provider enrollment pin (required for App Attest).
    #[arg(long)]
    provider_genesis: Option<hellas_rpc::ContentId>,
    #[arg(long)]
    apple_app_id: Option<String>,
    #[arg(long, value_delimiter = ',', value_parser = crate::parse_hex_array::<32>)]
    apple_cd_hashes: Vec<[u8; 32]>,
    /// Provider work configuration, including chain identity and policy.
    #[arg(long = "work-config", value_name = "FILE")]
    work_config: PathBuf,

    /// Client-owned directory for durable setup and channel journals.
    #[arg(long = "journal-root", value_name = "DIR")]
    journal_root: PathBuf,

    /// Provider's authenticated Iroh endpoint ID.
    #[arg(long = "provider", value_name = "ENDPOINT_ID")]
    provider: EndpointId,

    /// Direct UDP address for the provider. Repeat or comma-separate.
    #[arg(long = "provider-addr", value_delimiter = ',', value_name = "IP:PORT")]
    provider_addrs: Vec<SocketAddr>,

    /// Provider bond edge advertised for this client.
    #[arg(long = "bond", value_name = "HEX")]
    bond: String,

    /// Client coin funding the payment edge. Repeat or comma-separate.
    #[arg(long = "payment-coin", value_delimiter = ',', value_name = "HEX")]
    payment_coins: Vec<String>,

    /// Capacity reserved as the understatement-omission penalty.
    #[arg(long = "omission-bond")]
    omission_bond: u64,

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
    producer_key: hellas_rpc::ProducerSigningKey,
) -> CliResult<()> {
    match command {
        PaidWorkCommand::PrepareFetch(args) => prepare_fetch(args, &producer_key),
        #[cfg(feature = "llm")]
        PaidWorkCommand::PrepareInput(args) => prepare_input(args, &transport_key, &settlement_key),
        PaidWorkCommand::InspectInput(args) => {
            inspect_input(&args.prepared_input, &transport_key, &settlement_key)
        }
        PaidWorkCommand::InspectChain(args) => inspect_chain(&args.validators).await,
        PaidWorkCommand::Run(args) => {
            anyhow::ensure!(
                args.timeout_secs > 0,
                "--timeout-secs must be greater than zero"
            );
            let timeout = Duration::from_secs(args.timeout_secs);
            tokio::time::timeout(timeout, run_one(*args, transport_key, settlement_key))
                .await
                .map_err(|_| anyhow::anyhow!("paid-work run exceeded its {timeout:?} limit"))?
        }
    }
}

fn prepare_fetch(args: PrepareFetchArgs, key: &hellas_rpc::ProducerSigningKey) -> CliResult<()> {
    let environment = match args.execution_environment.as_str() {
        "openai-responses" => hellas_rpc::FetchEnvironment::OpenAiResponses,
        "codex-responses" => hellas_rpc::FetchEnvironment::CodexResponses,
        "http" => hellas_rpc::FetchEnvironment::Http,
        _ => bail!("unsupported fetch environment"),
    };
    let payload = super::fetch::load_payload_file(&args.payload_file)?;
    if environment == hellas_rpc::FetchEnvironment::Http {
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
    let prepared = PreparedPaidFetchInputV1::new(&events, &environment.manifest())?;
    write_private(&args.out, &prepared.encode()?)?;
    println!("prepared_input: {}", args.out.display());
    println!("allowed_environment: {}", environment.manifest_id());
    println!("provider_payload_retention: memory-only");
    Ok(())
}

#[cfg(feature = "llm")]
fn prepare_input(
    args: PrepareInputArgs,
    transport_key: &SecretKey,
    settlement_key: &Secp256k1Signer,
) -> CliResult<()> {
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed as _, OutputAddressed as _, SourceRef, TextArtifact,
        TextExecution, TextPolicy, TokenIds,
    };

    anyhow::ensure!(
        args.max_new_tokens > 0,
        "--max-new-tokens must be greater than zero"
    );
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
    let manifest = environment.manifest();
    let presentation = hellas_presentation::TextPresentation::load(&args.tokenizer)?;
    let prompt_tokens = TokenIds::from_u32s(presentation.encode(&args.prompt)?);
    let text_policy = TextPolicy::from_u32_stop_tokens(args.max_new_tokens, args.stop_token_ids);
    let identity_artifact =
        TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
    let text_execution = TextExecution::new(
        SourceRef::output(identity_artifact.output_id()),
        prompt_tokens.output_id(),
        text_policy.output_id(),
    );
    let evaluate_request = hellas_rpc::EvaluateRequest {
        text_execution: text_execution.input_id().digest(),
        runner_public_key: hellas_rpc::PublicKey::Secp256k1(settlement_key.party_key().to_bytes()),
        execution_environment: manifest.content_id(),
        nonce: rand::random(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    let prepared = PreparedPaidInputV1::new(
        &evaluate_request,
        &manifest,
        &text_execution,
        &prompt_tokens,
        &text_policy,
        &identity_artifact,
    );
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
        PreparedPaidWorkInput::Evaluate(prepared) => {
            inspect_prepared(&prepared, transport_key, settlement_key)
        }
        PreparedPaidWorkInput::Fetch(prepared) => {
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

use hellas_sdk::paid_client::InputIdentities;

async fn inspect_chain(validators: &[String]) -> CliResult<()> {
    anyhow::ensure!(
        validators.len() == 6,
        "--validator must be passed exactly six times, got {}",
        validators.len(),
    );
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
        ConsensusVerifier::new(&info)
            .with_context(|| format!("validator {url} reported an unusable threshold identity"))?
            .verify_snapshot(&first.snapshot)
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
    let (info, genesis) = observed.expect("six validators produced one observation");
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

fn paid_provider_trust(
    args: &RunArgs,
    assurance: hellas_rpc::Assurance,
) -> CliResult<Option<hellas_client::ProviderTrustAnchor>> {
    if args.provider_genesis.is_some() || assurance != hellas_rpc::Assurance::ProducerSigned {
        Ok(Some(crate::identity::provider_trust(
            args.provider_genesis,
            assurance,
            args.apple_app_id.clone(),
            args.apple_cd_hashes.clone(),
        )?))
    } else {
        Ok(None)
    }
}

async fn open_paid_channel(
    args: &RunArgs,
    endpoint: iroh::Endpoint,
    settlement_key: Secp256k1Signer,
    assurance: hellas_rpc::Assurance,
) -> CliResult<OpenPaidChannel> {
    anyhow::ensure!(
        !args.payment_coins.is_empty(),
        "at least one --payment-coin is required"
    );
    let provider_trust = paid_provider_trust(args, assurance)?;
    OpenPaidChannel::open(
        hellas_sdk::paid_client::PaidWorkOptions {
            config: load_work_config(&args.work_config)?,
            journal_root: args.journal_root.clone(),
            provider: args.provider,
            provider_addrs: args.provider_addrs.clone(),
            provider_trust,
            bond: edge_id("--bond", &args.bond)?,
            payment_funding: Funding::new(coins(&args.payment_coins)?, empty_coins()),
            omission_bond: args.omission_bond,
            acceptance_blocks: args.acceptance_blocks,
            terminal_blocks: args.terminal_blocks,
            payment_blocks: args.payment_blocks,
            timeout: Duration::from_secs(args.timeout_secs),
        },
        endpoint,
        settlement_key,
    )
    .await
    .map_err(Into::into)
}

async fn run_one(
    args: RunArgs,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<()> {
    let prepared = read_prepared_work_input(&args.prepared_input)?;
    let endpoint = bind_paid_endpoint(transport_key).await?;
    let mut channel = open_paid_channel(
        &args,
        endpoint.clone(),
        settlement_key,
        prepared.assurance()?,
    )
    .await?;
    println!(
        "bond_edge: {}",
        hex::encode(channel.descriptor().bond_edge().to_bytes())
    );
    println!(
        "payment_edge: {}",
        hex::encode(channel.descriptor().channel().payment_edge().to_bytes())
    );
    println!(
        "channel_id: {}",
        hex::encode(channel.descriptor().channel().id().as_bytes())
    );
    let result = channel
        .run(Some(prepared), false, None)
        .await?
        .context("paid execution returned no result")?;
    println!("work_id: {}", hex::encode(result.work_id.as_bytes()));
    println!("job_price: {}", result.job_price);
    println!("credited_cumulative: {}", result.credited_cumulative);
    println!("authenticated_result: true");
    if let Some(output) = &args.output {
        write_private(output, &result.transcript)?;
    }
    println!("result_bytes: {}", result.transcript.len());
    if args.settle {
        println!("settled_provider_payout: {}", channel.settle().await?);
    }
    println!("settled: {}", args.settle);
    println!("client_journals: {}", args.journal_root.display());
    endpoint.close().await;
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
#[cfg(test)]
use hellas_sdk::paid_client::check_genesis_payload;

fn read_prepared_work_input(path: &Path) -> CliResult<PreparedPaidWorkInput> {
    let bytes = super::read_bounded_regular_file(path, "prepared paid input", MAX_RECORD_BYTES)?;
    PreparedPaidWorkInput::decode(&bytes, MAX_RECORD_BYTES)
        .map_err(|error| anyhow::anyhow!("invalid prepared paid input {}: {error}", path.display()))
}

#[cfg(test)]
fn read_prepared_input(path: &Path) -> CliResult<PreparedPaidInputV1> {
    let bytes = super::read_bounded_regular_file(path, "prepared paid input", MAX_RECORD_BYTES)?;
    PreparedPaidInputV1::decode(&bytes, MAX_RECORD_BYTES)
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

fn edge_id(flag: &str, value: &str) -> CliResult<EdgeId> {
    Ok(EdgeId::from_bytes(fixed_hex(flag, value)?))
}

fn coins(values: &[String]) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    let ids = values
        .iter()
        .map(|value| fixed_hex("--payment-coin", value).map(CoinId::from_bytes))
        .collect::<CliResult<Vec<_>>>()?;
    let slots: [CoinId; MAX_PARTY_INPUTS] = std::array::from_fn(|index| {
        ids.get(index)
            .copied()
            .unwrap_or_else(|| CoinId::from_bytes([0; CoinId::LENGTH]))
    });
    List::new(slots, ids.len()).context("too many --payment-coin values")
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    List::take(
        [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
        0,
    )
}

fn fixed_hex<const N: usize>(flag: &str, value: &str) -> CliResult<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{flag} is not hex"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{flag} is {} bytes; expected {N}", bytes.len()))
}

#[cfg(test)]
mod tests;
