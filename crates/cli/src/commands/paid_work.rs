//! Operator entry points for one paid-work channel and one paid job.
//!
//! This deliberately stays a thin orchestration layer over the setup,
//! journal, light-client, and work APIs.  The durable state remains in the
//! production setup and channel journals; this command does not keep a
//! parallel receipt or invent a second protocol.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand};
use hellas_chain::client::{RemoteLightClient, VerifiedRemoteLightClient};
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlockQuery, FinalizedBlockView,
    FinalizedWorkView as _, LightClient as _, WorkBlocks, WorkChannelQuery,
};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::{CollectResultOutcome, collect_result};
use hellas_kernel::{
    CoinId, EdgeId, Funding, List, MAX_PARTY_INPUTS, MAX_START_VALIDITY_BLOCKS, Secp256k1Signer,
    Secp256k1Verifier, WorkPaymentTerms,
};
use hellas_rpc::protocol::artifacts::{Canonical as _, PreparedPaidInputV1};
use hellas_rpc::protocol::work::{
    JobDeadlines, generation_policy_digest, identity_source_digest, private_policy_commitment,
};
use hellas_rpc::protocol::work_setup::{ProviderChannelPolicy, WorkChannelDescriptor};
use hellas_wire::ServiceMarker;
use hellas_wire::iroh::IrohTransport;
use hellas_work::work::{ClientEndpoint, JobProposal, propose_work, resume_work_proposal};
use hellas_work::work_close::CloseProgress;
use hellas_work::work_close::FinalizedBlocks as _;
use hellas_work::work_handshake::{
    PaymentAdmission, SetupEndpoint, SetupService, apply_setup_exchange, prepare_setup_exchange,
    send_setup_exchange,
};
use hellas_work::work_open::{SetupAdvance, SetupProgress};
use hellas_work::work_store::journal::MAX_RECORD_BYTES;
use hellas_work::work_store::{Role, SetupScan, SetupStore};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};

use super::CliResult;
use super::serve::work_config::{WorkConfig, load_work_config};

#[cfg(feature = "gateway")]
mod gateway;
#[cfg(feature = "gateway")]
pub use gateway::load_gateway_backend;

/// Paid-work commands intended for deployment bring-up and smoke tests.
#[derive(Debug, Subcommand)]
pub enum PaidWorkCommand {
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

    /// Canonical PreparedPaidInputV1 bytes to execute.
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
) -> CliResult<()> {
    match command {
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
    let prepared = read_prepared_input(path)?;
    inspect_prepared(&prepared, transport_key, settlement_key)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InputIdentities {
    allowed_environment: hellas_rpc::ContentId,
    generation_policy_digest: hellas_rpc::Digest,
    identity_source_digest: hellas_rpc::Digest,
}

impl InputIdentities {
    fn from_prepared(prepared: &PreparedPaidInputV1) -> CliResult<Self> {
        let parts = prepared
            .parts()
            .context("prepared input contains a non-canonical body")?;
        let allowed_environment = parts.manifest.content_id();
        anyhow::ensure!(
            parts.evaluate_request.execution_environment == allowed_environment,
            "prepared input request names environment {}, but its manifest derives {}",
            parts.evaluate_request.execution_environment,
            allowed_environment,
        );
        Ok(Self {
            allowed_environment,
            generation_policy_digest: generation_policy_digest(
                &parts.text_policy.canonical_bytes(),
            )?,
            identity_source_digest: identity_source_digest(
                &parts.identity_artifact.canonical_bytes(),
            )?,
        })
    }
}

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

async fn run_one(
    args: RunArgs,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<()> {
    let prepared = read_prepared_input(&args.prepared_input)?;
    let endpoint = bind_paid_endpoint(transport_key).await?;
    let mut channel = OpenPaidChannel::open(args, endpoint, settlement_key).await?;
    println!(
        "bond_edge: {}",
        hex::encode(channel.descriptor.bond_edge().to_bytes())
    );
    println!(
        "payment_edge: {}",
        hex::encode(channel.descriptor.channel().payment_edge().to_bytes())
    );
    println!(
        "channel_id: {}",
        hex::encode(channel.descriptor.channel().id().as_bytes())
    );
    let result = channel
        .run(Some(prepared), false, None)
        .await?
        .context("paid execution returned no result")?;
    println!("work_id: {}", hex::encode(result.work_id.as_bytes()));
    println!("job_price: {}", result.job_price);
    println!("credited_cumulative: {}", result.credited_cumulative);
    println!("authenticated_result: true");
    if let Some(output) = channel.args.output.as_ref() {
        std::fs::write(output, &result.transcript).with_context(|| {
            format!("failed to write result transcript to {}", output.display())
        })?;
        println!(
            "result: {} ({} bytes)",
            output.display(),
            result.transcript.len()
        );
    } else {
        println!("result_bytes: {}", result.transcript.len());
    }
    if channel.args.settle {
        channel
            .client
            .prepare_close()
            .context("failed to prepare the client payment close")?;
        loop {
            match channel
                .client
                .advance_close(&channel.chain, &channel.chain)
                .await
                .context("failed to advance the client payment close")?
            {
                CloseProgress::Settled { provider_payout } => {
                    println!("settled: true");
                    println!("settled_provider_payout: {provider_payout}");
                    println!(
                        "settled_finalized_height: {}",
                        channel.client.state().cursor().0
                    );
                    break;
                }
                CloseProgress::Submitted { outcome, .. } => {
                    tracing::info!(?outcome, "client payment close submitted");
                }
                CloseProgress::Opened { .. } | CloseProgress::Nothing => {}
            }
            tokio::time::sleep(channel.config.poll).await;
        }
    } else {
        println!("settled: false");
    }
    println!("client_journals: {}", channel.args.journal_root.display());
    Ok(())
}

struct PaidOutput {
    work_id: hellas_rpc::Digest,
    job_price: u64,
    credited_cumulative: u64,
    transcript: Vec<u8>,
    #[cfg(feature = "gateway")]
    provider_key: hellas_rpc::PublicKey,
    #[cfg(feature = "gateway")]
    input: hellas_rpc::InputCommitment,
}

struct OpenPaidChannel {
    args: RunArgs,
    config: WorkConfig,
    descriptor: WorkChannelDescriptor,
    dialer: ProviderDialer,
    chain: WorkBlocks<VerifiedRemoteLightClient>,
    next_validator: usize,
    client: ClientEndpoint,
    needs_recovery: bool,
}

impl OpenPaidChannel {
    async fn open(
        args: RunArgs,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
    ) -> CliResult<Self> {
        anyhow::ensure!(
            args.acceptance_blocks > 0 && args.terminal_blocks > 0 && args.payment_blocks > 0,
            "all three deadline spans must be greater than zero",
        );
        anyhow::ensure!(
            !args.payment_coins.is_empty(),
            "at least one --payment-coin is required",
        );

        let config = load_work_config(&args.work_config)?;
        let policy = config.provider_policy();
        let bond = edge_id("--bond", &args.bond)?;
        let payment_funding = Funding::new(coins(&args.payment_coins)?, empty_coins());
        let mut next_validator = 0;
        let chain = connect_chain(&config, &mut next_validator).await?;
        check_genesis(&config, &chain).await?;

        std::fs::create_dir_all(&args.journal_root).with_context(|| {
            format!(
                "failed to create client journal root {}",
                args.journal_root.display(),
            )
        })?;
        let store = SetupStore::open(
            &args.journal_root,
            config.chain.network,
            bond,
            Role::Client,
            &Secp256k1Verifier::new(),
        )
        .with_context(|| {
            format!(
                "failed to open client setup journal under {}",
                args.journal_root.display(),
            )
        })?;
        let mut setup = SetupEndpoint::new(
            store,
            settlement_key.clone(),
            PaymentAdmission::Proposes(Box::new(policy.clone())),
        );
        let dialer = ProviderDialer::new(args.provider, args.provider_addrs.clone(), endpoint);

        if setup.state().revision().is_none() {
            exchange_setup(&dialer, &mut setup).await?;
        }
        let bundle = setup
            .state()
            .bundle()
            .cloned()
            .context("provider returned no bond proposal")?;
        anyhow::ensure!(
            bundle.bond_edge() == bond,
            "provider proposed a different bond edge"
        );
        anyhow::ensure!(
            bundle.bond_terms().parties.taker() == settlement_key.party_key(),
            "provider bond names client settlement key {}, not this identity's {}",
            hex::encode(bundle.bond_terms().parties.taker().to_bytes()),
            hex::encode(settlement_key.party_key().to_bytes()),
        );
        if setup.state().scan_armed().is_none() {
            setup.arm_scan(finalized_floor(&chain).await?)?;
        }
        if setup.state().revision() == Some(1) {
            let terms = payment_terms(&config, &policy, &bundle, args.omission_bond);
            setup.propose_payment(payment_funding, terms)?;
        }
        if setup.state().revision() == Some(2) {
            exchange_setup(&dialer, &mut setup).await?;
        }
        anyhow::ensure!(
            setup.state().revision() == Some(3),
            "setup did not reach its countersigned revision",
        );

        let setup_service = SetupService::new(setup);
        let (mounted, descriptor) =
            drive_setup(&setup_service, &policy, &chain, config.poll).await?;
        let ready = ready_channel(&descriptor, &chain).await?;
        let client = ClientEndpoint::new(ready.clone(), mounted, settlement_key)?;

        Ok(Self {
            args,
            config,
            descriptor,
            dialer,
            chain,
            next_validator,
            client,
            needs_recovery: true,
        })
    }

    async fn follow_chain(&mut self) -> CliResult<()> {
        for attempt in 0..self.config.validators.len() {
            match self.client.catch_up(&self.chain).await {
                Ok(_) => return Ok(()),
                Err(error) if attempt + 1 == self.config.validators.len() => {
                    return Err(error.into());
                }
                Err(error) => {
                    tracing::debug!(%error, "paid channel will continue catch-up through another validator");
                    self.chain = connect_chain(&self.config, &mut self.next_validator).await?;
                    check_genesis(&self.config, &self.chain).await?;
                }
            }
        }
        bail!("no configured validator supplied finalized history")
    }

    async fn run(
        &mut self,
        prepared: Option<PreparedPaidInputV1>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
    ) -> CliResult<Option<PaidOutput>> {
        self.run_with_admission(prepared, recover, progress, None)
            .await
    }

    async fn run_with_admission(
        &mut self,
        prepared: Option<PreparedPaidInputV1>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
        proposed: Option<&AtomicBool>,
    ) -> CliResult<Option<PaidOutput>> {
        self.follow_chain().await?;
        let Self {
            args,
            config,
            descriptor,
            dialer,
            chain,
            client,
            needs_recovery,
            ..
        } = self;
        if let Some(prepared) = prepared.as_ref() {
            check_policy_input(&config.provider_policy(), prepared)?;
        }
        let ready = caught_up_channel(descriptor, client, &*chain).await?;
        if recover && *needs_recovery {
            if let Some(payment) = client.state().last_payment() {
                // The provider may have committed payment while its acknowledgement
                // was lost. Re-send the retained certificate before accepting work.
                pay_for_result(dialer.work().await?, client, payment.work_id).await?;
            }
            let pending = client
                .state()
                .jobs()
                .filter(|job| {
                    // The journal forbids signing payment after this height.
                    // Keep the evidence, but do not let an unpayable old job
                    // prevent this channel from serving a new request. Retained
                    // certificates are re-sent separately above.
                    let payable = job.authorization().payment_deadline >= client.state().cursor().0;
                    if !payable {
                        tracing::info!(
                            work_id = %hex::encode(job.work_id().as_bytes()),
                            payment_deadline = job.authorization().payment_deadline,
                            "retaining expired unpaid job without retrying execution",
                        );
                    }
                    payable
                })
                .map(|job| {
                    PreparedPaidInputV1::decode(job.prepared_input(), MAX_RECORD_BYTES)
                        .map(|input| (job.work_id(), job.phase(), input))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (work_id, phase, pending) in pending {
                let result = execute_paid_job(
                    args,
                    pending,
                    dialer,
                    client,
                    &ready,
                    &*chain,
                    config.poll,
                    None,
                    JobLookup::Retained(work_id),
                    None,
                )
                .await;
                if let Err(error) = &result
                    && ((phase == hellas_work::work_store::JobPhase::HalfSigned
                        && matches!(
                            error.downcast_ref::<hellas_work::work::ProposeError>(),
                            Some(hellas_work::work::ProposeError::Refused {
                                refusal,
                                ..
                            }) if !refusal.is_retryable()
                        ))
                        || permanently_refused_delivery(error))
                {
                    // Keep the signed evidence without deciding that an unpaid
                    // job was paid or cancelled. A permanent provider refusal
                    // cannot be repaired by blocking every later request here.
                    tracing::info!(%work_id, %error, "retaining an unpaid job refused by the provider");
                    continue;
                }
                result?;
            }
        }
        // Keep recovery armed across any error or cancellation after acceptance.
        *needs_recovery = prepared.is_some();
        let result = match prepared {
            Some(prepared) => {
                let ready = caught_up_channel(descriptor, client, &*chain).await?;
                Some(
                    execute_paid_job(
                        args,
                        prepared,
                        dialer,
                        client,
                        &ready,
                        &*chain,
                        config.poll,
                        progress.as_ref(),
                        if recover {
                            JobLookup::New
                        } else {
                            JobLookup::PreparedInput
                        },
                        proposed,
                    )
                    .await?,
                )
            }
            None => None,
        };
        *needs_recovery = false;
        Ok(result)
    }
}

fn permanently_refused_delivery(error: &anyhow::Error) -> bool {
    use hellas_client::work::CollectResultError;
    use hellas_work::work::DeliverError;
    let delivery = error.downcast_ref::<DeliverError>().or_else(|| {
        match error.downcast_ref::<CollectResultError>() {
            Some(CollectResultError::Deliver(delivery)) => Some(delivery),
            _ => None,
        }
    });
    matches!(delivery, Some(DeliverError::Refused { refusal, .. }) if !refusal.is_retryable())
}

/// Proposes until a provider accepts or the caller's execution window closes.
/// A provider catching its chain cursor up replies `NotReady`; that is not an
/// answer to the job. The retained proposal makes each retry the same request,
/// while bounded exponential backoff avoids turning recovery into a request
/// flood.
async fn propose_when_ready(
    dialer: &ProviderDialer,
    client: &mut ClientEndpoint,
    proposal: &JobProposal,
    retained: Option<hellas_rpc::Digest>,
    poll: Duration,
    timeout: Duration,
    proposed: Option<&AtomicBool>,
) -> CliResult<hellas_rpc::Digest> {
    let deadline = Instant::now() + timeout;
    let mut delay = poll.max(Duration::from_secs(1));
    loop {
        if Instant::now() >= deadline {
            bail!("provider remained not ready for {timeout:?}");
        }
        let transport = dialer.work().await?;
        // Once a proposal can leave this process, a lost acknowledgement must
        // be treated as accepted work. HTTP cancellation may no longer stop it.
        if let Some(proposed) = proposed {
            proposed.store(true, Ordering::Release);
        }
        let result = match retained {
            Some(work_id) => resume_work_proposal(transport, client, work_id).await,
            None => propose_work(transport, client, proposal).await,
        };
        match result {
            Ok(work_id) => return Ok(work_id),
            Err(hellas_work::work::ProposeError::Refused { refusal, .. })
                if refusal.is_retryable() =>
            {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(delay.min(remaining)).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

enum JobLookup {
    Retained(hellas_rpc::Digest),
    PreparedInput,
    New,
}

#[allow(clippy::too_many_arguments)]
async fn execute_paid_job(
    args: &RunArgs,
    prepared: PreparedPaidInputV1,
    dialer: &ProviderDialer,
    client: &mut ClientEndpoint,
    ready: &hellas_rpc::protocol::work_setup::ReadyChannel,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    poll: Duration,
    progress: Option<&hellas_work::work::PaidProgress>,
    lookup: JobLookup,
    proposed: Option<&AtomicBool>,
) -> CliResult<PaidOutput> {
    let readiness_timeout = Duration::from_secs(args.timeout_secs);
    let prepared_bytes = prepared.encode()?;
    let current = client.state().cursor().0;
    let deadlines = relative_deadlines(current, args)?;
    let proposal = JobProposal {
        prepared_input: prepared,
        deadlines,
    };
    let existing = client
        .state()
        .jobs()
        .filter(|job| match &lookup {
            JobLookup::Retained(work_id) => job.work_id() == *work_id,
            JobLookup::New => false,
            JobLookup::PreparedInput => {
                job.prepared_input() == prepared_bytes.as_slice()
                    && job.authorization().payment_deadline >= current
                    && (job.phase() != hellas_work::work_store::JobPhase::HalfSigned
                        || job.authorization().acceptance_deadline >= current)
            }
        })
        .map(|job| (job.work_id(), job.phase(), *job.authorization()))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        existing.len() <= 1,
        "more than one active job matches this prepared input; inspect the retained channel journal",
    );
    if !existing.is_empty()
        && let Some(proposed) = proposed
    {
        proposed.store(true, Ordering::Release);
    }
    let (work_id, already_collected) = match existing.first().copied() {
        Some((work_id, hellas_work::work_store::JobPhase::HalfSigned, _)) => (
            propose_when_ready(
                dialer,
                client,
                &proposal,
                Some(work_id),
                poll,
                readiness_timeout,
                proposed,
            )
            .await?,
            false,
        ),
        Some((work_id, hellas_work::work_store::JobPhase::Ready, _))
        | Some((work_id, hellas_work::work_store::JobPhase::Matched, _)) => (work_id, true),
        Some((work_id, _, _)) => (work_id, false),
        None => (
            propose_when_ready(
                dialer,
                client,
                &proposal,
                None,
                poll,
                readiness_timeout,
                proposed,
            )
            .await?,
            false,
        ),
    };
    let transcript = if already_collected {
        client
            .state()
            .job_by_id(work_id)
            .map(|job| job.transcript().to_vec())
            .context("collected job disappeared from its journal")?
    } else if let Some(progress) = progress {
        let mut emitted = false;
        let delivery = loop {
            let result = hellas_work::work::fetch_result_stream(
                dialer.work().await?,
                client,
                ready,
                work_id,
                |event| {
                    emitted = true;
                    progress(event.clone()).map_err(|error| {
                        hellas_rpc::protocol::work::PaidWorkError::Transcript(error.to_string())
                    })
                },
            )
            .await;
            let error = match result {
                Ok(delivery) => break delivery,
                Err(error) => error,
            };
            let retryable = match &error {
                hellas_work::work::DeliverError::Transport(status) => {
                    status.code == hellas_wire::WireCode::Unavailable
                }
                hellas_work::work::DeliverError::Refused { refusal, .. } => refusal.is_retryable(),
                _ => false,
            };
            // Retry delivery of this accepted job only before exposing output.
            // Reopening after a prefix would replay it into the user's stream.
            if emitted || !retryable {
                return Err(error.into());
            }
            client.catch_up(chain).await?;
            let job = client
                .state()
                .job_by_id(work_id)
                .context("accepted job disappeared")?;
            anyhow::ensure!(
                client.state().cursor().0 <= job.authorization().payment_deadline,
                "payment deadline elapsed while waiting for result stream"
            );
            tracing::debug!(%error, %work_id, "waiting for paid result stream readiness");
            tokio::time::sleep(poll.max(Duration::from_secs(1))).await;
        };
        client.catch_up(chain).await?;
        anyhow::ensure!(
            client.state().cursor().0 <= proposal.deadlines.payment,
            "payment deadline elapsed during delivery"
        );
        delivery.transcript
    } else {
        collect_until_ready(dialer, client, ready, chain, work_id, poll).await?
    };
    let credited = pay_for_result(dialer.work().await?, client, work_id).await?;
    Ok(PaidOutput {
        work_id,
        job_price: ready.execution_policy().fixed_price,
        credited_cumulative: credited,
        transcript,
        #[cfg(feature = "gateway")]
        provider_key: hellas_rpc::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
        #[cfg(feature = "gateway")]
        input: hellas_rpc::evaluate::input_commitment(
            &proposal.prepared_input.parts()?.evaluate_request,
        ),
    })
}

fn check_policy_input(
    policy: &ProviderChannelPolicy,
    prepared: &PreparedPaidInputV1,
) -> CliResult<()> {
    let input = InputIdentities::from_prepared(prepared)?;
    let parts = prepared.parts()?;
    let expected = policy.execution_policy;
    anyhow::ensure!(
        expected.allowed_environment == input.allowed_environment,
        "work config allows environment {}, but prepared input uses {}",
        expected.allowed_environment,
        input.allowed_environment,
    );
    anyhow::ensure!(
        hellas_rpc::protocol::work::matches_generation_policy(&expected, &parts.text_policy)?,
        "work config generation_policy_digest does not match prepared input",
    );
    anyhow::ensure!(
        expected.identity_source_digest == input.identity_source_digest,
        "work config identity_source_digest does not match prepared input",
    );
    Ok(())
}

fn payment_terms(
    config: &WorkConfig,
    policy: &ProviderChannelPolicy,
    bundle: &hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1,
    omission_bond: u64,
) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bundle.bond_edge(),
        bond_terms: bundle.bond_terms().clone(),
        private_policy_commitment: private_policy_commitment(
            config.chain.network,
            &policy.policy_salt,
            &policy.channel_policy,
        ),
        omit_response_blocks: policy.min_omit_response_blocks,
        start_validity_blocks: MAX_START_VALIDITY_BLOCKS,
        omission_bond,
    }
}

async fn drive_setup(
    setup: &SetupService,
    policy: &ProviderChannelPolicy,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    poll: Duration,
) -> CliResult<(hellas_work::work_store::ChannelStore, WorkChannelDescriptor)> {
    loop {
        let SetupAdvance { progress, mounted } = setup
            .advance_setup(chain, chain, chain)
            .await
            .context("failed to advance paid-work setup")?;
        if let Some(store) = mounted {
            let channel = store.state().channel();
            let descriptor = policy
                .admit(channel.payment_edge(), channel.payment_terms().clone())
                .context("the funded channel no longer satisfies the configured policy")?;
            return Ok((store, descriptor));
        }
        match progress {
            SetupProgress::Aborted(reason) => bail!("paid-work setup aborted: {reason:?}"),
            SetupProgress::Faulted(reason) => bail!("paid-work setup faulted: {reason:?}"),
            SetupProgress::TimeoutBond => bail!("provider bond timed out before setup completed"),
            _ => tokio::time::sleep(poll).await,
        }
    }
}

async fn ready_channel(
    descriptor: &WorkChannelDescriptor,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> CliResult<hellas_rpc::protocol::work_setup::ReadyChannel> {
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: descriptor.channel().payment_edge(),
        funding: Default::default(),
    };
    let snapshot = chain
        .work_channel_snapshot(query)
        .await?
        .context("no finalized channel snapshot is available")?;
    descriptor
        .check_ready(&snapshot.observed_channel())
        .context("the finalized channel is not ready")
}

/// Reads the ready snapshot once the client has processed it.
///
/// The snapshot and the blocks the cursor follows are answered by
/// validators independently, so the snapshot can name a height the
/// light client has not finalized yet, and a snapshot read after the
/// catch-up on a moving chain always lands a few blocks ahead of it.
/// The snapshot is sampled first and then the cursor is brought to it:
/// a fixed height is a target the catch-up reaches, where a fresh
/// snapshot every round was not. A state at or behind the cursor is
/// the direction `check_caught_up` accepts.
async fn caught_up_channel(
    descriptor: &WorkChannelDescriptor,
    client: &mut ClientEndpoint,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> CliResult<hellas_rpc::protocol::work_setup::ReadyChannel> {
    let ready = ready_channel(descriptor, chain).await?;
    for _ in 0..16 {
        let cursor = client.catch_up(chain).await?;
        if ready.check_caught_up(cursor).is_ok() {
            return Ok(ready);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let cursor = client.catch_up(chain).await?;
    ready.check_caught_up(cursor)?;
    Ok(ready)
}

async fn collect_until_ready(
    dialer: &ProviderDialer,
    client: &mut ClientEndpoint,
    ready: &hellas_rpc::protocol::work_setup::ReadyChannel,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    work_id: hellas_rpc::Digest,
    poll: Duration,
) -> CliResult<Vec<u8>> {
    loop {
        match collect_result(dialer.work().await?, client, ready, chain, work_id).await? {
            CollectResultOutcome::Collected(result) => return Ok(result.transcript),
            CollectResultOutcome::NotReady { reason } => {
                tracing::debug!(%reason, "waiting for paid result");
                tokio::time::sleep(poll.max(Duration::from_secs(1))).await;
            }
        }
    }
}

fn relative_deadlines(current: u64, args: &RunArgs) -> CliResult<JobDeadlines> {
    let acceptance = current
        .checked_add(args.acceptance_blocks)
        .context("acceptance deadline overflow")?;
    let terminal = acceptance
        .checked_add(args.terminal_blocks)
        .context("terminal deadline overflow")?;
    let payment = terminal
        .checked_add(args.payment_blocks)
        .context("payment deadline overflow")?;
    Ok(JobDeadlines {
        acceptance,
        terminal,
        payment,
    })
}

async fn exchange_setup(dialer: &ProviderDialer, setup: &mut SetupEndpoint) -> CliResult<()> {
    let request = prepare_setup_exchange(setup);
    let response = send_setup_exchange(dialer.setup().await?, request).await?;
    apply_setup_exchange(setup, response)?;
    Ok(())
}

struct ProviderDialer {
    endpoint: Endpoint,
    provider: EndpointAddr,
}

async fn bind_paid_endpoint(secret_key: SecretKey) -> CliResult<Endpoint> {
    Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![
            hellas_rpc::services::work_setup::WorkSetup::ALPN
                .as_bytes()
                .to_vec(),
            hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
        ])
        .bind()
        .await
        .context("failed to bind paid-work Iroh endpoint")
}

impl ProviderDialer {
    fn new(provider: EndpointId, addresses: Vec<SocketAddr>, endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            provider: EndpointAddr::from_parts(
                provider,
                addresses.into_iter().map(TransportAddr::Ip),
            ),
        }
    }

    async fn setup(&self) -> CliResult<IrohTransport> {
        self.connect(hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes())
            .await
    }

    async fn work(&self) -> CliResult<IrohTransport> {
        self.connect(hellas_rpc::services::work::Work::ALPN.as_bytes())
            .await
    }

    async fn connect(&self, alpn: &[u8]) -> CliResult<IrohTransport> {
        let connection = self
            .endpoint
            .connect(self.provider.clone(), alpn)
            .await
            .with_context(|| format!("failed to connect to provider {}", self.provider.id))?;
        Ok(IrohTransport::new(connection))
    }
}

async fn connect_chain(
    config: &WorkConfig,
    next_validator: &mut usize,
) -> CliResult<WorkBlocks<VerifiedRemoteLightClient>> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })
    .context("configured threshold identity is unusable")?;
    // A peer can accept connections while lacking a historical certificate.
    // Reconnects must make progress through the configured alternatives.
    let start = *next_validator;
    let mut failures = Vec::new();
    for url in config
        .validators
        .iter()
        .cycle()
        .skip(start)
        .take(config.validators.len())
    {
        *next_validator = (*next_validator + 1) % config.validators.len();
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => return Ok(WorkBlocks::new(client)),
            Err(error) => failures.push(format!("{url}: {error}")),
        }
    }
    bail!("no configured validator answered: {}", failures.join("; "))
}

async fn check_genesis(
    config: &WorkConfig,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> CliResult<()> {
    let first = chain
        .block_at(1)
        .await?
        .context(
            "configured validator has no finalized block 1; genesis cannot be authenticated until block 1 is finalized",
        )?;
    check_genesis_payload(
        config.chain.genesis_payload_digest.as_bytes(),
        &first.parent,
    )
}

fn check_genesis_payload(expected: &[u8; 32], actual: &[u8; 32]) -> CliResult<()> {
    anyhow::ensure!(
        actual == expected,
        "validator genesis payload {} does not match configured {}",
        hex::encode(actual),
        hex::encode(expected),
    );
    Ok(())
}

async fn finalized_floor(chain: &WorkBlocks<VerifiedRemoteLightClient>) -> CliResult<SetupScan> {
    let height = chain
        .latest_height()
        .await?
        .context("configured validator has finalized no blocks")?;
    let block = chain
        .block_at(height)
        .await?
        .context("configured validator did not return its finalized tip")?;
    Ok(SetupScan {
        height,
        payload: block.payload,
    })
}

fn read_prepared_input(path: &Path) -> CliResult<PreparedPaidInputV1> {
    let bytes = super::read_bounded_regular_file(path, "prepared paid input", MAX_RECORD_BYTES)?;
    PreparedPaidInputV1::decode(&bytes, MAX_RECORD_BYTES)
        .map_err(|error| anyhow::anyhow!("invalid prepared paid input {}: {error}", path.display()))
}

#[cfg(feature = "llm")]
fn write_private(path: &Path, bytes: &[u8]) -> CliResult<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict {}", path.display()))?;
    }
    Ok(())
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
