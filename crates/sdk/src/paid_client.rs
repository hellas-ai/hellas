//! Reusable paid-work sessions: provider authentication, admission, verified delivery,
//! journal recovery, payment, and finalized settlement. Journals are client-owned.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

mod error;
pub use error::PaidClientError;
type Result<T, E = PaidClientError> = std::result::Result<T, E>;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedWorkView as _, WorkBlocks, WorkChannelQuery,
};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::{CollectResultOutcome, collect_result};
use hellas_kernel::{
    EdgeId, Funding, MAX_START_VALIDITY_BLOCKS, Secp256k1Signer, Secp256k1Verifier,
    WorkPaymentTerms,
};
use hellas_rpc::protocol::artifacts::{Canonical as _, PreparedPaidInputV1};
use hellas_rpc::protocol::work::{
    JobDeadlines, generation_policy_digest, identity_source_digest, private_policy_commitment,
};
use hellas_rpc::protocol::work_profile::{PaidWorkPolicy, PreparedPaidWorkInput};
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

use crate::work_config::WorkConfig;

/// Options shared by all jobs on a paid channel.
pub struct PaidWorkOptions {
    pub config: WorkConfig,
    pub journal_root: PathBuf,
    pub provider: EndpointId,
    pub provider_addrs: Vec<SocketAddr>,
    pub provider_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub bond: EdgeId,
    pub payment_funding: Funding,
    pub omission_bond: u64,
    pub acceptance_blocks: u64,
    pub terminal_blocks: u64,
    pub payment_blocks: u64,
    /// Bounds retries while a provider is not ready. A session's overall lifetime
    /// is controlled by its caller; `run_paid_work` also enforces an overall limit.
    pub timeout: Duration,
}

/// Convenience options for one complete paid job.
pub struct PaidWorkRun {
    pub config: WorkConfig,
    pub journal_root: PathBuf,
    pub provider: EndpointId,
    pub provider_addrs: Vec<SocketAddr>,
    pub provider_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub bond: EdgeId,
    pub payment_funding: Funding,
    pub omission_bond: u64,
    pub prepared_input: PreparedPaidWorkInput,
    pub acceptance_blocks: u64,
    pub terminal_blocks: u64,
    pub payment_blocks: u64,
    pub timeout: Duration,
    pub settle: bool,
}

pub struct PaidWorkResult {
    pub transcript: Vec<u8>,
    pub work_id: hellas_rpc::Digest,
    pub credited_cumulative: u64,
    pub job_price: u64,
    pub provider_key: hellas_rpc::PublicKey,
    pub input: hellas_rpc::InputCommitment,
    pub settled_provider_payout: Option<u64>,
}

/// Executes one job using a client-owned journal, with an overall time limit.
pub async fn run_paid_work(
    args: PaidWorkRun,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> Result<PaidWorkResult> {
    if args.timeout.is_zero() {
        return Err(PaidClientError::InvalidOptions("timeout must be positive"));
    }
    tokio::time::timeout(args.timeout, async move {
        let PaidWorkRun {
            config,
            journal_root,
            provider,
            provider_addrs,
            provider_trust,
            bond,
            payment_funding,
            omission_bond,
            prepared_input,
            acceptance_blocks,
            terminal_blocks,
            payment_blocks,
            timeout,
            settle,
        } = args;
        let options = PaidWorkOptions {
            config,
            journal_root,
            provider,
            provider_addrs,
            provider_trust,
            bond,
            payment_funding,
            omission_bond,
            acceptance_blocks,
            terminal_blocks,
            payment_blocks,
            timeout,
        };
        check_request(
            &options.config.provider_policy(),
            &prepared_input,
            options.provider_trust.as_ref(),
            hellas_rpc::PublicKey::Secp256k1(settlement_key.party_key().to_bytes()),
        )?;
        let endpoint = bind_paid_endpoint(transport_key).await?;
        let mut session = PaidWorkSession::open(options, endpoint.clone(), settlement_key).await?;
        let mut result = session
            .run(Some(prepared_input), false, None)
            .await?
            .ok_or(PaidClientError::MissingState(
                "paid execution returned no result",
            ))?;
        if settle {
            result.settled_provider_payout = Some(session.settle().await?);
        }
        endpoint.close().await;
        Ok(result)
    })
    .await
    .map_err(|_| PaidClientError::Timeout { stage: "paid job" })?
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputIdentities {
    pub allowed_environment: hellas_rpc::ContentId,
    pub generation_policy_digest: hellas_rpc::Digest,
    pub identity_source_digest: hellas_rpc::Digest,
}

impl InputIdentities {
    pub fn from_prepared(prepared: &PreparedPaidInputV1) -> Result<Self> {
        let parts = prepared.parts()?;
        Self::from_parts(&parts)
    }

    fn from_parts(parts: &hellas_rpc::protocol::artifacts::PreparedPaidInputParts) -> Result<Self> {
        let allowed_environment = parts.manifest.content_id();
        if parts.evaluate_request.execution_environment != allowed_environment {
            return Err(PaidClientError::InputMismatch("environment manifest"));
        }
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

/// A funded client channel. Keep one session per journal and serialize its jobs.
/// Cancellation retains recovery state; call `run(None, true, None)` to resume it.
pub struct PaidWorkSession {
    args: PaidWorkOptions,
    descriptor: WorkChannelDescriptor,
    dialer: ProviderDialer,
    chain: WorkBlocks<VerifiedRemoteLightClient>,
    next_validator: usize,
    client: ClientEndpoint,
    needs_recovery: bool,
}

impl PaidWorkSession {
    pub async fn open(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
    ) -> Result<Self> {
        if !(args.acceptance_blocks > 0 && args.terminal_blocks > 0 && args.payment_blocks > 0) {
            return Err(PaidClientError::InvalidOptions(
                "deadline spans must be positive",
            ));
        }
        if args.timeout.is_zero() {
            return Err(PaidClientError::InvalidOptions("timeout must be positive"));
        }

        let config = &args.config;
        let policy = config.provider_policy();
        let bond = args.bond;
        let payment_funding = args.payment_funding.clone();
        let mut next_validator = 0;
        let chain = connect_chain(config, &mut next_validator).await?;
        check_genesis(config, &chain).await?;

        std::fs::create_dir_all(&args.journal_root).map_err(|source| {
            PaidClientError::JournalDirectory {
                path: args.journal_root.clone(),
                source,
            }
        })?;
        let store = SetupStore::open(
            &args.journal_root,
            config.chain.network,
            bond,
            Role::Client,
            &Secp256k1Verifier::new(),
        )?;
        let mut setup = SetupEndpoint::new(
            store,
            settlement_key.clone(),
            PaymentAdmission::Proposes(Box::new(policy.clone())),
        );
        let dialer = ProviderDialer::new(
            args.provider,
            args.provider_addrs.clone(),
            endpoint,
            args.provider_trust.clone(),
        );

        if setup.state().revision().is_none() {
            exchange_setup(&dialer, &mut setup).await?;
        }
        let bundle = setup
            .state()
            .bundle()
            .cloned()
            .ok_or(PaidClientError::MissingState(
                "provider returned no bond proposal",
            ))?;
        if bundle.bond_edge() != bond {
            return Err(PaidClientError::InputMismatch("bond edge"));
        }
        if bundle.bond_terms().parties.taker() != settlement_key.party_key() {
            return Err(PaidClientError::InputMismatch("client settlement identity"));
        }
        dialer.require_producer(hellas_rpc::PublicKey::Secp256k1(
            bundle.bond_terms().parties.maker().to_bytes(),
        ))?;
        if setup.state().scan_armed().is_none() {
            setup.arm_scan(finalized_floor(&chain).await?)?;
        }
        if setup.state().revision() == Some(1) {
            let terms = payment_terms(config, &policy, &bundle, args.omission_bond);
            setup.propose_payment(payment_funding, terms)?;
        }
        if setup.state().revision() == Some(2) {
            exchange_setup(&dialer, &mut setup).await?;
        }
        if setup.state().revision() != Some(3) {
            return Err(PaidClientError::MissingState(
                "countersigned setup revision",
            ));
        }

        let setup_service = SetupService::new(setup);
        let (mounted, descriptor) =
            drive_setup(&setup_service, &policy, &chain, config.poll).await?;
        let ready = ready_channel(&descriptor, &chain).await?;
        let client = ClientEndpoint::new(ready.clone(), mounted, settlement_key)?;

        Ok(Self {
            args,
            descriptor,
            dialer,
            chain,
            next_validator,
            client,
            needs_recovery: true,
        })
    }

    /// Identifies the funded channel and its admitted execution policy.
    pub fn descriptor(&self) -> &WorkChannelDescriptor {
        &self.descriptor
    }

    /// Read-only journal state for routing, recovery, and admission decisions.
    pub fn state(&self) -> &hellas_work::work_store::ChannelState {
        self.client.state()
    }

    /// True after reopening a journal or an interrupted request.
    pub fn needs_recovery(&self) -> bool {
        self.needs_recovery
    }

    /// Opens the client close and waits for its finalized provider payout.
    pub async fn settle(&mut self) -> Result<u64> {
        self.client.prepare_close()?;
        loop {
            match self.client.advance_close(&self.chain, &self.chain).await? {
                CloseProgress::Settled { provider_payout } => return Ok(provider_payout),
                CloseProgress::Submitted { outcome, .. } => {
                    tracing::info!(?outcome, "client payment close submitted")
                }
                CloseProgress::Opened { .. } | CloseProgress::Nothing => {}
            }
            tokio::time::sleep(self.args.config.poll).await;
        }
    }

    /// Refreshes finalized state, rotating through configured validators on failure.
    pub async fn follow_chain(&mut self) -> Result<()> {
        for attempt in 0..self.args.config.validators.len() {
            match self.client.catch_up(&self.chain).await {
                Ok(_) => return Ok(()),
                Err(error) if attempt + 1 == self.args.config.validators.len() => {
                    return Err(error.into());
                }
                Err(error) => {
                    tracing::debug!(%error, "paid channel will continue catch-up through another validator");
                    self.chain = connect_chain(&self.args.config, &mut self.next_validator).await?;
                    check_genesis(&self.args.config, &self.chain).await?;
                }
            }
        }
        Err(PaidClientError::NoValidators)
    }

    /// Runs a request and pays only after verifying its complete result.
    /// With `recover`, resume payable journaled work first and admit this as a new
    /// job; otherwise reuse a still-active job matching the input. `None` only
    /// performs recovery. Prefixes are authenticated before incremental delivery.
    pub async fn run(
        &mut self,
        prepared: Option<PreparedPaidWorkInput>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
    ) -> Result<Option<PaidWorkResult>> {
        self.run_with_admission(prepared, recover, progress, None)
            .await
    }

    /// Like `run`, also marking `proposed` before a proposal can leave the process.
    /// A caller using cancellation must continue payment/recovery once it is set.
    pub async fn run_with_admission(
        &mut self,
        prepared: Option<PreparedPaidWorkInput>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
        proposed: Option<&AtomicBool>,
    ) -> Result<Option<PaidWorkResult>> {
        self.follow_chain().await?;
        let Self {
            args,
            descriptor,
            dialer,
            chain,
            client,
            needs_recovery,
            ..
        } = self;
        let config = &args.config;
        if let Some(prepared) = prepared.as_ref() {
            check_request(
                &config.provider_policy(),
                prepared,
                dialer.trust.as_ref(),
                hellas_rpc::PublicKey::Secp256k1(descriptor.channel().client_key().to_bytes()),
            )?;
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
                    // Fetch journals retain accounting only. A restart cannot
                    // reconstruct a lost request or authorize another execution.
                    if job.prepared_input().is_empty() {
                        return Err(PaidClientError::MissingPayload {
                            work_id: job.work_id(),
                            payment_deadline: job.authorization().payment_deadline,
                        });
                    }
                    PreparedPaidWorkInput::decode(job.prepared_input(), MAX_RECORD_BYTES)
                        .map(|input| (job.work_id(), job.phase(), input))
                        .map_err(PaidClientError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;
            for (work_id, phase, pending) in pending {
                check_request(
                    &config.provider_policy(),
                    &pending,
                    dialer.trust.as_ref(),
                    hellas_rpc::PublicKey::Secp256k1(descriptor.channel().client_key().to_bytes()),
                )?;
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
                            error,
                            PaidClientError::Propose(hellas_work::work::ProposeError::Refused {
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

fn permanently_refused_delivery(error: &PaidClientError) -> bool {
    use hellas_client::work::CollectResultError;
    use hellas_work::work::DeliverError;
    let delivery = match error {
        PaidClientError::Deliver(error)
        | PaidClientError::Collect(CollectResultError::Deliver(error)) => Some(error),
        _ => None,
    };
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
) -> Result<hellas_rpc::Digest> {
    let deadline = Instant::now() + timeout;
    let mut delay = poll.max(Duration::from_secs(1));
    loop {
        if Instant::now() >= deadline {
            return Err(PaidClientError::Timeout {
                stage: "provider admission",
            });
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
    args: &PaidWorkOptions,
    prepared: PreparedPaidWorkInput,
    dialer: &ProviderDialer,
    client: &mut ClientEndpoint,
    ready: &hellas_rpc::protocol::work_setup::ReadyChannel,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
    poll: Duration,
    progress: Option<&hellas_work::work::PaidProgress>,
    lookup: JobLookup,
    proposed: Option<&AtomicBool>,
) -> Result<PaidWorkResult> {
    let readiness_timeout = args.timeout;
    let prepared_bytes = prepared.encode()?;
    let current = client.state().cursor().0;
    let deadlines = deadlines(
        current,
        args.acceptance_blocks,
        args.terminal_blocks,
        args.payment_blocks,
    )?;
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
    if existing.len() > 1 {
        return Err(PaidClientError::AmbiguousRecovery);
    }
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
            .ok_or(PaidClientError::MissingState(
                "collected job disappeared from its journal",
            ))?
    } else if progress.is_some()
        || matches!(proposal.prepared_input, PreparedPaidWorkInput::Fetch(_))
    {
        let mut emitted = false;
        let delivery = loop {
            let result = hellas_work::work::fetch_result_stream(
                dialer.work().await?,
                client,
                ready,
                work_id,
                |event| {
                    emitted = true;
                    if let Some(progress) = progress {
                        progress(event.clone()).map_err(|error| {
                            hellas_rpc::protocol::work::PaidWorkError::Transcript(error.to_string())
                        })?;
                    }
                    Ok(())
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
                .ok_or(PaidClientError::MissingState("accepted job disappeared"))?;
            if client.state().cursor().0 > job.authorization().payment_deadline {
                return Err(PaidClientError::PaymentExpired);
            }
            tracing::debug!(%error, %work_id, "waiting for paid result stream readiness");
            tokio::time::sleep(poll.max(Duration::from_secs(1))).await;
        };
        client.catch_up(chain).await?;
        if client.state().cursor().0
            > client
                .state()
                .job_by_id(work_id)
                .ok_or(PaidClientError::MissingState("accepted job disappeared"))?
                .authorization()
                .payment_deadline
        {
            return Err(PaidClientError::PaymentExpired);
        }
        delivery.transcript
    } else {
        collect_until_ready(dialer, client, ready, chain, work_id, poll).await?
    };
    let credited = pay_for_result(dialer.work().await?, client, work_id).await?;
    Ok(PaidWorkResult {
        work_id,
        job_price: ready.execution_policy().fixed_price(),
        credited_cumulative: credited,
        transcript,
        provider_key: hellas_rpc::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
        input: proposal.prepared_input.input_commitment()?,
        settled_provider_payout: None,
    })
}

fn check_request(
    policy: &ProviderChannelPolicy,
    prepared: &PreparedPaidWorkInput,
    trust: Option<&hellas_client::ProviderTrustAnchor>,
    caller: hellas_rpc::PublicKey,
) -> Result<()> {
    let assurance = prepared.assurance()?;
    if trust
        .as_ref()
        .is_some_and(|trust| trust.required_assurance != assurance)
    {
        return Err(PaidClientError::InputMismatch(
            "assurance differs from provider trust",
        ));
    }
    if assurance != hellas_rpc::Assurance::ProducerSigned && trust.is_none() {
        return Err(PaidClientError::InvalidOptions(
            "attested work requires a provider trust anchor",
        ));
    }
    match (prepared, &policy.execution_policy) {
        (PreparedPaidWorkInput::Evaluate(input), PaidWorkPolicy::Evaluate(_)) => {
            check_evaluate_input(policy, input)?;
        }
        (PreparedPaidWorkInput::Fetch(input), PaidWorkPolicy::Fetch { policy, route }) => {
            let parts = input.parts()?;
            let request = hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript)?;
            if request.caller_key != caller {
                return Err(PaidClientError::InputMismatch("Fetch caller"));
            }
            if !(request.execution_environment == policy.allowed_environment
                && parts.manifest.content_id() == policy.allowed_environment)
            {
                return Err(PaidClientError::InputMismatch("Fetch environment"));
            }
            if request.retention != hellas_rpc::Retention::Ephemeral {
                return Err(PaidClientError::InputMismatch(
                    "Fetch retention must be ephemeral",
                ));
            }
            if let hellas_rpc::protocol::work_fetch::FetchRoutePolicy::SealedRoute {
                service,
                method,
            } = route
                && (&request.service != service || &request.method != method)
            {
                return Err(PaidClientError::InputMismatch("Fetch route"));
            }
        }
        _ => return Err(PaidClientError::InputMismatch("work profile")),
    }
    Ok(())
}
/// Checks an Evaluate request against the configured execution bounds.
pub fn check_evaluate_input(
    policy: &ProviderChannelPolicy,
    prepared: &PreparedPaidInputV1,
) -> Result<()> {
    let parts = prepared.parts()?;
    let input = InputIdentities::from_parts(&parts)?;
    let PaidWorkPolicy::Evaluate(expected) = &policy.execution_policy else {
        return Err(PaidClientError::InputMismatch("expected Evaluate profile"));
    };
    if expected.allowed_environment != input.allowed_environment {
        return Err(PaidClientError::InputMismatch("Evaluate environment"));
    }
    if !(hellas_rpc::protocol::work::matches_generation_policy(expected, &parts.text_policy)?) {
        return Err(PaidClientError::InputMismatch("generation policy"));
    }
    if expected.identity_source_digest != input.identity_source_digest {
        return Err(PaidClientError::InputMismatch("identity source"));
    }
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
) -> Result<(hellas_work::work_store::ChannelStore, WorkChannelDescriptor)> {
    loop {
        let SetupAdvance { progress, mounted } = setup.advance_setup(chain, chain, chain).await?;
        if let Some(store) = mounted {
            let channel = store.state().channel();
            let descriptor =
                policy.admit(channel.payment_edge(), channel.payment_terms().clone())?;
            return Ok((store, descriptor));
        }
        match progress {
            end @ (SetupProgress::Aborted(_)
            | SetupProgress::Faulted(_)
            | SetupProgress::TimeoutBond) => return Err(PaidClientError::SetupEnded(end)),
            _ => tokio::time::sleep(poll).await,
        }
    }
}

async fn ready_channel(
    descriptor: &WorkChannelDescriptor,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> Result<hellas_rpc::protocol::work_setup::ReadyChannel> {
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: descriptor.channel().payment_edge(),
        funding: Default::default(),
    };
    let snapshot =
        chain
            .work_channel_snapshot(query)
            .await?
            .ok_or(PaidClientError::MissingState(
                "no finalized channel snapshot is available",
            ))?;
    descriptor
        .check_ready(&snapshot.observed_channel())
        .map_err(PaidClientError::from)
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
) -> Result<hellas_rpc::protocol::work_setup::ReadyChannel> {
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
) -> Result<Vec<u8>> {
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

pub fn deadlines(
    current: u64,
    acceptance_blocks: u64,
    terminal_blocks: u64,
    payment_blocks: u64,
) -> Result<JobDeadlines> {
    let acceptance =
        current
            .checked_add(acceptance_blocks)
            .ok_or(PaidClientError::DeadlineOverflow {
                stage: "acceptance",
            })?;
    let terminal = acceptance
        .checked_add(terminal_blocks)
        .ok_or(PaidClientError::DeadlineOverflow { stage: "terminal" })?;
    let payment = terminal
        .checked_add(payment_blocks)
        .ok_or(PaidClientError::DeadlineOverflow { stage: "payment" })?;
    Ok(JobDeadlines {
        acceptance,
        terminal,
        payment,
    })
}

pub async fn bind_paid_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
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
        .map_err(PaidClientError::from)
}

async fn exchange_setup(dialer: &ProviderDialer, setup: &mut SetupEndpoint) -> Result<()> {
    let request = prepare_setup_exchange(setup);
    let response = send_setup_exchange(dialer.setup().await?, request).await?;
    apply_setup_exchange(setup, response)?;
    Ok(())
}

struct ProviderDialer {
    endpoint: Endpoint,
    provider: EndpointAddr,
    trust: Option<hellas_client::ProviderTrustAnchor>,
    producer: std::sync::Mutex<Option<hellas_rpc::PublicKey>>,
}

impl ProviderDialer {
    fn new(
        provider: EndpointId,
        addresses: Vec<SocketAddr>,
        endpoint: Endpoint,
        trust: Option<hellas_client::ProviderTrustAnchor>,
    ) -> Self {
        Self {
            trust,
            producer: std::sync::Mutex::new(None),
            endpoint,
            provider: EndpointAddr::from_parts(
                provider,
                addresses.into_iter().map(TransportAddr::Ip),
            ),
        }
    }

    fn require_producer(&self, key: hellas_rpc::PublicKey) -> Result<()> {
        let mut expected = self
            .producer
            .lock()
            .map_err(|_| PaidClientError::ProviderIdentityPoisoned)?;
        if expected.as_ref().is_some_and(|old| *old != key) {
            return Err(PaidClientError::ProviderIdentityChanged);
        }
        *expected = Some(key);
        Ok(())
    }

    async fn setup(&self) -> Result<IrohTransport> {
        self.connect(hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes())
            .await
    }

    async fn work(&self) -> Result<IrohTransport> {
        self.connect(hellas_rpc::services::work::Work::ALPN.as_bytes())
            .await
    }

    async fn connect(&self, alpn: &[u8]) -> Result<IrohTransport> {
        let connection = self
            .endpoint
            .connect(self.provider.clone(), alpn)
            .await
            .map_err(|source| PaidClientError::Connect {
                provider: self.provider.id,
                source,
            })?;
        let transport = IrohTransport::new(connection);
        if let Some(trust) = &self.trust {
            let producer = if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
                hellas_client::confidential_open::<hellas_rpc::services::work::Open>(
                    &transport, trust,
                )
                .await?
            } else {
                hellas_client::confidential_open::<hellas_rpc::services::work_setup::Open>(
                    &transport, trust,
                )
                .await?
            };
            self.require_producer(producer)?;
        }
        Ok(transport)
    }
}

async fn connect_chain(
    config: &WorkConfig,
    next_validator: &mut usize,
) -> Result<WorkBlocks<VerifiedRemoteLightClient>> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })?;
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
            Err(error) => failures.push((url.clone(), error)),
        }
    }
    Err(PaidClientError::ValidatorsUnavailable(failures))
}

async fn check_genesis(
    config: &WorkConfig,
    chain: &WorkBlocks<VerifiedRemoteLightClient>,
) -> Result<()> {
    let first = chain
        .block_at(1)
        .await?
        .ok_or(PaidClientError::MissingState(
            "finalized block 1 for genesis authentication",
        ))?;
    check_genesis_payload(
        config.chain.genesis_payload_digest.as_bytes(),
        &first.parent,
    )
}
pub fn check_genesis_payload(expected: &[u8; 32], actual: &[u8; 32]) -> Result<()> {
    if actual != expected {
        return Err(PaidClientError::GenesisMismatch {
            expected: *expected,
            actual: *actual,
        });
    }
    Ok(())
}

async fn finalized_floor(chain: &WorkBlocks<VerifiedRemoteLightClient>) -> Result<SetupScan> {
    let height = chain
        .latest_height()
        .await?
        .ok_or(PaidClientError::MissingState(
            "configured validator has finalized no blocks",
        ))?;
    let block = chain
        .block_at(height)
        .await?
        .ok_or(PaidClientError::MissingState(
            "configured validator did not return its finalized tip",
        ))?;
    Ok(SetupScan {
        height,
        payload: block.payload,
    })
}

#[cfg(test)]
mod tests;
