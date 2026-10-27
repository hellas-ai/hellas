//! Reusable paid-work sessions: provider authentication, admission, verified delivery,
//! journal recovery, payment, and finalized settlement. Journals are client-owned.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::Instrument as _;

mod error;
pub(crate) mod offer;
pub use error::PaidClientError;
pub use offer::{PaidQuote, request_paid_quote, retained_paid_policy};
type Result<T, E = PaidClientError> = std::result::Result<T, E>;
use crate::client_owner::ClientOwner;
use crate::work_link::WorkLink as ProviderDialer;
use futures::StreamExt as _;
use hellas_chain::client::RemoteLightClient;
use hellas_chain::{FinalizedWorkView as _, WorkBlocks, WorkChannelQuery};
use hellas_client::work::payment::pay_for_result;
use hellas_kernel::{
    EdgeId, Funding, MAX_START_VALIDITY_BLOCKS, Secp256k1Signer, Secp256k1Verifier,
    WorkPaymentTerms,
};
use hellas_rpc::protocol::artifacts::Canonical as _;
use hellas_wire::ServiceMarker;
#[cfg(test)]
use hellas_wire::iroh::IrohTransport;
use hellas_work::model::prepared_input::PreparedPaidInputV1;
use hellas_work::model::profile::{PreparedWorkInput, WorkPolicy};
use hellas_work::model::setup::{ProviderChannelPolicy, WorkChannelDescriptor};
use hellas_work::model::work::{
    JobDeadlines, generation_policy_digest, identity_source_digest, private_policy_commitment,
};
use hellas_work::work::{
    ClientChannel as _, ClientEndpoint, ClientObserver, ClientService, JobProposal, fetch_result,
    propose_work, resume_work_proposal,
};
use hellas_work::work_close::FinalizedBlocks as _;
use hellas_work::work_handshake::{
    PaymentAdmission, SetupEndpoint, SetupService, apply_setup_exchange, prepare_setup_exchange,
    send_setup_exchange,
};
use hellas_work::work_open::{SetupAdvance, SetupProgress};
use hellas_work::work_store::{Role, SetupScan, SetupStore};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointId, SecretKey};
use std::sync::Arc;

use crate::work_config::WorkConfig;

/// Options shared by all jobs on a paid channel.
#[derive(Clone)]
pub struct PaidWorkOptions {
    pub config: WorkConfig,
    pub journal_root: PathBuf,
    pub provider: EndpointId,
    pub provider_addrs: Vec<SocketAddr>,
    pub assurance: hellas_rpc::Assurance,
    pub apple_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub expected_price: u64,
    pub acceptance_blocks: u64,
    pub terminal_blocks: u64,
    pub payment_blocks: u64,
    /// Bounds retries while a provider is not ready. A session's overall lifetime
    /// is controlled by its caller; `transact` also enforces an overall limit.
    pub timeout: Duration,
}

impl PaidWorkOptions {
    /// Reject impossible deadlines and collateral before connecting or signing.
    pub fn validate(&self) -> Result<()> {
        if !(self.acceptance_blocks > 0 && self.terminal_blocks > 0 && self.payment_blocks > 0) {
            return Err(PaidClientError::InvalidOptions(
                "deadline spans must be positive",
            ));
        }
        if self.timeout.is_zero() {
            return Err(PaidClientError::InvalidOptions("timeout must be positive"));
        }

        if self.expected_price == 0 {
            return Err(PaidClientError::InvalidOptions("price must be positive"));
        }
        Ok(())
    }
}

async fn propose_client_payment(
    setup: &mut SetupEndpoint,
    owner: hellas_auth::authority::PrincipalId,
    signer: &Secp256k1Signer,
    funding: Funding,
    terms: WorkPaymentTerms,
) -> Result<()> {
    let bundle = setup
        .state()
        .bundle()
        .ok_or(PaidClientError::MissingState("bond proposal"))?;
    check_client_party(bundle, owner, signer)?;
    setup.propose_payment(funding, terms).await?;
    Ok(())
}

fn check_client_party(
    bundle: &hellas_work::model::bundle::WorkChannelSetupBundleV2,
    owner: hellas_auth::authority::PrincipalId,
    signer: &Secp256k1Signer,
) -> Result<()> {
    let party = bundle.bond_terms().parties.taker();
    if party.owner().to_bytes() != *owner.as_bytes() {
        return Err(PaidClientError::InputMismatch("client coin owner"));
    }
    if party.signer() != signer.party_key() {
        return Err(PaidClientError::InputMismatch("client settlement identity"));
    }
    if party.payout_delegate() != Some(signer.party_key()) {
        return Err(PaidClientError::InputMismatch("client payout delegation"));
    }
    Ok(())
}

/// A paid result authenticated against its channel and caller input.
pub struct PaidWorkResult {
    pub bond_edge: EdgeId,
    pub payment_edge: EdgeId,
    pub channel_id: hellas_auth::Digest,
    pub transcript: Vec<u8>,
    pub work_id: hellas_auth::Digest,
    pub credited_cumulative: u64,
    pub job_price: u64,
    pub provider_key: hellas_auth::PublicKey,
    pub input: hellas_rpc::InputCommitment,
    pub settled_provider_payout: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputIdentities {
    pub allowed_environment: hellas_rpc::ContentId,
    pub generation_policy_digest: hellas_auth::Digest,
    pub identity_source_digest: hellas_auth::Digest,
}

impl InputIdentities {
    pub fn from_prepared(prepared: &PreparedPaidInputV1) -> Result<Self> {
        let parts = prepared.parts()?;
        Self::from_parts(&parts)
    }

    fn from_parts(
        parts: &hellas_work::model::prepared_input::PreparedPaidInputParts,
    ) -> Result<Self> {
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
    policy: ProviderChannelPolicy,
    dialer: ProviderDialer,
    client: ClientService,
    observer: Option<tokio::task::JoinHandle<()>>,
    needs_recovery: bool,
}

impl Drop for PaidWorkSession {
    fn drop(&mut self) {
        // Dropping the sole client owner removes payment authority; stop its observer.
        if let Some(observer) = &self.observer {
            observer.abort();
        }
    }
}

fn spawn_observer(
    client: ClientObserver,
    descriptor: WorkChannelDescriptor,
    config: WorkConfig,
    mut remote: RemoteLightClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut source_config = config.clone();
        let mut finalized = tokio::time::timeout(config.poll, remote.subscribe_finalized())
            .await
            .ok()
            .and_then(|result| result.ok());
        loop {
            if client
                .with_state(|state| state.close_settled().is_some())
                .await
                .unwrap_or(false)
            {
                break;
            }
            let Ok(floor) = client.with_state(|state| state.cursor().0).await else {
                let _ = client.suspend().await;
                break;
            };
            let chain = WorkBlocks::new(remote.clone()).with_min_height(floor);
            let started = hellas_work::work::ObservationTime::now();
            let span = hellas_rpc::request_span!(target: "hellas_request", parent: None, "paid.channel.observe", hellas.channel.role = "client");
            let result = tokio::time::timeout(
                config.max_observation_age,
                async {
                    let mut driver = client.drive()?;
                    driver.advance_close(&chain, &chain).await?;
                    let ready = ready_channel(&descriptor, &chain).await?;
                    if ready
                        .check_caught_up(client.with_state(|state| state.cursor().0).await?)
                        .is_err()
                    {
                        driver.catch_up_to(&chain, ready.finalized_height()).await?;
                    }
                    client
                        .observe_ready(ready, started, config.max_observation_age)
                        .await?;
                    Ok::<_, PaidClientError>(())
                }
                .instrument(span),
            )
            .await
            .unwrap_or(Err(PaidClientError::Timeout {
                stage: "channel observer",
            }));
            if let Err(error) = result {
                let _ = client.suspend().await;
                tracing::debug!(%error, "paid client observation unavailable");
                finalized = None;
                source_config.validators.rotate_left(1);
                match crate::client_chain::connect(&source_config, config.max_observation_age).await
                {
                    Ok(next) => remote = next,
                    Err(error) => {
                        tracing::debug!(%error, "waiting for a verified remote chain source");
                        tokio::time::sleep(config.poll).await;
                        continue;
                    }
                }
            }
            if let Some(stream) = &mut finalized {
                tokio::select! {
                    item = stream.next() => if !matches!(item, Some(Ok(_))) { finalized = None; },
                    _ = tokio::time::sleep(config.poll) => {},
                }
            } else {
                tokio::time::sleep(config.poll).await;
                finalized = tokio::time::timeout(config.poll, remote.subscribe_finalized())
                    .await
                    .ok()
                    .and_then(|result| result.ok());
            }
        }
    })
}

async fn check_payment_window(client: &ClientService, work_id: hellas_auth::Digest) -> Result<()> {
    client
        .with_state(|state| {
            let job = state
                .job_by_id(work_id)
                .ok_or(PaidClientError::MissingState("accepted job disappeared"))?;
            if state.cursor().0 > job.authorization().payment_deadline {
                Err(PaidClientError::PaymentExpired)
            } else {
                Ok(())
            }
        })
        .await?
}

enum OpenIntent {
    Any,
    Job(Box<crate::job::Job>),
    Retained,
}
impl OpenIntent {
    fn job(&self) -> Option<&crate::job::Job> {
        if let Self::Job(job) = self {
            Some(job)
        } else {
            None
        }
    }
}

impl PaidWorkSession {
    pub fn open(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
    ) -> impl std::future::Future<Output = Result<Self>> {
        Box::pin(Self::open_inner(
            args,
            endpoint,
            settlement_key,
            owner,
            OpenIntent::Any,
        ))
    }

    /// Reopens an existing channel without requesting fresh owner funding.
    pub fn open_retained(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
    ) -> impl std::future::Future<Output = Result<Self>> {
        Box::pin(Self::open_inner(
            args,
            endpoint,
            settlement_key,
            owner,
            OpenIntent::Retained,
        ))
    }

    /// Admits the unsigned job against the actual quote before funding it.
    pub fn open_for_job(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
        job: &crate::job::Job,
    ) -> impl std::future::Future<Output = Result<Self>> {
        Box::pin(Self::open_inner(
            args,
            endpoint,
            settlement_key,
            owner,
            OpenIntent::Job(Box::new(job.clone())),
        ))
    }

    async fn open_inner(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
        intent: OpenIntent,
    ) -> Result<Self> {
        args.validate()?;
        let config = &args.config;
        config.clone().validate()?;
        if owner.delegate() != settlement_key.party_key() {
            return Err(PaidClientError::InvalidOptions(
                "funding delegate differs from the settlement key",
            ));
        }
        let read_timeout = args.timeout.min(hellas_chain::node::RECOVERY_TIMEOUT);
        let remote = crate::client_chain::connect(config, read_timeout).await?;
        let chain = WorkBlocks::new(remote.clone()).with_read_retry(config.poll, read_timeout);

        std::fs::create_dir_all(&args.journal_root).map_err(|source| {
            PaidClientError::JournalDirectory {
                path: args.journal_root.clone(),
                source,
            }
        })?;
        let (store, signed) = match offer::retained_offer(
            &args.journal_root,
            config.chain.network,
            args.provider,
            &chain,
        )
        .await?
        {
            Some(retained) => retained,
            None if matches!(intent, OpenIntent::Retained) => {
                return Err(PaidClientError::NoRetainedChannel);
            }
            None => {
                let signed = offer::obtain_offer(
                    &args,
                    &endpoint,
                    &settlement_key,
                    &owner,
                    &remote,
                    intent.job(),
                )
                .await?;
                check_client_party(&signed.offer().proposal, owner.principal(), &settlement_key)?;
                let store = SetupStore::open(
                    &args.journal_root,
                    config.chain.network,
                    signed.offer().proposal.bond_edge(),
                    Role::Client,
                    &Secp256k1Verifier::new(),
                )
                .await?;
                (store, signed)
            }
        };
        signed.check()?;
        let payment_funding = signed.offer().payment_funding.clone();
        let policy = signed.offer().policy.clone();
        let omission_bond = signed.offer().omission_bond;
        offer::check_policy(&args, &policy, omission_bond)?;
        if let Some(job) = intent.job() {
            job.check_policy(&policy)?;
        }
        check_client_party(&signed.offer().proposal, owner.principal(), &settlement_key)?;
        let bond = signed.offer().proposal.bond_edge();
        let trust = hellas_client::selected_provider_trust(
            &signed.offer().provider,
            args.assurance,
            args.apple_trust.as_ref(),
        )?;
        let dialer =
            ProviderDialer::new(args.provider, args.provider_addrs.clone(), endpoint, trust);
        let mut setup = SetupEndpoint::new(
            store,
            settlement_key.clone(),
            PaymentAdmission::Proposes(Box::new(policy.clone())),
        );
        if setup.state().revision().is_none() {
            setup
                .import_offer(*args.provider.as_bytes(), signed)
                .await?;
        }
        owner
            .claim(config.chain.network, args.provider, &payment_funding)
            .await?;
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
        dialer.require_producer(hellas_auth::PublicKey::Secp256k1(
            bundle.bond_terms().parties.maker().signer().to_bytes(),
        ))?;
        if setup.state().scan_armed().is_none() {
            setup.arm_scan(finalized_floor(&chain).await?).await?;
        }
        if setup.state().revision() == Some(1) {
            let terms = payment_terms(config, &policy, &bundle, omission_bond);
            propose_client_payment(
                &mut setup,
                owner.principal(),
                &settlement_key,
                payment_funding,
                terms,
            )
            .await?;
        } else {
            check_client_party(&bundle, owner.principal(), &settlement_key)?;
        }
        if setup.state().revision() == Some(2) {
            exchange_setup(&dialer, &mut setup, config.poll, args.timeout).await?;
        }
        if setup.state().revision() != Some(3) {
            return Err(PaidClientError::MissingState(
                "countersigned setup revision",
            ));
        }

        let setup_service = SetupService::new(setup);
        let (mounted, descriptor) =
            drive_setup(&setup_service, &policy, &chain, config.poll).await?;
        let chain = chain.with_min_height(mounted.state().cursor().0);
        let started = hellas_work::work::ObservationTime::now();
        let ready = match ready_channel(&descriptor, &chain).await {
            Ok(ready) => Some(ready),
            Err(PaidClientError::WorkSetup(_)) => None,
            Err(error) => return Err(error),
        };
        let initially_ready = ready.is_some();
        let mut endpoint = ClientEndpoint::recover(mounted, settlement_key)?;
        endpoint.catch_up(&chain).await?;
        let client = ClientService::new(endpoint);
        if let Some(ready) = ready {
            client
                .observer()
                .observe_ready(ready, started, config.max_observation_age)
                .await?;
        }
        let observer = spawn_observer(
            client.observer(),
            descriptor.clone(),
            config.clone(),
            remote,
        );

        let session = Self {
            args,
            descriptor,
            policy,
            dialer,
            client,
            observer: Some(observer),
            needs_recovery: true,
        };
        if initially_ready {
            // A long restart catch-up may outlive the first observation. Wait
            // during channel opening; requests never perform this catch-up.
            // The session already owns the task, so cancellation aborts it.
            tokio::time::timeout(session.args.timeout, async {
                while session.client.readiness().await.is_err()
                    && !session
                        .client
                        .with_state(|state| state.is_closing())
                        .await?
                {
                    tokio::time::sleep(session.args.config.poll).await;
                }
                Ok::<_, PaidClientError>(())
            })
            .await
            .map_err(|_| PaidClientError::Timeout {
                stage: "initial channel observation",
            })??;
        }
        Ok(session)
    }

    /// Stops observation and joins the task before releasing the journal.
    /// Call after draining jobs; retained accounting is recovered on restart.
    pub async fn shutdown(&mut self) {
        if let Some(observer) = &mut self.observer {
            observer.abort();
            let _ = observer.await;
        }
        self.observer = None;
        // The observer can no longer renew readiness after suspension.
        let _ = self.client.observer().suspend().await;
    }

    /// Identifies the funded channel and its admitted execution policy.
    pub fn descriptor(&self) -> &WorkChannelDescriptor {
        &self.descriptor
    }

    /// Reads local journal state under a short lock.
    pub async fn with_state<R>(
        &self,
        read: impl FnOnce(&hellas_work::work_store::Channel) -> R,
    ) -> Result<R> {
        Ok(self.client.with_state(read).await?)
    }

    /// True after reopening a journal or an interrupted request.
    pub fn needs_recovery(&self) -> bool {
        self.needs_recovery
    }

    /// Opens a close; the independent observer drives its finalized payout.
    /// There is no deadline here: with the observer stopped or validators
    /// unreachable this waits as long as the process runs. Callers that need
    /// a bound should wrap it in one.
    pub async fn settle(&mut self) -> Result<u64> {
        if !self.client.with_state(|state| state.is_closing()).await? {
            self.client.client().await?.prepare_close().await?;
        }
        loop {
            if let Some(settlement) = self
                .client
                .with_state(|state| state.close_settled())
                .await?
            {
                return Ok(settlement.provider_payout);
            }
            tokio::time::sleep(self.args.config.poll).await;
        }
    }

    /// Runs a request and pays only after verifying its complete result.
    /// With `recover`, resume payable journaled work first and admit this as a new
    /// job; otherwise reuse a still-active job matching the input. `None` only
    /// performs recovery. Prefixes are authenticated before incremental delivery.
    pub async fn run(
        &mut self,
        prepared: Option<PreparedWorkInput>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
    ) -> Result<Option<PaidWorkResult>> {
        self.run_prepared(prepared, recover, progress, None, None)
            .await
    }

    /// Like `run`, also marking `proposed` before a proposal can leave the process.
    /// A caller using cancellation must continue payment/recovery once it is set.
    pub(crate) async fn run_prepared(
        &mut self,
        prepared: Option<PreparedWorkInput>,
        recover: bool,
        progress: Option<hellas_work::work::PaidProgress>,
        proposed: Option<&AtomicBool>,
        purchase: Option<&mut crate::transact::Purchase>,
    ) -> Result<Option<PaidWorkResult>> {
        let Self {
            args,
            descriptor,
            policy,
            dialer,
            client,
            needs_recovery,
            ..
        } = self;
        let config = &args.config;
        if let Some(prepared) = prepared.as_ref() {
            check_request(
                policy,
                prepared,
                &dialer.trust,
                hellas_auth::PublicKey::Secp256k1(descriptor.channel().client_key().to_bytes()),
            )?;
        }
        if recover
            && *needs_recovery
            && let Some(work_id) = client
                .with_state(|state| state.last_payment().map(|payment| payment.work_id))
                .await?
        {
            // A lost acknowledgement never requires fresh admission: these
            // exact certificate bytes are already durable on the client.
            pay_for_result(dialer.work().await?, client, work_id).await?;
        }
        if client.with_state(|state| state.is_closing()).await? {
            return if prepared.is_none() {
                Ok(None)
            } else {
                Err(hellas_work::work::EndpointError::NotAdmitting.into())
            };
        }
        let ready = client.readiness().await?;
        if recover && *needs_recovery {
            enum RecoveredJob {
                /// The result was delivered, verified and committed before the
                /// restart; only its payment is outstanding, and settling it
                /// needs none of the payload a Fetch journal strips.
                Delivered(hellas_auth::Digest),
                /// No payload and no result: the job can neither execute nor
                /// settle. Its evidence is retained until the payment deadline
                /// filters it out, without blocking every later request.
                Unrecoverable(hellas_auth::Digest),
                Replay(
                    hellas_auth::Digest,
                    hellas_work::work_store::JobPhase,
                    PreparedWorkInput,
                ),
            }
            let pending = client
                .with_state(|state| {
                    state
                        .jobs()
                        .filter(|job| {
                            // The journal forbids signing payment after this height.
                            // Keep the evidence, but do not let an unpayable old job
                            // prevent this channel from serving a new request. Retained
                            // certificates are re-sent separately above.
                            let payable = job.authorization().payment_deadline >= state.cursor().0;
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
                            // reconstruct a lost request or authorize another
                            // execution, but an already delivered result still
                            // settles: signing payment needs no payload.
                            if job.prepared_input().is_empty() {
                                return Ok(if job.result().is_some() {
                                    RecoveredJob::Delivered(job.work_id())
                                } else {
                                    RecoveredJob::Unrecoverable(job.work_id())
                                });
                            }
                            PreparedWorkInput::decode(
                                job.prepared_input(),
                                hellas_work::content::MAX_CONTENT_BYTES,
                            )
                            .map(|input| RecoveredJob::Replay(job.work_id(), job.phase(), input))
                            .map_err(PaidClientError::from)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .await??;
            for recovered in pending {
                let (work_id, phase, pending) = match recovered {
                    RecoveredJob::Delivered(work_id) => {
                        pay_for_result(dialer.work().await?, client, work_id).await?;
                        continue;
                    }
                    RecoveredJob::Unrecoverable(work_id) => {
                        tracing::warn!(
                            %work_id,
                            "retaining an unpaid job whose request payload is lost; \
                             it can neither execute nor settle before its payment deadline"
                        );
                        continue;
                    }
                    RecoveredJob::Replay(work_id, phase, input) => (work_id, phase, input),
                };
                check_request(
                    policy,
                    &pending,
                    &dialer.trust,
                    hellas_auth::PublicKey::Secp256k1(descriptor.channel().client_key().to_bytes()),
                )?;
                let result = execute_paid_job(
                    args,
                    pending,
                    dialer,
                    client,
                    &ready,
                    config.poll,
                    None,
                    JobLookup::Retained(work_id),
                    None,
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
        // A caller that declined recovery keeps the flag for a later run.
        if prepared.is_some() {
            *needs_recovery = true;
        }
        let result = match prepared {
            Some(prepared) => {
                let ready = client.readiness().await?;
                Some(
                    execute_paid_job(
                        args,
                        prepared,
                        dialer,
                        client,
                        &ready,
                        config.poll,
                        progress.as_ref(),
                        if recover {
                            JobLookup::New
                        } else {
                            JobLookup::PreparedInput
                        },
                        proposed,
                        purchase,
                    )
                    .await?,
                )
            }
            None => None,
        };
        if recover || result.is_some() {
            *needs_recovery = client
                .with_state(|state| {
                    state.jobs().any(|job| {
                        job.authorization().payment_deadline >= state.cursor().0
                            && (!job.prepared_input().is_empty() || job.result().is_some())
                    })
                })
                .await?;
        }
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
    client: &mut ClientService,
    proposal: &JobProposal,
    retained: Option<hellas_auth::Digest>,
    poll: Duration,
    timeout: Duration,
    proposed: Option<&AtomicBool>,
) -> Result<hellas_auth::Digest> {
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
                if refusal.is_retryable() => {}
            // Finalized setup can reach the client before the provider's clock
            // mounts Work. Upload has no structured NotReady response; the
            // retained half-signed proposal makes this retry the same purchase.
            Err(hellas_work::work::ProposeError::Transport(status))
                if status.code() == hellas_wire::WireCode::Unavailable => {}
            Err(error) => return Err(error.into()),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(delay.min(remaining)).await;
        delay = delay.saturating_mul(2).min(Duration::from_secs(10));
    }
}

enum JobLookup {
    Retained(hellas_auth::Digest),
    PreparedInput,
    New,
}

#[allow(clippy::too_many_arguments)]
async fn execute_paid_job(
    args: &PaidWorkOptions,
    prepared: PreparedWorkInput,
    dialer: &ProviderDialer,
    client: &mut ClientService,
    ready: &hellas_work::model::setup::ReadyChannel,
    poll: Duration,
    progress: Option<&hellas_work::work::PaidProgress>,
    lookup: JobLookup,
    proposed: Option<&AtomicBool>,
    mut purchase: Option<&mut crate::transact::Purchase>,
) -> Result<PaidWorkResult> {
    let readiness_timeout = args.timeout;
    let prepared_bytes = prepared.encode()?;
    let current = client.with_state(|state| state.cursor().0).await?;
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
        .with_state(|state| {
            state
                .jobs()
                .filter(|job| match &lookup {
                    JobLookup::Retained(work_id) => job.work_id() == *work_id,
                    JobLookup::New => false,
                    JobLookup::PreparedInput => {
                        job.authorization().input_content
                            == hellas_rpc::ContentRef::for_bytes(&prepared_bytes)
                            && job.authorization().payment_deadline >= current
                            && (job.phase() != hellas_work::work_store::JobPhase::HalfSigned
                                || job.authorization().acceptance_deadline >= current)
                    }
                })
                .map(|job| (job.work_id(), job.phase(), *job.authorization()))
                .collect::<Vec<_>>()
        })
        .await?;
    if existing.len() > 1 {
        return Err(PaidClientError::AmbiguousRecovery);
    }
    if !existing.is_empty()
        && let Some(proposed) = proposed
    {
        proposed.store(true, Ordering::Release);
    }
    if let Some((work_id, _, _)) = existing.first() {
        client
            .restore_input(*work_id, ready, &proposal.prepared_input)
            .await?;
        tracing::debug!(%work_id, "retained job input restored");
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
        | Some((work_id, hellas_work::work_store::JobPhase::Matched, _)) => {
            let retained = client
                .with_state(|state| {
                    state
                        .job_by_id(work_id)
                        .is_some_and(|job| !job.transcript().is_empty())
                })
                .await?;
            (work_id, retained)
        }
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
    if let Some(purchase) = purchase.as_deref_mut() {
        purchase.accepting(work_id)?;
    }
    let transcript = if already_collected {
        client
            .with_state(|state| {
                state
                    .job_by_id(work_id)
                    .map(|job| job.transcript().to_vec())
            })
            .await?
            .ok_or(PaidClientError::MissingState(
                "collected job disappeared from its journal",
            ))?
    } else if progress.is_some() || matches!(proposal.prepared_input, PreparedWorkInput::Fetch(_)) {
        let mut emitted = false;
        let delivery = loop {
            let result = hellas_work::work::fetch_result_stream(
                dialer.work().await?,
                client,
                ready,
                work_id,
                |event| {
                    // Output is only exposed when a user stream observes it;
                    // recovery without one may safely retry after any event.
                    if let Some(progress) = progress {
                        emitted = true;
                        progress(event.clone()).map_err(|error| {
                            hellas_work::model::work::PaidWorkError::Transcript(error.to_string())
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
            check_payment_window(client, work_id).await?;
            tracing::debug!(%error, %work_id, "waiting for paid result stream readiness");
            tokio::time::sleep(poll.max(Duration::from_secs(1))).await;
        };
        check_payment_window(client, work_id).await?;
        delivery.transcript
    } else {
        collect_until_ready(dialer, client, ready, work_id, poll).await?
    };
    if let Some(purchase) = purchase.as_deref_mut() {
        purchase.paying(work_id)?;
    }
    let credited = pay_for_result(dialer.work().await?, client, work_id).await?;
    if let Some(purchase) = purchase {
        purchase.paid(work_id)?;
    }
    Ok(PaidWorkResult {
        bond_edge: ready.channel().payment_terms().bond_edge,
        payment_edge: ready.channel().payment_edge(),
        channel_id: ready.channel().id(),
        work_id,
        job_price: ready.payment_policy().fixed_price,
        credited_cumulative: credited,
        transcript,
        provider_key: hellas_auth::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
        input: proposal.prepared_input.input_commitment()?,
        settled_provider_payout: None,
    })
}

pub(crate) fn check_request(
    policy: &ProviderChannelPolicy,
    prepared: &PreparedWorkInput,
    trust: &hellas_client::ProviderTrustAnchor,
    caller: hellas_auth::PublicKey,
) -> Result<()> {
    if trust.apple_app_attest.is_some() {
        trust.verify_environment(policy.work_policy.allowed_environment())?;
    }
    let assurance = prepared.assurance()?;
    if trust.required_assurance != assurance {
        return Err(PaidClientError::InputMismatch(
            "assurance differs from provider trust",
        ));
    }
    match (prepared, &policy.work_policy) {
        (PreparedWorkInput::Evaluate(input), WorkPolicy::Evaluate(_)) => {
            check_evaluate_input(policy, input)?;
        }
        (
            PreparedWorkInput::Fetch(input),
            WorkPolicy::Fetch {
                policy,
                route,
                contract,
            },
        ) => {
            let parts = input.parts()?;
            if parts.contract != *contract || policy.allowed_environment != contract.manifest_id() {
                return Err(PaidClientError::InputMismatch("Fetch contract"));
            }
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
            if let hellas_work::model::fetch::FetchRoutePolicy::SealedRoute { service, method } =
                route
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
    let WorkPolicy::Evaluate(expected) = &policy.work_policy else {
        return Err(PaidClientError::InputMismatch("expected Evaluate profile"));
    };
    if expected.allowed_environment != input.allowed_environment {
        return Err(PaidClientError::InputMismatch("Evaluate environment"));
    }
    if !(hellas_work::model::work::matches_generation_policy(expected, &parts.text_policy)?) {
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
    bundle: &hellas_work::model::bundle::WorkChannelSetupBundleV2,
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
    chain: &WorkBlocks<RemoteLightClient>,
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
    chain: &WorkBlocks<RemoteLightClient>,
) -> Result<hellas_work::model::setup::ReadyChannel> {
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: Some(descriptor.channel().payment_edge()),
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

async fn collect_until_ready(
    dialer: &ProviderDialer,
    client: &mut ClientService,
    ready: &hellas_work::model::setup::ReadyChannel,
    work_id: hellas_auth::Digest,
    poll: Duration,
) -> Result<Vec<u8>> {
    loop {
        match fetch_result(dialer.work().await?, client, ready, work_id).await {
            Ok(delivery) => {
                check_payment_window(client, work_id).await?;
                return Ok(delivery.transcript);
            }
            Err(hellas_work::work::DeliverError::Refused { refusal, reason })
                if refusal.is_retryable() =>
            {
                check_payment_window(client, work_id).await?;
                tracing::debug!(%reason, "waiting for paid result");
                tokio::time::sleep(poll.max(Duration::from_secs(1))).await;
            }
            Err(error) => return Err(error.into()),
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

async fn exchange_setup(
    dialer: &ProviderDialer,
    setup: &mut SetupEndpoint,
    poll: Duration,
    timeout: Duration,
) -> Result<()> {
    let request = prepare_setup_exchange(setup);
    tokio::time::timeout(timeout, async {
        loop {
            let response = send_setup_exchange(dialer.setup().await?, request.clone()).await?;
            match apply_setup_exchange(setup, response).await {
                Err(hellas_work::work_handshake::SetupExchangeError::Refused {
                    refusal, ..
                }) if refusal.is_retryable() => tokio::time::sleep(poll).await,
                result => return Ok(result?),
            }
        }
    })
    .await
    .map_err(|_| PaidClientError::Timeout {
        stage: "setup exchange",
    })?
}

async fn finalized_floor(chain: &WorkBlocks<RemoteLightClient>) -> Result<SetupScan> {
    let height = chain
        .latest_height()
        .await?
        .ok_or(PaidClientError::MissingState(
            "remote chain has no finalized blocks",
        ))?;
    let block = chain
        .block_at(height)
        .await?
        .ok_or(PaidClientError::MissingState(
            "remote archive did not return its finalized tip",
        ))?;
    Ok(SetupScan {
        height,
        payload: block.payload,
    })
}

#[cfg(test)]
mod tests;
