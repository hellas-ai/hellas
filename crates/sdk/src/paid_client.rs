//! Reusable paid-work sessions: provider authentication, admission, verified delivery,
//! journal recovery, payment, and finalized settlement. Journals are client-owned.
use hellas_private::StoreLocation;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::Instrument as _;

mod content;
mod error;
mod funding;
pub(crate) mod offer;
mod settlement;
pub use content::recover_content;
pub use error::PaidClientError;
pub use funding::{RecoveredFundingChannel, recover_funding_channels, recover_funding_intent};
pub use offer::{PaidQuote, request_paid_quote};
pub use settlement::{
    FinalizedChannelSettlement, RetainedSettlementChannel, finalized_channel_settlement,
    retained_settlement_channels, settle_channel,
};
type Result<T, E = PaidClientError> = std::result::Result<T, E>;
use crate::client_owner::ClientOwner;
use crate::work_link::WorkLink as ProviderDialer;
use hellas_chain::LightClient as _;
use hellas_chain::client::RemoteLightClient;
use hellas_chain::{FinalizedWorkView as _, WorkBlocks, WorkChannelQuery};
use hellas_channel::model::setup::{ProviderChannelPolicy, WorkChannelDescriptor};
use hellas_channel::model::work::{JobDeadlines, private_policy_commitment};
use hellas_channel::work::{
    ClientChannel as _, ClientEndpoint, ClientObserver, ClientService, JobProposal, propose_work,
    resume_work_proposal,
};
use hellas_channel::work_handshake::{
    PaymentAdmission, SetupEndpoint, SetupService, apply_setup_exchange, prepare_setup_exchange,
    send_setup_exchange,
};
use hellas_channel::work_open::{SetupAdvance, SetupProgress};
use hellas_channel::work_store::{Role, SetupStore};
use hellas_client::work::payment::pay_for_result;
use hellas_kernel::{
    EdgeId, Funding, MAX_START_VALIDITY_BLOCKS, Secp256k1Signer, Secp256k1Verifier,
    WorkPaymentTerms,
};
use hellas_rpc::protocol::invocation::PreparedInvocation;
use hellas_store::content::{LocalStore, Scope};
use hellas_wire::ServiceMarker;
#[cfg(test)]
use hellas_wire::iroh::IrohTransport;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use std::sync::Arc;

use crate::work_config::WorkConfig;

/// Client purchases and gateway pools own distinct journal layouts.
#[derive(Clone, Copy, Debug)]
pub enum PaidJournalKind {
    Client,
    Gateway,
}

/// Options shared by all jobs on a paid channel.
#[derive(Clone)]
pub struct PaidWorkOptions {
    pub config: WorkConfig,
    pub journal_kind: PaidJournalKind,
    pub content: hellas_store::content::DiskStore,
    /// Every connection must present exactly this enrollment and node.
    pub provider: hellas_client::ProviderAddress,
    /// Direct UDP addresses of `provider.node`.
    pub provider_addrs: Vec<SocketAddr>,
    pub assurance: hellas_rpc::Assurance,
    /// Independent approval an Apple provider requires; it must name
    /// `provider.enrollment`.
    pub apple_trust: Option<hellas_client::ProviderTrustAnchor>,
    /// The most a job may cost. A quote above it is refused; a job's own
    /// signed price must equal the price the provider quotes.
    pub expected_price: u64,
    pub acceptance_blocks: u64,
    pub terminal_blocks: u64,
    pub payment_blocks: u64,
    /// Bounds retries while a provider is not ready; `None` waits until done.
    /// A session's overall lifetime is controlled by its caller.
    pub timeout: Option<Duration>,
}

/// Application approval of the actual channel funding. Implementations must
/// reserve idempotently for a stable reservation ID, including after a crash
/// between approval and persistence of the signed funding intent.
/// A caller must use a distinct reservation for each deliberate funding
/// attempt and keep the same ID when recovering that attempt.
pub trait FundingApproval: Send + Sync {
    fn reservation(
        &self,
        network: hellas_kernel::NetworkId,
        provider: iroh::EndpointId,
    ) -> [u8; 16];
    fn reserve(
        &self,
        reservation: [u8; 16],
        amount: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), PaidClientError>>;
    fn recover(
        &self,
        reservation: [u8; 16],
        amount: u64,
    ) -> futures::future::BoxFuture<'_, std::result::Result<(), PaidClientError>>;
}

/// Funding constraints shared by native and gateway session opening.
#[derive(Clone, Default)]
pub struct SessionFundingOptions {
    /// Maximum actual funding for a newly quoted channel. Reopening a retained
    /// channel does not reserve or fund again and does not apply this cap.
    pub max_funding: Option<u64>,
    /// Durable application reservation for fresh funding; omitted for callers
    /// that do not need an application-level reservation.
    pub approval: Option<Arc<dyn FundingApproval>>,
}

impl SessionFundingOptions {
    pub(crate) fn check_quote(&self, funding_value: u64) -> Result<()> {
        if self.max_funding.is_some_and(|limit| funding_value > limit) {
            return Err(PaidClientError::InvalidOptions(
                "quote exceeds caller funding cap",
            ));
        }
        Ok(())
    }
}

/// Chain reads keep their recovery bound even when the caller sets none.
pub(crate) fn read_timeout(timeout: Option<Duration>) -> Duration {
    timeout.map_or(hellas_channel::work::MAX_CERTIFIED_AGE, |timeout| {
        timeout.min(hellas_channel::work::MAX_CERTIFIED_AGE)
    })
}

/// How long owner funding may wait for its transaction to finalize. That
/// spans blocks, not one read, so the caller's deadline bounds it; without
/// one it keeps the read bound.
pub(crate) fn funding_timeout(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or(hellas_channel::work::MAX_CERTIFIED_AGE)
}

/// The channel's readiness from a confirmation that has not lapsed, within
/// the caller's deadline. See [`ClientObserver::fresh_readiness`].
async fn fresh_readiness(
    client: &ClientService,
    timeout: Option<Duration>,
) -> Result<hellas_channel::model::setup::ReadyChannel> {
    within(timeout, "channel readiness", async {
        Ok(client.observer().fresh_readiness().await?)
    })
    .await
}

/// Bounds `work` by the caller's timeout; without one it waits until done.
async fn within<T>(
    timeout: Option<Duration>,
    stage: &'static str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, work)
            .await
            .map_err(|_| PaidClientError::Timeout { stage })?,
        None => work.await,
    }
}

impl PaidWorkOptions {
    pub fn journal_root(&self) -> StoreLocation {
        match self.journal_kind {
            PaidJournalKind::Client => self
                .config
                .chain
                .client_journals(&self.provider.to_string()),
            PaidJournalKind::Gateway => self.config.chain.gateway(&self.provider.node.to_string()),
        }
    }

    /// Reject impossible deadlines and collateral before connecting or signing.
    pub fn validate(&self) -> Result<()> {
        if !(self.acceptance_blocks > 0 && self.terminal_blocks > 0 && self.payment_blocks > 0) {
            return Err(PaidClientError::InvalidOptions(
                "deadline spans must be positive",
            ));
        }
        if self.timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(PaidClientError::InvalidOptions("timeout must be positive"));
        }

        if self.expected_price == 0 {
            return Err(PaidClientError::InvalidOptions("price must be positive"));
        }
        self.trust()?;
        Ok(())
    }

    /// The trust every connection to the addressed provider must satisfy.
    pub fn trust(&self) -> Result<hellas_client::ProviderTrustAnchor> {
        Ok(self
            .provider
            .trust(self.assurance, self.apple_trust.as_ref())?)
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
    bundle: &hellas_channel::model::bundle::WorkChannelSetupBundleV2,
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
    pub output: hellas_rpc::protocol::invocation::output::InvocationOutput,
    pub work_id: hellas_auth::Digest,
    /// Provider co-signature over the accepted work identity.
    pub acceptance_signature: hellas_kernel::Sig,
    pub credited_cumulative: u64,
    pub job_price: u64,
    pub provider_key: hellas_auth::PublicKey,
    pub input: hellas_rpc::InputCommitment,
}

/// A funded channel. Its owner serializes proposal and payment exchanges;
/// accepted jobs collect concurrently through the shared journal.
/// Cancellation retains recovery state; call `run(None, true, None)` to resume it.
pub struct PaidWorkSession {
    args: PaidWorkOptions,
    descriptor: WorkChannelDescriptor,
    policy: ProviderChannelPolicy,
    dialer: Arc<ProviderDialer>,
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

async fn observe_client(
    client: &ClientObserver,
    descriptor: &WorkChannelDescriptor,
    remote: &RemoteLightClient,
    floor: u64,
) -> Result<()> {
    let chain = WorkBlocks::new(remote.clone()).with_min_height(floor);
    let span = hellas_rpc::request_span!(target: "hellas_request", parent: None, "paid.channel.observe", hellas.channel.role = "client");
    tokio::time::timeout(
        hellas_channel::work::MAX_CERTIFIED_AGE,
        async {
            let snapshot = settlement::channel_read(&chain, descriptor.channel()).await?;
            let observed = snapshot.observed_channel();
            client.drive()?.advance_close(&observed, &chain).await?;
            client
                .observe_ready(descriptor.check_ready(&observed)?)
                .await?;
            Ok::<_, PaidClientError>(())
        }
        .instrument(span),
    )
    .await
    .unwrap_or(Err(PaidClientError::Timeout {
        stage: "channel observer",
    }))
}

fn spawn_observer(
    client: ClientObserver,
    descriptor: WorkChannelDescriptor,
    config: WorkConfig,
    mut remote: RemoteLightClient,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut source_config = config.clone();
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
            if let Err(error) = observe_client(&client, &descriptor, &remote, floor).await {
                let _ = client.suspend().await;
                tracing::debug!(%error, "paid client observation unavailable");
                source_config.chain.rotate_validators();
                match crate::client_chain::connect_at(
                    &source_config,
                    hellas_channel::work::MAX_CERTIFIED_AGE,
                    floor,
                )
                .await
                {
                    Ok(next) => remote = next,
                    Err(error) => {
                        tracing::debug!(%error, "waiting for a verified remote chain source");
                    }
                }
            }
            // Read again before the last confirmation lapses. A read of an
            // aged block leaves less than the age bound, and waiting a whole
            // POLL after it would refuse new money while fresher blocks exist.
            let left = client.freshness().await.unwrap_or_default();
            let next = hellas_channel::work::POLL
                .min(left / 2)
                .max(hellas_channel::work::SETUP_POLL);
            #[expect(
                clippy::disallowed_methods,
                reason = "inventory class B/C: the certified-read poll the response window is sized for"
            )]
            tokio::time::sleep(next).await;
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

pub(crate) struct OpenIntent<'a> {
    pub(crate) job: Option<Box<crate::job::Job>>,
    pub(crate) allow_funding: bool,
    pub(crate) before_open: Option<crate::client_owner::FundingBinding<'a>>,
}

/// The empty content a recovery-only run reads.
pub(crate) fn empty_content() -> (LocalStore, Scope) {
    (
        LocalStore::Memory(hellas_store::content::MemoryStore::new(
            hellas_store::content::Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ),
        )),
        Scope::Owner,
    )
}

/// Admission mode for session opening. Retained opening cannot fund a channel.
pub enum SessionOpenMode<'a> {
    Any,
    Job(&'a crate::job::Job),
    Retained,
}

impl PaidWorkSession {
    pub(crate) fn state_key(&self) -> String {
        self.args.config.chain.state_key()
    }

    pub(crate) fn execution_target(&self) -> crate::execution::ExecutionTarget {
        crate::execution::ExecutionTarget {
            network: self.args.config.network(),
            provider: self.args.provider,
        }
    }

    /// Opens a session, admitting `mode`'s job against the actual quote before
    /// any fresh owner funding.
    ///
    /// The admission mode is an argument rather than a default: whether a call
    /// may allocate funding belongs at the call site, not hidden in a wrapper.
    /// Boxed rather than an `async fn`: the opener is reached from deep inside a
    /// caller's future, and its state must not be composed inline there.
    pub fn open(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
        mode: SessionOpenMode<'_>,
        funding: SessionFundingOptions,
    ) -> impl Future<Output = Result<Self>> {
        let (job, allow_funding) = match mode {
            SessionOpenMode::Any => (None, true),
            SessionOpenMode::Job(job) => (Some(Box::new(job.clone())), true),
            SessionOpenMode::Retained => (None, false),
        };
        Box::pin(Self::open_inner(
            args,
            endpoint,
            settlement_key,
            owner,
            OpenIntent {
                job,
                allow_funding,
                before_open: None,
            },
            None,
            funding,
        ))
    }

    /// `before_open` runs after selected-policy admission and application
    /// reservation, so a refusal there leaves no signature and no reservation
    /// behind. `connection_timeout` bounds reaching the provider only.
    pub(crate) async fn open_inner(
        args: PaidWorkOptions,
        endpoint: Endpoint,
        settlement_key: Secp256k1Signer,
        owner: Arc<ClientOwner>,
        mut intent: OpenIntent<'_>,
        connection_timeout: Option<Duration>,
        funding: SessionFundingOptions,
    ) -> Result<Self> {
        if let Some(job) = intent.job.as_deref() {
            job.validate_content().await?;
        }

        args.validate()?;
        let config = &args.config;
        if owner.chain().as_path() != config.chain.as_path() {
            return Err(PaidClientError::InvalidOptions(
                "funding owner belongs to another chain directory",
            ));
        }
        if owner.delegate() != settlement_key.party_key() {
            return Err(PaidClientError::InvalidOptions(
                "funding delegate differs from the settlement key",
            ));
        }
        let read_timeout = read_timeout(args.timeout);
        let journal_root = args.journal_root();
        journal_root
            .durability()
            .create_dir_all(&journal_root)
            .map_err(|source| PaidClientError::JournalDirectory {
                path: journal_root.clone().into_path_buf(),
                source,
            })?;
        // Retained journals can already depend on a height a fast validator
        // has not reached. Establish that floor before a source is chosen;
        // recovery reads below it would only be refused by the same guard.
        let setups =
            offer::RetainedSetups::discover(&journal_root, config.network(), args.provider).await?;
        let floor = setups.floor();
        let remote = crate::client_chain::connect_at(config, read_timeout, floor).await?;
        let chain = WorkBlocks::new(remote.clone()).with_min_height(floor);
        let retained = setups.select(&chain).await?;
        let reconnect = retained.is_some();
        let (mut store, signed) = match retained {
            Some(retained) => retained,
            None if !intent.allow_funding => {
                return Err(PaidClientError::NoRetainedChannel);
            }
            None => {
                let quote = within(
                    connection_timeout,
                    "paid provider connection",
                    request_paid_quote(&args, &endpoint, &settlement_key, owner.principal()),
                )
                .await?;
                funding.check_quote(quote.funding_value)?;
                if let Some(job) = intent.job.as_deref() {
                    job.check_policy(&quote.policy)?;
                }
                let signed = offer::fund_offer(
                    &args,
                    &endpoint,
                    &settlement_key,
                    &owner,
                    &remote,
                    quote,
                    crate::client_owner::FundingControls {
                        timeout: funding_timeout(args.timeout),
                        approval: funding.approval.as_deref(),
                        before_sign: intent.before_open.take(),
                    },
                )
                .await?;
                check_client_party(&signed.offer().proposal, owner.principal(), &settlement_key)?;
                let store = SetupStore::open(
                    &args.journal_root(),
                    config.network(),
                    signed.offer().proposal.bond_edge(),
                    Role::Client,
                    &Secp256k1Verifier::new(),
                )
                .await?;
                (store, signed)
            }
        };
        store.set_content_store(args.content.clone());
        signed.check()?;
        let payment_funding = signed.offer().payment_funding.clone();
        let policy = signed.offer().policy.clone();
        let omission_bond = signed.offer().omission_bond;
        offer::check_policy(&args, &policy, omission_bond)?;
        if let Some(job) = intent.job.as_deref() {
            job.check_policy(&policy)?;
        }
        check_client_party(&signed.offer().proposal, owner.principal(), &settlement_key)?;
        let bond = signed.offer().proposal.bond_edge();
        // Fresh and retained offers alike must name the addressed enrollment.
        let trust = args.trust()?;
        trust.verify_enrollment(&signed.offer().provider)?;
        if let Some(bind) = intent.before_open.take() {
            bind()?;
        }
        let dialer = Arc::new(ProviderDialer::new(
            args.provider.node,
            args.provider_addrs.clone(),
            endpoint,
            trust,
        ));
        let mut setup = SetupEndpoint::new(
            store,
            settlement_key.clone(),
            PaymentAdmission::Proposes(Box::new(policy.clone())),
        );
        if setup.state().revision().is_none() {
            setup
                .import_offer(*args.provider.node.as_bytes(), signed)
                .await?;
        }
        owner.claim(args.provider.node, &payment_funding).await?;
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
        // A retained gateway route must be reachable before it occupies the
        // request. Direct journal recovery/settlement can remain offline.
        if reconnect && let Some(timeout) = connection_timeout {
            within(Some(timeout), "paid provider connection", async {
                dialer.setup().await?;
                Ok(())
            })
            .await?;
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
            exchange_setup(&dialer, &mut setup, args.timeout).await?;
        }
        if setup.state().revision() != Some(3) {
            return Err(PaidClientError::MissingState(
                "countersigned setup revision",
            ));
        }

        let setup_service = SetupService::new(setup);
        let result = drive_setup(&setup_service, &policy, &chain).await;
        setup_service.close().await;
        let (mounted, descriptor) = result?;
        // A completed setup journal stops at the height that finished the
        // handshake, while the channel journal it mounted keeps advancing.
        // The source chosen for the setup floor can therefore be behind the
        // channel's own cursor by the time the channel is mounted. Reselect
        // at that cursor before the readiness read: a source below it is
        // refused by the journal's own height guard, and waiting for the
        // same fast source to catch up would never mount.
        // One unretried read: a source that cannot report its tip, or whose tip
        // regressed below state it already proved, is reselected like one that is
        // merely behind, rather than retried until the open deadline.
        let channel_floor = mounted.state().cursor().0;
        let tip = remote.get_latest_block().await;
        let (mut remote, chain) = if !matches!(&tip, Ok(Some(block)) if block.height >= channel_floor)
        {
            let remote =
                crate::client_chain::connect_at(config, read_timeout, channel_floor).await?;
            let chain = WorkBlocks::new(remote.clone()).with_min_height(channel_floor);
            (remote, chain)
        } else {
            (remote, chain.with_min_height(channel_floor))
        };
        let snapshot = settlement::channel_read(&chain, descriptor.channel()).await?;
        let ready = descriptor.check_ready(&snapshot.observed_channel()).ok();
        let initially_ready = ready.is_some();
        let mut endpoint = ClientEndpoint::recover(mounted, settlement_key)?;
        endpoint.observe(&snapshot.observed_channel()).await?;
        let client = ClientService::new(endpoint);
        if let Some(ready) = ready {
            // A first read that aged out while the journal mounted is not a
            // refusal: the initial observation below waits for a fresh one.
            match client.observer().observe_ready(ready).await {
                Ok(()) | Err(hellas_channel::work::EndpointError::ObservationStale) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if initially_ready {
            // Keep initial observation in the opening future. Cancellation must
            // release this journal before a caller can immediately reopen it.
            let mut source_config = config.clone();
            within(args.timeout, "initial channel observation", async {
                // Readiness changes only with a read of a newer block, so a
                // read that leaves the channel unready waits for one.
                let mut blocks = remote.finalized_blocks().await.ok();
                while client.readiness().await.is_err()
                    && !client.with_state(|state| state.is_closing()).await?
                {
                    let floor = client.with_state(|state| state.cursor().0).await?;
                    let step: Result<()> = match blocks.as_mut() {
                        Some(blocks) => async {
                            observe_client(&client.observer(), &descriptor, &remote, floor).await?;
                            if client.readiness().await.is_err() {
                                blocks.next().await?;
                            }
                            Ok(())
                        }.await,
                        None => Err(PaidClientError::MissingState("finalized block subscription")),
                    };
                    if let Err(error) = step {
                        client.observer().suspend().await?;
                        tracing::debug!(%error, "paid client observation unavailable");
                        source_config.chain.rotate_validators();
                        match crate::client_chain::connect_at(
                            &source_config, hellas_channel::work::MAX_CERTIFIED_AGE, floor,
                        ).await {
                            // A new source is read from its next block on, which also
                            // paces a source whose reads keep failing.
                            Ok(next) => {
                                blocks = next.finalized_blocks().await.ok();
                                if let Some(waiting) = blocks.as_mut()
                                    && waiting.next().await.is_err()
                                {
                                    blocks = None;
                                }
                                remote = next;
                            }
                            Err(error) => tracing::debug!(%error, "waiting for a verified remote chain source"),
                        }
                    }
                }
                Ok(())
            }).await?;
        }
        let observer = spawn_observer(
            client.observer(),
            descriptor.clone(),
            config.clone(),
            remote,
        );
        // No suspension between giving the observer ownership and returning it.
        Ok(Self {
            args,
            descriptor,
            policy,
            dialer,
            client,
            observer: Some(observer),
            needs_recovery: true,
        })
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
        if let Err(error) = self.client.close().await {
            tracing::warn!(%error, "paid client journal did not close cleanly");
        }
    }

    /// Identifies the funded channel and its admitted execution policy.
    pub fn descriptor(&self) -> &WorkChannelDescriptor {
        &self.descriptor
    }

    /// Finish an existing verified payment obligation only. This path never
    /// proposes work, uploads input, or invokes the provider's backend.
    pub(crate) async fn recover_verified_payment(
        &mut self,
        work: hellas_auth::Digest,
    ) -> Result<bool> {
        let payable = self
            .client
            .with_state(|state| {
                state.job_by_id(work).is_some_and(|job| {
                    job.phase() == hellas_channel::work_store::JobPhase::Verified
                        && job.result().is_some_and(|(result, _)| {
                            result.outcome == hellas_channel::model::work::ResultOutcome::Finished
                        })
                })
            })
            .await?;
        if !payable {
            return Ok(false);
        }
        pay_on(&self.dialer, &mut self.client, work).await?;
        Ok(true)
    }

    pub(crate) async fn recorded_terminal(
        &self,
        work: hellas_auth::Digest,
    ) -> Result<Option<bool>> {
        self.client
            .with_state(|state| {
                state.terminal_by_id(work).map(|terminal| {
                    matches!(
                        terminal.outcome,
                        hellas_channel::work_store::TerminalOutcome::Certified { .. }
                    )
                })
            })
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn propose_job(
        &mut self,
        job: &crate::job::Job,
        signer: &hellas_auth::ProducerSigningKey,
        proposed: &Arc<AtomicBool>,
    ) -> std::result::Result<PaidDelivery, crate::transact::TransactError> {
        let quoted = self.descriptor.payment_policy().fixed_price;
        if quoted != job.price() {
            return Err(crate::transact::TransactError::Price {
                quoted,
                requested: job.price(),
            });
        }
        let (_, prepared) = crate::transact::prepare(self, job, signer, false, None).await?;
        check_request(
            &self.policy,
            &prepared,
            &self.dialer.trust,
            hellas_auth::PublicKey::Secp256k1(self.descriptor.channel().client_key().to_bytes()),
        )?;
        let ready = fresh_readiness(&self.client, self.args.timeout).await?;
        self.needs_recovery = true;
        Ok(propose_paid_job(
            &self.args,
            prepared,
            &job.content(),
            &self.dialer,
            &mut self.client,
            &ready,
            JobLookup::New,
            Some(proposed),
        )
        .await?)
    }

    pub(crate) async fn pay(&mut self, mut result: PaidWorkResult) -> Result<PaidWorkResult> {
        result.credited_cumulative = pay_on(&self.dialer, &mut self.client, result.work_id).await?;
        Ok(result)
    }

    /// Reads local journal state under a short lock.
    pub async fn with_state<R>(
        &self,
        read: impl FnOnce(&hellas_channel::work_store::Channel) -> R,
    ) -> Result<R> {
        Ok(self.client.with_state(read).await?)
    }

    /// True after reopening a journal or an interrupted request.
    pub fn needs_recovery(&self) -> bool {
        self.needs_recovery
    }

    /// Runs a request and pays only after verifying its complete result.
    /// With `recover`, resume payable journaled work first and admit this as a new
    /// job; otherwise reuse a still-active job matching the input. `None` only
    /// performs recovery. Prefixes are authenticated before incremental delivery.
    pub async fn run(
        &mut self,
        prepared: Option<PreparedInvocation>,
        content: &(LocalStore, Scope),
        recover: bool,
        progress: Option<hellas_channel::work::PaidProgress>,
    ) -> Result<Option<PaidWorkResult>> {
        self.run_prepared(prepared, content, recover, progress, None, None, None)
            .await
    }

    /// Like `run`, also marking `proposed` before a proposal can leave the process,
    /// and reporting the provider's acceptance of `prepared` to `accepted`.
    /// A caller using cancellation must continue payment/recovery once it is set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_prepared(
        &mut self,
        prepared: Option<PreparedInvocation>,
        content: &(LocalStore, Scope),
        recover: bool,
        progress: Option<hellas_channel::work::PaidProgress>,
        accepted: Option<crate::transact::Accepted>,
        proposed: Option<&Arc<AtomicBool>>,
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
        if let Some(prepared) = prepared.as_ref() {
            check_request(
                policy,
                prepared,
                &dialer.trust,
                hellas_auth::PublicKey::Secp256k1(descriptor.channel().client_key().to_bytes()),
            )?;
        }
        // A fresh job still depends on the provider seeing the preceding
        // certificate. Repair its acknowledgement even without active-job replay.
        if *needs_recovery
            && let Some(work_id) = client
                .with_state(|state| state.last_payment().map(|payment| payment.work_id))
                .await?
        {
            // A lost acknowledgement never requires fresh admission: these
            // exact certificate bytes are already durable on the client.
            pay_on(dialer, client, work_id).await?;
        }
        if client.with_state(|state| state.is_closing()).await? {
            return if prepared.is_none() {
                Ok(None)
            } else {
                Err(hellas_channel::work::EndpointError::NotAdmitting.into())
            };
        }
        let ready = fresh_readiness(client, args.timeout).await?;
        if recover && *needs_recovery {
            enum RecoveredJob {
                /// The result was delivered, verified and committed before the
                /// restart; only its payment is outstanding, and settling it
                /// needs none of the payload a Fetch journal strips.
                Delivered(hellas_auth::Digest),
                Failed(hellas_auth::Digest, hellas_auth::Digest),
                /// No payload and no result: the job can neither execute nor
                /// settle. Its evidence is retained until the payment deadline
                /// filters it out, without blocking every later request.
                Unrecoverable(hellas_auth::Digest),
                Replay(
                    hellas_auth::Digest,
                    hellas_channel::work_store::JobPhase,
                    Box<PreparedInvocation>,
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
                            let failed = job.result().is_some_and(|(result, _)| {
                                result.outcome == hellas_channel::model::work::ResultOutcome::Failed
                            });
                            let payable = job.authorization().payment_deadline >= state.cursor().0;
                            if !payable && !failed {
                                tracing::info!(
                                    work_id = %hex::encode(job.work_id().as_bytes()),
                                    payment_deadline = job.authorization().payment_deadline,
                                    "retaining expired unpaid job without retrying execution",
                                );
                            }
                            failed || payable
                        })
                        .map(|job| job.work_id())
                        .collect::<Vec<_>>()
                })
                .await?;
            for work in pending {
                let recovered = {
                    let mut endpoint = client.client().await?;
                    let settled = endpoint.state().job_by_id(work).is_some_and(|job| {
                        job.phase() == hellas_channel::work_store::JobPhase::Verified
                            || job.result().is_some_and(|(result, _)| {
                                result.outcome == hellas_channel::model::work::ResultOutcome::Failed
                            })
                    });
                    if !settled {
                        endpoint.load_retained_input(work).await?;
                    }
                    let job = endpoint
                        .state()
                        .job_by_id(work)
                        .ok_or(PaidClientError::MissingState("recovered job"))?;
                    (|job: &hellas_channel::work_store::JobState| {
                        if let Some((result, _)) = job.result()
                            && result.outcome == hellas_channel::model::work::ResultOutcome::Failed
                        {
                            return Ok(RecoveredJob::Failed(
                                job.work_id(),
                                result.transcript_content.id().digest(),
                            ));
                        }
                        // Fetch journals retain accounting only. A restart cannot
                        // reconstruct a lost request or authorize another
                        // execution, but an already delivered result still
                        // settles: signing payment needs no payload.
                        if job.prepared_input().is_empty()
                            || job.phase() == hellas_channel::work_store::JobPhase::Verified
                        {
                            return Ok(
                                if job.phase() == hellas_channel::work_store::JobPhase::Verified {
                                    RecoveredJob::Delivered(job.work_id())
                                } else {
                                    RecoveredJob::Unrecoverable(job.work_id())
                                },
                            );
                        }
                        PreparedInvocation::from_canonical_bytes(
                            job.prepared_input(),
                            hellas_channel::content::MAX_CONTENT_BYTES,
                        )
                        .map(|input| {
                            RecoveredJob::Replay(job.work_id(), job.phase(), Box::new(input))
                        })
                        .map_err(PaidClientError::from)
                    })(job)?
                };
                let (work_id, phase, pending) = match recovered {
                    RecoveredJob::Failed(work_id, evidence) => {
                        client.client().await?.rejected(work_id, evidence).await?;
                        continue;
                    }
                    RecoveredJob::Delivered(work_id) => {
                        pay_on(dialer, client, work_id).await?;
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
                    RecoveredJob::Replay(work_id, phase, input) => (work_id, phase, *input),
                };
                // A retained half-signed job resumes from its own durable
                // closure. Missing content is unresolved, never an empty
                // program: uploading a fabricated root would sign for work
                // this process cannot produce.
                let retained_upload = phase == hellas_channel::work_store::JobPhase::HalfSigned
                    && client
                        .with_state(|state| {
                            state.job_by_id(work_id).is_some_and(|job| {
                                job.authorization().retention == hellas_rpc::Retention::Retain
                            })
                        })
                        .await?;
                let job_content = if retained_upload {
                    match client.client().await?.retained_content(work_id)? {
                        Some(content) => content,
                        None => {
                            tracing::warn!(
                                %work_id,
                                "retaining an unpaid job whose upload never completed; \
                                 it is unresolved rather than an empty program"
                            );
                            continue;
                        }
                    }
                } else {
                    content.clone()
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
                    &job_content,
                    dialer,
                    client,
                    &ready,
                    None,
                    None,
                    JobLookup::Retained(work_id),
                    None,
                    None,
                )
                .await;
                if let Err(error) = &result
                    && ((phase == hellas_channel::work_store::JobPhase::HalfSigned
                        && matches!(
                            error,
                            PaidClientError::Propose(hellas_channel::work::ProposeError::Refused {
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
                if !matches!(&result, Err(PaidClientError::InvocationFailed { .. })) {
                    result?;
                }
            }
        }
        // Keep recovery armed across any error or cancellation after acceptance.
        // A caller that declined recovery keeps the flag for a later run.
        if prepared.is_some() {
            *needs_recovery = true;
        }
        let result = match prepared {
            Some(prepared) => {
                let ready = fresh_readiness(client, args.timeout).await?;
                execute_paid_job(
                    args,
                    prepared,
                    content,
                    dialer,
                    client,
                    &ready,
                    progress.as_ref(),
                    accepted.as_ref(),
                    if recover {
                        JobLookup::New
                    } else {
                        JobLookup::PreparedInput
                    },
                    proposed,
                    purchase,
                )
                .await
                .map(Some)
            }
            None => Ok(None),
        };
        if (recover && result.is_ok())
            || matches!(
                &result,
                Ok(Some(_)) | Err(PaidClientError::InvocationFailed { .. })
            )
        {
            *needs_recovery = client
                .with_state(|state| {
                    state.jobs().any(|job| {
                        job.result().is_some_and(|(result, _)| {
                            result.outcome == hellas_channel::model::work::ResultOutcome::Failed
                        }) || (job.authorization().payment_deadline >= state.cursor().0
                            && (!job.prepared_input().is_empty()
                                || job.result().is_some()
                                || state.retained_roots().contains_key(&job.work_id())))
                    })
                })
                .await?;
        }
        result
    }
}

fn permanently_refused_delivery(error: &PaidClientError) -> bool {
    use hellas_channel::work::DeliverError;
    use hellas_client::work::CollectResultError;
    let delivery = match error {
        PaidClientError::Deliver(error)
        | PaidClientError::Collect(CollectResultError::Deliver(error)) => Some(error),
        _ => None,
    };
    matches!(delivery, Some(DeliverError::Refused { refusal, .. }) if !refusal.is_retryable())
}

/// One exchange; an ambiguous proposal or certificate is recovered when the
/// session next opens, before any new work is admitted.
async fn propose_on(
    dialer: &ProviderDialer,
    client: &mut ClientService,
    proposal: &JobProposal,
    content: &(LocalStore, Scope),
    retained: Option<hellas_auth::Digest>,
    proposed: Option<&Arc<AtomicBool>>,
) -> Result<hellas_auth::Digest> {
    let transport = dialer.work().await?;
    Ok(match retained {
        Some(work_id) => {
            if let Some(proposed) = proposed {
                proposed.store(true, Ordering::Release);
            }
            resume_work_proposal(transport, client, work_id, content).await?
        }
        None => propose_work(transport, client, proposal, content, proposed.cloned()).await?,
    })
}

async fn pay_on(
    dialer: &ProviderDialer,
    client: &mut ClientService,
    work_id: hellas_auth::Digest,
) -> Result<u64> {
    Ok(pay_for_result(dialer.work().await?, client, work_id).await?)
}

enum JobLookup {
    Retained(hellas_auth::Digest),
    PreparedInput,
    New,
}

#[allow(clippy::too_many_arguments)]
async fn execute_paid_job(
    args: &PaidWorkOptions,
    prepared: PreparedInvocation,
    content: &(LocalStore, Scope),
    dialer: &Arc<ProviderDialer>,
    client: &mut ClientService,
    ready: &hellas_channel::model::setup::ReadyChannel,
    progress: Option<&hellas_channel::work::PaidProgress>,
    accepted: Option<&crate::transact::Accepted>,
    lookup: JobLookup,
    proposed: Option<&Arc<AtomicBool>>,
    purchase: Option<&mut crate::transact::Purchase>,
) -> Result<PaidWorkResult> {
    let delivery = propose_paid_job(
        args, prepared, content, dialer, client, ready, lookup, proposed,
    )
    .await?;
    let mut purchase = purchase;
    let mut result = delivery
        .collect(progress, accepted, purchase.as_deref_mut())
        .await?;
    result.credited_cumulative = pay_on(dialer, client, result.work_id).await?;
    if let Some(purchase) = purchase {
        purchase.paid(result.work_id)?;
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn propose_paid_job(
    args: &PaidWorkOptions,
    prepared: PreparedInvocation,
    content: &(LocalStore, Scope),
    dialer: &Arc<ProviderDialer>,
    client: &mut ClientService,
    ready: &hellas_channel::model::setup::ReadyChannel,
    lookup: JobLookup,
    proposed: Option<&Arc<AtomicBool>>,
) -> Result<PaidDelivery> {
    let prepared_bytes = prepared.canonical_bytes()?;
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
                            && (job.phase() != hellas_channel::work_store::JobPhase::HalfSigned
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
    let (work_id, collected) = match existing.first().copied() {
        Some((work_id, hellas_channel::work_store::JobPhase::HalfSigned, _)) => (
            propose_on(dialer, client, &proposal, content, Some(work_id), proposed).await?,
            None,
        ),
        Some((work_id, hellas_channel::work_store::JobPhase::Ready, _))
        | Some((work_id, hellas_channel::work_store::JobPhase::Verified, _)) => {
            let mut endpoint = client.client().await?;
            endpoint
                .load_retained_transcript(work_id, &proposal.prepared_input)
                .await?;
            let retained = endpoint
                .state()
                .job_by_id(work_id)
                .filter(|job| !job.transcript().is_empty())
                .map(|job| job.transcript.to_vec());
            (work_id, retained)
        }
        Some((work_id, _, _)) => (work_id, None),
        None => (
            propose_on(dialer, client, &proposal, content, None, proposed).await?,
            None,
        ),
    };
    let acceptance_signature = client
        .with_state(|state| {
            state
                .job_by_id(work_id)
                .and_then(|job| job.provider_signature())
        })
        .await?
        .ok_or(PaidClientError::MissingState("accepted work signature"))?;
    Ok(PaidDelivery {
        client: client.clone(),
        dialer: dialer.clone(),
        ready: ready.clone(),
        prepared: proposal.prepared_input,
        work_id,
        acceptance_signature,
        collected,
    })
}

pub(crate) struct PaidDelivery {
    client: ClientService,
    dialer: Arc<ProviderDialer>,
    ready: hellas_channel::model::setup::ReadyChannel,
    prepared: PreparedInvocation,
    work_id: hellas_auth::Digest,
    acceptance_signature: hellas_kernel::Sig,
    collected: Option<Vec<u8>>,
}
impl PaidDelivery {
    pub(crate) async fn collect(
        self,
        progress: Option<&hellas_channel::work::PaidProgress>,
        accepted: Option<&crate::transact::Accepted>,
        purchase: Option<&mut crate::transact::Purchase>,
    ) -> Result<PaidWorkResult> {
        let Self {
            mut client,
            dialer,
            ready,
            prepared,
            work_id,
            acceptance_signature,
            collected,
        } = self;
        let client = &mut client;
        let ready = &ready;
        if let Some(accepted) = accepted {
            accepted(hellas_rpc::provenance::ExecutionProvenance {
                commitment_id: *work_id.as_bytes(),
                provider: hellas_auth::PublicKey::Secp256k1(
                    ready.channel().provider_key().to_bytes(),
                ),
            });
        }
        let transcript = if let Some(transcript) = collected {
            transcript
        } else {
            let delivery = hellas_channel::work::fetch_result_stream(
                dialer.work().await?,
                client,
                ready,
                work_id,
                |event| {
                    if let Some(progress) = progress {
                        progress(event.clone()).map_err(|error| {
                            hellas_channel::model::work::PaidWorkError::Transcript(
                                error.to_string(),
                            )
                        })?;
                    }
                    Ok(())
                },
            )
            .await?;
            check_payment_window(client, work_id).await?;
            delivery.transcript.to_vec()
        };
        let verified = verify_transcript(
            &prepared,
            ready.invocation_policy(),
            &hellas_auth::PublicKey::Secp256k1(ready.channel().client_key().to_bytes()),
            &hellas_auth::PublicKey::Secp256k1(ready.channel().provider_key().to_bytes()),
            &transcript,
        )?;
        let output = verified.output;
        if let hellas_rpc::protocol::invocation::output::Outcome::Failed(reason) = output.outcome {
            client
                .client()
                .await?
                .rejected(work_id, verified.transcript.id().digest())
                .await?;
            if let Some(purchase) = purchase {
                purchase.unpaid(work_id)?;
            }
            return Err(PaidClientError::InvocationFailed { work_id, reason });
        }
        client.client().await?.verified(work_id, &prepared).await?;
        Ok(PaidWorkResult {
            bond_edge: ready.channel().payment_terms().bond_edge,
            payment_edge: ready.channel().payment_edge(),
            channel_id: ready.channel().id(),
            work_id,
            acceptance_signature,
            job_price: ready.payment_policy().fixed_price,
            credited_cumulative: 0,
            transcript,
            output,
            provider_key: hellas_auth::PublicKey::Secp256k1(
                ready.channel().provider_key().to_bytes(),
            ),
            input: prepared.request.input_commitment()?,
        })
    }
}

fn verify_transcript(
    prepared: &PreparedInvocation,
    policy: &hellas_rpc::protocol::invocation::InvocationPolicy,
    caller: &hellas_auth::PublicKey,
    provider: &hellas_auth::PublicKey,
    transcript: &[u8],
) -> Result<hellas_rpc::protocol::invocation::VerifiedOutput> {
    let facts = policy.admit(prepared, caller)?;
    let events =
        hellas_channel::model::work::decode_transcript(transcript, facts.max_spool_bytes as usize)?;
    Ok(prepared.verify_output(policy, caller, provider, &events)?)
}

pub(crate) fn check_request(
    policy: &ProviderChannelPolicy,
    prepared: &PreparedInvocation,
    trust: &hellas_client::ProviderTrustAnchor,
    caller: hellas_auth::PublicKey,
) -> Result<()> {
    if trust.required_assurance != prepared.request.assurance {
        return Err(PaidClientError::InputMismatch(
            "assurance differs from provider trust",
        ));
    }
    policy.invocation_policy.admit(prepared, &caller)?;
    Ok(())
}

fn payment_terms(
    config: &WorkConfig,
    policy: &ProviderChannelPolicy,
    bundle: &hellas_channel::model::bundle::WorkChannelSetupBundleV2,
    omission_bond: u64,
) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bundle.bond_edge(),
        bond_terms: bundle.bond_terms().clone(),
        private_policy_commitment: private_policy_commitment(
            config.network(),
            &policy.policy_salt,
            &policy.channel_policy,
        ),
        start_validity_blocks: MAX_START_VALIDITY_BLOCKS,
        omission_bond,
    }
}

async fn drive_setup(
    setup: &SetupService,
    policy: &ProviderChannelPolicy,
    chain: &WorkBlocks<RemoteLightClient>,
) -> Result<(
    hellas_channel::work_store::ChannelStore,
    WorkChannelDescriptor,
)> {
    let mut blocks = chain.client().finalized_blocks().await?;
    loop {
        let query = setup
            .query()
            .await?
            .ok_or(PaidClientError::MissingState("setup names no payment edge"))?;
        let snapshot = chain
            .work_channel_snapshot(WorkChannelQuery {
                bond_edge: query.bond_edge,
                payment_edge: query.payment_edge,
                funding: query.funding.clone(),
            })
            .await?
            .ok_or(PaidClientError::MissingState(
                "no certified setup state is available",
            ))?;
        let read = snapshot
            .finalized_setup(&query)
            .ok_or(PaidClientError::MissingState(
                "setup read answers another query",
            ))?;
        let SetupAdvance { progress, mounted } = setup.advance_setup(&read, chain).await?;
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
            _ => blocks.next().await?,
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
    timeout: Option<Duration>,
) -> Result<()> {
    let request = prepare_setup_exchange(setup);
    within(timeout, "setup exchange", async {
        loop {
            let response = send_setup_exchange(dialer.setup().await?, request.clone()).await?;
            match apply_setup_exchange(setup, response).await {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "inventory class C: retryable setup refusal"
                )]
                Err(hellas_channel::work_handshake::SetupExchangeError::Refused {
                    refusal,
                    ..
                }) if refusal.is_retryable() => {
                    tokio::time::sleep(hellas_channel::work::SETUP_POLL).await;
                }
                result => return Ok(result?),
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests;
