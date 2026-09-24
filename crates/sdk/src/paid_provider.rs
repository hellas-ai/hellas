//! Shared provider routing and finalized-chain clock for paid work.
use crate::work_config::WorkRoutes;
use anyhow::Context;
use futures::future::BoxFuture;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::work_blocks::{PaidWorkClockError, advance_paid_work_clock};
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedWorkView, WorkBlocks, WorkChannelQuery,
};
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::work::*;
use hellas_rpc::peers::PeerId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidJobAuthorizationV1, PrivateRecord as _, work_id as accepted_work_id,
};
use hellas_rpc::protocol::work_setup::{
    ProviderChannelPolicy, ReadyChannel, WorkChannelDescriptor,
};
use hellas_rpc::services::work::WorkHandler;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_wire::{TransportContext, WireStatus};
use hellas_work::work::{
    CloseEndpoint, PaidWorkBackend, RunError, RunOutcome, WorkService, run_accepted_work,
};
use hellas_work::work_close::{CatchUpError, FinalizedBlocks, TxSink};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{SetupAdvance, SetupDriveError, SetupProgress, SetupView};
use hellas_work::work_store::{ChannelStore, JobPhase, Role, SetupStore, discover_setups};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tracing::{debug, info, warn};
pub type ProductionWorkSource = WorkBlocks<VerifiedRemoteLightClient>;
#[derive(Clone, Copy, Debug)]
pub struct UnmountedWork;

fn not_ready() -> WorkRefused {
    WorkRefused {
        code: WorkRefusalCode::NotReady as i32,
        reason: "work state is not mounted".to_string(),
    }
}

impl WorkSetupHandler for UnmountedWork {
    async fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<ExchangeSetupResponse>> + Send, WireStatus> {
        Ok(ExchangeSetupResponse {
            outcome: Some(exchange_setup_response::Outcome::Refused(not_ready())),
        })
    }
}

impl WorkHandler for UnmountedWork {
    async fn accept_work(
        &self,
        _request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        Ok(AcceptWorkResponse {
            outcome: Some(accept_work_response::Outcome::Refused(not_ready())),
        })
    }

    async fn deliver_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        Ok(DeliverResultResponse {
            outcome: Some(deliver_result_response::Outcome::Refused(not_ready())),
        })
    }

    async fn stream_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        Err(WireStatus::new(
            hellas_wire::WireCode::Unavailable,
            "paid work channel is not mounted",
        ))
    }

    async fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        Ok(AdmitCertificateResponse {
            outcome: Some(admit_certificate_response::Outcome::Refused(not_ready())),
        })
    }
}

/// Validated configuration for driving provider journals.
pub struct WorkRunnerConfig {
    /// The network the journals are keyed and the signatures bound to.
    pub network: NetworkId,
    /// The threshold identity finalized blocks must authenticate under.
    pub threshold_identity: Vec<u8>,
    /// The configured root the setup journals live under.
    pub journal_root: PathBuf,
    /// Bilateral routes from authenticated peers to owned journals.
    pub routes: WorkRoutes,
    /// The validator RPCs a read and a submission go to.
    pub validators: Vec<String>,
    /// How often the clock ticks.
    pub poll: Duration,
    /// The key every settlement this node signs is signed with.
    pub settlement_key: Secp256k1Signer,
    /// What every setup endpoint this node builds countersigns over.
    pub policy: ProviderChannelPolicy,
}

/// Channels indexed by authenticated peer. Handlers share the runner's state;
/// mount locks are released before processing requests.
#[derive(Clone)]
pub struct MountedWork<S> {
    mounted: Arc<Mutex<BTreeMap<PeerId, Vec<MountedWorkService<S>>>>>,
    driver: Option<AcceptedWorkDriver>,
}

impl<S> Default for MountedWork<S> {
    fn default() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            driver: None,
        }
    }
}

/// Type-erased runner for an accepted job.
type RunAcceptedWork = dyn Fn(WorkService, ReadyChannel, Digest) -> BoxFuture<'static, Result<RunOutcome, RunError>>
    + Send
    + Sync;

#[derive(Clone)]
struct AcceptedWorkDriver(Arc<RunAcceptedWork>);

impl AcceptedWorkDriver {
    fn new<B>(backend: B) -> Self
    where
        B: PaidWorkBackend + Send + Sync + 'static,
    {
        let backend = Arc::new(backend);
        Self(Arc::new(move |service, ready, work_id| {
            let backend = Arc::clone(&backend);
            Box::pin(
                async move { run_accepted_work(&service, &ready, backend.as_ref(), work_id).await },
            )
        }))
    }

    /// Starts one accepted job without lending its lifetime to either the
    /// request path or the close clock.
    fn spawn(&self, service: WorkService, ready: ReadyChannel, work_id: Digest) {
        let running = (self.0)(service, ready, work_id);
        let span = hellas_rpc::request_span!(target: "hellas_request", "paid.provider.execute", hellas.work.id = ?work_id, otel.status_code = tracing::field::Empty);
        tokio::spawn(tracing::Instrument::instrument(
            async move {
                match running.await {
                    Ok(RunOutcome::Completed { .. }) => {
                        debug!(?work_id, "the accepted paid job completed")
                    }
                    Ok(RunOutcome::Ready { .. }) => {
                        debug!(?work_id, "the accepted paid job was already complete")
                    }
                    Ok(RunOutcome::Running) => {
                        debug!(?work_id, "the accepted paid job was already running")
                    }
                    Ok(RunOutcome::Indeterminate) => {
                        warn!(
                            ?work_id,
                            "the accepted paid job is indeterminate after restart"
                        )
                    }
                    // `run_accepted_work` has already made backend and
                    // transcript faults terminal before returning them. The
                    // remaining errors have no node-local terminal policy;
                    // keep the exact failure visible to the operator.
                    Err(error) => {
                        tracing::Span::current().record("otel.status_code", "ERROR");
                        warn!(?work_id, %error, "the accepted paid job did not complete");
                    }
                }
            },
            span,
        ));
    }
}

/// One channel's handler. The runner replaces `source` when it redials a validator.
/// `accepting` serializes each fresh readiness read through signing to prevent
/// concurrent requests from consuming the same credit.
#[derive(Clone)]
pub struct MountedWorkService<S> {
    bond_edge: EdgeId,
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    source: Arc<Mutex<S>>,
    accepting: Arc<AsyncMutex<()>>,
    driver: Option<AcceptedWorkDriver>,
}

impl<S> MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    /// Refreshes admission and checks the cursor using one coherent finalized read.
    /// Any failure leaves admission disabled until a later successful refresh.
    pub async fn refresh_admission(&self) -> anyhow::Result<ReadyChannel> {
        // Drop the source lock before awaiting the chain read.
        let source = {
            let held = self
                .source
                .lock()
                .map_err(|_| anyhow::anyhow!("the finalized source lock is poisoned"))?;
            held.clone()
        };
        refresh_work_admission(&self.service, self.descriptor.as_ref(), &source).await
    }

    async fn refresh_delivery(&self, request: &DeliverResultRequest) -> anyhow::Result<()> {
        let Ok(bytes) = request.work_id.as_slice().try_into() else {
            return Ok(());
        };
        let work_id = Digest::from_bytes(bytes);
        let active = self
            .service
            .with_state(|state| state.job_by_id(work_id).is_some());
        if !matches!(active, Ok(true)) {
            return Ok(());
        }
        // A restarted mount has no readiness cached. A retained result must
        // be collectable without first accepting another job. Terminal replies
        // need no fresh admission and are authenticated by the core service.
        let _accepting = self.accepting.lock().await;
        let result = self.refresh_admission().await;
        if let Err(error) = &result {
            debug!(%error, "a delivery attempt found no fresh channel readiness");
        }
        result.map(|_| ())
    }
}

/// Shared readiness check for live requests and restart recovery.
/// Both paths use a fresh finalized snapshot.
async fn refresh_work_admission<S>(
    service: &WorkService,
    descriptor: Option<&WorkChannelDescriptor>,
    source: &S,
) -> anyhow::Result<ReadyChannel>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    let Some(descriptor) = descriptor else {
        anyhow::bail!("this channel has no admission descriptor");
    };
    let query = WorkChannelQuery {
        bond_edge: descriptor.bond_edge(),
        payment_edge: descriptor.channel().payment_edge(),
        funding: Default::default(),
    };
    let Some(snapshot) = source
        .work_channel_snapshot(query.clone())
        .await
        .context("the fresh coherent channel read failed")?
    else {
        anyhow::bail!("no finalized channel snapshot is available");
    };
    if snapshot.query() != &query {
        anyhow::bail!("the finalized source answered for another channel");
    }
    let ready = descriptor
        .check_ready(&snapshot.observed_channel())
        .context("the fresh channel snapshot is not ready")?;
    // Keep one snapshot as the target. Recovery runs on the clock itself,
    // so waiting for another tick here would prevent the cursor advancing.
    // Take the service's existing driver when available; a concurrent clock
    // drive keeps that authority until it finishes its own catch-up.
    for _ in 0..16 {
        let cursor = service
            .with_state(|state| state.cursor().0)
            .context("the mounted channel cursor is unavailable")?;
        if ready.check_caught_up(cursor).is_ok() {
            break;
        }
        if let Ok(mut driver) = service.drive() {
            driver
                .catch_up(source)
                .await
                .context("the mounted channel could not catch up to the fresh snapshot")?;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let cursor = service
        .with_state(|state| state.cursor().0)
        .context("the mounted channel cursor is unavailable")?;
    ready
        .check_caught_up(cursor)
        .context("the mounted channel has not caught up to the fresh snapshot")?;
    service
        .admit_new_work(ready.clone())
        .context("the driven work service refused its fresh readiness")?;
    Ok(ready)
}

impl<S> WorkHandler for MountedWorkService<S>
where
    S: FinalizedBlocks + FinalizedWorkView + Sync,
{
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        if let Some(response) = self.service.precheck_acceptance(&request) {
            return Ok(response);
        }
        let _accepting = self.accepting.lock().await;
        // A preceding request or the clock may have resolved this proposal
        // while admission was serialized. Retained replies need no fresh read.
        if let Some(response) = self.service.precheck_acceptance(&request) {
            return Ok(response);
        }
        let ready = match self.refresh_admission().await {
            Ok(ready) => ready,
            Err(error) => {
                debug!(%error, "an acceptance attempt found no fresh channel readiness");
                return Ok(AcceptWorkResponse {
                    outcome: Some(accept_work_response::Outcome::Refused(WorkRefused {
                        code: WorkRefusalCode::NotReady as i32,
                        reason: "fresh channel readiness is unavailable".to_string(),
                    })),
                });
            }
        };
        // Derive the id from the request while the accepted response
        // is still only a possibility. The response carries only the
        // provider signature, and consulting `state.jobs().next()` after it
        // leaves would race the clock terminalizing that same job.
        let work_id = self
            .service
            .with_state(|state| {
                PaidJobAuthorizationV1::decode(&request.authorization)
                    .ok()
                    .map(|authorization| accepted_work_id(state.channel(), &authorization))
            })
            .ok()
            .flatten();
        let response = self.service.accept(&request);
        if matches!(
            response.outcome.as_ref(),
            Some(accept_work_response::Outcome::Accepted(_))
        ) {
            match (self.driver.as_ref(), work_id) {
                (Some(driver), Some(work_id)) => {
                    driver.spawn(self.service.clone(), ready, work_id);
                }
                (None, Some(work_id)) => {
                    warn!(?work_id, "accepted paid work has no execution backend")
                }
                (_, None) => warn!("accepted paid work has no mounted job to execute"),
            }
        }
        Ok(response)
    }

    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        let response: WithTrailer<DeliverResultResponse> =
            if self.refresh_delivery(&request).await.is_ok() {
                self.service.deliver_result(request, context).await?.into()
            } else {
                DeliverResultResponse {
                    outcome: Some(deliver_result_response::Outcome::Refused(WorkRefused {
                        code: WorkRefusalCode::NotReady as i32,
                        reason: "fresh channel readiness is unavailable".to_string(),
                    })),
                }
                .into()
            };
        Ok(response)
    }

    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        self.refresh_delivery(&request).await.map_err(|_| {
            WireStatus::new(
                hellas_wire::WireCode::Unavailable,
                "fresh channel readiness is unavailable",
            )
        })?;
        let mounted = self.clone();
        let mut stream = self.service.stream_result(request.clone(), context).await?;
        Ok(Box::pin(async_stream::try_stream! {
            let mut refresh = tokio::time::interval(Duration::from_secs(1));
            loop {
                let event = tokio::select! {
                    event = futures::StreamExt::next(&mut stream) => Some(event),
                    _ = refresh.tick() => None,
                };
                // Even buffered prefixes need a fresh finalized decision before
                // leaving the node; a contest can start after this stream opens.
                mounted.refresh_delivery(&request).await.map_err(|_| WireStatus::new(
                    hellas_wire::WireCode::Unavailable,
                    "fresh channel readiness is unavailable",
                ))?;
                if let Some(event) = event {
                    match event {
                        Some(event) => yield event?,
                        None => break,
                    }
                }
            }
        }))
    }

    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        self.service.admit_certificate(request, context).await
    }
}

impl<S: Clone> MountedWork<S> {
    pub fn with_backend<B>(backend: B) -> Self
    where
        B: PaidWorkBackend + Send + Sync + 'static,
    {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            driver: Some(AcceptedWorkDriver::new(backend)),
        }
    }

    /// Mounts a channel for a peer. Multiple candidates disable routing for that peer.
    pub fn mount(
        &self,
        peer: PeerId,
        bond_edge: EdgeId,
        service: &WorkService,
        descriptor: Option<WorkChannelDescriptor>,
        accepting: Arc<AsyncMutex<()>>,
        source: &S,
    ) -> bool {
        match self.mounted.lock() {
            Ok(mut held) => {
                let mounted = held.entry(peer).or_default();
                mounted.push(MountedWorkService {
                    bond_edge,
                    service: service.clone(),
                    descriptor,
                    source: Arc::new(Mutex::new(source.clone())),
                    accepting,
                    driver: self.driver.clone(),
                });
                mounted.len() == 1
            }
            Err(_) => false,
        }
    }

    /// The one handler mounted for the transport-vouched peer.
    pub fn handler(&self, context: &TransportContext) -> Option<MountedWorkService<S>> {
        let peer = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))?;
        self.mounted.lock().ok().and_then(|held| {
            let [mounted] = held.get(&peer)?.as_slice() else {
                return None;
            };
            Some(mounted.clone())
        })
    }

    /// Returns the local service for journal inspection and recovery.
    /// Remote requests must use `handler`, which refreshes finalized readiness.
    pub fn service(&self, context: &TransportContext) -> Option<WorkService> {
        self.handler(context).map(|mounted| mounted.service)
    }

    /// Updates the shared source, including handlers held by live connections.
    fn refresh_source(&self, peer: PeerId, bond_edge: EdgeId, source: &S) {
        let source_slot = self.mounted.lock().ok().and_then(|held| {
            held.get(&peer)?
                .iter()
                .find(|mounted| mounted.bond_edge == bond_edge)
                .map(|mounted| Arc::clone(&mounted.source))
        });
        if let Some(source_slot) = source_slot
            && let Ok(mut held) = source_slot.lock()
        {
            *held = source.clone();
        }
    }

    /// Unmounts all channels when the clock stops, releasing its journal handles.
    pub fn clear_all(&self) {
        if let Ok(mut held) = self.mounted.lock() {
            held.clear();
        }
    }
}

/// Setups indexed by authenticated peer. Serving and driving share each journal.
#[derive(Clone, Debug, Default)]
pub struct MountedSetup(Arc<Mutex<BTreeMap<PeerId, Vec<MountedSetupService>>>>);

#[derive(Clone, Debug)]
struct MountedSetupService {
    bond_edge: EdgeId,
    service: SetupService,
}

impl MountedSetup {
    /// Adds one owned setup under its authenticated peer.
    pub fn mount(&self, peer: PeerId, bond_edge: EdgeId, service: &SetupService) -> bool {
        match self.0.lock() {
            Ok(mut held) => {
                let mounted = held.entry(peer).or_default();
                mounted.push(MountedSetupService {
                    bond_edge,
                    service: service.clone(),
                });
                mounted.len() == 1
            }
            Err(_) => false,
        }
    }

    /// The exact setup service mounted for the transport-vouched peer,
    /// cloned without holding the map across dispatch.
    pub fn service(&self, context: &TransportContext) -> Option<SetupService> {
        let peer = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))?;
        self.0.lock().ok().and_then(|held| {
            let [mounted] = held.get(&peer)?.as_slice() else {
                return None;
            };
            Some(mounted.service.clone())
        })
    }

    /// Stops serving only the setup that made this transition.
    fn clear(&self, peer: PeerId, bond_edge: EdgeId) {
        if let Ok(mut held) = self.0.lock()
            && let Some(mounted) = held.get_mut(&peer)
        {
            mounted.retain(|mounted| mounted.bond_edge != bond_edge);
            if mounted.is_empty() {
                held.remove(&peer);
            }
        }
    }

    /// Stops serving every setup during runner shutdown.
    pub fn clear_all(&self) {
        if let Ok(mut held) = self.0.lock() {
            held.clear();
        }
    }
}

/// A journal transitions from setup to channel when `advance_setup` returns its
/// mounted store. The store is transferred without reopening its exclusive file.
enum Driven {
    /// The journal is driven behind the setup service that answers for
    /// it. The policy is retained beside the service: it is the provider
    /// authority from which the full channel descriptor is rebuilt after
    /// the setup reveals its actual terms.
    Setup {
        /// The endpoint this journal is both driven and served behind.
        service: SetupService,
        /// Boxed to keep the other enum variants small.
        policy: Box<ProviderChannelPolicy>,
    },
    /// The channel this setup mounted, including the recovery authority
    /// needed to finish a job accepted before a process restart.
    Channel(Box<DrivenChannel>),
    /// The setup ended, or its mount was refused. Nothing left to
    /// drive.
    Done,
}

/// A driven channel recovers accepted jobs even without a peer route.
/// Live acceptance and recovery share the same admission lock.
struct DrivenChannel {
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    accepting: Arc<AsyncMutex<()>>,
    driver: Option<AcceptedWorkDriver>,
}

impl DrivenChannel {
    fn accepted_work_id(&self) -> anyhow::Result<Option<Digest>> {
        self.service
            .with_state(|state| {
                let mut jobs = state.jobs();
                let job = jobs.next()?;
                (jobs.next().is_none() && job.phase() == JobPhase::Accepted).then(|| job.work_id())
            })
            .context("the driven channel state is unavailable")
    }

    /// Resumes accepted work after a fresh readiness check. The durable `JobRunning`
    /// record admits one invocation even when a live request races this clock tick.
    async fn resume_accepted<S>(&self, source: &S) -> anyhow::Result<bool>
    where
        S: FinalizedBlocks + FinalizedWorkView + Sync,
    {
        if self.accepted_work_id()?.is_none() {
            return Ok(false);
        }
        let _accepting = self.accepting.lock().await;
        let Some(work_id) = self.accepted_work_id()? else {
            return Ok(false);
        };
        let driver = self
            .driver
            .as_ref()
            .context("the accepted paid job has no execution backend")?;
        let ready = refresh_work_admission(&self.service, self.descriptor.as_ref(), source).await?;
        driver.spawn(self.service.clone(), ready, work_id);
        Ok(true)
    }
}

/// One setup journal on a clock.
struct SetupClock {
    /// The bond this journal stakes, so a log line names which one.
    bond_edge: EdgeId,
    /// The authenticated peer whose configured route names this bond.
    /// Together with `bond_edge`, this is the journal's route identity;
    /// `None` keeps an unconfigured owned journal on its close clock
    /// without making it a fallback service.
    route_peer: Option<PeerId>,
    /// What is being driven for it.
    driven: Driven,
}

impl SetupClock {
    /// Advances the journal; returns false on a source failure so the caller redials.
    async fn tick<S>(
        &mut self,
        source: &S,
        signer: &Secp256k1Signer,
        work_mount: &MountedWork<S>,
        setup_mount: &MountedSetup,
    ) -> bool
    where
        S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
    {
        let bond = hex::encode(self.bond_edge.to_bytes());
        let mut answered = true;
        // One step of the setup this journal holds, with the policy the
        // mount it may hand back is rebuilt from; nothing, once the
        // journal is past its setup.
        let step = match &mut self.driven {
            Driven::Setup { service, policy } => Some((
                service.advance_setup(source, source, source).await,
                policy.clone(),
            )),
            Driven::Channel(_) | Driven::Done => None,
        };
        if let Some((step, policy)) = step {
            match step {
                Ok(SetupAdvance { progress, mounted }) => {
                    if let Some(store) = mounted {
                        if let Some(peer) = self.route_peer {
                            setup_mount.clear(peer, self.bond_edge);
                        }
                        self.take_mount(store, signer, &policy, source, work_mount);
                    } else if matches!(
                        progress,
                        SetupProgress::Aborted(_) | SetupProgress::Faulted(_)
                    ) {
                        warn!(bond, ?progress, "this setup ended with no channel to drive");
                        self.driven = Driven::Done;
                    } else {
                        debug!(bond, ?progress, "the setup advanced");
                    }
                }
                Err(error) => {
                    answered = !matches!(error, SetupDriveError::Source(_));
                    warn!(bond, %error, "this setup did not advance");
                }
            }
        }
        if let Driven::Channel(channel) = &self.driven {
            if let Some(peer) = self.route_peer {
                work_mount.refresh_source(peer, self.bond_edge, source);
            }
            if let Err(error) = channel.resume_accepted(source).await {
                warn!(bond, %error, "an accepted paid job did not resume");
            }
            match advance_paid_work_clock(&channel.service, source).await {
                Ok(progress) => debug!(bond, ?progress, "the channel advanced"),
                // `resume_accepted` owns the channel while it starts the
                // durable execution. The clock's concurrent close pass has
                // no work to do until that owner returns the cursor.
                Err(PaidWorkClockError::CloseDrive(CatchUpError::Busy)) => {
                    debug!(bond, "the channel is already being driven")
                }
                Err(error) => {
                    answered &= !error.source_failed();
                    warn!(bond, %error, "this channel's close did not advance");
                }
            }
        }
        answered
    }

    /// Transfers the mounted store returned by setup, preserving its exclusive lock.
    fn take_mount<S: Clone>(
        &mut self,
        store: ChannelStore,
        signer: &Secp256k1Signer,
        policy: &ProviderChannelPolicy,
        source: &S,
        mount: &MountedWork<S>,
    ) {
        let bond = hex::encode(self.bond_edge.to_bytes());
        // Rebuild the descriptor from the retained policy and signed payment terms.
        let descriptor = {
            let channel = store.state().channel();
            match policy.admit(channel.payment_edge(), channel.payment_terms().clone()) {
                Ok(descriptor) => Some(descriptor),
                Err(error) => {
                    warn!(bond, %error, "the mounted channel no longer satisfies its admission policy");
                    None
                }
            }
        };
        match CloseEndpoint::new(store, signer.clone()) {
            Ok(close) => {
                let service = WorkService::close_only(close);
                let accepting = Arc::new(AsyncMutex::new(()));
                if self.route_peer.is_some_and(|peer| {
                    mount.mount(
                        peer,
                        self.bond_edge,
                        &service,
                        descriptor.clone(),
                        Arc::clone(&accepting),
                        source,
                    )
                }) {
                    info!(
                        bond,
                        "this node now answers Work from the channel it mounted"
                    );
                } else {
                    warn!(
                        bond,
                        "this channel has no unique peer route; it is driven and not served",
                    );
                }
                self.driven = Driven::Channel(Box::new(DrivenChannel {
                    service,
                    descriptor,
                    accepting,
                    driver: mount.driver.clone(),
                }));
            }
            // The journal and the key are not both the provider's view
            // of one channel. Nothing this runner can do about it, and
            // dropping the mount is what stops it being reopened every
            // tick.
            Err(error) => {
                warn!(bond, %error, "the mounted channel is not this node's to close");
                self.driven = Driven::Done;
            }
        }
    }
}

/// The clock, over every paid-work journal this node owns.
pub struct WorkRunner<S> {
    clocks: Vec<SetupClock>,
    signer: Secp256k1Signer,
    work_mount: MountedWork<S>,
    setup_mount: MountedSetup,
    poll: Duration,
    validators: Vec<String>,
    consensus_verifier: ConsensusVerifier,
}

impl<S> WorkRunner<S> {
    pub fn journal_count(&self) -> usize {
        self.clocks.len()
    }
    pub fn channel_count(&self) -> usize {
        self.clocks
            .iter()
            .filter(|c| matches!(c.driven, Driven::Channel(_)))
            .count()
    }
}

impl<S> WorkRunner<S>
where
    S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
{
    /// Discovers provider journals and mounts configured routes. Unrouted journals
    /// are still driven through close. Unreadable journals are logged; failure to
    /// enumerate the root is returned to the caller.
    pub fn discover(
        config: WorkRunnerConfig,
        work_mount: MountedWork<S>,
        setup_mount: MountedSetup,
    ) -> anyhow::Result<Self> {
        let consensus_verifier = ConsensusVerifier::new(&ConsensusInfo {
            validators: config.validators.clone(),
            threshold_identity: config.threshold_identity,
            network_id: config.network.as_str().to_owned(),
        })
        .context("the configured threshold identity is not usable")?;
        let settlement_verifier = Secp256k1Verifier::new();
        let found = discover_setups(&config.journal_root, config.network).with_context(|| {
            format!(
                "failed to enumerate the work journals under {}",
                config.journal_root.display(),
            )
        })?;
        for unnamed in &found.unidentified {
            warn!(
                path = %unnamed.path.display(),
                reason = %unnamed.reason,
                "a setup journal under the work root could not be named",
            );
        }
        let mut clocks = Vec::with_capacity(found.setups.len());
        for setup in found.setups {
            let bond = hex::encode(setup.bond_edge.to_bytes());
            let route_peer = config
                .routes
                .iter()
                .find(|route| route.bond == setup.bond_edge)
                .map(|route| route.peer);
            // A close capability binds the provider half, and this
            // process holds the provider's key. A client journal beside
            // this node's own is another party's, and this runner has
            // nothing to sign for it.
            if setup.role != Role::Provider {
                warn!(
                    bond,
                    "a setup journal under the work root is not this node's half"
                );
                continue;
            }
            let store = match SetupStore::open(
                &config.journal_root,
                config.network,
                setup.bond_edge,
                setup.role,
                &settlement_verifier,
            ) {
                Ok(store) => store,
                Err(error) => {
                    warn!(bond, %error, "a discovered setup journal did not open");
                    continue;
                }
            };
            let policy = Box::new(config.policy.clone());
            let service = SetupService::new(SetupEndpoint::new(
                store,
                config.settlement_key.clone(),
                PaymentAdmission::Admits(policy.clone()),
            ));
            if let Some(peer) = route_peer {
                if setup_mount.mount(peer, setup.bond_edge, &service) {
                    info!(
                        bond,
                        "this node now answers WorkSetup from its driven setup"
                    );
                } else {
                    warn!(bond, "this provider setup has an ambiguous peer route");
                }
            } else {
                warn!(bond, "this provider setup has no configured peer route");
            }
            let driven = Driven::Setup { service, policy };
            clocks.push(SetupClock {
                bond_edge: setup.bond_edge,
                route_peer,
                driven,
            });
        }
        Ok(Self {
            clocks,
            signer: config.settlement_key,
            work_mount,
            setup_mount,
            poll: config.poll,
            validators: config.validators,
            consensus_verifier,
        })
    }

    /// Takes one step of every journal, and says whether the chain
    /// answered all of them.
    pub async fn tick(&mut self, source: &S) -> bool {
        let mut answered = true;
        for clock in &mut self.clocks {
            answered &= clock
                .tick(source, &self.signer, &self.work_mount, &self.setup_mount)
                .await;
        }
        answered
    }

    /// Ticks each journal once per period and redials after a source failure.
    pub async fn run_over<D, F>(mut self, mut stop: oneshot::Receiver<()>, dial: D)
    where
        D: Fn() -> F,
        F: core::future::Future<Output = Option<S>>,
    {
        if self.clocks.is_empty() {
            info!("no provider setup journal under the work root; the clock has nothing to drive");
            self.work_mount.clear_all();
            self.setup_mount.clear_all();
            return;
        }
        let mut chain = None;
        loop {
            tokio::select! {
                _ = &mut stop => break,
                () = tokio::time::sleep(self.poll) => {}
            }
            let Some(source) = chain.take() else {
                chain = dial().await;
                continue;
            };
            if self.tick(&source).await {
                chain = Some(source);
            }
        }
        self.work_mount.clear_all();
        self.setup_mount.clear_all();
        info!("the paid-work clock stopped, and its journals are closed");
    }
}

impl WorkRunner<ProductionWorkSource> {
    /// Ticks until told to stop, over the validators the configuration
    /// names.
    pub async fn run(self, stop: oneshot::Receiver<()>) {
        let validators = self.validators.clone();
        let verifier = self.consensus_verifier.clone();
        self.run_over(stop, move || {
            let validators = validators.clone();
            let verifier = verifier.clone();
            async move { connect_chain(&validators, verifier).await }
        })
        .await;
    }
}

/// Rotates the first candidate on reconnect. Chain reads and submissions use
/// the selected verified connection.
async fn connect_chain(
    validators: &[String],
    verifier: ConsensusVerifier,
) -> Option<ProductionWorkSource> {
    static NEXT_VALIDATOR: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let start =
        NEXT_VALIDATOR.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % validators.len();
    for url in validators.iter().cycle().skip(start).take(validators.len()) {
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => {
                info!(validator = %url, "the paid-work clock reads and submits here");
                return Some(WorkBlocks::new(client));
            }
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    None
}
