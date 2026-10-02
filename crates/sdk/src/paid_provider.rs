//! Shared provider routing and finalized-chain clock for paid work.
use crate::work_config::WorkRoutes;
use crate::work_router::{UnmountedWork, not_ready};
use futures::future::BoxFuture;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::work_blocks::advance_paid_work_clock;
use hellas_chain::{
    ConsensusInfo, ConsensusVerifier, FinalizedWorkView, WorkBlocks, WorkChannelQuery,
};
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    FundingKind, GetStandingRequest, GetStandingResponse, WorkRefusalCode, WorkRefused, WorkRoute,
    accept_work_response, get_standing_response,
};
use hellas_rpc::peers::PeerId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{
    PaidJobAuthorizationV2, PrivateRecord as _, work_id as accepted_work_id,
};
use hellas_rpc::protocol::work_setup::{
    ProviderChannelPolicy, ReadyChannel, WorkChannelDescriptor,
};
use hellas_rpc::services::work::WorkHandler;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_wire::{TransportContext, WireStatus};
use hellas_work::work::{
    CloseEndpoint, RunError, RunOutcome, WorkBackend, WorkService, run_accepted_work,
};
use hellas_work::work_close::{FinalizedBlocks, TxSink};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{SetupAdvance, SetupDriveError, SetupProgress, SetupView};
use hellas_work::work_store::{ChannelStore, JobPhase, Role, SetupStore, discover_setups};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
use tracing::{Instrument as _, debug, info, warn};
/// Provider observation and recovery failures preserve their typed causes.
#[derive(Debug, thiserror::Error)]
pub enum PaidProviderError {
    #[error("paid-work observer task failed")]
    Task(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Mount(#[from] MountError),
    #[error("channel has no admission descriptor")]
    NoDescriptor,
    #[error("no finalized channel snapshot is available")]
    NoSnapshot,
    #[error("finalized snapshot names another channel")]
    WrongSnapshot,
    #[error("accepted work has no execution backend")]
    NoBackend,
    #[error("observer age must exceed a positive polling interval")]
    InvalidObservationPolicy,
    #[error("the paid-work clock requires at least one validator")]
    NoValidators,
    #[error("validator has no finalized block 1 for genesis authentication")]
    MissingGenesis,
    #[error("validator genesis does not match the configured payload digest")]
    GenesisMismatch,
    #[error(transparent)]
    BlockSource(#[from] hellas_work::work_close::BlockSourceError),
    #[error(transparent)]
    Endpoint(#[from] hellas_work::work::EndpointError),
    #[error(transparent)]
    Setup(#[from] hellas_rpc::protocol::work_setup::WorkSetupError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    CatchUp(#[from] hellas_work::work_close::CatchUpError),
    #[error(transparent)]
    Consensus(#[from] hellas_chain::ConsensusVerificationError),
    #[error("cannot discover work journals under {}: {source}", path.display())]
    Discover {
        path: PathBuf,
        source: hellas_work::work_store::WorkStoreError,
    },
}

pub type ProductionWorkSource = WorkBlocks<VerifiedRemoteLightClient>;
/// Validated configuration for driving provider journals.
pub struct WorkRunnerConfig {
    /// The network the journals are keyed and the signatures bound to.
    pub network: NetworkId,
    /// The parent payload digest authenticated by finalized block 1.
    pub genesis_payload_digest: Digest,
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
    /// Bounds observer stalls and the age of local admission evidence.
    pub max_observation_age: Duration,
    /// The key every settlement this node signs is signed with.
    pub settlement_key: Secp256k1Signer,
    /// What every setup endpoint this node builds countersigns over.
    pub policy: ProviderChannelPolicy,
}

impl WorkRunnerConfig {
    /// Validate observation policy and chain identity before startup performs I/O.
    pub fn validate(&self) -> Result<(), PaidProviderError> {
        self.consensus_verifier().map(|_| ())
    }

    fn consensus_verifier(&self) -> Result<ConsensusVerifier, PaidProviderError> {
        if self.poll.is_zero() || self.max_observation_age <= self.poll {
            return Err(PaidProviderError::InvalidObservationPolicy);
        }
        if self.validators.is_empty() {
            return Err(PaidProviderError::NoValidators);
        }
        let consensus_verifier = ConsensusVerifier::new(&ConsensusInfo {
            validators: self.validators.clone(),
            threshold_identity: self.threshold_identity.clone(),
            network_id: self.network.as_str().to_owned(),
        })?;
        Ok(consensus_verifier)
    }
}

/// Owns the observer through graceful shutdown, including cancellation of the caller.
pub struct WorkWatcher {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), MountError>>,
}
impl WorkWatcher {
    pub fn spawn(runner: WorkRunner) -> Self {
        let (stop, stopped) = oneshot::channel();
        Self {
            stop: Some(stop),
            task: tokio::spawn(runner.run(stopped)),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), PaidProviderError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        (&mut self.task).await??;
        Ok(())
    }
}
impl Drop for WorkWatcher {
    fn drop(&mut self) {
        self.stop.take();
    }
}

/// Mount failures are distinct from a valid route with no matching channel.
#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("payment mount lock is poisoned")]
    Poisoned,
    #[error("channel {0:?} is already mounted")]
    DuplicateChannel(Digest),
    #[error("setup for peer {peer:?} and bond {bond:?} is already mounted")]
    DuplicateSetup { peer: PeerId, bond: EdgeId },
    #[error("missing work route")]
    MissingRoute,
    #[error("invalid funding kind")]
    FundingKind,
    #[error("invalid channel identity")]
    ChannelId,
    #[error(transparent)]
    Endpoint(#[from] hellas_work::work::EndpointError),
}

impl From<MountError> for WireStatus {
    fn from(error: MountError) -> Self {
        use hellas_wire::WireCode;
        match error {
            MountError::MissingRoute | MountError::FundingKind | MountError::ChannelId => {
                Self::new(WireCode::InvalidArgument, error.to_string())
            }
            _ => Self::new(WireCode::Unavailable, "payment mounts are unavailable"),
        }
    }
}

type MountedChannels = BTreeMap<Digest, (PeerId, MountedWorkService)>;

/// Payment channels indexed by channel identity and bound to an authenticated peer.
/// The observer and request handlers share these mounts.
#[derive(Clone)]
pub struct MountedWork {
    mounted: Arc<Mutex<MountedChannels>>,
    driver: Option<AcceptedWorkDriver>,
}

impl Default for MountedWork {
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
        B: WorkBackend + Send + Sync + 'static,
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

/// A peer's local paid channel. Validator connections belong to the observer.
#[derive(Clone)]
pub struct MountedWorkService {
    service: WorkService,
    driver: Option<AcceptedWorkDriver>,
}

impl WorkHandler for MountedWorkService {
    async fn get_standing(
        &self,
        _request: GetStandingRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        Ok(GetStandingResponse {
            outcome: Some(get_standing_response::Outcome::Refused(not_ready())),
        })
    }

    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        if let Some(response) = self.service.precheck_acceptance(&request) {
            return Ok(response);
        }
        let ready = match self.service.readiness() {
            Ok(ready) => ready,
            Err(error) => {
                debug!(%error, "channel observer is not ready for acceptance");
                return Ok(AcceptWorkResponse {
                    outcome: Some(accept_work_response::Outcome::Refused(WorkRefused {
                        grant: None,
                        code: WorkRefusalCode::NotReady as i32,
                        reason: error.to_string(),
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
                PaidJobAuthorizationV2::decode(&request.authorization)
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
        self.service.deliver_result(request, context).await
    }

    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        self.service.stream_result(request, context).await
    }

    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        self.service.admit_certificate(request, context).await
    }
}

impl MountedWork {
    pub fn with_backend<B>(backend: B) -> Self
    where
        B: WorkBackend + Send + Sync + 'static,
    {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            driver: Some(AcceptedWorkDriver::new(backend)),
        }
    }

    /// Mounts one channel; duplicate identities are refused without replacement.
    pub fn mount(&self, peer: PeerId, service: &WorkService) -> Result<(), MountError> {
        let channel = service.with_state(|state| state.channel().id())?;
        let mut held = self.mounted.lock().map_err(|_| MountError::Poisoned)?;
        let std::collections::btree_map::Entry::Vacant(entry) = held.entry(channel) else {
            return Err(MountError::DuplicateChannel(channel));
        };
        entry.insert((
            peer,
            MountedWorkService {
                service: service.clone(),
                driver: self.driver.clone(),
            },
        ));
        Ok(())
    }

    /// Resolves an explicit route, also checking the transport-vouched peer.
    pub fn handler(
        &self,
        context: &TransportContext,
        route: Option<&WorkRoute>,
    ) -> Result<Option<MountedWorkService>, MountError> {
        let route = route.ok_or(MountError::MissingRoute)?;
        match FundingKind::try_from(route.funding_kind) {
            Ok(FundingKind::Payment) => {}
            Ok(FundingKind::Grant) => return Ok(None),
            _ => return Err(MountError::FundingKind),
        }
        let channel = <[u8; 32]>::try_from(route.channel_id.as_slice())
            .map(Digest::from_bytes)
            .map_err(|_| MountError::ChannelId)?;
        let Some(peer) = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))
        else {
            return Ok(None);
        };
        let held = self.mounted.lock().map_err(|_| MountError::Poisoned)?;
        Ok(held
            .get(&channel)
            .and_then(|(owner, mounted)| (*owner == peer).then(|| mounted.clone())))
    }

    /// Returns a specific local payment service for journal inspection.
    pub fn service(
        &self,
        context: &TransportContext,
        channel: Digest,
    ) -> Result<Option<WorkService>, MountError> {
        Ok(self
            .handler(context, Some(&WorkRoute::payment(channel)))?
            .map(|mounted| mounted.service))
    }

    /// Suspends and releases every channel, including after a poisoned mount lock.
    pub fn clear_all(&self) -> Result<(), MountError> {
        let (mut held, mut result) = match self.mounted.lock() {
            Ok(held) => (held, Ok(())),
            Err(error) => (error.into_inner(), Err(MountError::Poisoned)),
        };
        for (_, channel) in held.values() {
            let suspended = channel.service.suspend().map_err(MountError::from);
            result = result.and(suspended);
        }
        held.clear();
        result
    }
}

/// Setups indexed by authenticated peer. Serving and driving share each journal.
#[derive(Clone, Debug, Default)]
pub struct MountedSetup(Arc<Mutex<BTreeMap<(PeerId, EdgeId), SetupService>>>);

impl MountedSetup {
    /// Mounts a distinct bond under its authenticated transport peer.
    pub fn mount(
        &self,
        peer: PeerId,
        bond: EdgeId,
        service: &SetupService,
    ) -> Result<(), MountError> {
        let mut held = self.0.lock().map_err(|_| MountError::Poisoned)?;
        let std::collections::btree_map::Entry::Vacant(entry) = held.entry((peer, bond)) else {
            return Err(MountError::DuplicateSetup { peer, bond });
        };
        entry.insert(service.clone());
        Ok(())
    }
    /// Selects a setup using both the authenticated peer and explicit bond.
    pub fn service(
        &self,
        context: &TransportContext,
        bond: EdgeId,
    ) -> Result<Option<SetupService>, MountError> {
        let Some(peer) = context
            .vouched_peer()
            .map(|peer| PeerId::from_bytes(peer.0))
        else {
            return Ok(None);
        };
        Ok(self
            .0
            .lock()
            .map_err(|_| MountError::Poisoned)?
            .get(&(peer, bond))
            .cloned())
    }
    fn clear(&self, peer: PeerId, bond: EdgeId) -> Result<(), MountError> {
        self.0
            .lock()
            .map_err(|_| MountError::Poisoned)?
            .remove(&(peer, bond));
        Ok(())
    }
    /// Releases every setup, including after a poisoned mount lock.
    pub fn clear_all(&self) -> Result<(), MountError> {
        match self.0.lock() {
            Ok(mut held) => {
                held.clear();
                Ok(())
            }
            Err(error) => {
                error.into_inner().clear();
                Err(MountError::Poisoned)
            }
        }
    }
}

impl WorkSetupHandler for MountedSetup {
    async fn exchange_setup(
        &self,
        request: ExchangeSetupRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<ExchangeSetupResponse>> + Send, WireStatus> {
        let bond = <[u8; 32]>::try_from(request.bond_edge.as_slice())
            .map(EdgeId::from_bytes)
            .map_err(|_| {
                WireStatus::new(hellas_wire::WireCode::InvalidArgument, "invalid setup bond")
            })?;
        match self.service(&context, bond)? {
            Some(service) => Ok(Into::<WithTrailer<ExchangeSetupResponse>>::into(
                service.exchange_setup(request, context).await?,
            )),
            None => Ok(Into::<WithTrailer<ExchangeSetupResponse>>::into(
                UnmountedWork.exchange_setup(request, context).await?,
            )),
        }
    }
}

impl WorkHandler for MountedWork {
    async fn get_standing(
        &self,
        request: GetStandingRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        self.handler(&context, request.route.as_ref())?;
        Ok(GetStandingResponse {
            outcome: Some(get_standing_response::Outcome::Refused(not_ready())),
        })
    }

    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Some(service) => Ok(Into::<WithTrailer<AcceptWorkResponse>>::into(
                service.accept_work(request, context).await?,
            )),
            None => Ok(Into::<WithTrailer<AcceptWorkResponse>>::into(
                UnmountedWork.accept_work(request, context).await?,
            )),
        }
    }
    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Some(service) => Ok(Into::<WithTrailer<DeliverResultResponse>>::into(
                service.deliver_result(request, context).await?,
            )),
            None => Ok(Into::<WithTrailer<DeliverResultResponse>>::into(
                UnmountedWork.deliver_result(request, context).await?,
            )),
        }
    }
    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Some(service) => service.stream_result(request, context).await,
            None => UnmountedWork.stream_result(request, context).await,
        }
    }
    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Some(service) => Ok(Into::<WithTrailer<AdmitCertificateResponse>>::into(
                service.admit_certificate(request, context).await?,
            )),
            None => Ok(Into::<WithTrailer<AdmitCertificateResponse>>::into(
                UnmountedWork.admit_certificate(request, context).await?,
            )),
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
/// Live acceptance and recovery use the same journaled running marker.
struct DrivenChannel {
    service: WorkService,
    descriptor: Option<WorkChannelDescriptor>,
    max_observation_age: Duration,
    driver: Option<AcceptedWorkDriver>,
}

impl DrivenChannel {
    async fn refresh<S>(
        &self,
        source: &S,
        started: hellas_work::work::ObservationTime,
        snapshot: Option<hellas_chain::WorkChannelSnapshot>,
    ) -> Result<(), PaidProviderError>
    where
        S: FinalizedBlocks + FinalizedWorkView + Sync,
    {
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or(PaidProviderError::NoDescriptor)?;
        let query = WorkChannelQuery {
            bond_edge: descriptor.bond_edge(),
            payment_edge: descriptor.channel().payment_edge(),
            funding: Default::default(),
        };
        let snapshot = snapshot.ok_or(PaidProviderError::NoSnapshot)?;
        if snapshot.query() != &query {
            return Err(PaidProviderError::WrongSnapshot);
        }
        let ready = descriptor.check_ready(&snapshot.observed_channel())?;
        let cursor = self.service.with_state(|state| state.cursor().0)?;
        if ready.check_caught_up(cursor).is_err() {
            self.service
                .drive()?
                .catch_up_to(source, ready.finalized_height())
                .await?;
        }
        self.service
            .observe_ready(ready, started, self.max_observation_age)?;
        Ok(())
    }

    fn accepted_work_id(&self) -> Result<Option<Digest>, PaidProviderError> {
        self.service
            .with_state(|state| {
                let mut jobs = state.jobs();
                let job = jobs.next()?;
                (jobs.next().is_none() && job.phase() == JobPhase::Accepted).then(|| job.work_id())
            })
            .map_err(PaidProviderError::from)
    }

    /// Resumes accepted work after a fresh readiness check. The durable `JobRunning`
    /// record admits one invocation even when a live request races this clock tick.
    fn resume_accepted(&self) -> Result<bool, PaidProviderError> {
        let Some(work_id) = self.accepted_work_id()? else {
            return Ok(false);
        };
        let driver = self.driver.as_ref().ok_or(PaidProviderError::NoBackend)?;
        let ready = self.service.readiness()?;
        driver.spawn(self.service.clone(), ready, work_id);
        Ok(true)
    }
}

/// One setup journal on a clock.
struct SetupClock {
    max_observation_age: Duration,
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
        work_mount: &MountedWork,
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
                        if let Some(peer) = self.route_peer
                            && let Err(error) = setup_mount.clear(peer, self.bond_edge)
                        {
                            warn!(%error, "setup could not be unmounted");
                        }
                        self.take_mount(store, signer, &policy, work_mount);
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
            let started = hellas_work::work::ObservationTime::now();
            let snapshot = match advance_paid_work_clock(&channel.service, source).await {
                Ok(progress) => {
                    debug!(bond, close = ?progress.close, "the channel advanced");
                    progress.snapshot
                }
                Err(error) => {
                    let _ = channel.service.suspend();
                    warn!(bond, %error, "this channel's close did not advance");
                    return !error.source_failed();
                }
            };
            if let Err(error) = channel.refresh(source, started, snapshot).await {
                let _ = channel.service.suspend();
                debug!(bond, %error, "channel observation did not renew admission");
                answered &= !matches!(
                    error,
                    PaidProviderError::Query(_)
                        | PaidProviderError::CatchUp(
                            hellas_work::work_close::CatchUpError::Source(_)
                        )
                );
            } else if let Err(error) = channel.resume_accepted() {
                warn!(bond, %error, "an accepted paid job did not resume");
            }
        }
        answered
    }

    /// Transfers the mounted store returned by setup, preserving its exclusive lock.
    fn take_mount(
        &mut self,
        store: ChannelStore,
        signer: &Secp256k1Signer,
        policy: &ProviderChannelPolicy,
        mount: &MountedWork,
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
                if let Err(error) = service.require_observer() {
                    warn!(bond, %error, "channel observer could not be installed");
                    self.driven = Driven::Done;
                    return;
                }
                match self.route_peer {
                    Some(peer) => match mount.mount(peer, &service) {
                        Ok(()) => {
                            info!(bond, "this node now answers Work from its mounted channel")
                        }
                        Err(error) => {
                            warn!(bond, %error, "channel is driven but could not be mounted")
                        }
                    },
                    None => warn!(bond, "channel is driven without a peer route"),
                }
                self.driven = Driven::Channel(Box::new(DrivenChannel {
                    service,
                    descriptor,
                    max_observation_age: self.max_observation_age,
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
pub struct WorkRunner {
    clocks: Vec<SetupClock>,
    signer: Secp256k1Signer,
    work_mount: MountedWork,
    setup_mount: MountedSetup,
    poll: Duration,
    validators: Vec<String>,
    consensus_verifier: ConsensusVerifier,
    genesis_payload_digest: Digest,
}

impl WorkRunner {
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

impl WorkRunner {
    /// Discovers provider journals and mounts configured routes. Unrouted journals
    /// are still driven through close. Unreadable journals are logged; failure to
    /// enumerate the root is returned to the caller.
    pub fn discover(
        config: WorkRunnerConfig,
        work_mount: MountedWork,
        setup_mount: MountedSetup,
    ) -> Result<Self, PaidProviderError> {
        let consensus_verifier = config.consensus_verifier()?;
        let settlement_verifier = Secp256k1Verifier::new();
        let found = discover_setups(&config.journal_root, config.network).map_err(|source| {
            PaidProviderError::Discover {
                path: config.journal_root.clone(),
                source,
            }
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
                match setup_mount.mount(peer, setup.bond_edge, &service) {
                    Ok(()) => info!(
                        bond,
                        "this node now answers WorkSetup from its driven setup"
                    ),
                    Err(error) => warn!(bond, %error, "provider setup could not be mounted"),
                }
            } else {
                warn!(bond, "this provider setup has no configured peer route");
            }
            let driven = Driven::Setup { service, policy };
            clocks.push(SetupClock {
                max_observation_age: config.max_observation_age,
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
            genesis_payload_digest: config.genesis_payload_digest,
        })
    }

    /// Takes one step of every journal, and says whether the chain
    /// answered all of them.
    pub async fn tick<S>(&mut self, source: &S) -> bool
    where
        S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
    {
        let mut answered = true;
        for clock in &mut self.clocks {
            answered &= clock
                .tick(source, &self.signer, &self.work_mount, &self.setup_mount)
                .await;
        }
        answered
    }

    /// Ticks each journal once per period and redials after a source failure.
    pub async fn run_over<S, D, F>(
        mut self,
        mut stop: oneshot::Receiver<()>,
        dial: D,
    ) -> Result<(), MountError>
    where
        S: SetupView + FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
        D: Fn() -> F,
        F: core::future::Future<Output = Option<S>>,
    {
        if self.clocks.is_empty() {
            info!("no provider setup journal under the work root; the clock has nothing to drive");
            return self.unmount_all();
        }
        // Each channel owns its observer loop. A slow source or a large restart
        // backlog on one channel cannot stop another channel's close response.
        {
            use futures::{StreamExt as _, stream::FuturesUnordered};
            let signer = &self.signer;
            let work_mount = &self.work_mount;
            let setup_mount = &self.setup_mount;
            let dial = &dial;
            let poll = self.poll;
            let mut observers = self
                .clocks
                .iter_mut()
                .map(|clock| async move {
                    let mut chain = None;
                    loop {
                        let budget = clock.max_observation_age;
                        if chain.is_none() {
                            chain = tokio::time::timeout(budget, dial()).await.ok().flatten();
                        }
                        if let Some(source) = chain.as_ref() {
                            match tokio::time::timeout(
                                budget,
                                clock.tick(source, signer, work_mount, setup_mount).instrument(hellas_rpc::request_span!(target: "hellas_request", parent: None, "paid.channel.observe", hellas.channel.role = "provider")),
                            )
                            .await
                            {
                                Ok(true) => {}
                                Ok(false) | Err(_) => {
                                    if let Driven::Channel(channel) = &clock.driven {
                                        let _ = channel.service.suspend();
                                    }
                                    chain = None;
                                }
                            }
                        }
                        if matches!(clock.driven, Driven::Done) {
                            break;
                        }
                        tokio::time::sleep(poll).await;
                    }
                })
                .collect::<FuturesUnordered<_>>();
            loop {
                tokio::select! {
                    _ = &mut stop => break,
                    next = observers.next() => if next.is_none() { break; },
                }
            }
        }
        let result = self.unmount_all();
        info!("the paid-work clock stopped, and its journals are closed");
        result
    }
}

impl WorkRunner {
    fn unmount_all(&self) -> Result<(), MountError> {
        let work = self.work_mount.clear_all();
        let setup = self.setup_mount.clear_all();
        work.and(setup)
    }

    /// Ticks until told to stop, over the validators the configuration
    /// names.
    pub async fn run(self, stop: oneshot::Receiver<()>) -> Result<(), MountError> {
        let validators = self.validators.clone();
        let verifier = self.consensus_verifier.clone();
        let genesis = self.genesis_payload_digest;
        let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        self.run_over(stop, move || {
            let validators = validators.clone();
            let verifier = verifier.clone();
            let next = next.clone();
            async move { connect_chain(&validators, verifier, genesis, &next).await }
        })
        .await
    }
}

/// Rotates the first candidate on reconnect, per runner. Chain reads and
/// submissions use the selected verified connection.
async fn connect_chain(
    validators: &[String],
    verifier: ConsensusVerifier,
    genesis: Digest,
    next: &std::sync::atomic::AtomicUsize,
) -> Option<ProductionWorkSource> {
    if validators.is_empty() {
        return None;
    }
    let start = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % validators.len();
    for url in validators.iter().cycle().skip(start).take(validators.len()) {
        match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => {
                let source = WorkBlocks::new(client);
                if let Err(error) = authenticate_genesis(&source, genesis).await {
                    warn!(validator = %url, %error, "validator failed genesis authentication");
                    continue;
                }
                info!(validator = %url, "the paid-work clock reads and submits here");
                return Some(source);
            }
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    None
}

async fn authenticate_genesis(
    source: &impl FinalizedBlocks,
    expected: Digest,
) -> Result<(), PaidProviderError> {
    let first = source
        .block_at(1)
        .await?
        .ok_or(PaidProviderError::MissingGenesis)?;
    if &first.parent != expected.as_bytes() {
        return Err(PaidProviderError::GenesisMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_work::work_close::{BlockSourceError, FinalizedWork};

    struct Source(Result<Option<FinalizedWork>, BlockSourceError>);

    impl FinalizedBlocks for Source {
        async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
            panic!("genesis authentication must request block 1 directly")
        }

        async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
            assert_eq!(height, 1);
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn validator_connection_requires_the_configured_genesis() {
        let block = FinalizedWork {
            height: 1,
            parent: [7; 32],
            payload: [8; 32],
            txs: Vec::new(),
        };
        authenticate_genesis(&Source(Ok(Some(block.clone()))), [7; 32].into())
            .await
            .unwrap();
        assert!(matches!(
            authenticate_genesis(&Source(Ok(Some(block))), [9; 32].into()).await,
            Err(PaidProviderError::GenesisMismatch)
        ));
        assert!(matches!(
            authenticate_genesis(&Source(Ok(None)), [7; 32].into()).await,
            Err(PaidProviderError::MissingGenesis)
        ));
        assert!(matches!(
            authenticate_genesis(
                &Source(Err(BlockSourceError::new("offline"))),
                [7; 32].into()
            )
            .await,
            Err(PaidProviderError::BlockSource(_))
        ));
    }

    #[test]
    fn poisoned_mounts_are_errors_and_shutdown_still_releases_channels() {
        use hellas_wire::{AuthLevel, PeerIdentity};
        let fixture = crate::test_support::PaidFixture::new();
        let service = fixture.provider();
        let channel = fixture.descriptor.channel().id();
        let peer = PeerId::from_bytes([1; 32]);
        let context = TransportContext {
            peer: Some(PeerIdentity(peer.into_bytes())),
            auth_level: AuthLevel::Vouched,
            ..TransportContext::default()
        };
        let mount = MountedWork::default();
        mount.mount(peer, &service).unwrap();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = mount.mounted.lock().unwrap();
            panic!("inject a poisoned mount");
        }));
        assert!(poisoned.is_err());
        assert!(matches!(
            mount.service(&context, channel),
            Err(MountError::Poisoned)
        ));
        assert!(matches!(
            mount.mount(peer, &service),
            Err(MountError::Poisoned)
        ));
        assert!(matches!(mount.clear_all(), Err(MountError::Poisoned)));
        assert!(match mount.mounted.lock() {
            Err(error) => error.into_inner().is_empty(),
            Ok(_) => panic!("lock remains poisoned"),
        });

        let setups = MountedSetup::default();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = setups.0.lock().unwrap();
            panic!("inject a poisoned setup mount");
        }));
        assert!(poisoned.is_err());
        assert!(matches!(
            setups.service(&context, fixture.descriptor.bond_edge()),
            Err(MountError::Poisoned)
        ));
        assert!(matches!(setups.clear_all(), Err(MountError::Poisoned)));
    }

    #[test]
    fn missing_validators_are_rejected_before_discovering_journals() {
        let fixture = crate::test_support::PaidFixture::new();
        let config = &fixture.config;
        let runner = WorkRunner::discover(
            WorkRunnerConfig {
                network: config.chain.network,
                genesis_payload_digest: config.chain.genesis_payload_digest,
                threshold_identity: config.chain.threshold_identity.clone(),
                journal_root: config.journal_root.clone(),
                routes: config.routes.clone(),
                validators: Vec::new(),
                poll: config.poll,
                max_observation_age: config.max_observation_age,
                settlement_key: crate::test_support::signer(2),
                policy: config.provider_policy(),
            },
            MountedWork::default(),
            MountedSetup::default(),
        );
        assert!(matches!(runner, Err(PaidProviderError::NoValidators)));
        assert!(!config.journal_root.exists());
    }
}
