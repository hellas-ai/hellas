//! Shared provider routing and certified-read clock for paid work.
use hellas_private::StoreLocation;
use hellas_rpc::pb::work::Refusable;

mod offers;
use crate::work_router::{UnmountedWork, not_ready};
use futures::future::BoxFuture;
use hellas_auth::Digest;
use hellas_chain::work_blocks::advance_paid_work_clock;
use hellas_chain::{FinalizedWorkView, WorkBlocks, WorkChannelQuery, WorkChannelSnapshot};
use hellas_channel::model::setup::{ProviderChannelPolicy, ReadyChannel, WorkChannelDescriptor};
use hellas_channel::model::work::{
    PaidJobAuthorizationV2, PrivateRecord as _, work_id as accepted_work_id,
};
use hellas_channel::work::{
    CloseEndpoint, MAX_CERTIFIED_AGE, POLL, RunError, RunOutcome, SETUP_POLL, WorkBackend,
    WorkService, check_certified_age, run_accepted_work,
};
use hellas_channel::work_close::TxSink;
use hellas_channel::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_channel::work_open::{SetupAdvance, SetupDriveError, SetupProgress, SetupQuery};
use hellas_channel::work_store::{ChannelStore, Role, SetupStore, discover_setups};
use hellas_kernel::{EdgeId, NetworkId, Secp256k1Signer, Secp256k1Verifier};
use hellas_rpc::call::{WithTrailer, with_trailer as wt};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    ExchangeSetupRequest, ExchangeSetupResponse, FundingKind, GetStandingRequest,
    GetStandingResponse, StreamResultRequest, WorkRefusalCode, WorkRefused, WorkRoute,
    accept_work_response,
};
use hellas_rpc::services::work::WorkHandler;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_wire::peers::PeerId;
use hellas_wire::{TransportContext, WireStatus};
use offers::{AutomaticOffers, OfferAllocator};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;
use tracing::{Instrument as _, debug, info, warn};
/// Provider observation and recovery failures preserve their typed causes.
#[derive(Debug, thiserror::Error)]
pub enum PaidProviderError {
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error("provider setup has no durable offer or its signing identity differs")]
    InvalidOffer,
    #[error("channel journal has no recovered setup binding: {}", path.display())]
    UnmatchedChannel { path: PathBuf },
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
    #[error(transparent)]
    BlockSource(#[from] hellas_channel::work_close::BlockSourceError),
    #[error(transparent)]
    Endpoint(#[from] hellas_channel::work::EndpointError),
    #[error(transparent)]
    Setup(#[from] hellas_channel::model::setup::WorkSetupError),
    #[error(transparent)]
    SetupDrive(#[from] SetupDriveError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    CatchUp(#[from] hellas_channel::work_close::CatchUpError),
    #[error("cannot discover work journals under {}: {source}", path.display())]
    Discover {
        path: PathBuf,
        source: hellas_channel::work_store::WorkStoreError,
    },
}

/// Validated configuration for driving provider journals.
#[derive(Clone)]
pub struct WorkRunnerConfig {
    pub chain: hellas_chain::chain_dir::ChainDir,
    /// The key every settlement this node signs is signed with.
    pub settlement_key: Secp256k1Signer,
}

impl WorkRunnerConfig {
    pub fn network(&self) -> NetworkId {
        self.chain.network()
    }
    pub fn journal_root(&self) -> StoreLocation {
        self.chain.provider_journals()
    }
}

/// Owns the observer through graceful shutdown, including cancellation of the caller.
pub struct WorkWatcher {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), MountError>>,
}
impl WorkWatcher {
    pub fn spawn(runner: ChainWorkRunner) -> Self {
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
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error("offer worker failed")]
    OfferWorker(#[source] tokio::task::JoinError),
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
    Endpoint(#[from] hellas_channel::work::EndpointError),
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
    changes: Arc<tokio::sync::Mutex<()>>,
    driver: Option<AcceptedWorkDriver>,
}

impl Default for MountedWork {
    fn default() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            changes: Arc::new(tokio::sync::Mutex::new(())),
            driver: None,
        }
    }
}

/// Type-erased runner for an accepted job.
type RunAcceptedWork = dyn Fn(WorkService, ReadyChannel, Digest) -> BoxFuture<'static, Result<RunOutcome, RunError>>
    + Send
    + Sync;

/// Runs accepted jobs detached from requests and the clock; provider shutdown
/// aborts them, which cancels their backend work (including compilation).
#[derive(Clone)]
struct AcceptedWorkDriver(Arc<RunAcceptedWork>, Arc<Mutex<tokio::task::JoinSet<()>>>);

impl AcceptedWorkDriver {
    fn new<B>(backend: B) -> Self
    where
        B: WorkBackend + Send + Sync + 'static,
    {
        let backend = Arc::new(backend);
        Self(
            Arc::new(move |service, ready, work_id| {
                let backend = Arc::clone(&backend);
                Box::pin(async move {
                    run_accepted_work(&service, &ready, backend.as_ref(), work_id).await
                })
            }),
            Default::default(),
        )
    }

    /// Aborts every accepted job and waits until each has been dropped.
    async fn shutdown(&self) {
        let mut tasks = match self.1.lock() {
            Ok(mut tasks) => std::mem::take(&mut *tasks),
            Err(error) => std::mem::take(&mut *error.into_inner()),
        };
        tasks.shutdown().await;
    }

    /// Starts one accepted job without lending its lifetime to either the
    /// request path or the close clock.
    fn spawn(&self, service: WorkService, ready: ReadyChannel, work_id: Digest) {
        let running = (self.0)(service, ready, work_id);
        let span = hellas_rpc::request_span!(target: "hellas_request", "paid.provider.execute", hellas.work.id = ?work_id, otel.status_code = tracing::field::Empty);
        let mut tasks = match self.1.lock() {
            Ok(tasks) => tasks,
            Err(error) => error.into_inner(),
        };
        while tasks.try_join_next().is_some() {}
        tasks.spawn(tracing::Instrument::instrument(
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

/// A peer's local paid channel, admitted by its own certified observation.
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
        Ok(GetStandingResponse::refused(not_ready()))
    }

    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        if let Some(response) = self.service.precheck_acceptance(&request).await {
            return Ok(response);
        }
        let ready = match self.service.readiness().await {
            Ok(ready) => ready,
            Err(error) => {
                debug!(%error, "channel observer is not ready for acceptance");
                return Ok(AcceptWorkResponse::refused(WorkRefused {
                    grant: None,
                    code: WorkRefusalCode::NotReady as i32,
                    reason: error.to_string(),
                }));
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
            .await
            .ok()
            .flatten();
        let response = self.service.accept(&request).await;
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

    async fn stream_result(
        &self,
        request: StreamResultRequest,
        context: TransportContext,
    ) -> Result<hellas_channel::work::PaidResultStream, WireStatus> {
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
    pub(crate) async fn upload_stream(
        &self,
        mut requests: std::pin::Pin<
            Box<
                dyn futures::Stream<
                        Item = Result<hellas_rpc::pb::content::UploadRequest, WireStatus>,
                    > + Send,
            >,
        >,
        context: TransportContext,
        cancellation: hellas_channel::work::admission::Cancellation,
    ) -> Result<hellas_rpc::call::ResponseStream<hellas_rpc::pb::content::UploadResponse>, WireStatus>
    {
        use futures::StreamExt;
        use prost::Message;
        let denied = || {
            WireStatus::new(
                hellas_wire::WireCode::PermissionDenied,
                "invalid Work content opening",
            )
        };
        let first = requests.next().await.ok_or_else(denied)??;
        let Some(hellas_rpc::pb::content::upload_request::Part::Open(open)) = &first.part else {
            return Err(denied());
        };
        let opening = open.work.as_ref().ok_or_else(denied)?;
        let request =
            AcceptWorkRequest::decode(opening.signed_opening.as_slice()).map_err(|_| denied())?;
        let service = self
            .handler(&context, request.route.as_ref())
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        service
            .service
            .upload_stream(
                Box::pin(futures::stream::once(async move { Ok(first) }).chain(requests)),
                context,
                cancellation,
            )
            .await
    }
    pub fn with_backend<B>(backend: B) -> Self
    where
        B: WorkBackend + Send + Sync + 'static,
    {
        Self {
            mounted: Arc::new(Mutex::new(BTreeMap::new())),
            changes: Arc::new(tokio::sync::Mutex::new(())),
            driver: Some(AcceptedWorkDriver::new(backend)),
        }
    }

    /// Mounts one channel; duplicate identities are refused without replacement.
    pub async fn mount(&self, peer: PeerId, service: &WorkService) -> Result<(), MountError> {
        let _changes = self.changes.lock().await;
        let channel = service.with_state(|state| state.channel().id()).await?;
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

    /// Stops admission and waits out journal writes before aborting accepted jobs.
    /// Cancellation retains the mounts so shutdown can resume.
    pub async fn clear_all(&self) -> Result<(), MountError> {
        let _changes = self.changes.lock().await;
        let (channels, mut result) = {
            let (held, result) = match self.mounted.lock() {
                Ok(held) => (held, Ok(())),
                Err(error) => (error.into_inner(), Err(MountError::Poisoned)),
            };
            (
                held.values()
                    .map(|(_, channel)| channel.service.clone())
                    .collect::<Vec<_>>(),
                result,
            )
        };
        for service in &channels {
            service.stop().await?;
        }
        use hellas_channel::work_close::CloseChannel as _;
        let mut drivers = channels
            .iter()
            .map(WorkService::drive)
            .collect::<Result<Vec<_>, _>>()?;
        {
            // Hold every journal writer while aborting; queued writers are
            // cancelled before these guards are released.
            let mut writers = Vec::new();
            for driver in &mut drivers {
                writers.push(driver.store().await.map_err(|_| MountError::Poisoned)?);
            }
            if let Some(driver) = &self.driver {
                driver.shutdown().await;
            }
        }
        for driver in &mut drivers {
            let closed = async {
                driver
                    .store()
                    .await
                    .map_err(|_| MountError::Poisoned)?
                    .close()
                    .await?;
                Ok::<_, MountError>(())
            }
            .await;
            result = result.and(closed);
        }
        let mut held = match self.mounted.lock() {
            Ok(held) => held,
            Err(error) => {
                result = Err(MountError::Poisoned);
                error.into_inner()
            }
        };
        held.clear();
        result
    }
}

/// Setups indexed by authenticated peer. Serving and driving share each journal.
#[derive(Clone, Debug, Default)]
pub struct MountedSetup(
    Arc<Mutex<BTreeMap<(PeerId, EdgeId), SetupService>>>,
    Arc<std::sync::OnceLock<AutomaticOffers>>,
    Option<hellas_store::content::DiskStore>,
);

impl MountedSetup {
    /// Share the host store before discovering journals or mounting automatic offers.
    pub fn with_content_store(content: hellas_store::content::DiskStore) -> Self {
        Self(Default::default(), Default::default(), Some(content))
    }
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
    async fn clear(&self, peer: PeerId, bond: EdgeId) -> Result<(), MountError> {
        let setup = self
            .0
            .lock()
            .map_err(|_| MountError::Poisoned)?
            .remove(&(peer, bond));
        if let Some(setup) = setup {
            setup.close().await;
        }
        Ok(())
    }
    /// Releases every setup, including after a poisoned mount lock.
    pub async fn clear_all(&self) -> Result<(), MountError> {
        let (setups, result) = match self.0.lock() {
            Ok(mut held) => (std::mem::take(&mut *held), Ok(())),
            Err(error) => (
                std::mem::take(&mut *error.into_inner()),
                Err(MountError::Poisoned),
            ),
        };
        for setup in setups.into_values() {
            setup.close().await;
        }
        result
    }
}

impl WorkSetupHandler for MountedSetup {
    async fn request_offer(
        &self,
        request: hellas_rpc::pb::work::RequestOfferRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<hellas_rpc::pb::work::RequestOfferResponse>> + Send, WireStatus>
    {
        let offers = self.1.get().ok_or_else(|| {
            WireStatus::new(
                hellas_wire::WireCode::Unavailable,
                "paid offers unavailable",
            )
        })?;
        offers.request(request, context).await
    }

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
            Some(service) => wt(service.exchange_setup(request, context)).await,
            None => wt(UnmountedWork.exchange_setup(request, context)).await,
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
        Ok(GetStandingResponse::refused(not_ready()))
    }

    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Some(service) => wt(service.accept_work(request, context)).await,
            None => wt(UnmountedWork.accept_work(request, context)).await,
        }
    }

    async fn stream_result(
        &self,
        request: StreamResultRequest,
        context: TransportContext,
    ) -> Result<hellas_channel::work::PaidResultStream, WireStatus> {
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
            Some(service) => wt(service.admit_certificate(request, context)).await,
            None => wt(UnmountedWork.admit_certificate(request, context)).await,
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
    driver: Option<AcceptedWorkDriver>,
}

impl DrivenChannel {
    /// Renews admission from the read the close drive just applied.
    async fn refresh(&self, snapshot: &WorkChannelSnapshot) -> Result<(), PaidProviderError> {
        let descriptor = self
            .descriptor
            .as_ref()
            .ok_or(PaidProviderError::NoDescriptor)?;
        if snapshot.query().bond_edge != descriptor.bond_edge()
            || snapshot.query().payment_edge != Some(descriptor.channel().payment_edge())
        {
            return Err(PaidProviderError::WrongSnapshot);
        }
        let ready = match descriptor.check_ready(&snapshot.observed_channel()) {
            Ok(ready) => ready,
            Err(error) => {
                self.service
                    .observe_unavailable(snapshot.block().height)
                    .await?;
                return Err(error.into());
            }
        };
        self.service.observe_ready(ready).await?;
        Ok(())
    }

    /// Resumes every accepted job after a fresh readiness check. Overlapping
    /// accepted executions are each dispatched; the durable `JobRunning`
    /// record admits one invocation per job even when a live request races
    /// this clock tick.
    async fn resume_accepted(&self) -> Result<bool, PaidProviderError> {
        let work_ids = self.service.accepted_work_ids().await?;
        if work_ids.is_empty() {
            return Ok(false);
        }
        let driver = self.driver.as_ref().ok_or(PaidProviderError::NoBackend)?;
        let ready = self.service.readiness().await?;
        for work_id in work_ids {
            driver.spawn(self.service.clone(), ready.clone(), work_id);
        }
        Ok(true)
    }
}

/// One step of a mounted channel from one certified read of it: the close
/// drive, then admission, then any accepted job left to resume.
///
/// Returns whether the chain answered, and whether the channel has
/// something on chain in flight — a live contest, or a transaction it just
/// submitted — that the next read should come soon for.
async fn drive_channel<T: TxSink + Sync>(
    channel: &DrivenChannel,
    snapshot: &WorkChannelSnapshot,
    sink: &T,
    bond: &str,
) -> (bool, bool) {
    let busy = match advance_paid_work_clock(&channel.service, snapshot, sink).await {
        Ok(progress) => {
            debug!(bond, close = ?progress.close, "the channel advanced");
            progress.bond_timeout.is_some()
                || matches!(
                    progress.close,
                    hellas_channel::work_close::CloseProgress::Opened { .. }
                        | hellas_channel::work_close::CloseProgress::Submitted { .. }
                        | hellas_channel::work_close::CloseProgress::AdjudicationSubmitted { .. }
                )
        }
        Err(error) => {
            let _ = channel.service.suspend().await;
            warn!(bond, %error, "this channel's close did not advance");
            return (!error.source_failed(), false);
        }
    };
    if let Err(error) = channel.refresh(snapshot).await {
        let _ = channel.service.suspend().await;
        debug!(bond, %error, "channel observation did not renew admission");
    } else if let Err(error) = channel.resume_accepted().await {
        warn!(bond, %error, "an accepted paid job did not resume");
    }
    (true, busy)
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
    /// The last step left a contest live or a transaction in flight.
    busy: bool,
}

/// What one tick of one journal asks the chain.
enum Asked {
    Setup(SetupQuery),
    Channel(WorkChannelQuery),
}

impl Asked {
    fn query(&self) -> WorkChannelQuery {
        match self {
            Self::Setup(query) => WorkChannelQuery {
                bond_edge: query.bond_edge,
                payment_edge: query.payment_edge,
                funding: query.funding.clone(),
            },
            Self::Channel(query) => query.clone(),
        }
    }
}

impl SetupClock {
    /// The read this journal needs next, or `None` while it waits on its
    /// counterparty or has ended.
    async fn asked(&self) -> Option<Asked> {
        match &self.driven {
            Driven::Setup { service, .. } => service.query().await.ok().flatten().map(Asked::Setup),
            // From the journal, not the admission descriptor: a channel its
            // policy no longer admits still owes its close.
            Driven::Channel(channel) => channel
                .service
                .with_state(|state| {
                    Asked::Channel(WorkChannelQuery {
                        bond_edge: state.channel().payment_terms().bond_edge,
                        payment_edge: Some(state.channel().payment_edge()),
                        funding: Default::default(),
                    })
                })
                .await
                .ok(),
            Driven::Done => None,
        }
    }

    /// Advances the journal from one certified read of it; returns false
    /// when the read or a submission failed, so the caller redials.
    async fn tick<T>(
        &mut self,
        asked: &Asked,
        snapshot: &WorkChannelSnapshot,
        sink: &T,
        signer: &Secp256k1Signer,
        work_mount: &MountedWork,
        setup_mount: &MountedSetup,
    ) -> bool
    where
        T: TxSink + Sync,
    {
        let bond = hex::encode(self.bond_edge.to_bytes());
        match check_certified_age(snapshot.certified_at_ms()) {
            Ok(age) => debug!(
                bond,
                height = snapshot.block().height,
                certified_age_ms = age.as_millis(),
                "certified channel read"
            ),
            Err(error) => {
                if let Driven::Channel(channel) = &self.driven {
                    let _ = channel.service.suspend().await;
                }
                warn!(bond, %error, "the certified read is too old to act on");
                return false;
            }
        }
        match (&mut self.driven, asked) {
            (Driven::Setup { service, policy }, Asked::Setup(query)) => {
                let Some(read) = snapshot.finalized_setup(query) else {
                    return false;
                };
                let policy = policy.clone();
                match service.advance_setup(&read, sink).await {
                    Ok(SetupAdvance {
                        progress,
                        mounted: Some(store),
                    }) => {
                        let origin = match progress {
                            SetupProgress::Complete(origin)
                            | SetupProgress::CloseOnly { origin, .. } => origin,
                            _ => {
                                warn!(bond, "mounted channel has no verified setup origin");
                                return true;
                            }
                        };
                        if let Some(peer) = self.route_peer
                            && let Err(error) = setup_mount.clear(peer, self.bond_edge).await
                        {
                            warn!(%error, "setup could not be unmounted");
                        }
                        if let Err(error) = self
                            .take_mount(store, signer, &policy, work_mount, origin)
                            .await
                        {
                            warn!(bond, %error, "the mounted channel could not be bound");
                            if !matches!(self.driven, Driven::Channel(_)) {
                                self.driven = Driven::Done;
                            }
                            return true;
                        }
                        // The read that completed the setup is the channel's
                        // own first read: admit from it now rather than a poll
                        // later, while the buyer is waiting on its first job.
                        match &self.driven {
                            Driven::Channel(channel) => {
                                let (answered, busy) =
                                    drive_channel(channel, snapshot, sink, &bond).await;
                                self.busy = busy;
                                answered
                            }
                            _ => true,
                        }
                    }
                    Ok(SetupAdvance { progress, .. }) => {
                        if matches!(
                            progress,
                            SetupProgress::Aborted(_) | SetupProgress::Faulted(_)
                        ) {
                            warn!(bond, ?progress, "this setup ended with no channel to drive");
                            self.driven = Driven::Done;
                        } else {
                            debug!(bond, ?progress, "the setup advanced");
                        }
                        true
                    }
                    Err(error) => {
                        warn!(bond, %error, "this setup did not advance");
                        !matches!(error, SetupDriveError::Source(_))
                    }
                }
            }
            (Driven::Channel(channel), Asked::Channel(_)) => {
                let (answered, busy) = drive_channel(channel, snapshot, sink, &bond).await;
                self.busy = busy;
                answered
            }
            // The journal moved on between asking and answering; the next
            // tick asks again.
            _ => true,
        }
    }

    /// Transfers the mounted store returned by setup, preserving its exclusive lock.
    async fn take_mount(
        &mut self,
        store: ChannelStore,
        signer: &Secp256k1Signer,
        policy: &ProviderChannelPolicy,
        mount: &MountedWork,
        origin: hellas_channel::work_store::SetupOrigin,
    ) -> Result<(), PaidProviderError> {
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
        debug!(
            bond,
            height = origin.height,
            "the channel journal starts at its first sighting"
        );
        let service = WorkService::close_only(CloseEndpoint::new(store, signer.clone())?);
        service.require_observer().await?;
        self.driven = Driven::Channel(Box::new(DrivenChannel {
            service: service.clone(),
            descriptor,
            driver: mount.driver.clone(),
        }));
        match self.route_peer {
            Some(peer) => mount.mount(peer, &service).await?,
            None => warn!(bond, "channel is driven without a peer route"),
        }
        Ok(())
    }
}

/// The clock, over every paid-work journal this node owns.
pub struct WorkRunner {
    config: WorkRunnerConfig,
    adopt: tokio::sync::mpsc::Receiver<SetupClock>,
    sender: tokio::sync::mpsc::Sender<SetupClock>,
    registry: BTreeMap<EdgeId, SetupService>,
    clocks: Vec<SetupClock>,
    signer: Secp256k1Signer,
    work_mount: MountedWork,
    setup_mount: MountedSetup,
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
    /// are still driven through close. Unreadable or unbound journals fail
    /// startup before content recovery can permit collection.
    pub async fn discover(
        config: WorkRunnerConfig,
        work_mount: MountedWork,
        setup_mount: MountedSetup,
    ) -> Result<Self, PaidProviderError> {
        let found = discover_setups(&config.journal_root(), config.network())
            .await
            .map_err(|source| PaidProviderError::Discover {
                path: config.journal_root().into_path_buf(),
                source,
            })?;
        if !found.unidentified.is_empty() {
            return Err(PaidProviderError::InvalidOffer);
        }
        let journal_root = config.journal_root();
        // Every initialized channel must be claimed before the global disk
        // recovery barrier can permit collection or new reservations.
        use hellas_channel::work_store::journal::{Journal, JournalKind};
        let mut unmatched = BTreeMap::new();
        for stem in Journal::stems(&journal_root)
            .map_err(hellas_channel::work_store::WorkStoreError::from)?
        {
            if !stem.starts_with("channel-") {
                continue;
            }
            let (identity, replay) = Journal::inspect(&journal_root, &stem)
                .await
                .map_err(hellas_channel::work_store::WorkStoreError::from)?;
            if identity.kind != JournalKind::Channel
                || stem != format!("channel-{}", hex::encode(identity.key))
            {
                return Err(PaidProviderError::UnmatchedChannel {
                    path: Journal::path(&journal_root, &stem),
                });
            }
            if replay.checkpoint.is_some() || !replay.records.is_empty() {
                unmatched.insert(identity.key, Journal::path(&journal_root, &stem));
            }
        }
        let mut clocks = Vec::new();
        let mut registry = BTreeMap::new();
        for setup in found
            .setups
            .into_iter()
            .filter(|s| s.role == Role::Provider)
        {
            let store = SetupStore::open(
                &config.journal_root(),
                config.network(),
                setup.bond_edge,
                Role::Provider,
                &Secp256k1Verifier::new(),
            )
            .await?;
            let recovered = match (
                store.state().origin(),
                store.state().close_descriptor(),
                &setup_mount.2,
            ) {
                (Some(origin), Some(descriptor), Some(content)) => Box::pin(ChannelStore::recover(
                    &journal_root,
                    descriptor.channel().clone(),
                    Role::Provider,
                    content.clone(),
                    &Secp256k1Verifier::new(),
                ))
                .await?
                .map(|store| (store, origin)),
                _ => None,
            };
            let mut clock = Self::adopt_setup(&config, store, &setup_mount)?;
            if let Driven::Setup { service, .. } = &clock.driven {
                registry.insert(setup.bond_edge, service.clone());
            }
            if let Some((store, origin)) = recovered {
                unmatched.remove(&ChannelStore::journal_key(store.state().channel()));
                let policy = match &clock.driven {
                    Driven::Setup { policy, .. } => policy.clone(),
                    _ => unreachable!(),
                };
                clock
                    .take_mount(store, &config.settlement_key, &policy, &work_mount, origin)
                    .await?;
                if let Some(peer) = clock.route_peer {
                    setup_mount.clear(peer, clock.bond_edge).await?;
                }
            }
            clocks.push(clock);
        }
        if let Some((_, path)) = unmatched.into_iter().next() {
            return Err(PaidProviderError::UnmatchedChannel { path });
        }
        let (sender, adopt) = tokio::sync::mpsc::channel(16);
        Ok(Self {
            signer: config.settlement_key.clone(),
            clocks,
            work_mount,
            setup_mount,
            config,
            sender,
            adopt,
            registry,
        })
    }

    fn adopt_setup(
        config: &WorkRunnerConfig,
        mut store: SetupStore,
        setup_mount: &MountedSetup,
    ) -> Result<SetupClock, PaidProviderError> {
        let (peer, offer) = store
            .state()
            .offer()
            .ok_or(PaidProviderError::InvalidOffer)?;
        if offer.offer().proposal.bond_terms().parties.maker().signer()
            != config.settlement_key.party_key()
        {
            return Err(PaidProviderError::InvalidOffer);
        }
        let peer = PeerId::from_bytes(*peer);
        let bond_edge = offer.offer().proposal.bond_edge();
        let policy = Box::new(offer.offer().policy.clone());
        if let Some(content) = &setup_mount.2 {
            store.set_content_store(content.clone());
        }
        let service = SetupService::new(SetupEndpoint::new(
            store,
            config.settlement_key.clone(),
            PaymentAdmission::Admits(policy.clone()),
        ));
        setup_mount.mount(peer, bond_edge, &service)?;
        Ok(SetupClock {
            busy: false,
            bond_edge,
            route_peer: Some(peer),
            driven: Driven::Setup { service, policy },
        })
    }

    /// One poll: every journal's read in as few proof reads as the key
    /// limit allows, then one step of each journal from its own read.
    /// Returns false when the chain did not answer, or answered too old,
    /// so the caller redials another validator.
    pub async fn tick<S>(&mut self, source: &S) -> bool
    where
        S: FinalizedWorkView + TxSink + Sync,
    {
        while let Ok(clock) = self.adopt.try_recv() {
            self.clocks.push(clock);
        }
        self.clocks
            .retain(|clock| !matches!(clock.driven, Driven::Done));
        let mut asked = Vec::new();
        for (index, clock) in self.clocks.iter().enumerate() {
            if let Some(question) = clock.asked().await {
                asked.push((index, question));
            }
        }
        if asked.is_empty() {
            return true;
        }
        let queries = asked.iter().map(|(_, question)| question.query()).collect();
        let snapshots =
            match tokio::time::timeout(MAX_CERTIFIED_AGE, source.work_channel_snapshots(queries))
                .await
            {
                Ok(Ok(snapshots)) => snapshots,
                Ok(Err(error)) => {
                    warn!(%error, "the channels' certified read failed");
                    return false;
                }
                Err(_) => {
                    warn!("the channels' certified read outlived its age bound");
                    return false;
                }
            };
        for ((index, question), snapshot) in asked.iter().zip(snapshots) {
            let Some(snapshot) = snapshot else {
                return false;
            };
            let Some(clock) = self.clocks.get_mut(*index) else {
                continue;
            };
            if !clock
                .tick(
                    question,
                    &snapshot,
                    &BoundedSink(source),
                    &self.signer,
                    &self.work_mount,
                    &self.setup_mount,
                )
                .instrument(hellas_rpc::request_span!(target: "hellas_request", parent: None, "paid.channel.observe", hellas.channel.role = "provider"))
                .await
            {
                // The source failed: stop here and let the loop redial
                // rather than wait it out once per journal.
                return false;
            }
        }
        true
    }

    /// Suspends every channel's admission while no fresh read can arrive.
    async fn suspend_all(&self) {
        for clock in &self.clocks {
            if let Driven::Channel(channel) = &clock.driven {
                let _ = channel.service.suspend().await;
            }
        }
    }

    /// Drives every journal over whatever `dial` connects to, redialling
    /// when a poll fails.
    ///
    /// Every [`POLL`] — the interval the response window is sized for —
    /// and every [`SETUP_POLL`] while a setup is waiting on an Open or a
    /// channel has a contest live or a transaction in flight.
    pub async fn run_over<S, D, F>(
        mut self,
        mut stop: oneshot::Receiver<()>,
        dial: D,
    ) -> Result<(), MountError>
    where
        S: FinalizedWorkView + TxSink + Sync,
        D: Fn() -> F,
        F: core::future::Future<Output = Option<S>>,
    {
        let mut chain = None;
        loop {
            if chain.is_none() {
                chain = tokio::select! {
                    biased;
                    _ = &mut stop => break,
                    dialed = dial() => dialed,
                };
            }
            if let Some(source) = chain.as_ref()
                && !self.tick(source).await
            {
                self.suspend_all().await;
                chain = None;
            }
            let poll = if self
                .clocks
                .iter()
                .any(|clock| clock.busy || matches!(clock.driven, Driven::Setup { .. }))
            {
                SETUP_POLL
            } else {
                POLL
            };
            #[expect(
                clippy::disallowed_methods,
                reason = "inventory class B/C: the certified-read poll the response window is sized for"
            )]
            let wait = tokio::time::sleep(poll);
            tokio::select! {
                biased;
                _ = &mut stop => break,
                Some(clock) = self.adopt.recv() => self.clocks.push(clock),
                () = wait => {}
            }
        }
        self.adopt.close();
        while self.adopt.try_recv().is_ok() {}
        let result = self.unmount_all().await;
        info!("the paid-work clock stopped, and its journals are closed");
        result
    }

    async fn unmount_all(&self) -> Result<(), MountError> {
        let offers = match self.setup_mount.1.get() {
            Some(offers) => offers.shutdown().await,
            None => Ok(()),
        };
        let work = self.work_mount.clear_all().await;
        let setup = self.setup_mount.clear_all().await;
        offers.and(work).and(setup)
    }

    /// Binds the clock and the automatic offers to the configured chain.
    pub fn on_chain(
        self,
        chain: crate::work_config::WorkConfig,
        authority: hellas_authority::node::NodeCoordinator,
        provider: hellas_rpc::ProviderEnrollmentBundle,
        addresses: Vec<String>,
    ) -> ChainWorkRunner {
        self.setup_mount
            .1
            .set(AutomaticOffers::spawn(OfferAllocator {
                needs_restart: Default::default(),
                config: self.config.clone(),
                chain: offers::OfferChain::new(chain.clone()),
                authority,
                provider,
                addresses,
                registry: Arc::new(tokio::sync::Mutex::new(self.registry.clone())),
                adopt: self.sender.clone(),
                mount: MountedSetup(
                    self.setup_mount.0.clone(),
                    Default::default(),
                    self.setup_mount.2.clone(),
                ),
            }))
            .unwrap_or_else(|_| panic!("offer service already installed"));
        ChainWorkRunner {
            runner: self,
            chain,
        }
    }
}

/// The chain a journal step submits to, with the same bound as a read.
///
/// One loop drives every journal, so a submission the source never answers
/// would stall every channel's watcher behind it. A source that does not
/// answer within [`MAX_CERTIFIED_AGE`] is a failed source: the step reports
/// it and the loop redials.
struct BoundedSink<'a, S>(&'a S);

impl<S: TxSink + Sync> TxSink for BoundedSink<'_, S> {
    async fn submit(
        &self,
        tx: hellas_kernel::Tx,
    ) -> Result<hellas_rpc::SubmitTxOutcome, hellas_channel::work_close::BlockSourceError> {
        tokio::time::timeout(MAX_CERTIFIED_AGE, self.0.submit(tx))
            .await
            .unwrap_or_else(|_| {
                Err(hellas_channel::work_close::BlockSourceError::new(
                    "the chain did not take the transaction within the certified-age bound",
                ))
            })
    }
}

/// A provider clock bound to remote, proof-checked reads of its chain.
pub struct ChainWorkRunner {
    runner: WorkRunner,
    chain: crate::work_config::WorkConfig,
}

impl ChainWorkRunner {
    /// Runs the clock until `stop`, dialling the next configured validator
    /// whenever a read fails or is too old to act on.
    pub async fn run(self, stop: oneshot::Receiver<()>) -> Result<(), MountError> {
        let config = Mutex::new(self.chain);
        self.runner
            .run_over(stop, || {
                let config = match config.lock() {
                    Ok(mut config) => {
                        config.chain.rotate_validators();
                        config.clone()
                    }
                    Err(error) => error.into_inner().clone(),
                };
                async move {
                    match crate::client_chain::connect_at(&config, MAX_CERTIFIED_AGE, 0).await {
                        Ok(remote) => Some(WorkBlocks::new(remote)),
                        Err(error) => {
                            warn!(%error, "no verified chain source answered");
                            None
                        }
                    }
                }
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{PaidFixture, accept_uploaded};
    use hellas_channel::work_store::JobPhase;

    /// Every durable acceptance is dispatched after a restart, not only
    /// a lone one. The running gate is the duplicate-execution barrier;
    /// this asserts the clock reaches it for each job.
    #[tokio::test]
    async fn restart_dispatches_every_accepted_job() {
        let fixture = PaidFixture::new();
        let service = fixture.provider().await;
        use hellas_channel::work::ClientChannel as _;
        let mut client = fixture.client().await;
        let mut accepted = Vec::new();
        for _ in 0..2 {
            let request = client
                .propose(
                    &fixture.proposal(),
                    &hellas_channel::test_support::channel::program_content().await,
                    None,
                )
                .await
                .unwrap();
            let response = accept_uploaded(&fixture, &service, &client, &request).await;
            accepted.push(
                client
                    .client()
                    .await
                    .unwrap()
                    .accepted(&response)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(
            service
                .with_state(|state| state
                    .jobs()
                    .filter(|job| job.phase() == JobPhase::Accepted)
                    .count())
                .await
                .unwrap(),
            2
        );

        let (seen, mut dispatched) = tokio::sync::mpsc::unbounded_channel();
        let driver = AcceptedWorkDriver(
            Arc::new(move |_service, _ready, work_id| {
                let seen = seen.clone();
                Box::pin(async move {
                    seen.send(work_id).unwrap();
                    Ok(RunOutcome::Running)
                })
            }),
            Default::default(),
        );
        let channel = DrivenChannel {
            service,
            descriptor: Some(fixture.descriptor.clone()),
            driver: Some(driver),
        };
        assert!(channel.resume_accepted().await.unwrap());

        let mut reached = Vec::new();
        while reached.len() < accepted.len() {
            reached.push(
                tokio::time::timeout(std::time::Duration::from_secs(5), dispatched.recv())
                    .await
                    .expect("every accepted job is dispatched")
                    .unwrap(),
            );
        }
        reached.sort();
        accepted.sort();
        assert_eq!(reached, accepted);
    }

    #[tokio::test]
    async fn poisoned_mounts_are_errors_and_shutdown_still_releases_channels() {
        use hellas_wire::{AuthLevel, PeerIdentity};
        let fixture = crate::test_support::PaidFixture::new();
        let service = fixture.provider().await;
        let channel = fixture.descriptor.channel().id();
        let peer = PeerId::from_bytes([1; 32]);
        let context = TransportContext {
            peer: Some(PeerIdentity(peer.into_bytes())),
            auth_level: AuthLevel::Vouched,
            ..TransportContext::default()
        };
        let mount = MountedWork::default();
        mount.mount(peer, &service).await.unwrap();
        // Cancellation while suspension waits must retain the registered channel.
        use hellas_channel::work_close::CloseChannel as _;
        let mut driver = service.drive().unwrap();
        let held = driver.store().await.unwrap();
        let mut clearing = Box::pin(mount.clear_all());
        assert!(futures::poll!(clearing.as_mut()).is_pending());
        drop(clearing);
        assert!(mount.service(&context, channel).unwrap().is_some());
        drop(held);
        drop(driver);
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
            mount.mount(peer, &service).await,
            Err(MountError::Poisoned)
        ));
        assert!(matches!(mount.clear_all().await, Err(MountError::Poisoned)));
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
        assert!(matches!(
            setups.clear_all().await,
            Err(MountError::Poisoned)
        ));
    }
}
