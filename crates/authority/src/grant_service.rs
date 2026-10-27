//! Grant funding on Work. One provider writer owns authority and accounting;
//! bounded RAM owns bodies. Executor admission is reserved before co-signing.
use crate::model::grant::records::grant_producer;
use crate::model::grant::{
    ChannelClient, ChannelId, GrantJobAuthorizationV1,
    budget::Usage,
    grant_work_id,
    records::{GrantError, GrantPolicy},
    standing::StandingLocator,
};
use futures::{FutureExt, future::BoxFuture};
use hellas_auth::authority::UnixMillis;
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, Signature};
use hellas_channel::model::profile::{PreparedWorkInput, WorkContext};
use hellas_channel::model::work::{PrivateRecord, bound_result_digest, encode_transcript};
use hellas_channel::work::admission::{CapacityDomain, WorkAdmission, WorkPermit};
use hellas_channel::work::{
    BackendFault, PaidProgress, PaidResultStream, PreparedEvaluateInput, PreparedFetchInput,
    WorkBackend,
};
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::pb::work::Refusable;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, GetStandingRequest, GetStandingResponse,
    GrantRefusal, GrantRefusalCode, GrantTerminalMetadata, GrantTerminalState, WorkAccepted,
    WorkDelivered, WorkRefused, WorkRoute, WorkStreamEvent, WorkStreamTerminal,
    accept_work_response, deliver_result_response, get_standing_response, work_stream_event,
};
use hellas_wire::{TransportContext, WireStatus};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use {
    crate::work_store::grant::GrantOutcome, crate::work_store::grant::GrantTerminal,
    crate::work_store::grant::NodeStore, crate::work_store::grant::NodeStoreError,
    crate::work_store::grant::SignedResult, crate::work_store::grant::refusal::refused,
    hellas_channel::work_store::JobPhase,
};
mod access;
mod cache;
mod delivery;
pub(crate) use access::Access;
mod upload;
pub use access::{GrantWork, WORK_EXECUTE, allowance_resource};
pub(crate) use cache::ResultCache;
pub(crate) use delivery::Delivery;

const MAX_RAM: usize = 64 << 20;
fn event_ram(event: &OutputEventEnvelope) -> usize {
    event.payload().len().saturating_mul(2).saturating_add(1024)
}
fn transcript_ram(events: &[OutputEventEnvelope]) -> usize {
    events.iter().fold(0usize, |bytes, event| {
        bytes.saturating_add(event_ram(event))
    })
}
type Admit = dyn Fn(CapacityDomain) -> Result<WorkPermit, BackendFault> + Send + Sync;
type Run = dyn Fn(
        PreparedWorkInput,
        GrantPolicy,
        WorkAdmission,
        PaidProgress,
    ) -> BoxFuture<'static, Result<Vec<OutputEventEnvelope>, BackendFault>>
    + Send
    + Sync;
pub type GrantClock = Arc<dyn Fn() -> UnixMillis + Send + Sync>;

#[derive(Clone)]
pub struct GrantService {
    node: crate::node::NodeCoordinator,
    inner: Arc<Mutex<Runtime>>,
    signer: Arc<ProducerSigningKey>,
    admit: Arc<Admit>,
    run: Arc<Run>,
    draining: Arc<tokio::sync::Mutex<()>>,
    addresses: Arc<Vec<String>>,
    upload_quota: hellas_channel::content::UploadQuota,
}
struct Runtime {
    uploads: BTreeMap<Digest, hellas_channel::content::UploadStore>,
    live: BTreeMap<Digest, Live>,
    status: ServiceStatus,
    tasks: BTreeMap<Digest, tokio::task::JoinHandle<()>>,
}
struct Live {
    authorization: GrantJobAuthorizationV1,
    policy: GrantPolicy,
    cache: Arc<ResultCache>,
    prefix: cache::Prefix,
    reserved_ram: usize,
    phase: LivePhase,
}
impl Live {
    fn ram(&self) -> usize {
        if self.phase.active() {
            self.reserved_ram
        } else {
            self.cache.bytes()
        }
    }
}
enum ServiceStatus {
    Serving,
    Draining,
    Stopped,
    Failed(Arc<NodeStoreError>),
}
impl ServiceStatus {
    fn check(&self) -> Result<(), NodeStoreError> {
        match self {
            Self::Failed(source) => Err(NodeStoreError::Completion(source.clone())),
            _ => Ok(()),
        }
    }
}
impl Runtime {
    fn discard(&mut self) {
        for live in self.live.values() {
            live.cache.cancel();
        }
        self.uploads.clear();
    }
    fn fail(&mut self, error: NodeStoreError) {
        self.discard();
        if !matches!(self.status, ServiceStatus::Failed(_)) {
            self.status = ServiceStatus::Failed(Arc::new(error));
        }
    }
    fn reap(&mut self) {
        let mut failure = None;
        self.tasks.retain(|_, task| {
            if !task.is_finished() {
                return true;
            }
            match task.now_or_never() {
                Some(Ok(())) => false,
                Some(Err(error)) => {
                    failure = Some(error);
                    false
                }
                None => true,
            }
        });
        if let Some(error) = failure {
            self.fail(error.into());
        }
    }
}
enum LivePhase {
    Queued,
    Running { started: Instant },
    Completing,
    Finished(SignedResult),
    Refused(GrantRefusalCode),
}
impl LivePhase {
    fn active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running { .. } | Self::Completing)
    }
    fn started(&self) -> Option<Instant> {
        match self {
            Self::Running { started } => Some(*started),
            _ => None,
        }
    }
    fn result(&self) -> Option<&SignedResult> {
        match self {
            Self::Finished(result) => Some(result),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ExecutionError {
    #[error("grant input does not match its execution policy")]
    Profile,
    #[error("grant is no longer dispatchable")]
    NotDispatchable,
    #[error("grant input is missing")]
    MissingInput,
    #[error("backend ran without dispatch admission")]
    NotDispatched,
    #[error("grant output exceeds its resource bound")]
    OutputBound,
    #[error("grant execution deadline passed")]
    Deadline,
    #[error("grant backend panicked; sensitive details suppressed")]
    Panicked,
}

#[derive(Debug, thiserror::Error)]
enum CompletionError {
    #[error("provider is not configured")]
    ProviderUnavailable,
    #[error(transparent)]
    Backend(#[from] BackendFault),
    #[error("backend transcript differs from the streamed prefix")]
    Prefix,
    #[error("backend transcript exceeds the signed spool bound")]
    Spool,
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Transcript(#[from] hellas_channel::model::work::PaidWorkError),
    #[error(transparent)]
    Signature(#[from] hellas_auth::signature::SignatureError),
}

impl GrantService {
    pub fn with_upload_quota(mut self, quota: hellas_channel::content::UploadQuota) -> Self {
        self.upload_quota = quota;
        self
    }
    /// Shares this exact writer; the returned interface still requires an
    /// authenticated application caller for every authority mutation.
    pub fn node(&self) -> crate::node::NodeCoordinator {
        self.node.clone()
    }
    pub fn new<B: WorkBackend + Send + Sync + 'static>(
        store: NodeStore,
        signer: Arc<ProducerSigningKey>,
        backend: B,
        addresses: Vec<String>,
        clock: GrantClock,
    ) -> Result<Self, NodeStoreError> {
        if signer.public_key()
            != PublicKey::Secp256k1(grant_producer(store.state().provider()?)?.to_bytes())
        {
            return Err(GrantError::Signature.into());
        }
        Ok(Self::build(
            crate::node::NodeCoordinator::new(store, clock),
            signer,
            backend,
            addresses,
        ))
    }

    /// Attach execution to the host's existing writer. Restarting a provider
    /// never reopens or reinitializes that authority.
    pub async fn from_node<B: WorkBackend + Send + Sync + 'static>(
        node: crate::node::NodeCoordinator,
        enrollment: &hellas_rpc::ProviderEnrollmentBundle,
        signer: Arc<ProducerSigningKey>,
        backend: B,
        addresses: Vec<String>,
    ) -> Result<Self, NodeStoreError> {
        node.check_provider(enrollment).await?;
        if signer.public_key() != PublicKey::Secp256k1(grant_producer(enrollment)?.to_bytes()) {
            return Err(GrantError::Signature.into());
        }
        Ok(Self::build(node, signer, backend, addresses))
    }

    fn build<B: WorkBackend + Send + Sync + 'static>(
        node: crate::node::NodeCoordinator,
        signer: Arc<ProducerSigningKey>,
        backend: B,
        addresses: Vec<String>,
    ) -> Self {
        // NodeStore already requires initialized authority. Losing an administrator
        // does not cancel the node's persistent assignments or settlement duties.
        let backend = Arc::new(backend);
        let capacity = backend.clone();
        let run = Arc::new(move |input, policy: GrantPolicy, admission, progress| {
            let backend = backend.clone();
            Box::pin(async move {
                let input = match (input, policy.work) {
                    (PreparedWorkInput::Evaluate(input), _) => PreparedEvaluateInput::admitted(
                        input.parts().map_err(BackendFault::caused_by)?,
                        admission,
                    )
                    .into(),
                    (
                        PreparedWorkInput::Fetch(input),
                        hellas_channel::model::profile::WorkPolicy::Fetch { policy, .. },
                    ) => PreparedFetchInput::admitted(
                        input.parts().map_err(BackendFault::caused_by)?,
                        policy,
                        admission,
                    )
                    .into(),
                    _ => return Err(BackendFault::caused_by(ExecutionError::Profile)),
                };
                backend.execute_stream(input, progress).await
            }) as BoxFuture<'static, _>
        });
        Self {
            node,
            inner: Arc::new(Mutex::new(Runtime {
                uploads: BTreeMap::new(),
                live: BTreeMap::new(),
                status: ServiceStatus::Serving,
                tasks: BTreeMap::new(),
            })),
            signer,
            admit: Arc::new(move |domain| capacity.try_admit(domain)),
            run,
            draining: Arc::new(tokio::sync::Mutex::new(())),
            addresses: Arc::new(addresses),
            upload_quota: Default::default(),
        }
    }
    /// Internal serialized driver access. Public administration verifies its caller.
    /// The callback holds the writer; await only local store operations here.
    pub(crate) async fn administer<T>(
        &self,
        op: impl AsyncFnOnce(&mut NodeStore, UnixMillis) -> Result<T, NodeStoreError>,
    ) -> Result<T, NodeStoreError> {
        let _changed = crate::node::ChangeNotification(self.node.changed.clone());
        let (mut store, now) = self.node.lock().await?;
        self.inner
            .lock()
            .map_err(|_| NodeStoreError::WriterPoisoned)?
            .status
            .check()?;
        let result = op(&mut store, now).await.map_err(|error| {
            // Preserve the first durable failure until replay.
            if matches!(
                &error,
                NodeStoreError::Journal(
                    hellas_channel::work_store::journal::JournalError::Io(_)
                        | hellas_channel::work_store::journal::JournalError::Sqlx(_)
                        | hellas_channel::work_store::journal::JournalError::Poisoned
                )
            ) {
                let source = Arc::new(error);
                if let Ok(mut held) = self.inner.lock()
                    && !matches!(held.status, ServiceStatus::Failed(_))
                {
                    held.discard();
                    held.status = ServiceStatus::Failed(source.clone());
                }
                NodeStoreError::Completion(source)
            } else {
                error
            }
        });
        drop(store);
        result
    }
    async fn standing(&self, access: &Access, request: &GetStandingRequest) -> GetStandingResponse {
        let mut decision = access.decision("work.standing");
        let result: Result<Vec<u8>, WorkRefused> = async {
            let locator = StandingLocator::decode(&request.locator)
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            let store = self.node.writer().await?;
            access.observe(&mut decision, &store, self.node.observed_time(&store));
            access.authorize(&store, locator.grant, self.node.observed_time(&store))?;
            if Some(locator.client)
                != ChannelClient::of(access.caller(&store, self.node.observed_time(&store))?).ok()
            {
                return Err(refused(GrantRefusalCode::Unauthorized));
            }
            self.inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .status
                .check()?;
            if !request
                .route
                .as_ref()
                .is_some_and(|r| r.selects_grant(locator.channel(store.state().network()).0))
            {
                return Err(refused(GrantRefusalCode::Unauthorized));
            }
            let standing = store.standing(
                locator,
                &self.signer,
                self.addresses.as_ref().clone(),
                (self.node.clock)(),
            )?;
            access.authorize(&store, locator.grant, self.node.observed_time(&store))?;
            standing
                .encode()
                .map_err(|_| refused(GrantRefusalCode::StateCapacity))
        }
        .await;
        GetStandingResponse {
            outcome: Some(match decision.finish_work(result) {
                Ok(bytes) => get_standing_response::Outcome::Standing(bytes),
                Err(refusal) => get_standing_response::Outcome::Refused(refusal),
            }),
        }
    }
    async fn accept(&self, access: &Access, request: &AcceptWorkRequest) -> AcceptWorkResponse {
        let result = self.accept_inner(access, request).await;
        AcceptWorkResponse {
            outcome: Some(match result {
                Ok(accepted) => accept_work_response::Outcome::Accepted(accepted),
                Err(refusal) => accept_work_response::Outcome::Refused(refusal),
            }),
        }
    }
    async fn accept_inner(
        &self,
        access: &Access,
        request: &AcceptWorkRequest,
    ) -> Result<WorkAccepted, WorkRefused> {
        let mut decision = access.decision("work.accept");
        let result = async {
            let a = GrantJobAuthorizationV1::decode(&request.authorization)
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            let client_signature = signature(&request.client_signature)?;
            let mut store = self.node.writer().await?;
            access.observe(&mut decision, &store, self.node.observed_time(&store));
            access.authorize(&store, a.grant_id, self.node.observed_time(&store))?;
            authorize_route(a.channel_id, request.route.as_ref())?;
            self.inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .reap();
            let now = self.node.observed_time(&store);
            let id = grant_work_id(store.state().network(), &a);
            let caller = access.caller(&store, now)?;
            let client = ChannelClient::of(caller).map_err(NodeStoreError::from)?;
            if let Some(signature) = store
                .precheck_acceptance(&a, client, &client_signature, now)
                .await?
            {
                access.authorize(&store, a.grant_id, self.node.observed_time(&store))?;
                return Ok(accepted(id, signature));
            }
            // Refresh after the durable probe; its wait must not extend the job deadline.
            let observed_at = Instant::now();
            let now = self.node.observed_time(&store);
            access.authorize(&store, a.grant_id, now)?;
            let reference =
                hellas_rpc::protocol::content_upload::decode_reference(&request.prepared_input)
                    .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
            let prepared_input = self
                .inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .uploads
                .get(&a.channel_id.0)
                .ok_or_else(|| refused(GrantRefusalCode::Malformed))?
                .read(id, reference)
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            let (policy, reserve) = {
                let mut held = self
                    .inner
                    .lock()
                    .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                held.status.check()?;
                if !matches!(held.status, ServiceStatus::Serving) {
                    return Err(refused(GrantRefusalCode::QueueCapacity));
                }
                held.live.retain(|_, l| {
                    l.phase.active()
                        || (l.authorization.delivery_deadline_ms >= now && l.cache.retained())
                });
                let policy = store.state().policy_for(&a)?.clone();
                let reserve = prepared_input.len().saturating_add(
                    policy
                        .work
                        .max_spool_bytes()
                        .try_into()
                        .unwrap_or(usize::MAX),
                );
                if held.live.len() >= 256
                    || held
                        .live
                        .values()
                        .fold(reserve, |n, l| n.saturating_add(l.ram()))
                        > MAX_RAM
                {
                    return Err(refused(GrantRefusalCode::StateCapacity));
                }
                (policy, reserve)
            };
            let domain = match policy.work {
                hellas_channel::model::profile::WorkPolicy::Evaluate(_) => CapacityDomain::Gpu,
                _ => CapacityDomain::Fetch,
            };
            let permit =
                (self.admit)(domain).map_err(|_| refused(GrantRefusalCode::QueueCapacity))?;
            if permit.domain() != domain {
                return Err(refused(GrantRefusalCode::QueueCapacity));
            }
            let input = PreparedWorkInput::decode(
                &prepared_input,
                hellas_channel::content::MAX_CONTENT_BYTES,
            )
            .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            let deadline = observed_at
                .checked_add(Duration::from_millis(
                    a.terminal_deadline_ms.0.saturating_sub(now.0),
                ))
                .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
            let application = access.application(&store, now)?;
            let signature = store
                .accept(application, a, client_signature, &input, &self.signer, now)
                .await?;
            self.inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
                .uploads
                .remove(&a.channel_id.0);
            let cache = ResultCache::new(a.terminal_deadline_ms, self.node.changed.clone());
            let registered_at = self.node.observed_time(&store);
            let cancellation =
                store.register_execution(id, a, access.clone(), &cache, registered_at);
            cache.monitor(self.node.clock.clone());
            let mut held = self
                .inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
            held.live.insert(
                id,
                Live {
                    authorization: a,
                    policy: policy.clone(),
                    cache,
                    prefix: Default::default(),
                    reserved_ram: reserve,
                    phase: LivePhase::Queued,
                },
            );
            let service = self.clone();
            let execution_access = access.clone();
            let admission =
                WorkAdmission::grant(permit, deadline, cancellation.clone(), async move {
                    let mut store = service
                        .node
                        .store
                        .lock()
                        .await
                        .map_err(|_| BackendFault::caused_by(NodeStoreError::WriterPoisoned))?;
                    service
                        .inner
                        .lock()
                        .map_err(|_| BackendFault::caused_by(NodeStoreError::WriterPoisoned))?
                        .status
                        .check()
                        .map_err(BackendFault::caused_by)?;
                    execution_access
                        .authorize(&store, a.grant_id, service.node.observed_time(&store))
                        .map_err(BackendFault::caused_by)?;
                    // Unlike idempotent journal replay, an invocation must consume the
                    // Accepted phase exactly once before any backend preparation.
                    let job = store
                        .state()
                        .channel(a.channel_id)
                        .and_then(|c| c.job_book().job_by_id(id));
                    if job.is_none_or(|j| j.phase() != JobPhase::Accepted) {
                        return Err(BackendFault::caused_by(ExecutionError::NotDispatchable));
                    }
                    let started = Instant::now();
                    let now = service.node.observed_time(&store);
                    let application = execution_access
                        .application(&store, now)
                        .map_err(BackendFault::caused_by)?;
                    store
                        .dispatch(application, a.channel_id, id, now)
                        .await
                        .map_err(BackendFault::caused_by)?;
                    service
                        .inner
                        .lock()
                        .map_err(|_| BackendFault::caused_by(NodeStoreError::WriterPoisoned))?
                        .live
                        .get_mut(&id)
                        .ok_or_else(|| BackendFault::caused_by(ExecutionError::MissingInput))?
                        .phase = LivePhase::Running { started };
                    Ok(())
                });
            let service = self.clone();
            let progress_service = self.clone();
            let progress = Arc::new(move |event| progress_service.progress(id, event));
            let task = tokio::spawn(async move {
                let execution =
                    async { (service.run)(input.clone(), policy, admission, progress).await };
                let execution = std::panic::AssertUnwindSafe(execution).catch_unwind();
                tokio::pin!(execution);
                let output = tokio::select! {
                    result = &mut execution => result,
                    () = service.monitor_execution(id, cancellation) => execution.await,
                }
                .unwrap_or_else(|_| Err(BackendFault::caused_by(ExecutionError::Panicked)));
                if let Err(error) = service.finish(id, &input, output).await {
                    tracing::error!(?id, %error, "grant completion could not be made durable");
                    if let Ok(mut held) = service.inner.lock() {
                        held.fail(error);
                        if let Some(live) = held.live.get_mut(&id) {
                            live.phase = LivePhase::Refused(GrantRefusalCode::StorageUnavailable);
                        }
                    }
                }
                service.node.changed.notify_waiters();
            });
            held.tasks.insert(id, task);
            drop(held);
            Ok(accepted(id, signature))
        }
        .await;
        decision.finish_work(result)
    }
    async fn monitor_execution(
        &self,
        id: Digest,
        cancellation: hellas_channel::work::admission::Cancellation,
    ) {
        loop {
            let changed = self.node.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let expires = match self.node.store.lock().await {
                Ok(store) => store.refresh_execution(id, self.node.observed_time(&store)),
                Err(_) => {
                    cancellation.cancel();
                    return;
                }
            };
            let Some(expires) = expires else {
                return;
            };
            let remaining =
                Duration::from_millis(expires.0.saturating_sub((self.node.clock)().0).max(1));
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep(remaining) => {} }
        }
    }
    fn progress(&self, id: Digest, event: OutputEventEnvelope) -> Result<(), BackendFault> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| BackendFault::caused_by(NodeStoreError::WriterPoisoned))?;
        let live = held
            .live
            .get_mut(&id)
            .ok_or_else(|| BackendFault::caused_by(ExecutionError::MissingInput))?;
        if !matches!(live.phase, LivePhase::Running { .. }) {
            return Err(BackendFault::caused_by(ExecutionError::NotDispatched));
        }
        if (self.node.clock)() > live.authorization.terminal_deadline_ms {
            live.cache.cancel();
            return Err(BackendFault::caused_by(ExecutionError::Deadline));
        }
        if !live.cache.retained_at((self.node.clock)()) {
            return Err(hellas_channel::work::admission::AdmissionError::Cancelled.into());
        }
        let mut body = live.cache.lock().map_err(BackendFault::caused_by)?;
        if !body.retained {
            return Err(hellas_channel::work::admission::AdmissionError::Cancelled.into());
        }
        let charge = event_ram(&event);
        let next = body.bytes.saturating_add(charge);
        if next as u64 > live.policy.work.max_spool_bytes()
            || charge as u64 > live.policy.work.max_encoded_result_frame() as u64
        {
            return Err(BackendFault::caused_by(ExecutionError::OutputBound));
        }
        live.prefix.push(&event).map_err(BackendFault::caused_by)?;
        body.bytes = next;
        body.events.push(event);
        drop(body);
        drop(held);
        self.node.changed.notify_waiters();
        Ok(())
    }
    async fn finish(
        &self,
        id: Digest,
        input: &PreparedWorkInput,
        output: Result<Vec<OutputEventEnvelope>, BackendFault>,
    ) -> Result<(), NodeStoreError> {
        let mut store = self.node.writer().await?;
        let now = self.node.observed_time(&store);
        let (a, phase, usage, completion) = {
            let mut held = self
                .inner
                .lock()
                .map_err(|_| NodeStoreError::WriterPoisoned)?;
            let live = held.live.get_mut(&id).ok_or(GrantError::Unauthorized)?;
            let a = live.authorization;
            let phase = store
                .state()
                .channel(a.channel_id)
                .and_then(|c| c.job_book().job_by_id(id))
                .map(|j| j.phase());
            let verified = if phase
                .is_some_and(|p| matches!(p, JobPhase::Running | JobPhase::Streaming))
            {
                match self.verify_completion(&store, live, id, input, output) {
                    Ok(completion) => Some(completion),
                    Err(error) => {
                        tracing::warn!(?id, %error, "grant execution did not produce a verified result");
                        None
                    }
                }
            } else {
                None
            };
            let usage = verified.as_ref().map_or(Usage::Unknown, |(events, _)| {
                accounting::usage(
                    &live.policy,
                    events,
                    live.phase.started().map(|s| s.elapsed()),
                )
            });
            // Seal progress before persistence, without holding the RAM lock over I/O.
            live.phase = LivePhase::Completing;
            (
                a,
                phase,
                usage,
                verified.filter(|_| now <= a.terminal_deadline_ms),
            )
        };
        if phase == Some(JobPhase::Accepted) {
            store.release(a.channel_id, id, now).await?;
        } else if phase.is_some_and(|p| matches!(p, JobPhase::Running | JobPhase::Streaming)) {
            // Late output cannot satisfy the deadline, but its verified usage
            // still settles at the observed value without faulting a healthy route.
            store
                .finish(
                    a.channel_id,
                    id,
                    if completion.is_some() {
                        GrantOutcome::Finished
                    } else {
                        GrantOutcome::Failed
                    },
                    completion.as_ref().map(|(_, signed)| signed.clone()),
                    usage,
                    now,
                )
                .await?;
        }
        let mut held = self
            .inner
            .lock()
            .map_err(|_| NodeStoreError::WriterPoisoned)?;
        let live = held.live.get_mut(&id).ok_or(GrantError::Unauthorized)?;
        if let Some((events, signed)) = completion {
            let mut body = live.cache.lock()?;
            if body.retained {
                body.bytes = transcript_ram(&events);
                body.events = events;
            }
            live.phase = LivePhase::Finished(signed);
        } else {
            live.cache.cancel();
            live.phase =
                LivePhase::Refused(if phase == Some(JobPhase::Accepted) || phase.is_none() {
                    GrantRefusalCode::Released
                } else {
                    GrantRefusalCode::Indeterminate
                });
        }
        Ok(())
    }
    fn verify_completion(
        &self,
        store: &NodeStore,
        live: &Live,
        id: Digest,
        input: &PreparedWorkInput,
        output: Result<Vec<OutputEventEnvelope>, BackendFault>,
    ) -> Result<(Vec<OutputEventEnvelope>, SignedResult), CompletionError> {
        let events = output?;
        if !live.prefix.matches(&events)? {
            return Err(CompletionError::Prefix);
        }
        let maximum = live.policy.work.max_spool_bytes();
        if transcript_ram(&events) as u64 > maximum
            || encode_transcript(&events)?.len() as u64 > maximum
        {
            return Err(CompletionError::Spool);
        }
        let a = &live.authorization;
        let admission = store
            .state()
            .admission(a.channel_id, id)
            .ok_or(GrantError::Unauthorized)?;
        let context = WorkContext {
            network: store.state().network(),
            channel: a.channel_id.0,
            client: ChannelClient::recorded(admission.accepted().caller())?.signer(),
            provider: grant_producer(
                store
                    .state()
                    .provider()
                    .map_err(|_| CompletionError::ProviderUnavailable)?,
            )?,
        };
        let result =
            live.policy
                .work
                .bound_terminal_result(&context, id, &a.into(), input, &events)?;
        let signature = self.signer.sign_digest(bound_result_digest(
            context.network,
            context.channel,
            &result,
        ))?;
        Ok((events, SignedResult { result, signature }))
    }
    fn stream(&self, access: Access, request: DeliverResultRequest) -> PaidResultStream {
        let service = self.clone();
        self.stream_binding(async move { service.bind_delivery(&access, &request).await })
    }
    fn stream_binding(
        &self,
        binding: impl Future<Output = Result<Arc<Delivery>, WorkRefused>> + Send + 'static,
    ) -> PaidResultStream {
        let service = self.clone();
        PaidResultStream::new(async_stream::stream! {
            let delivery = match binding.await {
                Ok(value) => value,
                Err(refusal) => { yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(refusal)) }); return; }
            };
            let mut position = 0;
            loop {
                let changed = service.node.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let wake_at = match service.stream_update(&delivery, position).await {
                    Ok((Some(event), _)) => {
                        let done = matches!(event.outcome, Some(work_stream_event::Outcome::Terminal(_)));
                        if !done { position += 1; }
                        yield Ok(event);
                        if done { return; }
                        // Polling again must check the current allowance before copying
                        // another buffered event, including an already finished result.
                        continue;
                    }
                    Ok((None, wake_at)) => wake_at,
                    Err(refusal) => { yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(refusal)) }); return; }
                };
                let remaining = Duration::from_millis(wake_at.0.saturating_sub((service.node.clock)().0).max(1));
                tokio::select! {
                    _ = changed => {},
                    _ = delivery.cancellation().cancelled() => {},
                    _ = tokio::time::sleep(remaining) => {},
                }
            }
        })
    }
    async fn stream_update(
        &self,
        delivery: &Delivery,
        position: usize,
    ) -> Result<(Option<WorkStreamEvent>, UnixMillis), WorkRefused> {
        let store = self.node.writer().await?;
        let held = self
            .inner
            .lock()
            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
        held.status.check()?;
        let now = self.node.observed_time(&store);
        let wake_at = delivery.refresh(&store, now)?;
        let id = delivery.id;
        let live = held.live.get(&id).ok_or_else(|| {
            store
                .state()
                .channel(delivery.authorization.channel_id)
                .and_then(|c| c.job_book().terminal_by_id(id))
                .map_or_else(
                    || refused(GrantRefusalCode::OutputUnavailable),
                    |t| terminal_refusal(id, &t.outcome),
                )
        })?;
        if let LivePhase::Refused(code) = live.phase {
            return Err(store
                .state()
                .channel(live.authorization.channel_id)
                .and_then(|c| c.job_book().terminal_by_id(id))
                .map_or_else(|| refused(code), |t| terminal_refusal(id, &t.outcome)));
        }
        let body = live.cache.lock()?;
        if !body.retained {
            return Err(store
                .state()
                .channel(live.authorization.channel_id)
                .and_then(|c| c.job_book().terminal_by_id(id))
                .map_or_else(
                    || refused(GrantRefusalCode::OutputUnavailable),
                    |t| terminal_refusal(id, &t.outcome),
                ));
        }
        let end = body
            .events
            .len()
            .saturating_sub(usize::from(live.phase.result().is_some()));
        let pending = body
            .events
            .get(position..end)
            .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
        if let Some(event) = pending.first() {
            let prefix = encode_transcript(std::slice::from_ref(event))
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            return Ok((
                Some(WorkStreamEvent {
                    outcome: Some(work_stream_event::Outcome::Prefix(prefix)),
                }),
                wake_at,
            ));
        }
        if let Some(signed) = live.phase.result() {
            let last = body
                .events
                .last()
                .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
            return Ok((
                Some(WorkStreamEvent {
                    outcome: Some(work_stream_event::Outcome::Terminal(WorkStreamTerminal {
                        result: signed.result.encode(),
                        provider_signature: signed.signature.bytes().to_vec(),
                        terminal_transcript: encode_transcript(std::slice::from_ref(last))
                            .map_err(|_| refused(GrantRefusalCode::Malformed))?,
                    })),
                }),
                wake_at,
            ));
        }
        Ok((None, wake_at))
    }
    // A poisoned writer cannot be used again, but its task handles still own
    // physical invocations and must be joined during shutdown.
    fn lock_for_shutdown(&self) -> std::sync::MutexGuard<'_, Runtime> {
        match self.inner.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                let mut held = poisoned.into_inner();
                held.fail(NodeStoreError::WriterPoisoned);
                held
            }
        }
    }
    /// Cancel queued grants, then keep execution owners alive until physical
    /// completion. No endpoint or journal is dropped ahead of these duties.
    pub async fn drain(&self) -> Result<(), NodeStoreError> {
        let _draining = self.draining.lock().await;
        {
            let store = self.node.store.lock().await;
            let accepted = {
                let mut held = self.lock_for_shutdown();
                held.reap();
                if matches!(held.status, ServiceStatus::Serving) {
                    held.status = ServiceStatus::Draining;
                    held.uploads.clear();
                }
                match &store {
                    Ok(store) if held.status.check().is_ok() => held
                        .live
                        .iter()
                        .filter_map(|(id, live)| {
                            store
                                .state()
                                .channel(live.authorization.channel_id)?
                                .job_book()
                                .job_by_id(*id)
                                .filter(|job| job.phase() == JobPhase::Accepted)
                                .map(|_| (live.authorization.channel_id, *id))
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => {
                        held.fail(NodeStoreError::WriterPoisoned);
                        Vec::new()
                    }
                    _ => Vec::new(),
                }
            };
            if let Ok(mut store) = store {
                for (channel, id) in accepted {
                    if let Err(error) = store.release(channel, id, (self.node.clock)()).await {
                        self.lock_for_shutdown().fail(error);
                        break;
                    }
                }
            }
        }
        // Keep handles in the service while joining so cancelling drain never
        // detaches an execution from a later shutdown attempt.
        futures::future::poll_fn(|cx| {
            let mut held = self.lock_for_shutdown();
            let mut failure = None;
            held.tasks.retain(|_, task| match Pin::new(task).poll(cx) {
                Poll::Ready(Ok(())) => false,
                Poll::Ready(Err(error)) => {
                    failure = Some(error);
                    false
                }
                Poll::Pending => true,
            });
            if let Some(error) = failure {
                held.fail(error.into());
            }
            if !held.tasks.is_empty() {
                return Poll::Pending;
            }
            let result = held.status.check();
            if result.is_ok() {
                held.status = ServiceStatus::Stopped;
            }
            Poll::Ready(result)
        })
        .await
    }
}
fn terminal_refusal(id: Digest, terminal: &GrantTerminal) -> WorkRefused {
    let (state, code) = match terminal.outcome {
        GrantOutcome::Finished => (
            GrantTerminalState::Finished,
            GrantRefusalCode::OutputUnavailable,
        ),
        GrantOutcome::Failed => (GrantTerminalState::Failed, GrantRefusalCode::Indeterminate),
        GrantOutcome::Released => (GrantTerminalState::Released, GrantRefusalCode::Released),
        GrantOutcome::Indeterminate => (
            GrantTerminalState::Indeterminate,
            GrantRefusalCode::Indeterminate,
        ),
    };
    WorkRefused {
        grant: Some(GrantRefusal {
            code: code as i32,
            current_revision: 0,
            terminal: Some(Box::new(GrantTerminalMetadata {
                work_id: id.as_bytes().to_vec(),
                state: state as i32,
                result: terminal
                    .result
                    .as_ref()
                    .map_or_else(Vec::new, |r| r.result.encode()),
                provider_signature: terminal
                    .result
                    .as_ref()
                    .map_or_else(Vec::new, |r| r.signature.bytes().to_vec()),
            })),
        }),
        ..refused(code)
    }
}
fn authorize_route(channel: ChannelId, route: Option<&WorkRoute>) -> Result<(), WorkRefused> {
    if !route.is_some_and(|r| r.selects_grant(channel.0)) {
        return Err(refused(GrantRefusalCode::Unauthorized));
    }
    Ok(())
}
fn signature(bytes: &[u8]) -> Result<Signature, WorkRefused> {
    Ok(Signature::Secp256k1(
        bytes
            .try_into()
            .map_err(|_| refused(GrantRefusalCode::Malformed))?,
    ))
}
fn digest(bytes: &[u8]) -> Result<Digest, WorkRefused> {
    Ok(Digest::from_bytes(
        bytes
            .try_into()
            .map_err(|_| refused(GrantRefusalCode::Malformed))?,
    ))
}
fn accepted(id: Digest, signature: Signature) -> WorkAccepted {
    WorkAccepted {
        work_id: id.as_bytes().to_vec(),
        provider_signature: signature.bytes().to_vec(),
    }
}
mod accounting;
mod admin;
pub use admin::WorkAdministration;

impl hellas_rpc::services::work::WorkHandler for GrantWork {
    async fn get_standing(
        &self,
        request: GetStandingRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<GetStandingResponse>> + Send, WireStatus>
    {
        Ok(self.standing(&request).await)
    }
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send, WireStatus>
    {
        Ok(self.accept(&request).await)
    }
    async fn upload_content(
        &self,
        request: hellas_rpc::pb::work::UploadContentRequest,
        context: TransportContext,
    ) -> Result<
        impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::UploadContentResponse>> + Send,
        WireStatus,
    > {
        self.upload(&request, &context).await
    }
    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<PaidResultStream, WireStatus> {
        let delivery = match self.service.bind_delivery(&self.access, &request).await {
            Ok(delivery) => delivery,
            Err(refusal) => {
                return Ok(PaidResultStream::new(futures::stream::once(async move {
                    Ok(WorkStreamEvent {
                        outcome: Some(work_stream_event::Outcome::Refused(refusal)),
                    })
                })));
            }
        };
        Ok(self
            .service
            .stream_binding(futures::future::ready(Ok(delivery.clone())))
            .with_write_authority(self.service.delivery_authority(delivery)))
    }
    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send, WireStatus>
    {
        use futures::StreamExt;
        use hellas_channel::model::work::decode_transcript;
        use hellas_rpc::call::WithTrailer;
        let delivery = match self.service.bind_delivery(&self.access, &request).await {
            Ok(delivery) => delivery,
            Err(refusal) => {
                return Ok(WithTrailer::new(DeliverResultResponse::refused(refusal)));
            }
        };
        let bound = hellas_channel::work_store::journal::MAX_RECORD_BYTES;
        let mut stream = self
            .service
            .stream_binding(futures::future::ready(Ok(delivery.clone())));
        let mut events = Vec::new();
        let mut retained = 0usize;
        let mut outcome =
            deliver_result_response::Outcome::Refused(refused(GrantRefusalCode::OutputUnavailable));
        while let Some(event) = stream.next().await {
            match event?.outcome {
                Some(work_stream_event::Outcome::Prefix(bytes)) => {
                    retained = retained.saturating_add(bytes.len());
                    if retained > bound {
                        break;
                    }
                    let prefix = decode_transcript(&bytes, bound).map_err(|_| {
                        WireStatus::new(hellas_wire::WireCode::Internal, "invalid stored prefix")
                    })?;
                    events.extend(prefix);
                }
                Some(work_stream_event::Outcome::Terminal(terminal)) => {
                    let tail =
                        decode_transcript(&terminal.terminal_transcript, bound).map_err(|_| {
                            WireStatus::new(
                                hellas_wire::WireCode::Internal,
                                "invalid stored terminal",
                            )
                        })?;
                    events.extend(tail);
                    let transcript = encode_transcript(&events).map_err(|_| {
                        WireStatus::new(
                            hellas_wire::WireCode::Internal,
                            "invalid stored transcript",
                        )
                    })?;
                    if transcript.len().saturating_add(1024) > bound {
                        break;
                    }
                    outcome = deliver_result_response::Outcome::Delivered(WorkDelivered {
                        result: terminal.result,
                        provider_signature: terminal.provider_signature,
                        transcript,
                    });
                    break;
                }
                Some(work_stream_event::Outcome::Refused(refusal)) => {
                    outcome = deliver_result_response::Outcome::Refused(refusal);
                    break;
                }
                _ => break,
            }
        }
        Ok(WithTrailer::new(DeliverResultResponse {
            outcome: Some(outcome),
        })
        .with_write_authority(self.service.delivery_authority(delivery)))
    }
    async fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send, WireStatus>
    {
        Ok(AdmitCertificateResponse::refused(refused(
            GrantRefusalCode::Unauthorized,
        )))
    }
}

#[cfg(test)]
mod tests;
