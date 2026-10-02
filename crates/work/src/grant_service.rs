//! Grant funding on Work. One provider writer owns authority and accounting;
//! bounded RAM owns bodies. Executor admission is reserved before co-signing.
use crate::work::admission::{CapacityDomain, WorkAdmission, WorkPermit};
use crate::work::{
    BackendFault, PaidProgress, PaidResultStream, PreparedEvaluateInput, PreparedFetchInput,
    WorkBackend,
};
use crate::work_store::{
    JobPhase,
    grant::{
        GrantConnection, GrantOutcome, GrantStore, GrantStoreError, GrantTerminal, SignedResult,
        refusal::refused,
    },
};
use futures::{FutureExt, future::BoxFuture};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, GetStandingRequest, GetStandingResponse,
    GrantRefusalCode, GrantTerminalMetadata, GrantTerminalState, WorkAccepted, WorkDelivered,
    WorkRefused, WorkRoute, WorkStreamEvent, WorkStreamTerminal, accept_work_response,
    admit_certificate_response, deliver_result_response, get_standing_response, work_stream_event,
};
use hellas_rpc::protocol::work::{
    PrivateRecord, bound_delivery_request_digest, bound_result_digest, encode_transcript,
};
use hellas_rpc::protocol::work_grant::{
    ChannelId, GrantId, GrantJobAuthorizationV1, Revision, UnixMillis,
    budget::Usage,
    grant_work_id,
    records::{GrantDef, GrantError, GrantKind, GrantPolicy, GrantState},
    standing::{StandingLocator, StandingQuery},
};
use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkContext};
use hellas_rpc::{Digest, OutputEventEnvelope, ProducerSigningKey, PublicKey, Signature};
use hellas_wire::{TransportContext, WireStatus};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

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
    inner: Arc<Mutex<Runtime>>,
    signer: Arc<ProducerSigningKey>,
    admit: Arc<Admit>,
    run: Arc<Run>,
    changed: Arc<Notify>,
    draining: Arc<tokio::sync::Mutex<()>>,
    clock: GrantClock,
    addresses: Arc<Vec<String>>,
}
struct Runtime {
    store: GrantStore,
    live: BTreeMap<Digest, Live>,
    status: ServiceStatus,
    tasks: BTreeMap<Digest, tokio::task::JoinHandle<()>>,
}
struct Live {
    authorization: GrantJobAuthorizationV1,
    policy: GrantPolicy,
    events: Vec<OutputEventEnvelope>,
    bytes: usize,
    reserved_ram: usize,
    phase: LivePhase,
}
enum ServiceStatus {
    Serving,
    Draining,
    Stopped,
    Failed(Arc<GrantStoreError>),
}
impl ServiceStatus {
    fn check(&self) -> Result<(), GrantStoreError> {
        match self {
            Self::Failed(source) => Err(GrantStoreError::Completion(source.clone())),
            _ => Ok(()),
        }
    }
}
impl Runtime {
    fn fail(&mut self, error: GrantStoreError) {
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
    Finished(SignedResult),
    Refused(GrantRefusalCode),
}
impl LivePhase {
    fn active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running { .. })
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
    #[error(transparent)]
    Backend(#[from] BackendFault),
    #[error("backend transcript differs from the streamed prefix")]
    Prefix,
    #[error("backend transcript exceeds the signed spool bound")]
    Spool,
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Transcript(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error(transparent)]
    Signature(#[from] hellas_rpc::protocol::signature::SignatureError),
}

pub fn wall_clock() -> UnixMillis {
    UnixMillis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
    )
}
impl GrantService {
    pub fn new<B: WorkBackend + Send + Sync + 'static>(
        store: GrantStore,
        signer: Arc<ProducerSigningKey>,
        backend: B,
        addresses: Vec<String>,
        clock: GrantClock,
    ) -> Result<Self, GrantStoreError> {
        if signer.public_key()
            != PublicKey::Secp256k1(store.state().provider().grant_producer()?.to_bytes())
        {
            return Err(GrantError::Signature.into());
        }
        if !store.state().users().any(|user| {
            user.permissions == hellas_rpc::protocol::work_grant::admin::UserPermissions::Owner
        }) {
            return Err(GrantError::Unauthorized.into());
        }
        let backend = Arc::new(backend);
        let capacity = backend.clone();
        let run = Arc::new(move |input, policy: GrantPolicy, admission, progress| {
            let backend = backend.clone();
            Box::pin(async move {
                match (input, policy.work) {
                    (PreparedWorkInput::Evaluate(input), _) => {
                        backend
                            .evaluate_stream(
                                PreparedEvaluateInput::admitted(
                                    input.parts().map_err(BackendFault::caused_by)?,
                                    admission,
                                ),
                                progress,
                            )
                            .await
                    }
                    (
                        PreparedWorkInput::Fetch(input),
                        hellas_rpc::protocol::work_profile::WorkPolicy::Fetch { policy, .. },
                    ) => {
                        backend
                            .fetch_stream(
                                PreparedFetchInput::admitted(
                                    input.parts().map_err(BackendFault::caused_by)?,
                                    policy,
                                    admission,
                                ),
                                progress,
                            )
                            .await
                    }
                    _ => Err(BackendFault::caused_by(ExecutionError::Profile)),
                }
            }) as BoxFuture<'static, _>
        });
        Ok(Self {
            inner: Arc::new(Mutex::new(Runtime {
                store,
                live: BTreeMap::new(),
                status: ServiceStatus::Serving,
                tasks: BTreeMap::new(),
            })),
            signer,
            admit: Arc::new(move |domain| capacity.try_admit(domain)),
            run,
            changed: Arc::new(Notify::new()),
            draining: Arc::new(tokio::sync::Mutex::new(())),
            clock,
            addresses: Arc::new(addresses),
        })
    }
    /// The local admin handler must authorize before entering this writer.
    pub fn administer<T>(
        &self,
        op: impl FnOnce(&mut GrantStore, UnixMillis) -> Result<T, GrantStoreError>,
    ) -> Result<T, GrantStoreError> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| GrantStoreError::WriterPoisoned)?;
        held.status.check()?;
        let now = (self.clock)().max(held.store.state().now());
        let result = op(&mut held.store, now).map_err(|error| {
            // A failed write/sync leaves permission durability uncertain. Keep
            // the writer failed until replay while retaining the I/O cause.
            if matches!(
                &error,
                GrantStoreError::Journal(
                    crate::work_store::journal::JournalError::Io(_)
                        | crate::work_store::journal::JournalError::Poisoned
                )
            ) {
                let source = Arc::new(error);
                held.status = ServiceStatus::Failed(source.clone());
                GrantStoreError::Completion(source)
            } else {
                error
            }
        });
        drop(held);
        self.changed.notify_waiters();
        result
    }
    pub fn standing(
        &self,
        request: &GetStandingRequest,
        context: &TransportContext,
    ) -> GetStandingResponse {
        let result = (|| -> Result<Vec<u8>, WorkRefused> {
            let query = StandingQuery {
                locator: StandingLocator::decode(&request.locator)
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?,
                signature: signature(&request.client_signature)?,
            };
            let connection = connection(context)?;
            let mut held = self
                .inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
            if held.status.check().is_err() {
                return Err(refused(GrantRefusalCode::StorageUnavailable));
            }
            if !request.route.as_ref().is_some_and(|r| {
                r.selects_grant(query.locator.channel(held.store.state().network()))
            }) {
                return Err(refused(GrantRefusalCode::Unauthorized));
            }
            held.store
                .standing(
                    query,
                    connection,
                    &self.signer,
                    self.addresses.as_ref().clone(),
                    (self.clock)(),
                )
                .map_err(|e| WorkRefused::from(&e))?
                .encode()
                .map_err(|_| refused(GrantRefusalCode::StateCapacity))
        })();
        GetStandingResponse {
            outcome: Some(match result {
                Ok(bytes) => get_standing_response::Outcome::Standing(bytes),
                Err(refusal) => get_standing_response::Outcome::Refused(refusal),
            }),
        }
    }
    pub fn accept(
        &self,
        request: &AcceptWorkRequest,
        context: &TransportContext,
    ) -> AcceptWorkResponse {
        let result = self.accept_inner(request, context);
        AcceptWorkResponse {
            outcome: Some(match result {
                Ok(accepted) => accept_work_response::Outcome::Accepted(accepted),
                Err(refusal) => accept_work_response::Outcome::Refused(refusal),
            }),
        }
    }
    fn accept_inner(
        &self,
        request: &AcceptWorkRequest,
        context: &TransportContext,
    ) -> Result<WorkAccepted, WorkRefused> {
        let a = GrantJobAuthorizationV1::decode(&request.authorization)
            .map_err(|_| refused(GrantRefusalCode::Malformed))?;
        let client_signature = signature(&request.client_signature)?;
        let connection = connection(context)?;
        let mut held = self
            .inner
            .lock()
            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
        authorize_peer(
            &held.store,
            a.channel_id,
            request.route.as_ref(),
            connection.peer,
        )?;
        held.reap();
        let now = (self.clock)().max(held.store.state().now());
        let id = grant_work_id(held.store.state().network(), &a);
        if let Some(signature) = held
            .store
            .precheck_acceptance(&a, &client_signature, now)
            .map_err(|e| WorkRefused::from(&e))?
        {
            return Ok(accepted(id, signature));
        }
        held.status.check().map_err(|e| WorkRefused::from(&e))?;
        if !matches!(held.status, ServiceStatus::Serving) {
            return Err(refused(GrantRefusalCode::QueueCapacity));
        }
        held.live
            .retain(|_, l| l.phase.active() || l.authorization.delivery_deadline_ms >= now);
        let policy = held
            .store
            .state()
            .policy_for(&a)
            .map_err(|e| WorkRefused::from(&e))?
            .clone();
        let reserve = request.prepared_input.len().saturating_add(
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
                .fold(reserve, |n, l| n.saturating_add(l.reserved_ram))
                > MAX_RAM
        {
            return Err(refused(GrantRefusalCode::StateCapacity));
        }
        let domain = match policy.work {
            hellas_rpc::protocol::work_profile::WorkPolicy::Evaluate(_) => CapacityDomain::Gpu,
            _ => CapacityDomain::Fetch,
        };
        let permit = (self.admit)(domain).map_err(|_| refused(GrantRefusalCode::QueueCapacity))?;
        if permit.domain() != domain {
            return Err(refused(GrantRefusalCode::QueueCapacity));
        }
        let input = PreparedWorkInput::decode(
            &request.prepared_input,
            crate::work_store::journal::MAX_RECORD_BYTES,
        )
        .map_err(|_| refused(GrantRefusalCode::Malformed))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(
                a.terminal_deadline_ms.0.saturating_sub(now.0),
            ))
            .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
        let signature = held
            .store
            .accept(a, client_signature, &input, &self.signer, now)
            .map_err(|e| WorkRefused::from(&e))?;
        held.live.insert(
            id,
            Live {
                authorization: a,
                policy: policy.clone(),
                events: vec![],
                bytes: 0,
                reserved_ram: reserve,
                phase: LivePhase::Queued,
            },
        );
        let service = self.clone();
        let admission = WorkAdmission::grant(
            permit,
            deadline,
            Box::new(move || {
                let mut held = service
                    .inner
                    .lock()
                    .map_err(|_| BackendFault::caused_by(GrantStoreError::WriterPoisoned))?;
                held.status.check().map_err(BackendFault::caused_by)?;
                // Unlike idempotent journal replay, an invocation must consume the
                // Accepted phase exactly once before any backend preparation.
                let job = held
                    .store
                    .state()
                    .channel(a.channel_id)
                    .and_then(|c| c.job_book().job_by_id(id));
                if job.is_none_or(|j| j.phase() != JobPhase::Accepted) {
                    return Err(BackendFault::caused_by(ExecutionError::NotDispatchable));
                }
                let started = Instant::now();
                held.store
                    .dispatch(a.channel_id, id, (service.clock)())
                    .map_err(BackendFault::caused_by)?;
                held.live
                    .get_mut(&id)
                    .ok_or_else(|| BackendFault::caused_by(ExecutionError::MissingInput))?
                    .phase = LivePhase::Running { started };
                Ok(())
            }),
        );
        let service = self.clone();
        let progress_service = self.clone();
        let progress = Arc::new(move |event| progress_service.progress(id, event));
        let task = tokio::spawn(async move {
            let execution =
                async { (service.run)(input.clone(), policy, admission, progress).await };
            let output = std::panic::AssertUnwindSafe(execution)
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(BackendFault::caused_by(ExecutionError::Panicked)));
            if let Err(error) = service.finish(id, &input, output) {
                tracing::error!(?id, %error, "grant completion could not be made durable");
                if let Ok(mut held) = service.inner.lock() {
                    held.fail(error);
                    if let Some(live) = held.live.get_mut(&id) {
                        live.phase = LivePhase::Refused(GrantRefusalCode::StorageUnavailable);
                    }
                }
            }
            service.changed.notify_waiters();
        });
        held.tasks.insert(id, task);
        drop(held);
        Ok(accepted(id, signature))
    }
    fn progress(&self, id: Digest, event: OutputEventEnvelope) -> Result<(), BackendFault> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| BackendFault::caused_by(GrantStoreError::WriterPoisoned))?;
        let live = held
            .live
            .get_mut(&id)
            .ok_or_else(|| BackendFault::caused_by(ExecutionError::MissingInput))?;
        if !matches!(live.phase, LivePhase::Running { .. }) {
            return Err(BackendFault::caused_by(ExecutionError::NotDispatched));
        }
        let charge = event_ram(&event);
        let next = live.bytes.saturating_add(charge);
        if next as u64 > live.policy.work.max_spool_bytes()
            || charge as u64 > live.policy.work.max_encoded_result_frame() as u64
        {
            return Err(BackendFault::caused_by(ExecutionError::OutputBound));
        }
        if (self.clock)() > live.authorization.terminal_deadline_ms {
            return Err(BackendFault::caused_by(ExecutionError::Deadline));
        }
        live.bytes = next;
        live.events.push(event);
        drop(held);
        self.changed.notify_waiters();
        Ok(())
    }
    fn finish(
        &self,
        id: Digest,
        input: &PreparedWorkInput,
        output: Result<Vec<OutputEventEnvelope>, BackendFault>,
    ) -> Result<(), GrantStoreError> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| GrantStoreError::WriterPoisoned)?;
        let live = held.live.get(&id).ok_or(GrantError::Unauthorized)?;
        let a = live.authorization;
        let now = (self.clock)().max(held.store.state().now());
        let phase = held
            .store
            .state()
            .channel(a.channel_id)
            .and_then(|c| c.job_book().job_by_id(id))
            .map(|j| j.phase());
        if phase == Some(JobPhase::Accepted) {
            held.store.release(a.channel_id, id, now)?;
        }
        let live = held.live.get(&id).ok_or(GrantError::Unauthorized)?;
        let verified = if phase
            .is_some_and(|p| matches!(p, JobPhase::Running | JobPhase::Streaming))
        {
            match self.verify_completion(&held, live, id, input, output) {
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
        // Late output cannot satisfy the execution deadline, but verified usage
        // still settles at its observed value and must not fault a healthy route.
        let completion = verified.filter(|_| now <= a.terminal_deadline_ms);
        if phase.is_some_and(|p| matches!(p, JobPhase::Running | JobPhase::Streaming)) {
            held.store.finish(
                a.channel_id,
                id,
                if completion.is_some() {
                    GrantOutcome::Finished
                } else {
                    GrantOutcome::Failed
                },
                completion.as_ref().map(|(_, s)| s.clone()),
                usage,
                now,
            )?;
        }
        let live = held.live.get_mut(&id).ok_or(GrantError::Unauthorized)?;
        if let Some((events, signed)) = completion {
            live.bytes = transcript_ram(&events);
            live.events = events;
            live.phase = LivePhase::Finished(signed);
        } else {
            live.phase =
                LivePhase::Refused(if phase == Some(JobPhase::Accepted) || phase.is_none() {
                    GrantRefusalCode::Released
                } else {
                    GrantRefusalCode::Indeterminate
                });
        }
        // Terminal output is immutable. Keep its actual retained charge, not
        // the worst-case spool reservation, through the delivery window.
        live.reserved_ram = live
            .reserved_ram
            .saturating_sub(
                live.policy
                    .work
                    .max_spool_bytes()
                    .try_into()
                    .unwrap_or(usize::MAX),
            )
            .saturating_add(live.bytes);
        Ok(())
    }
    fn verify_completion(
        &self,
        held: &Runtime,
        live: &Live,
        id: Digest,
        input: &PreparedWorkInput,
        output: Result<Vec<OutputEventEnvelope>, BackendFault>,
    ) -> Result<(Vec<OutputEventEnvelope>, SignedResult), CompletionError> {
        let events = output?;
        if !events.starts_with(&live.events) {
            return Err(CompletionError::Prefix);
        }
        let maximum = live.policy.work.max_spool_bytes();
        if transcript_ram(&events) as u64 > maximum
            || encode_transcript(&events)?.len() as u64 > maximum
        {
            return Err(CompletionError::Spool);
        }
        let a = &live.authorization;
        let def = held
            .store
            .state()
            .grant(a.grant_id)
            .ok_or(GrantError::Unauthorized)?;
        let context = WorkContext {
            network: held.store.state().network(),
            channel: a.channel_id.0,
            client: def.kind.principal().producer(),
            provider: held.store.state().provider().grant_producer()?,
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
    fn authorize_delivery(
        &self,
        request: &DeliverResultRequest,
        context: &TransportContext,
    ) -> Result<(Digest, UnixMillis), WorkRefused> {
        let connection = connection(context)?;
        let id = digest(&request.work_id)?;
        let signature = signature(&request.client_signature)?;
        let held = self
            .inner
            .lock()
            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
        held.status.check().map_err(|e| WorkRefused::from(&e))?;
        let channel = ChannelId(digest(
            &request
                .route
                .as_ref()
                .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?
                .channel_id,
        )?);
        authorize_peer(
            &held.store,
            channel,
            request.route.as_ref(),
            connection.peer,
        )?;
        let book = held
            .store
            .state()
            .channel(channel)
            .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?
            .job_book();
        let a = book
            .job_by_id(id)
            .map(|j| *j.authorization())
            .or_else(|| book.terminal_by_id(id).map(|t| t.outcome.authorization))
            .ok_or_else(|| refused(GrantRefusalCode::OutputUnavailable))?;
        let def = held
            .store
            .state()
            .grant(a.grant_id)
            .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?;
        hellas_rpc::signature::verify_digest_signature(
            &PublicKey::Secp256k1(def.kind.principal().producer().to_bytes()),
            &signature,
            bound_delivery_request_digest(
                held.store.state().network(),
                channel.0,
                id,
                &connection.exporter,
            ),
        )
        .map_err(|_| refused(GrantRefusalCode::Unauthorized))?;
        let now = (self.clock)().max(held.store.state().now());
        def.admits(now)
            .map_err(|e| WorkRefused::from(&GrantStoreError::from(e)))?;
        if now > a.delivery_deadline_ms {
            return Err(refused(GrantRefusalCode::Expired));
        }
        if !held.live.contains_key(&id) {
            return Err(book.terminal_by_id(id).map_or_else(
                || refused(GrantRefusalCode::OutputUnavailable),
                |t| terminal_refusal(id, &t.outcome),
            ));
        }
        Ok((id, a.delivery_deadline_ms))
    }
    pub fn stream(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> PaidResultStream {
        let service = self.clone();
        Box::pin(async_stream::stream! {
            let (id, deadline) = match service.authorize_delivery(&request, &context) {
                Ok(value) => value,
                Err(refusal) => { yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(refusal)) }); return; }
            };
            let mut position = 0;
            loop {
                let changed = service.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let update = service.stream_update(id, position, deadline);
                match update {
                    Ok((events, done)) => {
                        for event in events {
                            if matches!(event.outcome, Some(work_stream_event::Outcome::Prefix(_))) { position += 1; }
                            yield Ok(event);
                        }
                        if done { return; }
                    }
                    Err(refusal) => { yield Ok(WorkStreamEvent { outcome: Some(work_stream_event::Outcome::Refused(refusal)) }); return; }
                }
                let remaining = Duration::from_millis(deadline.0.saturating_sub((service.clock)().0).saturating_add(1));
                tokio::select! { _ = changed => {}, _ = tokio::time::sleep(remaining) => {} }
            }
        })
    }
    fn stream_update(
        &self,
        id: Digest,
        position: usize,
        deadline: UnixMillis,
    ) -> Result<(Vec<WorkStreamEvent>, bool), WorkRefused> {
        let held = self
            .inner
            .lock()
            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
        held.status.check().map_err(|e| WorkRefused::from(&e))?;
        if (self.clock)().max(held.store.state().now()) > deadline {
            return Err(refused(GrantRefusalCode::Expired));
        }
        let live = held
            .live
            .get(&id)
            .ok_or_else(|| refused(GrantRefusalCode::OutputUnavailable))?;
        if held
            .store
            .state()
            .grant(live.authorization.grant_id)
            .is_none_or(|g| g.state == GrantState::Revoked)
        {
            return Err(refused(GrantRefusalCode::Revoked));
        }
        if let LivePhase::Refused(code) = live.phase {
            return Err(held
                .store
                .state()
                .channel(live.authorization.channel_id)
                .and_then(|c| c.job_book().terminal_by_id(id))
                .map_or_else(|| refused(code), |t| terminal_refusal(id, &t.outcome)));
        }
        let mut events = Vec::new();
        let end = live
            .events
            .len()
            .saturating_sub(usize::from(live.phase.result().is_some()));
        for event in live
            .events
            .get(position..end)
            .ok_or_else(|| refused(GrantRefusalCode::Malformed))?
        {
            let prefix = encode_transcript(std::slice::from_ref(event))
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            events.push(WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Prefix(prefix)),
            });
        }
        if let Some(signed) = live.phase.result() {
            let last = live
                .events
                .last()
                .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
            events.push(WorkStreamEvent {
                outcome: Some(work_stream_event::Outcome::Terminal(WorkStreamTerminal {
                    result: signed.result.encode(),
                    provider_signature: signed.signature.bytes().to_vec(),
                    terminal_transcript: encode_transcript(std::slice::from_ref(last))
                        .map_err(|_| refused(GrantRefusalCode::Malformed))?,
                })),
            });
        }
        Ok((events, live.phase.result().is_some()))
    }
    // A poisoned writer cannot be used again, but its task handles still own
    // physical invocations and must be joined during shutdown.
    fn lock_for_shutdown(&self) -> std::sync::MutexGuard<'_, Runtime> {
        match self.inner.lock() {
            Ok(held) => held,
            Err(poisoned) => {
                let mut held = poisoned.into_inner();
                held.fail(GrantStoreError::WriterPoisoned);
                held
            }
        }
    }
    /// Cancel queued grants, then keep execution owners alive until physical
    /// completion. No endpoint or journal is dropped ahead of these duties.
    pub async fn drain(&self) -> Result<(), GrantStoreError> {
        let _draining = self.draining.lock().await;
        {
            let mut held = self.lock_for_shutdown();
            held.reap();
            if matches!(held.status, ServiceStatus::Serving) {
                held.status = ServiceStatus::Draining;
            }
            if held.status.check().is_ok() {
                let accepted: Vec<_> = held
                    .live
                    .iter()
                    .filter_map(|(id, live)| {
                        held.store
                            .state()
                            .channel(live.authorization.channel_id)?
                            .job_book()
                            .job_by_id(*id)
                            .filter(|job| job.phase() == JobPhase::Accepted)
                            .map(|_| (live.authorization.channel_id, *id))
                    })
                    .collect();
                for (channel, id) in accepted {
                    if let Err(error) = held.store.release(channel, id, (self.clock)()) {
                        held.fail(error);
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
    let mut refusal = refused(code);
    refusal.grant.as_mut().expect("grant refusal").terminal =
        Some(Box::new(GrantTerminalMetadata {
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
        }));
    refusal
}
fn connection(context: &TransportContext) -> Result<GrantConnection, WorkRefused> {
    Ok(GrantConnection {
        peer: context
            .vouched_peer()
            .ok_or_else(|| refused(GrantRefusalCode::WrongTransport))?
            .0,
        exporter: context
            .open_exporter
            .ok_or_else(|| refused(GrantRefusalCode::WrongTransport))?,
    })
}
fn authorize_peer(
    store: &GrantStore,
    channel: ChannelId,
    route: Option<&WorkRoute>,
    peer: [u8; 32],
) -> Result<(), WorkRefused> {
    if !route.is_some_and(|r| r.selects_grant(channel)) {
        return Err(refused(GrantRefusalCode::Unauthorized));
    }
    let binding = store
        .state()
        .channel_binding(channel)
        .ok_or_else(|| refused(GrantRefusalCode::Unauthorized))?;
    if binding.client.transport() != peer {
        return Err(refused(GrantRefusalCode::WrongTransport));
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

impl hellas_rpc::services::work::WorkHandler for GrantService {
    async fn get_standing(
        &self,
        request: GetStandingRequest,
        context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<GetStandingResponse>> + Send, WireStatus>
    {
        Ok(self.standing(&request, &context))
    }
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AcceptWorkResponse>> + Send, WireStatus>
    {
        Ok(self.accept(&request, &context))
    }
    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<PaidResultStream, WireStatus> {
        Ok(self.stream(request, context))
    }
    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<DeliverResultResponse>> + Send, WireStatus>
    {
        use futures::StreamExt;
        use hellas_rpc::protocol::work::decode_transcript;
        let bound = crate::work_store::journal::MAX_RECORD_BYTES;
        let mut stream = self.stream(request, context);
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
        Ok(DeliverResultResponse {
            outcome: Some(outcome),
        })
    }
    async fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<AdmitCertificateResponse>> + Send, WireStatus>
    {
        Ok(AdmitCertificateResponse {
            outcome: Some(admit_certificate_response::Outcome::Refused(refused(
                GrantRefusalCode::Unauthorized,
            ))),
        })
    }
}

#[cfg(test)]
mod tests;
