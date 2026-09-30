//! Grant funding on Work. One provider writer owns authority and accounting;
//! bounded RAM owns bodies. Executor admission is reserved before co-signing.
use crate::work::admission::{CapacityDomain, WorkAdmission, WorkPermit};
use crate::work::{
    BackendFault, PaidProgress, PaidResultStream, PreparedEvaluateInput, PreparedFetchInput,
    WorkBackend,
};
use crate::work_store::{
    JobPhase,
    grant::{refusal::refused, *},
};
use futures::future::BoxFuture;
use hellas_rpc::pb::work::*;
use hellas_rpc::protocol::work::{
    PrivateRecord, bound_delivery_request_digest, bound_result_digest, encode_transcript,
};
use hellas_rpc::protocol::work_grant::{budget::*, records::*, standing::*, *};
use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkContext};
use hellas_rpc::{Digest, OutputEventEnvelope, ProducerSigningKey, PublicKey, Signature};
use hellas_wire::{TransportContext, WireStatus};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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
    clock: GrantClock,
    addresses: Arc<Vec<String>>,
}
struct Runtime {
    store: GrantStore,
    live: BTreeMap<Digest, Live>,
    stopping: bool,
    failed: bool,
}
struct Live {
    authorization: GrantJobAuthorizationV1,
    policy: GrantPolicy,
    events: Vec<OutputEventEnvelope>,
    bytes: usize,
    reserved_ram: usize,
    active: bool,
    started: Option<Instant>,
    result: Option<SignedResult>,
    refusal: Option<GrantRefusalCode>,
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
                                    input
                                        .parts()
                                        .map_err(|e| BackendFault::new(e.to_string()))?,
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
                                    input
                                        .parts()
                                        .map_err(|e| BackendFault::new(e.to_string()))?,
                                    policy,
                                    admission,
                                ),
                                progress,
                            )
                            .await
                    }
                    _ => Err(BackendFault::new("grant profile mismatch")),
                }
            }) as BoxFuture<'static, _>
        });
        Ok(Self {
            inner: Arc::new(Mutex::new(Runtime {
                store,
                live: BTreeMap::new(),
                stopping: false,
                failed: false,
            })),
            signer,
            admit: Arc::new(move |domain| capacity.try_admit(domain)),
            run,
            changed: Arc::new(Notify::new()),
            clock,
            addresses: Arc::new(addresses),
        })
    }
    /// The local admin handler must authorize before entering this writer.
    pub fn administer<T>(
        &self,
        op: impl FnOnce(&mut GrantStore, UnixMillis) -> Result<T, GrantStoreError>,
    ) -> Result<T, GrantStoreError> {
        let mut held = self.inner.lock().map_err(|_| GrantStoreError::Malformed)?;
        if held.failed {
            return Err(GrantStoreError::Unavailable);
        }
        let now = (self.clock)().max(held.store.state().now());
        let result = op(&mut held.store, now);
        // A failed write/sync can leave permission durability uncertain. Do not
        // continue authorizing against the in-memory view until replay succeeds.
        if matches!(
            &result,
            Err(GrantStoreError::Journal(
                crate::work_store::journal::JournalError::Io(_)
                    | crate::work_store::journal::JournalError::Poisoned
            ))
        ) {
            held.failed = true;
        }
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
            if held.failed {
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
        let now = (self.clock)().max(held.store.state().now());
        let id = grant_work_id(held.store.state().network(), &a);
        if let Some(signature) = held
            .store
            .precheck_acceptance(&a, &client_signature, now)
            .map_err(|e| WorkRefused::from(&e))?
        {
            return Ok(accepted(id, signature));
        }
        if held.failed {
            return Err(refused(GrantRefusalCode::StorageUnavailable));
        }
        if held.stopping {
            return Err(refused(GrantRefusalCode::QueueCapacity));
        }
        held.live
            .retain(|_, l| l.active || l.authorization.delivery_deadline_ms >= now);
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
        let class = held
            .store
            .state()
            .grant(a.grant_id)
            .expect("accepted grant")
            .kind
            .class();
        held.live.insert(
            id,
            Live {
                authorization: a,
                policy: policy.clone(),
                events: vec![],
                bytes: 0,
                reserved_ram: reserve,
                active: true,
                started: None,
                result: None,
                refusal: None,
            },
        );
        drop(held);
        let service = self.clone();
        let admission = WorkAdmission::grant(
            permit,
            class,
            deadline,
            Box::new(move || {
                let mut held = service
                    .inner
                    .lock()
                    .map_err(|_| BackendFault::new("grant writer unavailable"))?;
                // Unlike idempotent journal replay, an invocation must consume the
                // Accepted phase exactly once before any backend preparation.
                let job = held
                    .store
                    .state()
                    .channel(a.channel_id)
                    .and_then(|c| c.job_book().job_by_id(id));
                if job.is_none_or(|j| j.phase() != JobPhase::Accepted) {
                    return Err(BackendFault::new("grant is no longer dispatchable"));
                }
                let started = Instant::now();
                held.store
                    .dispatch(a.channel_id, id, (service.clock)())
                    .map_err(|e| BackendFault::new(e.to_string()))?;
                held.live
                    .get_mut(&id)
                    .ok_or_else(|| BackendFault::new("grant input missing"))?
                    .started = Some(started);
                Ok(())
            }),
        );
        let service = self.clone();
        let progress_service = self.clone();
        let progress = Arc::new(move |event| progress_service.progress(id, event));
        tokio::spawn(async move {
            let output = (service.run)(input.clone(), policy, admission, progress).await;
            if let Err(error) = service.finish(id, &input, output) {
                tracing::error!(?id, %error, "grant completion could not be made durable");
                if let Ok(mut held) = service.inner.lock() {
                    held.failed = true;
                    if let Some(live) = held.live.get_mut(&id) {
                        live.active = false;
                    }
                }
            }
            service.changed.notify_waiters();
        });
        Ok(accepted(id, signature))
    }
    fn progress(&self, id: Digest, event: OutputEventEnvelope) -> Result<(), BackendFault> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| BackendFault::new("grant writer unavailable"))?;
        let live = held
            .live
            .get_mut(&id)
            .ok_or_else(|| BackendFault::new("grant input missing"))?;
        if live.started.is_none() {
            return Err(BackendFault::new("backend ran without dispatch admission"));
        }
        let charge = event_ram(&event);
        let next = live.bytes.saturating_add(charge);
        if next as u64 > live.policy.work.max_spool_bytes()
            || charge as u64 > live.policy.work.max_encoded_result_frame() as u64
            || (self.clock)() > live.authorization.terminal_deadline_ms
        {
            return Err(BackendFault::new(
                "grant output exceeds its resource or time bound",
            ));
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
        let mut held = self.inner.lock().map_err(|_| GrantStoreError::Malformed)?;
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
            output
                .ok()
                .filter(|events| events.starts_with(&live.events))
                .filter(|events| {
                    transcript_ram(events) as u64 <= live.policy.work.max_spool_bytes()
                })
                .filter(|events| {
                    encode_transcript(events)
                        .is_ok_and(|bytes| bytes.len() as u64 <= live.policy.work.max_spool_bytes())
                })
                .and_then(|events| {
                    let def = held.store.state().grant(a.grant_id)?;
                    let context = WorkContext {
                        network: held.store.state().network(),
                        channel: a.channel_id.0,
                        client: def.kind.principal().producer(),
                        provider: held.store.state().provider().grant_producer().ok()?,
                    };
                    let result = live
                        .policy
                        .work
                        .bound_terminal_result(&context, id, &(&a).into(), input, &events)
                        .ok()?;
                    let signature = self
                        .signer
                        .sign_digest(bound_result_digest(
                            context.network,
                            context.channel,
                            &result,
                        ))
                        .ok()?;
                    Some((events, SignedResult { result, signature }))
                })
        } else {
            None
        };
        let usage = verified.as_ref().map_or(Usage::Unknown, |(events, _)| {
            accounting::usage(&live.policy, events, live.started.map(|s| s.elapsed()))
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
        live.active = false;
        if let Some((events, signed)) = completion {
            live.bytes = transcript_ram(&events);
            live.events = events;
            live.result = Some(signed);
        } else {
            live.refusal = Some(if phase == Some(JobPhase::Accepted) || phase.is_none() {
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
        if held.failed {
            return Err(refused(GrantRefusalCode::StorageUnavailable));
        }
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
        if held.failed {
            return Err(refused(GrantRefusalCode::StorageUnavailable));
        }
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
        if let Some(code) = live.refusal {
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
            .saturating_sub(usize::from(live.result.is_some()));
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
        if let Some(signed) = &live.result {
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
        Ok((events, live.result.is_some()))
    }
    /// Cancel queued grants, then keep execution owners alive until physical
    /// completion. No endpoint or journal is dropped ahead of these duties.
    pub async fn drain(&self) -> Result<(), GrantStoreError> {
        {
            let mut held = self.inner.lock().map_err(|_| GrantStoreError::Malformed)?;
            if held.failed {
                return Err(GrantStoreError::Unavailable);
            }
            held.stopping = true;
            let accepted: Vec<_> = held
                .live
                .iter()
                .filter_map(|(id, live)| {
                    held.store
                        .state()
                        .channel(live.authorization.channel_id)?
                        .job_book()
                        .job_by_id(*id)
                        .filter(|j| j.phase() == JobPhase::Accepted)
                        .map(|_| (live.authorization.channel_id, *id))
                })
                .collect();
            for (channel, id) in accepted {
                held.store.release(channel, id, (self.clock)())?;
            }
        }
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let held = self.inner.lock().map_err(|_| GrantStoreError::Malformed)?;
                if held.failed {
                    return Err(GrantStoreError::Unavailable);
                }
                if !held.live.values().any(|l| l.active) {
                    return Ok(());
                }
            }
            changed.await;
        }
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
