//! The gateway backend: every HTTP request becomes one job on the job
//! commands' target, run by the same [`Executor`]. Admission, streamed
//! output and shutdown are shared here.
use crate::execution::{ExecutionError, Executor, RequestStopped};
use crate::grant_client::GrantClientError;
use crate::job::{Job, JobError, JobInput};
use futures::{future::BoxFuture, stream::BoxStream};
use hellas_authority::model::grant::records::{GrantPolicy, grant_transport};
use hellas_authority::model::grant::resource::HttpsResource;
use hellas_gateway::{
    ComputeEvent, WorkEvent, WorkExecutionBackend, WorkFetchRequest, WorkGatewayBusy,
    WorkGatewayError, WorkOutputStream, WorkShutdownError,
};
use hellas_rpc::http_fetch::HttpFetchRequest;
use hellas_rpc::output::OutputEvent;
use hellas_rpc::protocol::invocation::output::{ArtifactChunk, ArtifactPrefix, InvocationOutput};
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, fetch::FetchRoutePolicy};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

// A complete image burst can retain prefixes, an integer-array CBOR
// transcript and decoded pixels together before the consumer polls.
pub const OUTPUT_BUFFER_BYTES: usize = 4 * hellas_channel::work_store::journal::MAX_RECORD_BYTES;
pub const OUTPUT_EVENT_OVERHEAD: usize = 1024;
pub const OUTPUT_BUFFER_EVENTS: usize = OUTPUT_BUFFER_BYTES / OUTPUT_EVENT_OVERHEAD;
pub type BufferedEvent<E, X> = (Result<E, X>, OwnedSemaphorePermit);
fn output_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> hellas_gateway::WorkGatewayError {
    hellas_gateway::WorkGatewayError::Execution(Box::new(error))
}
pub(crate) fn fetch_prefix(
    chunk: hellas_rpc::protocol::invocation::output::ArtifactChunk,
    pending: &mut Vec<u8>,
) -> Result<Vec<hellas_rpc::output::OutputEvent>, hellas_gateway::WorkGatewayError> {
    use hellas_rpc::protocol::invocation::fetch;
    if chunk.name != fetch::RESPONSE_EVENTS || chunk.format != fetch::RESPONSE_EVENTS_FORMAT {
        return Err(output_error(std::io::Error::other(
            "Fetch artifact identity",
        )));
    }
    pending.extend_from_slice(chunk.bytes.as_bytes());
    let mut events = Vec::new();
    let mut consumed = 0;
    while let Some(header) = pending.get(consumed..consumed + 4) {
        let length = u32::from_be_bytes(header.try_into().map_err(output_error)?) as usize;
        if length > hellas_rpc::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(output_error(std::io::Error::other(
                "Fetch frame exceeds payload bound",
            )));
        }
        let start = consumed + 4;
        let end = start + length;
        if pending.len() < end {
            break;
        }
        events.push(
            hellas_rpc::fetch::decode_fetch_event_payload(&pending[start..end])
                .map_err(output_error)?,
        );
        consumed = end;
    }
    pending.drain(..consumed);
    Ok(events)
}
pub(crate) fn fetch_terminal(
    output: &hellas_rpc::protocol::invocation::output::InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Result<hellas_rpc::output::OutputEvent, hellas_gateway::WorkGatewayError> {
    let response = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider)
        .map_err(output_error)?;
    let (_, terminal) = response.output_event_payloads();
    Ok(hellas_rpc::fetch::decode_fetch_terminal_payload(terminal)
        .map_err(output_error)?
        .to_output_event())
}

pub fn emit<E, X>(
    sender: &mpsc::Sender<BufferedEvent<E, X>>,
    overflow: &watch::Sender<bool>,
    budget: &Arc<Semaphore>,
    event: Result<E, X>,
    bytes: usize,
) {
    if *overflow.borrow() || sender.is_closed() {
        return;
    }
    let bytes = bytes.saturating_add(OUTPUT_EVENT_OVERHEAD);
    let permits = u32::try_from(bytes)
        .ok()
        .and_then(|n| budget.clone().try_acquire_many_owned(n).ok());
    let Some(permits) = permits else {
        overflow.send_replace(true);
        return;
    };
    if matches!(
        sender.try_send((event, permits)),
        Err(mpsc::error::TrySendError::Full(_))
    ) {
        overflow.send_replace(true);
    }
}
pub fn response_stream<E: Send + 'static, X: Send + 'static>(
    mut receiver: mpsc::Receiver<BufferedEvent<E, X>>,
    mut overflow: watch::Receiver<bool>,
    slow_consumer: fn() -> X,
) -> BoxStream<'static, Result<E, X>> {
    Box::pin(async_stream::try_stream! {
        loop {
            if *overflow.borrow() { receiver.close(); Err(slow_consumer())?; }
            let event = tokio::select! {
                biased;
                _ = overflow.changed(), if overflow.has_changed().is_ok() => continue,
                event = receiver.recv() => event,
            };
            match event { Some((event, permit)) => { drop(permit); yield event?; }, None => return }
        }
    })
}

/// Owns accepted tasks until their futures physically terminate. Drain polls the
/// handles in place so dropping a drain future cannot detach unfinished work.
#[derive(Default)]
pub struct WorkTasks {
    state: std::sync::Mutex<TaskState>,
    draining: tokio::sync::Mutex<()>,
}
#[derive(Default)]
struct TaskState {
    closed: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    failure: Option<Arc<tokio::task::JoinError>>,
}
impl TaskState {
    fn poll(&mut self, cx: &mut std::task::Context<'_>, finished_only: bool) {
        use std::{future::Future as _, pin::Pin, task::Poll};
        let failure = &mut self.failure;
        self.tasks.retain_mut(|task| {
            if finished_only && !task.is_finished() {
                return true;
            }
            match Pin::new(task).poll(cx) {
                Poll::Pending => true,
                Poll::Ready(Ok(())) => false,
                Poll::Ready(Err(error)) => {
                    failure.get_or_insert_with(|| Arc::new(error));
                    false
                }
            }
        });
    }
}
impl WorkTasks {
    pub fn spawn(
        &self,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), hellas_gateway::WorkGatewayBusy> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| hellas_gateway::WorkGatewayBusy)?;
        if state.closed {
            return Err(hellas_gateway::WorkGatewayBusy);
        }
        let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
        state.poll(&mut cx, true);
        state.tasks.push(tokio::spawn(future));
        Ok(())
    }

    pub fn close(&self) {
        match self.state.lock() {
            Ok(mut state) => state.closed = true,
            Err(error) => error.into_inner().closed = true,
        }
    }

    pub async fn drain(&self) -> Result<(), hellas_gateway::WorkShutdownError> {
        use hellas_gateway::WorkShutdownError;
        self.close();
        let _draining = self.draining.lock().await;
        std::future::poll_fn(|cx| {
            let (mut state, poisoned) = match self.state.lock() {
                Ok(state) => (state, false),
                Err(error) => (error.into_inner(), true),
            };
            state.poll(cx, false);
            if !state.tasks.is_empty() {
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(if let Some(error) = &state.failure {
                Err(WorkShutdownError::Task(error.clone()))
            } else if poisoned {
                Err(WorkShutdownError::Poisoned)
            } else {
                Ok(())
            })
        })
        .await
    }
}

/// Gateway events derived from one invocation's signed output.
pub trait GatewayEvent: serde::Serialize + Send + Sized + 'static {
    fn prefix(chunk: ArtifactChunk, pending: &mut Vec<u8>) -> Result<Vec<Self>, WorkGatewayError>;
    fn completed(
        output: &InvocationOutput,
        provider: &hellas_auth::PublicKey,
    ) -> Result<Self, WorkGatewayError>;
    fn bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(OUTPUT_BUFFER_BYTES, |bytes| bytes.len())
    }
}
impl GatewayEvent for OutputEvent {
    fn prefix(chunk: ArtifactChunk, pending: &mut Vec<u8>) -> Result<Vec<Self>, WorkGatewayError> {
        fetch_prefix(chunk, pending)
    }
    fn completed(
        output: &InvocationOutput,
        provider: &hellas_auth::PublicKey,
    ) -> Result<Self, WorkGatewayError> {
        fetch_terminal(output, provider)
    }
}
impl GatewayEvent for ComputeEvent {
    fn bytes(&self) -> usize {
        // These events are held as Rust buffers, never JSON. Decimal JSON
        // expansion would reject a valid transcript + full output completion.
        match self {
            ComputeEvent::Output(chunk) => chunk
                .name
                .capacity()
                .saturating_add(chunk.format.capacity())
                .saturating_add(chunk.bytes.0.capacity()),
            ComputeEvent::Done { output, .. } => output.artifacts.iter().fold(
                output.metadata.0.capacity().saturating_add(
                    output
                        .artifacts
                        .capacity()
                        .saturating_mul(std::mem::size_of::<
                            hellas_rpc::protocol::invocation::Artifact,
                        >()),
                ),
                |bytes, artifact| {
                    bytes
                        .saturating_add(artifact.name.capacity())
                        .saturating_add(artifact.format.capacity())
                        .saturating_add(artifact.bytes.0.capacity())
                },
            ),
        }
    }
    fn prefix(chunk: ArtifactChunk, pending: &mut Vec<u8>) -> Result<Vec<Self>, WorkGatewayError> {
        let _ = pending;
        Ok(vec![ComputeEvent::Output(chunk)])
    }
    fn completed(
        output: &InvocationOutput,
        provider: &hellas_auth::PublicKey,
    ) -> Result<Self, WorkGatewayError> {
        Ok(ComputeEvent::Done {
            output: output.clone(),
            provider: *provider,
        })
    }
}

/// What one event charges against the requester's output budget.
fn event_bytes<E: GatewayEvent>(event: &WorkEvent<E>) -> usize {
    match event {
        WorkEvent::Accepted(provenance) => {
            std::mem::size_of_val(&provenance.commitment_id) + provenance.provider.bytes().len()
        }
        WorkEvent::Output(event) => event.bytes(),
        WorkEvent::Transcript(transcript) => transcript.len(),
    }
}

/// What a requester's consumer reads: work events, or the source's failure.
pub type RequestStream<E, X> = BoxStream<'static, Result<WorkEvent<E>, X>>;

/// The listening side of one accepted request.
pub struct Requester<E, X> {
    sender: mpsc::Sender<BufferedEvent<WorkEvent<E>, X>>,
    overflow: watch::Sender<bool>,
    budget: Arc<Semaphore>,
}
impl<E, X> Clone for Requester<E, X> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            overflow: self.overflow.clone(),
            budget: self.budget.clone(),
        }
    }
}
impl<E: GatewayEvent, X: std::fmt::Display + Send + 'static> Requester<E, X> {
    pub(crate) fn new() -> (Self, RequestStream<E, X>)
    where
        X: From<WorkGatewayError>,
    {
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let requester = Self {
            sender,
            overflow,
            budget: Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES)),
        };
        (
            requester,
            response_stream(receiver, overflow_receiver, || {
                X::from(WorkGatewayError::Execution(Box::new(
                    std::io::Error::other(
                        "gateway output consumer is too slow; accepted work continues",
                    ),
                )))
            }),
        )
    }
    pub(crate) fn emit(&self, event: Result<WorkEvent<E>, X>) {
        // The signed transcript is one mandatory evidence record whose size is
        // fixed by the job's authorised spool, not by how fast the consumer
        // reads. Charging it against the slow-consumer byte budget made a
        // verified, already-paid result undeliverable whenever the transcript
        // exceeded the whole queue, which then suppressed the completion too.
        // It is moved rather than copied, takes a queue slot, and a consumer
        // that stops reading still ends the stream.
        if matches!(&event, Ok(WorkEvent::Transcript(_))) {
            return self.emit_mandatory(event);
        }
        let bytes = match &event {
            Ok(event) => event_bytes(event),
            Err(error) => error.to_string().len(),
        };
        emit(&self.sender, &self.overflow, &self.budget, event, bytes);
    }
    /// Queues an event whose size is set by the job rather than by the reader.
    fn emit_mandatory(&self, event: Result<WorkEvent<E>, X>) {
        if *self.overflow.borrow() || self.sender.is_closed() {
            return;
        }
        let Ok(permits) = self.budget.clone().try_acquire_many_owned(0) else {
            self.overflow.send_replace(true);
            return;
        };
        if matches!(
            self.sender.try_send((event, permits)),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            self.overflow.send_replace(true);
        }
    }
    /// Reports the provider's acceptance as it happens, before any output.
    pub(crate) fn accepted(&self) -> crate::transact::Accepted {
        let requester = self.clone();
        Arc::new(move |provenance| requester.emit(Ok(WorkEvent::Accepted(provenance))))
    }
    /// Signed prefixes, decoded and delivered as they arrive.
    pub(crate) fn progress(&self) -> hellas_channel::work::PaidProgress {
        let requester = self.clone();
        let state = std::sync::Mutex::new((ArtifactPrefix::default(), Vec::new()));
        Arc::new(move |envelope| {
            use hellas_channel::work::BackendFault;
            let mut state = state.lock().map_err(|_| {
                BackendFault::caused_by(std::io::Error::other("prefix lock poisoned"))
            })?;
            let (prefix, pending) = &mut *state;
            let chunk = prefix.push(&envelope).map_err(BackendFault::caused_by)?;
            for event in E::prefix(chunk, pending).map_err(BackendFault::caused_by)? {
                requester.emit(Ok(WorkEvent::Output(event)));
            }
            Ok(())
        })
    }
    #[cfg(test)]
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    /// Disconnecting stops a request only before its proposal.
    pub(crate) fn stop(&self) -> crate::execution::Stop {
        let sender = self.sender.clone();
        crate::execution::stop_on(async move { sender.closed().await })
    }
    pub(crate) fn observers(&self) -> crate::execution::ExecutionObservers {
        crate::execution::ExecutionObservers {
            progress: Some(self.progress()),
            accepted: Some(self.accepted()),
        }
    }
    /// The signed transcript, then the completion. Queueing is the handoff.
    pub(crate) fn delivery(&self) -> crate::execution::Delivery<'static>
    where
        X: From<WorkGatewayError>,
    {
        let requester = self.clone();
        Box::new(move |completed| {
            requester.emit(Ok(WorkEvent::Transcript(completed.transcript.clone())));
            requester.emit(
                E::completed(&completed.output, &completed.provider_key)
                    .map(WorkEvent::Output)
                    .map_err(Into::into),
            );
            Ok(())
        })
    }
}

/// What HTTP asks for, before any source has matched it to a policy.
pub enum WorkRequest {
    /// Pinned to one provider by the HTTP account router; the contract comes
    /// from the admitting policy.
    Fetch(WorkFetchRequest),
    /// A complete input; any admitting provider may run it.
    Job(JobInput),
}

impl WorkRequest {
    /// The provider this request must run on, if it names one.
    pub fn pinned(&self) -> Option<iroh::EndpointId> {
        match self {
            WorkRequest::Fetch(request) => Some(request.provider),
            WorkRequest::Job(_) => None,
        }
    }

    /// The one input `policy` admits for this request. A Fetch tries each
    /// Fetch contract of `policy`; an HTTPS body is first repaired under
    /// `https`, a complete HTTPS job's body too. Two admitting contracts are
    /// refused, never chosen between.
    pub fn admitted(
        &self,
        policy: &InvocationPolicy,
        https: Option<&HttpsResource>,
        assurance: hellas_rpc::Assurance,
        retain: bool,
    ) -> Result<JobInput, JobError> {
        let request = match self {
            WorkRequest::Job(input) => {
                let mut input = input.clone();
                if let (
                    Some(https),
                    JobInput::Fetch {
                        contract, request, ..
                    },
                ) = (https, &mut input)
                    && contract.schema() == hellas_rpc::FetchSchema::HttpV1
                {
                    *request = repair(https, request)?;
                }
                input.admits(policy, retain)?;
                return Ok(input);
            }
            WorkRequest::Fetch(request) => request,
        };
        let mut contracts = Vec::new();
        for admission in &policy.admissions {
            if let Admission::Fetch { admission } = admission
                && !contracts.contains(&admission.contract)
            {
                contracts.push(admission.contract.clone());
            }
        }
        let mut admitted = None;
        let mut refusal = None;
        for contract in contracts {
            let body = match https {
                Some(https) if contract.schema() == hellas_rpc::FetchSchema::HttpV1 => {
                    repair(https, &request.body)?
                }
                _ => request.body.clone(),
            };
            let input = JobInput::Fetch {
                contract,
                service: request.service.clone(),
                method: request.method.clone(),
                request: body,
                assurance,
            };
            match input.admits(policy, retain) {
                Ok(()) if admitted.is_some() => {
                    return Err(JobError::Invalid(
                        "several Fetch contracts admit this request".into(),
                    ));
                }
                Ok(()) => admitted = Some(input),
                Err(error) => refusal = Some(error),
            }
        }
        admitted.ok_or_else(|| {
            refusal.unwrap_or_else(|| JobError::Invalid("the policy admits no Fetch".into()))
        })
    }
}

/// An HTTPS body completed under the granted resource's template.
fn repair(https: &HttpsResource, body: &[u8]) -> Result<Vec<u8>, JobError> {
    let mut http = HttpFetchRequest::decode(body).map_err(|e| JobError::Invalid(e.to_string()))?;
    https
        .prepare(&mut http)
        .map_err(|e| JobError::Invalid(e.to_string()))?;
    Ok(serde_json::to_vec(&http)?)
}

/// The Fetch routes `policy` admits on `provider`, each once.
pub(crate) fn fetch_routes<'a>(
    provider: iroh::EndpointId,
    policies: impl IntoIterator<Item = &'a InvocationPolicy>,
) -> Vec<hellas_gateway::FetchRoute> {
    use hellas_rpc::protocol::invocation::fetch::FetchRoutePolicy;
    let mut routes = Vec::new();
    for policy in policies {
        for admission in &policy.admissions {
            let Admission::Fetch { admission } = admission else {
                continue;
            };
            let route = hellas_gateway::FetchRoute {
                resource: None,
                channel: None,
                provider,
                schema: admission.contract.schema(),
                sealed: match &admission.route {
                    FetchRoutePolicy::SealedRoute { service, method } => {
                        Some((service.clone(), method.clone()))
                    }
                    FetchRoutePolicy::OpenFetch { .. } => None,
                },
            };
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
    }
    routes
}

/// What a gateway serves beyond what its work source admits.
#[derive(Clone)]
pub struct GatewayServeOptions {
    pub server: hellas_gateway::ServerOptions,
    pub models: Vec<hellas_gateway::ModelOptions>,
    pub http: Option<hellas_gateway::HttpGatewayConfig>,
    /// Merged into Responses requests sent as a Fetch.
    pub responses_overrides: serde_json::Map<String, serde_json::Value>,
    /// Models the Responses Fetch answers to; empty means any.
    pub responses_models: Vec<String>,
}

/// Serve `work` with the caller's presentations, plus Responses when the
/// source seals exactly one Responses route. A failed start drains `work`.
pub async fn serve_gateway(
    work: Arc<dyn WorkExecutionBackend>,
    options: GatewayServeOptions,
) -> hellas_gateway::GatewayResult<hellas_gateway::GatewayHandle> {
    let responses = match hellas_gateway::ResponsesFetch::from_routes(
        &work.fetch_routes(),
        options.responses_overrides,
        options.responses_models,
    ) {
        Ok(responses) => responses,
        Err(error) => {
            return match work.drain().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(hellas_gateway::GatewayError::Cleanup {
                    primary: Box::new(error),
                    cleanup,
                }),
            };
        }
    };
    hellas_gateway::start(hellas_gateway::GatewayOptions {
        server: options.server,
        work,
        presentations: hellas_gateway::Presentations {
            models: options.models,
            responses,
            http: options.http,
        },
    })
    .await
}

/// Where every request of one gateway runs: the job commands' targets.
#[expect(clippy::large_enum_variant, reason = "one per gateway")]
pub enum GatewayTarget {
    /// The provider's quoted terms, asked once when the gateway starts;
    /// `options.expected_price` is the quoted price.
    Paid {
        options: crate::paid_client::PaidWorkOptions,
        policy: InvocationPolicy,
        endpoint: iroh::Endpoint,
        settlement_key: hellas_kernel::Secp256k1Signer,
        owner: Arc<crate::client_owner::ClientOwner>,
    },
    /// One granted resource of an access file.
    Grant {
        options: crate::grant_client::GrantSessionOptions,
        transport: crate::grant_client::GrantTransport,
        policy: GrantPolicy,
    },
    /// This machine, under the caller's own limits.
    #[cfg(feature = "compute")]
    Local {
        execution: crate::execution::local::LocalExecution,
        timeout: std::time::Duration,
    },
}

impl GatewayTarget {
    /// The endpoint requests reach their provider through, if remote.
    pub fn endpoint(&self) -> Option<&iroh::Endpoint> {
        match self {
            Self::Paid { endpoint, .. }
            | Self::Grant {
                transport: crate::grant_client::GrantTransport::Remote(endpoint),
                ..
            } => Some(endpoint),
            _ => None,
        }
    }

    /// The provider every request runs on; none for this machine.
    fn provider(&self) -> Result<Option<iroh::EndpointId>, WorkGatewayError> {
        Ok(match self {
            Self::Paid { options, .. } => Some(options.provider.node),
            Self::Grant { options, .. } => Some(
                iroh::EndpointId::from_bytes(
                    &grant_transport(&options.target.offer().provider).map_err(execution)?,
                )
                .map_err(execution)?,
            ),
            #[cfg(feature = "compute")]
            Self::Local { .. } => None,
        })
    }

    /// The one job `request` becomes under this target's terms.
    fn job(&self, request: &WorkRequest) -> Result<Job, WorkGatewayError> {
        if let Some(provider) = request.pinned()
            && self.provider()? != Some(provider)
        {
            return Err(WorkGatewayError::Provider(provider));
        }
        let input = match self {
            Self::Paid {
                options, policy, ..
            } => {
                if matches!(request, WorkRequest::Fetch(fetch) if fetch.resource.is_some() || fetch.channel.is_some())
                {
                    return Err(rejected(std::io::Error::other(
                        "paid work has no grant resource selector",
                    )));
                }
                request.admitted(policy, None, options.assurance, true)
            }
            Self::Grant {
                options, policy, ..
            } => {
                if let WorkRequest::Fetch(fetch) = request
                    && (fetch.resource.is_some() != fetch.channel.is_some()
                        || fetch.resource.is_some_and(|id| id != policy.resource)
                        || fetch.channel.is_some_and(|id| Some(id) != channel(options)))
                {
                    return Err(rejected(std::io::Error::other(
                        "the request names another granted resource",
                    )));
                }
                request.admitted(
                    &policy.invocation_policy,
                    policy.https.as_ref(),
                    options.target.trust().required_assurance,
                    false,
                )
            }
            #[cfg(feature = "compute")]
            Self::Local { timeout, .. } => match request {
                WorkRequest::Job(input) => {
                    crate::execution::local::policy(input, *timeout).and_then(|policy| {
                        request.admitted(&policy, None, hellas_rpc::Assurance::ProducerSigned, false)
                    })
                }
                WorkRequest::Fetch(_) => return Err(WorkGatewayError::Unsupported),
            },
        }
        .map_err(rejected)?;
        let price = match self {
            Self::Paid { options, .. } => options.expected_price,
            _ => 0,
        };
        Job::from_input(price, input).map_err(rejected)
    }

    /// An untracked run of one job: the gateway process finishes what it proposes.
    #[cfg_attr(
        not(feature = "compute"),
        expect(
            unused_variables,
            reason = "only local runs size their terms to the job"
        )
    )]
    fn executor(&self, job: &Job) -> Result<Executor, ExecutionError> {
        Ok(match self {
            Self::Paid {
                options,
                endpoint,
                settlement_key,
                owner,
                ..
            } => Executor::Paid(crate::execution::PaidExecution {
                options: options.clone(),
                endpoint: endpoint.clone(),
                settlement_key: settlement_key.clone(),
                owner: owner.clone(),
                funding: Default::default(),
                attempt: None,
                settle: false,
            }),
            Self::Grant {
                options,
                transport,
                policy,
            } => Executor::Grant(crate::execution::GrantExecution {
                options: options.clone(),
                transport: transport.clone(),
                resource: policy.resource,
                attempt: None,
            }),
            #[cfg(feature = "compute")]
            Self::Local { execution, timeout } => Executor::Local(
                execution.clone(),
                crate::execution::local::policy(job.input(), *timeout)?,
            ),
        })
    }

    /// The most steps one Compute job may take: the quoted terms of a paid
    /// provider, the granted resource's, none on this machine.
    pub fn max_steps(&self) -> Option<u64> {
        match self {
            Self::Paid { policy, .. } => Some(policy.limits.step_bound()),
            Self::Grant { policy, .. } => Some(policy.invocation_policy.limits.step_bound()),
            #[cfg(feature = "compute")]
            Self::Local { .. } => None,
        }
    }

    /// The Fetch routes this target admits.
    pub fn fetch_routes(&self) -> Result<Vec<hellas_gateway::FetchRoute>, WorkGatewayError> {
        let Some(provider) = self.provider()? else {
            return Ok(Vec::new());
        };
        Ok(match self {
            Self::Paid { policy, .. } => fetch_routes(provider, [policy]),
            Self::Grant {
                options, policy, ..
            } => fetch_routes(provider, [&policy.invocation_policy])
                .into_iter()
                .map(|mut route| {
                    route.resource = Some(policy.resource);
                    route.channel = channel(options);
                    route
                })
                .collect(),
            #[cfg(feature = "compute")]
            Self::Local { .. } => Vec::new(),
        })
    }

    /// The HTTP routes a granted HTTPS resource presents, if it has one.
    pub fn http_config(
        &self,
    ) -> Result<Option<hellas_gateway::HttpGatewayConfig>, WorkGatewayError> {
        let Self::Grant { policy, .. } = self else {
            return Ok(None);
        };
        if policy.https.is_none() {
            return Ok(None);
        }
        let (service, method, routes) = policy_http_routes(policy)?;
        Ok(Some(hellas_gateway::HttpGatewayConfig {
            service: Some(service),
            method: Some(method),
            backends: Default::default(),
            max_in_flight: 32,
            routes,
        }))
    }
}

/// A granted HTTPS resource as HTTP presentation routes on its one sealed route.
fn policy_http_routes(
    policy: &GrantPolicy,
) -> Result<(String, String, Vec<hellas_gateway::HttpRoute>), WorkGatewayError> {
    let unsealed = || {
        rejected(std::io::Error::other(
            "the HTTPS resource seals no one route",
        ))
    };
    let template = policy.https.as_ref().ok_or_else(unsealed)?;
    let mut sealed = policy
        .invocation_policy
        .admissions
        .iter()
        .filter_map(|admission| match admission {
            Admission::Fetch { admission }
                if admission.contract.schema() == hellas_rpc::FetchSchema::HttpV1 =>
            {
                match &admission.route {
                    FetchRoutePolicy::SealedRoute { service, method } => Some((service, method)),
                    FetchRoutePolicy::OpenFetch { .. } => None,
                }
            }
            _ => None,
        });
    let (service, method) = sealed.next().ok_or_else(unsealed)?;
    if sealed.any(|route| route != (service, method)) {
        return Err(unsealed());
    }
    let routes = template
        .paths
        .iter()
        .flat_map(|path| {
            template
                .methods
                .iter()
                .map(move |verb| hellas_gateway::HttpRoute {
                    path: path.clone(),
                    method: verb.clone(),
                    url: format!("{}{}", template.origin, path),
                    credential: template.credential.clone(),
                    tls: template.tls.clone(),
                    headers: vec![],
                    max_response_bytes: template.max_response_bytes,
                    models: template
                        .model_policy
                        .as_ref()
                        .and_then(|policies| policies.iter().find(|policy| policy.path == *path))
                        .map(|policy| policy.models.clone()),
                })
        })
        .collect();
    Ok((service.clone(), method.clone(), routes))
}

/// The grant channel this device opens with the offer.
fn channel(
    options: &crate::grant_client::GrantSessionOptions,
) -> Option<hellas_channel::model::grant::ChannelId> {
    let node =
        hellas_auth::authority::NodeKey::from_public_key(options.signer.public_key()).ok()?;
    Some(
        options
            .target
            .offer()
            .channel(hellas_channel::model::grant::ChannelClient {
                principal: options.principal,
                node,
            }),
    )
}

/// The gateway backend: one [`Executor`] run per request, one at a time,
/// since a channel journal, a funding wallet and a machine each have one owner.
/// It owns its target's endpoint and closes it when it drains.
pub struct ExecutorGateway {
    inner: Arc<Inner>,
    admission: Arc<Semaphore>,
    tasks: WorkTasks,
}

struct Inner {
    target: GatewayTarget,
    signer: Arc<hellas_auth::ProducerSigningKey>,
    serial: tokio::sync::Mutex<()>,
}

impl ExecutorGateway {
    /// `signer` signs paid and local proposals: the caller's device key.
    pub fn new(target: GatewayTarget, signer: Arc<hellas_auth::ProducerSigningKey>) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Inner {
                target,
                signer,
                serial: tokio::sync::Mutex::new(()),
            }),
            admission: Arc::new(Semaphore::new(32)),
            tasks: WorkTasks::default(),
        })
    }

    pub fn target(&self) -> &GatewayTarget {
        &self.inner.target
    }

    fn request<E: GatewayEvent>(
        &self,
        request: WorkRequest,
    ) -> Result<WorkOutputStream<E>, WorkGatewayError> {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| WorkGatewayBusy)?;
        let job = self.inner.target.job(&request)?;
        let (requester, stream) = Requester::<E, WorkGatewayError>::new();
        let inner = self.inner.clone();
        self.tasks.spawn(async move {
            let _permit = permit;
            if let Err(error) = inner.run(job, requester.clone()).await {
                requester.emit(Err(error));
            }
        })?;
        Ok(stream)
    }
}

impl Inner {
    /// A request that disconnects while queued never starts.
    async fn run<E: GatewayEvent>(
        &self,
        job: Job,
        requester: Requester<E, WorkGatewayError>,
    ) -> Result<(), WorkGatewayError> {
        let stop = requester.stop();
        let Ok(_serial) =
            crate::execution::before_proposal(None, &stop, None, self.serial.lock()).await
        else {
            return Ok(());
        };
        let executor = self.target.executor(&job).map_err(gateway_error)?;
        let run = executor
            .run(
                &job,
                &self.signer,
                None,
                stop,
                requester.observers(),
                requester.delivery(),
            )
            .await;
        match run {
            Ok(_) | Err(ExecutionError::Stopped(RequestStopped::Disconnected)) => Ok(()),
            Err(error) => Err(gateway_error(error)),
        }
    }
}

impl WorkExecutionBackend for ExecutorGateway {
    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        self.inner.target.fetch_routes().unwrap_or_default()
    }
    fn max_steps(&self) -> Option<u64> {
        self.inner.target.max_steps()
    }
    fn fetch(
        &self,
        request: WorkFetchRequest,
    ) -> Result<WorkOutputStream<OutputEvent>, WorkGatewayError> {
        self.request(WorkRequest::Fetch(request))
    }
    fn run(
        &self,
        job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        self.request(WorkRequest::Job(JobInput::Compute {
            environment: job.environment,
            plan: job.plan,
            inputs: job.inputs,
            content: Arc::new(job.content),
        }))
    }
    /// Finishes accepted work, then closes the target's endpoint.
    fn drain(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
        self.admission.close();
        self.tasks.close();
        Box::pin(async move {
            let drained = self.tasks.drain().await;
            if let Some(endpoint) = self.inner.target.endpoint()
                && !endpoint.is_closed()
            {
                endpoint.close().await;
            }
            drained
        })
    }
}

fn execution(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Execution(Box::new(e))
}
fn rejected(e: impl std::error::Error + Send + Sync + 'static) -> WorkGatewayError {
    WorkGatewayError::Rejected(Box::new(e))
}

/// What every presentation reports for a failed run.
fn gateway_error(error: ExecutionError) -> WorkGatewayError {
    match error {
        ExecutionError::Grant(error) => grant_error(error),
        ExecutionError::Job(error) => rejected(error),
        ExecutionError::Identity => rejected(ExecutionError::Identity),
        ExecutionError::Stopped(error) => WorkGatewayError::Timeout(Box::new(error)),
        error => execution(error),
    }
}

fn grant_error(e: GrantClientError) -> WorkGatewayError {
    use hellas_rpc::pb::work::{GrantRefusalCode as C, WorkRefused};
    let code = match &e {
        GrantClientError::Refused { code, .. } => Some(*code),
        GrantClientError::Wire(status)
        | GrantClientError::Client(hellas_client::ClientError::Wire { source: status, .. })
            if matches!(
                status.code(),
                hellas_wire::WireCode::PermissionDenied | hellas_wire::WireCode::Unauthenticated
            ) =>
        {
            Some(C::Unauthorized)
        }
        GrantClientError::Store(store) => WorkRefused::from(store)
            .grant
            .and_then(|r| C::try_from(r.code).ok()),
        GrantClientError::Grant(grant) => WorkRefused::from(
            &hellas_authority::work_store::grant::NodeStoreError::Grant(grant.clone()),
        )
        .grant
        .and_then(|r| C::try_from(r.code).ok()),
        _ => None,
    };
    if matches!(
        e,
        GrantClientError::Timeout | GrantClientError::AdmissionExpired
    ) {
        return WorkGatewayError::Timeout(Box::new(e));
    }
    let unreachable = match &e {
        GrantClientError::Wire(status)
        | GrantClientError::Client(hellas_client::ClientError::Wire { source: status, .. }) => {
            status.code() == hellas_wire::WireCode::Unavailable
        }
        GrantClientError::Client(hellas_client::ClientError::Source { source, .. }) => {
            source.is::<iroh::endpoint::ConnectError>()
        }
        _ => false,
    };
    if unreachable {
        return WorkGatewayError::Unreachable(Box::new(e));
    }
    match code {
        Some(C::Budget) => WorkGatewayError::Quota(Box::new(e)),
        Some(C::Concurrency | C::QueueCapacity | C::StateCapacity) => WorkGatewayBusy.into(),
        Some(
            C::Unauthorized
            | C::Expired
            | C::Paused
            | C::Revoked
            | C::Quarantined
            | C::StaleGeneration
            | C::StaleRevision,
        ) => WorkGatewayError::Denied(Box::new(e)),
        Some(
            C::Malformed
            | C::OutOfScope
            | C::Origin
            | C::PathMethod
            | C::Tls
            | C::Credential
            | C::Headers
            | C::GenerationCap
            | C::StreamUsage
            | C::ResponseCap,
        ) => rejected(e),
        _ => execution(e),
    }
}
#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
mod grant_tests;

#[cfg(test)]
mod task_tests {
    use super::WorkTasks;
    use hellas_gateway::WorkShutdownError;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn cancelled_drain_keeps_tasks_even_when_state_is_poisoned() {
        for poison in [false, true] {
            let tasks = WorkTasks::default();
            let (release, released) = oneshot::channel();
            let (finished, completed) = oneshot::channel();
            tasks
                .spawn(async move {
                    released.await.unwrap();
                    finished.send(()).unwrap();
                })
                .unwrap();
            if poison {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let _state = tasks.state.lock().unwrap();
                        panic!("inject poisoned task state");
                    }))
                    .is_err()
                );
            }
            {
                let mut first = std::pin::pin!(tasks.drain());
                assert!(futures::poll!(&mut first).is_pending());
            }
            assert!(tasks.spawn(async {}).is_err());
            let mut second = std::pin::pin!(tasks.drain());
            assert!(futures::poll!(&mut second).is_pending());
            release.send(()).unwrap();
            let result = second.await;
            completed.await.unwrap();
            if poison {
                assert!(matches!(result, Err(WorkShutdownError::Poisoned)));
            } else {
                result.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn task_panic_is_reported_after_other_work_finishes() {
        let tasks = WorkTasks::default();
        tasks
            .spawn(async {
                panic!("inject gateway task panic");
            })
            .unwrap();
        let (release, released) = oneshot::channel();
        tasks
            .spawn(async {
                released.await.unwrap();
            })
            .unwrap();
        let mut draining = std::pin::pin!(tasks.drain());
        assert!(futures::poll!(&mut draining).is_pending());
        tokio::task::yield_now().await;
        assert!(futures::poll!(&mut draining).is_pending());
        release.send(()).unwrap();
        assert!(matches!(draining.await, Err(WorkShutdownError::Task(error)) if error.is_panic()));
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    use futures::StreamExt;

    type TestRequester = Requester<OutputEvent, WorkGatewayError>;

    #[test]
    fn fetch_prefix_preserves_batched_events_and_split_trailing_frames() {
        use hellas_rpc::protocol::invocation::fetch;
        let expected: Vec<_> = (0..100)
            .map(|index| OutputEvent::TextDelta {
                index,
                delta: format!("delta {index}"),
                channel: hellas_rpc::output::TextChannel::Output,
            })
            .collect();
        let wire: Vec<_> = expected
            .iter()
            .flat_map(|event| {
                fetch::frame_event(&hellas_rpc::fetch::encode_fetch_event_payload(event).unwrap())
                    .unwrap()
            })
            .collect();
        for size in [1, 3, 127, wire.len() - 1, wire.len()] {
            let mut pending = Vec::new();
            let mut actual = Vec::new();
            let mut offset = 0;
            for bytes in wire.chunks(size) {
                actual.extend(
                    fetch_prefix(
                        ArtifactChunk {
                            name: fetch::RESPONSE_EVENTS.into(),
                            format: fetch::RESPONSE_EVENTS_FORMAT.into(),
                            offset,
                            bytes: hellas_rpc::JsonBytes(bytes.to_vec()),
                        },
                        &mut pending,
                    )
                    .unwrap(),
                );
                offset += bytes.len() as u64;
            }
            assert_eq!(actual, expected, "chunk size {size}");
            assert!(pending.is_empty());
        }
    }

    #[test]
    fn compute_preserves_named_buffers_and_raw_emissions() {
        let mut pending = Vec::new();
        for (name, offset) in [("transcription", 0), ("transcription", 3), ("emitted", 0)] {
            let chunk = ArtifactChunk {
                name: name.into(),
                format: "catena.bytes.v1".into(),
                offset,
                bytes: hellas_rpc::JsonBytes(vec![0, 255, 17]),
            };
            let events = ComputeEvent::prefix(chunk.clone(), &mut pending).unwrap();
            assert!(matches!(&events[..], [ComputeEvent::Output(output)] if output == &chunk));
        }
        // Emissions are values, not necessarily u32 tokenizer ids; chunk
        // boundaries may split a value. Only the presentation interprets them.
        let bytes = u64::MAX.to_le_bytes();
        for (offset, bytes) in [(0, &bytes[..3]), (3, &bytes[3..])] {
            let events = ComputeEvent::prefix(
                ArtifactChunk {
                    name: "emitted".into(),
                    format: "catena.u64le.v1".into(),
                    offset,
                    bytes: hellas_rpc::JsonBytes(bytes.to_vec()),
                },
                &mut pending,
            )
            .unwrap();
            assert!(matches!(&events[..], [ComputeEvent::Output(chunk)]
                if chunk.name == "emitted" && chunk.format == "catena.u64le.v1" && chunk.offset == offset && chunk.bytes.as_bytes() == bytes));
        }
        assert!(pending.is_empty());
    }

    #[test]
    fn compute_completion_preserves_buffers_failure_and_provider() {
        use hellas_rpc::protocol::invocation::{
            Artifact,
            compute::RunMetadata,
            output::{FailureReason, Outcome},
        };
        let provider = hellas_auth::ProducerSigningKey::from_secret_bytes([17; 32])
            .unwrap()
            .public_key();
        let mut output = InvocationOutput {
            outcome: Outcome::Succeeded,
            artifacts: vec![Artifact::new(
                "transcription",
                "catena.bytes.v1",
                vec![1, 2, 3],
            )],
            metadata: hellas_rpc::JsonBytes(
                hellas_rpc::canonical_dag_cbor(&RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        };
        for failed in [false, true] {
            if failed {
                output.outcome = Outcome::Failed(FailureReason::Execution);
                output.metadata = hellas_rpc::JsonBytes(Vec::new());
            }
            let event = ComputeEvent::completed(&output, &provider).unwrap();
            assert!(
                matches!(event, ComputeEvent::Done { output: actual, provider: signer }
                if actual == output && signer == provider)
            );
        }
    }

    fn text(delta: &str) -> OutputEvent {
        OutputEvent::TextDelta {
            index: 0,
            delta: delta.into(),
            channel: hellas_rpc::output::TextChannel::Output,
        }
    }

    #[tokio::test]
    async fn buffered_reconnect_burst_is_delivered_and_releases_byte_budget() {
        let (requester, mut response) = TestRequester::new();
        let budget = requester.budget.clone();
        // Retained output can arrive in one burst before HTTP gets a poll.
        for position in 0..128 {
            requester.emit(Ok(WorkEvent::Output(text(&position.to_string()))));
        }
        drop(requester);
        let mut count = 0;
        while let Some(event) = response.next().await {
            event.unwrap();
            count += 1;
        }
        assert_eq!(count, 128);
        assert_eq!(budget.available_permits(), OUTPUT_BUFFER_BYTES);
    }

    #[tokio::test]
    async fn a_transcript_larger_than_the_output_budget_is_delivered() {
        let (requester, mut response) = TestRequester::new();
        // A job may be authorised to spool more evidence than the whole
        // slow-consumer queue holds. That evidence is mandatory and already
        // resident, so it must not be charged against the reader's budget;
        // otherwise a verified, already-paid result cannot be delivered and
        // its completion is suppressed with it.
        let transcript = vec![0xab; OUTPUT_BUFFER_BYTES + 4096];
        requester.emit(Ok(WorkEvent::Transcript(transcript.clone())));
        requester.emit(Ok(WorkEvent::Output(text("done"))));
        drop(requester);
        assert!(
            matches!(response.next().await.unwrap().unwrap(), WorkEvent::Transcript(actual) if actual == transcript),
            "the whole signed transcript is delivered"
        );
        assert!(
            matches!(
                response.next().await.unwrap().unwrap(),
                WorkEvent::Output(_)
            ),
            "and the completion follows it"
        );
        assert!(response.next().await.is_none());
    }

    #[tokio::test]
    async fn slow_reader_gets_an_error_without_blocking_payment() {
        let (requester, mut response) = TestRequester::new();
        // A stalled reader cannot retain more than the byte budget, and the
        // synchronous producer callback still returns without waiting on it.
        let half = OUTPUT_BUFFER_BYTES / 2 - OUTPUT_EVENT_OVERHEAD - text("").bytes();
        for _ in 0..3 {
            requester.emit(Ok(WorkEvent::Output(text(&"x".repeat(half)))));
        }
        assert_eq!(requester.budget.available_permits(), 0);
        assert!(
            response
                .next()
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("too slow")
        );
        assert!(requester.is_closed());
        assert!(response.next().await.is_none());
    }
}
