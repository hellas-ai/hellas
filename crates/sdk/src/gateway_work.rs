//! One gateway backend over any source of work. A paid pool and a grant
//! session differ only in how they fund and run one request; input
//! preparation, admission, streamed output and shutdown are shared here.
use crate::job::{JobError, JobInput};
use futures::{future::BoxFuture, stream::BoxStream};
use hellas_authority::model::grant::resource::HttpsResource;
use hellas_gateway::{
    ComputeEvent, WorkEvent, WorkExecutionBackend, WorkFetchRequest, WorkGatewayBusy,
    WorkGatewayError, WorkOutputStream, WorkShutdownError,
};
use hellas_rpc::http_fetch::HttpFetchRequest;
use hellas_rpc::output::OutputEvent;
use hellas_rpc::protocol::invocation::output::{ArtifactChunk, ArtifactPrefix, InvocationOutput};
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy};
use std::sync::Arc;
use std::time::Duration;
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
    while let Some(header) = pending.get(..4) {
        let length = u32::from_be_bytes(header.try_into().map_err(output_error)?) as usize;
        if length > hellas_rpc::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
            return Err(output_error(std::io::Error::other(
                "Fetch frame exceeds payload bound",
            )));
        }
        let end = 4 + length;
        if pending.len() < end {
            break;
        }
        events.push(
            hellas_rpc::fetch::decode_fetch_event_payload(&pending[4..end])
                .map_err(output_error)?,
        );
        pending.drain(..end);
    }
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

/// A verified completion, the provider key that signed it, and the
/// canonical bytes of the signed transcript it was verified from.
pub struct Completed {
    pub output: InvocationOutput,
    pub provider: hellas_auth::PublicKey,
    pub transcript: Vec<u8>,
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
        let bytes = match &event {
            Ok(event) => event_bytes(event),
            Err(error) => error.to_string().len(),
        };
        emit(&self.sender, &self.overflow, &self.budget, event, bytes);
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
    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    pub(crate) async fn closed(&self) {
        self.sender.closed().await
    }
}

/// What HTTP asks for, before any source has matched it to a policy.
pub enum WorkRequest {
    /// Pinned to one provider by the HTTP account router; the contract comes
    /// from the admitting policy.
    Fetch(WorkFetchRequest),
    /// A complete program input; any admitting provider may run it.
    Compute(JobInput),
}

impl WorkRequest {
    /// The provider this request must run on, if it names one.
    pub fn pinned(&self) -> Option<iroh::EndpointId> {
        match self {
            WorkRequest::Fetch(request) => Some(request.provider),
            WorkRequest::Compute(_) => None,
        }
    }

    /// The one input `policy` admits for this request. A Fetch tries each
    /// Fetch contract of `policy`; an HTTPS body is first repaired under
    /// `https`. Two admitting contracts are refused, never chosen between.
    pub fn admitted(
        &self,
        policy: &InvocationPolicy,
        https: Option<&HttpsResource>,
        assurance: hellas_rpc::Assurance,
        retain: bool,
    ) -> Result<JobInput, JobError> {
        let request = match self {
            WorkRequest::Compute(input) => {
                input.admits(policy, retain)?;
                return Ok(input.clone());
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
                    let mut http = HttpFetchRequest::decode(&request.body)
                        .map_err(|e| JobError::Invalid(e.to_string()))?;
                    https
                        .prepare(&mut http)
                        .map_err(|e| JobError::Invalid(e.to_string()))?;
                    serde_json::to_vec(&http)?
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

/// How one source funds and runs gateway requests.
pub trait WorkSource: Send + Sync + Sized + 'static {
    type Error: From<WorkGatewayError> + std::fmt::Display + Send + 'static;
    /// One request, already matched to this source's policies.
    type Request: Send + 'static;
    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute>;
    /// Matches the request to this source's policies and builds its input.
    fn request(&self, request: WorkRequest) -> Result<Self::Request, Self::Error>;
    /// Runs the request to its verified completion. Work not yet proposed
    /// stops when the requester disconnects; proposed work runs to completion.
    fn run<E: GatewayEvent>(
        self: Arc<Self>,
        request: Self::Request,
        requester: Requester<E, Self::Error>,
    ) -> BoxFuture<'static, Result<Option<Completed>, Self::Error>>;
    fn timeout(&self) -> Option<Duration>;
    fn gateway_error(error: Self::Error) -> WorkGatewayError;
    fn shutdown(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>>;
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

/// One gateway backend: shared admission, output delivery and shutdown over a source.
pub struct WorkGateway<S> {
    pub(crate) source: Arc<S>,
    pub(crate) admission: Arc<Semaphore>,
    tasks: WorkTasks,
    pub(crate) endpoints: tokio::sync::Mutex<Vec<iroh::Endpoint>>,
}
impl<S: WorkSource> WorkGateway<S> {
    pub(crate) fn new(source: S, max_pending: usize) -> Self {
        Self {
            source: Arc::new(source),
            admission: Arc::new(Semaphore::new(max_pending)),
            tasks: WorkTasks::default(),
            endpoints: tokio::sync::Mutex::new(Vec::new()),
        }
    }
    pub(crate) fn with_endpoint(mut self, endpoint: Option<iroh::Endpoint>) -> Self {
        self.endpoints = tokio::sync::Mutex::new(endpoint.into_iter().collect());
        self
    }
    pub(crate) fn with_endpoints(mut self, endpoints: Vec<iroh::Endpoint>) -> Self {
        self.endpoints = tokio::sync::Mutex::new(endpoints);
        self
    }
    pub(crate) fn submit<E: GatewayEvent>(
        &self,
        request: S::Request,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<RequestStream<E, S::Error>, S::Error> {
        if self.admission.is_closed() {
            return Err(WorkGatewayError::from(WorkGatewayBusy).into());
        }
        let (requester, stream) = Requester::<E, S::Error>::new();
        let source = self.source.clone();
        self.tasks
            .spawn(async move {
                let _permit = permit;
                match source.run(request, requester.clone()).await {
                    Ok(Some(completed)) => {
                        requester.emit(Ok(WorkEvent::Transcript(completed.transcript.clone())));
                        requester.emit(
                            E::completed(&completed.output, &completed.provider)
                                .map(WorkEvent::Output)
                                .map_err(Into::into),
                        )
                    }
                    Ok(None) => {}
                    Err(error) => requester.emit(Err(error)),
                }
            })
            .map_err(|busy| S::Error::from(busy.into()))?;
        Ok(stream)
    }
    fn request<E: GatewayEvent>(
        &self,
        request: WorkRequest,
    ) -> Result<WorkOutputStream<E>, WorkGatewayError> {
        use futures::StreamExt as _;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| WorkGatewayBusy)?;
        let request = self.source.request(request).map_err(S::gateway_error)?;
        let stream = self
            .submit::<E>(request, Some(permit))
            .map_err(S::gateway_error)?;
        Ok(Box::pin(
            stream.map(|event| event.map_err(S::gateway_error)),
        ))
    }
}
/// Close each distinct live endpoint once. Clones observe the same closed
/// state, while independently bound endpoints remain individually owned.
pub(crate) async fn close_endpoints(endpoints: &mut Vec<iroh::Endpoint>) {
    while let Some(endpoint) = endpoints.last() {
        if !endpoint.is_closed() {
            endpoint.close().await;
        }
        endpoints.pop();
    }
}

impl<S: WorkSource> WorkExecutionBackend for WorkGateway<S> {
    fn fetch_routes(&self) -> Vec<hellas_gateway::FetchRoute> {
        self.source.fetch_routes()
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
        self.request(WorkRequest::Compute(JobInput::Compute {
            environment: job.environment,
            plan: job.plan,
            inputs: job.inputs,
            content: hellas_channel::content::InvocationContent::Ephemeral(job.content),
        }))
    }
    fn timeout(&self) -> Option<Duration> {
        self.source.timeout()
    }
    fn drain(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
        self.admission.close();
        self.tasks.close();
        Box::pin(async move {
            let tasks = self.tasks.drain().await;
            let source = self.source.shutdown().await;
            let mut endpoints = self.endpoints.lock().await;
            close_endpoints(&mut endpoints).await;
            tasks.and(source)
        })
    }
}

#[cfg(test)]
mod task_tests {
    use super::WorkTasks;
    use hellas_gateway::WorkShutdownError;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn endpoint_clones_and_distinct_endpoints_are_drained() {
        use iroh::endpoint::presets;
        let first = iroh::Endpoint::builder(presets::Minimal)
            .bind()
            .await
            .unwrap();
        let second = iroh::Endpoint::builder(presets::Minimal)
            .bind()
            .await
            .unwrap();
        let mut endpoints = vec![first.clone(), first.clone(), second.clone()];
        super::close_endpoints(&mut endpoints).await;
        assert!(endpoints.is_empty());
        assert!(first.is_closed());
        assert!(second.is_closed());
    }

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
