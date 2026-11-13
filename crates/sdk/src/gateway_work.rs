//! The gateway backend: every HTTP request becomes one job on the job
//! commands' target, run by the same [`Executor`]. Admission, streamed
//! output and shutdown are shared here.
pub(crate) mod provider;
use crate::execution::{ExecutionError, Executor};
use crate::grant_client::GrantClientError;
use crate::job::{Job, JobError, JobInput};
use futures::{future::BoxFuture, stream::BoxStream};
use hellas_authority::model::grant::records::GrantPolicy;
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
    job: Arc<hellas_gateway::jobs::Job>,
    sender: mpsc::Sender<BufferedEvent<WorkEvent<E>, X>>,
    overflow: watch::Sender<bool>,
    budget: Arc<Semaphore>,
}
impl<E, X> Clone for Requester<E, X> {
    fn clone(&self) -> Self {
        Self {
            job: self.job.clone(),
            sender: self.sender.clone(),
            overflow: self.overflow.clone(),
            budget: self.budget.clone(),
        }
    }
}
impl<E: GatewayEvent, X: std::fmt::Display + Send + 'static> Requester<E, X> {
    pub(crate) fn new(job: Arc<hellas_gateway::jobs::Job>) -> (Self, RequestStream<E, X>)
    where
        X: From<WorkGatewayError>,
    {
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let requester = Self {
            job: job.clone(),
            sender,
            overflow,
            budget: Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES)),
        };
        (
            requester,
            Box::pin(futures::StreamExt::take_until(
                response_stream(receiver, overflow_receiver, || {
                    X::from(WorkGatewayError::Execution(Box::new(
                        std::io::Error::other(
                            "gateway output consumer is too slow; accepted work continues",
                        ),
                    )))
                }),
                async move { job.cancelled().await },
            )),
        )
    }
    pub(crate) fn emit(&self, event: Result<WorkEvent<E>, X>) {
        if self.job.is_cancelled() {
            return;
        }
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
        Arc::new(move |provenance| {
            requester.job.accepted();
            requester.emit(Ok(WorkEvent::Accepted(provenance)));
        })
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
        let job = self.job.clone();
        crate::execution::stop_on(async move {
            tokio::select! { _ = sender.closed() => {}, _ = job.cancelled() => {} }
        })
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
#[expect(clippy::large_enum_variant, reason = "one owned input per request")]
pub enum WorkRequest {
    /// The contract comes from the admitting policy.
    Fetch(WorkFetchRequest),
    /// A complete input; any admitting provider may run it.
    Job(JobInput),
}

impl WorkRequest {
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

/// A runtime backend and its shared scheduling state.
#[derive(Clone)]
pub struct Backend {
    id: String,
    instance: u64,
    jobs: Arc<hellas_gateway::jobs::Jobs>,
    evaluator: Option<String>,
    slots: Arc<Semaphore>,
    capacity: usize,
    down: Arc<std::sync::atomic::AtomicBool>,
    pub state: BackendState,
}

#[derive(Clone)]
pub enum BackendState {
    Local {
        execution: crate::execution::local::LocalExecution,
        timeout: std::time::Duration,
    },
    Fetch {
        execution: hellas_executor::ExecutorHandle,
        policy: InvocationPolicy,
    },
    Grant(Box<GrantBackend>),
    Paid(Box<PaidBackend>),
}

#[derive(Clone)]
pub struct PaidBackend {
    /// Absent until quoted; saved jobs already carry their policy.
    pub(crate) policy: Option<InvocationPolicy>,
    pub options: crate::paid_client::PaidWorkOptions,
    pub endpoint: iroh::Endpoint,
    pub settlement_key: hellas_kernel::Secp256k1Signer,
    pub owner: Arc<crate::client_owner::ClientOwner>,
    pub(crate) session: Arc<tokio::sync::Mutex<Option<crate::paid_client::PaidWorkSession>>>,
    active: Arc<std::sync::atomic::AtomicUsize>,
}
#[derive(Clone)]
pub struct GrantBackend {
    pub options: crate::grant_client::GrantSessionOptions,
    pub transport: crate::grant_client::GrantTransport,
    pub policy: GrantPolicy,
    pub(crate) channel: Arc<GrantChannel>,
}

#[derive(Default)]
pub(crate) struct GrantChannel {
    session: tokio::sync::Mutex<Option<crate::grant_client::GrantSession>>,
    active: Arc<std::sync::atomic::AtomicUsize>,
    members: std::sync::Mutex<std::collections::BTreeSet<String>>,
    retired: std::sync::atomic::AtomicBool,
    down: Arc<std::sync::atomic::AtomicBool>,
}
type GrantChannels = std::collections::BTreeMap<hellas_auth::Digest, std::sync::Weak<GrantChannel>>;
struct SessionUse(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for SessionUse {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}
impl GrantBackend {
    fn channel_id(&self) -> Option<hellas_authority::model::grant::ChannelId> {
        Some(
            self.options
                .target
                .offer()
                .channel(hellas_authority::model::grant::ChannelClient {
                    principal: self.options.principal,
                    node: hellas_auth::authority::NodeKey::from_public_key(
                        self.options.signer.public_key(),
                    )
                    .ok()?,
                }),
        )
    }
}

impl Backend {
    fn new(state: BackendState) -> Self {
        Self {
            id: String::new(),
            instance: 0,
            jobs: Default::default(),
            evaluator: None,
            slots: Arc::new(Semaphore::new(1)),
            capacity: 1,
            down: Default::default(),
            state,
        }
    }
    pub fn paid(
        policy: Option<InvocationPolicy>,
        options: crate::paid_client::PaidWorkOptions,
        endpoint: iroh::Endpoint,
        settlement_key: hellas_kernel::Secp256k1Signer,
        owner: Arc<crate::client_owner::ClientOwner>,
    ) -> Self {
        Self::new(BackendState::Paid(Box::new(PaidBackend {
            policy,
            options,
            endpoint,
            settlement_key,
            owner,
            session: Default::default(),
            active: Default::default(),
        })))
    }
    pub fn grant(
        policy: GrantPolicy,
        options: crate::grant_client::GrantSessionOptions,
        transport: crate::grant_client::GrantTransport,
    ) -> Self {
        Self::new(BackendState::Grant(Box::new(GrantBackend {
            options,
            transport,
            policy,
            channel: Default::default(),
        })))
    }
    pub fn local(
        execution: crate::execution::local::LocalExecution,
        timeout: std::time::Duration,
    ) -> Self {
        Self::new(BackendState::Local { execution, timeout })
    }
    pub fn fetch(execution: hellas_executor::ExecutorHandle, policy: InvocationPolicy) -> Self {
        Self::new(BackendState::Fetch { execution, policy })
    }
    pub fn policy(&self) -> Option<&InvocationPolicy> {
        match &self.state {
            BackendState::Local { .. } => None,
            BackendState::Fetch { policy, .. } => Some(policy),
            BackendState::Grant(grant) => Some(&grant.policy.invocation_policy),
            BackendState::Paid(paid) => paid.policy.as_ref(),
        }
    }
    /// The endpoint requests reach their provider through, if remote.
    pub fn endpoint(&self) -> Option<&iroh::Endpoint> {
        match &self.state {
            BackendState::Paid(paid) => Some(&paid.endpoint),
            BackendState::Grant(grant) => match &grant.transport {
                crate::grant_client::GrantTransport::Remote(endpoint) => Some(endpoint),
                crate::grant_client::GrantTransport::Local(_) => None,
            },
            BackendState::Local { .. } | BackendState::Fetch { .. } => None,
        }
    }

    /// Quote paid work before rendering a job. Saved jobs already carry their
    /// price and can execute without requesting another quote.
    pub async fn quote(&mut self) -> Result<u64, crate::paid_client::PaidClientError> {
        let BackendState::Paid(paid) = &mut self.state else {
            return Ok(0);
        };
        let quote = crate::paid_client::request_paid_quote(
            &paid.options,
            &paid.endpoint,
            &paid.settlement_key,
            paid.owner.principal(),
        )
        .await?;
        paid.options.expected_price = quote.policy.payment_policy.fixed_price;
        paid.policy = Some(quote.policy.invocation_policy);
        Ok(paid.options.expected_price)
    }

    /// The one job `request` becomes under this target's terms.
    fn job(&self, request: &WorkRequest) -> Result<Job, WorkGatewayError> {
        use hellas_rpc::Assurance::ProducerSigned;
        let local_policy;
        let (policy, https, assurance, price, paid) = match &self.state {
            BackendState::Local { timeout, .. } => {
                let WorkRequest::Job(input) = request else {
                    return Err(WorkGatewayError::Unsupported);
                };
                local_policy =
                    crate::execution::local::policy(input, *timeout).map_err(rejected)?;
                (&local_policy, None, ProducerSigned, 0, false)
            }
            BackendState::Fetch { policy, .. } => (policy, None, ProducerSigned, 0, false),
            BackendState::Grant(grant) => (
                &grant.policy.invocation_policy,
                grant.policy.https.as_ref(),
                grant.options.target.trust().required_assurance,
                0,
                false,
            ),
            BackendState::Paid(paid) => (
                paid.policy.as_ref().ok_or(WorkGatewayError::Unsupported)?,
                None,
                paid.options.assurance,
                paid.options.expected_price,
                true,
            ),
        };
        let input = request
            .admitted(policy, https, assurance, paid)
            .map_err(rejected)?;
        Job::from_input(price, input).map_err(rejected)
    }

    /// The Fetch schemas and routes admitted by this backend, each once.
    pub fn fetch_routes(&self) -> Vec<(hellas_rpc::FetchSchema, FetchRoutePolicy)> {
        let policy = self.policy();
        let mut routes = Vec::new();
        if let Some(policy) = policy {
            for admission in &policy.admissions {
                if let Admission::Fetch { admission } = admission {
                    let route = (admission.contract.schema(), admission.route.clone());
                    if !routes.contains(&route) {
                        routes.push(route);
                    }
                }
            }
        }
        routes
    }
}

pub fn grant_routes(
    policy: &GrantPolicy,
    id: &str,
) -> Result<Vec<hellas_gateway::Route>, WorkGatewayError> {
    if policy.https.is_some() {
        let (service, method, routes) = policy_http_routes(policy)?;
        return Ok(routes
            .into_iter()
            .map(|route| hellas_gateway::Route {
                backends: vec![id.into()],
                presentation: hellas_gateway::Presentation::Http {
                    targets: [(
                        id.into(),
                        hellas_gateway::HttpTarget {
                            service: service.clone(),
                            method: method.clone(),
                            route,
                        },
                    )]
                    .into(),
                },
            })
            .collect());
    }
    let Some(resource) = &policy.responses else {
        return Ok(vec![]);
    };
    let routes: Vec<_> = policy
        .invocation_policy
        .admissions
        .iter()
        .filter_map(|admission| match admission {
            Admission::Fetch { admission } => {
                Some((admission.contract.schema(), admission.route.clone()))
            }
            _ => None,
        })
        .collect();
    let mut sealed = routes.iter().filter_map(|(schema, route)| match route {
        FetchRoutePolicy::SealedRoute { service, method }
            if *schema == hellas_rpc::FetchSchema::StatelessResponsesV1 =>
        {
            Some((service, method))
        }
        _ => None,
    });
    let (service, method) = sealed.next().ok_or(WorkGatewayError::Unsupported)?;
    if sealed.next().is_some() {
        return Err(WorkGatewayError::Unsupported);
    }
    Ok(vec![hellas_gateway::Route {
        backends: vec![id.into()],
        presentation: hellas_gateway::Presentation::Responses {
            service: service.clone(),
            method: method.clone(),
            models: vec![resource.model.clone()],
            overrides: Default::default(),
        },
    }])
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

/// A configured execution destination. Ids are scoped to one daemon document.
pub struct BackendEntry {
    pub backend: Backend,
    pub evaluator: Option<String>,
    pub max_in_flight: std::num::NonZeroUsize,
}

pub struct ExecutorGateway {
    backends: std::collections::BTreeMap<String, Arc<Backend>>,
    signer: Arc<hellas_auth::ProducerSigningKey>,
    pub jobs: Arc<hellas_gateway::jobs::Jobs>,
    grants: Arc<std::sync::Mutex<GrantChannels>>,
}
impl ExecutorGateway {
    pub fn backend(&self, id: &str) -> Option<&Backend> {
        self.backends.get(id).map(AsRef::as_ref)
    }

    pub fn new(
        backends: std::collections::BTreeMap<String, BackendEntry>,
        signer: Arc<hellas_auth::ProducerSigningKey>,
    ) -> Arc<Self> {
        Self::prepare(
            backends,
            signer,
            Arc::new(hellas_gateway::jobs::Jobs::default()),
            None,
            &Default::default(),
        )
    }

    pub(crate) fn prepare(
        backends: std::collections::BTreeMap<String, BackendEntry>,
        signer: Arc<hellas_auth::ProducerSigningKey>,
        jobs: Arc<hellas_gateway::jobs::Jobs>,
        previous: Option<&Self>,
        reuse: &std::collections::BTreeSet<String>,
    ) -> Arc<Self> {
        Self::prepare_identified(backends, signer, jobs, previous, reuse, &[])
    }

    pub(crate) fn prepare_identified(
        backends: std::collections::BTreeMap<String, BackendEntry>,
        signer: Arc<hellas_auth::ProducerSigningKey>,
        jobs: Arc<hellas_gateway::jobs::Jobs>,
        previous: Option<&Self>,
        reuse: &std::collections::BTreeSet<String>,
        identities: &[hellas_gateway::BackendInfo],
    ) -> Arc<Self> {
        let grants: Arc<std::sync::Mutex<GrantChannels>> =
            previous.map_or_else(Default::default, |old| old.grants.clone());
        let mut channels = grants.lock().unwrap();
        channels.retain(|_, channel| channel.strong_count() > 0);
        let mut resolved: std::collections::BTreeMap<_, _> = previous
            .into_iter()
            .flat_map(|previous| previous.backends.iter())
            .filter(|(id, _)| reuse.contains(*id))
            .map(|(id, inner)| (id.clone(), inner.clone()))
            .collect();
        resolved.extend(backends.into_iter().map(|(id, entry)| {
            let mut backend = entry.backend;
            backend.id = id.clone();
            backend.instance = identities
                .iter()
                .find(|info| info.id == id)
                .map_or_else(rand::random, |info| info.instance);
            backend.jobs = jobs.clone();
            backend.evaluator = entry.evaluator;
            backend.capacity = entry.max_in_flight.get();
            backend.slots = Arc::new(Semaphore::new(backend.capacity));
            backend.down = Default::default();
            if let BackendState::Grant(grant) = &mut backend.state {
                if let Some(id) = grant.channel_id() {
                    let retained = channels.entry(id.0).or_default();
                    if let Some(channel) = retained.upgrade() {
                        grant.channel = channel;
                    } else {
                        *retained = Arc::downgrade(&grant.channel);
                    }
                }
                grant
                    .channel
                    .retired
                    .store(false, std::sync::atomic::Ordering::Release);
                backend.down = grant.channel.down.clone();
            }
            (id, Arc::new(backend))
        }));
        for channel in channels.values().filter_map(std::sync::Weak::upgrade) {
            channel.members.lock().unwrap().clear();
        }
        for (id, backend) in &resolved {
            if let BackendState::Grant(grant) = &backend.state {
                grant.channel.members.lock().unwrap().insert(id.clone());
            }
        }
        drop(channels);
        Arc::new(Self {
            backends: resolved,
            signer,
            jobs,
            grants,
        })
    }

    pub(crate) async fn retire(&self, next: &Self) -> Result<(), WorkShutdownError> {
        let mut failure = None;
        for (id, backend) in &self.backends {
            if next
                .backends
                .get(id)
                .is_some_and(|next| Arc::ptr_eq(backend, next))
            {
                continue;
            }
            backend.slots.close();
            if let BackendState::Grant(grant) = &backend.state {
                let retained = next.backends.values().any(|next| {
                    matches!(&next.state,
                    BackendState::Grant(other) if Arc::ptr_eq(&grant.channel, &other.channel))
                });
                grant
                    .channel
                    .retired
                    .store(!retained, std::sync::atomic::Ordering::Release);
            }
            if let Err(error) = backend.close_sessions().await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    fn request<E: GatewayEvent>(
        &self,
        id: &str,
        request_job: Arc<hellas_gateway::jobs::Job>,
        request: WorkRequest,
    ) -> Result<WorkOutputStream<E>, WorkGatewayError> {
        let inner = self
            .backends
            .get(id)
            .ok_or(WorkGatewayError::Unsupported)?
            .clone();
        let permit = inner
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| WorkGatewayError::PreProposal(Box::new(WorkGatewayBusy.into())))?;
        let job = inner
            .job(&request)
            .map_err(|error| WorkGatewayError::PreProposal(Box::new(error)))?;
        let session_use = inner.use_session();
        let (requester, stream) = Requester::<E, WorkGatewayError>::new(request_job.clone());
        let signer = self.signer.clone();
        request_job
            .spawn(id, async move {
                let _permit = permit;
                if let Err(error) = inner
                    .run(job, requester.clone(), &signer, session_use)
                    .await
                {
                    requester.emit(Err(error));
                }
            })
            .map_err(|error| WorkGatewayError::PreProposal(Box::new(error.into())))?;
        Ok(stream)
    }
}
impl Backend {
    async fn close_sessions(&self) -> Result<(), WorkShutdownError> {
        match &self.state {
            BackendState::Grant(target) => {
                use std::sync::atomic::Ordering;
                if !(target.channel.retired.load(Ordering::Acquire)
                    || target.channel.down.load(Ordering::Acquire))
                    || target.channel.active.load(Ordering::Acquire) != 0
                {
                    return Ok(());
                }
                let mut session = target.channel.session.lock().await;
                if (target.channel.retired.load(Ordering::Acquire)
                    || target.channel.down.load(Ordering::Acquire))
                    && target.channel.active.load(Ordering::Acquire) == 0
                    && let Some(mut session) = session.take()
                {
                    session
                        .shutdown()
                        .await
                        .map_err(|error| WorkShutdownError::Recovery(Arc::new(error)))?;
                }
            }
            BackendState::Paid(target) => {
                let mut session = target.session.lock().await;
                if (self.down.load(std::sync::atomic::Ordering::Acquire) || self.slots.is_closed())
                    && target.active.load(std::sync::atomic::Ordering::Acquire) == 0
                    && let Some(mut session) = session.take()
                {
                    session.shutdown().await;
                }
            }
            BackendState::Local { .. } | BackendState::Fetch { .. } => {}
        }
        Ok(())
    }
    fn use_session(&self) -> Option<SessionUse> {
        let active = match &self.state {
            BackendState::Paid(paid) => &paid.active,
            BackendState::Grant(grant) => &grant.channel.active,
            _ => return None,
        };
        active.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Some(SessionUse(active.clone()))
    }

    fn health(&self, down: bool) {
        self.jobs.change(|| {
            if self.down.swap(down, std::sync::atomic::Ordering::AcqRel) == down {
                return Vec::new();
            }
            let ids = match &self.state {
                BackendState::Grant(grant) => grant
                    .channel
                    .members
                    .lock()
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect(),
                _ => vec![self.id.clone()],
            };
            ids.into_iter()
                .map(|id| hellas_gateway::jobs::Event::Backend {
                    id,
                    down,
                    reason: if down {
                        "session failed"
                    } else {
                        "session opened"
                    }
                    .into(),
                })
                .collect()
        });
    }

    async fn run<E: GatewayEvent>(
        &self,
        job: Job,
        requester: Requester<E, WorkGatewayError>,
        signer: &hellas_auth::ProducerSigningKey,
        session_use: Option<SessionUse>,
    ) -> Result<(), WorkGatewayError> {
        use crate::execution::AttemptError;
        let stop = requester.stop();
        let request = WorkRequest::Job(job.input().clone());
        let run = match &self.state {
            BackendState::Paid(target) => {
                self.run_paid(target, &job, &stop, &requester, signer).await
            }
            BackendState::Grant(target) => {
                self.run_grant(target, &request, &stop, &requester).await
            }
            BackendState::Fetch { .. } | BackendState::Local { .. } => {
                self.run_here(&job, stop, &requester, signer).await
            }
        };
        let result = match run {
            Ok(_) => Ok(()),
            Err(AttemptError::PreProposal(error)) => {
                requester.job.pre_proposal_failure();
                if backend_failed(&error) {
                    self.health(true);
                }
                Err(WorkGatewayError::PreProposal(Box::new(gateway_error(
                    *error,
                ))))
            }
            Err(AttemptError::Committed(error)) => {
                if backend_failed(&error)
                    && !matches!(
                        &*error,
                        ExecutionError::Grant(GrantClientError::Refused { .. })
                    )
                {
                    self.health(true);
                }
                Err(gateway_error(*error))
            }
            Err(AttemptError::Stopped(crate::execution::RequestStopped::Disconnected)) => {
                requester.job.stopped();
                Ok(())
            }
            Err(AttemptError::Stopped(error)) => Err(gateway_error(error.into())),
        };
        drop(session_use);
        // Session ownership ends before the task releases its scheduling permit.
        finish_job(&requester.job, result, self.close_sessions().await)
    }

    async fn run_here<E: GatewayEvent>(
        &self,
        job: &Job,
        stop: crate::execution::Stop,
        requester: &Requester<E, WorkGatewayError>,
        signer: &hellas_auth::ProducerSigningKey,
    ) -> Result<crate::execution::Completed, crate::execution::AttemptError> {
        use crate::execution::AttemptError;
        let result = Executor::new(self.clone())
            .run(
                job,
                signer,
                None,
                stop,
                requester.observers(),
                requester.delivery(),
            )
            .await;
        result.map_err(|error| match error {
            ExecutionError::LocalAdmission(_) => AttemptError::PreProposal(Box::new(error)),
            ExecutionError::Stopped(stopped) => AttemptError::Stopped(stopped),
            _ => AttemptError::Committed(Box::new(error)),
        })
    }
    async fn run_paid<E: GatewayEvent>(
        &self,
        target: &PaidBackend,
        job: &Job,
        stop: &crate::execution::Stop,
        requester: &Requester<E, WorkGatewayError>,
        signer: &hellas_auth::ProducerSigningKey,
    ) -> Result<crate::execution::Completed, crate::execution::AttemptError> {
        use crate::execution::{AttemptError, PaidOpen, before_proposal, open_paid_session};
        use std::sync::atomic::Ordering;
        let pre = |error: ExecutionError| AttemptError::PreProposal(Box::new(error));
        let committed = |error: ExecutionError| AttemptError::Committed(Box::new(error));
        let PaidBackend {
            options,
            endpoint,
            settlement_key,
            owner,
            ..
        } = target;
        let mut guard = before_proposal(None, stop, None, target.session.lock()).await?;
        if self.down.load(Ordering::Acquire) && guard.is_some() {
            return Err(pre(ExecutionError::RecoveryRequired));
        }
        if guard.is_none() {
            let opened = before_proposal(
                None,
                stop,
                None,
                Box::pin(async {
                    let mut session = open_paid_session(
                        options.clone(),
                        endpoint.clone(),
                        settlement_key.clone(),
                        owner.clone(),
                        Default::default(),
                        PaidOpen::Job(job),
                        None,
                    )
                    .await?;
                    session
                        .run(None, &crate::paid_client::empty_content(), true, None)
                        .await?;
                    Ok::<_, ExecutionError>(session)
                }),
            )
            .await?
            .map_err(pre)?;
            *guard = Some(opened);
            self.health(false);
        }
        let session = guard
            .as_mut()
            .ok_or_else(|| pre(ExecutionError::Identity))?;
        let floor = session
            .with_state(|state| state.proposal_nonce_high_water())
            .await
            .map_err(|error| pre(error.into()))?;
        let proposed = requester.job.proposal();
        let proposal = before_proposal(
            None,
            stop,
            Some(&proposed),
            session.propose_job(job, signer, &proposed),
        )
        .await?;
        let delivery = match proposal {
            Ok(delivery) => delivery,
            Err(error) => {
                let after = session
                    .with_state(|state| state.proposal_nonce_high_water())
                    .await
                    .ok();
                let error = ExecutionError::from(error);
                return Err(
                    if !proposed.load(Ordering::Acquire) && after == Some(floor) {
                        pre(error)
                    } else {
                        committed(error)
                    },
                );
            }
        };
        drop(guard);
        let collected = delivery
            .collect(
                Some(&requester.progress()),
                Some(&requester.accepted()),
                None,
            )
            .await
            .map_err(|error| committed(error.into()))?;
        // Payment uses the proposal mutex: no new proposal can pass an
        // unacknowledged cumulative certificate.
        let mut guard = target.session.lock().await;
        let result = guard
            .as_mut()
            .ok_or_else(|| committed(ExecutionError::Identity))?
            .pay(collected)
            .await;
        let result = result.map_err(|error| committed(error.into()))?;
        drop(guard);
        let completed = crate::execution::paid_completed(result);
        requester.delivery()(&completed)
            .map_err(|error| committed(ExecutionError::Delivery(error)))?;
        Ok(completed)
    }

    async fn run_grant<E: GatewayEvent>(
        &self,
        target: &GrantBackend,
        request: &WorkRequest,
        stop: &crate::execution::Stop,
        requester: &Requester<E, WorkGatewayError>,
    ) -> Result<crate::execution::Completed, crate::execution::AttemptError> {
        use crate::execution::{AttemptError, before_proposal, prepare_grant_input};
        let pre = |error: ExecutionError| AttemptError::PreProposal(Box::new(error));
        let committed = |error: ExecutionError| AttemptError::Committed(Box::new(error));
        let GrantBackend {
            options,
            transport,
            policy,
            ..
        } = target;
        let mut guard = before_proposal(None, stop, None, target.channel.session.lock()).await?;
        if guard
            .as_ref()
            .is_some_and(|session| !session.reusable_with(options))
        {
            if target
                .channel
                .active
                .load(std::sync::atomic::Ordering::Acquire)
                > 1
            {
                return Err(pre(ExecutionError::RecoveryRequired));
            }
            if let Some(mut session) = guard.take() {
                session
                    .shutdown()
                    .await
                    .map_err(|error| pre(error.into()))?;
            }
        }
        if self.down.load(std::sync::atomic::Ordering::Acquire) && guard.is_some() {
            return Err(pre(ExecutionError::RecoveryRequired));
        }
        if guard.is_none() {
            let opened = before_proposal(None, stop, None, async {
                let mut session =
                    crate::grant_client::GrantSession::open(options.clone(), transport.clone())
                        .await?;
                session.recover().await?;
                Ok::<_, crate::grant_client::GrantClientError>(session)
            })
            .await?
            .map_err(|error| pre(error.into()))?;
            *guard = Some(opened);
            self.health(false);
        }
        let session = guard
            .as_mut()
            .ok_or_else(|| pre(ExecutionError::Identity))?;
        let proposed = requester.job.proposal();
        let proposal = before_proposal(None, stop, Some(&proposed), async {
            session.refresh().await?;
            let current = session
                .offer()
                .offer()
                .grant
                .policies
                .iter()
                .find(|current| current.resource == policy.resource)
                .ok_or(ExecutionError::Identity)?;
            let input = request.admitted(
                &current.invocation_policy,
                current.https.as_ref(),
                session.assurance(),
                false,
            )?;
            let prepared =
                prepare_grant_input(&input, current, session.offer(), session.execution_signer())?;
            Ok::<_, ExecutionError>(
                session
                    .propose_resource(policy.resource, prepared, &input.content(), Some(&proposed))
                    .await?,
            )
        })
        .await?;
        let delivery = proposal.map_err(|error| {
            if proposed.load(std::sync::atomic::Ordering::Acquire) {
                committed(error)
            } else {
                pre(error)
            }
        })?;
        drop(guard);
        // A remote acceptance cannot be cancelled by the HTTP consumer.
        let collected = delivery
            .collect(Some(requester.progress()), Some(requester.accepted()))
            .await
            .map_err(|error| committed(error.into()))?;
        let result = target
            .channel
            .session
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| committed(ExecutionError::Identity))?
            .complete(collected)
            .await
            .map_err(|error| committed(error.into()))?;
        let completed = crate::execution::grant_completed(result)?;
        requester.delivery()(&completed)
            .map_err(|error| committed(ExecutionError::Delivery(error)))?;
        Ok(completed)
    }
}
fn finish_job(
    job: &hellas_gateway::jobs::Job,
    result: Result<(), WorkGatewayError>,
    closed: Result<(), WorkShutdownError>,
) -> Result<(), WorkGatewayError> {
    if let Err(error) = closed {
        tracing::warn!(%error, "session close retains recovery obligations");
    }
    if !matches!(&result, Err(WorkGatewayError::PreProposal(_))) {
        job.finish(if result.is_ok() {
            hellas_gateway::jobs::Outcome::Completed
        } else {
            hellas_gateway::jobs::Outcome::Failed
        });
    }
    result
}

fn backend_failed(error: &ExecutionError) -> bool {
    use crate::grant_client::GrantClientError as G;
    use crate::paid_client::PaidClientError as P;
    use hellas_channel::work::{DeliverError, ProposeError};
    use hellas_channel::work_store::WorkStoreError;
    match error {
        ExecutionError::Paid(error)
        | ExecutionError::Transaction(crate::transact::TransactError::Client(error)) => matches!(
            error,
            P::Connect { .. }
                | P::OfferUnavailable { .. }
                | P::OfferRefused(_)
                | P::SetupEnded(_)
                | P::Endpoint(_)
                | P::ProviderIdentityPoisoned
                | P::Store(_)
                | P::Client(_)
                | P::Payment(_)
                | P::Timeout { .. }
                | P::Propose(
                    ProposeError::Transport(_)
                        | ProposeError::Endpoint(_)
                        | ProposeError::Conflict
                        | ProposeError::Store(WorkStoreError::Journal(_))
                )
                | P::Deliver(DeliverError::Transport(_))
        ),
        ExecutionError::RecoveryRequired | ExecutionError::Io(_) => true,
        ExecutionError::Grant(error) => matches!(
            error,
            G::RecoveryRequired | G::Timeout | G::Wire(_) | G::Client(_) | G::Refused { .. }
        ),
        _ => false,
    }
}
impl WorkExecutionBackend for ExecutorGateway {
    fn backends(&self) -> Vec<hellas_gateway::BackendInfo> {
        self.backends
            .iter()
            .map(|(id, backend)| hellas_gateway::BackendInfo {
                id: id.clone(),
                instance: backend.instance,
                evaluator: backend.evaluator.clone(),
                max_in_flight: backend.capacity,
                in_flight: backend.capacity - backend.slots.available_permits(),
                down: backend.down.load(std::sync::atomic::Ordering::Acquire),
            })
            .collect()
    }
    fn fetch(
        &self,
        backend: &str,
        request_job: Arc<hellas_gateway::jobs::Job>,
        request: WorkFetchRequest,
    ) -> Result<WorkOutputStream<OutputEvent>, WorkGatewayError> {
        self.request(backend, request_job, WorkRequest::Fetch(request))
    }
    fn run(
        &self,
        backend: &str,
        request_job: Arc<hellas_gateway::jobs::Job>,
        job: hellas_client::model::ComputeJob,
    ) -> Result<WorkOutputStream<ComputeEvent>, WorkGatewayError> {
        let evaluator = self
            .backends
            .get(backend)
            .and_then(|b| b.evaluator.clone())
            .ok_or(WorkGatewayError::Unsupported)?;
        self.request(
            backend,
            request_job,
            WorkRequest::Job(JobInput::Compute {
                evaluator,
                environment: job.environment,
                plan: job.plan,
                inputs: job.inputs,
                content: Arc::new(job.content),
            }),
        )
    }
    fn drain(&self) -> BoxFuture<'_, Result<(), WorkShutdownError>> {
        for backend in self.backends.values() {
            backend.slots.close();
            if let BackendState::Grant(grant) = &backend.state {
                grant
                    .channel
                    .retired
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
        self.jobs.close();
        Box::pin(async move {
            let mut drained = self.jobs.drain().await;
            for backend in self.backends.values() {
                if let Err(error) = backend.close_sessions().await {
                    drained = drained.and(Err(error));
                }
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
        #[cfg(feature = "compute")]
        ExecutionError::LocalAdmission(_) => WorkGatewayBusy.into(),
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
    async fn close_failure_preserves_a_delivered_result_and_finishes_the_job() {
        let jobs = Arc::new(hellas_gateway::jobs::Jobs::default());
        let job = crate::test_support::request_job(&jobs);
        job.accepted();
        let (_, mut events) = jobs.watch(|_| ());
        assert!(finish_job(&job, Ok(()), Err(WorkShutdownError::Poisoned)).is_ok());
        assert!(jobs.watch(|jobs| jobs).0.is_empty());
        assert!(
            matches!(events.try_recv().unwrap(), hellas_gateway::jobs::Event::Job { job } if job.outcome == Some(hellas_gateway::jobs::Outcome::Completed))
        );
        jobs.drain().await.unwrap();
    }

    #[tokio::test]
    async fn completed_paid_users_close_even_before_their_permits_drop() {
        let (_fixture, backend, endpoint, _validator) =
            crate::paid_client::tests::concurrency::cached_paid_backend().await;
        let gateway = ExecutorGateway::new(
            [(
                "paid".into(),
                BackendEntry {
                    backend,
                    evaluator: None,
                    max_in_flight: std::num::NonZeroUsize::new(2).unwrap(),
                },
            )]
            .into(),
            Arc::new(hellas_auth::ProducerSigningKey::from_secret_bytes([1; 32]).unwrap()),
        );
        let backend = gateway.backend("paid").unwrap();
        let first = backend.slots.clone().acquire_owned().await.unwrap();
        let second = backend.slots.clone().acquire_owned().await.unwrap();
        // Completed users may still own their scheduling permits until their task returns.
        let next = ExecutorGateway::prepare(
            Default::default(),
            gateway.signer.clone(),
            gateway.jobs.clone(),
            Some(&gateway),
            &Default::default(),
        );
        gateway.retire(&next).await.unwrap();
        let BackendState::Paid(paid) = &backend.state else {
            unreachable!()
        };
        assert!(
            paid.session.lock().await.is_none(),
            "retired session must close once no user remains"
        );
        drop((first, second));
        gateway.drain().await.unwrap();
        endpoint.close().await;
    }

    #[tokio::test]
    async fn buffered_reconnect_burst_is_delivered_and_releases_byte_budget() {
        let (requester, mut response) = TestRequester::new(crate::test_support::job());
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
        let (requester, mut response) = TestRequester::new(crate::test_support::job());
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
        let (requester, mut response) = TestRequester::new(crate::test_support::job());
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
