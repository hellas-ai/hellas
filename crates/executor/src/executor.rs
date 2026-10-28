use crate::{
    ExecutorError, ExecutorMetrics, FetchCall, FetchRoute, FetchRouteRegistry, ProjectedFetch,
    catena,
};
use futures_util::StreamExt;
use hellas_auth::ProducerSigningKey;
use hellas_channel::{
    content::InvocationContent,
    work::{
        Admitted, BackendFault, PaidProgress, WorkBackend,
        admission::{
            AdmissionError, CancelOnFailure, Cancellation, CapacityDomain, RunningWork, WorkPermit,
        },
    },
};
use hellas_rpc::{
    Assurance, OutputEventEnvelope,
    protocol::invocation::{
        Admission, InvocationPolicy, Limits, PreparedInvocation, fetch,
        output::{FailureReason, OutputStream},
    },
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub const DEFAULT_GPU_SESSION_PROGRAMS: usize = 8;
pub const DEFAULT_GPU_SESSION_ASSET_BYTES: u64 = 128 * 1024 * 1024 * 1024;
#[derive(Clone, Copy, Debug)]
pub struct GpuConfig {
    pub backend: crate::GpuDialect,
    pub session_programs: usize,
    pub session_asset_bytes: u64,
}
impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            backend: crate::GpuDialect::Hip,
            session_programs: DEFAULT_GPU_SESSION_PROGRAMS,
            session_asset_bytes: DEFAULT_GPU_SESSION_ASSET_BYTES,
        }
    }
}
#[derive(Clone)]
pub struct ExecutorSpawnConfig {
    pub queue_capacity: usize,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub assurance: Assurance,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub content_store: hellas_store::ContentStore,
    pub gpu_config: GpuConfig,
}
impl ExecutorSpawnConfig {
    pub fn new(
        producer_key: Arc<ProducerSigningKey>,
        assurance: Assurance,
        fetch_routes: FetchRouteRegistry,
    ) -> Self {
        Self {
            queue_capacity: hellas_rpc::DEFAULT_EXECUTION_QUEUE_CAPACITY,
            metrics: Arc::new(ExecutorMetrics::default()),
            producer_key,
            assurance,
            fetch_routes,
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            content_store: hellas_store::ContentStore::new(),
            gpu_config: GpuConfig::default(),
        }
    }
    pub fn supports_compute(&self) -> bool {
        true
    }
}
pub struct Executor {
    config: ExecutorSpawnConfig,
    fetch_capacity: Arc<Semaphore>,
    gpu_capacity: Arc<Semaphore>,
    fetch_active: Arc<Semaphore>,
    gpu_active: Arc<Semaphore>,
    pool: catena::pool::Pool,
    assets: catena::assets::Assets,
}
#[derive(Clone)]
pub struct ExecutorHandle {
    inner: Arc<Executor>,
}
pub(crate) struct FetchProviderFailure {
    pub position: u64,
    pub error: crate::FetchProviderError,
}

impl Executor {
    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        if config.fetch_max_in_flight == 0 {
            return Err(ExecutorError::ResourceExhausted(
                "Fetch concurrency must be positive".into(),
            ));
        }
        let capacity = |active: usize, queued: usize| -> Result<Arc<Semaphore>, ExecutorError> {
            let total = active
                .checked_add(queued)
                .filter(|n| *n <= Semaphore::MAX_PERMITS)
                .ok_or_else(|| {
                    ExecutorError::ResourceExhausted("executor capacity overflow".into())
                })?;
            Ok(Arc::new(Semaphore::new(total)))
        };
        let pool = catena::pool::Pool::new(1, config.gpu_config.session_programs)
            .map_err(|e| ExecutorError::Execution(e.to_string()))?;
        Ok(ExecutorHandle {
            inner: Arc::new(Self {
                fetch_capacity: capacity(config.fetch_max_in_flight, config.fetch_queue_capacity)?,
                gpu_capacity: capacity(1, config.queue_capacity)?,
                fetch_active: Arc::new(Semaphore::new(config.fetch_max_in_flight)),
                gpu_active: Arc::new(Semaphore::new(1)),
                pool,
                assets: catena::assets::Assets::new(
                    config.gpu_config.session_asset_bytes,
                    config.gpu_config.backend,
                ),
                config,
            }),
        })
    }
}
impl ExecutorHandle {
    fn capacity(&self, domain: CapacityDomain) -> Result<Arc<Semaphore>, BackendFault> {
        match domain {
            CapacityDomain::Fetch => Ok(self.inner.fetch_capacity.clone()),
            CapacityDomain::Gpu if self.inner.pool.available() => {
                Ok(self.inner.gpu_capacity.clone())
            }
            _ => Err(AdmissionError::Unsupported(domain).into()),
        }
    }
    async fn invoke(
        &self,
        input: Admitted<PreparedInvocation>,
        progress: Option<PaidProgress>,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let name = match input.capacity_domain() {
            CapacityDomain::Gpu => "compute",
            CapacityDomain::Fetch => "fetch",
        };
        self.inner.config.metrics.record_execution_started(name);
        let result = self.run(input, progress).await;
        self.inner
            .config
            .metrics
            .record_execution_finished(name, result.is_ok());
        result
    }
    async fn run(
        &self,
        input: Admitted<PreparedInvocation>,
        progress: Option<PaidProgress>,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let domain = input.capacity_domain();
        let capacity = self.capacity(domain)?;
        let input = input
            .reserve(async {
                capacity
                    .acquire_owned()
                    .await
                    .map(|permit| WorkPermit::new(domain, permit))
                    .map_err(|_| AdmissionError::Closed.into())
            })
            .await?;
        let (prepared, limits, content, admission) = input.into_parts_and_admission();
        if prepared.request.assurance != self.inner.config.assurance
            || prepared.request.runner_public_key != self.inner.config.producer_key.public_key()
        {
            return Err(BackendFault::caused_by(ExecutorError::PolicyDenied(
                "invocation names a different provider or assurance".into(),
            )));
        }
        let active = match domain {
            CapacityDomain::Gpu => self.inner.gpu_active.clone(),
            CapacityDomain::Fetch => self.inner.fetch_active.clone(),
        };
        let expires = admission.deadline();
        let deadline = async {
            match expires {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => std::future::pending().await,
            }
        };
        let active = tokio::select! {
            permit = active.acquire_owned() => permit.map_err(|_| AdmissionError::Closed)?,
            () = admission.cancelled() => return Err(AdmissionError::Cancelled.into()),
            () = deadline => return Err(AdmissionError::Deadline.into()),
        };
        let running = Arc::new(admission.dispatch().await?);
        running.check_active()?;
        match domain {
            CapacityDomain::Gpu => {
                let cancel = catena::Cancellation::default();
                let signal = cancel.clone();
                let _cancel_on_drop =
                    CancelOnFailure(vec![Cancellation::with_cleanup(move || signal.cancel())]);
                let executor = self.inner.clone();
                let physical = running.clone();
                let control = cancel.clone();
                let mut task = tokio::task::spawn_blocking(move || {
                    let _active = active;
                    let _physical = physical;
                    let result = (|| {
                        let loaded = (|| {
                            let program = catena::program::BoundProgram::compile_cancellable(
                                &content,
                                &prepared,
                                &limits,
                                &std::env::current_exe()?,
                                &control,
                                executor.config.gpu_config.backend,
                            )?;
                            let worker = executor.pool.lease_cancellable(
                                program.module(),
                                Duration::from_millis(limits.execution_timeout_ms),
                                control.clone(),
                            )?;
                            Ok::<_, Box<dyn std::error::Error>>((program, worker))
                        })();
                        let (program, mut worker) = match loaded {
                            Ok(loaded) => loaded,
                            Err(error) => {
                                // Accepted work owes B a signed terminal, an
                                // invalid plan included: B retires it unpaid.
                                tracing::warn!(%error, "compute preparation failed");
                                let reason = if control.is_cancelled() {
                                    FailureReason::Cancelled
                                } else {
                                    FailureReason::Compilation
                                };
                                let (_, events) = OutputStream::new(
                                    &prepared.request,
                                    &executor.config.producer_key,
                                    hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES,
                                )?
                                .fail(reason)?;
                                if let Some(progress) = &progress {
                                    progress(events.last().unwrap().clone())?;
                                }
                                return Ok(events);
                            }
                        };
                        catena::driver::execute_signed(
                            &mut worker,
                            &program,
                            &prepared,
                            &limits,
                            &executor.assets,
                            &content,
                            &executor.config.producer_key,
                            |event| {
                                if let Some(progress) = &progress {
                                    progress(event)?;
                                }
                                Ok(())
                            },
                        )
                        .map(|(_, events)| events)
                    })();
                    result.map_err(|error: Box<dyn std::error::Error>| {
                        ExecutorError::Execution(error.to_string())
                    })
                });
                let deadline = async {
                    match running.deadline() {
                        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                        None => std::future::pending().await,
                    }
                };
                let result = tokio::select! {
                    result = &mut task => result,
                    () = running.cancelled() => { cancel.cancel(); task.await },
                    () = deadline => { cancel.cancel(); task.await },
                };
                result
                    .map_err(BackendFault::caused_by)?
                    .map_err(|e| BackendFault::caused_by(ExecutorError::Execution(e.to_string())))
            }
            CapacityDomain::Fetch => {
                let _active = active;
                self.run_fetch(prepared, limits, content, running, progress)
                    .await
            }
        }
    }
    async fn run_fetch(
        &self,
        prepared: PreparedInvocation,
        limits: Limits,
        _content: InvocationContent,
        running: Arc<RunningWork>,
        progress: Option<PaidProgress>,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let invalid = |e: &dyn std::fmt::Display| {
            BackendFault::caused_by(ExecutorError::InvalidInput(e.to_string()))
        };
        let policy = InvocationPolicy::from_canonical_bytes(prepared.application_policy.as_bytes())
            .map_err(|e| invalid(&e))?;
        let artifact = prepared
            .input
            .artifacts
            .first()
            .ok_or_else(|| invalid(&"missing Fetch request"))?;
        let events: Vec<hellas_rpc::InputEventEnvelope> =
            hellas_rpc::value::decode_canonical_dag_cbor(artifact.bytes.as_bytes())
                .map_err(|e| invalid(&e))?;
        let request = hellas_rpc::fetch::verify_input_events(&events).map_err(|e| invalid(&e))?;
        let caller = request.caller_key;
        let manifest = prepared.manifest().map_err(|e| invalid(&e))?;
        let bounds = policy.admit(&prepared, &caller).map_err(|e| invalid(&e))?;
        let admissions = policy
            .admissions
            .iter()
            .filter_map(|a| match a {
                Admission::Fetch { admission }
                    if fetch::validate_input(
                        &prepared,
                        admission,
                        limits.max_output_bytes,
                        &caller,
                    )
                    .is_ok() =>
                {
                    Some((a, admission))
                }
                _ => None,
            })
            .map(|(a, admission)| {
                let bounds = InvocationPolicy {
                    admissions: vec![a.clone()],
                    limits,
                }
                .classify_manifest(&manifest)?;
                Ok((admission, bounds))
            })
            .collect::<Result<Vec<_>, hellas_rpc::value::CanonicalDecodeError>>()
            .map_err(|e| invalid(&e))?;
        let entry = self
            .inner
            .config
            .fetch_routes
            .entry(&FetchRoute::new(&request.service, &request.method))
            .ok_or_else(|| invalid(&"Fetch route unavailable"))?;
        if entry.execution_environment() != prepared.request.execution_environment {
            return Err(invalid(&"Fetch route manifest mismatch"));
        }
        let call = FetchCall::new(
            request.service,
            request.method,
            request.body,
            request.input_commitment,
        );
        let session = entry
            .adaptor_factory
            .create(&call)
            .map_err(|e| invalid(&e))?;
        entry
            .capabilities
            .validate(&session.request_view)
            .map_err(|e| invalid(&e))?;
        let projected = crate::fetch_execution::project_fetch(
            entry.provider.clone(),
            session.provider_request,
            session.projector,
        );
        tokio::pin!(projected);
        let key = &self.inner.config.producer_key;
        let budget = bounds.max_transcript_payload_bytes as usize;
        let mut stream =
            OutputStream::new(&prepared.request, key, budget).map_err(|e| invalid(&e))?;
        // Size a real largest failure envelope; eight bytes cover sequence growth.
        // Fixed-width digests, keys and signatures keep their encoded widths.
        let (_, failure) = OutputStream::new(&prepared.request, key, budget)
            .map_err(|e| invalid(&e))?
            .fail(FailureReason::ExecutionTimeout)
            .map_err(|e| invalid(&e))?;
        prepared
            .verify_output(&policy, &caller, &key.public_key(), &failure)
            .map_err(|e| invalid(&e))?;
        let failure_frame = hellas_rpc::canonical_dag_cbor(&failure[0])
            .map_err(|e| invalid(&e))?
            .len() as u64
            + 8;
        let retained = |event: &OutputEventEnvelope| {
            event
                .retained_heap_bytes()
                .and_then(|n| n.checked_add(4 * std::mem::size_of::<OutputEventEnvelope>()))
                .map(|n| n as u64)
                .unwrap_or(u64::MAX)
        };
        let failure_heap = retained(&failure[0]);
        let fits = |logical: u64, envelopes: u64, frame: u64, encoded: u64, heap: u64| {
            admissions.iter().any(|(admission, bounds)| {
                logical <= u64::from(admission.limits.max_output_events)
                    && envelopes <= bounds.max_output_events
                    && frame.max(failure_frame) <= u64::from(bounds.max_encoded_result_frame)
                    && encoded.saturating_add(failure_frame) <= bounds.max_spool_bytes
                    && heap.saturating_add(failure_heap) <= bounds.max_spool_bytes
            })
        };
        if !fits(1, 1, 0, 9, 0) {
            return Err(invalid(&"Fetch bounds cannot hold a signed failure"));
        }
        let mut published = Vec::new();
        // Nine bytes is the largest CBOR array header, independent of event count.
        let mut encoded = 9u64;
        let mut heap = 0u64;
        let mut largest_frame = 0u64;
        let mut payload_bytes = 0u64;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.execution_timeout_ms))
            .ok_or_else(|| invalid(&"execution deadline overflow"))?;
        let deadline = running
            .deadline()
            .map_or(deadline, |grant| grant.min(deadline));
        let mut payloads = Vec::new();
        let mut offset = 0;
        let terminal = 'response: loop {
            let next = tokio::select! {
                event = projected.next() => event,
                () = running.cancelled() => break Err(FailureReason::Cancelled),
                () = tokio::time::sleep_until(deadline.into()) => break Err(FailureReason::ExecutionTimeout),
            };
            match next {
                Some(Ok(ProjectedFetch::Event(payload))) => {
                    let frame = fetch::frame_event(&payload).map_err(|e| invalid(&e))?;
                    if payload_bytes.saturating_add(payload.len() as u64) > limits.max_output_bytes
                    {
                        break Err(FailureReason::OutputLimit);
                    }
                    payload_bytes += payload.len() as u64;
                    for chunk in frame.chunks(64 * 1024) {
                        let event = match stream.push(
                            fetch::RESPONSE_EVENTS,
                            fetch::RESPONSE_EVENTS_FORMAT,
                            offset,
                            chunk,
                        ) {
                            Ok(event) => event,
                            Err(_) => break 'response Err(FailureReason::OutputLimit),
                        };
                        let frame_bytes = hellas_rpc::canonical_dag_cbor(&event)
                            .map_err(|e| invalid(&e))?
                            .len() as u64;
                        let event_heap = retained(&event);
                        if !fits(
                            payloads.len() as u64 + 2,
                            published.len() as u64 + 2,
                            largest_frame.max(frame_bytes),
                            encoded.saturating_add(frame_bytes),
                            heap.saturating_add(event_heap),
                        ) {
                            // Discard this signed but unpublished candidate before failing.
                            stream = OutputStream::resume(
                                &prepared.request,
                                key,
                                published.clone(),
                                budget,
                            )
                            .map_err(|e| invalid(&e))?;
                            break 'response Err(FailureReason::OutputLimit);
                        }
                        largest_frame = largest_frame.max(frame_bytes);
                        encoded += frame_bytes;
                        heap += event_heap;
                        if let Some(progress) = &progress {
                            progress(event.clone())?;
                        }
                        published.push(event);
                        offset += chunk.len() as u64;
                    }
                    payloads.push(payload);
                }
                Some(Ok(ProjectedFetch::Terminal(terminal))) => break Ok(terminal),
                Some(Err(error)) => {
                    tracing::warn!(position = error.position, error = %error.error, "Fetch provider failed");
                    break Err(FailureReason::Execution);
                }
                None => break Err(FailureReason::Execution),
            }
        };
        let output = match terminal {
            Ok(terminal) if Instant::now() < deadline => {
                let output = fetch::output(&payloads, &terminal).map_err(|e| invalid(&e))?;
                stream.finish_or_fail(output, 64 * 1024)
            }
            Ok(_) => stream.fail(FailureReason::ExecutionTimeout),
            Err(reason) => stream.fail(reason),
        };
        let (_, events) = output.map_err(|e| invalid(&e))?;
        if prepared
            .verify_output(&policy, &caller, &key.public_key(), &events)
            .is_err()
        {
            return OutputStream::resume(&prepared.request, key, published, budget)
                .map_err(|e| invalid(&e))?
                .fail(FailureReason::OutputLimit)
                .map(|(_, events)| events)
                .map_err(|e| invalid(&e));
        }
        Ok(events)
    }
}
impl WorkBackend for ExecutorHandle {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        let permit = self
            .capacity(domain)?
            .try_acquire_owned()
            .map_err(|_| AdmissionError::Capacity)?;
        Ok(WorkPermit::new(domain, permit))
    }
    async fn execute(
        &self,
        input: Admitted<PreparedInvocation>,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.invoke(input, None).await
    }
    async fn execute_stream(
        &self,
        input: Admitted<PreparedInvocation>,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.invoke(input, Some(progress)).await
    }
}
