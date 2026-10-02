use crate::artifacts::{ResolvedEvaluateExecution, resolve_prepared_paid_input};
use crate::environment::CausalLmEnvironmentSource;
use crate::executor::{ExecuteOutcome, ExecutorCompletion, ProviderContext};
use crate::state::{Invocation, StopReason, Termination, new_execution_id, validate_invocation};
use crate::worker::{
    EnqueueError, ExecuteJob, ExecuteWorker, GpuConfig, WorkerCompletion, WorkerCompletionResult,
};
use crate::{ExecutorError, ExecutorMetrics};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::{Assurance, ContentId, EvaluateRequest, OutputEventEnvelope};
use hellas_store::ContentStore;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use tokio::sync::mpsc;
use tracing::warn;
const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
const BOUND_ENVIRONMENT_CACHE_CAPACITY: usize = 256;
pub struct EvaluateJob {
    pub evaluate_request: EvaluateRequest,
    pub source: CausalLmEnvironmentSource,
    pub invocation: Invocation,
}
enum StartExecutionError {
    Busy(Box<ExecuteJob>),
    Closed(Box<ExecuteJob>),
    Rejected {
        job: Box<ExecuteJob>,
        error: ExecutorError,
    },
}

enum WorkerState {
    Idle,
    Busy { execution_id: String },
    Stopped,
}

enum PendingExecution {
    Prepared {
        input: hellas_work::work::PreparedEvaluateInput<hellas_work::work::admission::AdmittedWork>,
        complete: tokio::sync::oneshot::Sender<()>,
        sender:
            mpsc::Sender<Result<hellas_rpc::execution_event::WorkEvent, hellas_wire::WireStatus>>,
    },
    #[cfg(test)]
    Resolved(ExecuteJob),
}
impl PendingExecution {
    fn is_owed(&self) -> bool {
        match self {
            Self::Prepared { input, .. } => input.admission().is_owed(),
            #[cfg(test)]
            Self::Resolved(_) => true,
        }
    }
}
pub struct EvaluateEngine {
    content_store: ContentStore,
    environments: HashMap<ContentId, CausalLmEnvironmentSource>,
    environment_order: VecDeque<ContentId>,
    worker: ExecuteWorker,
    worker_state: WorkerState,
    gpu_config: GpuConfig,
    pending_owed_executions: VecDeque<PendingExecution>,
    queue_capacity: usize,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
}
pub(crate) struct EvaluateEngineConfig {
    pub content_store: ContentStore,
    pub gpu_config: GpuConfig,
    pub queue_capacity: usize,
    pub metrics: Arc<ExecutorMetrics>,
    pub provider: ProviderContext,
    pub completion_tx: mpsc::Sender<ExecutorCompletion>,
}
impl EvaluateEngine {
    pub(crate) fn new(config: EvaluateEngineConfig) -> Result<Self, ExecutorError> {
        let worker = ExecuteWorker::spawn(config.completion_tx.clone(), config.gpu_config)
            .map_err(|error| {
                ExecutorError::ResourceExhausted(format!(
                    "failed to spawn GPU worker thread: {error}"
                ))
            })?;
        Ok(Self::with_worker(config, worker))
    }
    fn with_worker(config: EvaluateEngineConfig, worker: ExecuteWorker) -> Self {
        Self {
            content_store: config.content_store,
            environments: HashMap::new(),
            environment_order: VecDeque::new(),
            worker,
            worker_state: WorkerState::Idle,
            gpu_config: config.gpu_config,
            pending_owed_executions: VecDeque::new(),
            queue_capacity: config.queue_capacity,
            metrics: config.metrics,
            provider: config.provider,
        }
    }
    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        match &self.worker_state {
            WorkerState::Busy { .. } => return Err(StartExecutionError::Busy(Box::new(job))),
            WorkerState::Stopped => return Err(StartExecutionError::Closed(Box::new(job))),
            WorkerState::Idle => {}
        }
        let execution_id = job.execution_id.clone();
        match self.worker.try_enqueue(job) {
            Ok(()) => {
                self.worker_state = WorkerState::Busy { execution_id };
                Ok(())
            }
            Err(EnqueueError::Busy(job)) => Err(StartExecutionError::Rejected {
                job,
                error: ExecutorError::Execution(
                    "GPU worker handoff was full while the actor marked it idle".to_string(),
                ),
            }),
            Err(EnqueueError::Stopped(job)) => {
                self.worker_state = WorkerState::Stopped;
                Err(StartExecutionError::Closed(job))
            }
        }
    }
    fn admit_resolved_job(
        &self,
        resolved: ResolvedEvaluateExecution,
        environment_source: CausalLmEnvironmentSource,
    ) -> Result<EvaluateJob, ExecutorError> {
        let evaluate_request = &resolved.evaluate_request;
        ensure_supported_assurance(evaluate_request.assurance, self.provider.assurance)?;
        if environment_source.manifest_id() != evaluate_request.execution_environment {
            return Err(ExecutorError::InvalidInput(format!(
                "bound environment is {}, but request pins {}",
                environment_source.manifest_id(),
                evaluate_request.execution_environment
            )));
        }
        validate_invocation(
            &resolved.invocation,
            environment_source.environment().vocabulary_size(),
            environment_source.environment().maximum_capacity(),
        )?;
        self.validate_provider_resources(&environment_source, &resolved.invocation)?;
        Ok(EvaluateJob {
            evaluate_request: resolved.evaluate_request,
            source: environment_source,
            invocation: resolved.invocation,
        })
    }
    fn validate_provider_resources(
        &self,
        source: &CausalLmEnvironmentSource,
        invocation: &Invocation,
    ) -> Result<(), ExecutorError> {
        self.gpu_config
            .validate_environment_invocation_resources(invocation, source.environment())
            .map_err(|error| {
                ExecutorError::InvalidInput(format!(
                    "environment {} exceeds the provider GPU resource envelope: {error}",
                    source.manifest_id()
                ))
            })
    }
    fn get_or_bind_environment(
        &mut self,
        manifest_bytes: &[u8],
    ) -> Result<CausalLmEnvironmentSource, ExecutorError> {
        let manifest = CausalLmEnvironmentSource::parse_manifest(manifest_bytes)
            .map_err(|error| ExecutorError::InvalidInput(error.to_string()))?;
        if let Some(source) = self.environments.get(&manifest.id()) {
            return Ok(source.clone());
        }
        let source = CausalLmEnvironmentSource::bind_manifest(&self.content_store, manifest)
            .map_err(|error| ExecutorError::InvalidInput(error.to_string()))?;
        while self.environments.len() >= BOUND_ENVIRONMENT_CACHE_CAPACITY {
            let Some(oldest) = self.environment_order.pop_front() else {
                break;
            };
            self.environments.remove(&oldest);
        }
        let manifest_id = source.manifest_id();
        self.environment_order.push_back(manifest_id);
        self.environments.insert(manifest_id, source.clone());
        Ok(source)
    }
    async fn completed_evaluate_termination(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        output: (StopReason, Vec<u32>),
        output_events: Vec<OutputEventEnvelope>,
    ) -> Result<(Termination, u64), ExecutorError> {
        let (stop_reason, output_tokens) = output;
        let text_artifact = completed_text(
            TextExecutionId::from_digest(evaluate_request.text_execution),
            &invocation.input_ids,
            &output_tokens,
        )
        .artifact
        .output_id()
        .digest();
        let input_units = invocation.input_ids.len() as u64;
        let output_units = output_tokens.len() as u64;
        let usage = EvaluateUsage {
            input_units,
            output_units,
        };
        let billable_units = usage
            .billable_units()
            .map_err(|err| ExecutorError::Execution(format!("evaluate billing failed: {err}")))?;
        let (stop_reason, matched_stop_token_id) = evaluate_stop_reason(stop_reason);
        let terminal = EvaluateTerminal {
            final_position: output_units,
            stop_reason,
            matched_stop_token_id,
            text_artifact,
            usage,
            billable_units,
        };
        let mut output_events = EvaluateOutputTranscriptBuilder::resume_verified(
            input_commitment(evaluate_request),
            evaluate_request.assurance,
            &self.provider.producer_key,
            output_events,
        )
        .map_err(|err| ExecutorError::Execution(format!("evaluate transcript failed: {err}")))?
        .finish(terminal)
        .map_err(|err| ExecutorError::Execution(format!("evaluate transcript failed: {err}")))?;
        let terminal_output_event = output_events.pop().ok_or_else(|| {
            ExecutorError::Execution("evaluate transcript finished without a terminal event".into())
        })?;
        Ok((
            Termination::Completed {
                terminal_output_event: Box::new(terminal_output_event),
            },
            billable_units,
        ))
    }
    pub(crate) async fn on_completion(&mut self, completion: WorkerCompletion) {
        let WorkerCompletion {
            execution_id,
            evaluate_request,
            invocation,
            sender,
            result,
            running,
            complete,
        } = completion;

        match &self.worker_state {
            WorkerState::Busy {
                execution_id: active,
            } if active == &execution_id => {
                self.worker_state = WorkerState::Idle;
            }
            WorkerState::Busy {
                execution_id: active,
            } => {
                warn!(
                    %execution_id,
                    active_execution_id = %active,
                    "ignoring mismatched GPU completion for worker readiness"
                );
            }
            WorkerState::Idle => {
                warn!(%execution_id, "received duplicate GPU completion while worker was idle");
            }
            WorkerState::Stopped => {
                warn!(%execution_id, "received GPU completion after worker was marked stopped");
            }
        }

        let generated = result.position();
        let (termination, billable_units) = match result {
            WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
                output_events,
            } => match self
                .completed_evaluate_termination(
                    &evaluate_request,
                    &invocation,
                    (stop_reason, output_tokens),
                    output_events,
                )
                .await
            {
                Ok((termination, billable_units)) => (termination, Some(billable_units)),
                Err(err) => {
                    let msg = format!("{err:#}");
                    warn!(
                        %execution_id,
                        "execute worker failed while recording/signing output transcript"
                    );
                    (
                        Termination::Failed {
                            position: generated,
                            error: msg,
                        },
                        None,
                    )
                }
            },
            WorkerCompletionResult::Failed { position, error } => {
                (Termination::Failed { position, error }, None)
            }
        };

        if billable_units.is_some() {
            self.metrics
                .record_execution_completed("evaluate", "causal-lm", generated);
        } else {
            self.metrics
                .record_execution_failed("evaluate", "causal-lm", generated);
        }

        // Completion runs on the actor itself. A stalled consumer must never
        // wedge environment admission or every later execution behind an
        // awaited send into its already-full per-run channel.
        let _ = sender.try_send(Ok(termination.into_event()));
        drop(running);
        let _ = complete.send(());
    }
    pub(crate) async fn start_prepared_input(
        &mut self,
        input: hellas_work::work::PreparedEvaluateInput<hellas_work::work::admission::AdmittedWork>,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let (sender, events) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let (complete, completion) = tokio::sync::oneshot::channel();
        self.pending_owed_executions
            .push_back(PendingExecution::Prepared {
                input,
                sender,
                complete,
            });
        self.dispatch_next_execution();
        Ok(ExecuteOutcome { events, completion })
    }

    pub(crate) fn has_queue_capacity(&self) -> bool {
        !self.has_work() || self.pending_owed_executions.len() < self.queue_capacity
    }
    pub(crate) fn has_work(&self) -> bool {
        matches!(self.worker_state, WorkerState::Busy { .. })
            || !self.pending_owed_executions.is_empty()
    }
    pub(crate) fn dispatch_next_execution(&mut self) {
        if matches!(self.worker_state, WorkerState::Busy { .. }) {
            return;
        }
        loop {
            let next = self
                .pending_owed_executions
                .iter()
                .position(PendingExecution::is_owed)
                .unwrap_or(0);
            let Some(pending) = self.pending_owed_executions.remove(next) else {
                return;
            };
            let job = match pending {
                #[cfg(test)]
                PendingExecution::Resolved(job) => job,
                PendingExecution::Prepared {
                    input,
                    sender,
                    complete,
                } => {
                    if matches!(self.worker_state, WorkerState::Stopped) {
                        let _ = sender.try_send(Err(ExecutorError::ChannelClosed.into()));
                        continue;
                    }
                    match self.prepare_for_dispatch(input, sender.clone(), complete) {
                        Ok(job) => job,
                        Err(error) => {
                            let _ = sender.try_send(Err(error.into()));
                            continue;
                        }
                    }
                }
            };
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job) | StartExecutionError::Closed(job)) => {
                    let _ = job
                        .sender
                        .try_send(Err(ExecutorError::ChannelClosed.into()));
                }
                Err(StartExecutionError::Rejected { job, error }) => {
                    let _ = job.sender.try_send(Err(error.into()));
                }
            }
        }
    }
    fn prepare_for_dispatch(
        &mut self,
        input: hellas_work::work::PreparedEvaluateInput<hellas_work::work::admission::AdmittedWork>,
        sender: mpsc::Sender<
            Result<hellas_rpc::execution_event::WorkEvent, hellas_wire::WireStatus>,
        >,
        complete: tokio::sync::oneshot::Sender<()>,
    ) -> Result<ExecuteJob, ExecutorError> {
        let (parts, admission) = input.into_parts_and_admission();
        let running = admission.dispatch().map_err(ExecutorError::Backend)?;
        let (manifest, resolved) = resolve_prepared_paid_input(parts)?;
        let source = self.get_or_bind_environment(&manifest.canonical_bytes())?;
        let job = self.admit_resolved_job(resolved, source)?;
        running.check_deadline().map_err(ExecutorError::Backend)?;
        let prompt = job.invocation.input_ids.len() as u64;
        self.metrics
            .record_execution_started("evaluate", "causal-lm", prompt, prompt);
        Ok(ExecuteJob {
            span: tracing::Span::current(),
            execution_id: new_execution_id(),
            evaluate_request: job.evaluate_request,
            source: job.source,
            invocation: job.invocation,
            accepted_at: Instant::now(),
            sender,
            producer_key: self.provider.producer_key.clone(),
            running,
            complete,
        })
    }
    #[cfg(test)]
    fn start(
        &mut self,
        job: EvaluateJob,
        execution_id: String,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let stat_prompt = job.invocation.input_ids.len() as u64;
        let (sender, events) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let (complete, completion) = tokio::sync::oneshot::channel();
        let permit = hellas_work::work::admission::WorkPermit::new(
            hellas_work::work::admission::CapacityDomain::Gpu,
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        );
        let running = hellas_work::work::admission::AdmittedWork::payment(permit)
            .dispatch()
            .unwrap();
        let job = ExecuteJob {
            span: tracing::Span::current(),
            execution_id,
            evaluate_request: job.evaluate_request,
            source: job.source,
            invocation: job.invocation,
            accepted_at: Instant::now(),
            sender,
            producer_key: self.provider.producer_key.clone(),
            running,
            complete,
        };
        if !self.pending_owed_executions.is_empty() {
            self.pending_owed_executions
                .push_back(PendingExecution::Resolved(job));
        } else {
            match self.try_start_execution(job) {
                Ok(()) => {}
                Err(StartExecutionError::Busy(job)) => self
                    .pending_owed_executions
                    .push_back(PendingExecution::Resolved(*job)),
                Err(StartExecutionError::Closed(_)) => return Err(ExecutorError::ChannelClosed),
                Err(StartExecutionError::Rejected { error, .. }) => return Err(error),
            }
        }
        self.metrics
            .record_execution_started("evaluate", "causal-lm", stat_prompt, stat_prompt);
        Ok(ExecuteOutcome { events, completion })
    }
}
fn evaluate_stop_reason(stop_reason: StopReason) -> (EvaluateStopReason, Option<u32>) {
    match stop_reason {
        StopReason::StopToken(token_id) => (EvaluateStopReason::STOP_TOKEN, Some(token_id)),
        StopReason::MaxNewTokens => (EvaluateStopReason::MAX_OUTPUT, None),
    }
}
fn ensure_supported_assurance(
    request: Assurance,
    provider: Assurance,
) -> Result<(), ExecutorError> {
    if request == provider {
        Ok(())
    } else {
        Err(ExecutorError::InvalidInput(
            "request assurance does not match provider assurance".to_string(),
        ))
    }
}
#[cfg(test)]
pub(crate) mod environment_admission_tests {
    use super::*;
    use hellas_rpc::{CausalLmEnvironment, ContentRef, ProducerSigningKey};
    use std::path::{Path, PathBuf};
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/hellas-evaluate-admission")
                .join(uuid::Uuid::new_v4().to_string());
            std::fs::create_dir_all(&path).expect("create admission fixture directory");
            Self(path)
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).expect("write admission fixture");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub(crate) struct EnvironmentFixture {
        _scratch: Scratch,
        pub(crate) store: ContentStore,
        program_path: PathBuf,
        pub(crate) manifest_bytes: Vec<u8>,
        pub(crate) manifest_id: ContentId,
    }

    impl EnvironmentFixture {
        pub(crate) fn new() -> Self {
            Self::with_generation_capacity(1_024)
        }

        fn with_generation_capacity(fixed_capacity: u64) -> Self {
            let scratch = Scratch::new();
            let store = ContentStore::new();
            let program_path = scratch.write("model.hex", b"fn model() { return; }");
            let indexed_program = store.index(&program_path).expect("index program");
            let program = ContentRef::new(
                ContentId::from_bytes(*indexed_program.id.as_bytes()),
                indexed_program.len,
            );
            let environment = CausalLmEnvironment::new(
                program,
                "model",
                Vec::new(),
                Vec::new(),
                vec![4],
                256,
                1_024,
                hellas_rpc::CausalLmGenerationSchedule {
                    fixed_capacity,
                    prefill_chunk_tokens: u32::try_from(fixed_capacity.min(64)).unwrap(),
                },
            )
            .expect("valid environment");
            let environment_path =
                scratch.write("model.environment", &environment.canonical_bytes());
            let indexed_environment = store.index(&environment_path).expect("index environment");
            assert_eq!(
                ContentId::from_bytes(*indexed_environment.id.as_bytes()),
                environment.content_id()
            );
            let manifest = environment.manifest();
            Self {
                _scratch: scratch,
                store,
                program_path,
                manifest_bytes: manifest.canonical_bytes(),
                manifest_id: manifest.content_id(),
            }
        }

        fn additional_manifest(&self, index: usize) -> (ContentId, Vec<u8>) {
            let indexed_program = self
                .store
                .index(&self.program_path)
                .expect("re-index fixture program");
            let program = ContentRef::new(
                ContentId::from_bytes(*indexed_program.id.as_bytes()),
                indexed_program.len,
            );
            let environment = CausalLmEnvironment::new(
                program,
                format!("model_{index}"),
                Vec::new(),
                Vec::new(),
                vec![4],
                256,
                1_024,
                hellas_rpc::CausalLmGenerationSchedule {
                    fixed_capacity: 1_024,
                    prefill_chunk_tokens: 64,
                },
            )
            .expect("valid distinct environment");
            let environment_path = self._scratch.write(
                &format!("model-{index}.environment"),
                &environment.canonical_bytes(),
            );
            let indexed_environment = self
                .store
                .index(&environment_path)
                .expect("index distinct environment");
            assert_eq!(
                ContentId::from_bytes(*indexed_environment.id.as_bytes()),
                environment.content_id()
            );
            let manifest = environment.manifest();
            (manifest.content_id(), manifest.canonical_bytes())
        }
    }

    fn evaluate_job(
        engine: &mut EvaluateEngine,
        fixture: &EnvironmentFixture,
        index: u8,
    ) -> EvaluateJob {
        let source = engine
            .get_or_bind_environment(&fixture.manifest_bytes)
            .expect("bind fixture environment");
        let runner = ProducerSigningKey::from_secret_bytes([index.max(1); 32])
            .expect("valid runner key")
            .public_key();
        EvaluateJob {
            evaluate_request: EvaluateRequest {
                text_execution: hellas_rpc::Digest::from_bytes([index; 32]),
                runner_public_key: runner,
                execution_environment: fixture.manifest_id,
                nonce: [index.wrapping_add(1); 32],
                assurance: Assurance::ProducerSigned,
                retain: false,
            },
            source,
            invocation: Invocation {
                input_ids: vec![1],
                max_new_tokens: 1,
                stop_token_ids: vec![4],
            },
        }
    }
    fn engine(store: ContentStore, gpu_config: GpuConfig) -> EvaluateEngine {
        let (completion_tx, _completion_rx) = mpsc::channel(1);
        EvaluateEngine::new(EvaluateEngineConfig {
            content_store: store,
            gpu_config,
            queue_capacity: 1,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: Arc::new(
                    ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid provider key"),
                ),
                assurance: Assurance::ProducerSigned,
            },
            completion_tx,
        })
        .expect("GPU worker thread starts")
    }

    #[test]
    fn admission_uses_the_bound_environment_vocabulary_and_capacity() {
        let valid = Invocation {
            input_ids: vec![1, 2],
            max_new_tokens: 3,
            stop_token_ids: vec![4],
        };
        validate_invocation(&valid, 5, 5).unwrap();

        let invalid_token = Invocation {
            stop_token_ids: vec![5],
            ..valid.clone()
        };
        assert!(validate_invocation(&invalid_token, 5, 5).is_err());

        let over_capacity = Invocation {
            max_new_tokens: 4,
            ..valid
        };
        assert!(validate_invocation(&over_capacity, 5, 5).is_err());
    }
    #[test]
    fn cached_environment_lookup_does_not_reopen_content() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let first = engine
            .get_or_bind_environment(&fixture.manifest_bytes)
            .expect("initial binding");

        std::fs::write(&fixture.program_path, b"replaced after binding")
            .expect("replace indexed program");
        let cached = engine
            .get_or_bind_environment(&fixture.manifest_bytes)
            .expect("cached lookup must not reopen descriptors");

        assert_eq!(cached.manifest_id(), first.manifest_id());
        assert!(std::ptr::eq(cached.environment(), first.environment()));
        assert!(
            cached.open_verified_files().is_err(),
            "the worker-time reopen must still detect replacement"
        );
    }
    #[test]
    fn bound_environment_metadata_cache_evicts_fifo() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let mut ids = Vec::with_capacity(BOUND_ENVIRONMENT_CACHE_CAPACITY + 1);

        for index in 0..=BOUND_ENVIRONMENT_CACHE_CAPACITY {
            let (id, manifest) = fixture.additional_manifest(index);
            let bound = engine
                .get_or_bind_environment(&manifest)
                .expect("bind distinct environment metadata");
            assert_eq!(bound.manifest_id(), id);
            ids.push(id);
        }

        assert_eq!(engine.environments.len(), BOUND_ENVIRONMENT_CACHE_CAPACITY);
        assert_eq!(
            engine.environment_order.len(),
            BOUND_ENVIRONMENT_CACHE_CAPACITY
        );
        assert!(!engine.environments.contains_key(&ids[0]));
        assert!(engine.environments.contains_key(ids.last().unwrap()));
        assert_eq!(engine.environment_order.front(), Some(&ids[1]));
        assert_eq!(engine.environment_order.back(), ids.last());
    }
    #[test]
    fn paid_admission_preserves_valid_jobs() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let source = engine
            .get_or_bind_environment(&fixture.manifest_bytes)
            .expect("bind environment");
        let invocation = Invocation {
            input_ids: vec![1, 2],
            max_new_tokens: 2,
            stop_token_ids: vec![3],
        };
        let resolved = ResolvedEvaluateExecution {
            evaluate_request: EvaluateRequest {
                text_execution: hellas_rpc::Digest::from_bytes([4; 32]),
                runner_public_key: ProducerSigningKey::from_secret_bytes([8; 32])
                    .unwrap()
                    .public_key(),
                execution_environment: fixture.manifest_id,
                nonce: [5; 32],
                assurance: Assurance::ProducerSigned,
                retain: false,
            },
            invocation: invocation.clone(),
        };

        let admitted = engine
            .admit_resolved_job(resolved, source)
            .expect("paid admission preserves the exact input");
        assert_eq!(admitted.invocation.input_ids, invocation.input_ids);
        assert_eq!(
            admitted.evaluate_request.execution_environment,
            fixture.manifest_id
        );
    }
    #[tokio::test]
    async fn accepted_evaluate_jobs_keep_fifo_order_after_waiter_disconnects() {
        let fixture = EnvironmentFixture::new();
        let (worker, control) = ExecuteWorker::controlled();
        let (completion_tx, _) = mpsc::channel(1);
        let mut engine = EvaluateEngine::with_worker(
            EvaluateEngineConfig {
                content_store: fixture.store.clone(),
                gpu_config: GpuConfig::default(),
                queue_capacity: 1,
                metrics: Arc::new(ExecutorMetrics::default()),
                provider: ProviderContext {
                    producer_key: Arc::new(ProducerSigningKey::from_secret_bytes([7; 32]).unwrap()),
                    assurance: Assurance::ProducerSigned,
                },
                completion_tx,
            },
            worker,
        );
        let first = evaluate_job(&mut engine, &fixture, 1);
        let second = evaluate_job(&mut engine, &fixture, 2);
        let first_stream = engine.start(first, "first".into()).unwrap();
        drop(engine.start(second, "second".into()).unwrap());
        assert!(!engine.has_queue_capacity());
        let job = control.try_recv().unwrap();
        assert_eq!(job.execution_id, "first");
        assert!(control.try_recv().is_err());
        drop(first_stream);
        engine
            .on_completion(WorkerCompletion {
                execution_id: job.execution_id,
                evaluate_request: job.evaluate_request,
                invocation: job.invocation,
                sender: job.sender,
                running: job.running,
                complete: job.complete,
                result: WorkerCompletionResult::Failed {
                    position: 0,
                    error: "fixture".into(),
                },
            })
            .await;
        engine.dispatch_next_execution();
        assert_eq!(control.try_recv().unwrap().execution_id, "second");
    }
}
