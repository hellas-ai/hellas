use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::ExecutorError;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    decode_token_delta_payload, input_commitment,
};
use hellas_rpc::pb::courtesy::{
    GetArtifactRequest, GetArtifactResponse, QuoteResponse, QuoteTokensRequest,
};
use hellas_rpc::pb::evaluate::EvaluateRequest as PbEvaluateRequest;
use hellas_rpc::pb::execute::{Ticket, WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::protocol::artifacts::{OutputAddressed, TextExecutionId, completed_text};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{
    Assurance, ContentId, Digest, Evaluate, EvaluateRequest, OutputEventEnvelope, PublicKey,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{info, warn};

use crate::artifacts::{
    EvaluateArtifactStore, PreparedTextArtifacts, ResolvedEvaluateExecution,
    resolve_prepared_paid_input,
};
use crate::environment::CausalLmEnvironmentSource;
use crate::executor::{ExecuteOutcome, ExecutorCompletion, ProviderContext, TicketOutcome};
use crate::metrics::ExecutorMetrics;
use crate::state::{
    ExecutorState, Invocation, QUOTE_AMOUNT, QUOTE_TTL, QuoteKind, QuotePlan, QuoteRecord,
    StopReason, Termination, evaluate_request_to_pb, new_execution_id, quote_ticket,
    validate_invocation,
};
use crate::worker::{
    EnqueueError, ExecuteJob, ExecuteWorker, GpuConfig, WorkerCompletion, WorkerCompletionResult,
};
use hellas_store::ContentStore;

const PER_EXECUTION_CHANNEL_CAPACITY: usize = 64;
/// Bound roots remembered only to avoid reopening verified metadata. Jobs
/// already quoted, queued, or running own an `Arc` clone, so FIFO eviction
/// cannot invalidate accepted work.
const BOUND_ENVIRONMENT_CACHE_CAPACITY: usize = 256;
const COMPLETED_EXECUTION_CACHE_CAPACITY: usize = 1024;
/// Replay is an optimization, not authority to retain arbitrary transcript
/// payload forever. 128 MiB leaves ample room for ordinary retained answers
/// while bounding the aggregate structurally accounted transcript footprint.
const COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY: usize = 128 * 1024 * 1024;
const COMPLETED_EXECUTION_REPLAY_MAX_IN_FLIGHT: usize = 16;

/// The opaque quote payload the executor core stores for an evaluate ticket.
#[derive(Clone)]
pub struct EvaluateJob {
    pub evaluate_request: EvaluateRequest,
    pub source: CausalLmEnvironmentSource,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
}

impl EvaluateJob {
    /// Conservative logical heap retained by the boxed quote payload.
    ///
    /// The fixed value is the allocation behind `Box<EvaluateJob>`. Owned
    /// buffers are charged at capacity, and the full environment metadata is
    /// charged once per quote even when its `Arc` is shared with the cache.
    pub(crate) fn retained_heap_bytes(&self) -> Option<usize> {
        let invocation = self
            .invocation
            .input_ids
            .capacity()
            .checked_mul(std::mem::size_of::<u32>())?
            .checked_add(
                self.invocation
                    .stop_token_ids
                    .capacity()
                    .checked_mul(std::mem::size_of::<u32>())?,
            )?;
        let prepared = match &self.prepared_artifacts {
            Some(prepared) => prepared.retained_heap_bytes()?,
            None => 0,
        };
        std::mem::size_of::<Self>()
            .checked_add(invocation)?
            .checked_add(prepared)?
            .checked_add(self.source.retained_heap_bytes()?)
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionClass {
    BestEffort,
    Owed,
}

pub struct EvaluateEngine {
    output_cache: hellas_rpc::cache::CacheOptions,
    artifacts: EvaluateArtifactStore,
    content_store: ContentStore,
    environments: HashMap<ContentId, CausalLmEnvironmentSource>,
    environment_order: VecDeque<ContentId>,
    completed: HashMap<[u8; 32], CompletedEvaluate>,
    completed_order: VecDeque<[u8; 32]>,
    completed_bytes: usize,
    replay_slots: Arc<Semaphore>,
    worker: ExecuteWorker,
    worker_state: WorkerState,
    gpu_config: GpuConfig,
    /// Paid executions whose durable gate has already committed to invoking
    /// them. This actor-owned FIFO is deliberately separate from the bounded
    /// peer queue: owed work cannot be refused merely because peers filled
    /// their admission capacity, and it always dispatches first.
    pending_owed_executions: VecDeque<ExecuteJob>,
    pending_executions: VecDeque<ExecuteJob>,
    queue_capacity: usize,
    execute_policy: ExecutePolicy,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
}

pub(crate) struct EvaluateEngineConfig {
    pub output_cache: hellas_rpc::cache::CacheOptions,
    pub artifacts: EvaluateArtifactStore,
    pub content_store: ContentStore,
    pub gpu_config: GpuConfig,
    pub queue_capacity: usize,
    pub execute_policy: ExecutePolicy,
    pub metrics: Arc<ExecutorMetrics>,
    pub provider: ProviderContext,
    pub completion_tx: mpsc::Sender<ExecutorCompletion>,
}

#[derive(Clone)]
struct CompletedEvaluate {
    runner_public_key: PublicKey,
    assurance: Assurance,
    termination: Termination,
    retained_bytes: usize,
}

impl CompletedEvaluate {
    fn new(
        runner_public_key: PublicKey,
        assurance: Assurance,
        termination: Termination,
    ) -> Option<Self> {
        let retained_bytes = termination_retained_bytes(&termination)?;
        Some(Self {
            runner_public_key,
            assurance,
            termination,
            retained_bytes,
        })
    }
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
            output_cache: config.output_cache,
            artifacts: config.artifacts,
            content_store: config.content_store,
            environments: HashMap::new(),
            environment_order: VecDeque::new(),
            completed: HashMap::new(),
            completed_order: VecDeque::new(),
            completed_bytes: 0,
            replay_slots: Arc::new(Semaphore::new(COMPLETED_EXECUTION_REPLAY_MAX_IN_FLIGHT)),
            worker,
            worker_state: WorkerState::Idle,
            gpu_config: config.gpu_config,
            pending_owed_executions: VecDeque::new(),
            pending_executions: VecDeque::new(),
            queue_capacity: config.queue_capacity,
            execute_policy: config.execute_policy,
            metrics: config.metrics,
            provider: config.provider,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_worker(config: EvaluateEngineConfig, worker: ExecuteWorker) -> Self {
        Self::with_worker(config, worker)
    }

    fn try_start_execution(&mut self, job: ExecuteJob) -> Result<(), StartExecutionError> {
        if let Err(error) = self
            .artifacts
            .ensure_retention_available(&job.evaluate_request)
        {
            return Err(StartExecutionError::Rejected {
                job: Box::new(job),
                error,
            });
        }
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

    pub(super) async fn replay_completed(
        &self,
        request_commitment: [u8; 32],
        runner_public_key: &PublicKey,
        assurance: Assurance,
    ) -> Result<Option<ExecuteOutcome>, ExecutorError> {
        let Some(completed) = self.completed.get(&request_commitment) else {
            return Ok(None);
        };
        if completed.runner_public_key != *runner_public_key {
            return Err(ExecutorError::PolicyDenied(
                "run ticket signer is not authorized for this ticket".to_string(),
            ));
        }
        if completed.assurance != assurance {
            return Err(ExecutorError::InvalidQuoteRequest(
                "evaluate request assurance does not match ticket terms".to_string(),
            ));
        }
        let replay_permit = Arc::clone(&self.replay_slots)
            .try_acquire_owned()
            .map_err(|_| {
                ExecutorError::ResourceExhausted(
                    "evaluate replay concurrency capacity is exhausted".to_string(),
                )
            })?;
        let termination = completed.termination.clone();
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        tokio::spawn(replay_evaluate_termination(
            termination,
            sender,
            replay_permit,
        ));
        Ok(Some(ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: request_commitment,
            },
            events: receiver,
        }))
    }

    pub(crate) fn dispatch_next_execution(&mut self, allow_best_effort: bool) {
        while let Some((class, job)) = self.pop_dispatchable_execution(allow_best_effort) {
            if job.sender.is_closed() {
                tracing::debug!(
                    execution_id = %job.execution_id,
                    ?class,
                    "dropping queued execution: consumer disconnected before dispatch"
                );
                self.metrics
                    .record_execution_failed("evaluate", "causal-lm", 0);
                continue;
            }
            match self.try_start_execution(job) {
                Ok(()) => return,
                Err(StartExecutionError::Busy(job)) => {
                    self.push_front_pending_execution(class, *job);
                    return;
                }
                Err(StartExecutionError::Closed(job)) => {
                    warn!(execution_id = %job.execution_id, ?class, "failed to start queued execution: executor channel closed");
                    self.metrics
                        .record_execution_failed("evaluate", "causal-lm", 0);
                    let _ = job
                        .sender
                        .try_send(Err(ExecutorError::ChannelClosed.into()));
                }
                Err(StartExecutionError::Rejected { job, error }) => {
                    warn!(execution_id = %job.execution_id, ?class, %error, "rejected queued execution before GPU dispatch");
                    self.metrics
                        .record_execution_failed("evaluate", "causal-lm", 0);
                    let _ = job.sender.try_send(Err(error.into()));
                }
            }
        }
    }

    fn pop_dispatchable_execution(
        &mut self,
        allow_best_effort: bool,
    ) -> Option<(ExecutionClass, ExecuteJob)> {
        if allow_best_effort {
            return self.pop_pending_execution();
        }
        self.pending_owed_executions
            .pop_front()
            .map(|job| (ExecutionClass::Owed, job))
    }

    fn pop_pending_execution(&mut self) -> Option<(ExecutionClass, ExecuteJob)> {
        self.pending_owed_executions
            .pop_front()
            .map(|job| (ExecutionClass::Owed, job))
            .or_else(|| {
                self.pending_executions
                    .pop_front()
                    .map(|job| (ExecutionClass::BestEffort, job))
            })
    }

    fn push_front_pending_execution(&mut self, class: ExecutionClass, job: ExecuteJob) {
        match class {
            ExecutionClass::BestEffort => self.pending_executions.push_front(job),
            ExecutionClass::Owed => self.pending_owed_executions.push_front(job),
        }
    }

    async fn completed_evaluate_termination(
        &mut self,
        evaluate_request: &EvaluateRequest,
        invocation: &Invocation,
        output: (StopReason, Vec<u32>),
        output_events: Vec<OutputEventEnvelope>,
        prepared_artifacts: Option<&PreparedTextArtifacts>,
        cache_recording: Option<&hellas_rpc::cache::CacheRecording>,
    ) -> Result<(Termination, u64), ExecutorError> {
        let (stop_reason, output_tokens) = output;
        let text_artifact = if evaluate_request.retention().should_retain() {
            self.artifacts
                .record_completed_text_with_prepared(
                    evaluate_request,
                    invocation,
                    &output_tokens,
                    prepared_artifacts,
                )
                .await?
        } else {
            completed_text(
                TextExecutionId::from_digest(evaluate_request.text_execution),
                &invocation.input_ids,
                &output_tokens,
            )
            .artifact
            .output_id()
            .digest()
        };
        let input_units = invocation.input_ids.len() as u64;
        let output_units = output_tokens.len() as u64;
        let usage = EvaluateUsage {
            input_units,
            output_units,
        };
        let billable_units = usage
            .billable_units()
            .map_err(|err| ExecutorError::Execution(format!("evaluate billing failed: {err}")))?;
        let cached_stop_reason = stop_reason;
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
        crate::inference_cache::record(
            cache_recording,
            evaluate_request,
            invocation,
            &output_tokens,
            cached_stop_reason,
            text_artifact,
            &output_events,
        )
        .await?;
        let terminal_output_event = output_events.pop().ok_or_else(|| {
            ExecutorError::Execution("evaluate transcript finished without a terminal event".into())
        })?;
        Ok((
            Termination::Completed {
                streamed_prefix: output_events.into(),
                terminal_output_event: Box::new(terminal_output_event),
            },
            billable_units,
        ))
    }

    /// Resolves one request into the job that would execute it, and
    /// refuses it if this node may not.
    ///
    /// Every admission this engine has that is about the *request* — the
    /// assurance it was made under, the artifacts it names, the execute
    /// policy, and whether the exact environment is locally available —
    /// runs here, once, so the quoted path and the paid path cannot
    /// disagree about what this node will run.
    ///
    /// It says nothing about payment. Whether the job may run at all is
    /// the paid endpoint's question, and it is answered before this is
    /// reached.
    async fn prepare_job(
        &mut self,
        evaluate_request: EvaluateRequest,
    ) -> Result<EvaluateJob, ExecutorError> {
        let environment_source = self
            .environments
            .get(&evaluate_request.execution_environment)
            .cloned()
            .ok_or_else(|| {
                ExecutorError::InvalidQuoteRequest(format!(
                    "execution environment {} is not locally available",
                    evaluate_request.execution_environment
                ))
            })?;
        let resolved = self
            .artifacts
            .resolve_evaluate_request(evaluate_request)
            .await?;
        self.admit_resolved_job(resolved, environment_source)
    }

    fn admit_resolved_job(
        &self,
        resolved: ResolvedEvaluateExecution,
        environment_source: CausalLmEnvironmentSource,
    ) -> Result<EvaluateJob, ExecutorError> {
        let evaluate_request = &resolved.evaluate_request;
        ensure_supported_assurance(evaluate_request.assurance, self.provider.assurance)?;
        if environment_source.manifest_id() != evaluate_request.execution_environment {
            return Err(ExecutorError::InvalidQuoteRequest(format!(
                "bound environment is {}, but request pins {}",
                environment_source.manifest_id(),
                evaluate_request.execution_environment
            )));
        }
        if !self
            .execute_policy
            .allows_environment(&evaluate_request.execution_environment.to_string())
        {
            return Err(ExecutorError::PolicyDenied(format!(
                "execute policy denied environment {}",
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
            prepared_artifacts: resolved.prepared_artifacts,
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
                ExecutorError::InvalidQuoteRequest(format!(
                    "environment {} exceeds the provider GPU resource envelope: {error}",
                    source.manifest_id()
                ))
            })
    }

    /// Returns an immutable cached environment when the exact canonical
    /// manifest was already bound. Only a cache miss opens and verifies local
    /// content; the worker still reopens the descriptors before execution.
    fn get_or_bind_environment(
        &mut self,
        manifest_bytes: &[u8],
    ) -> Result<CausalLmEnvironmentSource, ExecutorError> {
        let manifest = CausalLmEnvironmentSource::parse_manifest(manifest_bytes)
            .map_err(|error| ExecutorError::InvalidQuoteRequest(error.to_string()))?;
        if let Some(source) = self.environments.get(&manifest.id()) {
            return Ok(source.clone());
        }
        let source = CausalLmEnvironmentSource::bind_manifest(&self.content_store, manifest)
            .map_err(|error| ExecutorError::InvalidQuoteRequest(error.to_string()))?;
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
}

fn evaluate_stop_reason(stop_reason: StopReason) -> (EvaluateStopReason, Option<u32>) {
    match stop_reason {
        StopReason::StopToken(token_id) => (EvaluateStopReason::STOP_TOKEN, Some(token_id)),
        StopReason::MaxNewTokens => (EvaluateStopReason::MAX_OUTPUT, None),
    }
}

impl EvaluateEngine {
    pub(crate) async fn quote_evaluate(
        &mut self,
        store: &mut ExecutorState,
        request: PbEvaluateRequest,
    ) -> Result<TicketOutcome<Ticket>, ExecutorError> {
        store.prune_expired_quotes(Instant::now());
        let evaluate_request = crate::state::evaluate_request_from_pb(request)?;
        let job = self.prepare_job(evaluate_request).await?;
        let request_commitment = Evaluate::commit_request(&job.evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            job.evaluate_request.assurance,
        )?;
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: job.evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate(Box::new(job)),
        })?;

        Ok(TicketOutcome {
            response: ticket,
            provenance: ExecutionProvenance {
                commitment_id: request_commitment_bytes,
            },
        })
    }

    pub(crate) async fn quote_tokens(
        &mut self,
        store: &mut ExecutorState,
        request: QuoteTokensRequest,
    ) -> Result<TicketOutcome<QuoteResponse>, ExecutorError> {
        let total_start = Instant::now();
        store.prune_expired_quotes(Instant::now());
        let source = self.get_or_bind_environment(&request.program_manifest)?;
        let plan = QuotePlan::from_tokens_request(request, &source)?;
        // Reject an obviously oversized genesis request before constructing
        // transient artifacts. Artifact-start requests are checked again with
        // their complete materialized prefix by `admit_resolved_job` below.
        self.validate_provider_resources(&source, &plan.invocation)?;

        let resolved = self.artifacts.prepare_text(&plan).await?;
        let job = self.admit_resolved_job(resolved, source)?;
        let evaluate_request_pb = evaluate_request_to_pb(&job.evaluate_request);
        let request_commitment = Evaluate::commit_request(&job.evaluate_request);
        let (terms, ticket) = quote_ticket(
            request_commitment,
            self.provider.genesis.as_slice(),
            job.evaluate_request.assurance,
        )?;
        let commitment_id = request_commitment.digest();
        let prompt_tokens = u32::try_from(plan.invocation.input_ids.len()).map_err(|_| {
            ExecutorError::InvalidTokenPayload(
                "prompt token count exceeds the RPC representation".to_string(),
            )
        })?;
        let request_commitment_bytes = store.create_quote(QuoteRecord {
            terms,
            expires_at: Instant::now() + QUOTE_TTL,
            runner_public_key: job.evaluate_request.runner_public_key,
            kind: QuoteKind::Evaluate(Box::new(job)),
        })?;

        info!(
            request_commitment = %hex32(&request_commitment_bytes),
            commitment_id = %commitment_id,
            prompt_tokens,
            amount = QUOTE_AMOUNT,
            total_ms = total_start.elapsed().as_millis(),
            "quoted causal-LM evaluate execution"
        );

        Ok(TicketOutcome {
            response: QuoteResponse {
                ticket: Some(ticket),
                prompt_tokens,
                evaluate_request: Some(evaluate_request_pb),
            },
            provenance: ExecutionProvenance {
                commitment_id: *commitment_id.as_bytes(),
            },
        })
    }

    pub(crate) async fn get_artifact(
        &mut self,
        request: GetArtifactRequest,
    ) -> Result<GetArtifactResponse, ExecutorError> {
        // Courtesy only exposes the retained store. Ephemeral prompt and
        // token artifacts live in the separate memory store and are never
        // reachable through this API.
        let canonical_artifact = self
            .artifacts
            .get_canonical_bytes(digest_from_slice(&request.digest, "digest")?)
            .await?;
        Ok(GetArtifactResponse { canonical_artifact })
    }

    pub(crate) fn start(
        &mut self,
        job: EvaluateJob,
        execution_id: String,
        request_commitment: [u8; 32],
    ) -> Result<ExecuteOutcome, ExecutorError> {
        self.start_with_class(
            job,
            execution_id,
            request_commitment,
            ExecutionClass::BestEffort,
        )
    }

    #[cfg(test)]
    pub(crate) fn start_owed_for_test(
        &mut self,
        job: EvaluateJob,
        execution_id: String,
        request_commitment: [u8; 32],
    ) -> Result<ExecuteOutcome, ExecutorError> {
        self.start_with_class(job, execution_id, request_commitment, ExecutionClass::Owed)
    }

    fn start_with_class(
        &mut self,
        job: EvaluateJob,
        execution_id: String,
        request_commitment: [u8; 32],
        class: ExecutionClass,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let EvaluateJob {
            evaluate_request,
            source,
            invocation,
            prepared_artifacts,
        } = job;
        let stat_prompt = invocation.input_ids.len() as u64;
        let (sender, receiver) = mpsc::channel(PER_EXECUTION_CHANNEL_CAPACITY);
        let execute_job = ExecuteJob {
            cache_recording: self
                .output_cache
                .recording()
                .map_err(|error| ExecutorError::ArtifactStore(error.to_string()))?,
            output_cache: self.output_cache.clone(),
            span: tracing::Span::current(),
            execution_id: execution_id.clone(),
            request_commitment,
            evaluate_request,
            source,
            invocation,
            prepared_artifacts,
            accepted_at: Instant::now(),
            sender,
            producer_key: self.provider.producer_key.clone(),
        };

        // An owed FIFO entry represents a durable paid-work decision. New
        // peer work must not slip into the worker or the bounded peer queue
        // ahead of it. A later owed entry likewise joins the FIFO directly so
        // it cannot race an earlier one for a newly idle worker.
        let queued = if !self.pending_owed_executions.is_empty() {
            match class {
                ExecutionClass::Owed => {
                    self.pending_owed_executions.push_back(execute_job);
                    true
                }
                ExecutionClass::BestEffort => {
                    return Err(ExecutorError::QueueFull {
                        capacity: self.queue_capacity,
                    });
                }
            }
        } else {
            match self.try_start_execution(execute_job) {
                Ok(()) => false,
                Err(StartExecutionError::Busy(job)) => {
                    match class {
                        ExecutionClass::Owed => self.pending_owed_executions.push_back(*job),
                        ExecutionClass::BestEffort => {
                            if self.pending_executions.len() >= self.queue_capacity {
                                return Err(ExecutorError::QueueFull {
                                    capacity: self.queue_capacity,
                                });
                            }
                            self.pending_executions.push_back(*job);
                        }
                    }
                    true
                }
                Err(StartExecutionError::Closed(_job)) => {
                    return Err(ExecutorError::ChannelClosed);
                }
                Err(StartExecutionError::Rejected { error, .. }) => return Err(error),
            }
        };

        self.metrics.record_execution_started(
            "evaluate",
            "causal-lm",
            stat_prompt,
            /* prefill= */ stat_prompt,
        );

        info!(
            execution_id = %execution_id,
            request_commitment = %hex32(&request_commitment),
            ?class,
            queued,
            queue_len = self.pending_executions.len(),
            owed_queue_len = self.pending_owed_executions.len(),
            "accepted evaluate execution"
        );

        Ok(ExecuteOutcome {
            provenance: ExecutionProvenance {
                commitment_id: request_commitment,
            },
            events: receiver,
        })
    }

    /// Resolves and starts a paid input rebuilt from its durable journal.
    ///
    /// The paid endpoint's durable journal, rather than the transient quote
    /// store, admits this call. Its canonical manifest rebinds the environment
    /// from verified local content, so restart recovery does not depend on a
    /// Courtesy quote having populated this process's registry.
    pub(crate) async fn start_prepared_input(
        &mut self,
        input: hellas_work::work::PreparedEvaluateInput,
    ) -> Result<ExecuteOutcome, ExecutorError> {
        let (manifest, resolved) = resolve_prepared_paid_input(input.into_parts())?;
        let request_commitment = *Evaluate::commit_request(&resolved.evaluate_request).as_bytes();
        let source = self.get_or_bind_environment(&manifest.canonical_bytes())?;
        let job = self.admit_resolved_job(resolved, source)?;
        // Deliberately not `replay_completed`: that map is keyed by
        // request commitment and would answer a second paid job for the
        // same request out of the first one's transcript, without
        // invoking anything. A paid job is invoked because its journal
        // says so, and this is the invocation.
        self.start_with_class(
            job,
            new_execution_id(),
            request_commitment,
            ExecutionClass::Owed,
        )
    }

    fn cache_completed(&mut self, request_commitment: [u8; 32], completed: CompletedEvaluate) {
        self.cache_completed_with_limits(
            request_commitment,
            completed,
            COMPLETED_EXECUTION_CACHE_CAPACITY,
            COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY,
        );
    }

    fn cache_completed_with_limits(
        &mut self,
        request_commitment: [u8; 32],
        completed: CompletedEvaluate,
        entry_capacity: usize,
        byte_capacity: usize,
    ) {
        // A replacement is a new completion and becomes the newest FIFO
        // entry. Removing first also ensures an over-large replacement never
        // leaves a stale transcript for the same request commitment.
        self.completed_order
            .retain(|candidate| candidate != &request_commitment);
        self.remove_completed(request_commitment);

        if entry_capacity == 0 || completed.retained_bytes > byte_capacity {
            return;
        }
        while self.completed.len() >= entry_capacity
            || self
                .completed_bytes
                .checked_add(completed.retained_bytes)
                .is_none_or(|bytes| bytes > byte_capacity)
        {
            let Some(oldest) = self.completed_order.pop_front() else {
                // This is an internal-accounting inconsistency, not a reason
                // to let an optimization escape its hard memory bound.
                self.completed.clear();
                self.completed_bytes = 0;
                break;
            };
            self.remove_completed(oldest);
        }
        let Some(completed_bytes) = self
            .completed_bytes
            .checked_add(completed.retained_bytes)
            .filter(|bytes| *bytes <= byte_capacity)
        else {
            return;
        };
        self.completed_bytes = completed_bytes;
        self.completed_order.push_back(request_commitment);
        self.completed.insert(request_commitment, completed);
    }

    fn remove_completed(&mut self, request_commitment: [u8; 32]) {
        let Some(removed) = self.completed.remove(&request_commitment) else {
            return;
        };
        let Some(remaining) = self.completed_bytes.checked_sub(removed.retained_bytes) else {
            // Clear the replay optimization on impossible accounting state;
            // live completion delivery does not depend on this cache.
            self.completed.clear();
            self.completed_order.clear();
            self.completed_bytes = 0;
            return;
        };
        self.completed_bytes = remaining;
    }

    pub(crate) async fn on_completion(&mut self, completion: WorkerCompletion) {
        let WorkerCompletion {
            cache_recording,
            execution_id,
            request_commitment,
            evaluate_request,
            invocation,
            prepared_artifacts,
            sender,
            result,
            ..
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
                    prepared_artifacts.as_ref(),
                    cache_recording.as_ref(),
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
            if evaluate_request.retention().should_retain()
                && let Some(completed) = CompletedEvaluate::new(
                    evaluate_request.runner_public_key,
                    evaluate_request.assurance,
                    termination.clone(),
                )
            {
                self.cache_completed(request_commitment, completed);
            }
        } else {
            self.metrics
                .record_execution_failed("evaluate", "causal-lm", generated);
        }

        // Completion runs on the actor itself. A stalled consumer must never
        // wedge environment admission, quotes, or every later execution behind an
        // awaited send into its already-full per-run channel.
        let _ = sender.try_send(Ok(termination.into_pb()));
    }
}

async fn replay_evaluate_termination(
    termination: Termination,
    sender: mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
    _replay_permit: OwnedSemaphorePermit,
) {
    async {
        let (streamed_prefix, terminal_output_event) = match termination {
            Termination::Completed {
                streamed_prefix,
                terminal_output_event,
            } => (streamed_prefix, terminal_output_event),
            failed @ Termination::Failed { .. } => {
                let _ = sender.send(Ok(failed.into_pb())).await;
                return;
            }
        };

        let mut position = 0_u64;
        for output_event in streamed_prefix.iter() {
            let next_position = match decode_token_delta_payload(output_event.payload()) {
                Ok(delta) if delta.start_position == position => match delta.end_position() {
                    Ok(position) => position,
                    Err(error) => {
                        send_evaluate_replay_failed(
                            &sender,
                            position,
                            format!("stored evaluate transcript is invalid: {error}"),
                        )
                        .await;
                        return;
                    }
                },
                Ok(delta) => {
                    send_evaluate_replay_failed(
                        &sender,
                        position,
                        format!(
                            "stored evaluate transcript starts at {}, expected {position}",
                            delta.start_position
                        ),
                    )
                    .await;
                    return;
                }
                Err(error) => {
                    send_evaluate_replay_failed(
                        &sender,
                        position,
                        format!("stored evaluate transcript is invalid: {error}"),
                    )
                    .await;
                    return;
                }
            };
            let chunk = WorkEvent {
                kind: Some(work_event::Kind::Chunk(WorkChunk {
                    output_event: Some(output_event_to_pb(output_event)),
                })),
            };
            if sender.send(Ok(chunk)).await.is_err() {
                return;
            }
            position = next_position;
        }
        let terminal_frame = WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: Some(output_event_to_pb(terminal_output_event.as_ref())),
                assurance_evidence: Vec::new(),
            })),
        };
        let _ = sender.send(Ok(terminal_frame)).await;
    }
    .await;

    // A slot covers the consumer's buffered replay lifetime, not only this
    // producer task. This resolves once the receiver drains every item or is
    // dropped, and keeps abandoned replays within the fixed semaphore bound.
    let _drained_or_dropped = sender.reserve_many(PER_EXECUTION_CHANNEL_CAPACITY).await;
}

async fn send_evaluate_replay_failed(
    sender: &mpsc::Sender<Result<WorkEvent, hellas_wire::WireStatus>>,
    position: u64,
    error: impl Into<String>,
) {
    let _ = sender
        .send(Ok(WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed {
                position,
                error: error.into(),
            })),
        }))
        .await;
}

/// Checked structural footprint of one cached replay transcript.
///
/// `size_of` accounts for every fixed field and shared-slice handle. The slice
/// length and terminal box account for every allocated envelope value, while
/// [`OutputEventEnvelope::retained_heap_bytes`] accounts for the exact
/// capacities of their only variable buffers.
fn termination_retained_bytes(termination: &Termination) -> Option<usize> {
    let fixed = std::mem::size_of::<Termination>();
    match termination {
        Termination::Completed {
            streamed_prefix,
            terminal_output_event,
        } => {
            let slots =
                std::mem::size_of::<OutputEventEnvelope>().checked_mul(streamed_prefix.len())?;
            let bytes = streamed_prefix
                .iter()
                .try_fold(fixed.checked_add(slots)?, |bytes, envelope| {
                    bytes.checked_add(envelope.retained_heap_bytes()?)
                })?;
            bytes
                .checked_add(std::mem::size_of::<OutputEventEnvelope>())?
                .checked_add(terminal_output_event.retained_heap_bytes()?)
        }
        Termination::Failed { error, .. } => fixed.checked_add(error.capacity()),
    }
}

fn ensure_supported_assurance(
    request: Assurance,
    provider: Assurance,
) -> Result<(), ExecutorError> {
    if request == provider {
        Ok(())
    } else {
        Err(ExecutorError::InvalidQuoteRequest(
            "request assurance does not match provider assurance".to_string(),
        ))
    }
}

fn digest_from_slice(bytes: &[u8], field: &str) -> Result<Digest, ExecutorError> {
    crate::state::fixed::<32>(field, bytes)
        .map(Digest::from_bytes)
        .map_err(ExecutorError::InvalidQuoteRequest)
}

fn hex32(bytes: &[u8; 32]) -> String {
    Digest::from_bytes(*bytes).to_string()
}

#[cfg(test)]
pub(crate) mod environment_admission_tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment,
    };
    use hellas_rpc::pb::courtesy::{
        EvaluateGenesisStart, EvaluateStart, QuoteTokensRequest, evaluate_start,
    };
    use hellas_rpc::pb::execute::work_event;
    use hellas_rpc::policy::ExecutePolicy;
    use hellas_rpc::stream::output_event_from_pb;
    use hellas_rpc::{
        Assurance, CausalLmEnvironment, ContentId, ContentRef, Digest, EvaluateRequest, JobTerms,
        ProducerSigningKey, RequestCommitment,
    };
    use hellas_store::ContentStore;
    use tokio::sync::{Semaphore, mpsc};

    use super::{
        BOUND_ENVIRONMENT_CACHE_CAPACITY, COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY,
        COMPLETED_EXECUTION_CACHE_CAPACITY, CompletedEvaluate, EvaluateArtifactStore,
        EvaluateEngine, EvaluateEngineConfig, EvaluateJob, ExecuteJob, ExecutionClass,
        ExecutorError, ExecutorMetrics, ExecutorState, GpuConfig, Invocation, ProviderContext,
        QuoteKind, QuoteRecord, ResolvedEvaluateExecution, Termination,
        replay_evaluate_termination, termination_retained_bytes, validate_invocation,
    };

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

    fn engine(store: ContentStore, gpu_config: GpuConfig) -> EvaluateEngine {
        let (completion_tx, _completion_rx) = mpsc::channel(1);
        EvaluateEngine::new(EvaluateEngineConfig {
            output_cache: Default::default(),
            artifacts: EvaluateArtifactStore::memory(),
            content_store: store,
            gpu_config,
            queue_capacity: 1,
            execute_policy: ExecutePolicy::Any,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: Arc::new(
                    ProducerSigningKey::from_secret_bytes([7; 32]).expect("valid provider key"),
                ),
                genesis: Arc::new(b"genesis".to_vec()),
                assurance: Assurance::ProducerSigned,
            },
            completion_tx,
        })
        .expect("GPU worker thread starts")
    }

    fn request_commitment(index: u32) -> [u8; 32] {
        let mut commitment = [0_u8; 32];
        commitment[..4].copy_from_slice(&index.to_be_bytes());
        commitment
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
                text_execution: Digest::from_bytes([index; 32]),
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
            prepared_artifacts: None,
        }
    }

    fn pending_job(
        engine: &mut EvaluateEngine,
        fixture: &EnvironmentFixture,
        index: u8,
        execution_id: &str,
    ) -> ExecuteJob {
        let EvaluateJob {
            evaluate_request,
            source,
            invocation,
            prepared_artifacts,
        } = evaluate_job(engine, fixture, index);
        let (sender, _receiver) = mpsc::channel(1);
        ExecuteJob {
            cache_recording: None,
            output_cache: Default::default(),
            span: tracing::Span::none(),
            execution_id: execution_id.to_string(),
            request_commitment: request_commitment(index.into()),
            evaluate_request,
            source,
            invocation,
            prepared_artifacts,
            accepted_at: Instant::now(),
            sender,
            producer_key: engine.provider.producer_key.clone(),
        }
    }

    fn completed_evaluate(token_count: usize) -> CompletedEvaluate {
        let producer =
            ProducerSigningKey::from_secret_bytes([9; 32]).expect("valid completion key");
        let request = EvaluateRequest {
            text_execution: Digest::from_bytes([10; 32]),
            runner_public_key: producer.public_key(),
            execution_environment: ContentId::from_bytes([11; 32]),
            nonce: [12; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        };
        let mut builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&request),
            request.assurance,
            &producer,
        );
        for _ in 0..token_count {
            builder
                .push_token_delta(vec![7])
                .expect("non-empty token delta");
        }
        let output_units = u64::try_from(token_count).expect("fixture token count fits u64");
        let mut output_events = builder
            .finish(EvaluateTerminal {
                final_position: output_units,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: Digest::from_bytes([13; 32]),
                usage: EvaluateUsage {
                    input_units: 1,
                    output_units,
                },
                billable_units: output_units + 1,
            })
            .expect("valid completed transcript");
        let terminal_output_event = output_events.pop().expect("terminal event");
        CompletedEvaluate::new(
            request.runner_public_key,
            request.assurance,
            Termination::Completed {
                streamed_prefix: output_events.into(),
                terminal_output_event: Box::new(terminal_output_event),
            },
        )
        .expect("fixture size accounting does not overflow")
    }

    fn quote_request(fixture: &EnvironmentFixture) -> QuoteTokensRequest {
        let runner = ProducerSigningKey::from_secret_bytes([8; 32]).expect("valid runner key");
        QuoteTokensRequest {
            program_manifest: fixture.manifest_bytes.clone(),
            prompt_token_ids: vec![1, 2],
            max_new_tokens: Some(2),
            stop_token_ids: vec![3],
            start: Some(EvaluateStart {
                kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
            }),
            runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                &runner.public_key(),
            )),
            assurance: Assurance::ProducerSigned.to_byte().into(),
            retain: Some(false),
        }
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
    fn owed_fifo_dispatches_before_best_effort_and_preserves_each_order() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let best_one = pending_job(&mut engine, &fixture, 1, "best-one");
        let best_two = pending_job(&mut engine, &fixture, 2, "best-two");
        let owed_one = pending_job(&mut engine, &fixture, 3, "owed-one");
        let owed_two = pending_job(&mut engine, &fixture, 4, "owed-two");
        engine.pending_executions.extend([best_one, best_two]);
        engine.pending_owed_executions.extend([owed_one, owed_two]);

        let mut order = Vec::new();
        while let Some((_class, job)) = engine.pop_pending_execution() {
            order.push(job.execution_id);
        }

        assert_eq!(order, ["owed-one", "owed-two", "best-one", "best-two"]);
    }

    #[test]
    fn owed_backlog_refuses_best_effort_and_appends_paid_exactly_once() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let first_owed = pending_job(&mut engine, &fixture, 1, "owed-one");
        engine.pending_owed_executions.push_back(first_owed);

        let ordinary = evaluate_job(&mut engine, &fixture, 2);
        let error = engine
            .start(ordinary, "best-effort".into(), request_commitment(2))
            .expect_err("peer work cannot bypass an owed execution");
        assert!(matches!(error, ExecutorError::QueueFull { capacity: 1 }));
        assert!(engine.pending_executions.is_empty());
        assert_eq!(engine.pending_owed_executions.len(), 1);

        let paid = evaluate_job(&mut engine, &fixture, 3);
        let _outcome = engine
            .start_with_class(
                paid,
                "owed-two".into(),
                request_commitment(3),
                ExecutionClass::Owed,
            )
            .expect("a durable paid execution joins the owed FIFO");
        assert_eq!(engine.pending_owed_executions.len(), 2);
        assert_eq!(
            engine
                .pending_owed_executions
                .iter()
                .map(|job| job.execution_id.as_str())
                .collect::<Vec<_>>(),
            ["owed-one", "owed-two"]
        );
    }

    #[test]
    fn evaluate_quote_accounts_for_box_buffers_and_bound_environment_metadata() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store.clone(), GpuConfig::default());
        let source = engine
            .get_or_bind_environment(&fixture.manifest_bytes)
            .expect("bind environment");
        let source_bytes = source.retained_heap_bytes().unwrap();
        let runner = ProducerSigningKey::from_secret_bytes([8; 32])
            .expect("valid runner key")
            .public_key();
        let mut input_ids = Vec::with_capacity(512);
        input_ids.extend([1, 2]);
        let mut stop_token_ids = Vec::with_capacity(128);
        stop_token_ids.push(3);
        let invocation_bytes = input_ids.capacity() * std::mem::size_of::<u32>()
            + stop_token_ids.capacity() * std::mem::size_of::<u32>();
        let job = EvaluateJob {
            evaluate_request: EvaluateRequest {
                text_execution: Digest::from_bytes([4; 32]),
                runner_public_key: runner,
                execution_environment: fixture.manifest_id,
                nonce: [5; 32],
                assurance: Assurance::ProducerSigned,
                retain: false,
            },
            source,
            invocation: Invocation {
                input_ids,
                max_new_tokens: 2,
                stop_token_ids,
            },
            prepared_artifacts: None,
        };
        let expected_job_bytes =
            std::mem::size_of::<EvaluateJob>() + invocation_bytes + source_bytes;
        assert_eq!(job.retained_heap_bytes(), Some(expected_job_bytes));

        let quote = QuoteRecord {
            terms: JobTerms {
                request: RequestCommitment::from_digest(Digest::from_bytes([6; 32])),
                provider_genesis: ContentId::from_bytes([7; 32]),
                assurance: Assurance::ProducerSigned,
                amount: 1,
                ttl_ms: 1,
            },
            expires_at: std::time::Instant::now(),
            runner_public_key: runner,
            kind: QuoteKind::Evaluate(Box::new(job)),
        };

        assert_eq!(
            quote.retained_heap_bytes(),
            Some(std::mem::size_of::<QuoteRecord>() + expected_job_bytes)
        );
        assert!(invocation_bytes > 3 * std::mem::size_of::<u32>());
    }

    #[tokio::test]
    async fn courtesy_quote_rejects_provider_capacity_and_state_envelopes() {
        let fixture = EnvironmentFixture::with_generation_capacity(4);
        for (gpu_config, expected) in [
            (
                GpuConfig::new(
                    1,
                    1,
                    3,
                    1_024,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .unwrap(),
                "generation capacity 4",
            ),
            (
                GpuConfig::new(
                    1,
                    1,
                    1_024,
                    15,
                    Duration::from_secs(1),
                    Duration::from_secs(1),
                )
                .unwrap(),
                "minimum generation device bytes",
            ),
        ] {
            let mut engine = engine(fixture.store.clone(), gpu_config);
            let mut state = ExecutorState::new();
            let error = engine
                .quote_tokens(&mut state, quote_request(&fixture))
                .await
                .expect_err("provider envelope must reject the quote");
            assert!(
                matches!(&error, ExecutorError::InvalidQuoteRequest(message) if message.contains(expected)),
                "unexpected rejection: {error}"
            );
        }
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
    fn completed_replay_cache_enforces_entries_bytes_and_replacement_accounting() {
        let fixture = EnvironmentFixture::new();
        let small = completed_evaluate(1);
        let large = completed_evaluate(32);
        assert_eq!(
            termination_retained_bytes(&small.termination),
            Some(small.retained_bytes)
        );
        assert!(large.retained_bytes > small.retained_bytes);

        let mut entries = engine(fixture.store.clone(), GpuConfig::default());
        for index in 0..3 {
            entries.cache_completed_with_limits(
                request_commitment(index),
                small.clone(),
                2,
                usize::MAX,
            );
        }
        assert_eq!(entries.completed.len(), 2);
        assert!(!entries.completed.contains_key(&request_commitment(0)));
        assert_eq!(
            entries.completed_order.front(),
            Some(&request_commitment(1))
        );
        assert_eq!(
            entries.completed_bytes,
            small.retained_bytes.checked_mul(2).unwrap()
        );

        let mut bytes = engine(fixture.store.clone(), GpuConfig::default());
        let byte_capacity = small.retained_bytes.checked_mul(2).unwrap();
        for index in 0..3 {
            bytes.cache_completed_with_limits(
                request_commitment(index),
                small.clone(),
                8,
                byte_capacity,
            );
        }
        assert_eq!(bytes.completed.len(), 2);
        assert!(!bytes.completed.contains_key(&request_commitment(0)));
        assert_eq!(bytes.completed_bytes, byte_capacity);

        let mut replacement = engine(fixture.store.clone(), GpuConfig::default());
        let replacement_capacity = small
            .retained_bytes
            .checked_add(large.retained_bytes)
            .unwrap();
        replacement.cache_completed_with_limits(
            request_commitment(1),
            small.clone(),
            8,
            replacement_capacity,
        );
        replacement.cache_completed_with_limits(
            request_commitment(2),
            small.clone(),
            8,
            replacement_capacity,
        );
        replacement.cache_completed_with_limits(
            request_commitment(1),
            large.clone(),
            8,
            replacement_capacity,
        );
        assert_eq!(replacement.completed.len(), 2);
        assert_eq!(replacement.completed_bytes, replacement_capacity);
        assert_eq!(
            replacement
                .completed_order
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![request_commitment(2), request_commitment(1)]
        );
        replacement.cache_completed_with_limits(
            request_commitment(1),
            small.clone(),
            8,
            replacement_capacity,
        );
        assert_eq!(
            replacement.completed_bytes,
            small.retained_bytes.checked_mul(2).unwrap()
        );

        let mut oversized = engine(fixture.store, GpuConfig::default());
        oversized.cache_completed_with_limits(
            request_commitment(9),
            large.clone(),
            8,
            large.retained_bytes - 1,
        );
        assert!(oversized.completed.is_empty());
        assert!(oversized.completed_order.is_empty());
        assert_eq!(oversized.completed_bytes, 0);
        assert_eq!(COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY, 128 * 1024 * 1024);
    }

    #[tokio::test]
    async fn evaluate_replay_streams_prefix_then_singular_terminal() {
        let completed = completed_evaluate(3);
        let Termination::Completed {
            streamed_prefix,
            terminal_output_event,
        } = &completed.termination
        else {
            panic!("fixture completes");
        };
        let expected_prefix = Arc::clone(streamed_prefix);
        let expected_terminal = terminal_output_event.as_ref().clone();
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned().unwrap();
        let (sender, mut receiver) = mpsc::channel(super::PER_EXECUTION_CHANNEL_CAPACITY);
        let replay = tokio::spawn(replay_evaluate_termination(
            completed.termination,
            sender,
            permit,
        ));

        for expected in expected_prefix.iter() {
            let event = receiver.recv().await.unwrap().unwrap();
            let Some(work_event::Kind::Chunk(chunk)) = event.kind else {
                panic!("replay prefix must use WorkChunk");
            };
            let actual = output_event_from_pb(chunk.output_event.expect("signed output event"))
                .expect("valid output envelope");
            assert_eq!(&actual, expected);
        }
        let event = receiver.recv().await.unwrap().unwrap();
        let Some(work_event::Kind::Finished(finished)) = event.kind else {
            panic!("replay must finish after its prefix");
        };
        let actual = output_event_from_pb(
            finished
                .terminal_output_event
                .expect("signed terminal output event"),
        )
        .expect("valid terminal envelope");
        assert_eq!(actual, expected_terminal);
        assert_eq!(slots.available_permits(), 0);

        drop(receiver);
        replay.await.unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn evaluate_replay_larger_than_its_channel_remains_complete() {
        let event_count = super::PER_EXECUTION_CHANNEL_CAPACITY * 2;
        let completed = completed_evaluate(event_count);
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned().unwrap();
        let (sender, mut receiver) = mpsc::channel(super::PER_EXECUTION_CHANNEL_CAPACITY);
        let replay = tokio::spawn(replay_evaluate_termination(
            completed.termination,
            sender,
            permit,
        ));

        for _ in 0..event_count {
            let event = receiver.recv().await.unwrap().unwrap();
            assert!(matches!(event.kind, Some(work_event::Kind::Chunk(_))));
        }
        let terminal = receiver.recv().await.unwrap().unwrap();
        assert!(matches!(terminal.kind, Some(work_event::Kind::Finished(_))));
        drop(receiver);
        replay.await.unwrap();
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn completed_replay_rejects_a_different_runner_key() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store, GpuConfig::default());
        let commitment = request_commitment(41);
        let completed = completed_evaluate(1);
        engine.cache_completed_with_limits(
            commitment,
            completed,
            COMPLETED_EXECUTION_CACHE_CAPACITY,
            COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY,
        );
        let stranger = ProducerSigningKey::from_secret_bytes([10; 32])
            .expect("valid stranger key")
            .public_key();

        let error = engine
            .replay_completed(commitment, &stranger, Assurance::ProducerSigned)
            .await
            .expect_err("another runner must not replay a retained execution");

        assert!(matches!(error, ExecutorError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn completed_replay_rejects_different_assurance_terms() {
        let fixture = EnvironmentFixture::new();
        let mut engine = engine(fixture.store, GpuConfig::default());
        let commitment = request_commitment(42);
        let completed = completed_evaluate(1);
        let runner = completed.runner_public_key;
        engine.cache_completed_with_limits(
            commitment,
            completed,
            COMPLETED_EXECUTION_CACHE_CAPACITY,
            COMPLETED_EXECUTION_CACHE_BYTE_CAPACITY,
        );

        let error = engine
            .replay_completed(commitment, &runner, Assurance::AppleAppAttest)
            .await
            .expect_err("different assurance terms must not replay retained execution");

        assert!(matches!(error, ExecutorError::InvalidQuoteRequest(_)));
    }

    #[test]
    fn shared_direct_and_paid_admission_preserves_valid_jobs() {
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
            prepared_artifacts: None,
        };

        let admitted = engine
            .admit_resolved_job(resolved, source)
            .expect("the direct and paid paths share valid admission");
        assert_eq!(admitted.invocation.input_ids, invocation.input_ids);
        assert_eq!(
            admitted.evaluate_request.execution_environment,
            fixture.manifest_id
        );
    }
}
