use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use catena_lang::safe_gpu::causal_lm::{
    GenerationControl, GenerationError, GenerationTermination, MAX_MODEL_STATIC_BYTES, Model,
    ModelConfig, minimum_generation_device_bytes,
};
use catena_lang::safe_gpu::{
    Asset, AssetOwner, MAX_RESIDENT_ASSET_BYTES, MAX_RESIDENT_ASSETS, Program, Session,
    SessionTimeouts,
};
use hellas_rpc::evaluate::{EvaluateOutputTranscriptBuilder, input_commitment};
use hellas_rpc::pb::execute::{
    WorkChunk as PbChunk, WorkEvent as PbWorkEvent, work_event::Kind as PbEvent,
};
use hellas_rpc::protocol::artifacts::MAX_RETRIEVABLE_TOKEN_IDS;
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{
    ContentId, ContentRef, EvaluateRequest, MAX_CAUSAL_LM_STATIC_BYTES, OutputEventEnvelope,
    ProducerSigningKey,
};
use hellas_wire::WireStatus;
use tokio::sync::mpsc as tokio_mpsc;
use tracing::warn;
use zeroize::Zeroizing;

use crate::artifacts::PreparedTextArtifacts;
use crate::environment::{CausalLmEnvironmentSource, read_verified_bytes};
use crate::executor::ExecutorCompletion;
use crate::state::{Invocation, StopReason};

/// Default number of distinct programs admitted into one GPU worker session.
///
/// Hellas recycles the execution worker at this boundary to bound compiled
/// artifacts. Immutable assets remain resident in a separate bounded owner.
pub const DEFAULT_GPU_SESSION_PROGRAMS: usize = 8;

/// Default aggregate size of unique static objects retained by one asset owner.
pub const DEFAULT_GPU_SESSION_ASSET_BYTES: u64 = 128 * 1024 * 1024 * 1024;

/// Default provider limit for prompt plus generated tokens in one invocation.
pub const DEFAULT_GPU_MAX_GENERATION_CAPACITY: u64 = 32 * 1024;

/// Conservative provider generation ceiling whose worst-case retained token
/// artifact fits the unary transport's 4 MiB frame.
pub const MAX_GPU_GENERATION_CAPACITY: u64 = MAX_RETRIEVABLE_TOKEN_IDS;

/// Default provider envelope for all non-asset device memory owned or allocated
/// by one generation.
pub const DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Default deadline for loading and compiling one Catena program.
pub const DEFAULT_GPU_COMPILE_TIMEOUT_SECS: u64 =
    catena_lang::safe_gpu::DEFAULT_COMPILE_TIMEOUT.as_secs();

/// Default deadline for one complete GPU generation or control operation.
pub const DEFAULT_GPU_EXECUTION_TIMEOUT_SECS: u64 =
    catena_lang::safe_gpu::DEFAULT_EXECUTION_TIMEOUT.as_secs();

/// Manifest-specific bindings are cheap to recreate from resident programs and
/// assets. Keep only a small working set rather than growing them without bound.
const MAX_RESIDENT_MODELS: usize = 16;

// The canonical protocol and Catena runtime live in separate crates. The
// executor is their meeting point, so compilation must fail if their portable
// logical-static-byte contracts drift apart.
const _: () = assert!(MAX_CAUSAL_LM_STATIC_BYTES == MAX_MODEL_STATIC_BYTES);

/// Bounded provider-local lifetime policy for the isolated GPU worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuConfig {
    backend: catena_lang::safe_gpu::Backend,
    session_programs: usize,
    session_asset_bytes: u64,
    max_generation_capacity: u64,
    max_generation_device_bytes: u64,
    compile_timeout: Duration,
    execution_timeout: Duration,
}

impl GpuConfig {
    pub fn new(
        session_programs: usize,
        session_asset_bytes: u64,
        max_generation_capacity: u64,
        max_generation_device_bytes: u64,
        compile_timeout: Duration,
        execution_timeout: Duration,
    ) -> Result<Self, String> {
        if session_programs == 0 {
            return Err("GPU session program limit must be greater than zero".to_string());
        }
        if session_asset_bytes == 0 {
            return Err("GPU session asset-byte limit must be greater than zero".to_string());
        }
        if session_asset_bytes > MAX_RESIDENT_ASSET_BYTES {
            return Err(format!(
                "GPU session asset-byte limit must not exceed Catena's {MAX_RESIDENT_ASSET_BYTES}-byte ceiling"
            ));
        }
        if max_generation_capacity == 0 {
            return Err("GPU generation capacity limit must be greater than zero".to_string());
        }
        if max_generation_capacity > MAX_GPU_GENERATION_CAPACITY {
            return Err(format!(
                "GPU generation capacity limit must not exceed {MAX_GPU_GENERATION_CAPACITY} tokens so retained output remains retrievable"
            ));
        }
        if max_generation_device_bytes == 0 {
            return Err(
                "GPU generation device-allocation limit must be greater than zero".to_string(),
            );
        }
        if compile_timeout.is_zero() {
            return Err("GPU compile timeout must be greater than zero".to_string());
        }
        if execution_timeout.is_zero() {
            return Err("GPU execution timeout must be greater than zero".to_string());
        }
        Ok(Self {
            backend: catena_lang::safe_gpu::Backend::Auto,
            session_programs,
            session_asset_bytes,
            max_generation_capacity,
            max_generation_device_bytes,
            compile_timeout,
            execution_timeout,
        })
    }

    #[must_use]
    pub const fn with_backend(mut self, backend: catena_lang::safe_gpu::Backend) -> Self {
        self.backend = backend;
        self
    }

    #[must_use]
    pub const fn session_programs(self) -> usize {
        self.session_programs
    }

    #[must_use]
    pub const fn session_asset_bytes(self) -> u64 {
        self.session_asset_bytes
    }

    #[must_use]
    pub const fn max_generation_capacity(self) -> u64 {
        self.max_generation_capacity
    }

    #[must_use]
    pub const fn max_generation_device_bytes(self) -> u64 {
        self.max_generation_device_bytes
    }

    #[must_use]
    pub const fn compile_timeout(self) -> Duration {
        self.compile_timeout
    }

    #[must_use]
    pub const fn execution_timeout(self) -> Duration {
        self.execution_timeout
    }

    /// Pure provider-envelope validation shared by preflight and the isolated
    /// worker's last check before any compile or GPU operation.
    pub(crate) fn validate_invocation_resources(
        self,
        invocation: &Invocation,
        state_byte_multipliers: &[u64],
        vocabulary_size: u64,
    ) -> Result<(), String> {
        let prompt_tokens = u64::try_from(invocation.input_ids.len())
            .map_err(|_| "causal-LM prompt token count does not fit u64".to_string())?;
        let capacity = prompt_tokens
            .checked_add(u64::from(invocation.max_new_tokens))
            .ok_or_else(|| "causal-LM generation capacity overflowed".to_string())?;
        validate_generation_limits(self, capacity, state_byte_multipliers, vocabulary_size)
    }
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            backend: catena_lang::safe_gpu::Backend::Auto,
            session_programs: DEFAULT_GPU_SESSION_PROGRAMS,
            session_asset_bytes: DEFAULT_GPU_SESSION_ASSET_BYTES,
            max_generation_capacity: DEFAULT_GPU_MAX_GENERATION_CAPACITY,
            max_generation_device_bytes: DEFAULT_GPU_MAX_GENERATION_DEVICE_BYTES,
            compile_timeout: Duration::from_secs(DEFAULT_GPU_COMPILE_TIMEOUT_SECS),
            execution_timeout: Duration::from_secs(DEFAULT_GPU_EXECUTION_TIMEOUT_SECS),
        }
    }
}

pub(crate) struct ExecuteWorker {
    tx: SyncSender<WorkerCommand>,
}

/// One actor-authorized handoff, not a second execution queue.
///
/// `EvaluateEngine` owns the busy/idle state and never sends while a job is
/// active. The single slot only removes a scheduler race between the actor and
/// the worker thread reaching `recv`; execution ordering remains actor-owned.
const WORKER_HANDOFF_CAPACITY: usize = 1;

enum WorkerCommand {
    Execute(Box<ExecuteJob>),
}

pub(crate) enum EnqueueError {
    Busy(Box<ExecuteJob>),
    Stopped(Box<ExecuteJob>),
}

pub(crate) struct ExecuteJob {
    pub output_cache: hellas_rpc::cache::CacheOptions,
    pub cache_recording: Option<hellas_rpc::cache::CacheRecording>,
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub evaluate_request: EvaluateRequest,
    pub source: CausalLmEnvironmentSource,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
    pub accepted_at: Instant,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    pub producer_key: Arc<ProducerSigningKey>,
}

pub(crate) struct WorkerCompletion {
    pub cache_recording: Option<hellas_rpc::cache::CacheRecording>,
    pub execution_id: String,
    pub request_commitment: [u8; 32],
    pub evaluate_request: EvaluateRequest,
    pub invocation: Invocation,
    pub prepared_artifacts: Option<PreparedTextArtifacts>,
    pub sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    pub result: WorkerCompletionResult,
}

pub(crate) enum WorkerCompletionResult {
    Completed {
        stop_reason: StopReason,
        output_tokens: Vec<u32>,
        output_events: Vec<OutputEventEnvelope>,
    },
    Failed {
        position: u64,
        error: String,
    },
}

impl WorkerCompletionResult {
    pub(crate) fn position(&self) -> u64 {
        match self {
            Self::Completed { output_tokens, .. } => output_tokens.len() as u64,
            Self::Failed { position, .. } => *position,
        }
    }
}

impl ExecuteWorker {
    pub(crate) fn spawn(
        completion_tx: tokio_mpsc::Sender<ExecutorCompletion>,
        config: GpuConfig,
    ) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<WorkerCommand>(WORKER_HANDOFF_CAPACITY);
        std::thread::Builder::new()
            .name("hellas-gpu-worker".to_string())
            .spawn(move || worker_loop(rx, completion_tx, config))?;
        Ok(Self { tx })
    }

    #[cfg(test)]
    pub(crate) fn controlled() -> (Self, ControlledExecuteWorker) {
        let (tx, rx) = mpsc::sync_channel::<WorkerCommand>(WORKER_HANDOFF_CAPACITY);
        (Self { tx }, ControlledExecuteWorker { rx })
    }

    pub(crate) fn try_enqueue(&self, job: ExecuteJob) -> Result<(), EnqueueError> {
        match self.tx.try_send(WorkerCommand::Execute(Box::new(job))) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(WorkerCommand::Execute(job))) => Err(EnqueueError::Busy(job)),
            Err(TrySendError::Disconnected(WorkerCommand::Execute(job))) => {
                Err(EnqueueError::Stopped(job))
            }
        }
    }
}

#[cfg(test)]
pub(crate) struct ControlledExecuteWorker {
    rx: Receiver<WorkerCommand>,
}

#[cfg(test)]
impl ControlledExecuteWorker {
    pub(crate) fn try_recv(&self) -> Result<ExecuteJob, std::sync::mpsc::TryRecvError> {
        self.rx.try_recv().map(|command| match command {
            WorkerCommand::Execute(job) => *job,
        })
    }
}

fn worker_loop(
    rx: Receiver<WorkerCommand>,
    completion_tx: tokio_mpsc::Sender<ExecutorCompletion>,
    config: GpuConfig,
) {
    // Starting the executor does not touch a GPU. Catena is created lazily
    // only after an authorized paid job reaches this dedicated thread.
    let mut runtime = ModelRuntime::new(config);
    while let Ok(WorkerCommand::Execute(job)) = rx.recv() {
        let job = *job;
        let execution_id = job.execution_id.clone();
        let request_commitment = job.request_commitment;
        let execution_environment = job.evaluate_request.execution_environment;
        let sender = job.sender.clone();
        let evaluate_request = job.evaluate_request.clone();
        let invocation = job.invocation.clone();
        let prepared_artifacts = job.prepared_artifacts.clone();
        let producer_key = job.producer_key.clone();
        let cache_recording = job.cache_recording.clone();

        let mut position = 0;
        let mut output_builder = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&evaluate_request),
            evaluate_request.assurance,
            &producer_key,
        );
        let mut output_events = Vec::new();
        let on_progress = make_on_progress(
            &mut position,
            sender.clone(),
            execution_id.clone(),
            &mut output_builder,
            &mut output_events,
        );

        let termination = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_job(job, on_progress, &mut runtime)
        })) {
            Ok(Ok((stop_reason, output_tokens))) => WorkerCompletionResult::Completed {
                stop_reason,
                output_tokens,
                output_events,
            },
            Ok(Err(error)) => {
                warn!(%execution_id, %execution_environment, "GPU execution failed");
                WorkerCompletionResult::Failed {
                    position,
                    error: error.to_string(),
                }
            }
            Err(_) => {
                runtime.discard_session();
                warn!(%execution_id, %execution_environment, "GPU worker panicked; session discarded");
                WorkerCompletionResult::Failed {
                    position,
                    error: "GPU worker panicked; sensitive details suppressed".to_string(),
                }
            }
        };

        let _ = completion_tx.blocking_send(ExecutorCompletion::EvaluateFinished(Box::new(
            WorkerCompletion {
                cache_recording,
                execution_id,
                request_commitment,
                evaluate_request,
                invocation,
                prepared_artifacts,
                sender,
                result: termination,
            },
        )));
    }
}

fn run_job(
    job: ExecuteJob,
    mut on_progress: impl FnMut(u32) -> Result<(), crate::ExecutorError>,
    runtime: &mut ModelRuntime,
) -> Result<(StopReason, Vec<u32>), crate::ExecutorError> {
    if let Some(output) = crate::inference_cache::replay(&job, &mut on_progress)? {
        return Ok(output);
    }
    let ExecuteJob {
        execution_id,
        source,
        invocation,
        accepted_at,
        ..
    } = job;

    debug!(
        execution_id = %execution_id,
        execution_environment = %source.manifest_id(),
        queue_wait_ms = accepted_at.elapsed().as_millis(),
        prompt_tokens = invocation.input_ids.len(),
        "GPU worker starting causal-LM execution"
    );

    runtime.validate_generation_resources(&source, &invocation)?;
    let input_ids = Zeroizing::new(invocation.input_ids);
    let result = runtime.model(&source)?.generate_tokens_streaming(
        input_ids.as_slice(),
        invocation.max_new_tokens,
        &invocation.stop_token_ids,
        |token| {
            on_progress(token)?;
            Ok(GenerationControl::Continue)
        },
    );

    let result = match result {
        Ok(result) => result,
        Err(GenerationError::Callback(error)) => {
            return Err(match error.downcast::<crate::ExecutorError>() {
                Ok(error) => error,
                Err(_) => {
                    crate::ExecutorError::Execution("causal-LM output callback failed".to_string())
                }
            });
        }
        Err(GenerationError::Resident(error)) => {
            if error.invalidates_session() {
                warn!(
                    execution_environment = %source.manifest_id(),
                    runtime_error = %error,
                    "Catena GPU session failed and will be recycled"
                );
                runtime.discard_session();
            } else {
                warn!(
                    execution_environment = %source.manifest_id(),
                    runtime_error = %error,
                    "Catena causal-LM generation failed"
                );
            }
            return Err(crate::ExecutorError::Execution(format!(
                "GPU execution failed for environment {}",
                source.manifest_id()
            )));
        }
        Err(error @ GenerationError::ReleaseAfterFailure { .. }) => {
            if error.invalidates_session() {
                warn!(
                    execution_environment = %source.manifest_id(),
                    runtime_error = %error,
                    "Catena generation and GPU-state release failed; session will be recycled"
                );
                runtime.discard_session();
            } else {
                warn!(
                    execution_environment = %source.manifest_id(),
                    runtime_error = %error,
                    "Catena generation and GPU-state release both failed"
                );
            }
            return Err(crate::ExecutorError::Execution(format!(
                "GPU execution failed for environment {}",
                source.manifest_id()
            )));
        }
        Err(GenerationError::InvalidRequest(error)) => {
            warn!(
                execution_environment = %source.manifest_id(),
                runtime_error = %error,
                "validated causal-LM request was rejected by Catena"
            );
            return Err(crate::ExecutorError::Execution(
                "validated causal-LM request was rejected by the GPU runtime".to_string(),
            ));
        }
    };

    let stop_reason = match result.termination {
        GenerationTermination::StopToken(token_id) => StopReason::StopToken(token_id),
        GenerationTermination::MaxNewTokens => StopReason::MaxNewTokens,
        GenerationTermination::Cancelled => {
            return Err(crate::ExecutorError::Execution(
                "causal-LM generation cancelled unexpectedly".to_string(),
            ));
        }
    };
    Ok((stop_reason, result.generated_tokens))
}

struct CachedContent<T> {
    value: T,
    bytes: u64,
}

struct ExactContentCache<T> {
    entries: HashMap<ContentId, CachedContent<T>>,
}

impl<T> Default for ExactContentCache<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<T> ExactContentCache<T> {
    fn get(&self, content: ContentRef) -> Result<Option<&T>, crate::ExecutorError> {
        let Some(cached) = self.entries.get(&content.id()) else {
            return Ok(None);
        };
        if cached.bytes != content.bytes() {
            return Err(crate::ExecutorError::Execution(format!(
                "content {} was declared with conflicting lengths",
                content.id()
            )));
        }
        Ok(Some(&cached.value))
    }

    fn insert(&mut self, content: ContentRef, value: T) {
        self.entries.insert(
            content.id(),
            CachedContent {
                value,
                bytes: content.bytes(),
            },
        );
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

struct ModelRuntime {
    config: GpuConfig,
    session: Option<Session>,
    asset_owner: Option<AssetOwner>,
    models: HashMap<ContentId, Model>,
    model_order: VecDeque<ContentId>,
    programs: ExactContentCache<Program>,
    assets: ExactContentCache<Asset>,
    asset_bytes: u64,
}

impl ModelRuntime {
    fn new(config: GpuConfig) -> Self {
        Self {
            config,
            session: None,
            asset_owner: None,
            models: HashMap::new(),
            model_order: VecDeque::new(),
            programs: ExactContentCache::default(),
            assets: ExactContentCache::default(),
            asset_bytes: 0,
        }
    }

    /// Check every provider-local per-invocation bound before starting a
    /// session, compiling source, attaching an asset, or allocating GPU state.
    fn validate_generation_resources(
        &self,
        source: &CausalLmEnvironmentSource,
        invocation: &Invocation,
    ) -> Result<(), crate::ExecutorError> {
        let environment = source.environment();
        validate_static_input_bytes(
            environment
                .static_inputs()
                .iter()
                .map(|slice| slice.bytes()),
        )
        .and_then(|()| {
            self.config.validate_invocation_resources(
                invocation,
                environment.state_bytes_per_capacity(),
                environment.vocabulary_size(),
            )
        })
        .map_err(|error| {
            crate::ExecutorError::Execution(format!(
                "environment {} exceeds the provider GPU resource envelope: {error}",
                source.manifest_id()
            ))
        })
    }

    fn model(
        &mut self,
        source: &CausalLmEnvironmentSource,
    ) -> Result<&Model, crate::ExecutorError> {
        let manifest_id = source.manifest_id();
        if self.models.contains_key(&manifest_id) {
            self.touch_model(manifest_id);
        } else {
            self.load_model(source)?;
        }
        self.models.get(&manifest_id).ok_or_else(|| {
            crate::ExecutorError::Execution(format!(
                "GPU model {manifest_id} was not retained after loading"
            ))
        })
    }

    fn touch_model(&mut self, manifest_id: ContentId) {
        if let Some(index) = self.model_order.iter().position(|id| *id == manifest_id) {
            self.model_order.remove(index);
        }
        self.model_order.push_back(manifest_id);
    }

    fn retain_model(&mut self, manifest_id: ContentId, model: Model) {
        self.models.insert(manifest_id, model);
        self.touch_model(manifest_id);
        while self.models.len() > MAX_RESIDENT_MODELS {
            let oldest = self
                .model_order
                .pop_front()
                .expect("resident model order tracks every cached model");
            self.models.remove(&oldest);
        }
    }

    fn load_model(
        &mut self,
        source: &CausalLmEnvironmentSource,
    ) -> Result<(), crate::ExecutorError> {
        // Existing models can continue using imported allocations after owner
        // loss. Loading a model requires a live owner for any new imports.
        if self
            .asset_owner
            .as_ref()
            .is_some_and(|owner| !owner.is_available())
        {
            self.discard_asset_owner();
        }
        let environment = source.environment();
        let program_ref = environment.program();
        let program_is_resident = self.programs.get(program_ref)?.is_some();
        let mut environment_asset_bytes = 0_u64;
        let mut missing_asset_count = 0_usize;
        let mut missing_asset_bytes = 0_u64;
        for content in environment.static_objects().iter().copied() {
            environment_asset_bytes = environment_asset_bytes
                .checked_add(content.bytes())
                .ok_or_else(|| {
                    crate::ExecutorError::Execution(
                        "causal-LM static object size overflowed".to_string(),
                    )
                })?;
            if self.assets.get(content)?.is_none() {
                missing_asset_count = missing_asset_count.checked_add(1).ok_or_else(|| {
                    crate::ExecutorError::Execution(
                        "causal-LM missing static object count overflowed".to_string(),
                    )
                })?;
                missing_asset_bytes = missing_asset_bytes
                    .checked_add(content.bytes())
                    .ok_or_else(|| {
                        crate::ExecutorError::Execution(
                            "causal-LM static object size overflowed".to_string(),
                        )
                    })?;
            }
        }
        if environment_asset_bytes > self.config.session_asset_bytes {
            return Err(crate::ExecutorError::Execution(format!(
                "environment {} requires {environment_asset_bytes} static bytes, over this provider's {}-byte GPU session limit",
                source.manifest_id(),
                self.config.session_asset_bytes
            )));
        }
        if session_requires_recycle(
            program_is_resident,
            SessionUsage {
                programs: self.programs.len(),
                assets: self.assets.len(),
                asset_bytes: self.asset_bytes,
            },
            MissingAssets {
                count: missing_asset_count,
                bytes: missing_asset_bytes,
            },
            self.config,
        ) {
            debug!(
                resident_programs = self.programs.len(),
                attached_asset_bytes = self.asset_bytes,
                "recycling bounded Catena GPU session"
            );
            if asset_owner_requires_recycle(
                self.assets.len(),
                self.asset_bytes,
                MissingAssets {
                    count: missing_asset_count,
                    bytes: missing_asset_bytes,
                },
                self.config,
            ) {
                self.discard_asset_owner();
            } else {
                self.discard_session();
            }
        }

        // Recompute cache misses after a possible recycle, then reopen every
        // required descriptor before starting HIP or compiling source. A
        // missing, path-replaced, or length-changed object can therefore fail
        // only this cheap preflight; it cannot waste a newly created GPU
        // session or a completed compilation. The backing-inode immutability
        // requirement is documented at CausalLmEnvironmentSource.
        let program_source = if self.programs.get(program_ref)?.is_some() {
            None
        } else {
            let program_file = source.open_verified_program().map_err(|error| {
                crate::ExecutorError::Execution(format!(
                    "execution environment {} is no longer locally available: {error}",
                    source.manifest_id()
                ))
            })?;
            let program_bytes = read_verified_bytes(program_file).map_err(|error| {
                warn!(
                    execution_environment = %source.manifest_id(),
                    io_error = %error,
                    "failed to read verified Catena program"
                );
                crate::ExecutorError::Execution(format!(
                    "Catena program for environment {} could not be read at its verified exact length",
                    source.manifest_id()
                ))
            })?;
            Some(String::from_utf8(program_bytes).map_err(|error| {
                warn!(
                    execution_environment = %source.manifest_id(),
                    utf8_error = %error,
                    "verified Catena program is not UTF-8"
                );
                crate::ExecutorError::Execution(format!(
                    "Catena program for environment {} is not valid UTF-8 source",
                    source.manifest_id()
                ))
            })?)
        };
        let mut preopened_assets = Vec::with_capacity(environment.static_objects().len());
        for (index, content) in environment.static_objects().iter().copied().enumerate() {
            let file = if self.assets.get(content)?.is_some() {
                None
            } else {
                Some(source.open_verified_static_object(index).map_err(|error| {
                    crate::ExecutorError::Execution(format!(
                        "execution environment {} is no longer locally available: {error}",
                        source.manifest_id()
                    ))
                })?)
            };
            preopened_assets.push(file);
        }

        if self.session.is_none() {
            let timeouts = SessionTimeouts::default()
                .with_compile_timeout(self.config.compile_timeout)
                .with_execution_timeout(self.config.execution_timeout);
            if self.asset_owner.is_none() {
                self.asset_owner = Some(AssetOwner::with_backend(self.config.backend, timeouts).map_err(
                    |error| {
                        warn!(backend = %self.config.backend, runtime_error = %error, "failed to start Catena GPU asset owner");
                        crate::ExecutorError::Execution("GPU runtime is unavailable".to_string())
                    },
                )?);
            }
            self.session = Some(Session::with_assets(
                self.asset_owner.as_ref().expect("asset owner was initialized above"),
                timeouts,
            ).map_err(
                |error| {
                    warn!(backend = %self.config.backend, runtime_error = %error, "failed to start Catena GPU session");
                    crate::ExecutorError::Execution("GPU runtime is unavailable".to_string())
                },
            )?);
        }

        let reused_program = program_source.is_none();
        let program = if let Some(program) = self.programs.get(program_ref)? {
            program.clone()
        } else {
            let prepared = self
                .session
                .as_mut()
                .expect("session was initialized above")
                .prepare(
                    program_source
                        .as_deref()
                        .expect("preflight read every nonresident program"),
                );
            let program = match prepared {
                Ok(program) => program,
                Err(error) => {
                    warn!(
                        execution_environment = %source.manifest_id(),
                        compile_error = %error,
                        "Catena program compilation failed"
                    );
                    if error.invalidates_session() {
                        self.discard_session();
                    }
                    return Err(crate::ExecutorError::Execution(format!(
                        "Catena program for environment {} did not compile",
                        source.manifest_id()
                    )));
                }
            };
            self.programs.insert(program_ref, program.clone());
            program
        };

        let mut ordered_assets = Vec::with_capacity(environment.static_objects().len());
        let mut newly_attached_bytes = 0_u64;
        for (index, content) in environment.static_objects().iter().copied().enumerate() {
            let asset = if let Some(asset) = self.assets.get(content)? {
                asset.clone()
            } else {
                let file = preopened_assets[index]
                    .take()
                    .expect("preflight opened every nonresident static object");
                let attached = self
                    .asset_owner
                    .as_ref()
                    .expect("asset owner was initialized above")
                    .attach(*content.id().as_bytes(), file.into_file());
                let asset = match attached {
                    Ok(asset) => asset,
                    Err(error) => {
                        warn!(
                            execution_environment = %source.manifest_id(),
                            content = %content.id(),
                            runtime_error = %error,
                            "Catena asset attachment failed"
                        );
                        if error.invalidates_session() {
                            self.discard_asset_owner();
                        }
                        return Err(crate::ExecutorError::Execution(format!(
                            "static content {} could not be attached to the GPU runtime",
                            content.id()
                        )));
                    }
                };
                self.asset_bytes =
                    self.asset_bytes
                        .checked_add(content.bytes())
                        .ok_or_else(|| {
                            crate::ExecutorError::Execution(
                                "GPU session static byte count overflowed".to_string(),
                            )
                        })?;
                newly_attached_bytes = newly_attached_bytes
                    .checked_add(content.bytes())
                    .expect("validated environment static-byte total fits u64");
                self.assets.insert(content, asset.clone());
                asset
            };
            ordered_assets.push(asset);
        }

        let session = self
            .session
            .as_ref()
            .expect("session was initialized above");
        let slices = environment
            .static_inputs()
            .iter()
            .map(|slice| {
                let asset = ordered_assets
                    .get(slice.object() as usize)
                    .expect("environment validation checked every static-object index");
                session
                    .slice(asset, slice.offset(), slice.bytes())
                    .map_err(|error| {
                        warn!(
                            execution_environment = %source.manifest_id(),
                            runtime_error = %error,
                            "Catena asset slicing failed after environment validation"
                        );
                        crate::ExecutorError::Execution(format!(
                            "static inputs for environment {} were rejected by the GPU runtime",
                            source.manifest_id()
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let binding = session.bind_causal_lm(
            &program,
            ModelConfig {
                entry_point: environment.entrypoint(),
                asset_slices: &slices,
                state_byte_multipliers: environment.state_bytes_per_capacity(),
                vocabulary_size: environment.vocabulary_size(),
                maximum_capacity: environment.maximum_capacity(),
                generation_device_allocation_budget_bytes: self.config.max_generation_device_bytes,
            },
        );
        let model = match binding {
            Ok(model) => model,
            Err(error) => {
                warn!(
                    execution_environment = %source.manifest_id(),
                    bind_error = %error,
                    "Catena causal-LM binding failed"
                );
                if self
                    .asset_owner
                    .as_ref()
                    .is_some_and(|owner| !owner.is_available())
                {
                    self.discard_asset_owner();
                } else if error.invalidates_session() {
                    self.discard_session();
                }
                return Err(crate::ExecutorError::Execution(format!(
                    "environment {} does not implement the causal-LM ABI",
                    source.manifest_id()
                )));
            }
        };
        self.retain_model(source.manifest_id(), model);
        info!(
            execution_environment = %source.manifest_id(),
            program = %program_ref.id(),
            reused_program,
            static_objects = environment.static_objects().len(),
            newly_attached_bytes,
            session_asset_bytes = self.asset_bytes,
            resident_programs = self.programs.len(),
            "bound resident Catena causal-LM environment"
        );
        Ok(())
    }

    fn discard_session(&mut self) {
        self.models.clear();
        self.model_order.clear();
        self.programs.clear();
        self.session = None;
    }

    fn discard_asset_owner(&mut self) {
        // Drop model handles and their execution worker before the owner whose
        // allocations those workers import.
        self.discard_session();
        self.assets.clear();
        self.asset_owner = None;
        self.asset_bytes = 0;
    }
}

#[derive(Clone, Copy, Debug)]
struct SessionUsage {
    programs: usize,
    assets: usize,
    asset_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct MissingAssets {
    count: usize,
    bytes: u64,
}

fn session_requires_recycle(
    program_is_resident: bool,
    resident: SessionUsage,
    missing: MissingAssets,
    config: GpuConfig,
) -> bool {
    (!program_is_resident && resident.programs >= config.session_programs)
        || asset_owner_requires_recycle(resident.assets, resident.asset_bytes, missing, config)
}

fn asset_owner_requires_recycle(
    assets: usize,
    asset_bytes: u64,
    missing: MissingAssets,
    config: GpuConfig,
) -> bool {
    assets
        .checked_add(missing.count)
        .is_none_or(|total| total > MAX_RESIDENT_ASSETS)
        || asset_bytes
            .checked_add(missing.bytes)
            .is_none_or(|total| total > config.session_asset_bytes)
}

fn validate_generation_limits(
    config: GpuConfig,
    capacity: u64,
    state_byte_multipliers: &[u64],
    vocabulary_size: u64,
) -> Result<(), String> {
    if capacity > config.max_generation_capacity {
        return Err(format!(
            "generation capacity {capacity} is over the {}-token limit",
            config.max_generation_capacity
        ));
    }
    // Catena owns the causal-LM ABI and therefore owns this arithmetic. Keep
    // quote-time admission on the same floor its safe runtime enforces before
    // allocating resident state, token staging, logits, or next-token output.
    let minimum_device_bytes =
        minimum_generation_device_bytes(state_byte_multipliers, capacity, vocabulary_size)
            .map_err(|error| error.to_string())?;
    if minimum_device_bytes > config.max_generation_device_bytes {
        return Err(format!(
            "{minimum_device_bytes} minimum generation device bytes are over the {}-byte limit",
            config.max_generation_device_bytes
        ));
    }
    Ok(())
}

fn validate_static_input_bytes(byte_lengths: impl IntoIterator<Item = u64>) -> Result<(), String> {
    let total = byte_lengths.into_iter().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(bytes)
            .ok_or_else(|| "aggregate model static-input byte count overflowed".to_string())
    })?;
    if total > MAX_MODEL_STATIC_BYTES {
        return Err(format!(
            "{total} logical static-input bytes are over Catena's {MAX_MODEL_STATIC_BYTES}-byte model limit"
        ));
    }
    Ok(())
}

fn make_on_progress<'a, 'b>(
    position: &'a mut u64,
    sender: tokio_mpsc::Sender<Result<PbWorkEvent, WireStatus>>,
    execution_id: String,
    output_builder: &'a mut EvaluateOutputTranscriptBuilder<'b>,
    output_events: &'a mut Vec<OutputEventEnvelope>,
) -> impl FnMut(u32) -> Result<(), crate::ExecutorError> + Send + 'a {
    move |token_id: u32| {
        // Leave one permit for the actor's terminal frame.
        if sender.capacity() <= 1 {
            warn!(%execution_id, "consumer stalled; failing execution before its channel can block the executor");
            return Err(crate::ExecutorError::Execution(
                "execution consumer did not drain its bounded event channel".to_string(),
            ));
        }
        let output_event = output_builder
            .push_token_delta(vec![token_id])
            .map_err(|error| crate::ExecutorError::Execution(error.to_string()))?;
        let event = PbWorkEvent {
            kind: Some(PbEvent::Chunk(PbChunk {
                output_event: Some(output_event_to_pb(&output_event)),
            })),
        };
        match sender.try_send(Ok(event)) {
            Ok(()) => {}
            Err(tokio_mpsc::error::TrySendError::Full(_)) => {
                warn!(%execution_id, "consumer stalled; failing execution before its channel can block the executor");
                return Err(crate::ExecutorError::Execution(
                    "execution consumer did not drain its bounded event channel".to_string(),
                ));
            }
            Err(tokio_mpsc::error::TrySendError::Closed(_)) => {
                debug!(%execution_id, "consumer dropped; failing execution");
                return Err(crate::ExecutorError::ChannelClosed);
            }
        }
        *position += 1;
        output_events.push(output_event);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
