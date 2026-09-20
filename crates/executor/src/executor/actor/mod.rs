pub(super) mod execution;
mod quote;

use crate::ExecutorError;
#[cfg(feature = "evaluate")]
use crate::artifact_store::ArtifactStoreConfig;
#[cfg(feature = "evaluate")]
use crate::artifacts::EvaluateArtifactStore;
#[cfg(feature = "evaluate")]
use crate::evaluate::{EvaluateEngine, EvaluateEngineConfig};
use crate::fetch::{
    FetchCallerPolicy, FetchStateMachine, FetchTranscriptStore, FetchTranscriptStoreBackend,
};
use crate::fetch_policy::{FetchAccessPolicy, FetchQuotaReservation};
use crate::fetch_registry::FetchRouteRegistry;
use crate::metrics::ExecutorMetrics;
use crate::state::ExecutorState;
use hellas_rpc::pb::courtesy::GetStatsResponse;
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::{Assurance, InputCommitment, ProducerSigningKey};
#[cfg(feature = "evaluate")]
use hellas_store::ContentStore;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};

use super::{
    ExecutorCompletion, ExecutorHandle, ExecutorOwedRequest, ExecutorRequest, PendingFetch,
    ProviderContext,
};

/// A small, fixed pressure boundary in front of the actor. Execution and
/// Fetch queues have their own semantic capacities; this mailbox only bounds
/// the number of RPC dispatches waiting to ask the actor a question.
const EXECUTOR_REQUEST_MAILBOX_CAPACITY: usize = 64;
/// Durable paid decisions wait for this bounded ingress instead of competing
/// with peer RPCs. Once admitted they move to the actor-owned owed FIFO.
const EXECUTOR_OWED_MAILBOX_CAPACITY: usize = 64;

/// Every unresolved pre-dispatch cancellation retains one small reservation
/// handle. Admission reserves capacity before creating another such liability,
/// so store failures cannot turn this retry queue into attacker-driven memory.
const MAX_DEFERRED_FETCH_QUOTA_CANCELLATIONS: usize = 4_096;
const FETCH_QUOTA_CANCELLATION_RETRIES_PER_TURN: usize = 16;
const FETCH_QUOTA_SETTLEMENT_RETRIES_PER_TURN: usize = 16;

#[cfg(feature = "evaluate")]
const EVALUATE_COMPLETION_PRODUCERS: usize = 1;
#[cfg(not(feature = "evaluate"))]
const EVALUATE_COMPLETION_PRODUCERS: usize = 0;

enum ExecutorInbox {
    Completion(ExecutorCompletion),
    Owed(ExecutorOwedRequest),
    Request(ExecutorRequest),
}

#[derive(Clone, Copy)]
enum TrustedPreference {
    Owed,
    Completion,
}

struct InboxArbiter {
    preference: TrustedPreference,
    request_open: bool,
    owed_open: bool,
}

impl Default for InboxArbiter {
    fn default() -> Self {
        Self {
            preference: TrustedPreference::Owed,
            request_open: true,
            owed_open: true,
        }
    }
}

impl InboxArbiter {
    fn record(&mut self, inbox: &ExecutorInbox) {
        self.preference = match inbox {
            ExecutorInbox::Owed(_) => TrustedPreference::Completion,
            ExecutorInbox::Completion(_) => TrustedPreference::Owed,
            ExecutorInbox::Request(_) => self.preference,
        };
    }

    fn record_drained_owed(&mut self) {
        self.preference = TrustedPreference::Completion;
    }
}

struct DeferredFetchQuotaCancellation {
    reservation: FetchQuotaReservation,
    /// Present only when Fetch state reached Running before durable quota
    /// activation failed. The marker and in-memory ticket must be removed
    /// before the reservation can be cancelled.
    abort_running: Option<InputCommitment>,
    /// Activation may have reached durable storage before returning an error.
    /// Only this pre-provider authority may remove either active lifecycle.
    allow_dispatched: bool,
}

struct DeferredFetchQuotaSettlement {
    reservation: FetchQuotaReservation,
    billable_units: u64,
}

pub struct Executor {
    request_rx: mpsc::Receiver<ExecutorRequest>,
    owed_rx: mpsc::Receiver<ExecutorOwedRequest>,
    completion_rx: mpsc::Receiver<ExecutorCompletion>,
    pub(super) completion_tx: mpsc::Sender<ExecutorCompletion>,
    pub(super) store: ExecutorState,
    #[cfg(feature = "evaluate")]
    pub(super) evaluate: EvaluateEngine,
    pub(super) metrics: Arc<ExecutorMetrics>,
    pub(super) provider: ProviderContext,
    pub(super) fetch_state: FetchStateMachine<FetchTranscriptStoreBackend>,
    pub(super) fetch_access_policy: FetchAccessPolicy,
    pub(super) fetch_routes: FetchRouteRegistry,
    pub(super) fetch_cache: Option<Arc<execution::cache::FetchCache>>,
    pub(super) pending_fetches: VecDeque<PendingFetch>,
    pending_fetch_quota_cancellations: VecDeque<DeferredFetchQuotaCancellation>,
    pending_fetch_quota_settlements: VecDeque<DeferredFetchQuotaSettlement>,
    pub(super) fetch_max_in_flight: usize,
    pub(super) fetch_queue_capacity: usize,
    pub(super) active_fetches: usize,
    pub(super) fetch_replay_slots: Arc<Semaphore>,
}

pub struct ExecutorSpawnConfig {
    pub output_cache: hellas_rpc::cache::CacheOptions,
    pub execute_policy: ExecutePolicy,
    pub queue_capacity: usize,
    pub metrics: Arc<ExecutorMetrics>,
    pub producer_key: Arc<ProducerSigningKey>,
    pub provider_genesis: Arc<Vec<u8>>,
    pub assurance: Assurance,
    pub fetch_access_policy: FetchAccessPolicy,
    pub fetch_routes: FetchRouteRegistry,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub fetch_replay_max_in_flight: usize,
    pub fetch_store: FetchTranscriptStoreBackend,
    #[cfg(feature = "evaluate")]
    pub artifact_store: ArtifactStoreConfig,
    #[cfg(feature = "evaluate")]
    pub content_store: ContentStore,
    #[cfg(feature = "evaluate")]
    pub gpu_config: crate::GpuConfig,
}

struct ExecutorRuntimeConfig {
    output_cache: hellas_rpc::cache::CacheOptions,
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    execute_policy: ExecutePolicy,
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    queue_capacity: usize,
    metrics: Arc<ExecutorMetrics>,
    provider: ProviderContext,
    fetch_access_policy: FetchAccessPolicy,
    fetch_routes: FetchRouteRegistry,
    fetch_max_in_flight: usize,
    fetch_queue_capacity: usize,
    fetch_replay_max_in_flight: usize,
    #[cfg(feature = "evaluate")]
    artifacts: EvaluateArtifactStore,
    #[cfg(feature = "evaluate")]
    content_store: ContentStore,
    #[cfg(feature = "evaluate")]
    gpu_config: crate::GpuConfig,
    fetch_store: FetchTranscriptStoreBackend,
}

impl Executor {
    pub fn spawn_with_producer_key(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            output_cache: Default::default(),
            execute_policy,
            queue_capacity,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: producer_key.clone(),
                genesis: Arc::new(provider_genesis),
                assurance,
            },
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes: FetchRouteRegistry::default(),
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            #[cfg(feature = "evaluate")]
            artifacts: EvaluateArtifactStore::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: crate::GpuConfig::default(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
        })
    }

    pub fn spawn_with_fetch_routes(
        execute_policy: ExecutePolicy,
        queue_capacity: usize,
        producer_key: ProducerSigningKey,
        provider_genesis: Vec<u8>,
        assurance: Assurance,
        fetch_routes: FetchRouteRegistry,
    ) -> Result<ExecutorHandle, ExecutorError> {
        let producer_key = Arc::new(producer_key);
        Self::spawn_runtime(ExecutorRuntimeConfig {
            output_cache: Default::default(),
            execute_policy,
            queue_capacity,
            metrics: Arc::new(ExecutorMetrics::default()),
            provider: ProviderContext {
                producer_key: producer_key.clone(),
                genesis: Arc::new(provider_genesis),
                assurance,
            },
            fetch_access_policy: FetchAccessPolicy::trusted_callers([producer_key.public_key()]),
            fetch_routes,
            fetch_max_in_flight: hellas_rpc::DEFAULT_FETCH_MAX_IN_FLIGHT,
            fetch_queue_capacity: hellas_rpc::DEFAULT_FETCH_QUEUE_CAPACITY,
            fetch_replay_max_in_flight: hellas_rpc::DEFAULT_FETCH_REPLAY_MAX_IN_FLIGHT,
            #[cfg(feature = "evaluate")]
            artifacts: EvaluateArtifactStore::memory(),
            #[cfg(feature = "evaluate")]
            content_store: ContentStore::new(),
            #[cfg(feature = "evaluate")]
            gpu_config: crate::GpuConfig::default(),
            fetch_store: FetchTranscriptStoreBackend::memory(),
        })
    }

    pub async fn spawn_configured(
        config: ExecutorSpawnConfig,
    ) -> Result<ExecutorHandle, ExecutorError> {
        #[cfg(feature = "evaluate")]
        let artifacts = EvaluateArtifactStore::open(config.artifact_store).await?;
        Self::spawn_runtime(ExecutorRuntimeConfig {
            output_cache: config.output_cache,
            execute_policy: config.execute_policy,
            queue_capacity: config.queue_capacity,
            metrics: config.metrics,
            provider: ProviderContext {
                producer_key: config.producer_key,
                genesis: config.provider_genesis,
                assurance: config.assurance,
            },
            fetch_access_policy: config.fetch_access_policy,
            fetch_routes: config.fetch_routes,
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            fetch_replay_max_in_flight: config.fetch_replay_max_in_flight,
            #[cfg(feature = "evaluate")]
            artifacts,
            #[cfg(feature = "evaluate")]
            content_store: config.content_store,
            #[cfg(feature = "evaluate")]
            gpu_config: config.gpu_config,
            fetch_store: config.fetch_store,
        })
    }

    fn spawn_runtime(mut config: ExecutorRuntimeConfig) -> Result<ExecutorHandle, ExecutorError> {
        if config.fetch_max_in_flight == 0 {
            return Err(ExecutorError::ResourceExhausted(
                "fetch concurrency capacity must be greater than zero".to_string(),
            ));
        }
        if config.fetch_replay_max_in_flight == 0 {
            return Err(ExecutorError::ResourceExhausted(
                "fetch replay capacity must be greater than zero".to_string(),
            ));
        }
        if config.fetch_replay_max_in_flight > Semaphore::MAX_PERMITS {
            return Err(ExecutorError::ResourceExhausted(format!(
                "fetch replay capacity {} exceeds the runtime limit",
                config.fetch_replay_max_in_flight
            )));
        }
        let completion_capacity = config
            .fetch_max_in_flight
            .checked_add(EVALUATE_COMPLETION_PRODUCERS)
            .ok_or_else(|| {
                ExecutorError::ResourceExhausted(
                    "executor completion mailbox capacity overflow".to_string(),
                )
            })?;
        if completion_capacity > Semaphore::MAX_PERMITS {
            return Err(ExecutorError::ResourceExhausted(format!(
                "executor completion mailbox capacity {completion_capacity} exceeds the runtime limit"
            )));
        }
        let (request_tx, request_rx) = mpsc::channel(EXECUTOR_REQUEST_MAILBOX_CAPACITY);
        let (owed_tx, owed_rx) = mpsc::channel(EXECUTOR_OWED_MAILBOX_CAPACITY);
        // Each active Fetch task and the single GPU worker can own at most one
        // unsent completion. Therefore every producer can retire even while
        // the actor is busy handling one request.
        let (completion_tx, completion_rx) = mpsc::channel(completion_capacity);
        // Make the fetch store root durable before any ticket can run, so
        // running markers always link into an already-durable directory.
        config.fetch_store.init().map_err(|err| {
            ExecutorError::ArtifactStore(format!("fetch transcript store init failed: {err}"))
        })?;
        config.fetch_access_policy.init_store().map_err(|err| {
            ExecutorError::ArtifactStore(format!("fetch quota store init failed: {err}"))
        })?;
        // This is the one recovery boundary for the documented single-owner
        // quota root. Only a new actor, before it can admit work, proves the
        // previous in-memory queue is gone: Pending/Cancelling can be reclaimed,
        // while Dispatched and legacy ambiguity become a full fresh-window
        // charge. Marker removal precedes each ledger replacement so a failed
        // recovery remains retryable on the next startup.
        let fetch_store = &config.fetch_store;
        let recovered_reservations = config
            .fetch_access_policy
            .recover_reservations(execution::now_ms(), |input| {
                fetch_store
                    .remove_running(input)
                    .map_err(|error| error.to_string())
            })
            .map_err(|error| {
                ExecutorError::ArtifactStore(format!(
                    "fetch quota startup recovery failed: {error}"
                ))
            })?;
        if recovered_reservations != 0 {
            tracing::info!(
                recovered_reservations,
                "recovered Fetch quota reservations at startup"
            );
        }
        let fetch_caller_policy = FetchCallerPolicy::new(config.fetch_access_policy.caller_keys());
        #[cfg(feature = "evaluate")]
        let evaluate = EvaluateEngine::new(EvaluateEngineConfig {
            output_cache: config.output_cache.clone(),
            artifacts: config.artifacts,
            content_store: config.content_store,
            gpu_config: config.gpu_config,
            queue_capacity: config.queue_capacity,
            execute_policy: config.execute_policy,
            metrics: config.metrics.clone(),
            provider: config.provider.clone(),
            completion_tx: completion_tx.clone(),
        })?;
        let executor = Self {
            request_rx,
            owed_rx,
            completion_rx,
            completion_tx,
            store: ExecutorState::new(),
            #[cfg(feature = "evaluate")]
            evaluate,
            metrics: config.metrics,
            provider: config.provider,
            fetch_state: FetchStateMachine::new(config.fetch_store, fetch_caller_policy),
            fetch_access_policy: config.fetch_access_policy,
            fetch_routes: config.fetch_routes,
            pending_fetches: VecDeque::new(),
            fetch_cache: execution::cache::FetchCache::open(config.output_cache)?,
            pending_fetch_quota_cancellations: VecDeque::new(),
            pending_fetch_quota_settlements: VecDeque::new(),
            fetch_max_in_flight: config.fetch_max_in_flight,
            fetch_queue_capacity: config.fetch_queue_capacity,
            active_fetches: 0,
            fetch_replay_slots: Arc::new(Semaphore::new(config.fetch_replay_max_in_flight)),
        };
        tokio::spawn(executor.run());
        Ok(ExecutorHandle {
            tx: request_tx,
            owed_tx,
        })
    }

    async fn run(mut self) {
        let mut arbiter = InboxArbiter::default();
        while let Some(message) = recv_next(
            &mut self.request_rx,
            &mut self.owed_rx,
            &mut self.completion_rx,
            &mut arbiter,
        )
        .await
        {
            match message {
                ExecutorInbox::Completion(completion) => {
                    let evaluate_finished = self.handle_completion(completion).await;
                    if evaluate_finished {
                        if self.admit_ready_owed().await != 0 {
                            arbiter.record_drained_owed();
                        }
                        self.dispatch_available_evaluate();
                    }
                }
                ExecutorInbox::Owed(request) => {
                    self.handle_owed_request(request).await;
                    self.dispatch_available_evaluate();
                }
                ExecutorInbox::Request(request) => self.handle_request(request).await,
            }
        }
    }

    async fn handle_completion(&mut self, completion: ExecutorCompletion) -> bool {
        match completion {
            #[cfg(feature = "evaluate")]
            ExecutorCompletion::EvaluateFinished(completion) => {
                self.evaluate.on_completion(*completion).await;
                true
            }
            ExecutorCompletion::FetchFinished(completion) => {
                self.handle_fetch_finished(*completion);
                false
            }
        }
    }

    async fn admit_ready_owed(&mut self) -> usize {
        // Snapshot the bounded ready population. Senders awakened as these
        // entries are removed get their own fair actor turn; they cannot let a
        // continuously replenished lane hold completion handling forever.
        let ready = self.owed_rx.len();
        let mut admitted = 0;
        for _ in 0..ready {
            let Ok(request) = self.owed_rx.try_recv() else {
                break;
            };
            self.handle_owed_request(request).await;
            admitted += 1;
        }
        admitted
    }

    fn dispatch_available_evaluate(&mut self) {
        #[cfg(feature = "evaluate")]
        self.evaluate
            .dispatch_next_execution(self.owed_rx.is_empty());
    }

    async fn handle_owed_request(&mut self, request: ExecutorOwedRequest) {
        match request {
            ExecutorOwedRequest::RunPaidEvaluate { input, reply, span } => {
                #[cfg(feature = "evaluate")]
                let result = tracing::Instrument::instrument(
                    self.evaluate.start_prepared_input(*input),
                    span.clone(),
                )
                .await;
                #[cfg(not(feature = "evaluate"))]
                let result = {
                    let _ = (input, span);
                    Err(evaluate_disabled())
                };
                let _ = reply.send(result);
            }
            #[cfg(all(test, feature = "evaluate"))]
            ExecutorOwedRequest::StartEvaluateForTest {
                job,
                execution_id,
                request_commitment,
                reply,
            } => {
                let result =
                    self.evaluate
                        .start_owed_for_test(*job, execution_id, request_commitment);
                let _ = reply.send(result);
            }
        }
    }

    async fn handle_request(&mut self, request: ExecutorRequest) {
        match request {
            ExecutorRequest::QuoteEvaluate { request, reply } => {
                #[cfg(feature = "evaluate")]
                let result = self.evaluate.quote_evaluate(&mut self.store, request).await;
                #[cfg(not(feature = "evaluate"))]
                let result = {
                    let _ = request;
                    Err(evaluate_disabled())
                };
                let _ = reply.send(result);
            }
            ExecutorRequest::QuoteFetch { request, reply } => {
                let _ = reply.send(self.handle_quote_fetch(request).await);
            }
            ExecutorRequest::QuoteTokens { request, reply } => {
                #[cfg(feature = "evaluate")]
                let result = self.evaluate.quote_tokens(&mut self.store, request).await;
                #[cfg(not(feature = "evaluate"))]
                let result = {
                    let _ = request;
                    Err(evaluate_disabled())
                };
                let _ = reply.send(result);
            }
            ExecutorRequest::GetArtifact { request, reply } => {
                #[cfg(feature = "evaluate")]
                let result = self.evaluate.get_artifact(request).await;
                #[cfg(not(feature = "evaluate"))]
                let result = {
                    let _ = request;
                    Err(evaluate_disabled())
                };
                let _ = reply.send(result);
            }
            ExecutorRequest::Execute {
                span,
                request,
                reply,
            } => {
                let result =
                    tracing::Instrument::instrument(self.handle_execute(request), span).await;
                let _ = reply.send(result);
            }
            ExecutorRequest::GetStats { reply } => {
                let _ = reply.send(Ok(GetStatsResponse {
                    stats: Some(self.metrics.global_snapshot()),
                }));
            }
            #[cfg(all(test, feature = "evaluate"))]
            ExecutorRequest::StartEvaluateForTest {
                job,
                execution_id,
                request_commitment,
                reply,
            } => {
                let result = self.evaluate.start(*job, execution_id, request_commitment);
                let _ = reply.send(result);
            }
            #[cfg(all(test, feature = "evaluate"))]
            ExecutorRequest::BarrierForTest { entered, release } => {
                let _ = entered.send(());
                let _ = release.await;
            }
        }
    }
}

/// Alternate the two trusted lanes when both remain ready, and admit either
/// before peer-driven traffic. This keeps completion retirement live without
/// allowing completions to hide an already-durable paid invocation behind a
/// queued best-effort execution.
async fn recv_next(
    request_rx: &mut mpsc::Receiver<ExecutorRequest>,
    owed_rx: &mut mpsc::Receiver<ExecutorOwedRequest>,
    completion_rx: &mut mpsc::Receiver<ExecutorCompletion>,
    arbiter: &mut InboxArbiter,
) -> Option<ExecutorInbox> {
    loop {
        if !arbiter.request_open && !arbiter.owed_open {
            return completion_rx.try_recv().ok().map(ExecutorInbox::Completion);
        }

        let next = match arbiter.preference {
            TrustedPreference::Owed => {
                tokio::select! {
                    biased;
                    owed = owed_rx.recv(), if arbiter.owed_open => {
                        match owed {
                            Some(request) => Some(ExecutorInbox::Owed(request)),
                            None => {
                                arbiter.owed_open = false;
                                None
                            }
                        }
                    }
                    Some(completion) = completion_rx.recv() => {
                        Some(ExecutorInbox::Completion(completion))
                    }
                    request = request_rx.recv(), if arbiter.request_open => {
                        match request {
                            Some(request) => Some(ExecutorInbox::Request(request)),
                            None => {
                                arbiter.request_open = false;
                                None
                            }
                        }
                    }
                }
            }
            TrustedPreference::Completion => {
                tokio::select! {
                    biased;
                    Some(completion) = completion_rx.recv() => {
                        Some(ExecutorInbox::Completion(completion))
                    }
                    owed = owed_rx.recv(), if arbiter.owed_open => {
                        match owed {
                            Some(request) => Some(ExecutorInbox::Owed(request)),
                            None => {
                                arbiter.owed_open = false;
                                None
                            }
                        }
                    }
                    request = request_rx.recv(), if arbiter.request_open => {
                        match request {
                            Some(request) => Some(ExecutorInbox::Request(request)),
                            None => {
                                arbiter.request_open = false;
                                None
                            }
                        }
                    }
                }
            }
        };
        let Some(next) = next else {
            continue;
        };
        arbiter.record(&next);
        return Some(next);
    }
}

#[cfg(not(feature = "evaluate"))]
fn evaluate_disabled() -> ExecutorError {
    ExecutorError::PolicyDenied("evaluate scheme is not enabled on this node".to_string())
}

#[cfg(test)]
mod mailbox_tests {
    #[cfg(feature = "evaluate")]
    use std::sync::Arc;
    #[cfg(feature = "evaluate")]
    use std::time::Duration;

    use hellas_rpc::{Digest, InputCommitment};
    use tokio::sync::{mpsc, oneshot};
    #[cfg(feature = "evaluate")]
    use tokio::time::timeout;

    use super::*;
    #[cfg(feature = "evaluate")]
    use crate::evaluate::environment_admission_tests::EnvironmentFixture;
    #[cfg(feature = "evaluate")]
    use crate::evaluate::{EvaluateEngineConfig, EvaluateJob};
    use crate::executor::{FetchCompletion, FetchProviderFailure};
    use crate::fetch_provider::FetchProviderError;
    #[cfg(feature = "evaluate")]
    use crate::state::Invocation;
    #[cfg(feature = "evaluate")]
    use crate::worker::{
        ControlledExecuteWorker, ExecuteJob, ExecuteWorker, GpuConfig, WorkerCompletion,
        WorkerCompletionResult,
    };
    #[cfg(feature = "evaluate")]
    use hellas_rpc::{Assurance, EvaluateRequest, ProducerSigningKey};

    fn request() -> ExecutorRequest {
        let (reply, _receiver) = oneshot::channel();
        ExecutorRequest::GetStats { reply }
    }

    fn completion(byte: u8) -> ExecutorCompletion {
        let (sender, _receiver) = mpsc::channel(1);
        ExecutorCompletion::FetchFinished(Box::new(FetchCompletion {
            input_commitment: InputCommitment::from_digest(Digest::from_bytes([byte; 32])),
            request_commitment_id: [byte; 32],
            quota_reservation: None,
            execution_id: format!("test-{byte}"),
            metric_name: "test".to_string(),
            sender,
            result: Err(FetchProviderFailure {
                position: 0,
                error: FetchProviderError::failed("test completion"),
            }),
        }))
    }

    #[cfg(feature = "evaluate")]
    struct SchedulingHarness {
        handle: ExecutorHandle,
        completion_tx: mpsc::Sender<ExecutorCompletion>,
        worker: ControlledExecuteWorker,
        fixture: EnvironmentFixture,
    }

    #[cfg(feature = "evaluate")]
    fn scheduling_harness() -> SchedulingHarness {
        let fixture = EnvironmentFixture::new();
        let (worker, controlled) = ExecuteWorker::controlled();
        let (request_tx, request_rx) = mpsc::channel(8);
        let (owed_tx, owed_rx) = mpsc::channel(8);
        let (completion_tx, completion_rx) = mpsc::channel(4);
        let producer_key = Arc::new(
            ProducerSigningKey::from_secret_bytes([0x71; 32]).expect("valid scheduling key"),
        );
        let provider = ProviderContext {
            producer_key: Arc::clone(&producer_key),
            genesis: Arc::new(b"scheduling-genesis".to_vec()),
            assurance: Assurance::ProducerSigned,
        };
        let metrics = Arc::new(ExecutorMetrics::default());
        let evaluate = EvaluateEngine::new_with_worker(
            EvaluateEngineConfig {
                output_cache: Default::default(),
                artifacts: EvaluateArtifactStore::memory(),
                content_store: fixture.store.clone(),
                gpu_config: GpuConfig::default(),
                queue_capacity: 4,
                execute_policy: ExecutePolicy::Any,
                metrics: Arc::clone(&metrics),
                provider: provider.clone(),
                completion_tx: completion_tx.clone(),
            },
            worker,
        );
        let caller = producer_key.public_key();
        let executor = Executor {
            fetch_cache: None,
            request_rx,
            owed_rx,
            completion_rx,
            completion_tx: completion_tx.clone(),
            store: ExecutorState::new(),
            evaluate,
            metrics,
            provider,
            fetch_state: FetchStateMachine::new(
                FetchTranscriptStoreBackend::memory(),
                FetchCallerPolicy::new([caller]),
            ),
            fetch_access_policy: FetchAccessPolicy::trusted_callers([caller]),
            fetch_routes: FetchRouteRegistry::default(),
            pending_fetches: VecDeque::new(),
            pending_fetch_quota_cancellations: VecDeque::new(),
            pending_fetch_quota_settlements: VecDeque::new(),
            fetch_max_in_flight: 1,
            fetch_queue_capacity: 1,
            active_fetches: 0,
            fetch_replay_slots: Arc::new(Semaphore::new(1)),
        };
        tokio::spawn(executor.run());
        SchedulingHarness {
            handle: ExecutorHandle {
                tx: request_tx,
                owed_tx,
            },
            completion_tx,
            worker: controlled,
            fixture,
        }
    }

    #[cfg(feature = "evaluate")]
    fn scheduling_job(fixture: &EnvironmentFixture, index: u8) -> EvaluateJob {
        let manifest =
            crate::environment::CausalLmEnvironmentSource::parse_manifest(&fixture.manifest_bytes)
                .expect("fixture manifest parses");
        let source =
            crate::environment::CausalLmEnvironmentSource::bind_manifest(&fixture.store, manifest)
                .expect("fixture environment binds");
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

    #[cfg(feature = "evaluate")]
    fn request_commitment(index: u8) -> [u8; 32] {
        let mut commitment = [0; 32];
        commitment[0] = index;
        commitment
    }

    #[cfg(feature = "evaluate")]
    async fn start_best_effort(
        handle: &ExecutorHandle,
        job: EvaluateJob,
        execution_id: &str,
        index: u8,
    ) -> crate::executor::ExecuteOutcome {
        let (reply, receive) = oneshot::channel();
        handle
            .tx
            .send(ExecutorRequest::StartEvaluateForTest {
                job: Box::new(job),
                execution_id: execution_id.to_string(),
                request_commitment: request_commitment(index),
                reply,
            })
            .await
            .expect("actor request ingress remains open");
        receive
            .await
            .expect("actor answers best-effort test request")
            .expect("test execution is admitted")
    }

    #[cfg(feature = "evaluate")]
    async fn receive_worker_job(worker: &ControlledExecuteWorker) -> ExecuteJob {
        timeout(Duration::from_secs(1), async {
            loop {
                match worker.try_recv() {
                    Ok(job) => return job,
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("controlled worker handoff disconnected")
                    }
                }
            }
        })
        .await
        .expect("actor dispatches to the controlled worker")
    }

    #[cfg(feature = "evaluate")]
    async fn actor_barrier(handle: &ExecutorHandle) {
        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        handle
            .tx
            .send(ExecutorRequest::BarrierForTest {
                entered,
                release: release_rx,
            })
            .await
            .expect("actor request ingress remains open");
        entered_rx.await.expect("actor reaches test barrier");
        release.send(()).expect("actor leaves test barrier");
    }

    #[cfg(feature = "evaluate")]
    fn failed_completion(job: ExecuteJob) -> ExecutorCompletion {
        let ExecuteJob {
            execution_id,
            request_commitment,
            evaluate_request,
            invocation,
            prepared_artifacts,
            sender,
            ..
        } = job;
        ExecutorCompletion::EvaluateFinished(Box::new(WorkerCompletion {
            cache_recording: None,
            execution_id,
            request_commitment,
            evaluate_request,
            invocation,
            prepared_artifacts,
            sender,
            result: WorkerCompletionResult::Failed {
                position: 0,
                error: "controlled scheduling completion".to_string(),
            },
        }))
    }

    #[tokio::test]
    async fn completions_stay_live_and_take_priority_when_requests_are_full() {
        let (request_tx, mut request_rx) = mpsc::channel(1);
        let (_owed_tx, mut owed_rx) = mpsc::channel(1);
        let (completion_tx, mut completion_rx) = mpsc::channel(1);
        let mut arbiter = InboxArbiter::default();
        assert!(request_tx.try_send(request()).is_ok());
        assert!(completion_tx.try_send(completion(1)).is_ok());

        assert!(matches!(
            recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await,
            Some(ExecutorInbox::Completion(
                ExecutorCompletion::FetchFinished(_)
            ))
        ));

        // Draining one trusted notification immediately frees its independent
        // slot even though the adversarial request mailbox remains saturated.
        assert!(completion_tx.try_send(completion(2)).is_ok());
        assert!(matches!(
            recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await,
            Some(ExecutorInbox::Completion(
                ExecutorCompletion::FetchFinished(_)
            ))
        ));
        assert!(matches!(
            recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await,
            Some(ExecutorInbox::Request(ExecutorRequest::GetStats { .. }))
        ));
    }

    #[cfg(feature = "evaluate")]
    #[tokio::test]
    async fn trusted_lanes_alternate_ahead_of_peer_requests() {
        let fixture = EnvironmentFixture::new();
        let (request_tx, mut request_rx) = mpsc::channel(1);
        let (owed_tx, mut owed_rx) = mpsc::channel(2);
        let (completion_tx, mut completion_rx) = mpsc::channel(2);
        let mut arbiter = InboxArbiter::default();

        assert!(request_tx.try_send(request()).is_ok());
        for index in [1, 2] {
            let (reply, _receive) = oneshot::channel();
            assert!(
                owed_tx
                    .try_send(ExecutorOwedRequest::StartEvaluateForTest {
                        job: Box::new(scheduling_job(&fixture, index)),
                        execution_id: format!("owed-{index}"),
                        request_commitment: request_commitment(index),
                        reply,
                    })
                    .is_ok()
            );
            assert!(completion_tx.try_send(completion(index)).is_ok());
        }

        for owed_first in [true, false, true, false] {
            let next = recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await;
            assert!(matches!(
                (owed_first, next),
                (true, Some(ExecutorInbox::Owed(_))) | (false, Some(ExecutorInbox::Completion(_)))
            ));
        }
        assert!(matches!(
            recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await,
            Some(ExecutorInbox::Request(_))
        ));
    }

    #[cfg(feature = "evaluate")]
    #[tokio::test]
    async fn completed_worker_handoff_cannot_lose_an_owed_execution() {
        let harness = scheduling_harness();
        let active_outcome = start_best_effort(
            &harness.handle,
            scheduling_job(&harness.fixture, 1),
            "active",
            1,
        )
        .await;
        let active = receive_worker_job(&harness.worker).await;
        assert_eq!(active.execution_id, "active");

        let owed_outcome = harness
            .handle
            .send_owed(|reply| ExecutorOwedRequest::StartEvaluateForTest {
                job: Box::new(scheduling_job(&harness.fixture, 2)),
                execution_id: "owed".to_string(),
                request_commitment: request_commitment(2),
                reply,
            })
            .await
            .expect("owed execution joins the actor FIFO while active is running");
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        harness
            .completion_tx
            .send(failed_completion(active))
            .await
            .expect("actor completion ingress remains open");

        // The controlled receiver deliberately was not waiting when the actor
        // dispatched. A zero-capacity try_send would put this job back forever.
        let owed = receive_worker_job(&harness.worker).await;
        assert_eq!(owed.execution_id, "owed");
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        harness
            .completion_tx
            .send(failed_completion(owed))
            .await
            .expect("owed completion is delivered exactly once");
        actor_barrier(&harness.handle).await;
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop((active_outcome, owed_outcome));
    }

    #[cfg(feature = "evaluate")]
    #[tokio::test]
    async fn ready_owed_ingress_beats_queued_best_effort_at_completion() {
        let harness = scheduling_harness();
        // Entering A through the trusted lane leaves the actor explicitly
        // preferring Completion. The barrier below therefore recreates the
        // original completion-first interleaving rather than relying on owed
        // selection to make the test pass.
        let active_outcome = harness
            .handle
            .send_owed(|reply| ExecutorOwedRequest::StartEvaluateForTest {
                job: Box::new(scheduling_job(&harness.fixture, 3)),
                execution_id: "active".to_string(),
                request_commitment: request_commitment(3),
                reply,
            })
            .await
            .expect("active owed execution starts");
        let active = receive_worker_job(&harness.worker).await;
        let best_effort_outcome = start_best_effort(
            &harness.handle,
            scheduling_job(&harness.fixture, 4),
            "best-effort",
            4,
        )
        .await;

        let (entered, entered_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        harness
            .handle
            .tx
            .send(ExecutorRequest::BarrierForTest {
                entered,
                release: release_rx,
            })
            .await
            .expect("barrier enters the peer mailbox");
        entered_rx.await.expect("actor reaches scheduling barrier");

        let (owed_reply, owed_reply_rx) = oneshot::channel();
        harness
            .handle
            .owed_tx
            .send(ExecutorOwedRequest::StartEvaluateForTest {
                job: Box::new(scheduling_job(&harness.fixture, 5)),
                execution_id: "owed".to_string(),
                request_commitment: request_commitment(5),
                reply: owed_reply,
            })
            .await
            .expect("owed ingress accepts the durable execution");
        harness
            .completion_tx
            .send(failed_completion(active))
            .await
            .expect("completion is ready beside owed ingress");
        release.send(()).expect("release actor scheduling barrier");

        let owed_outcome = owed_reply_rx
            .await
            .expect("actor answers the owed request")
            .expect("owed request is admitted");
        let first = receive_worker_job(&harness.worker).await;
        assert_eq!(first.execution_id, "owed");
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        harness
            .completion_tx
            .send(failed_completion(first))
            .await
            .expect("owed execution retires");
        let second = receive_worker_job(&harness.worker).await;
        assert_eq!(second.execution_id, "best-effort");
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        harness
            .completion_tx
            .send(failed_completion(second))
            .await
            .expect("best-effort execution retires");
        actor_barrier(&harness.handle).await;
        assert!(matches!(
            harness.worker.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop((active_outcome, owed_outcome, best_effort_outcome));
    }

    #[tokio::test]
    async fn inbox_closes_after_both_sides_are_drained() {
        let (request_tx, mut request_rx) = mpsc::channel(1);
        let (owed_tx, mut owed_rx) = mpsc::channel(1);
        let (completion_tx, mut completion_rx) = mpsc::channel(1);
        let mut arbiter = InboxArbiter::default();
        drop(request_tx);
        drop(owed_tx);
        drop(completion_tx);

        assert!(
            recv_next(
                &mut request_rx,
                &mut owed_rx,
                &mut completion_rx,
                &mut arbiter,
            )
            .await
            .is_none()
        );
    }
}
