//! Reusable paid gateway pool over durable client-owned state channels.

use crate::paid_client::{
    PaidClientError, PaidWorkOptions, PaidWorkResult, PaidWorkSession, bind_paid_endpoint,
    check_evaluate_input, check_request,
};
use hellas_kernel::Secp256k1Signer;
use hellas_rpc::protocol::artifacts::PreparedPaidInputV1;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_work::work_store::journal::MAX_RECORD_BYTES;
use iroh::EndpointId;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

mod config;
mod error;
pub use config::{PaidGatewayOptions, load_pool_options};
pub use error::PoolError;
type Result<T, E = PoolError> = std::result::Result<T, E>;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use hellas_gateway::{
    ExecutionEvent, Outcome, WorkExecutionBackend, WorkExecutionRequest, WorkFetchRequest,
};
use hellas_rpc::output::OutputEvent as FetchEvent;
use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkPolicy};
use iroh::Endpoint;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::Instrument;

// An OpenCode conversation has a substantial shared chat prefix. Smaller
// checkpoints are not worth routing work around.
const MIN_CACHE_AFFINITY_TOKENS: usize = 128;
const UNREACHABLE_PROVIDER_BACKOFF: Duration = Duration::from_secs(30);
// Opening a route is control-plane work. It must not inherit the model's
// execution allowance: an offline provider should yield to another route.
const PROVIDER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
// A retained job is durable, but it must not monopolize the channel that
// serves interactive requests after a restart or a provider interruption.
const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
// Bound queueing for Evaluate routes that can try another funded provider.
const CHANNEL_QUEUE_BUDGET: Duration = Duration::from_secs(1);
#[cfg(test)]
use crate::gateway_work::OUTPUT_EVENT_OVERHEAD;
use crate::gateway_work::{OUTPUT_BUFFER_BYTES, OUTPUT_BUFFER_EVENTS};
type BufferedEvent<E = ExecutionEvent> = crate::gateway_work::BufferedEvent<E, PoolError>;

trait GatewayEvent: Send + 'static {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self>
    where
        Self: Sized;
    fn completed(output: PaidWorkResult) -> Result<Vec<Self>>
    where
        Self: Sized;
    fn is_terminal(&self) -> bool;
    fn bytes(&self) -> usize;
}

struct Provider {
    args: PaidWorkOptions,
    policy: ProviderChannelPolicy,
    /// A setup/channel journal has a single owner even with concurrent HTTP calls.
    serial: AsyncMutex<Option<PaidWorkSession>>,
    pending: AtomicUsize,
    cache: Mutex<PrefixCache>,
    unavailable_until: Mutex<Option<Instant>>,
}

impl Provider {
    fn available(&self) -> bool {
        self.unavailable_until
            .lock()
            .expect("provider availability poisoned")
            .is_none_or(|until| until <= Instant::now())
    }

    fn connection_failed(&self) {
        *self
            .unavailable_until
            .lock()
            .expect("provider availability poisoned") =
            Some(Instant::now() + UNREACHABLE_PROVIDER_BACKOFF);
    }

    fn connection_succeeded(&self) {
        *self
            .unavailable_until
            .lock()
            .expect("provider availability poisoned") = None;
    }
}

#[derive(Default)]
struct PrefixCache(Option<Vec<u32>>);

impl PrefixCache {
    fn affinity(&self, input: &[u32]) -> usize {
        self.0
            .as_deref()
            .map(|checkpoint| shared_prefix_len(checkpoint, input))
            .filter(|shared| *shared >= MIN_CACHE_AFFINITY_TOKENS)
            .unwrap_or_default()
    }

    fn replace(&mut self, checkpoint: Option<Vec<u32>>) {
        self.0 = checkpoint;
    }
}

enum CacheUpdate {
    Replace(Vec<u32>),
    Clear,
}

impl CacheUpdate {
    fn from_request(environment: &hellas_rpc::CausalLmEnvironment, input: &[u32]) -> Self {
        let chunk = environment.generation_schedule().prefill_chunk_tokens as usize;
        // Only a completed request large enough to create a checkpoint gives
        // us a new affinity hint. Short requests conservatively clear the hint;
        // actual reuse remains the provider's decision under its device budget.
        let checkpoint = input
            .len()
            .saturating_sub(1)
            .checked_div(chunk)
            .unwrap_or_default()
            .saturating_sub(1)
            .saturating_mul(chunk);
        if checkpoint >= MIN_CACHE_AFFINITY_TOKENS {
            Self::Replace(input[..checkpoint].to_vec())
        } else {
            Self::Clear
        }
    }

    fn apply(self, cache: &mut PrefixCache) {
        match self {
            Self::Replace(checkpoint) => cache.replace(Some(checkpoint)),
            Self::Clear => cache.replace(None),
        }
    }
}

fn shared_prefix_len(left: &[u32], right: &[u32]) -> usize {
    left.iter()
        .zip(right)
        .take_while(|(left, right)| left == right)
        .count()
}

#[derive(Clone, Copy)]
struct Route {
    available: bool,
    cache_affinity_tokens: usize,
    pending: usize,
}

impl Route {
    fn score(self) -> (bool, usize, std::cmp::Reverse<usize>) {
        (
            self.available,
            self.cache_affinity_tokens,
            std::cmp::Reverse(self.pending),
        )
    }
}

struct ProviderUse(Arc<Provider>);
impl ProviderUse {
    fn new(provider: Arc<Provider>) -> Self {
        provider.pending.fetch_add(1, Ordering::Relaxed);
        Self(provider)
    }
}

impl Drop for ProviderUse {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct PaidGateway {
    providers: Vec<Arc<Provider>>,
    next: AtomicUsize,
    endpoint: Endpoint,
    settlement_key: Secp256k1Signer,
    producer_key: hellas_rpc::ProducerSigningKey,
    admission: Arc<Semaphore>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl PaidGateway {
    /// Open a reusable pool. Funding, recovery, queueing and payment are shared
    /// by CLI and embedding applications. Call `drain` during host shutdown.
    pub async fn open(
        options: PaidGatewayOptions,
        identity: crate::ClientIdentity,
    ) -> Result<Arc<Self>> {
        options.validate()?;
        let settlement_key = Secp256k1Signer::from_secret_scalar(identity.caller_secret_bytes())
            .map_err(|_| PoolError::Invalid("settlement identity is not secp256k1"))?;
        let providers = options
            .providers
            .into_iter()
            .map(|args| {
                Arc::new(Provider {
                    policy: args.config.provider_policy(),
                    args,
                    serial: AsyncMutex::new(None),
                    pending: AtomicUsize::new(0),
                    cache: Mutex::new(PrefixCache::default()),
                    unavailable_until: Mutex::new(None),
                })
            })
            .collect();
        let gateway = Arc::new(PaidGateway {
            admission: Arc::new(Semaphore::new(options.max_pending_requests)),
            providers,
            next: AtomicUsize::new(0),
            // One transport identity has one relay registration, shared by every
            // provider and request for the lifetime of this gateway.
            endpoint: bind_paid_endpoint(identity.transport_key()).await?,
            settlement_key,
            producer_key: identity.caller_key().clone(),
            tasks: Mutex::new(Vec::new()),
        });
        // Restart recovery uses the retained input and certificate, never a new job.
        // Empty journal roots do not fund a channel until an HTTP request arrives.
        for provider in &gateway.providers {
            let _recovery = gateway.submit::<ExecutionEvent>(
                vec![(
                    provider.clone(),
                    Route {
                        available: true,
                        cache_affinity_tokens: 0,
                        pending: 0,
                    },
                )],
                None,
                None,
                Some(RECOVERY_ATTEMPT_TIMEOUT),
                None,
            )?;
        }
        Ok(gateway)
    }
}

impl PaidGateway {
    fn execute_tokens(
        &self,
        request: WorkExecutionRequest,
    ) -> Result<BoxStream<'static, Result<ExecutionEvent>>> {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| hellas_gateway::WorkGatewayBusy)?;
        let input_ids = request.input_ids.clone();
        let cache_update = CacheUpdate::from_request(&request.environment, &input_ids);
        let prepared = prepare_request(request, &self.settlement_key)?;
        let eligible = self
            .providers
            .iter()
            .filter(|provider| check_evaluate_input(&provider.policy, &prepared).is_ok())
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Err(PoolError::NoMatchingPolicy);
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) % eligible.len();
        let mut candidates = (0..eligible.len())
            .map(|offset| {
                let provider = eligible[(start + offset) % eligible.len()];
                let cache = provider.cache.lock().expect("provider cache poisoned");
                let route = Route {
                    available: provider.available(),
                    cache_affinity_tokens: cache.affinity(&input_ids),
                    pending: provider.pending.load(Ordering::Relaxed),
                };
                (provider.clone(), route)
            })
            .collect::<Vec<_>>();
        // Stable sorting preserves the rotating order for equally ranked routes.
        candidates.sort_by_key(|(_, route)| std::cmp::Reverse(route.score()));
        self.submit(
            candidates,
            Some(prepared.into()),
            Some(cache_update),
            None,
            Some(permit),
        )
    }

    fn submit<E: GatewayEvent>(
        &self,
        candidates: Vec<(Arc<Provider>, Route)>,
        prepared: Option<PreparedWorkInput>,
        cache_update: Option<CacheUpdate>,
        recovery_timeout: Option<Duration>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Result<BoxStream<'static, Result<E>>> {
        // Admission can precede local request preparation. Serialize the final
        // gate check and registration with drain's close-and-snapshot boundary.
        let mut tasks = self.tasks.lock().expect("paid task list poisoned");
        if self.admission.is_closed() {
            return Err(hellas_gateway::WorkGatewayBusy.into());
        }
        let endpoint = self.endpoint.clone();
        let settlement_key = self.settlement_key.clone();
        let (sender, receiver) = mpsc::channel::<BufferedEvent<E>>(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let output_budget = Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES));
        let Some((initial_provider, _initial_route)) = candidates.first() else {
            return Err(PoolError::NoMatchingPolicy);
        };
        let span = hellas_rpc::request_span!(
            target: "hellas_request", "paid.gateway",
            hellas.provider.id = %initial_provider.args.provider,
            hellas.work.recovery = prepared.is_none(),
            hellas.route.cache_affinity_tokens = _initial_route.cache_affinity_tokens,
            hellas.route.pending = _initial_route.pending,
        );
        // Reserve the first route synchronously so concurrent HTTP requests see
        // both queued and executing work. Each failed candidate releases its slot.
        let mut occupied = prepared
            .as_ref()
            .map(|_| ProviderUse::new(initial_provider.clone()));
        let timeout = recovery_timeout.unwrap_or_else(|| initial_provider.args.timeout);
        // Queueing, recovery and fallback all consume the same request budget.
        let deadline = tokio::time::Instant::now() + timeout;
        let task_span = span.clone();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let token_sender = sender.clone();
            let token_overflow = overflow.clone();
            let token_budget = output_budget.clone();
            let streamed = prepared.is_some();
            let recovery = !streamed;
            let progress: hellas_work::work::PaidProgress = Arc::new(move |event| {
                let event = E::prefix(event).map_err(|error| hellas_work::work::BackendFault::new(error.to_string()))?;
                emit(&token_sender, &token_overflow, &token_budget, Ok(event));
                Ok(())
            });
            let result = async {
                let prepared_bytes = prepared.as_ref().map(PreparedWorkInput::encode).transpose()?;
                let mut provider_errors = Vec::new();
                for (provider, route) in candidates {
                    let _occupied = occupied.take().or_else(|| {
                        prepared.as_ref().map(|_| ProviderUse::new(provider.clone()))
                    });
                    task_span.record("hellas.provider.id", tracing::field::display(provider.args.provider));
                    task_span.record("hellas.route.cache_affinity_tokens", route.cache_affinity_tokens);
                    task_span.record("hellas.route.pending", route.pending);
                    // Serialize jobs on one funded channel; its observer runs independently.
                    let mut session = if recovery || matches!(prepared, Some(PreparedWorkInput::Fetch(_))) {
                        before_proposal(
                            &sender, streamed, deadline,
                            |_| provider.serial.lock().instrument(hellas_rpc::request_span!(target: "hellas_request", "paid.queue")),
                        ).await?
                    } else {
                        match tokio::time::timeout(
                            CHANNEL_QUEUE_BUDGET,
                            provider.serial.lock(),
                        ).await {
                            Ok(session) => session,
                            Err(_) => {
                                provider_errors.push(format!(
                                    "{}: paid channel is busy",
                                    provider.args.provider
                                ));
                                continue;
                            }
                        }
                    };
                    if prepared.is_none() && !has_retained_setup(&provider.args)? {
                        continue;
                    }
                    // Recheck after queueing, including restored channels whose
                    // setup journal opened without contacting the provider.
                    if !provider.available() {
                        provider_errors.push(format!("{}: provider is backing off", provider.args.provider));
                        continue;
                    }
                    if session.is_none() {
                        match connect_before_deadline(
                            &sender, streamed, deadline, PROVIDER_CONNECTION_TIMEOUT,
                            async { PaidWorkSession::open(provider.args.clone(), endpoint.clone(), settlement_key.clone()).await.map_err(PoolError::from) },
                        ).await
                        {
                            Ok(opened) => {
                                *session = Some(opened);
                            }
                            Err(error) => {
                                if !recovery && matches!(error, PoolError::Stopped(_)) { return Err(error); }
                                provider.connection_failed();
                                if recovery {
                                    tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                                        "retained paid-work recovery could not open its channel");
                                } else {
                                    tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                                        "paid provider channel could not be opened");
                                }
                                provider_errors.push(format!("{}: {error:#}", provider.args.provider));
                                continue;
                            }
                        }
                    }
                    let session = session.as_mut().expect("channel was opened");
                    if prepared.is_some() && session.needs_recovery() {
                        let recovery_deadline = deadline.min(
                            tokio::time::Instant::now() + RECOVERY_ATTEMPT_TIMEOUT,
                        );
                        let recovery = tokio::time::timeout_at(
                            recovery_deadline,
                            session.run(None, true, None),
                        )
                        .await
                        .map_err(|_| PoolError::RecoveryTimeout)
                        .and_then(|result| result.map_err(PoolError::from));
                        if let Err(error) = recovery {
                            // Nothing in this path has proposed the fresh request.
                            // Keep the journal for a later recovery and route this
                            // interactive request to another paid provider now.
                            provider.cache.lock().expect("provider cache poisoned").replace(None);
                            provider.connection_failed();
                            tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                                "retained paid work deferred before a fresh request");
                            provider_errors.push(format!(
                                "{}: retained work recovery deferred: {error:#}",
                                provider.args.provider
                            ));
                            continue;
                        }
                    }
                    // ClientEndpoint journals the proposal nonce before releasing
                    // its signature. Recovery and a failed dial need not propose
                    // this request; a lost acceptance response does advance it.
                    let proposal_nonce = session.with_state(|state| state.proposal_nonce_high_water())?;
                    let already_proposed = session.with_state(|state| prepared_bytes.as_ref().is_some_and(|input| state.jobs().any(|job| job.prepared_input() == input)))?;
                    let request_session = &mut *session;
                    let input = prepared.clone();
                    let on_progress = streamed.then(|| progress.clone());
                    let result = before_proposal(
                        &sender, streamed, deadline,
                        |proposed| async move {
                            request_session.run_with_admission(input, true, on_progress, Some(&proposed)).await
                        },
                    ).await
                        .and_then(|result| result.map_err(PoolError::from))
                        .and_then(|output| output.map(E::completed).transpose())
                        .map(Option::unwrap_or_default);
                    if let Err(error) = &result {
                        if !recovery && matches!(error, PoolError::Stopped(_))
                            && session.with_state(|state| state.proposal_nonce_high_water())? == proposal_nonce
                        {
                            return result;
                        }
                        provider.cache.lock().expect("provider cache poisoned").replace(None);
                        if recovery {
                            provider.connection_failed();
                            return result.map_err(|source| PoolError::Provider { provider: provider.args.provider, source: Box::new(source) });
                        }
                        // A failed journal append can leave a durable proposal that
                        // is not reflected in memory yet. Keep that failure with
                        // this provider, just like a proposal with no response.
                        let uncertain_append = matches!(
                            error,
                            PoolError::Client(PaidClientError::Propose(hellas_work::work::ProposeError::Store(_))),
                        );
                        if !already_proposed && !uncertain_append
                            && session.with_state(|state| state.proposal_nonce_high_water())? == proposal_nonce
                        {
                            provider.connection_failed();
                            tracing::debug!(provider = %provider.args.provider, error = %format!("{error:#}"),
                                "paid provider failed before proposing new work");
                            provider_errors.push(format!("{}: {error:#}", provider.args.provider));
                            continue;
                        }
                    } else {
                        provider.connection_succeeded();
                        if let Some(cache_update) = cache_update {
                            cache_update.apply(&mut provider.cache.lock().expect("provider cache poisoned"));
                        }
                    }
                    return result.map_err(|source| PoolError::Provider { provider: provider.args.provider, source: Box::new(source) });
                }
                Err(PoolError::ProvidersUnavailable(provider_errors))
            }.await;
            if let Err(error) = &result {
                if recovery {
                    tracing::debug!(error = %format!("{error:#}"),
                        "retained paid-work recovery deferred");
                } else {
                    tracing::error!(error = %format!("{error:#}"),
                        "paid gateway operation failed; durable journals retained for recovery");
                }
            }
            // A disconnected request stops before proposal. After proposal, it
            // still collects and pays until the deadline; journals retain any
            // unfinished operation for recovery.
            match result {
                Ok(events) => for event in events {
                    if !streamed || event.is_terminal() {
                        emit(&sender, &overflow, &output_budget, Ok(event));
                    }
                },
                Err(error) => { emit(&sender, &overflow, &output_budget, Err(error)); }
            }
        }.instrument(span));
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        Ok(response_stream(receiver, overflow_receiver))
    }
}

fn has_retained_setup(options: &PaidWorkOptions) -> Result<bool> {
    let found = hellas_work::work_store::discover_setups(
        &options.journal_root,
        options.config.chain.network,
    )?;
    // Counter files and other metadata alone must never trigger channel funding.
    // Unidentified setup journals still go through ordinary recovery and fail
    // closed; discovery is only a prefilter, not a signature check.
    Ok(!found.unidentified.is_empty()
        || found.setups.iter().any(|setup| {
            setup.role == hellas_work::work_store::Role::Client && setup.bond_edge == options.bond
        }))
}

impl WorkExecutionBackend for PaidGateway {
    fn fetch_providers(&self) -> Vec<EndpointId> {
        self.providers.iter().filter(|provider| matches!(provider.policy.work_policy,
            WorkPolicy::Fetch { policy, .. } if policy.allowed_environment == hellas_rpc::FetchEnvironment::Http.manifest_id()))
            .map(|provider| provider.args.provider).collect()
    }

    fn fetch(
        &self,
        request: WorkFetchRequest,
    ) -> Result<hellas_gateway::WorkFetchStream, hellas_gateway::WorkGatewayError> {
        use hellas_gateway::WorkGatewayError;
        let provider = self
            .providers
            .iter()
            .find(|provider| {
                provider.args.provider == request.provider
                    && matches!(provider.policy.work_policy, WorkPolicy::Fetch { .. })
            })
            .ok_or(WorkGatewayError::Provider(request.provider))?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| hellas_gateway::WorkGatewayBusy)?;
        let submit = || -> Result<_> {
            let prepared = prepare_fetch(&provider.args, &request, &self.producer_key)?;
            let route = Route {
                available: provider.available(),
                cache_affinity_tokens: 0,
                pending: provider.pending.load(Ordering::Relaxed),
            };
            // Account/session selection is already final. Never substitute another
            // provider, including on failure before acceptance.
            self.submit::<FetchEvent>(
                vec![(provider.clone(), route)],
                Some(prepared),
                None,
                None,
                Some(permit),
            )
        };
        paid_stream(submit())
    }

    fn timeout(&self) -> Duration {
        self.providers
            .iter()
            .map(|provider| provider.args.timeout)
            .max()
            .unwrap_or_default()
    }

    fn execute(
        &self,
        request: WorkExecutionRequest,
    ) -> Result<hellas_gateway::WorkOutputStream<ExecutionEvent>, hellas_gateway::WorkGatewayError>
    {
        paid_stream(self.execute_tokens(request))
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        let tasks = {
            let mut tasks = self.tasks.lock().expect("paid task list poisoned");
            self.admission.close();
            std::mem::take(&mut *tasks)
        };
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            let mut interrupted = 0;
            for mut task in tasks {
                match tokio::time::timeout_at(deadline, &mut task).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(%error, "paid gateway task failed during shutdown")
                    }
                    Err(_) => {
                        task.abort();
                        let _ = task.await;
                        interrupted += 1;
                    }
                }
            }
            if interrupted > 0 {
                tracing::warn!(
                    interrupted,
                    "paid gateway shutdown deadline reached; retained work will recover on startup"
                );
            }
            for provider in &self.providers {
                if let Some(mut session) = provider.serial.lock().await.take() {
                    session.shutdown().await;
                }
            }
            self.endpoint.close().await;
        })
    }
}

fn paid_stream<E: Send + 'static>(
    stream: Result<BoxStream<'static, Result<E>>>,
) -> Result<hellas_gateway::WorkOutputStream<E>, hellas_gateway::WorkGatewayError> {
    use futures::StreamExt as _;
    fn convert(error: PoolError) -> hellas_gateway::WorkGatewayError {
        match error {
            PoolError::Busy(busy) => busy.into(),
            error => hellas_gateway::WorkGatewayError::Execution(Box::new(error)),
        }
    }
    Ok(Box::pin(
        stream.map_err(convert)?.map(|event| event.map_err(convert)),
    ))
}

fn emit<E: GatewayEvent>(
    sender: &mpsc::Sender<BufferedEvent<E>>,
    overflow: &watch::Sender<bool>,
    budget: &Arc<Semaphore>,
    event: Result<E>,
) {
    let bytes = match &event {
        Ok(event) => event.bytes(),
        Err(error) => error.to_string().len(),
    };
    crate::gateway_work::emit(sender, overflow, budget, event, bytes);
}

fn response_stream<E: Send + 'static>(
    receiver: mpsc::Receiver<BufferedEvent<E>>,
    overflow: watch::Receiver<bool>,
) -> BoxStream<'static, Result<E>> {
    crate::gateway_work::response_stream(receiver, overflow, || PoolError::SlowConsumer)
}

#[derive(Debug, thiserror::Error)]
pub enum RequestStopped {
    #[error("paid request disconnected before proposal")]
    Disconnected,
    #[error("paid request deadline elapsed, including queue wait")]
    Deadline,
}

// A route's short connection allowance is recoverable by trying another
// provider; only the enclosing request deadline or disconnect is terminal.
async fn connect_before_deadline<T, E>(
    sender: &mpsc::Sender<BufferedEvent<E>>,
    cancel_on_disconnect: bool,
    deadline: tokio::time::Instant,
    connection_timeout: Duration,
    connection: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let connection_deadline = deadline.min(tokio::time::Instant::now() + connection_timeout);
    before_proposal(sender, cancel_on_disconnect, deadline, |_| async {
        tokio::time::timeout_at(connection_deadline, connection)
            .await
            .map_err(|_| PoolError::ConnectionTimeout(connection_timeout))?
    })
    .await?
}

/// Cancel an unproposed HTTP operation without interrupting work whose
/// proposal signature may already have reached a provider.
async fn before_proposal<T, F: std::future::Future<Output = T>, E>(
    sender: &mpsc::Sender<BufferedEvent<E>>,
    cancel_on_disconnect: bool,
    deadline: tokio::time::Instant,
    operation: impl FnOnce(Arc<AtomicBool>) -> F,
) -> Result<T> {
    if tokio::time::Instant::now() >= deadline {
        return Err(RequestStopped::Deadline.into());
    }
    // This flag belongs to this operation, never to retained matching input.
    // A prior journal record may prevent fallback but cannot authorize a new
    // request after its HTTP receiver has gone away.
    let proposed = Arc::new(AtomicBool::new(false));
    let operation = tokio::time::timeout_at(deadline, operation(proposed.clone()));
    tokio::pin!(operation);
    let result = tokio::select! {
        biased;
        _ = sender.closed(), if cancel_on_disconnect => {
            if !proposed.load(Ordering::Acquire) {
                return Err(RequestStopped::Disconnected.into());
            }
            operation.await
        }
        result = &mut operation => result,
    };
    result.map_err(|_| RequestStopped::Deadline.into())
}

fn prepare_fetch(
    options: &PaidWorkOptions,
    request: &WorkFetchRequest,
    signer: &hellas_rpc::ProducerSigningKey,
) -> Result<PreparedWorkInput> {
    use hellas_rpc::FetchEnvironment;
    let environment = [
        FetchEnvironment::Http,
        FetchEnvironment::OpenAiResponses,
        FetchEnvironment::CodexResponses,
    ]
    .into_iter()
    .find(|env| env.manifest_id() == options.config.work_policy.allowed_environment())
    .ok_or(PoolError::NoMatchingPolicy)?;
    let input = hellas_rpc::fetch::build_input_events_with_retention(
        &request.service,
        &request.method,
        &request.body,
        environment.manifest_id(),
        options.provider_trust.required_assurance,
        signer,
        hellas_rpc::Retention::Ephemeral,
    )?;
    let prepared = hellas_rpc::protocol::work_fetch::PreparedPaidFetchInputV1::new(
        &input,
        &environment.manifest(),
    )?
    .into();
    check_request(
        &options.config.provider_policy(),
        &prepared,
        &options.provider_trust,
        signer.public_key(),
    )?;
    Ok(prepared)
}

fn prepare_request(
    request: WorkExecutionRequest,
    signer: &Secp256k1Signer,
) -> Result<PreparedPaidInputV1> {
    Ok(crate::gateway_work::prepare_evaluate(
        request,
        hellas_rpc::PublicKey::Secp256k1(signer.party_key().to_bytes()),
    )?)
}

fn output_events(output: PaidWorkResult) -> Result<Vec<ExecutionEvent>> {
    let events =
        hellas_rpc::protocol::work::decode_transcript(&output.transcript, MAX_RECORD_BYTES)?;
    let verified = hellas_rpc::evaluate::verify_output_events_for_producer(
        output.input,
        hellas_rpc::Assurance::ProducerSigned,
        &output.provider_key,
        &events,
    )?;
    let mut result = Vec::with_capacity(verified.token_deltas.len() + 1);
    for delta in verified.token_deltas {
        result.push(ExecutionEvent::Chunk {
            position: delta.end_position()?,
            tokens: delta.token_bytes(),
        });
    }
    result.push(crate::gateway_work::evaluate_terminal(events)?);
    tracing::info!(
        work_id = %hex::encode(output.work_id.as_bytes()),
        job_price = output.job_price,
        credited_cumulative = output.credited_cumulative,
        result_bytes = output.transcript.len(),
        "paid inference result acknowledged",
    );
    Ok(result)
}

impl GatewayEvent for ExecutionEvent {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self> {
        let delta = hellas_rpc::evaluate::decode_token_delta_payload(event.payload())?;
        Ok(Self::Chunk {
            position: delta.end_position()?,
            tokens: delta.token_bytes(),
        })
    }
    fn completed(output: PaidWorkResult) -> Result<Vec<Self>> {
        output_events(output)
    }
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Done(_))
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Chunk { tokens, .. } => tokens.len(),
            Self::Done(Outcome::Completed { output_events, .. }) => output_events
                .iter()
                .map(|event| event.payload().len())
                .fold(0usize, usize::saturating_add),
            Self::Done(_) => MAX_RECORD_BYTES,
        }
    }
}

impl GatewayEvent for FetchEvent {
    fn prefix(event: hellas_rpc::OutputEventEnvelope) -> Result<Self> {
        Ok(hellas_rpc::fetch::decode_fetch_event_payload(
            event.payload(),
        )?)
    }
    fn completed(output: PaidWorkResult) -> Result<Vec<Self>> {
        let events = hellas_rpc::protocol::work::decode_transcript(
            &output.transcript,
            hellas_rpc::protocol::work_fetch::MAX_FETCH_TRANSCRIPT_BYTES,
        )?;
        let terminal = events
            .last()
            .ok_or(PoolError::MissingOutput("paid Fetch omitted terminal"))?;
        if terminal.event().body().kind() != hellas_rpc::fetch::OUTPUT_TERMINAL_KIND {
            return Err(PoolError::MissingOutput("paid Fetch terminal kind"));
        }
        let terminal =
            hellas_rpc::fetch::decode_fetch_terminal_payload(terminal.payload())?.to_output_event();
        tracing::info!(work_id = %hex::encode(output.work_id.as_bytes()), job_price = output.job_price,
            credited_cumulative = output.credited_cumulative, result_bytes = output.transcript.len(), "paid Fetch result acknowledged");
        Ok(vec![terminal])
    }
    fn is_terminal(&self) -> bool {
        self.terminal().is_some()
    }
    fn bytes(&self) -> usize {
        serde_json::to_vec(self).map_or(MAX_RECORD_BYTES, |bytes| bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::Endpoint;

    fn pool_options(fixture: &crate::test_support::PaidFixture) -> PaidGatewayOptions {
        use hellas_kernel::{CoinId, Funding, List};
        PaidGatewayOptions {
            max_pending_requests: 4,
            providers: vec![PaidWorkOptions {
                config: fixture.config.clone(),
                journal_root: fixture.root.path().join("client"),
                provider: iroh::SecretKey::from_bytes(&[3; 32]).public(),
                provider_addrs: Vec::new(),
                provider_trust: crate::test_support::provider_trust(
                    iroh::SecretKey::from_bytes(&[3; 32]).public(),
                ),
                bond: fixture.descriptor.bond_edge(),
                payment_funding: Funding::new(
                    List::take([CoinId::from_bytes([1; 32]); 4], 1),
                    List::empty(CoinId::from_bytes([0; 32])),
                ),
                omission_bond: 601,
                acceptance_blocks: 16,
                terminal_blocks: 64,
                payment_blocks: 32,
                timeout: Duration::from_secs(30),
            }],
        }
    }

    #[tokio::test]
    async fn paid_responses_backend_uses_its_manifest_and_refuses_route_mismatch_before_funding() {
        let fixture = crate::test_support::PaidFixture::new();
        let options = pool_options(&fixture);
        let identity = crate::ClientIdentity::from_secret_bytes([1; 32], [1; 32]).unwrap();
        let provider = options.providers[0].provider;
        let request = |method: &str| WorkFetchRequest {
            provider,
            service: "openai".into(),
            method: method.into(),
            body: crate::test_support::BODY.to_vec(),
        };
        let prepared = prepare_fetch(
            &options.providers[0],
            &request("responses"),
            identity.caller_key(),
        )
        .unwrap();
        let PreparedWorkInput::Fetch(prepared) = prepared else {
            panic!("Fetch input")
        };
        let input = hellas_rpc::fetch::verify_input_events(
            &prepared.parts().unwrap().fetch_input_transcript,
        )
        .unwrap();
        assert_eq!(
            input.execution_environment,
            hellas_rpc::FetchEnvironment::OpenAiResponses.manifest_id()
        );
        let gateway = PaidGateway::open(options, identity).await.unwrap();
        drop(
            gateway
                .fetch(request("responses"))
                .expect("Responses uses the shared paid backend"),
        );
        assert!(gateway.fetch(request("another-route")).is_err());
        gateway.drain().await;
        assert!(!fixture.root.path().join("client").exists());
    }

    #[test]
    fn counter_files_do_not_trigger_funding_but_incomplete_setup_recovers() {
        let fixture = crate::test_support::PaidFixture::new();
        let options = pool_options(&fixture);
        let provider = &options.providers[0];
        assert!(!has_retained_setup(provider).unwrap());
        std::fs::create_dir_all(provider.journal_root.join("apple-counters")).unwrap();
        std::fs::write(
            provider
                .journal_root
                .join("apple-counters/producer.counter"),
            [1],
        )
        .unwrap();
        assert!(!has_retained_setup(provider).unwrap());
        let store = hellas_work::work_store::SetupStore::open(
            &provider.journal_root,
            provider.config.chain.network,
            provider.bond,
            hellas_work::work_store::Role::Client,
            &hellas_kernel::Secp256k1Verifier::new(),
        )
        .unwrap();
        drop(store);
        assert!(has_retained_setup(provider).unwrap());
    }

    #[tokio::test]
    async fn shared_pool_rejects_reused_funding_before_opening_or_writing() {
        let fixture = crate::test_support::PaidFixture::new();
        let mut options = pool_options(&fixture);
        let mut second = options.providers[0].clone();
        second.provider = iroh::SecretKey::from_bytes(&[4; 32]).public();
        second.journal_root = fixture.root.path().join("other");
        options.providers.push(second);
        let result = PaidGateway::open(options, crate::ClientIdentity::generate()).await;
        assert!(matches!(
            result,
            Err(PoolError::Invalid(
                "a payment coin cannot fund two provider channels or appear twice"
            ))
        ));
        assert!(!fixture.root.path().join("client").exists());
        assert!(!fixture.root.path().join("other").exists());
    }

    #[tokio::test]
    async fn disconnected_queued_request_never_starts_work() {
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        drop(receiver);
        let started = AtomicBool::new(false);
        let result = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |_| async {
                started.store(true, Ordering::Relaxed);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn disconnect_after_proposal_still_finishes_payment() {
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let (proposal_sent, proposal_seen) = tokio::sync::oneshot::channel();
        let (payment_ready, payment_wait) = tokio::sync::oneshot::channel();
        let work = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |proposed| async move {
                proposed.store(true, Ordering::Release);
                proposal_sent.send(()).unwrap();
                payment_wait.await.unwrap();
                "payment acknowledged"
            },
        );
        let disconnect = async {
            proposal_seen.await.unwrap();
            drop(receiver);
            tokio::task::yield_now().await;
            payment_ready.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(work, disconnect);
        assert_eq!(result.unwrap(), "payment acknowledged");
    }

    #[tokio::test]
    async fn disconnect_during_dial_cancels_before_signature_release() {
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let signed = AtomicBool::new(false);
        let signed_ref = &signed;
        let (dial_started, dial_seen) = tokio::sync::oneshot::channel();
        let operation = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_secs(1),
            |proposed| async move {
                dial_started.send(()).unwrap();
                std::future::pending::<()>().await;
                proposed.store(true, Ordering::Release);
                signed_ref.store(true, Ordering::Release);
            },
        );
        let disconnect = async {
            dial_seen.await.unwrap();
            drop(receiver);
        };
        let (result, ()) = tokio::join!(operation, disconnect);
        assert!(matches!(result.unwrap_err(), PoolError::Stopped(_)));
        assert!(!signed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn connection_timeout_allows_fallback_within_the_request_deadline() {
        let (sender, _receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let failed = connect_before_deadline(
            &sender,
            true,
            deadline,
            Duration::from_millis(10),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(!matches!(failed, PoolError::Stopped(_)));
        assert_eq!(
            connect_before_deadline(&sender, true, deadline, Duration::from_millis(10), async {
                Ok("second provider")
            },)
            .await
            .unwrap(),
            "second provider"
        );
        let expired = connect_before_deadline(
            &sender,
            true,
            tokio::time::Instant::now(),
            Duration::from_secs(10),
            async { Ok(()) },
        )
        .await
        .unwrap_err();
        assert!(matches!(expired, PoolError::Stopped(_)));
    }

    #[tokio::test]
    async fn previous_proposal_does_not_authorize_disconnected_next_operation() {
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        before_proposal(&sender, true, deadline, |proposed| async move {
            proposed.store(true, Ordering::Release);
        })
        .await
        .unwrap();
        // A retained proposal from the earlier operation may still exist, but
        // the next operation must establish its own signature-release boundary.
        drop(receiver);
        let started = AtomicBool::new(false);
        let result = before_proposal(&sender, true, deadline, |_| async {
            started.store(true, Ordering::Release);
        })
        .await;
        assert!(matches!(result.unwrap_err(), PoolError::Stopped(_)));
        assert!(!started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn shutdown_rejects_admitted_work_not_yet_registered() {
        let gateway = PaidGateway {
            providers: Vec::new(),
            next: AtomicUsize::new(0),
            endpoint: Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap(),
            settlement_key: Secp256k1Signer::from_secret_scalar([7; 32]).unwrap(),
            producer_key: hellas_rpc::ProducerSigningKey::from_secret_bytes([7; 32]).unwrap(),
            admission: Arc::new(Semaphore::new(1)),
            tasks: Mutex::new(Vec::new()),
        };
        // Deterministically pause execute at the point after admission but
        // before preparation/routing has reached task registration.
        let permit = gateway.admission.clone().try_acquire_owned().unwrap();
        gateway.drain().await;
        let result = gateway.submit::<ExecutionEvent>(Vec::new(), None, None, None, Some(permit));
        assert!(matches!(
            result.err().expect("submission after drain"),
            PoolError::Busy(_)
        ));
        assert!(gateway.tasks.lock().unwrap().is_empty());
        assert_eq!(gateway.admission.available_permits(), 1);
    }

    #[test]
    fn the_largest_possible_completion_fits_the_output_budget() {
        // The terminal `Done(Completed)` is one channel message carrying the
        // whole transcript, and a transcript is capped at `MAX_RECORD_BYTES`.
        // `emit` must therefore charge it at most that, plus the single
        // per-message `OUTPUT_EVENT_OVERHEAD`, or a completion the protocol
        // permits cannot be delivered at all: `try_acquire_many_owned` fails,
        // `overflow` latches, and the caller is told its reader is too slow
        // for work it has already paid for.
        //
        // This is the invariant that a per-contained-event overhead broke.
        // Multiplying the overhead by event count makes the charge unbounded
        // with respect to `MAX_RECORD_BYTES` -- ~8000 small events exceeded
        // the budget on their own -- so no value of `OUTPUT_BUFFER_BYTES`
        // could satisfy this assertion.
        let worst_case = MAX_RECORD_BYTES.saturating_add(OUTPUT_EVENT_OVERHEAD);
        assert!(
            worst_case <= OUTPUT_BUFFER_BYTES,
            "a maximal completion charges {worst_case} against a {OUTPUT_BUFFER_BYTES} budget",
        );
    }

    #[tokio::test]
    async fn buffered_reconnect_burst_is_delivered_and_releases_byte_budget() {
        use futures::StreamExt;
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let budget = Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES));
        // Retained output can arrive in one burst before HTTP gets a poll.
        for position in 0..128 {
            emit(
                &sender,
                &overflow,
                &budget,
                Ok(ExecutionEvent::Chunk {
                    position,
                    tokens: vec![0; 4],
                }),
            );
        }
        drop(sender);
        drop(overflow);
        let mut response = response_stream(receiver, overflow_receiver);
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
        use futures::StreamExt;
        let (sender, receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let budget = Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES));
        // A stalled reader cannot retain more than the byte budget, and the
        // synchronous producer callback still returns without waiting on it.
        for position in 0..3 {
            emit(
                &sender,
                &overflow,
                &budget,
                Ok(ExecutionEvent::Chunk {
                    position,
                    tokens: vec![0; OUTPUT_BUFFER_BYTES / 2 - OUTPUT_EVENT_OVERHEAD],
                }),
            );
        }
        assert_eq!(budget.available_permits(), 0);
        let mut response = response_stream(receiver, overflow_receiver);
        assert!(
            response
                .next()
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("too slow")
        );
        assert!(sender.is_closed());
        assert!(response.next().await.is_none());
    }

    #[tokio::test]
    async fn queue_wait_uses_the_execution_deadline() {
        let (sender, _receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let serial = AsyncMutex::new(());
        let _busy = serial.lock().await;
        let result = before_proposal(
            &sender,
            true,
            tokio::time::Instant::now() + Duration::from_millis(20),
            |_| serial.lock(),
        )
        .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("including queue wait")
        );
    }

    #[tokio::test]
    async fn expired_request_does_not_start_a_fallback_provider() {
        let (sender, _receiver) = mpsc::channel::<BufferedEvent>(OUTPUT_BUFFER_EVENTS);
        let started = AtomicBool::new(false);
        let result = before_proposal(&sender, true, tokio::time::Instant::now(), |_| async {
            started.store(true, Ordering::Relaxed);
        })
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }
}
