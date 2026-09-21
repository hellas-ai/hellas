//! HTTP gateway adapter over the same durable paid-work client as the CLI.

use super::*;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use hellas_gateway::{
    ExecutionEvent, Outcome, PaidExecutionBackend, PaidExecutionRequest, StopReason,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed as _, OutputAddressed as _, SourceRef, TextArtifact, TextExecution,
    TextPolicy, TokenIds,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::Instrument;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
    providers: Vec<ProviderFile>,
    #[serde(default = "acceptance_blocks")]
    acceptance_blocks: u64,
    #[serde(default = "terminal_blocks")]
    terminal_blocks: u64,
    #[serde(default = "payment_blocks")]
    payment_blocks: u64,
    #[serde(default = "timeout_secs")]
    timeout_secs: u64,
    #[serde(default = "max_pending_requests")]
    max_pending_requests: usize,
}

const fn max_pending_requests() -> usize {
    64
}

const fn acceptance_blocks() -> u64 {
    16
}
const fn terminal_blocks() -> u64 {
    64
}
const fn payment_blocks() -> u64 {
    32
}
const fn timeout_secs() -> u64 {
    300
}

// An OpenCode conversation has a substantial shared chat prefix. Smaller
// checkpoints are not worth routing work around.
const MIN_CACHE_AFFINITY_TOKENS: usize = 128;
const UNREACHABLE_PROVIDER_BACKOFF: Duration = Duration::from_secs(30);
// A retained job is durable, but it must not monopolize the channel that
// serves interactive requests after a restart or a provider interruption.
const RECOVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
// Bound HTTP delivery independently of the authenticated transcript spool.
const OUTPUT_BUFFER_BYTES: usize = 2 * MAX_RECORD_BYTES;
const OUTPUT_EVENT_OVERHEAD: usize = 1024;
const OUTPUT_BUFFER_EVENTS: usize = OUTPUT_BUFFER_BYTES / OUTPUT_EVENT_OVERHEAD;
type BufferedEvent = (CliResult<ExecutionEvent>, OwnedSemaphorePermit);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    work_config: PathBuf,
    journal_root: PathBuf,
    provider: EndpointId,
    #[serde(default)]
    provider_addrs: Vec<SocketAddr>,
    bond: String,
    payment_coins: Vec<String>,
    omission_bond: u64,
}

struct Provider {
    args: RunArgs,
    policy: ProviderChannelPolicy,
    /// A setup/channel journal has a single owner even with concurrent HTTP calls.
    serial: AsyncMutex<Option<OpenPaidChannel>>,
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
    Preserve,
    Replace(Vec<u32>),
    Clear,
}

impl CacheUpdate {
    fn from_request(environment: &hellas_rpc::CausalLmEnvironment, input: &[u32]) -> Self {
        let Some(schedule) = environment.generation_schedule() else {
            return Self::Clear;
        };
        let chunk = schedule.prefill_chunk_tokens as usize;
        if input.len() <= chunk {
            // A one-chunk request is normally a title or tool bookkeeping.
            // The deployed Catena runtime leaves a compatible checkpoint intact.
            return Self::Preserve;
        }

        // A provider owns one checkpoint. Keep a prefix valid for the deployed
        // runtime and for the newer runtime that leaves two mutable chat suffix
        // chunks; every older routing hint is thereby discarded.
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
            Self::Preserve => {}
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

struct PaidGateway {
    providers: Vec<Arc<Provider>>,
    next: AtomicUsize,
    endpoint: Endpoint,
    settlement_key: Secp256k1Signer,
    admission: Arc<Semaphore>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    followers: Mutex<Vec<JoinHandle<()>>>,
}

pub async fn load_gateway_backend(
    path: &Path,
    transport_key: SecretKey,
    settlement_key: Secp256k1Signer,
) -> CliResult<Arc<dyn PaidExecutionBackend>> {
    let bytes =
        crate::commands::read_bounded_regular_file(path, "paid gateway config", MAX_RECORD_BYTES)?;
    let file: PoolFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid paid gateway config {}", path.display()))?;
    anyhow::ensure!(
        !file.providers.is_empty(),
        "paid gateway requires at least one provider"
    );
    anyhow::ensure!(
        file.timeout_secs > 0,
        "paid gateway timeout_secs must be greater than zero"
    );
    anyhow::ensure!(
        file.acceptance_blocks > 0 && file.terminal_blocks > 0 && file.payment_blocks > 0,
        "paid gateway deadline spans must be greater than zero"
    );
    anyhow::ensure!(
        file.max_pending_requests > 0 && file.max_pending_requests <= Semaphore::MAX_PERMITS,
        "paid gateway max_pending_requests must be a positive supported semaphore capacity"
    );
    let mut providers = Vec::new();
    let mut journals = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    let mut funding = std::collections::BTreeSet::new();
    for provider in file.providers {
        anyhow::ensure!(
            provider.work_config.is_absolute() && provider.journal_root.is_absolute(),
            "paid gateway work_config and journal_root must be absolute runtime paths"
        );
        anyhow::ensure!(
            journals.insert(provider.journal_root.clone()),
            "paid providers must have distinct journal roots"
        );
        anyhow::ensure!(
            endpoints.insert(provider.provider),
            "paid gateway repeats provider {}",
            provider.provider
        );
        anyhow::ensure!(
            !provider.payment_coins.is_empty(),
            "paid provider needs payment_coins"
        );
        coins(&provider.payment_coins)?;
        edge_id("bond", &provider.bond)?;
        for coin in &provider.payment_coins {
            anyhow::ensure!(
                funding.insert(fixed_hex::<32>("payment_coins", coin)?),
                "a payment coin cannot fund two provider channels"
            );
        }
        let config = load_work_config(&provider.work_config)?;
        providers.push(Arc::new(Provider {
            policy: config.provider_policy(),
            args: RunArgs {
                work_config: provider.work_config,
                journal_root: provider.journal_root,
                provider: provider.provider,
                provider_addrs: provider.provider_addrs,
                bond: provider.bond,
                payment_coins: provider.payment_coins,
                omission_bond: provider.omission_bond,
                prepared_input: PathBuf::new(),
                output: None,
                acceptance_blocks: file.acceptance_blocks,
                terminal_blocks: file.terminal_blocks,
                payment_blocks: file.payment_blocks,
                timeout_secs: file.timeout_secs,
                settle: false,
            },
            serial: AsyncMutex::new(None),
            pending: AtomicUsize::new(0),
            cache: Mutex::new(PrefixCache::default()),
            unavailable_until: Mutex::new(None),
        }));
    }
    let gateway = Arc::new(PaidGateway {
        admission: Arc::new(Semaphore::new(file.max_pending_requests)),
        providers,
        next: AtomicUsize::new(0),
        // One transport identity has one relay registration, shared by every
        // provider and request for the lifetime of this gateway.
        endpoint: bind_paid_endpoint(transport_key).await?,
        settlement_key,
        tasks: Mutex::new(Vec::new()),
        followers: Mutex::new(Vec::new()),
    });
    // Restart recovery uses the retained input and certificate, never a new job.
    // Empty journal roots do not fund a channel until an HTTP request arrives.
    for provider in &gateway.providers {
        let _recovery = gateway.submit(
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
        );
        let provider = provider.clone();
        gateway.followers.lock().expect("paid followers poisoned").push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut session = provider.serial.lock().await;
                if let Some(session) = session.as_mut() && let Err(error) = session.follow_chain().await {
                    tracing::warn!(provider = %provider.args.provider, %error, "paid channel chain follower will retry");
                }
            }
        }));
    }
    Ok(gateway)
}

impl PaidGateway {
    fn submit(
        &self,
        candidates: Vec<(Arc<Provider>, Route)>,
        prepared: Option<PreparedPaidInputV1>,
        cache_update: Option<CacheUpdate>,
        recovery_timeout: Option<Duration>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> BoxStream<'static, CliResult<ExecutionEvent>> {
        let endpoint = self.endpoint.clone();
        let settlement_key = self.settlement_key.clone();
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let (overflow, overflow_receiver) = watch::channel(false);
        let output_budget = Arc::new(Semaphore::new(OUTPUT_BUFFER_BYTES));
        let (initial_provider, _initial_route) = candidates.first().expect("paid provider exists");
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
        let timeout = recovery_timeout
            .unwrap_or_else(|| Duration::from_secs(initial_provider.args.timeout_secs));
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
                let delta = hellas_rpc::evaluate::decode_token_delta_payload(event.payload())
                    .map_err(|error| hellas_work::work::BackendFault::new(error.to_string()))?;
                let position = delta.end_position().map_err(|error| hellas_work::work::BackendFault::new(error.to_string()))?;
                emit(&token_sender, &token_overflow, &token_budget, Ok(ExecutionEvent::Chunk { position, tokens: delta.token_bytes() }));
                Ok(())
            });
            let result = async {
                let prepared_bytes = prepared.as_ref().map(PreparedPaidInputV1::encode).transpose()?;
                let mut provider_errors = Vec::new();
                for (provider, route) in candidates {
                    let _occupied = occupied.take().or_else(|| {
                        prepared.as_ref().map(|_| ProviderUse::new(provider.clone()))
                    });
                    task_span.record("hellas.provider.id", tracing::field::display(provider.args.provider));
                    task_span.record("hellas.route.cache_affinity_tokens", route.cache_affinity_tokens);
                    task_span.record("hellas.route.pending", route.pending);
                    let mut session = before_proposal(
                        &sender, streamed, &AtomicBool::new(false), deadline,
                        provider.serial.lock().instrument(hellas_rpc::request_span!(target: "hellas_request", "paid.queue")),
                    ).await?;
                    if prepared.is_none() && (!provider.args.journal_root.try_exists()? || std::fs::read_dir(&provider.args.journal_root)?.next().is_none()) {
                        return Ok(Vec::new());
                    }
                    // Recheck after queueing, including restored channels whose
                    // setup journal opened without contacting the provider.
                    if !provider.available() {
                        provider_errors.push(format!("{}: provider is backing off", provider.args.provider));
                        continue;
                    }
                    if session.is_none() {
                        match before_proposal(
                            &sender, streamed, &AtomicBool::new(false), deadline,
                            OpenPaidChannel::open(provider.args.clone(), endpoint.clone(), settlement_key.clone()),
                        ).await.and_then(|result| result)
                        {
                            Ok(opened) => {
                                *session = Some(opened);
                            }
                            Err(error) => {
                                if error.is::<RequestStopped>() { return Err(error); }
                                provider.connection_failed();
                                tracing::warn!(provider = %provider.args.provider, error = %format!("{error:#}"),
                                    "paid provider channel could not be opened");
                                provider_errors.push(format!("{}: {error:#}", provider.args.provider));
                                continue;
                            }
                        }
                    }
                    let session = session.as_mut().expect("channel was opened");
                    if prepared.is_some() && session.needs_recovery {
                        let recovery_deadline = deadline.min(
                            tokio::time::Instant::now() + RECOVERY_ATTEMPT_TIMEOUT,
                        );
                        let recovery = tokio::time::timeout_at(
                            recovery_deadline,
                            session.run(None, true, None),
                        )
                        .await
                        .map_err(|_| anyhow::anyhow!(
                            "retained paid work did not recover within {RECOVERY_ATTEMPT_TIMEOUT:?}"
                        ))
                        .and_then(|result| result);
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
                    let proposal_nonce = session.client.state().proposal_nonce_high_water();
                    let already_proposed = prepared_bytes.as_ref().is_some_and(|input| {
                        session.client.state().jobs().any(|job| job.prepared_input() == input)
                    });
                    let proposed = AtomicBool::new(already_proposed);
                    let result = before_proposal(
                        &sender, streamed, &proposed, deadline,
                        session.run_with_admission(prepared.clone(), true, streamed.then(|| progress.clone()), Some(&proposed)),
                    ).await
                        .and_then(|result| result)
                        .and_then(|output| output.map(output_events).transpose())
                        .map(Option::unwrap_or_default);
                    if let Err(error) = &result {
                        if error.is::<RequestStopped>() && !proposed.load(Ordering::Acquire) {
                            return result;
                        }
                        provider.cache.lock().expect("provider cache poisoned").replace(None);
                        // A failed journal append can leave a durable proposal that
                        // is not reflected in memory yet. Keep that failure with
                        // this provider, just like a proposal with no response.
                        let uncertain_append = matches!(
                            error.downcast_ref::<hellas_work::work::ProposeError>(),
                            Some(hellas_work::work::ProposeError::Store(_)),
                        );
                        if !already_proposed && !uncertain_append
                            && session.client.state().proposal_nonce_high_water() == proposal_nonce
                        {
                            provider.connection_failed();
                            tracing::warn!(provider = %provider.args.provider, error = %format!("{error:#}"),
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
                    return result.with_context(|| format!("paid provider {}", provider.args.provider));
                }
                Err(anyhow::anyhow!(
                    "no eligible paid provider could start this request: {}",
                    provider_errors.join("; ")
                ))
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
                    if !streamed || matches!(event, ExecutionEvent::Done(_)) {
                        emit(&sender, &overflow, &output_budget, Ok(event));
                    }
                },
                Err(error) => { emit(&sender, &overflow, &output_budget, Err(error)); }
            }
        }.instrument(span));
        let mut tasks = self.tasks.lock().expect("paid task list poisoned");
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        response_stream(receiver, overflow_receiver)
    }
}

impl PaidExecutionBackend for PaidGateway {
    fn timeout(&self) -> Duration {
        Duration::from_secs(self.providers[0].args.timeout_secs)
    }

    fn execute(
        &self,
        request: PaidExecutionRequest,
    ) -> CliResult<BoxStream<'static, CliResult<ExecutionEvent>>> {
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| hellas_gateway::PaidGatewayBusy)?;
        let input_ids = request.input_ids.clone();
        let cache_update = CacheUpdate::from_request(&request.environment, &input_ids);
        let prepared = prepare_request(request, &self.settlement_key)?;
        let eligible = self
            .providers
            .iter()
            .filter(|provider| check_policy_input(&provider.policy, &prepared).is_ok())
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !eligible.is_empty(),
            "no provider policy matches this environment, token limit, and stop token list"
        );
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
        Ok(self.submit(
            candidates,
            Some(prepared),
            Some(cache_update),
            None,
            Some(permit),
        ))
    }

    fn drain(&self) -> BoxFuture<'_, ()> {
        self.admission.close();
        for follower in self
            .followers
            .lock()
            .expect("paid followers poisoned")
            .drain(..)
        {
            follower.abort();
        }
        let tasks = std::mem::take(&mut *self.tasks.lock().expect("paid task list poisoned"));
        Box::pin(async move {
            for task in tasks {
                if let Err(error) = task.await {
                    tracing::error!(%error, "paid gateway task failed during shutdown");
                }
            }
            self.endpoint.close().await;
        })
    }
}

fn emit(
    sender: &mpsc::Sender<BufferedEvent>,
    overflow: &watch::Sender<bool>,
    budget: &Arc<Semaphore>,
    event: CliResult<ExecutionEvent>,
) {
    if *overflow.borrow() || sender.is_closed() {
        return;
    }
    let bytes = match &event {
        Ok(ExecutionEvent::Chunk { tokens, .. }) => tokens.len(),
        Ok(ExecutionEvent::Done(Outcome::Completed { output_events, .. })) => output_events
            .iter()
            .map(|event| event.payload().len().saturating_add(OUTPUT_EVENT_OVERHEAD))
            .fold(0usize, usize::saturating_add),
        Ok(ExecutionEvent::Done(_)) => MAX_RECORD_BYTES,
        Err(error) => error.to_string().len(),
    }
    .saturating_add(OUTPUT_EVENT_OVERHEAD);
    let permits = u32::try_from(bytes)
        .ok()
        .and_then(|bytes| budget.clone().try_acquire_many_owned(bytes).ok());
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

fn response_stream(
    mut receiver: mpsc::Receiver<BufferedEvent>,
    mut overflow: watch::Receiver<bool>,
) -> BoxStream<'static, CliResult<ExecutionEvent>> {
    Box::pin(async_stream::try_stream! {
        loop {
            let full = *overflow.borrow();
            if full {
                receiver.close();
                Err(anyhow::anyhow!("paid output consumer is too slow; accepted work continues settlement"))?;
            }
            let event = tokio::select! {
                biased;
                _ = overflow.changed(), if overflow.has_changed().is_ok() => continue,
                event = receiver.recv() => event,
            };
            match event {
                Some((event, permit)) => {
                    drop(permit);
                    yield event?;
                },
                None => return,
            }
        }
    })
}

#[derive(Debug, thiserror::Error)]
enum RequestStopped {
    #[error("paid request disconnected before proposal")]
    Disconnected,
    #[error("paid request deadline elapsed, including queue wait")]
    Deadline,
}

/// Cancel an unproposed HTTP operation without interrupting work whose
/// proposal signature may already have reached a provider.
async fn before_proposal<T>(
    sender: &mpsc::Sender<BufferedEvent>,
    cancel_on_disconnect: bool,
    proposed: &AtomicBool,
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = T>,
) -> CliResult<T> {
    if tokio::time::Instant::now() >= deadline {
        return Err(RequestStopped::Deadline.into());
    }
    let operation = tokio::time::timeout_at(deadline, operation);
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

fn prepare_request(
    request: PaidExecutionRequest,
    signer: &Secp256k1Signer,
) -> CliResult<PreparedPaidInputV1> {
    anyhow::ensure!(
        request.max_new_tokens > 0,
        "max_new_tokens must be greater than zero"
    );
    let manifest = request.environment.manifest();
    hellas_client::iroh::validate_causal_lm_quote_request(
        &hellas_rpc::pb::courtesy::QuoteTokensRequest {
            program_manifest: manifest.canonical_bytes(),
            prompt_token_ids: request.input_ids.clone(),
            max_new_tokens: Some(request.max_new_tokens),
            stop_token_ids: request.stop_token_ids.clone(),
            ..Default::default()
        },
        manifest.content_id(),
        &request.environment,
    )?;
    let tokens = TokenIds::from_u32s(request.input_ids);
    let policy = TextPolicy::from_u32_stop_tokens(request.max_new_tokens, request.stop_token_ids);
    let identity = TextArtifact::identity(BoundTermId::from_digest(manifest.content_id().digest()));
    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        tokens.output_id(),
        policy.output_id(),
    );
    let evaluate = hellas_rpc::EvaluateRequest {
        text_execution: execution.input_id().digest(),
        runner_public_key: hellas_rpc::PublicKey::Secp256k1(signer.party_key().to_bytes()),
        execution_environment: manifest.content_id(),
        nonce: rand::random(),
        assurance: hellas_rpc::Assurance::ProducerSigned,
        retain: true,
    };
    Ok(PreparedPaidInputV1::new(
        &evaluate, &manifest, &execution, &tokens, &policy, &identity,
    ))
}

fn output_events(output: PaidOutput) -> CliResult<Vec<ExecutionEvent>> {
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
    let terminal = verified.terminal;
    let stop_reason =
        if terminal.stop_reason == hellas_rpc::evaluate::EvaluateStopReason::STOP_TOKEN {
            StopReason::StopToken(
                terminal
                    .matched_stop_token_id
                    .context("signed stop-token result omitted its token ID")?,
            )
        } else {
            StopReason::MaxNewTokens
        };
    result.push(ExecutionEvent::Done(Outcome::Completed {
        total_tokens: terminal.usage.billable_units()?,
        stop_reason,
        text_artifact: terminal.text_artifact,
        output_events: events,
    }));
    tracing::info!(
        work_id = %hex::encode(output.work_id.as_bytes()),
        job_price = output.job_price,
        credited_cumulative = output.credited_cumulative,
        result_bytes = output.transcript.len(),
        "paid inference result acknowledged",
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnected_queued_request_never_starts_work() {
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        drop(receiver);
        let started = AtomicBool::new(false);
        let result = before_proposal(
            &sender,
            true,
            &AtomicBool::new(false),
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {
                started.store(true, Ordering::Relaxed);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn disconnect_after_proposal_still_finishes_payment() {
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let proposed = AtomicBool::new(false);
        let (proposal_sent, proposal_seen) = tokio::sync::oneshot::channel();
        let (payment_ready, payment_wait) = tokio::sync::oneshot::channel();
        let work = before_proposal(
            &sender,
            true,
            &proposed,
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {
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
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let proposed = AtomicBool::new(false);
        let (dial_started, dial_seen) = tokio::sync::oneshot::channel();
        let operation = before_proposal(
            &sender,
            true,
            &proposed,
            tokio::time::Instant::now() + Duration::from_secs(1),
            async {
                dial_started.send(()).unwrap();
                std::future::pending::<()>().await;
                proposed.store(true, Ordering::Release);
            },
        );
        let disconnect = async {
            dial_seen.await.unwrap();
            drop(receiver);
        };
        let (result, ()) = tokio::join!(operation, disconnect);
        assert!(result.unwrap_err().is::<RequestStopped>());
        assert!(!proposed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn buffered_reconnect_burst_is_delivered_and_releases_byte_budget() {
        use futures::StreamExt;
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
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
        let (sender, receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
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
        let (sender, _receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let serial = AsyncMutex::new(());
        let _busy = serial.lock().await;
        let result = before_proposal(
            &sender,
            true,
            &AtomicBool::new(false),
            tokio::time::Instant::now() + Duration::from_millis(20),
            serial.lock(),
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
        let (sender, _receiver) = mpsc::channel(OUTPUT_BUFFER_EVENTS);
        let started = AtomicBool::new(false);
        let result = before_proposal(
            &sender,
            true,
            &AtomicBool::new(false),
            tokio::time::Instant::now(),
            async {
                started.store(true, Ordering::Relaxed);
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!started.load(Ordering::Relaxed));
    }

    #[test]
    fn replacing_the_checkpoint_forgets_an_evicted_conversation() {
        let first = vec![7; MIN_CACHE_AFFINITY_TOKENS];
        let second = vec![9; MIN_CACHE_AFFINITY_TOKENS];
        let mut cache = PrefixCache::default();
        cache.replace(Some(first.clone()));
        cache.replace(Some(second.clone()));

        assert_eq!(cache.affinity(&first), 0);
        assert_eq!(cache.affinity(&second), MIN_CACHE_AFFINITY_TOKENS);
    }

    #[test]
    fn one_chunk_side_requests_preserve_a_checkpoint() {
        let conversation = vec![9; MIN_CACHE_AFFINITY_TOKENS];
        let mut cache = PrefixCache::default();
        cache.replace(Some(conversation.clone()));
        CacheUpdate::Preserve.apply(&mut cache);

        assert_eq!(cache.affinity(&conversation), conversation.len());
    }
}
