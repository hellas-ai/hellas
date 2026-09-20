//! Stream-shaped execution layer.
//!
//! The fundamental shape: every layer returns
//! `impl Stream<Item = Result<ExecutionEvent, ClientError>>` or
//! `impl Stream<Item = Result<FetchExecutionEvent, ClientError>>`. Drop-cancellation
//! propagates naturally — when a consumer drops the stream, the generator
//! is dropped, which drops every in-flight future, which drops every
//! resource, which (for local executions) drops the per-execution
//! `mpsc::Receiver` the worker pushes chunks into. The worker observes
//! the closed channel on its next chunk send and converts it into a
//! cancel that the runner sees between generation steps.
//!
//! ```text
//! ExecutionRequest::stream  →  PreparedExecution::stream
//!                                ├─ primary: PreparedRoute::stream
//!                                │   ├─ Local:        local stream over ExecutorHandle
//!                                │   ├─ RemoteDirect: ExecuteClientImpl over IrohTransport
//!                                │   └─ RemoteDiscovery: discover, quote, then execute
//!                                └─ shadow (verify):  same shape, run after primary
//! ```
//!
//! Remote transport lives in `crate::iroh`. This module binds token-native
//! execution to local or remote runtimes, with optional replay and independent
//! verification. Tokenizers and HTTP response shaping belong to callers.

use crate::ClientError as ExecutionError;
use crate::ExecutionRuntime as ClientExecutionRuntime;
use crate::signed_run_ticket_request;
use crate::{ClientResult as ExecutionResult, ExecutionRoute};
use crate::{
    EvaluateChunkVerifier, EvaluateExecutionEvent as ClientEvaluateEvent,
    EvaluateOutcome as ClientEvaluateOutcome, verify_evaluate_work_event,
};
use async_stream::try_stream;
use futures::StreamExt;
use futures::stream::BoxStream;
use futures::stream::Stream;
#[cfg(feature = "local")]
use hellas_executor::ExecutorHandle;
use hellas_rpc::ContentId;
#[cfg(test)]
use hellas_rpc::Digest;
use hellas_rpc::InputCommitment;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::PublicKey;
use hellas_rpc::Retention;
use hellas_rpc::evaluate::EvaluateStopReason;
use hellas_rpc::pb::courtesy::{
    EvaluateGenesisStart, EvaluateStart, QuoteTokensRequest, evaluate_start,
};
use hellas_rpc::pb::execute::Ticket;
use hellas_rpc::pb::execute::WorkEvent;
use hellas_rpc::protocol::artifacts::TextExecutionId;
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::execute::ExecuteClientImpl;
use hellas_wire::WireStatus;
use hellas_wire::iroh::IrohTransport;
#[cfg(feature = "local")]
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "local")]
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument;

/// A verified application terminal still needs the wire End frame so its
/// trailer can be checked. Once no further application event is legal, a
/// hostile peer gets only this finite grace period to supply it.
const REMOTE_TERMINAL_TRAILER_TIMEOUT: Duration = Duration::from_secs(30);

async fn next_remote_execute_item<S>(
    stream: &mut S,
    terminal_seen: bool,
    timeout: Duration,
) -> ExecutionResult<Option<S::Item>>
where
    S: Stream + Unpin,
{
    if !terminal_seen {
        return Ok(stream.next().await);
    }
    tokio::time::timeout(timeout, stream.next())
        .await
        .map_err(|source| {
            ExecutionError::source(
                "remote peer withheld the wire trailer after its terminal outcome",
                source,
            )
        })
}

#[cfg(feature = "local")]
trait ExecutionContext<T> {
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T>;
}

#[cfg(feature = "local")]
impl<T, E> ExecutionContext<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn exec_context(self, context: impl Into<String>) -> ExecutionResult<T> {
        self.map_err(|source| ExecutionError::source(context, source))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionStrategy {
    /// Consult the inference cache without constructing an execution route.
    Replay,
    Run(ExecutionRoute),
    Verify {
        primary: ExecutionRoute,
        shadow: ExecutionRoute,
    },
}

#[cfg(feature = "local")]
pub type CliRuntime = ClientExecutionRuntime<ExecutorHandle>;
#[cfg(not(feature = "local"))]
pub type CliRuntime = ClientExecutionRuntime<()>;

// ---------------------------------------------------------------------------
// Stream item types
// ---------------------------------------------------------------------------

pub use hellas_rpc::cache::{
    EvaluateEvent as ExecutionEvent, EvaluateOutcome as Outcome, EvaluateStop as StopReason,
};

#[cfg(feature = "local")]
fn require_local_executor(runtime: &CliRuntime) -> ExecutionResult<ExecutorHandle> {
    runtime.local_state().cloned().ok_or_else(|| {
        ExecutionError::protocol("local execution requested but no local executor is configured")
    })
}

fn ticket_assurance(ticket: &Ticket) -> ExecutionResult<hellas_rpc::Assurance> {
    hellas_rpc::run_ticket::job_terms_from_pb(ticket)
        .map(|terms| terms.assurance)
        .map_err(|source| ExecutionError::source("invalid evaluate ticket terms", source))
}

fn validate_evaluate_ticket(ticket: &Ticket, requested: i32) -> ExecutionResult<()> {
    let requested = hellas_rpc::run_ticket::assurance_from_pb(requested)
        .map_err(|source| ExecutionError::source("invalid requested assurance", source))?;
    if ticket_assurance(ticket)? == requested {
        Ok(())
    } else {
        Err(ExecutionError::protocol(
            "evaluate ticket assurance does not match request",
        ))
    }
}

// ---------------------------------------------------------------------------
// ExecutionRequest — public entry point
// ---------------------------------------------------------------------------

pub struct ExecutionRequest {
    runtime: CliRuntime,
    quote_req: QuoteTokensRequest,
    expected_manifest_id: ContentId,
    expected_environment: hellas_rpc::CausalLmEnvironment,
    strategy: ExecutionStrategy,
    runner_key: Arc<ProducerSigningKey>,
    cache: Option<Arc<crate::cache::OutputCache>>,
}

/// Canonical Catena causal-LM bodies checked against an out-of-band manifest
/// pin.
///
/// This contains only trusted token-native execution data. In particular it
/// does not contain a tokenizer, chat template, text decoder, model label, GPU
/// target, or acquisition hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalLmExecutionEnvironment {
    manifest_id: ContentId,
    program_manifest: Arc<[u8]>,
    environment: hellas_rpc::CausalLmEnvironment,
}

impl CausalLmExecutionEnvironment {
    /// Admits the one strict generic manifest spelling and the exact canonical
    /// causal-LM environment rooted by it.
    ///
    /// `expected_manifest_id` is an independent caller pin. The supplied
    /// manifest cannot select its own trusted identity merely by hashing
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] when either body is non-canonical, the
    /// manifest is outside the caller's pin, the application pair is not the
    /// Catena causal-LM contract, or the manifest root does not name the
    /// environment bytes.
    pub fn from_canonical_bytes(
        expected_manifest_id: ContentId,
        program_manifest: Vec<u8>,
        environment: Vec<u8>,
    ) -> ExecutionResult<Self> {
        let environment = crate::iroh::validate_causal_lm_environment(
            expected_manifest_id,
            &program_manifest,
            &environment,
        )?;
        Ok(Self {
            manifest_id: expected_manifest_id,
            program_manifest: program_manifest.into(),
            environment,
        })
    }

    /// Returns the content ID of the exact canonical program manifest.
    #[must_use]
    pub const fn manifest_id(&self) -> ContentId {
        self.manifest_id
    }

    /// Returns the canonical environment used to prepare this execution.
    pub fn environment(&self) -> &hellas_rpc::CausalLmEnvironment {
        &self.environment
    }
}

pub(super) fn genesis_text_execution_id(
    manifest: ContentId,
    prompt: &[u32],
    max_tokens: u32,
    stop_tokens: &[u32],
) -> hellas_rpc::Digest {
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextExecution,
        TextPolicy, TokenIds,
    };
    let identity = TextArtifact::identity(BoundTermId::from_digest(manifest.digest()));
    let prompt = TokenIds::from_u32s(prompt.iter().copied());
    let policy = TextPolicy::from_u32_stop_tokens(max_tokens, stop_tokens.iter().copied());
    TextExecution::new(
        SourceRef::output(identity.output_id()),
        prompt.output_id(),
        policy.output_id(),
    )
    .input_id()
    .digest()
}

#[cfg(test)]
pub(crate) fn test_causal_lm_environment(byte: u8) -> CausalLmExecutionEnvironment {
    let environment = hellas_rpc::CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(ContentId::from_bytes([byte; 32]), 1_024),
        "model",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        256,
        1_024,
    )
    .expect("the test causal-LM environment is valid");
    let manifest = environment.manifest();
    CausalLmExecutionEnvironment::from_canonical_bytes(
        manifest.content_id(),
        manifest.canonical_bytes(),
        environment.canonical_bytes(),
    )
    .expect("the test manifest and environment are bound")
}

#[derive(Debug, Clone, Copy)]
pub struct ExecutionRequestOptions {
    pub max_new_tokens: u32,
    pub assurance: hellas_rpc::Assurance,
    pub retention: Retention,
}

#[derive(Clone)]
struct ExpectedTextArtifact {
    execution: TextExecutionId,
    input_ids: Vec<u32>,
    vocabulary_size: u64,
    stop_token_ids: Vec<u32>,
}

fn expected_text_artifact(
    quote_req: &QuoteTokensRequest,
    execution: TextExecutionId,
    environment: &hellas_rpc::CausalLmEnvironment,
) -> ExecutionResult<ExpectedTextArtifact> {
    match quote_req
        .start
        .as_ref()
        .and_then(|start| start.kind.as_ref())
    {
        Some(evaluate_start::Kind::Genesis(_)) => Ok(ExpectedTextArtifact {
            execution,
            input_ids: quote_req.prompt_token_ids.clone(),
            vocabulary_size: environment.vocabulary_size(),
            stop_token_ids: quote_req.stop_token_ids.clone(),
        }),
        Some(evaluate_start::Kind::Artifact(_)) => Err(ExecutionError::protocol(
            "artifact-start evaluate requires verified prior state tokens and is not exposed by this client",
        )),
        None => Err(ExecutionError::protocol(
            "evaluate request is missing its start state",
        )),
    }
}

impl ExecutionRequest {
    pub fn new(
        runtime: CliRuntime,
        environment: CausalLmExecutionEnvironment,
        prompt_token_ids: Vec<u32>,
        stop_token_ids: Vec<u32>,
        options: ExecutionRequestOptions,
        strategy: ExecutionStrategy,
        runner_key: ProducerSigningKey,
    ) -> ExecutionResult<Self> {
        if stop_token_ids.len() > hellas_rpc::MAX_STOP_TOKEN_IDS {
            return Err(ExecutionError::protocol(format!(
                "stop token list has {} entries, over the limit of {}",
                stop_token_ids.len(),
                hellas_rpc::MAX_STOP_TOKEN_IDS
            )));
        }
        let mut stop_token_ids = stop_token_ids;
        hellas_rpc::normalize_stop_token_ids(&mut stop_token_ids);
        let quote_req = QuoteTokensRequest {
            program_manifest: environment.program_manifest.as_ref().to_vec(),
            prompt_token_ids,
            max_new_tokens: Some(options.max_new_tokens),
            stop_token_ids,
            start: Some(EvaluateStart {
                kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
            }),
            runner_public_key: Some(crate::runner_public_key(&runner_key)),
            assurance: options.assurance.to_byte().into(),
            retain: Some(options.retention.should_retain()),
        };
        crate::iroh::validate_causal_lm_quote_request(
            &quote_req,
            environment.manifest_id,
            &environment.environment,
        )?;
        Ok(Self {
            runtime,
            quote_req,
            expected_manifest_id: environment.manifest_id,
            expected_environment: environment.environment,
            strategy,
            runner_key: Arc::new(runner_key),
            cache: None,
        })
    }

    /// True if any leg of this strategy talks to a remote executor.
    pub fn uses_remote_transport(&self) -> bool {
        #[cfg(feature = "local")]
        let is_remote = |r: &ExecutionRoute| !matches!(r, ExecutionRoute::Local);
        #[cfg(not(feature = "local"))]
        let is_remote = |_r: &ExecutionRoute| true;
        match &self.strategy {
            ExecutionStrategy::Replay => false,
            ExecutionStrategy::Run(route) => is_remote(route),
            ExecutionStrategy::Verify { primary, shadow } => {
                is_remote(primary) || is_remote(shadow)
            }
        }
    }

    /// Attach a shared inference cache. Input identity is independent of the
    /// runtime, tokenizer, caller key, and provider ticket nonce.
    pub fn with_cache(mut self, cache: Option<Arc<crate::cache::OutputCache>>) -> Self {
        self.cache = cache;
        self
    }

    /// Check the cache, then quote only on a permitted miss. Preparation
    /// exposes provenance before the caller starts sending response headers.
    pub async fn prepare(self) -> ExecutionResult<PreparedExecution> {
        use crate::cache::CacheKey;
        let key = CacheKey::evaluate(genesis_text_execution_id(
            self.expected_manifest_id,
            &self.quote_req.prompt_token_ids,
            self.quote_req
                .max_new_tokens
                .expect("explicit decode limit"),
            &self.quote_req.stop_token_ids,
        ));
        if self.cache.is_some() && matches!(self.strategy, ExecutionStrategy::Verify { .. }) {
            return Err(ExecutionError::protocol(
                "verification requires live execution; disable inference caching",
            ));
        }
        let guard = if let Some(cache) = &self.cache {
            if let Some(entry) = cache
                .read::<ExecutionEvent, ExecutionProvenance>(key.clone())
                .await?
            {
                return Ok(PreparedExecution::replay(entry));
            }
            let guard = cache.acquire(&key).await?;
            if let Some(entry) = cache
                .read::<ExecutionEvent, ExecutionProvenance>(key.clone())
                .await?
            {
                return Ok(PreparedExecution::replay(entry));
            }
            Some(guard)
        } else {
            None
        };
        let (primary_route, shadow_route) = match self.strategy {
            ExecutionStrategy::Run(route) => (route, None),
            ExecutionStrategy::Verify { primary, shadow } => (primary, Some(shadow)),
            ExecutionStrategy::Replay => {
                return Err(ExecutionError::protocol(
                    "replay requires a cached inference result",
                ));
            }
        };
        let primary = PreparedRoute::prepare(
            &self.runtime,
            &self.quote_req,
            self.expected_manifest_id,
            &self.expected_environment,
            &primary_route,
            self.runner_key.clone(),
        )
        .await?;
        let shadow = if let Some(route) = shadow_route {
            Some(
                PreparedRoute::prepare(
                    &self.runtime,
                    &self.quote_req,
                    self.expected_manifest_id,
                    &self.expected_environment,
                    &route,
                    self.runner_key.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        let provenance = primary.provenance().cloned();
        let runtime = self.runtime;
        let inner =
            reconcile_execution_streams(primary.stream(), shadow.map(PreparedRoute::stream));
        let events = Box::pin(try_stream! {
            let _runtime = runtime;
            let mut inner = inner;
            while let Some(event) = inner.next().await {
                yield event?;
            }
        });
        let events = match (self.cache, guard) {
            (Some(cache), Some(guard)) => cache.record(key, provenance.clone(), events, guard),
            _ => events,
        };
        Ok(PreparedExecution { provenance, events })
    }

    /// Drive this request to completion as a stream of events.
    ///
    /// Owning consumption: dropping the returned stream cancels everything
    /// downstream (broadcast subscribers, wire streams, the executor's
    /// per-running cancel token).
    pub fn stream(self) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
        try_stream! {
            let prepared = self.prepare().await?;
            let inner = prepared.stream();
            tokio::pin!(inner);
            while let Some(event) = inner.next().await {
                yield event?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PreparedExecution — primary + optional shadow for Verify
// ---------------------------------------------------------------------------

pub struct PreparedExecution {
    provenance: Option<ExecutionProvenance>,
    events: BoxStream<'static, ExecutionResult<ExecutionEvent>>,
}

impl PreparedExecution {
    fn replay(entry: crate::cache::Transcript<ExecutionEvent, ExecutionProvenance>) -> Self {
        Self {
            provenance: entry.initial_provenance,
            events: Box::pin(futures::stream::iter(entry.events.into_iter().map(Ok))),
        }
    }

    pub fn provenance(&self) -> Option<&ExecutionProvenance> {
        self.provenance.as_ref()
    }

    pub fn stream(self) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        self.events
    }
}

impl crate::cache::CacheEvent for ExecutionEvent {
    fn terminal(&self) -> Option<bool> {
        match self {
            Self::Chunk { .. } => None,
            Self::Done(Outcome::Completed { .. }) => Some(true),
            Self::Done(Outcome::Failed { .. }) => Some(false),
        }
    }
}

fn reconcile_execution_streams(
    primary: BoxStream<'static, ExecutionResult<ExecutionEvent>>,
    shadow: Option<BoxStream<'static, ExecutionResult<ExecutionEvent>>>,
) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
    Box::pin(try_stream! {
        match shadow {
            None => {
                let mut primary = primary;
                while let Some(event) = primary.next().await {
                    yield event?;
                }
            }
            Some(shadow) => {
                let mut buffered = Vec::new();
                let mut primary_token_bytes = Vec::new();
                let mut primary = primary;
                let mut primary_done: Option<Outcome> = None;
                while let Some(event) = primary.next().await {
                    match event? {
                        ExecutionEvent::Chunk { position, tokens } => {
                            primary_token_bytes.extend_from_slice(&tokens);
                            buffered.push(ExecutionEvent::Chunk { position, tokens });
                        }
                        ExecutionEvent::Done(outcome) => {
                            primary_done = Some(outcome);
                            break;
                        }
                    }
                }
                let primary_outcome = primary_done
                    .ok_or_else(|| ExecutionError::protocol("primary stream ended without terminal outcome"))?;

                let final_outcome =
                    verify_shadow(primary_outcome, primary_token_bytes, shadow).await?;
                if matches!(final_outcome, Outcome::Completed { .. }) {
                    for event in buffered {
                        yield event;
                    }
                }
                yield ExecutionEvent::Done(final_outcome);
            }
        }
    })
}

/// Run the shadow stream to completion, compare its verified token sequence
/// and terminal artifact with the primary, and return the reconciled outcome.
async fn verify_shadow(
    primary: Outcome,
    primary_token_bytes: Vec<u8>,
    shadow: BoxStream<'static, ExecutionResult<ExecutionEvent>>,
) -> ExecutionResult<Outcome> {
    let (primary_digest, primary_stop_reason, primary_total_tokens) = match &primary {
        Outcome::Completed {
            text_artifact,
            stop_reason,
            total_tokens,
            ..
        } => (*text_artifact, *stop_reason, *total_tokens),
        Outcome::Failed { .. } => return Ok(primary),
    };
    let primary_output_tokens = token_count(&primary_token_bytes)?;

    let (shadow_token_bytes, shadow_outcome) = drain_to_outcome(shadow).await?;
    match shadow_outcome {
        Outcome::Completed {
            text_artifact: shadow_digest,
            stop_reason: shadow_stop_reason,
            total_tokens: shadow_total_tokens,
            ..
        } => {
            if primary_token_bytes != shadow_token_bytes {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: "verify mismatch: primary and shadow emitted different token sequences"
                        .to_string(),
                })
            } else if primary_digest != shadow_digest {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: format!(
                        "verify mismatch: primary evaluate artifact {primary_digest} != shadow evaluate artifact {shadow_digest}"
                    ),
                })
            } else if primary_stop_reason != shadow_stop_reason
                || primary_total_tokens != shadow_total_tokens
            {
                Ok(Outcome::Failed {
                    position: primary_output_tokens,
                    error: "verify mismatch: primary and shadow terminal semantics differ"
                        .to_string(),
                })
            } else {
                Ok(primary)
            }
        }
        Outcome::Failed {
            error: shadow_error,
            ..
        } => Ok(Outcome::Failed {
            position: primary_output_tokens,
            error: format!("shadow verification failed: {shadow_error}"),
        }),
    }
}

fn token_count(bytes: &[u8]) -> ExecutionResult<u64> {
    if !bytes.len().is_multiple_of(std::mem::size_of::<u32>()) {
        return Err(ExecutionError::protocol(
            "execution stream carried malformed token bytes",
        ));
    }
    u64::try_from(bytes.len() / std::mem::size_of::<u32>())
        .map_err(|_| ExecutionError::protocol("execution token count exceeds u64 range"))
}

/// Consume a stream to its terminal `Done`, retaining its canonical token
/// sequence independently of chunk boundaries.
async fn drain_to_outcome(
    stream: impl Stream<Item = ExecutionResult<ExecutionEvent>>,
) -> ExecutionResult<(Vec<u8>, Outcome)> {
    tokio::pin!(stream);
    let mut token_bytes = Vec::new();
    while let Some(event) = stream.next().await {
        match event? {
            ExecutionEvent::Chunk { tokens, .. } => token_bytes.extend_from_slice(&tokens),
            ExecutionEvent::Done(outcome) => return Ok((token_bytes, outcome)),
        }
    }
    Err(ExecutionError::protocol(
        "shadow stream ended without terminal outcome",
    ))
}

// ---------------------------------------------------------------------------
// PreparedRoute
// ---------------------------------------------------------------------------

#[allow(clippy::large_enum_variant)]
enum PreparedRoute {
    #[cfg(feature = "local")]
    Local {
        handle: ExecutorHandle,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
        producer_key: PublicKey,
        max_new_tokens: u32,
        expected_text_artifact: ExpectedTextArtifact,
    },
    RemoteDirect {
        transport: IrohTransport,
        ticket: Ticket,
        provenance: ExecutionProvenance,
        runner_key: Arc<ProducerSigningKey>,
        producer_key: PublicKey,
        max_new_tokens: u32,
        expected_text_artifact: ExpectedTextArtifact,
    },
}

impl PreparedRoute {
    fn provenance(&self) -> Option<&ExecutionProvenance> {
        match self {
            #[cfg(feature = "local")]
            PreparedRoute::Local { provenance, .. } => Some(provenance),
            PreparedRoute::RemoteDirect { provenance, .. } => Some(provenance),
        }
    }

    #[instrument(skip_all, fields(?route))]
    async fn prepare(
        runtime: &CliRuntime,
        quote_req: &QuoteTokensRequest,
        expected_manifest_id: ContentId,
        expected_environment: &hellas_rpc::CausalLmEnvironment,
        route: &ExecutionRoute,
        runner_key: Arc<ProducerSigningKey>,
    ) -> ExecutionResult<Self> {
        match route {
            ExecutionRoute::Local => {
                #[cfg(not(feature = "local"))]
                return Err(ExecutionError::protocol(
                    "local execution requested but no local executor is configured",
                ));
                #[cfg(feature = "local")]
                {
                    let handle = require_local_executor(runtime)?;
                    let outcome = handle
                        .quote_tokens(quote_req.clone())
                        .await
                        .exec_context("local quote_tokens failed")?;
                    let provenance = outcome.provenance.clone();
                    let validated = crate::iroh::validate_evaluate_quote_response(
                        quote_req,
                        expected_manifest_id,
                        expected_environment,
                        outcome.response,
                        None,
                    )?;
                    let provenance = crate::iroh::validate_evaluate_quote_provenance(
                        &validated.ticket,
                        provenance,
                    )?;
                    let expected_text_artifact = expected_text_artifact(
                        quote_req,
                        validated.text_execution,
                        expected_environment,
                    )?;
                    Ok(Self::Local {
                        handle,
                        ticket: validated.ticket,
                        provenance,
                        runner_key,
                        producer_key: validated.producer_key,
                        max_new_tokens: quote_req
                            .max_new_tokens
                            .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                        expected_text_artifact,
                    })
                }
            }
            ExecutionRoute::RemoteDirect(target) => {
                let (transport, ticket, provenance, producer_key, text_execution) =
                    crate::iroh::quote_tokens(
                        runtime,
                        target,
                        quote_req,
                        expected_manifest_id,
                        expected_environment,
                    )
                    .await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                Ok(Self::RemoteDirect {
                    transport,
                    ticket,
                    provenance,
                    runner_key,
                    producer_key,
                    max_new_tokens: quote_req
                        .max_new_tokens
                        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                    expected_text_artifact: expected_text_artifact(
                        quote_req,
                        text_execution,
                        expected_environment,
                    )?,
                })
            }
            ExecutionRoute::RemoteDiscovery {
                retries,
                provider_trust,
            } => {
                let (transport, ticket, provenance, producer_key, text_execution) =
                    crate::iroh::discover_and_quote(
                        runtime.remote_registry()?,
                        quote_req,
                        expected_manifest_id,
                        expected_environment,
                        *retries,
                        provider_trust,
                    )
                    .await?;
                validate_evaluate_ticket(&ticket, quote_req.assurance)?;
                Ok(Self::RemoteDirect {
                    transport,
                    ticket,
                    provenance,
                    runner_key,
                    producer_key,
                    max_new_tokens: quote_req
                        .max_new_tokens
                        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS),
                    expected_text_artifact: expected_text_artifact(
                        quote_req,
                        text_execution,
                        expected_environment,
                    )?,
                })
            }
        }
    }

    fn stream(self) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        match self {
            #[cfg(feature = "local")]
            PreparedRoute::Local {
                handle,
                ticket,
                provenance: _,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            } => local_execute_stream(
                handle,
                ticket,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            )
            .boxed(),
            PreparedRoute::RemoteDirect {
                transport,
                ticket,
                provenance: _,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            } => remote_execute_stream(
                transport,
                ticket,
                runner_key,
                producer_key,
                max_new_tokens,
                expected_text_artifact,
            )
            .boxed(),
        }
    }
}

// ---------------------------------------------------------------------------
// Local execute streams — talk directly to `ExecutorHandle`
// ---------------------------------------------------------------------------

#[cfg(feature = "local")]
fn local_execute_stream(
    handle: ExecutorHandle,
    ticket: Ticket,
    runner_key: Arc<ProducerSigningKey>,
    producer_key: PublicKey,
    max_new_tokens: u32,
    expected_text_artifact: ExpectedTextArtifact,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let request_commitment = ticket.request_commitment.clone();
        let assurance = ticket_assurance(&ticket)?;
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let outcome = handle
            .run_ticket_handle(run_ticket)
            .await
            .exec_context("failed to start local execution stream")?;
        let _provenance = outcome.provenance; // already surfaced from PreparedRoute::Local
        let input_commitment =
            crate::evaluate_input_from_request_commitment(&request_commitment)?;
        let verifier = EvaluateChunkVerifier::new(
            input_commitment,
            assurance,
            producer_key,
            max_new_tokens,
            expected_text_artifact.vocabulary_size,
            expected_text_artifact.stop_token_ids,
        )
        .with_text_artifact_expectation(
            expected_text_artifact.execution,
            expected_text_artifact.input_ids,
        );
        let verified = verified_local_execute_stream(
            ReceiverStream::new(outcome.events),
            input_commitment,
            verifier,
        );
        futures::pin_mut!(verified);
        while let Some(event) = verified.next().await {
            yield event?;
        }
        // Keep the handle alive for the lifetime of the stream so the
        // worker's per-execution sender doesn't trip the channel-closed
        // cancel path before the terminal event flushes.
        drop(handle);
    }
}

#[cfg(feature = "local")]
fn verified_local_execute_stream(
    mut events: ReceiverStream<Result<WorkEvent, WireStatus>>,
    input_commitment: InputCommitment,
    mut verifier: EvaluateChunkVerifier,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let mut terminal = None;
        while let Some(item) = events.next().await {
            if terminal.is_some() {
                Err(ExecutionError::protocol(
                    "local execution stream emitted an item after its terminal outcome"
                ))?;
            }
            let wire = item.map_err(|status| {
                ExecutionError::wire("local execution stream failed", status)
            })?;
            match convert_wire_event(wire, input_commitment, &mut verifier)? {
                ExecutionEvent::Chunk { position, tokens } => {
                    yield ExecutionEvent::Chunk { position, tokens };
                }
                ExecutionEvent::Done(outcome) => terminal = Some(outcome),
            }
        }
        let terminal = terminal.ok_or_else(|| {
            ExecutionError::protocol("local execution stream ended without terminal outcome")
        })?;
        yield ExecutionEvent::Done(terminal);
    }
}

// ---------------------------------------------------------------------------
// Remote execute streams — run on the already Open-bound IrohTransport
// ---------------------------------------------------------------------------

fn remote_execute_stream(
    transport: IrohTransport,
    ticket: Ticket,
    runner_key: Arc<ProducerSigningKey>,
    producer_key: PublicKey,
    max_new_tokens: u32,
    expected_text_artifact: ExpectedTextArtifact,
) -> impl Stream<Item = ExecutionResult<ExecutionEvent>> + Send {
    try_stream! {
        let client = ExecuteClientImpl::new(transport);
        let request_commitment = ticket.request_commitment.clone();
        let assurance = ticket_assurance(&ticket)?;
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let mut wire = client
            .run_ticket(run_ticket)
            .await
            .map_err(|status| ExecutionError::wire("failed to start remote execute stream", status))?;
        let mut terminal = None;
        let input_commitment =
            crate::evaluate_input_from_request_commitment(&request_commitment)?;
        let mut verifier = EvaluateChunkVerifier::new(
            input_commitment,
            assurance,
            producer_key,
            max_new_tokens,
            expected_text_artifact.vocabulary_size,
            expected_text_artifact.stop_token_ids,
        )
        .with_text_artifact_expectation(
            expected_text_artifact.execution,
            expected_text_artifact.input_ids,
        );
        loop {
            let item = next_remote_execute_item(
                &mut wire,
                terminal.is_some(),
                REMOTE_TERMINAL_TRAILER_TIMEOUT,
            )
            .await?;
            let Some(item) = item else {
                break;
            };
            if terminal.is_some() {
                Err(ExecutionError::protocol(
                    "remote execute stream emitted an event after its terminal outcome"
                ))?;
            }
            let event = convert_wire_event(
                item.map_err(|status: WireStatus| ExecutionError::wire("remote execute stream failed", status))?,
                input_commitment,
                &mut verifier,
            )?;
            match event {
                ExecutionEvent::Chunk { position, tokens } => {
                    yield ExecutionEvent::Chunk { position, tokens };
                }
                ExecutionEvent::Done(outcome) => {
                    terminal = Some(outcome);
                }
            }
        }
        // Stream EOF: surface the terminal trailer. A non-Ok trailer
        // (handler aborted mid-stream, transport-level abort, etc.)
        // becomes the call's error.
        wire.finish()
            .map_err(|status| ExecutionError::wire("remote execute stream trailer", status))?;
        let terminal = terminal.ok_or_else(|| {
            ExecutionError::protocol("remote execute stream ended Ok but emitted no Done event")
        })?;
        yield ExecutionEvent::Done(terminal);
        drop(client);
    }
}

// ---------------------------------------------------------------------------
// WorkEvent → execution events
// ---------------------------------------------------------------------------

fn convert_wire_event(
    event: WorkEvent,
    input_commitment: InputCommitment,
    verifier: &mut EvaluateChunkVerifier,
) -> ExecutionResult<ExecutionEvent> {
    match verify_evaluate_work_event(verifier, event, input_commitment)? {
        ClientEvaluateEvent::Chunk { position, tokens } => {
            Ok(ExecutionEvent::Chunk { position, tokens })
        }
        ClientEvaluateEvent::Done(ClientEvaluateOutcome::Completed {
            output,
            output_events,
        }) => Ok(ExecutionEvent::Done(Outcome::Completed {
            total_tokens: output.terminal.billable_units,
            stop_reason: stop_reason_from_evaluate(
                output.terminal.stop_reason,
                output.terminal.matched_stop_token_id,
            )?,
            text_artifact: output.terminal.text_artifact,
            output_events,
        })),
        ClientEvaluateEvent::Done(ClientEvaluateOutcome::Failed { position, error }) => {
            Ok(ExecutionEvent::Done(Outcome::Failed { position, error }))
        }
    }
}

fn stop_reason_from_evaluate(
    value: EvaluateStopReason,
    matched_stop_token_id: Option<u32>,
) -> ExecutionResult<StopReason> {
    match (value.as_u8(), matched_stop_token_id) {
        (1, Some(token_id)) => Ok(StopReason::StopToken(token_id)),
        (2, None) => Ok(StopReason::MaxNewTokens),
        (1, None) => Err(ExecutionError::protocol(
            "evaluate STOP_TOKEN terminal is missing its matched token",
        )),
        (2, Some(_)) => Err(ExecutionError::protocol(
            "evaluate MAX_OUTPUT terminal unexpectedly carries a matched token",
        )),
        (other, _) => Err(ExecutionError::EvaluateTranscript {
            source: hellas_rpc::evaluate::EvaluateProtocolError::UnknownStopReason(other),
        }),
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;
    use futures::stream;

    #[test]
    fn cache_identity_covers_execution_inputs_and_normalizes_stops() {
        let manifest = test_causal_lm_environment(1).manifest_id();
        let identity = genesis_text_execution_id(manifest, &[1], 2, &[3, 4]);
        assert_eq!(
            identity,
            genesis_text_execution_id(manifest, &[1], 2, &[4, 3, 3])
        );
        assert_ne!(
            identity,
            genesis_text_execution_id(
                test_causal_lm_environment(2).manifest_id(),
                &[1],
                2,
                &[3, 4]
            )
        );
        assert_ne!(
            identity,
            genesis_text_execution_id(manifest, &[2], 2, &[3, 4])
        );
        assert_ne!(
            identity,
            genesis_text_execution_id(manifest, &[1], 3, &[3, 4])
        );
        assert_ne!(identity, genesis_text_execution_id(manifest, &[1], 2, &[3]));
    }

    #[tokio::test]
    async fn replay_prepares_without_a_provider_or_local_executor() {
        use crate::cache::{
            CacheKey, CachePolicy, CacheStore, MemoryCacheStore, OutputCache, Transcript,
        };
        let environment = test_causal_lm_environment(1);
        let key = CacheKey::evaluate(genesis_text_execution_id(
            environment.manifest_id(),
            &[1],
            1,
            &[],
        ));
        let store = Arc::new(MemoryCacheStore::default());
        let transcript = Transcript {
            version: 1,
            key: key.clone(),
            initial_provenance: Some(ExecutionProvenance {
                commitment_id: [8; 32],
            }),
            events: vec![
                ExecutionEvent::Chunk {
                    position: 1,
                    tokens: hellas_rpc::encode_token_ids(&[2]),
                },
                ExecutionEvent::Done(completed(1)),
            ],
        };
        store
            .insert(&key, &serde_ipld_dagcbor::to_vec(&transcript).unwrap(), 0)
            .unwrap();
        let cache = Arc::new(OutputCache::new(CachePolicy::ReplayOnly, store));
        let request = |prompt| {
            ExecutionRequest::new(
                CliRuntime::default(),
                environment.clone(),
                vec![prompt],
                Vec::new(),
                ExecutionRequestOptions {
                    max_new_tokens: 1,
                    assurance: hellas_rpc::Assurance::ProducerSigned,
                    retention: Retention::Ephemeral,
                },
                ExecutionStrategy::Replay,
                ProducerSigningKey::from_secret_bytes([2; 32]).unwrap(),
            )
            .unwrap()
            .with_cache(Some(cache.clone()))
        };
        let prepared = request(1).prepare().await.unwrap();
        assert_eq!(prepared.provenance().unwrap().commitment_id, [8; 32]);
        assert_eq!(prepared.stream().collect::<Vec<_>>().await.len(), 2);
        let error = request(2)
            .prepare()
            .await
            .err()
            .expect("changed prompt misses");
        assert!(error.to_string().contains("replay miss"));
    }

    fn completed(artifact: u8) -> Outcome {
        Outcome::Completed {
            total_tokens: 2,
            stop_reason: StopReason::MaxNewTokens,
            text_artifact: Digest::from_bytes([artifact; 32]),
            output_events: Vec::new(),
        }
    }

    fn event_stream(
        events: Vec<ExecutionEvent>,
    ) -> BoxStream<'static, ExecutionResult<ExecutionEvent>> {
        Box::pin(stream::iter(events.into_iter().map(Ok)))
    }

    #[test]
    fn explicit_zero_output_limit_is_rejected() {
        let result = ExecutionRequest::new(
            CliRuntime::default(),
            test_causal_lm_environment(1),
            vec![1],
            Vec::new(),
            ExecutionRequestOptions {
                max_new_tokens: 0,
                assurance: hellas_rpc::Assurance::ProducerSigned,
                retention: Retention::Retain,
            },
            ExecutionStrategy::Run(ExecutionRoute::Local),
            ProducerSigningKey::from_secret_bytes([2; 32]).expect("valid test key"),
        );
        let error = match result {
            Ok(_) => panic!("an explicit zero output limit must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn invocation_is_rejected_before_dispatch_when_outside_environment_bounds() {
        let result = ExecutionRequest::new(
            CliRuntime::default(),
            test_causal_lm_environment(1),
            vec![256],
            Vec::new(),
            ExecutionRequestOptions {
                max_new_tokens: 1,
                assurance: hellas_rpc::Assurance::ProducerSigned,
                retention: Retention::Retain,
            },
            ExecutionStrategy::Run(ExecutionRoute::Local),
            ProducerSigningKey::from_secret_bytes([2; 32]).expect("valid test key"),
        );
        let error = match result {
            Ok(_) => panic!("an out-of-vocabulary token must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("vocabulary size"));
    }

    #[tokio::test]
    async fn verification_mismatch_exposes_no_primary_chunks() {
        let tokens = hellas_rpc::encode_token_ids(&[42]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens,
            },
            ExecutionEvent::Done(completed(2)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 1);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Done(Outcome::Failed { error, .. }))
                if error.contains("verify mismatch")
        ));
    }

    #[tokio::test]
    async fn verified_primary_chunks_are_released_after_matching_shadow() {
        let tokens = hellas_rpc::encode_token_ids(&[42]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 2);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Chunk { position: 1, tokens: actual }) if actual == &tokens
        ));
        assert!(matches!(
            &output[1],
            Ok(ExecutionEvent::Done(Outcome::Completed { text_artifact, .. }))
                if *text_artifact == Digest::from_bytes([1; 32])
        ));
    }

    #[tokio::test]
    async fn matching_artifact_claim_cannot_hide_different_shadow_tokens() {
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[42]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[43]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 1);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Done(Outcome::Failed { error, .. }))
                if error.contains("different token sequences")
        ));
    }

    #[tokio::test]
    async fn verification_ignores_honest_chunk_boundaries() {
        let primary_tokens = hellas_rpc::encode_token_ids(&[1, 2]);
        let primary = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 2,
                tokens: primary_tokens.clone(),
            },
            ExecutionEvent::Done(completed(1)),
        ]);
        let shadow = event_stream(vec![
            ExecutionEvent::Chunk {
                position: 1,
                tokens: hellas_rpc::encode_token_ids(&[1]),
            },
            ExecutionEvent::Chunk {
                position: 2,
                tokens: hellas_rpc::encode_token_ids(&[2]),
            },
            ExecutionEvent::Done(completed(1)),
        ]);

        let output = reconcile_execution_streams(primary, Some(shadow))
            .collect::<Vec<_>>()
            .await;
        assert_eq!(output.len(), 2);
        assert!(matches!(
            &output[0],
            Ok(ExecutionEvent::Chunk { position: 2, tokens }) if tokens == &primary_tokens
        ));
        assert!(matches!(
            &output[1],
            Ok(ExecutionEvent::Done(Outcome::Completed { .. }))
        ));
    }
}

#[cfg(test)]
mod remote_lifetime_tests {
    use super::*;
    use crate::{ProviderTrustAnchor, RemoteNodeTarget};
    use futures::stream;
    use hellas_rpc::call::WithTrailer;
    use hellas_rpc::open::{OpenDispatcher, OpenHandler};
    use hellas_rpc::pb::courtesy::{
        GetArtifactRequest, GetArtifactResponse, GetStatsRequest, GetStatsResponse, QuoteResponse,
    };
    use hellas_rpc::pb::execute::{
        OpenRequest, OpenResponse, RunTicketRequest, WorkFailed, open_response, work_event,
    };
    use hellas_rpc::protocol::artifacts::{
        BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextExecution,
        TextPolicy, TokenIds,
    };
    use hellas_rpc::serve::MethodDispatcher;
    use hellas_rpc::services::courtesy::{
        Courtesy, CourtesyHandler, CourtesyServer, Open as CourtesyOpen, QuoteTokens,
    };
    use hellas_rpc::services::execute::{ExecuteHandler, ExecuteServer, RunTicket};
    use hellas_rpc::{
        Assurance, Evaluate, JobTerms, PlatformCredential, PlatformEnrollment, ProgramManifest,
        ProviderEnrollmentBundle, ProviderGenesisStatement, RootKind, RootProof,
        SignedProviderGenesis,
    };
    use hellas_wire::{
        Dispatcher, Metadata, MethodMarker, ServiceMarker, StreamTransport, TransportContext,
    };
    use iroh::endpoint::{Connection, presets};
    use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[derive(Clone)]
    struct FixtureProvider {
        producer: ProducerSigningKey,
        enrollment: ProviderEnrollmentBundle,
    }

    impl FixtureProvider {
        fn new(transport_key: &SecretKey) -> Self {
            let root = ProducerSigningKey::from_secret_bytes([0x53; 32])
                .expect("the fixture root key is valid");
            let producer = ProducerSigningKey::from_secret_bytes([0x54; 32])
                .expect("the fixture producer key is valid");
            let statement = ProviderGenesisStatement {
                root_kind: RootKind::Software,
                root_public_key: root.public_key(),
                producer_public_key: producer.public_key(),
                transport_public_key: PublicKey::Ed25519(*transport_key.public().as_bytes()),
                platform_credential: PlatformCredential::Absent,
                installation_nonce: [0x55; 32],
            };
            let genesis = SignedProviderGenesis {
                root_proof: RootProof::Software(
                    root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                        .expect("the fixture root signs"),
                ),
                statement,
            };
            Self {
                producer,
                enrollment: ProviderEnrollmentBundle {
                    genesis,
                    platform: PlatformEnrollment::Absent,
                },
            }
        }

        fn trust(&self) -> ProviderTrustAnchor {
            ProviderTrustAnchor {
                expected_genesis: self.enrollment.content_id(),
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            }
        }

        fn quote(&self, request: QuoteTokensRequest) -> WithTrailer<QuoteResponse> {
            let manifest = ProgramManifest::from_canonical_bytes(&request.program_manifest)
                .expect("the fixture request has a canonical manifest");
            let execution_environment = manifest.content_id();
            let identity =
                TextArtifact::identity(BoundTermId::from_digest(execution_environment.digest()));
            let prompt = TokenIds::from_u32s(request.prompt_token_ids.iter().copied());
            let max_new_tokens = request
                .max_new_tokens
                .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS);
            let policy = TextPolicy::from_u32_stop_tokens(
                max_new_tokens,
                request.stop_token_ids.iter().copied(),
            );
            let text_execution = TextExecution::new(
                SourceRef::output(identity.output_id()),
                prompt.output_id(),
                policy.output_id(),
            );
            let runner_public_key = hellas_rpc::run_ticket::public_key_from_pb(
                request
                    .runner_public_key
                    .expect("the fixture request has a runner key"),
            )
            .expect("the fixture runner key decodes");
            let assurance = hellas_rpc::run_ticket::assurance_from_pb(request.assurance)
                .expect("the fixture assurance decodes");
            let evaluate = hellas_rpc::EvaluateRequest {
                text_execution: text_execution.input_id().digest(),
                runner_public_key,
                execution_environment,
                nonce: [0x56; 32],
                assurance,
                retain: request.retain.unwrap_or(false),
            };
            let request_commitment = Evaluate::commit_request(&evaluate);
            let provider_genesis = self.enrollment.canonical_bytes();
            let ticket = hellas_rpc::run_ticket::ticket_to_pb(
                JobTerms {
                    request: request_commitment,
                    provider_genesis: self.enrollment.content_id(),
                    assurance,
                    amount: 1,
                    ttl_ms: 1_000,
                },
                provider_genesis,
            )
            .expect("the fixture ticket matches its enrollment");
            let mut metadata = Metadata::new();
            hellas_rpc::provenance::write_provenance_metadata(
                &mut metadata,
                &ExecutionProvenance {
                    commitment_id: *request_commitment.as_bytes(),
                },
            );
            WithTrailer::with_metadata(
                QuoteResponse {
                    ticket: Some(ticket),
                    prompt_tokens: request.prompt_token_ids.len() as u32,
                    evaluate_request: Some(hellas_rpc::pb::evaluate::EvaluateRequest {
                        text_execution: evaluate.text_execution.as_bytes().to_vec(),
                        runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                            &evaluate.runner_public_key,
                        )),
                        execution_environment: evaluate.execution_environment.as_bytes().to_vec(),
                        nonce: evaluate.nonce.to_vec(),
                        assurance: evaluate.assurance.to_byte().into(),
                        retain: Some(evaluate.retain),
                    }),
                },
                metadata,
            )
        }
    }

    impl OpenHandler for FixtureProvider {
        async fn open(
            &self,
            request: OpenRequest,
            context: TransportContext,
            alpn: &'static [u8],
        ) -> Result<OpenResponse, WireStatus> {
            let nonce: [u8; 32] = request
                .nonce
                .try_into()
                .map_err(|_| WireStatus::internal("invalid fixture nonce"))?;
            let exporter = context
                .open_exporter
                .ok_or_else(|| WireStatus::internal("missing fixture exporter"))?;
            let binding = hellas_rpc::open_proof_binding(
                &exporter,
                &nonce,
                &self.enrollment.genesis.statement.producer_public_key,
                self.enrollment.content_id(),
                alpn,
            );
            let signature = self
                .producer
                .sign_digest(binding)
                .map_err(|_| WireStatus::internal("fixture signing failed"))?;
            Ok(OpenResponse {
                provider_genesis: self.enrollment.canonical_bytes(),
                proof: Some(open_response::Proof::ProducerSignature(
                    hellas_rpc::run_ticket::signature_to_pb(&signature),
                )),
            })
        }
    }

    #[allow(refining_impl_trait)]
    impl CourtesyHandler for FixtureProvider {
        async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
            Err(WireStatus::internal("fixture Open dispatcher was bypassed"))
        }

        async fn quote_tokens(
            &self,
            request: QuoteTokensRequest,
        ) -> Result<WithTrailer<QuoteResponse>, WireStatus> {
            Ok(self.quote(request))
        }

        async fn get_artifact(
            &self,
            _request: GetArtifactRequest,
        ) -> Result<GetArtifactResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }

        async fn get_stats(
            &self,
            _request: GetStatsRequest,
        ) -> Result<GetStatsResponse, WireStatus> {
            Err(WireStatus::unimplemented(
                "unused by endpoint lifetime test",
            ))
        }
    }

    #[derive(Clone, Copy)]
    struct ExecuteWitness;

    impl ExecuteHandler for ExecuteWitness {
        async fn run_ticket(
            &self,
            _request: RunTicketRequest,
        ) -> Result<BoxStream<'static, Result<WorkEvent, WireStatus>>, WireStatus> {
            Ok(Box::pin(stream::iter([Ok(WorkEvent {
                kind: Some(work_event::Kind::Failed(WorkFailed {
                    position: 0,
                    error: "execute reached after prepare".to_string(),
                })),
            })])))
        }
    }

    async fn accept_alpn(endpoint: &Endpoint, expected: &'static str) -> Connection {
        let incoming = endpoint
            .accept()
            .await
            .expect("the fixture receives a dial");
        let accepting = incoming.accept().expect("the fixture accepts the dial");
        let connection = accepting.await.expect("the fixture handshake completes");
        assert_eq!(connection.alpn(), expected.as_bytes());
        connection
    }

    #[tokio::test]
    async fn prepared_remote_execution_keeps_endpoint_alive_until_execute() {
        let server_key = SecretKey::from_bytes(&[0x51; 32]);
        let provider = FixtureProvider::new(&server_key);
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(server_key)
            .alpns(vec![Courtesy::ALPN.as_bytes().to_vec()])
            .bind_addr(
                "127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .expect("a loopback socket"),
            )
            .expect("the fixture has a valid bind address")
            .bind()
            .await
            .expect("the fixture server binds");
        let target = EndpointAddr::from_parts(
            server.id(),
            server.bound_sockets().into_iter().map(TransportAddr::Ip),
        );
        let (quote_dispatched, quote_is_dispatched) = oneshot::channel();
        let (release_run_ticket, run_ticket_released) = oneshot::channel();
        let (event_consumed, event_is_consumed) = oneshot::channel();
        let serving_endpoint = server.clone();
        let serving_provider = provider.clone();
        let serving = tokio::spawn(async move {
            let courtesy = IrohTransport::new(accept_alpn(&serving_endpoint, Courtesy::ALPN).await);
            let courtesy_server = OpenDispatcher::<_, _, CourtesyOpen>::new(
                MethodDispatcher::<_, _, RunTicket>::new(
                    ExecuteServer(ExecuteWitness),
                    CourtesyServer(serving_provider.clone()),
                ),
                serving_provider,
            );
            for expected_method in [CourtesyOpen::METHOD_ID, QuoteTokens::METHOD_ID] {
                let inbound = courtesy
                    .accept()
                    .await
                    .expect("Courtesy transport remains live")
                    .expect("Courtesy receives Open and QuoteTokens");
                assert_eq!(inbound.method_id, expected_method);
                Dispatcher::<IrohTransport>::dispatch(&courtesy_server, inbound)
                    .await
                    .expect("Courtesy request dispatches");
            }

            let _ = quote_dispatched.send(());
            let _ = run_ticket_released.await;
            let inbound = courtesy
                .accept()
                .await
                .expect("Courtesy transport remains live after prepare")
                .expect("Courtesy receives RunTicket");
            assert_eq!(inbound.method_id, RunTicket::METHOD_ID);
            Dispatcher::<IrohTransport>::dispatch(&courtesy_server, inbound)
                .await
                .expect("RunTicket dispatches on Courtesy");
            let _ = event_is_consumed.await;
        });

        let runtime = CliRuntime::remote(SecretKey::from_bytes(&[0x52; 32]))
            .await
            .expect("the fixture client binds");
        let request = ExecutionRequest::new(
            runtime,
            test_causal_lm_environment(0x57),
            vec![1, 2],
            Vec::new(),
            ExecutionRequestOptions {
                max_new_tokens: 1,
                assurance: Assurance::ProducerSigned,
                retention: Retention::Ephemeral,
            },
            ExecutionStrategy::Run(ExecutionRoute::RemoteDirect(RemoteNodeTarget {
                addr: target,
                provider_trust: provider.trust(),
            })),
            ProducerSigningKey::from_secret_bytes([0x58; 32])
                .expect("the fixture runner key is valid"),
        )
        .expect("the fixture request is valid");
        let prepared = tokio::time::timeout(Duration::from_secs(10), request.prepare())
            .await
            .expect("remote prepare does not hang")
            .expect("remote quote prepares");
        tokio::time::timeout(Duration::from_secs(10), quote_is_dispatched)
            .await
            .expect("the server reaches its post-quote barrier")
            .expect("the fixture reports that QuoteTokens dispatched");
        tokio::task::yield_now().await;
        let _ = release_run_ticket.send(());

        let mut output = prepared.stream();
        let event = tokio::time::timeout(Duration::from_secs(10), output.next())
            .await
            .expect("Execute response does not hang")
            .expect("Execute returns one terminal event")
            .expect("the fixture failure is a valid terminal event");
        assert!(matches!(
            event,
            ExecutionEvent::Done(Outcome::Failed { position: 0, error })
                if error == "execute reached after prepare"
        ));
        let _ = event_consumed.send(());
        drop(output);
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("the fixture server finishes")
            .expect("the fixture server task succeeds");
        server.close().await;
    }
}

#[cfg(all(test, feature = "local"))]
mod tests {
    use super::*;
    use futures::FutureExt;
    use hellas_rpc::ProducerSigningKey;
    use hellas_rpc::evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment as evaluate_input_commitment,
    };
    use hellas_rpc::pb::execute::{WorkChunk, WorkFinished, work_event};
    use hellas_rpc::stream::output_event_to_pb;
    use tokio::sync::mpsc;

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn evaluate_request(runner: &ProducerSigningKey) -> hellas_rpc::EvaluateRequest {
        hellas_rpc::EvaluateRequest {
            text_execution: Digest::from_bytes([9; 32]),
            runner_public_key: runner.public_key(),
            execution_environment: hellas_rpc::ContentId::from_bytes([8; 32]),
            nonce: [7; 32],
            assurance: hellas_rpc::Assurance::ProducerSigned,
            retain: true,
        }
    }

    fn completed_stream_fixture() -> (InputCommitment, EvaluateChunkVerifier, WorkEvent, WorkEvent)
    {
        let runner = key(1);
        let producer = key(2);
        let request = evaluate_request(&runner);
        let input = evaluate_input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, request.assurance, &producer);
        let token_event = builder.push_token_delta(vec![10, 11]).unwrap();
        let output_events = builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 3,
                    output_units: 2,
                },
                billable_units: 5,
            })
            .unwrap();
        let verifier = EvaluateChunkVerifier::new(
            input,
            request.assurance,
            producer.public_key(),
            3,
            1_000,
            vec![7],
        );
        let chunk = WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&token_event)),
            })),
        };
        let finished = WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: output_events.last().map(output_event_to_pb),
                assurance_evidence: Vec::new(),
            })),
        };
        (input, verifier, chunk, finished)
    }

    #[test]
    fn evaluate_chunk_projects_signed_event() {
        let runner = key(1);
        let producer = key(2);
        let request = evaluate_request(&runner);
        let input = evaluate_input_commitment(&request);
        let mut builder = EvaluateOutputTranscriptBuilder::new(input, request.assurance, &producer);
        let token_event = builder.push_token_delta(vec![10, 11]).unwrap();

        let mut verifier = EvaluateChunkVerifier::new(
            input,
            request.assurance,
            producer.public_key(),
            2,
            1_000,
            vec![7],
        );
        let event = WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&token_event)),
            })),
        };

        let decoded = convert_wire_event(event, input, &mut verifier).unwrap();
        assert!(matches!(
            decoded,
            ExecutionEvent::Chunk {
                position: 2,
                tokens
            } if tokens == hellas_rpc::encode_token_ids(&[10, 11])
        ));
    }

    #[test]
    fn evaluate_finished_verifies_streamed_prefix_and_terminal_event() {
        let (input, mut verifier, chunk, finished) = completed_stream_fixture();
        convert_wire_event(chunk, input, &mut verifier).unwrap();
        let decoded = convert_wire_event(finished, input, &mut verifier).unwrap();
        assert!(matches!(
            decoded,
            ExecutionEvent::Done(Outcome::Completed {
                total_tokens: 5,
                stop_reason: StopReason::StopToken(7),
                ..
            })
        ));
    }

    #[tokio::test]
    async fn remote_terminal_trailer_wait_is_bounded() {
        let mut silent = futures::stream::pending::<()>();
        let error = next_remote_execute_item(&mut silent, true, Duration::ZERO)
            .await
            .expect_err("a peer cannot withhold End forever after a signed terminal");
        assert!(
            error
                .to_string()
                .contains("withheld the wire trailer after its terminal outcome"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn local_stream_retains_terminal_until_eof() {
        let (input, verifier, chunk, finished) = completed_stream_fixture();
        let (sender, receiver) = mpsc::channel(2);
        sender.try_send(Ok(chunk)).unwrap();
        sender.try_send(Ok(finished)).unwrap();
        let stream = verified_local_execute_stream(ReceiverStream::new(receiver), input, verifier);
        futures::pin_mut!(stream);

        assert!(matches!(
            stream.next().await,
            Some(Ok(ExecutionEvent::Chunk { .. }))
        ));
        assert!(
            stream.next().now_or_never().is_none(),
            "the terminal must be retained while the producer can still append"
        );
        drop(sender);
        assert!(matches!(
            stream.next().await,
            Some(Ok(ExecutionEvent::Done(Outcome::Completed { .. })))
        ));
        assert!(stream.next().await.is_none());
    }

    async fn assert_local_suffix_rejected(suffix: Result<WorkEvent, WireStatus>) {
        let (input, verifier, chunk, finished) = completed_stream_fixture();
        let (sender, receiver) = mpsc::channel(2);
        sender.try_send(Ok(chunk)).unwrap();
        sender.try_send(Ok(finished)).unwrap();
        let stream = verified_local_execute_stream(ReceiverStream::new(receiver), input, verifier);
        futures::pin_mut!(stream);

        assert!(matches!(
            stream.next().await,
            Some(Ok(ExecutionEvent::Chunk { .. }))
        ));
        assert!(stream.next().now_or_never().is_none());
        sender.send(suffix).await.unwrap();
        let error = stream
            .next()
            .await
            .expect("the suffix produces a result")
            .expect_err("an item after the terminal must be rejected");
        assert!(error.to_string().contains("after its terminal outcome"));
    }

    #[tokio::test]
    async fn local_stream_rejects_event_and_error_suffixes() {
        let (_, _, chunk, finished) = completed_stream_fixture();
        assert_local_suffix_rejected(Ok(chunk)).await;
        assert_local_suffix_rejected(Ok(finished)).await;
        assert_local_suffix_rejected(Err(WireStatus::internal("late transport failure"))).await;
    }
}
