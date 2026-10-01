//! Presentation-neutral Work stream types and gateway archive integration.
use crate::ClientResult as ExecutionResult;
use futures::stream::BoxStream;
pub use hellas_rpc::cache::{
    EvaluateEvent as ExecutionEvent, EvaluateOutcome as Outcome, EvaluateStop as StopReason,
};
use hellas_rpc::{ContentId, provenance::ExecutionProvenance};
use std::sync::Arc;
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
    /// Returns [`crate::ClientError`] when either body is non-canonical, the
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

    /// The canonical environment used to construct token-native execution.
    pub fn environment(&self) -> &hellas_rpc::CausalLmEnvironment {
        &self.environment
    }
}

/// Canonical input identity shared by native and externally authenticated
/// causal-LM streams. Presentation, payment routing and request nonces do not
/// affect this identity.
pub fn genesis_text_execution_id(
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

type EvaluateStreamSource = (
    Option<ExecutionProvenance>,
    BoxStream<'static, ExecutionResult<ExecutionEvent>>,
);

/// Reuse or record a token-native evaluate stream under its canonical identity.
/// The live source is polled only after a permitted cache miss. Recording uses
/// the same event schema as native execution and publishes only after its
/// successful terminal and EOF; dropping a stream retains the source's own
/// cancellation semantics.
pub async fn prepare_evaluate_stream(
    identity: hellas_rpc::Digest,
    cache: Option<Arc<crate::cache::OutputCache>>,
    live: impl std::future::Future<Output = ExecutionResult<EvaluateStreamSource>>,
) -> ExecutionResult<PreparedExecution> {
    let key = crate::cache::CacheKey::evaluate(identity);
    let guard = if let Some(cache) = &cache {
        if let Some(entry) = cache.read(key.clone()).await? {
            return Ok(PreparedExecution::replay(entry));
        }
        let guard = cache.acquire(&key).await?;
        if let Some(entry) = cache.read(key.clone()).await? {
            return Ok(PreparedExecution::replay(entry));
        }
        Some(guard)
    } else {
        None
    };
    let (provenance, events) = live.await?;
    let events = match (cache, guard) {
        (Some(cache), Some(guard)) => cache.record(key, provenance.clone(), events, guard),
        _ => events,
    };
    Ok(PreparedExecution { provenance, events })
}

// ---------------------------------------------------------------------------
// PreparedExecution — a live or archived verified stream
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

pub fn validate_causal_lm_invocation(
    environment: &hellas_rpc::CausalLmEnvironment,
    prompt: &[u32],
    max_new_tokens: u32,
    stops: &[u32],
) -> crate::ClientResult<()> {
    use crate::ClientError;
    use hellas_rpc::MAX_STOP_TOKEN_IDS;
    if prompt.is_empty() {
        return Err(ClientError::protocol(
            "Evaluate prompt_token_ids must not be empty",
        ));
    }
    if stops.len() > MAX_STOP_TOKEN_IDS {
        return Err(ClientError::protocol(format!(
            "Evaluate has {} stop IDs, over the limit of {MAX_STOP_TOKEN_IDS}",
            stops.len()
        )));
    }
    for (field, tokens) in [("prompt_token_ids", prompt), ("stop_token_ids", stops)] {
        if let Some(token) = tokens
            .iter()
            .copied()
            .find(|token| u64::from(*token) >= environment.vocabulary_size())
        {
            return Err(ClientError::protocol(format!(
                "Evaluate {field} contains token {token}, but the environment vocabulary size is {}",
                environment.vocabulary_size()
            )));
        }
    }

    if max_new_tokens == 0 {
        return Err(ClientError::protocol(
            "Evaluate max_new_tokens must be greater than zero",
        ));
    }
    let total_tokens = u64::try_from(prompt.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(max_new_tokens));
    if total_tokens > environment.maximum_capacity() {
        return Err(ClientError::protocol(format!(
            "Evaluate prompt plus max_new_tokens is {total_tokens} tokens, but the environment capacity is {}",
            environment.maximum_capacity()
        )));
    }
    Ok(())
}
