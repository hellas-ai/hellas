//! Signed artifact chunks and one complete application result.
use hellas_auth::{ProducerSigningKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::{
    Artifact, InvocationRequest, bound, domain_is, encode, error, label, validate_artifacts,
};
use crate::protocol::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{
    CanonicalizationId, ContentId, JsonBytes, Operation, OutputEventEnvelope,
    OutputTranscriptBuilder, scheme_id, verify_output_event_envelopes,
};

pub const ARTIFACT_CHUNK: &str = "invocation.artifact-chunk.v1";
pub const TERMINAL: &str = "invocation.terminal.v1";
pub const FAILURE: &str = "invocation.failed.v1";
// Largest v1 failure payload: [FAILURE, "execution-timeout"]. Live prefixes
// leave this room so an exhausted output budget can still terminate as failed.
const FAILURE_PAYLOAD_BYTES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FailureReason {
    Compilation,
    Execution,
    Cancelled,
    ExecutionTimeout,
    OutputLimit,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    content = "reason",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Outcome {
    Succeeded,
    Failed(FailureReason),
}
const CANONICALIZATION: &[u8] = b"hellas.invocation.output.v1";
const RESULT_DOMAIN: &str = "hellas.invocation.result.v1";
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

pub(super) struct ComputeBounds {
    pub events: u64,
    pub payload: u64,
    pub frame: u64,
    pub spool: u64,
}

fn cbor_header(bytes: u64) -> u64 {
    match bytes {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Reserve the signed output allowance plus its actual codec framing. A step
/// emits one event; final artifacts use MAX_CHUNK_BYTES and may each be empty.
pub(super) fn compute_bounds(limits: super::Limits) -> Result<ComputeBounds, CanonicalDecodeError> {
    use crate::{
        EventCommitment, InputCommitment, OutputEventBody, OutputEventBodyParts, SignedOutputEvent,
        StreamId,
    };
    use hellas_auth::{Digest, ProducerId, Signature};

    let bytes = limits.max_output_bytes;
    let chunks = limits
        .max_steps
        .min(bytes / 8)
        .saturating_add(bytes.div_ceil(MAX_CHUNK_BYTES as u64))
        .saturating_add(super::MAX_ARTIFACTS as u64);
    let events = chunks.saturating_add(1);
    let chunk_bytes = bytes.min(MAX_CHUNK_BYTES as u64);
    let label = "x".repeat(super::MAX_LABEL_BYTES);
    let chunk_framing = encode(&(
        ARTIFACT_CHUNK,
        ArtifactChunk {
            name: label.clone(),
            format: label.clone(),
            offset: u64::MAX,
            bytes: JsonBytes(vec![]),
        },
    ))?
    .len() as u64
        + cbor_header(chunk_bytes)
        - 1;
    let metadata = encode(&super::compute::RunMetadata {
        steps: limits.max_steps,
        stop: Some(super::compute::StopReason::Matched(u64::MAX)),
    })?;
    let terminal_bytes = encode(&(
        TERMINAL,
        Terminal {
            artifacts: (0..super::MAX_ARTIFACTS)
                .map(|_| ArtifactEnd {
                    name: label.clone(),
                    format: label.clone(),
                    bytes,
                    content_id: ContentId::from_bytes([0; 32]),
                })
                .collect(),
            metadata: JsonBytes(metadata),
        },
    ))?
    .len() as u64;
    let maximum_payload = chunk_bytes
        .saturating_add(chunk_framing)
        .max(terminal_bytes);

    // Size the real envelope type. Signature/key contents do not affect their
    // byte-string widths; no signature is produced or trusted here.
    let key = PublicKey::Secp256k1([0; 33]);
    let digest = Digest::from_bytes([0; 32]);
    let body = OutputEventBody::from_parts(OutputEventBodyParts {
        scheme: scheme_id(Operation::Invoke, crate::Assurance::ProducerSigned),
        input: InputCommitment::from_digest(digest),
        stream_id: StreamId::from_digest(digest),
        sequence: u64::MAX,
        previous_event: EventCommitment::from_digest(digest),
        kind: ARTIFACT_CHUNK.into(),
        payload: Digest::hash(&[]),
        signer: ProducerId::from_public_key(&key),
        canonicalization: canonicalization(),
    });
    let event = SignedOutputEvent::from_parts(body, Signature::Secp256k1([0; 64]), key)
        .map_err(|e| error(e.to_string()))?;
    let envelope = OutputEventEnvelope::new(event, vec![]).map_err(|e| error(e.to_string()))?;
    let envelope_framing = encode(&envelope)?.len() as u64 + cbor_header(maximum_payload) - 1;
    // The envelope's Vec<u8> serializes as a CBOR integer array (at most two
    // bytes per byte). Reserve both that wire form and the retained-memory
    // accounting used by incremental verification and grant delivery.
    let event_framing = envelope_framing
        .max((4 * std::mem::size_of::<OutputEventEnvelope>() + ARTIFACT_CHUNK.len()) as u64)
        .max(1024);
    let payload = bytes
        .saturating_add(chunks.saturating_mul(chunk_framing))
        .saturating_add(terminal_bytes);
    Ok(ComputeBounds {
        events,
        payload,
        frame: maximum_payload
            .saturating_mul(2)
            .saturating_add(event_framing),
        spool: payload
            .saturating_mul(2)
            .saturating_add(events.saturating_mul(event_framing))
            .saturating_add(cbor_header(events)),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("invocation result exceeds its byte budget")]
    Limit,
    #[error(transparent)]
    Invalid(#[from] CanonicalDecodeError),
}
fn stream_error(message: impl Into<String>) -> OutputError {
    OutputError::Invalid(error(message))
}

/// The normalized answer: artifact identities and application-owned terminal
/// metadata. Host timings and transport chunk sizes do not enter this value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationOutput {
    pub outcome: Outcome,
    pub artifacts: Vec<Artifact>,
    pub metadata: JsonBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactChunk {
    pub name: String,
    pub format: String,
    pub offset: u64,
    pub bytes: JsonBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEnd {
    name: String,
    format: String,
    bytes: u64,
    content_id: ContentId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    artifacts: Vec<ArtifactEnd>,
    metadata: JsonBytes,
}

impl InvocationOutput {
    pub const fn is_success(&self) -> bool {
        matches!(self.outcome, Outcome::Succeeded)
    }
    fn terminal(&self) -> Result<Terminal, CanonicalDecodeError> {
        validate_artifacts(&self.artifacts)?;
        Ok(Terminal {
            artifacts: self
                .artifacts
                .iter()
                .map(|a| {
                    Ok(ArtifactEnd {
                        name: a.name.clone(),
                        format: a.format.clone(),
                        bytes: a.bytes.0.len() as u64,
                        content_id: a.content_id()?,
                    })
                })
                .collect::<Result<_, CanonicalDecodeError>>()?,
            metadata: self.metadata.clone(),
        })
    }

    /// The result content identity binds complete artifact bytes through their
    /// typed identities and excludes only transport chunk boundaries.
    pub fn content_id(&self) -> Result<ContentId, CanonicalDecodeError> {
        let terminal = self.terminal()?;
        let bytes = match self.outcome {
            Outcome::Succeeded => encode(&(RESULT_DOMAIN, terminal))?,
            Outcome::Failed(reason) => {
                if !self.metadata.0.is_empty() {
                    return Err(error("failed invocation cannot carry success metadata"));
                }
                encode(&(RESULT_DOMAIN, FAILURE, reason, terminal.artifacts))?
            }
        };
        Ok(ContentId::hash(&bytes))
    }

    pub fn sign(
        &self,
        request: &InvocationRequest,
        key: &ProducerSigningKey,
        chunk_size: usize,
    ) -> Result<Vec<OutputEventEnvelope>, OutputError> {
        let mut stream = OutputStream::new(request, key, super::MAX_INVOCATION_BYTES)?;
        if let Outcome::Failed(reason) = self.outcome {
            self.content_id()?;
            if chunk_size == 0 || chunk_size > MAX_CHUNK_BYTES {
                return Err(stream_error("invalid invocation chunk size"));
            }
            for artifact in &self.artifacts {
                for (i, bytes) in artifact.bytes.0.chunks(chunk_size).enumerate() {
                    stream.push(
                        &artifact.name,
                        &artifact.format,
                        (i * chunk_size) as u64,
                        bytes,
                    )?;
                }
                if artifact.bytes.0.is_empty() {
                    stream.push(&artifact.name, &artifact.format, 0, &[])?;
                }
            }
            return Ok(stream.fail(reason)?.1);
        }
        stream.finish(self, chunk_size)
    }
}

/// Sign generic artifact prefixes as they become available. The final result
/// must contain every published byte unchanged; it may append unstreamed tails.
/// Artifacts can interleave, while each artifact's byte offsets stay contiguous.
pub struct OutputStream<'a> {
    request: InvocationRequest,
    key: &'a ProducerSigningKey,
    inner: OutputTranscriptBuilder<'a>,
    artifacts: BTreeMap<String, Artifact>,
    payload_bytes: usize,
    maximum_payload_bytes: usize,
}

impl<'a> OutputStream<'a> {
    pub fn maximum_payload_bytes(&self) -> usize {
        self.maximum_payload_bytes
    }
    pub fn new(
        request: &InvocationRequest,
        key: &'a ProducerSigningKey,
        maximum_payload_bytes: usize,
    ) -> Result<Self, OutputError> {
        if request.runner_public_key != key.public_key() {
            return Err(stream_error(
                "invocation runner differs from its signing provider",
            ));
        }
        Ok(Self {
            request: request.clone(),
            key,
            inner: OutputTranscriptBuilder::new(
                scheme_id(Operation::Invoke, request.assurance),
                request.input_commitment()?,
                key,
                canonicalization(),
            ),
            artifacts: BTreeMap::new(),
            payload_bytes: 0,
            maximum_payload_bytes,
        })
    }

    /// Resume only a delivered artifact prefix, using the shared signature and
    /// chain verifier. Unpublished tails must not enter a failed continuation.
    pub fn resume(
        request: &InvocationRequest,
        key: &'a ProducerSigningKey,
        events: Vec<OutputEventEnvelope>,
        maximum_payload_bytes: usize,
    ) -> Result<Self, OutputError> {
        let mut stream = Self::new(request, key, maximum_payload_bytes)?;
        let mut prefix = ArtifactPrefix::default();
        for event in &events {
            let chunk = prefix.push(event)?;
            stream.payload_bytes = stream
                .payload_bytes
                .checked_add(event.payload().len())
                .ok_or_else(|| stream_error("invocation transcript size overflow"))?;
            if stream.payload_bytes > maximum_payload_bytes {
                return Err(OutputError::Limit);
            }
            stream
                .artifacts
                .entry(chunk.name.clone())
                .or_insert_with(|| Artifact::new(chunk.name, chunk.format, Vec::new()))
                .bytes
                .0
                .extend_from_slice(chunk.bytes.as_bytes());
        }
        if !events.is_empty() {
            stream.inner = OutputTranscriptBuilder::resume_verified(
                scheme_id(Operation::Invoke, request.assurance),
                request.input_commitment()?,
                key,
                canonicalization(),
                events,
            )
            .map_err(|e| stream_error(e.to_string()))?;
        }
        Ok(stream)
    }

    pub fn fail(
        mut self,
        reason: FailureReason,
    ) -> Result<(InvocationOutput, Vec<OutputEventEnvelope>), OutputError> {
        let payload = encode(&(FAILURE, reason))?;
        self.reserve(payload.len())?;
        self.inner
            .push(FAILURE, payload)
            .map_err(|e| stream_error(e.to_string()))?;
        let output = InvocationOutput {
            outcome: Outcome::Failed(reason),
            artifacts: self.artifacts.into_values().collect(),
            metadata: JsonBytes(Vec::new()),
        };
        let events = self
            .inner
            .finish()
            .map_err(|e| stream_error(e.to_string()))?
            .0;
        Ok((output, events))
    }

    pub fn push(
        &mut self,
        name: &str,
        format: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Result<OutputEventEnvelope, OutputError> {
        self.push_inner(name, format, offset, bytes, true)
    }

    fn push_inner(
        &mut self,
        name: &str,
        format: &str,
        offset: u64,
        bytes: &[u8],
        reserve_failure: bool,
    ) -> Result<OutputEventEnvelope, OutputError> {
        label(name)?;
        label(format)?;
        if bytes.len() > MAX_CHUNK_BYTES {
            return Err(stream_error("oversize artifact chunk"));
        }
        if let Some(previous) = self.artifacts.get(name) {
            if previous.format != format
                || previous.bytes.0.len() as u64 != offset
                || offset == 0
                || bytes.is_empty()
            {
                return Err(stream_error("artifact chunk is not contiguous"));
            }
        } else if offset != 0 || self.artifacts.len() >= super::MAX_ARTIFACTS {
            return Err(stream_error("invalid artifact start"));
        }
        let chunk = ArtifactChunk {
            name: name.into(),
            format: format.into(),
            offset,
            bytes: JsonBytes(bytes.to_vec()),
        };
        let payload = encode(&(ARTIFACT_CHUNK, chunk))?;
        self.reserve(
            payload
                .len()
                .checked_add(if reserve_failure {
                    FAILURE_PAYLOAD_BYTES
                } else {
                    0
                })
                .ok_or_else(|| stream_error("invocation transcript size overflow"))?,
        )?;
        let event = self
            .inner
            .push_envelope(ARTIFACT_CHUNK, payload)
            .map_err(|e| stream_error(e.to_string()))?;
        self.payload_bytes += event.payload().len();
        self.artifacts
            .entry(name.into())
            .or_insert_with(|| Artifact::new(name, format, Vec::new()))
            .bytes
            .0
            .extend_from_slice(bytes);
        Ok(event)
    }

    fn reserve(&self, bytes: usize) -> Result<(), OutputError> {
        if self
            .payload_bytes
            .checked_add(bytes)
            .is_none_or(|n| n > self.maximum_payload_bytes)
        {
            return Err(OutputError::Limit);
        }
        Ok(())
    }

    /// Complete the signed transcript, after checking already published prefixes
    /// against the final artifacts. The returned transcript includes live events.
    pub fn finish(
        mut self,
        output: &InvocationOutput,
        chunk_size: usize,
    ) -> Result<Vec<OutputEventEnvelope>, OutputError> {
        self.append_completion(output, chunk_size)?;
        Ok(self
            .inner
            .finish()
            .map_err(|e| stream_error(e.to_string()))?
            .0)
    }

    /// Finish one execution, or authenticate its failure after the previously
    /// published prefix. Locally signed but unpublished tails are discarded.
    pub fn finish_or_fail(
        mut self,
        output: InvocationOutput,
        chunk_size: usize,
    ) -> Result<(InvocationOutput, Vec<OutputEventEnvelope>), OutputError> {
        let published = self.inner.event_count();
        match self.append_completion(&output, chunk_size) {
            Ok(()) => Ok((
                output,
                self.inner
                    .finish()
                    .map_err(|e| stream_error(e.to_string()))?
                    .0,
            )),
            Err(cause) => {
                drop(output);
                let reason = if matches!(cause, OutputError::Limit) {
                    FailureReason::OutputLimit
                } else {
                    FailureReason::Execution
                };
                let mut events = match self.inner.finish() {
                    Ok((events, _)) => events,
                    Err(crate::StreamVerifyError::EmptyTranscript) => Vec::new(),
                    Err(e) => return Err(stream_error(e.to_string())),
                };
                events.truncate(published);
                Self::resume(&self.request, self.key, events, self.maximum_payload_bytes)?
                    .fail(reason)
            }
        }
    }

    fn append_completion(
        &mut self,
        output: &InvocationOutput,
        chunk_size: usize,
    ) -> Result<(), OutputError> {
        if !output.is_success() {
            return Err(stream_error(
                "failed invocation cannot have a success terminal",
            ));
        }
        let terminal = output.terminal()?;
        if chunk_size == 0 || chunk_size > MAX_CHUNK_BYTES {
            return Err(stream_error("invalid invocation chunk size"));
        }
        for (name, prefix) in &self.artifacts {
            let artifact = output
                .artifacts
                .iter()
                .find(|a| a.name == *name)
                .ok_or_else(|| {
                    stream_error("published artifact is missing from the final result")
                })?;
            if artifact.format != prefix.format || !artifact.bytes.0.starts_with(&prefix.bytes.0) {
                return Err(stream_error(
                    "final artifact differs from its published prefix",
                ));
            }
        }
        for artifact in &output.artifacts {
            let mut offset = self.artifacts.get(&artifact.name).map(|a| a.bytes.0.len());
            while offset.is_none() || offset.is_some_and(|n| n < artifact.bytes.0.len()) {
                let start = offset.unwrap_or(0);
                let end = artifact.bytes.0.len().min(start + chunk_size);
                self.push_inner(
                    &artifact.name,
                    &artifact.format,
                    start as u64,
                    &artifact.bytes.0[start..end],
                    false,
                )?;
                offset = Some(end);
            }
        }
        let payload = encode(&(TERMINAL, terminal))?;
        self.reserve(payload.len())?;
        self.inner
            .push(TERMINAL, payload)
            .map_err(|e| stream_error(e.to_string()))?;
        Ok(())
    }
}

pub fn canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(CANONICALIZATION)
}

/// Bounded semantic state for live delivery. Signature/chain verification is
/// performed by the common stream verifier before this method is called.
#[derive(Default)]
pub struct ArtifactPrefix {
    artifacts: BTreeMap<String, (String, u64)>,
}

impl ArtifactPrefix {
    pub fn validate(&mut self, event: &OutputEventEnvelope) -> Result<(), CanonicalDecodeError> {
        self.push(event).map(|_| ())
    }

    /// Decode a chunk and advance its contiguous artifact prefix. Call only
    /// after authenticating the event's producer, request and signature chain.
    /// This does not authenticate the final artifact; `verify` checks its terminal.
    pub fn push(
        &mut self,
        event: &OutputEventEnvelope,
    ) -> Result<ArtifactChunk, CanonicalDecodeError> {
        if event.event().body().kind() != ARTIFACT_CHUNK
            || event.event().body().canonicalization() != canonicalization()
        {
            return Err(error("wrong invocation artifact event"));
        }
        bound(event.payload(), MAX_CHUNK_BYTES + 2048)?;
        let (domain, chunk): (String, ArtifactChunk) = decode_canonical_dag_cbor(event.payload())?;
        domain_is(&domain, ARTIFACT_CHUNK)?;
        label(&chunk.name)?;
        label(&chunk.format)?;
        if chunk.bytes.0.len() > MAX_CHUNK_BYTES {
            return Err(error("oversize artifact chunk"));
        }
        let previous = self.artifacts.get(&chunk.name);
        if let Some((format, bytes)) = previous {
            if *format != chunk.format
                || *bytes != chunk.offset
                || chunk.offset == 0
                || chunk.bytes.0.is_empty()
            {
                return Err(error("artifact chunk is not contiguous"));
            }
        } else if chunk.offset != 0 || self.artifacts.len() >= super::MAX_ARTIFACTS {
            return Err(error("invalid artifact start"));
        }
        let end = chunk
            .offset
            .checked_add(chunk.bytes.0.len() as u64)
            .ok_or_else(|| error("artifact length overflow"))?;
        self.artifacts
            .insert(chunk.name.clone(), (chunk.format.clone(), end));
        Ok(chunk)
    }
}

/// Incremental authentication shared by paid delivery and direct execution.
/// No application bytes are released before their signature, chain position,
/// canonical encoding and contiguous artifact offset have been checked.
pub struct StreamVerifier {
    request: InvocationRequest,
    provider: PublicKey,
    previous: crate::EventCommitment,
    prefix: ArtifactPrefix,
    events: Vec<OutputEventEnvelope>,
    bytes: usize,
    budget: usize,
    retained_bytes: usize,
    retained_limit: usize,
    output: Option<InvocationOutput>,
}

impl StreamVerifier {
    pub fn new(
        request: InvocationRequest,
        provider: PublicKey,
        budget: usize,
    ) -> Result<Self, CanonicalDecodeError> {
        if request.runner_public_key != provider {
            return Err(error(
                "invocation runner differs from the expected provider",
            ));
        }
        let input = request.input_commitment()?;
        Ok(Self {
            request,
            provider,
            previous: crate::output_genesis(input, crate::StreamId::from_input_commitment(input)),
            prefix: ArtifactPrefix::default(),
            events: Vec::new(),
            bytes: 0,
            budget,
            retained_bytes: 0,
            retained_limit: super::MAX_INVOCATION_BYTES,
            output: None,
        })
    }

    pub fn terminal_seen(&self) -> bool {
        self.output.is_some()
    }

    pub fn push(
        &mut self,
        event: OutputEventEnvelope,
    ) -> Result<Option<ArtifactChunk>, CanonicalDecodeError> {
        if self.terminal_seen() {
            return Err(error("event after invocation terminal"));
        }
        // Charge spare payload/kind capacity and conservatively four times the fixed
        // event size to include the event Vec's amortized spare allocation.
        let retained_bytes = event
            .retained_heap_bytes()
            .and_then(|n| n.checked_add(4 * std::mem::size_of::<OutputEventEnvelope>()))
            .and_then(|n| self.retained_bytes.checked_add(n))
            .ok_or_else(|| error("invocation transcript memory accounting overflow"))?;
        if retained_bytes > self.retained_limit {
            return Err(error(
                "invocation transcript exceeds its retained-memory budget",
            ));
        }
        let bytes = self
            .bytes
            .checked_add(event.payload().len())
            .ok_or_else(|| error("invocation transcript size overflow"))?;
        if bytes > self.budget {
            return Err(error("invocation result exceeds its byte budget"));
        }
        let previous = crate::verify_output_event_continuation(
            scheme_id(Operation::Invoke, self.request.assurance),
            self.request.input_commitment()?,
            &self.provider,
            self.events.len() as u64,
            self.previous,
            &event,
        )
        .map_err(|e| error(e.to_string()))?;
        if event.event().body().canonicalization() != canonicalization() {
            return Err(error("wrong invocation output canonicalization"));
        }
        let chunk = match event.event().body().kind() {
            ARTIFACT_CHUNK => Some(self.prefix.push(&event)?),
            TERMINAL | FAILURE => None,
            _ => return Err(error("unknown invocation output event")),
        };
        self.events.push(event);
        if chunk.is_none() {
            match verify(&self.request, &self.provider, &self.events, self.budget) {
                Ok(output) => self.output = Some(output),
                Err(error) => {
                    self.events.pop();
                    return Err(error);
                }
            }
        }
        self.previous = previous;
        self.bytes = bytes;
        self.retained_bytes = retained_bytes;
        Ok(chunk)
    }

    /// Call only after transport EOF and its trailer have been accepted.
    pub fn finish(
        self,
    ) -> Result<(InvocationOutput, Vec<OutputEventEnvelope>), CanonicalDecodeError> {
        Ok((
            self.output
                .ok_or_else(|| error("missing invocation terminal"))?,
            self.events,
        ))
    }
}

/// Verify the expected provider, request, canonical event encoding, contiguous
/// artifacts, all terminal lengths/digests, and the complete payload budget.
pub fn verify(
    request: &InvocationRequest,
    provider: &PublicKey,
    events: &[OutputEventEnvelope],
    budget: usize,
) -> Result<InvocationOutput, CanonicalDecodeError> {
    if request.runner_public_key != *provider {
        return Err(error(
            "invocation runner differs from the expected provider",
        ));
    }
    let size = events
        .iter()
        .try_fold(0usize, |n, e| n.checked_add(e.payload().len()))
        .ok_or_else(|| error("invocation transcript size overflow"))?;
    if size > budget {
        return Err(error("invocation result exceeds its byte budget"));
    }
    verify_output_event_envelopes(
        scheme_id(Operation::Invoke, request.assurance),
        request.input_commitment()?,
        provider,
        events,
    )
    .map_err(|e| error(e.to_string()))?;
    let mut artifacts = BTreeMap::new();
    let mut prefix = ArtifactPrefix::default();
    let mut terminal = None;
    for (index, event) in events.iter().enumerate() {
        if terminal.is_some() {
            return Err(error("event after invocation terminal"));
        }
        let body = event.event().body();
        if body.canonicalization() != canonicalization() {
            return Err(error("wrong invocation output canonicalization"));
        }
        match body.kind() {
            ARTIFACT_CHUNK => {
                let chunk = prefix.push(event)?;
                let artifact = artifacts
                    .entry(chunk.name.clone())
                    .or_insert_with(|| Artifact::new(&chunk.name, &chunk.format, Vec::new()));
                artifact.bytes.0.extend_from_slice(chunk.bytes.as_bytes());
            }
            FAILURE => {
                if index + 1 != events.len() {
                    return Err(error("event after invocation failure"));
                }
                bound(event.payload(), FAILURE_PAYLOAD_BYTES)?;
                let (domain, reason): (String, FailureReason) =
                    decode_canonical_dag_cbor(event.payload())?;
                domain_is(&domain, FAILURE)?;
                return Ok(InvocationOutput {
                    outcome: Outcome::Failed(reason),
                    artifacts: artifacts.into_values().collect(),
                    metadata: JsonBytes(Vec::new()),
                });
            }
            TERMINAL => {
                let (domain, value): (String, Terminal) =
                    decode_canonical_dag_cbor(event.payload())?;
                domain_is(&domain, TERMINAL)?;
                terminal = Some(value);
            }
            _ => return Err(error("unknown invocation output event")),
        }
    }
    let terminal = terminal.ok_or_else(|| error("missing invocation terminal"))?;
    let output = InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: artifacts.into_values().collect(),
        metadata: terminal.metadata.clone(),
    };
    if output.terminal()? != terminal {
        return Err(error("terminal artifacts do not match delivered bytes"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Assurance;

    fn request(key: &ProducerSigningKey) -> InvocationRequest {
        InvocationRequest {
            execution_environment: ContentId::hash(b"generic source"),
            input: ContentId::hash(b"generic arguments"),
            runner_public_key: key.public_key(),
            nonce: [3; 32],
            assurance: Assurance::ProducerSigned,
            retain: false,
        }
    }
    fn result() -> InvocationOutput {
        InvocationOutput {
            outcome: Outcome::Succeeded,
            artifacts: vec![
                Artifact::new("a", "bytes-v1", vec![1, 2, 3, 4]),
                Artifact::new("b", "bytes-v1", vec![5, 6, 7]),
                Artifact::new("empty", "bytes-v1", vec![]),
            ],
            metadata: JsonBytes(vec![42]),
        }
    }
    #[test]
    fn live_interleaved_prefixes_finish_as_the_same_normalized_result() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        let output = result();
        let mut stream = OutputStream::new(&request, &key, 65536).unwrap();
        let mut prefix = ArtifactPrefix::default();
        let first = stream.push("b", "bytes-v1", 0, &[5]).unwrap();
        prefix.validate(&first).unwrap();
        prefix
            .validate(&stream.push("a", "bytes-v1", 0, &[1, 2]).unwrap())
            .unwrap();
        prefix
            .validate(&stream.push("b", "bytes-v1", 1, &[6]).unwrap())
            .unwrap();
        let events = stream.finish(&output, 1).unwrap();
        assert_eq!(events[0], first);
        assert_eq!(
            verify(&request, &key.public_key(), &events, 65536).unwrap(),
            output
        );
        let whole = output.sign(&request, &key, MAX_CHUNK_BYTES).unwrap();
        assert_eq!(
            verify(&request, &key.public_key(), &whole, 65536)
                .unwrap()
                .content_id()
                .unwrap(),
            output.content_id().unwrap()
        );
        for event in &events[3..events.len() - 1] {
            prefix.validate(event).unwrap();
        }
    }
    #[test]
    fn rejected_chunks_do_not_advance_the_stream() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        let mut stream = OutputStream::new(&request, &key, 65536).unwrap();
        stream.push("a", "bytes-v1", 0, &[1]).unwrap();
        for (format, offset, bytes) in [
            ("different", 1, vec![2]),
            ("bytes-v1", 2, vec![2]),
            ("bytes-v1", 0, vec![2]),
            ("bytes-v1", 1, vec![]),
            ("bytes-v1", 1, vec![0; MAX_CHUNK_BYTES + 1]),
        ] {
            assert!(stream.push("a", format, offset, &bytes).is_err());
        }
        assert!(stream.push("missing", "bytes-v1", 1, &[0]).is_err());
        stream.push("a", "bytes-v1", 1, &[2]).unwrap();
        let output = result();
        let events = stream.finish(&output, 2).unwrap();
        assert_eq!(
            verify(&request, &key.public_key(), &events, 65536).unwrap(),
            output
        );
    }
    #[test]
    fn completion_rejects_changed_removed_or_truncated_prefixes() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        for change in 0..4 {
            let mut stream = OutputStream::new(&request, &key, 65536).unwrap();
            stream.push("a", "bytes-v1", 0, &[1, 2]).unwrap();
            let mut output = result();
            match change {
                0 => output.artifacts[0].bytes.0[0] = 9,
                1 => {
                    output.artifacts.remove(0);
                }
                2 => output.artifacts[0].bytes.0.truncate(1),
                _ => output.artifacts[0].format = "changed".into(),
            }
            assert!(stream.finish(&output, 2).is_err());
        }
    }
    #[test]
    fn payload_budget_covers_live_chunks_and_the_terminal() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        let mut stream = OutputStream::new(&request, &key, 0).unwrap();
        assert!(stream.push("a", "bytes-v1", 0, &[1]).is_err());
        let output = result();
        let complete = output.sign(&request, &key, 2).unwrap();
        let size = complete.iter().map(|e| e.payload().len()).sum::<usize>();
        assert!(
            OutputStream::new(&request, &key, size - 1)
                .unwrap()
                .finish(&output, 2)
                .is_err()
        );
        assert!(
            OutputStream::new(&request, &key, size)
                .unwrap()
                .finish(&output, 2)
                .is_ok()
        );
    }
    #[test]
    fn valid_signatures_do_not_make_invalid_offsets_or_prefixes_valid() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        for offset in [0, 2, u64::MAX] {
            let mut signed = OutputTranscriptBuilder::new(
                scheme_id(Operation::Invoke, request.assurance),
                request.input_commitment().unwrap(),
                &key,
                canonicalization(),
            );
            for (offset, bytes) in [(0, vec![1]), (offset, vec![2])] {
                let chunk = ArtifactChunk {
                    name: "a".into(),
                    format: "bytes-v1".into(),
                    offset,
                    bytes: JsonBytes(bytes),
                };
                signed
                    .push(ARTIFACT_CHUNK, encode(&(ARTIFACT_CHUNK, chunk)).unwrap())
                    .unwrap();
            }
            signed
                .push(
                    TERMINAL,
                    encode(&(TERMINAL, result().terminal().unwrap())).unwrap(),
                )
                .unwrap();
            let events = signed.finish().unwrap().0;
            assert!(verify(&request, &key.public_key(), &events, 65536).is_err());
            let mut prefix = ArtifactPrefix::default();
            prefix.validate(&events[0]).unwrap();
            assert!(prefix.validate(&events[1]).is_err());
        }
    }
    #[test]
    fn incremental_verification_charges_retained_capacity_before_accepting_a_prefix() {
        let key = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
        let request = request(&key);
        let events = result().sign(&request, &key, 64).unwrap();
        let mut payload = Vec::with_capacity(8192);
        payload.extend_from_slice(events[0].payload());
        let oversized = OutputEventEnvelope::new(events[0].event().clone(), payload).unwrap();
        let mut verifier = StreamVerifier::new(request, key.public_key(), 65536).unwrap();
        verifier.retained_limit = 4096;
        assert!(verifier.push(oversized).is_err());
        // Rejecting excess spare capacity does not advance the signature chain.
        assert!(verifier.push(events[0].clone()).unwrap().is_some());
        assert_eq!(verifier.events.len(), 1);
    }
    const REASONS: [FailureReason; 6] = [
        FailureReason::Compilation,
        FailureReason::Execution,
        FailureReason::Cancelled,
        FailureReason::ExecutionTimeout,
        FailureReason::OutputLimit,
        FailureReason::Unavailable,
    ];

    #[test]
    fn exhausted_live_output_still_has_room_for_every_signed_failure() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let request = request(&key);
        let mut measure = OutputStream::new(&request, &key, 65536).unwrap();
        let first = measure.push("a", "bytes-v1", 0, &[1]).unwrap();
        let second = measure.push("a", "bytes-v1", 1, &[2]).unwrap();
        let failure_bytes = REASONS
            .iter()
            .map(|reason| encode(&(FAILURE, reason)).unwrap().len())
            .max()
            .unwrap();
        let budget = first.payload().len() + second.payload().len() + failure_bytes - 1;
        for reason in REASONS {
            let mut stream = OutputStream::new(&request, &key, budget).unwrap();
            stream.push("a", "bytes-v1", 0, &[1]).unwrap();
            assert!(matches!(
                stream.push("a", "bytes-v1", 1, &[2]),
                Err(OutputError::Limit)
            ));
            let (output, events) = stream.fail(reason).unwrap();
            assert_eq!(output.outcome, Outcome::Failed(reason));
            assert!(!output.is_success());
            assert_eq!(
                output.artifacts,
                vec![Artifact::new("a", "bytes-v1", vec![1])]
            );
            assert_eq!(events.len(), 2);
            assert!(events.iter().map(|e| e.payload().len()).sum::<usize>() <= budget);
            assert_eq!(
                verify(&request, &key.public_key(), &events, budget).unwrap(),
                output
            );
            let mut incremental =
                StreamVerifier::new(request.clone(), key.public_key(), budget).unwrap();
            for event in events.clone() {
                incremental.push(event).unwrap();
            }
            assert!(incremental.terminal_seen());
            assert_eq!(incremental.finish().unwrap(), (output.clone(), events));
            assert_ne!(
                output.content_id().unwrap(),
                InvocationOutput {
                    outcome: Outcome::Succeeded,
                    ..output.clone()
                }
                .content_id()
                .unwrap()
            );
        }
    }

    #[test]
    fn failed_completion_discards_locally_signed_unpublished_tails() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let request = request(&key);
        let mut stream = OutputStream::new(&request, &key, 512).unwrap();
        let first = stream.push("a", "bytes-v1", 0, &[1]).unwrap();
        let mut output = result();
        output.artifacts[1].bytes.0 = vec![5; 4096];
        let (output, events) = stream.finish_or_fail(output, 64).unwrap();
        assert_eq!(output.outcome, Outcome::Failed(FailureReason::OutputLimit));
        assert_eq!(
            output.artifacts,
            vec![Artifact::new("a", "bytes-v1", vec![1])]
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], first);
        assert_eq!(
            events[1].event().body().previous_event(),
            first.event_commitment()
        );
        assert_eq!(
            verify(&request, &key.public_key(), &events, 512).unwrap(),
            output
        );
    }

    #[test]
    fn resume_authenticates_the_exact_unfinished_request_prefix() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let request = request(&key);
        let mut stream = OutputStream::new(&request, &key, 65536).unwrap();
        let prefix = stream.push("a", "bytes-v1", 0, &[1]).unwrap();
        let mut other = request.clone();
        other.nonce[0] ^= 1;
        assert!(OutputStream::resume(&other, &key, vec![prefix.clone()], 65536).is_err());
        let wrong_key = ProducerSigningKey::from_secret_bytes([9; 32]).unwrap();
        assert!(OutputStream::resume(&request, &wrong_key, vec![prefix.clone()], 65536).is_err());
        let (_, failed) = stream.fail(FailureReason::Execution).unwrap();
        assert!(OutputStream::resume(&request, &key, failed, 65536).is_err());
        let succeeded = result().sign(&request, &key, 64).unwrap();
        assert!(OutputStream::resume(&request, &key, succeeded, 65536).is_err());
        let (output, events) = OutputStream::resume(&request, &key, vec![prefix], 65536)
            .unwrap()
            .fail(FailureReason::Cancelled)
            .unwrap();
        assert_eq!(
            verify(&request, &key.public_key(), &events, 65536).unwrap(),
            output
        );
    }

    #[test]
    fn failed_outcome_and_reason_are_authenticated_and_cannot_be_continued() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let request = request(&key);
        let (output, events) = OutputStream::new(&request, &key, 65536)
            .unwrap()
            .fail(FailureReason::Cancelled)
            .unwrap();
        let mut other = output.clone();
        other.outcome = Outcome::Failed(FailureReason::ExecutionTimeout);
        assert_ne!(output.content_id().unwrap(), other.content_id().unwrap());
        let old = events[0].event();
        let body = old.body();
        let payload = encode(&(FAILURE, FailureReason::ExecutionTimeout)).unwrap();
        let changed = crate::OutputEventBody::from_parts(crate::OutputEventBodyParts {
            scheme: body.scheme(),
            input: body.input(),
            stream_id: body.stream_id(),
            sequence: body.sequence(),
            previous_event: body.previous_event(),
            kind: body.kind().into(),
            payload: hellas_auth::Digest::hash(&payload),
            signer: body.signer(),
            canonicalization: body.canonicalization(),
        });
        let signed =
            crate::SignedOutputEvent::from_parts(changed, *old.signature(), *old.public_key())
                .unwrap();
        let forged = crate::OutputEventEnvelope::new(signed, payload).unwrap();
        assert!(verify(&request, &key.public_key(), &[forged], 65536).is_err());
        for kind in [TERMINAL, ARTIFACT_CHUNK] {
            let mut builder = OutputTranscriptBuilder::resume_verified(
                scheme_id(Operation::Invoke, request.assurance),
                request.input_commitment().unwrap(),
                &key,
                canonicalization(),
                events.clone(),
            )
            .unwrap();
            builder.push(kind, vec![]).unwrap();
            let continued = builder.finish().unwrap().0;
            assert!(verify(&request, &key.public_key(), &continued, 65536).is_err());
            let mut verifier =
                StreamVerifier::new(request.clone(), key.public_key(), 65536).unwrap();
            verifier.push(continued[0].clone()).unwrap();
            assert!(verifier.push(continued[1].clone()).is_err());
        }
    }

    #[test]
    fn malformed_failure_does_not_poison_the_incremental_prefix() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let request = request(&key);
        let mut builder = OutputTranscriptBuilder::new(
            scheme_id(Operation::Invoke, request.assurance),
            request.input_commitment().unwrap(),
            &key,
            canonicalization(),
        );
        let bad = builder
            .push_envelope(FAILURE, encode(&(FAILURE, "unknown-reason")).unwrap())
            .unwrap();
        let (output, events) = OutputStream::new(&request, &key, 65536)
            .unwrap()
            .fail(FailureReason::Execution)
            .unwrap();
        let mut verifier = StreamVerifier::new(request.clone(), key.public_key(), 65536).unwrap();
        assert!(verifier.push(bad).is_err());
        verifier.push(events[0].clone()).unwrap();
        assert_eq!(verifier.finish().unwrap(), (output, events));
    }

    #[test]
    fn requested_runner_is_enforced_independently_of_valid_signatures() {
        let key = ProducerSigningKey::from_secret_bytes([8; 32]).unwrap();
        let mut request = request(&key);
        request.runner_public_key = ProducerSigningKey::from_secret_bytes([9; 32])
            .unwrap()
            .public_key();
        assert!(OutputStream::new(&request, &key, 65536).is_err());
        let empty = InvocationOutput {
            outcome: Outcome::Succeeded,
            artifacts: vec![],
            metadata: JsonBytes(vec![]),
        };
        let mut builder = OutputTranscriptBuilder::new(
            scheme_id(Operation::Invoke, request.assurance),
            request.input_commitment().unwrap(),
            &key,
            canonicalization(),
        );
        builder
            .push(
                TERMINAL,
                encode(&(TERMINAL, empty.terminal().unwrap())).unwrap(),
            )
            .unwrap();
        let events = builder.finish().unwrap().0;
        verify_output_event_envelopes(
            scheme_id(Operation::Invoke, request.assurance),
            request.input_commitment().unwrap(),
            &key.public_key(),
            &events,
        )
        .unwrap();
        assert!(verify(&request, &key.public_key(), &events, 65536).is_err());
        assert!(StreamVerifier::new(request, key.public_key(), 65536).is_err());
    }
}
