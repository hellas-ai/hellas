use std::str;

use crate::pb::execute::InputEventEnvelope as PbInputEventEnvelope;
use crate::{
    Assurance, CanonicalizationId, ContentId, InputCommitment, InputEventEnvelope,
    InputTranscriptBuilder, JsonBytes, Operation, OutputEventEnvelope, OutputTranscriptBuilder,
    ProducerSigningKey, PublicKey, Retention, StreamVerifyError, scheme_id,
    verify_input_event_envelopes, verify_output_event_envelopes,
};
use k256::elliptic_curve::rand_core::{OsRng, RngCore};

const INPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.input.v3";
const OUTPUT_CANONICALIZATION: &[u8] = b"hellas.fetch.output.v2";
const OUTPUT_EVENT_KIND: &str = "response.event";
const OUTPUT_TERMINAL_KIND: &str = "response.terminal";
const INPUT_EVENT_KINDS: [&str; 8] = [
    "assurance",
    "execution.environment",
    "request.nonce",
    "service",
    "method",
    "request.retain",
    "request.body",
    "input.end",
];

/// Maximum signed envelopes in one successful Fetch output transcript,
/// including its terminal envelope.
///
/// Each envelope has its own wire frame; this bound limits retained state and
/// transcript verification work rather than the size of a terminal frame.
pub const MAX_FETCH_OUTPUT_EVENTS: usize = 32_768;

/// Maximum cumulative payload bytes across all signed Fetch output envelopes,
/// including the terminal payload.
pub const MAX_FETCH_OUTPUT_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Maximum UTF-8 JSON bytes in the signed Fetch `request.body` event.
///
/// This is checked before callers allocate/sign a transcript and again after
/// verifiers authenticate it, so every Fetch implementation shares the same
/// v0.0.1 admission bound.
pub const MAX_FETCH_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Maximum UTF-8 bytes in each signed Fetch route component (`service` and
/// `method`).
pub const MAX_FETCH_ROUTE_COMPONENT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchInput {
    pub input_commitment: InputCommitment,
    pub assurance: Assurance,
    pub caller_key: PublicKey,
    pub execution_environment: ContentId,
    pub service: String,
    pub method: String,
    pub body: JsonBytes,
    pub retention: Retention,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchOutput {
    pub producer_key: PublicKey,
    event_payloads: Vec<Vec<u8>>,
    terminal_payload: Vec<u8>,
}

impl FetchOutput {
    pub fn output_event_payloads(&self) -> (&[Vec<u8>], &[u8]) {
        (&self.event_payloads, &self.terminal_payload)
    }
}

pub fn input_canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(INPUT_CANONICALIZATION)
}

pub fn output_canonicalization() -> CanonicalizationId {
    CanonicalizationId::from_bytes(OUTPUT_CANONICALIZATION)
}

pub fn build_input_events(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    assurance: Assurance,
    key: &ProducerSigningKey,
) -> Result<Vec<InputEventEnvelope>, FetchProtocolError> {
    build_input_events_with_retention(
        service,
        method,
        payload,
        execution_environment,
        assurance,
        key,
        Retention::Retain,
    )
}

pub fn build_input_events_with_retention(
    service: &str,
    method: &str,
    payload: &[u8],
    execution_environment: ContentId,
    assurance: Assurance,
    key: &ProducerSigningKey,
    retention: Retention,
) -> Result<Vec<InputEventEnvelope>, FetchProtocolError> {
    validate_service_method(service.as_bytes(), method.as_bytes())?;
    validate_request_body_limit(payload)?;
    validate_json("request.body", payload)?;
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, assurance),
        key,
        input_canonicalization(),
    );
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    builder.push("assurance", vec![assurance.to_byte()])?;
    builder.push(
        "execution.environment",
        execution_environment.as_bytes().to_vec(),
    )?;
    builder.push("request.nonce", nonce.to_vec())?;
    builder.push("service", service.as_bytes().to_vec())?;
    builder.push("method", method.as_bytes().to_vec())?;
    builder.push("request.retain", vec![u8::from(retention.should_retain())])?;
    builder.push("request.body", payload.to_vec())?;
    builder.push("input.end", Vec::new())?;
    let (events, _) = builder.finish()?;
    Ok(events)
}

pub fn build_output_events(
    input: InputCommitment,
    assurance: Assurance,
    payload: &[u8],
    key: &ProducerSigningKey,
) -> Result<Vec<OutputEventEnvelope>, FetchProtocolError> {
    let mut builder = OutputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, assurance),
        input,
        key,
        output_canonicalization(),
    );
    builder.push(OUTPUT_TERMINAL_KIND, payload.to_vec())?;
    let (events, _) = builder.finish()?;
    Ok(events)
}

pub struct FetchOutputTranscriptBuilder<'a> {
    inner: OutputTranscriptBuilder<'a>,
}

impl<'a> FetchOutputTranscriptBuilder<'a> {
    pub fn new(input: InputCommitment, assurance: Assurance, key: &'a ProducerSigningKey) -> Self {
        Self {
            inner: OutputTranscriptBuilder::new(
                scheme_id(Operation::Fetch, assurance),
                input,
                key,
                output_canonicalization(),
            ),
        }
    }

    pub fn push_event(
        &mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<OutputEventEnvelope, FetchProtocolError> {
        Ok(self.inner.push_envelope(OUTPUT_EVENT_KIND, payload)?)
    }

    pub fn finish(
        mut self,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Vec<OutputEventEnvelope>, FetchProtocolError> {
        self.inner.push(OUTPUT_TERMINAL_KIND, payload)?;
        let (events, _) = self.inner.finish()?;
        Ok(events)
    }
}

pub fn verify_input_events(
    events: &[InputEventEnvelope],
) -> Result<FetchInput, FetchProtocolError> {
    // Shape and byte bounds are deliberately checked before signature
    // verification. The Fetch input language has exactly eight events, so an
    // adversarial peer must never be able to buy an unbounded signature loop
    // by appending otherwise well-formed envelopes.
    let parts = input_parts(events)?;
    let caller_key = *events[0].event().public_key();
    let assurance = parts.assurance;
    let input_commitment =
        verify_input_event_envelopes(scheme_id(Operation::Fetch, assurance), &caller_key, events)?;
    validate_json("request.body", parts.body)?;
    Ok(FetchInput {
        input_commitment,
        assurance,
        caller_key,
        execution_environment: parts.execution_environment,
        service: parts.service.to_string(),
        method: parts.method.to_string(),
        body: JsonBytes::new(parts.body.to_vec()),
        retention: parts.retention,
    })
}

/// Rejects oversized or invalid fixed Fetch payload shapes directly on the
/// decoded protobuf request, before envelope conversion hashes payloads or
/// allocates the signed domain objects.
pub fn validate_input_event_pb_shape(
    events: &[PbInputEventEnvelope],
) -> Result<(), FetchProtocolError> {
    input_payload_parts(events)?;
    for (index, (event, expected)) in events.iter().zip(INPUT_EVENT_KINDS).enumerate() {
        let Some(body) = &event.body else {
            // Domain conversion reports the more precise missing-body error.
            continue;
        };
        if body.kind != expected {
            return Err(FetchProtocolError::UnexpectedInputEvent {
                index,
                expected,
                actual: bounded_kind(&body.kind),
            });
        }
        if body.canonicalization_id != input_canonicalization().as_bytes() {
            return Err(FetchProtocolError::InputCanonicalizationMismatch { index });
        }
    }
    Ok(())
}

pub fn verify_output_events(
    input: InputCommitment,
    assurance: Assurance,
    events: &[OutputEventEnvelope],
) -> Result<FetchOutput, FetchProtocolError> {
    validate_output_limits(events)?;
    let producer_key = *events
        .first()
        .ok_or(FetchProtocolError::EmptyOutputTranscript)?
        .event()
        .public_key();
    verify_output_event_envelopes(
        scheme_id(Operation::Fetch, assurance),
        input,
        &producer_key,
        events,
    )?;
    let (event_payloads, terminal_payload) = output_payloads(events)?;
    Ok(FetchOutput {
        producer_key,
        event_payloads,
        terminal_payload,
    })
}

fn validate_output_limits(events: &[OutputEventEnvelope]) -> Result<(), FetchProtocolError> {
    if events.len() > MAX_FETCH_OUTPUT_EVENTS {
        return Err(FetchProtocolError::OutputEventLimit {
            actual: events.len(),
        });
    }
    let payload_bytes = events.iter().try_fold(0_usize, |total, event| {
        total
            .checked_add(event.payload().len())
            .ok_or(FetchProtocolError::OutputPayloadLengthOverflow)
    })?;
    if payload_bytes > MAX_FETCH_OUTPUT_PAYLOAD_BYTES {
        return Err(FetchProtocolError::OutputPayloadLimit {
            actual: payload_bytes,
        });
    }
    Ok(())
}

fn output_payloads(
    events: &[OutputEventEnvelope],
) -> Result<(Vec<Vec<u8>>, Vec<u8>), FetchProtocolError> {
    if events.is_empty() {
        return Err(FetchProtocolError::EmptyOutputTranscript);
    }
    let terminal_index = events.len() - 1;
    let mut payloads = Vec::with_capacity(terminal_index);
    for (index, event) in events[..terminal_index].iter().enumerate() {
        expect_output_event(event, index, OUTPUT_EVENT_KIND)?;
        payloads.push(event.payload().to_vec());
    }
    expect_output_event(
        &events[terminal_index],
        terminal_index,
        OUTPUT_TERMINAL_KIND,
    )?;
    Ok((payloads, events[terminal_index].payload().to_vec()))
}

struct FetchInputParts<'a> {
    assurance: Assurance,
    execution_environment: ContentId,
    service: &'a str,
    method: &'a str,
    body: &'a [u8],
    retention: Retention,
}

trait FetchInputPayload {
    fn fetch_payload(&self) -> &[u8];
}

impl FetchInputPayload for InputEventEnvelope {
    fn fetch_payload(&self) -> &[u8] {
        self.payload()
    }
}

impl FetchInputPayload for PbInputEventEnvelope {
    fn fetch_payload(&self) -> &[u8] {
        &self.payload
    }
}

fn input_parts(events: &[InputEventEnvelope]) -> Result<FetchInputParts<'_>, FetchProtocolError> {
    if events.len() != 8 {
        return Err(FetchProtocolError::WrongInputEventCount {
            actual: events.len(),
        });
    }
    for (index, (event, expected)) in events.iter().zip(INPUT_EVENT_KINDS).enumerate() {
        expect_input_event(event, index, expected)?;
    }
    input_payload_parts(events)
}

fn input_payload_parts<T: FetchInputPayload>(
    events: &[T],
) -> Result<FetchInputParts<'_>, FetchProtocolError> {
    if events.len() != 8 {
        return Err(FetchProtocolError::WrongInputEventCount {
            actual: events.len(),
        });
    }
    let payload = |index: usize| events[index].fetch_payload();
    if !payload(7).is_empty() {
        return Err(FetchProtocolError::NonEmptyInputEnd);
    }
    let execution_environment =
        ContentId::from_slice(payload(1)).map_err(|_| FetchProtocolError::WrongInputLength {
            field: "execution.environment",
            actual: payload(1).len(),
        })?;
    if payload(2).len() != 32 {
        return Err(FetchProtocolError::WrongInputLength {
            field: "request.nonce",
            actual: payload(2).len(),
        });
    }
    validate_service_method(payload(3), payload(4))?;
    let service = str::from_utf8(payload(3)).map_err(|source| FetchProtocolError::Utf8 {
        field: "service",
        source,
    })?;
    let method = str::from_utf8(payload(4)).map_err(|source| FetchProtocolError::Utf8 {
        field: "method",
        source,
    })?;
    let [retention] = payload(5) else {
        return Err(FetchProtocolError::WrongInputLength {
            field: "request.retain",
            actual: payload(5).len(),
        });
    };
    let retention = match retention {
        0 => Retention::Ephemeral,
        1 => Retention::Retain,
        tag => {
            return Err(FetchProtocolError::InvalidRetention { actual: vec![*tag] });
        }
    };
    let [assurance] = payload(0) else {
        return Err(FetchProtocolError::WrongAssuranceLength {
            actual: payload(0).len(),
        });
    };
    let assurance = Assurance::from_byte(*assurance)
        .map_err(|_| FetchProtocolError::UnknownAssurance(*assurance))?;
    validate_request_body_limit(payload(6))?;
    Ok(FetchInputParts {
        assurance,
        execution_environment,
        service,
        method,
        body: payload(6),
        retention,
    })
}

fn validate_service_method(service: &[u8], method: &[u8]) -> Result<(), FetchProtocolError> {
    if service.is_empty() {
        return Err(FetchProtocolError::EmptyService);
    }
    if method.is_empty() {
        return Err(FetchProtocolError::EmptyMethod);
    }
    if service.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
        return Err(FetchProtocolError::RouteComponentLimit {
            field: "service",
            actual: service.len(),
        });
    }
    if method.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
        return Err(FetchProtocolError::RouteComponentLimit {
            field: "method",
            actual: method.len(),
        });
    }
    Ok(())
}

fn validate_json(field: &'static str, bytes: &[u8]) -> Result<(), FetchProtocolError> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .map(|_| ())
        .map_err(|source| FetchProtocolError::Json { field, source })
}

fn expect_input_event(
    event: &InputEventEnvelope,
    index: usize,
    expected: &'static str,
) -> Result<(), FetchProtocolError> {
    if event.event().body().kind() == expected {
        if event.event().body().canonicalization() == input_canonicalization() {
            Ok(())
        } else {
            Err(FetchProtocolError::InputCanonicalizationMismatch { index })
        }
    } else {
        Err(FetchProtocolError::UnexpectedInputEvent {
            index,
            expected,
            actual: bounded_kind(event.event().body().kind()),
        })
    }
}

fn expect_output_event(
    event: &OutputEventEnvelope,
    index: usize,
    expected: &'static str,
) -> Result<(), FetchProtocolError> {
    if event.event().body().kind() == expected {
        if event.event().body().canonicalization() == output_canonicalization() {
            Ok(())
        } else {
            Err(FetchProtocolError::OutputCanonicalizationMismatch { index })
        }
    } else {
        Err(FetchProtocolError::UnexpectedOutputEvent {
            index,
            expected,
            actual: bounded_kind(event.event().body().kind()),
        })
    }
}

fn bounded_kind(kind: &str) -> String {
    const MAX_DISPLAY_BYTES: usize = 64;
    if kind.len() <= MAX_DISPLAY_BYTES {
        kind.to_string()
    } else {
        format!("<{} UTF-8 bytes>", kind.len())
    }
}

fn validate_request_body_limit(payload: &[u8]) -> Result<(), FetchProtocolError> {
    if payload.len() > MAX_FETCH_REQUEST_BODY_BYTES {
        Err(FetchProtocolError::RequestBodyLimit {
            actual: payload.len(),
        })
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchProtocolError {
    #[error("fetch service must not be empty")]
    EmptyService,
    #[error("fetch method must not be empty")]
    EmptyMethod,
    #[error(
        "fetch {field} contains {actual} bytes, over the {MAX_FETCH_ROUTE_COMPONENT_BYTES}-byte limit"
    )]
    RouteComponentLimit { field: &'static str, actual: usize },
    #[error("fetch output transcript is empty")]
    EmptyOutputTranscript,
    #[error("fetch input transcript must contain exactly 8 events, got {actual}")]
    WrongInputEventCount { actual: usize },
    #[error("fetch assurance must be exactly one byte, got {actual}")]
    WrongAssuranceLength { actual: usize },
    #[error("unknown fetch assurance tag 0x{0:02x}")]
    UnknownAssurance(u8),
    #[error("fetch retention signal must be exactly one byte, 0 or 1; got {actual:?}")]
    InvalidRetention { actual: Vec<u8> },
    #[error("fetch {field} must be 32 bytes, got {actual}")]
    WrongInputLength { field: &'static str, actual: usize },
    #[error(
        "fetch output transcript contains {actual} events, over the {MAX_FETCH_OUTPUT_EVENTS}-event limit"
    )]
    OutputEventLimit { actual: usize },
    #[error(
        "fetch output transcript contains {actual} payload bytes, over the {MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte limit"
    )]
    OutputPayloadLimit { actual: usize },
    #[error("fetch output transcript payload length exceeds usize range")]
    OutputPayloadLengthOverflow,
    #[error(
        "fetch request body contains {actual} bytes, over the {MAX_FETCH_REQUEST_BODY_BYTES}-byte limit"
    )]
    RequestBodyLimit { actual: usize },
    #[error("fetch input event {index} must be {expected}, got {actual}")]
    UnexpectedInputEvent {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("fetch output event {index} must be {expected}, got {actual}")]
    UnexpectedOutputEvent {
        index: usize,
        expected: &'static str,
        actual: String,
    },
    #[error("fetch input event {index} must use the fetch input canonicalization")]
    InputCanonicalizationMismatch { index: usize },
    #[error("fetch output event {index} must use the fetch output canonicalization")]
    OutputCanonicalizationMismatch { index: usize },
    #[error("fetch input.end payload must be empty")]
    NonEmptyInputEnd,
    #[error("fetch {field} event is not UTF-8: {source}")]
    Utf8 {
        field: &'static str,
        #[source]
        source: str::Utf8Error,
    },
    #[error("fetch {field} must be UTF-8 JSON: {source}")]
    Json {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("fetch stream verification failed: {0}")]
    Stream(#[from] StreamVerifyError),
}

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------
// Payload semantics: the dag-cbor event language inside signed fetch
// output transcripts. `FetchOutput` above verifies envelope signatures
// and hands out raw payload bytes; these codecs give those bytes their
// meaning. The codec strings version the payload shapes independently
// of the transcript canonicalization.
//
// Ownership boundary: these signed-payload codecs live here, not in
// hellas-adaptors. The reciprocal — converting to/from provider wire
// formats (OpenAI, Anthropic, SSE) — is adaptors' job and must never
// appear in this crate. rpc does not depend on adaptors; the vocabulary
// (crate::output) flows the other way. Rule of thumb: signed bytes → rpc,
// vendor-HTTP bytes → adaptors.
// ---------------------------------------------------------------------

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;

use crate::output::{
    OutputEvent, Provenance, StopReason, StructuredDelta, TextChannel, ToolCallArgumentsDelta,
    ToolCallEnd, ToolCallStart, Usage,
};
use crate::protocol::value::{CanonicalDecodeError, decode_canonical_dag_cbor};
use crate::{DagCborEncodeError, canonical_dag_cbor};

const EVENT_CODEC: &str = "hellas.fetch.output.event.v3";
const TERMINAL_CODEC: &str = "hellas.fetch.output.terminal.v2";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FetchEventPayload {
    TextDelta {
        index: u64,
        delta: String,
        channel: TextChannel,
    },
    ToolCallStart {
        index: u64,
        id: Option<String>,
        name: String,
    },
    ToolCallArgumentsDelta {
        index: u64,
        delta: String,
    },
    ToolCallEnd {
        index: u64,
        arguments: JsonValue,
    },
    StructuredOutputDelta(StructuredDelta),
    Adaptor(crate::output::AdaptorEvent),
    Usage(Usage),
    Provenance(Provenance),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FetchTerminalPayload {
    Finished {
        stop_reason: StopReason,
        usage: Option<Usage>,
        billable_units: u64,
    },
}

pub fn encode_fetch_event_payload(event: &OutputEvent) -> Result<Vec<u8>, FetchPayloadError> {
    let payload = FetchEventPayload::try_from(event)?;
    canonical_dag_cbor(&(EVENT_CODEC, payload)).map_err(FetchPayloadError::Encode)
}

pub fn decode_fetch_event_payload(bytes: &[u8]) -> Result<OutputEvent, FetchPayloadError> {
    let (codec, payload): (String, FetchEventPayload) = decode_canonical_dag_cbor(bytes)?;
    if codec != EVENT_CODEC {
        return Err(FetchPayloadError::CodecMismatch {
            expected: EVENT_CODEC,
            actual: codec,
        });
    }
    payload.try_into()
}

pub fn encode_fetch_terminal_payload(event: &OutputEvent) -> Result<Vec<u8>, FetchPayloadError> {
    let payload = match event {
        OutputEvent::Finished {
            stop_reason: StopReason::Cancelled,
            ..
        } => return Err(FetchPayloadError::CancelledTerminal),
        OutputEvent::Finished { stop_reason, usage } => FetchTerminalPayload::Finished {
            stop_reason: *stop_reason,
            usage: *usage,
            billable_units: fetch_billable_units(*usage),
        },
        OutputEvent::Error { .. } => return Err(FetchPayloadError::FailureAsTerminal),
        _ => return Err(FetchPayloadError::NonTerminalAsTerminal),
    };
    canonical_dag_cbor(&(TERMINAL_CODEC, payload)).map_err(FetchPayloadError::Encode)
}

pub fn decode_fetch_terminal_payload(
    bytes: &[u8],
) -> Result<FetchTerminalPayload, FetchPayloadError> {
    let (codec, payload): (String, FetchTerminalPayload) = decode_canonical_dag_cbor(bytes)?;
    if codec != TERMINAL_CODEC {
        return Err(FetchPayloadError::CodecMismatch {
            expected: TERMINAL_CODEC,
            actual: codec,
        });
    }
    let FetchTerminalPayload::Finished {
        stop_reason,
        usage,
        billable_units,
    } = &payload;
    if *stop_reason == StopReason::Cancelled {
        return Err(FetchPayloadError::CancelledTerminal);
    }
    let expected = fetch_billable_units(*usage);
    if *billable_units != expected {
        return Err(FetchPayloadError::BillableUnitsMismatch {
            expected,
            actual: *billable_units,
        });
    }
    Ok(payload)
}

fn fetch_billable_units(usage: Option<Usage>) -> u64 {
    usage
        .and_then(|usage| {
            usage
                .output_tokens
                .or(usage.total_tokens)
                .or(usage.input_tokens)
        })
        .unwrap_or_default()
}

impl FetchTerminalPayload {
    pub fn to_output_event(&self) -> OutputEvent {
        match self {
            Self::Finished {
                stop_reason, usage, ..
            } => OutputEvent::Finished {
                stop_reason: *stop_reason,
                usage: *usage,
            },
        }
    }

    pub const fn billable_units(&self) -> u64 {
        match self {
            Self::Finished { billable_units, .. } => *billable_units,
        }
    }
}

impl TryFrom<&OutputEvent> for FetchEventPayload {
    type Error = FetchPayloadError;

    fn try_from(event: &OutputEvent) -> Result<Self, Self::Error> {
        match event {
            OutputEvent::TextDelta {
                index,
                delta,
                channel,
            } => Ok(Self::TextDelta {
                index: (*index)
                    .try_into()
                    .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                delta: delta.clone(),
                channel: channel.clone(),
            }),
            OutputEvent::ToolCallStart(ToolCallStart { index, id, name }) => {
                Ok(Self::ToolCallStart {
                    index: (*index)
                        .try_into()
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    id: id.clone(),
                    name: name.clone(),
                })
            }
            OutputEvent::ToolCallArgumentsDelta(ToolCallArgumentsDelta { index, delta }) => {
                Ok(Self::ToolCallArgumentsDelta {
                    index: (*index)
                        .try_into()
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    delta: delta.clone(),
                })
            }
            OutputEvent::ToolCallEnd(ToolCallEnd { index, arguments }) => Ok(Self::ToolCallEnd {
                index: (*index)
                    .try_into()
                    .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                arguments: arguments.clone(),
            }),
            OutputEvent::StructuredOutputDelta(delta) => {
                Ok(Self::StructuredOutputDelta(delta.clone()))
            }
            OutputEvent::Adaptor(event) => Ok(Self::Adaptor(event.clone())),
            OutputEvent::Usage(usage) => Ok(Self::Usage(*usage)),
            OutputEvent::Provenance(provenance) => Ok(Self::Provenance(provenance.clone())),
            OutputEvent::Finished { .. } | OutputEvent::Error { .. } => {
                Err(FetchPayloadError::TerminalAsEvent)
            }
        }
    }
}

impl TryFrom<FetchEventPayload> for OutputEvent {
    type Error = FetchPayloadError;

    fn try_from(payload: FetchEventPayload) -> Result<Self, FetchPayloadError> {
        match payload {
            FetchEventPayload::TextDelta {
                index,
                delta,
                channel,
            } => Ok(Self::TextDelta {
                index: usize::try_from(index).map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                delta,
                channel,
            }),
            FetchEventPayload::ToolCallStart { index, id, name } => {
                Ok(Self::ToolCallStart(ToolCallStart {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    id,
                    name,
                }))
            }
            FetchEventPayload::ToolCallArgumentsDelta { index, delta } => {
                Ok(Self::ToolCallArgumentsDelta(ToolCallArgumentsDelta {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    delta,
                }))
            }
            FetchEventPayload::ToolCallEnd { index, arguments } => {
                Ok(Self::ToolCallEnd(ToolCallEnd {
                    index: usize::try_from(index)
                        .map_err(|_| FetchPayloadError::IndexOutOfRange)?,
                    arguments,
                }))
            }
            FetchEventPayload::StructuredOutputDelta(delta) => {
                Ok(Self::StructuredOutputDelta(delta))
            }
            FetchEventPayload::Adaptor(event) => Ok(Self::Adaptor(event)),
            FetchEventPayload::Usage(usage) => Ok(Self::Usage(usage)),
            FetchEventPayload::Provenance(provenance) => Ok(Self::Provenance(provenance)),
        }
    }
}

#[derive(Debug, Error)]
pub enum FetchPayloadError {
    #[error("fetch payload encode failed: {0}")]
    Encode(#[from] DagCborEncodeError),
    #[error("fetch payload decode failed: {0}")]
    Decode(#[from] CanonicalDecodeError),
    #[error("fetch payload codec mismatch: expected {expected}, got {actual}")]
    CodecMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("terminal fetch payload cannot be encoded as a stream event")]
    TerminalAsEvent,
    #[error("non-terminal fetch payload cannot be encoded as a terminal event")]
    NonTerminalAsTerminal,
    #[error("fetch cancellation is a failure")]
    CancelledTerminal,
    #[error("fetch failure cannot be signed as a success terminal")]
    FailureAsTerminal,
    #[error("fetch payload index does not fit this platform")]
    IndexOutOfRange,
    #[error("fetch billable_units must be {expected}, got {actual}")]
    BillableUnitsMismatch { expected: u64, actual: u64 },
}

#[cfg(test)]
mod payload_tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn overlong_tuple_header(canonical: &[u8]) -> Vec<u8> {
        assert_eq!(canonical[0], 0x82);
        let mut noncanonical = vec![0x98, 0x02];
        noncanonical.extend_from_slice(&canonical[1..]);
        noncanonical
    }

    #[test]
    fn event_payload_round_trip() {
        let event = OutputEvent::TextDelta {
            index: 2,
            delta: "hello".to_string(),
            channel: TextChannel::Reasoning,
        };

        let encoded = encode_fetch_event_payload(&event).unwrap();
        let decoded = decode_fetch_event_payload(&encoded).unwrap();

        assert_eq!(decoded, event);
    }

    #[test]
    fn event_payload_must_be_canonical_dag_cbor() {
        let canonical = encode_fetch_event_payload(&OutputEvent::TextDelta {
            index: 0,
            delta: "hello".to_string(),
            channel: TextChannel::Output,
        })
        .unwrap();
        let noncanonical = overlong_tuple_header(&canonical);
        let _: (String, FetchEventPayload) = serde_ipld_dagcbor::from_slice(&noncanonical)
            .expect("the permissive decoder accepts the equivalent tuple header");

        assert!(matches!(
            decode_fetch_event_payload(&noncanonical),
            Err(FetchPayloadError::Decode(_))
        ));
    }

    #[test]
    fn terminal_payload_must_be_canonical_dag_cbor() {
        let canonical = encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap();
        let noncanonical = overlong_tuple_header(&canonical);
        let _: (String, FetchTerminalPayload) = serde_ipld_dagcbor::from_slice(&noncanonical)
            .expect("the permissive decoder accepts the equivalent tuple header");

        assert!(matches!(
            decode_fetch_terminal_payload(&noncanonical),
            Err(FetchPayloadError::Decode(_))
        ));
    }

    #[test]
    fn terminal_payload_round_trip() {
        let event = OutputEvent::Finished {
            stop_reason: StopReason::MaxOutputTokens,
            usage: Some(Usage {
                input_tokens: Some(3),
                output_tokens: Some(4),
                total_tokens: Some(7),
            }),
        };

        let encoded = encode_fetch_terminal_payload(&event).unwrap();
        let decoded = decode_fetch_terminal_payload(&encoded).unwrap();

        assert_eq!(decoded.to_output_event(), event);
        assert_eq!(decoded.billable_units(), 4);
    }

    #[test]
    fn cancelled_terminal_is_rejected_by_both_codec_directions() {
        let event = OutputEvent::Finished {
            stop_reason: StopReason::Cancelled,
            usage: None,
        };
        assert!(matches!(
            encode_fetch_terminal_payload(&event),
            Err(FetchPayloadError::CancelledTerminal)
        ));

        let bytes = serde_ipld_dagcbor::to_vec(&(
            TERMINAL_CODEC,
            FetchTerminalPayload::Finished {
                stop_reason: StopReason::Cancelled,
                usage: None,
                billable_units: 0,
            },
        ))
        .unwrap();
        assert!(matches!(
            decode_fetch_terminal_payload(&bytes),
            Err(FetchPayloadError::CancelledTerminal)
        ));
    }

    #[test]
    fn terminal_payload_is_not_event_payload() {
        let event = OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        };

        assert!(matches!(
            encode_fetch_event_payload(&event).unwrap_err(),
            FetchPayloadError::TerminalAsEvent
        ));
    }

    #[test]
    fn event_payload_vector_is_pinned() {
        let event = OutputEvent::TextDelta {
            index: 0,
            delta: "hi".to_string(),
            channel: TextChannel::Output,
        };
        let actual = hex(&encode_fetch_event_payload(&event).unwrap());
        let expected = "82781c68656c6c61732e66657463682e6f75747075742e6576656e742e7633a1695465787444656c7461a36564656c746162686965696e64657800676368616e6e656c664f7574707574";
        assert_eq!(actual, expected);
    }
}
