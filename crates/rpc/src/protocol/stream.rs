use serde::{Deserialize, Serialize};

use crate::signature::verify_digest_signature;
#[cfg(test)]
use crate::{Assurance, Operation, scheme_id};
use crate::{
    DagCborEncoder, Digest, ProducerId, ProducerSigningKey, PublicKey, SchemeId, Signature,
    SignatureError, hash_tuple, tags,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CanonicalizationId(Digest);

impl CanonicalizationId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hash_tuple(tags::STREAM_CANONICALIZATION_ID_V2, &[bytes]))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventCommitment(Digest);

impl EventCommitment {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Self {
        Self(Digest::hash(bytes))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InputCommitment(Digest);

impl InputCommitment {
    pub fn from_terminal_event(event: EventCommitment) -> Self {
        Self(hash_tuple(
            tags::STREAM_INPUT_COMMITMENT_V2,
            &[event.as_bytes()],
        ))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StreamId(Digest);

impl StreamId {
    pub fn from_input_commitment(input: InputCommitment) -> Self {
        Self(hash_tuple(tags::STREAM_ID_V2, &[input.as_bytes()]))
    }

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Digest::LEN] {
        self.0.as_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEventBodyParts {
    pub scheme: SchemeId,
    pub sequence: u64,
    pub previous_event: EventCommitment,
    pub kind: String,
    pub payload: Digest,
    pub signer: ProducerId,
    pub canonicalization: CanonicalizationId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEventBody {
    scheme: SchemeId,
    sequence: u64,
    previous_event: EventCommitment,
    kind: String,
    payload: Digest,
    signer: ProducerId,
    canonicalization: CanonicalizationId,
}

impl InputEventBody {
    pub fn from_parts(parts: InputEventBodyParts) -> Self {
        Self {
            scheme: parts.scheme,
            sequence: parts.sequence,
            previous_event: parts.previous_event,
            kind: parts.kind,
            payload: parts.payload,
            signer: parts.signer,
            canonicalization: parts.canonicalization,
        }
    }

    pub const fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn previous_event(&self) -> EventCommitment {
        self.previous_event
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub const fn payload(&self) -> Digest {
        self.payload
    }

    pub const fn signer(&self) -> ProducerId {
        self.signer
    }

    pub const fn canonicalization(&self) -> CanonicalizationId {
        self.canonicalization
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(8);
        encoder.str(tags::STREAM_INPUT_EVENT_V2);
        encoder.u64(self.scheme.to_byte() as u64);
        encoder.u64(self.sequence);
        encoder.bytes(self.previous_event.as_bytes());
        encoder.str(&self.kind);
        encoder.bytes(self.payload.as_bytes());
        encoder.bytes(self.signer.as_bytes());
        encoder.bytes(self.canonicalization.as_bytes());
        encoder.into_bytes()
    }

    pub fn event_commitment(&self) -> EventCommitment {
        EventCommitment::from_canonical_bytes(&self.canonical_bytes())
    }

    /// The digest this body is signed over.
    ///
    /// Input and output bodies are signed under the one
    /// [`tags::STREAM_EVENT_SIGNATURE_V2`] domain, so the tag alone does
    /// not say which side of a stream a signature is for; the canonical
    /// bytes inside it do. An input body always opens with an
    /// eight-element array header (`0x88`) and the
    /// [`tags::STREAM_INPUT_EVENT_V2`] string, an output body with a
    /// ten-element header (`0x8a`) and [`tags::STREAM_OUTPUT_EVENT_V2`],
    /// so no input body's preimage can ever be an output body's: the two
    /// differ at byte 0. The embedded string is also what domains
    /// [`Self::event_commitment`], which hashes the same bytes with no
    /// outer tag at all.
    pub fn signature_preimage(&self) -> Digest {
        hash_tuple(tags::STREAM_EVENT_SIGNATURE_V2, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEventBodyParts {
    pub scheme: SchemeId,
    pub input: InputCommitment,
    pub stream_id: StreamId,
    pub sequence: u64,
    pub previous_event: EventCommitment,
    pub kind: String,
    pub payload: Digest,
    pub signer: ProducerId,
    pub canonicalization: CanonicalizationId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEventBody {
    scheme: SchemeId,
    input: InputCommitment,
    stream_id: StreamId,
    sequence: u64,
    previous_event: EventCommitment,
    kind: String,
    payload: Digest,
    signer: ProducerId,
    canonicalization: CanonicalizationId,
}

impl OutputEventBody {
    pub fn from_parts(parts: OutputEventBodyParts) -> Self {
        Self {
            scheme: parts.scheme,
            input: parts.input,
            stream_id: parts.stream_id,
            sequence: parts.sequence,
            previous_event: parts.previous_event,
            kind: parts.kind,
            payload: parts.payload,
            signer: parts.signer,
            canonicalization: parts.canonicalization,
        }
    }

    pub const fn scheme(&self) -> SchemeId {
        self.scheme
    }

    pub const fn input(&self) -> InputCommitment {
        self.input
    }

    pub const fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn previous_event(&self) -> EventCommitment {
        self.previous_event
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub const fn payload(&self) -> Digest {
        self.payload
    }

    pub const fn signer(&self) -> ProducerId {
        self.signer
    }

    pub const fn canonicalization(&self) -> CanonicalizationId {
        self.canonicalization
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(10);
        encoder.str(tags::STREAM_OUTPUT_EVENT_V2);
        encoder.u64(self.scheme.to_byte() as u64);
        encoder.bytes(self.input.as_bytes());
        encoder.bytes(self.stream_id.as_bytes());
        encoder.u64(self.sequence);
        encoder.bytes(self.previous_event.as_bytes());
        encoder.str(&self.kind);
        encoder.bytes(self.payload.as_bytes());
        encoder.bytes(self.signer.as_bytes());
        encoder.bytes(self.canonicalization.as_bytes());
        encoder.into_bytes()
    }

    pub fn event_commitment(&self) -> EventCommitment {
        EventCommitment::from_canonical_bytes(&self.canonical_bytes())
    }

    /// The digest this body is signed over. It shares the
    /// [`tags::STREAM_EVENT_SIGNATURE_V2`] domain with the input side;
    /// why a preimage cannot cross over is spelled out on
    /// [`InputEventBody::signature_preimage`].
    pub fn signature_preimage(&self) -> Digest {
        hash_tuple(tags::STREAM_EVENT_SIGNATURE_V2, &[&self.canonical_bytes()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInputEvent {
    body: InputEventBody,
    signature: Signature,
    public_key: PublicKey,
}

impl SignedInputEvent {
    pub fn sign(body: InputEventBody, key: &ProducerSigningKey) -> Result<Self, StreamVerifyError> {
        let public_key = key.public_key();
        if body.signer != ProducerId::from_public_key(&public_key) {
            return Err(StreamVerifyError::SignerMismatch);
        }
        let signature = key.sign_digest(body.signature_preimage())?;
        Ok(Self {
            body,
            signature,
            public_key,
        })
    }

    pub fn from_parts(
        body: InputEventBody,
        signature: Signature,
        public_key: PublicKey,
    ) -> Result<Self, StreamVerifyError> {
        if body.signer != ProducerId::from_public_key(&public_key) {
            return Err(StreamVerifyError::SignerMismatch);
        }
        Ok(Self {
            body,
            signature,
            public_key,
        })
    }

    pub const fn body(&self) -> &InputEventBody {
        &self.body
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn event_commitment(&self) -> EventCommitment {
        self.body.event_commitment()
    }

    pub fn verify(&self, expected_key: &PublicKey) -> Result<(), StreamVerifyError> {
        verify_signed_event(
            expected_key,
            &self.public_key,
            self.body.signer,
            &self.signature,
            self.body.signature_preimage(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOutputEvent {
    body: OutputEventBody,
    signature: Signature,
    public_key: PublicKey,
}

impl SignedOutputEvent {
    pub fn sign(
        body: OutputEventBody,
        key: &ProducerSigningKey,
    ) -> Result<Self, StreamVerifyError> {
        let public_key = key.public_key();
        if body.signer != ProducerId::from_public_key(&public_key) {
            return Err(StreamVerifyError::SignerMismatch);
        }
        let signature = key.sign_digest(body.signature_preimage())?;
        Ok(Self {
            body,
            signature,
            public_key,
        })
    }

    pub fn from_parts(
        body: OutputEventBody,
        signature: Signature,
        public_key: PublicKey,
    ) -> Result<Self, StreamVerifyError> {
        if body.signer != ProducerId::from_public_key(&public_key) {
            return Err(StreamVerifyError::SignerMismatch);
        }
        Ok(Self {
            body,
            signature,
            public_key,
        })
    }

    pub const fn body(&self) -> &OutputEventBody {
        &self.body
    }

    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn event_commitment(&self) -> EventCommitment {
        self.body.event_commitment()
    }

    pub fn verify(&self, expected_key: &PublicKey) -> Result<(), StreamVerifyError> {
        verify_signed_event(
            expected_key,
            &self.public_key,
            self.body.signer,
            &self.signature,
            self.body.signature_preimage(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputEventEnvelope {
    event: SignedInputEvent,
    payload: Vec<u8>,
}

impl InputEventEnvelope {
    pub fn new(
        event: SignedInputEvent,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, StreamVerifyError> {
        let payload = payload.into();
        if event.body().payload() != Digest::hash(&payload) {
            return Err(StreamVerifyError::PayloadMismatch);
        }
        Ok(Self { event, payload })
    }

    pub const fn event(&self) -> &SignedInputEvent {
        &self.event
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn event_commitment(&self) -> EventCommitment {
        self.event.event_commitment()
    }

    pub fn verify(&self, expected_key: &PublicKey) -> Result<(), StreamVerifyError> {
        if self.event.body().payload() != Digest::hash(&self.payload) {
            return Err(StreamVerifyError::PayloadMismatch);
        }
        self.event.verify(expected_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputEventEnvelope {
    event: SignedOutputEvent,
    payload: Vec<u8>,
}

impl OutputEventEnvelope {
    pub fn new(
        event: SignedOutputEvent,
        payload: impl Into<Vec<u8>>,
    ) -> Result<Self, StreamVerifyError> {
        let payload = payload.into();
        if event.body().payload() != Digest::hash(&payload) {
            return Err(StreamVerifyError::PayloadMismatch);
        }
        Ok(Self { event, payload })
    }

    pub const fn event(&self) -> &SignedOutputEvent {
        &self.event
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Exact requested heap allocation retained by this envelope's variable
    /// buffers, excluding the fixed-size [`OutputEventEnvelope`] value itself.
    ///
    /// `OutputEventBody` owns only its `kind` string; `Signature`, `PublicKey`,
    /// commitments, identifiers, and counters are fixed-size values. The
    /// envelope's opaque payload is its only other allocation.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> Option<usize> {
        self.event
            .body
            .kind
            .capacity()
            .checked_add(self.payload.capacity())
    }

    pub fn event_commitment(&self) -> EventCommitment {
        self.event.event_commitment()
    }

    pub fn verify(&self, expected_key: &PublicKey) -> Result<(), StreamVerifyError> {
        if self.event.body().payload() != Digest::hash(&self.payload) {
            return Err(StreamVerifyError::PayloadMismatch);
        }
        self.event.verify(expected_key)
    }
}

pub struct InputTranscriptBuilder<'a> {
    scheme: SchemeId,
    signing_key: &'a ProducerSigningKey,
    canonicalization: CanonicalizationId,
    previous_event: EventCommitment,
    next_sequence: u64,
    events: Vec<InputEventEnvelope>,
}

impl<'a> InputTranscriptBuilder<'a> {
    pub fn new(
        scheme: SchemeId,
        signing_key: &'a ProducerSigningKey,
        canonicalization: CanonicalizationId,
    ) -> Self {
        Self {
            scheme,
            signing_key,
            canonicalization,
            previous_event: input_genesis(scheme, &signing_key.public_key()),
            next_sequence: 0,
            events: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        kind: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<EventCommitment, StreamVerifyError> {
        let payload = payload.into();
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(StreamVerifyError::SequenceOverflow)?;
        let public_key = self.signing_key.public_key();
        let body = InputEventBody::from_parts(InputEventBodyParts {
            scheme: self.scheme,
            sequence,
            previous_event: self.previous_event,
            kind: kind.into(),
            payload: Digest::hash(&payload),
            signer: ProducerId::from_public_key(&public_key),
            canonicalization: self.canonicalization,
        });
        let event = SignedInputEvent::sign(body, self.signing_key)?;
        let envelope = InputEventEnvelope::new(event, payload)?;
        let commitment = envelope.event_commitment();
        self.previous_event = commitment;
        self.next_sequence = next_sequence;
        self.events.push(envelope);
        Ok(commitment)
    }

    pub fn finish(self) -> Result<(Vec<InputEventEnvelope>, InputCommitment), StreamVerifyError> {
        if self.events.is_empty() {
            return Err(StreamVerifyError::EmptyTranscript);
        }
        Ok((
            self.events,
            InputCommitment::from_terminal_event(self.previous_event),
        ))
    }
}

pub struct OutputTranscriptBuilder<'a> {
    scheme: SchemeId,
    input: InputCommitment,
    stream_id: StreamId,
    signing_key: &'a ProducerSigningKey,
    canonicalization: CanonicalizationId,
    previous_event: EventCommitment,
    next_sequence: u64,
    events: Vec<OutputEventEnvelope>,
}

impl<'a> OutputTranscriptBuilder<'a> {
    pub fn new(
        scheme: SchemeId,
        input: InputCommitment,
        signing_key: &'a ProducerSigningKey,
        canonicalization: CanonicalizationId,
    ) -> Self {
        let stream_id = StreamId::from_input_commitment(input);
        Self {
            scheme,
            input,
            stream_id,
            signing_key,
            canonicalization,
            previous_event: output_genesis(input, stream_id),
            next_sequence: 0,
            events: Vec::new(),
        }
    }

    pub fn resume_verified(
        scheme: SchemeId,
        input: InputCommitment,
        signing_key: &'a ProducerSigningKey,
        canonicalization: CanonicalizationId,
        events: Vec<OutputEventEnvelope>,
    ) -> Result<Self, StreamVerifyError> {
        let public_key = signing_key.public_key();
        verify_output_event_envelopes(scheme, input, &public_key, &events)?;
        let stream_id = StreamId::from_input_commitment(input);
        let previous_event = events
            .last()
            .map(OutputEventEnvelope::event_commitment)
            .ok_or(StreamVerifyError::EmptyTranscript)?;
        let next_sequence =
            u64::try_from(events.len()).map_err(|_| StreamVerifyError::SequenceOverflow)?;
        Ok(Self {
            scheme,
            input,
            stream_id,
            signing_key,
            canonicalization,
            previous_event,
            next_sequence,
            events,
        })
    }

    pub fn push(
        &mut self,
        kind: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<EventCommitment, StreamVerifyError> {
        self.push_envelope(kind, payload)
            .map(|envelope| envelope.event_commitment())
    }

    pub fn push_envelope(
        &mut self,
        kind: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<OutputEventEnvelope, StreamVerifyError> {
        let payload = payload.into();
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(StreamVerifyError::SequenceOverflow)?;
        let public_key = self.signing_key.public_key();
        let body = OutputEventBody::from_parts(OutputEventBodyParts {
            scheme: self.scheme,
            input: self.input,
            stream_id: self.stream_id,
            sequence,
            previous_event: self.previous_event,
            kind: kind.into(),
            payload: Digest::hash(&payload),
            signer: ProducerId::from_public_key(&public_key),
            canonicalization: self.canonicalization,
        });
        let event = SignedOutputEvent::sign(body, self.signing_key)?;
        let envelope = OutputEventEnvelope::new(event, payload)?;
        let commitment = envelope.event_commitment();
        self.previous_event = commitment;
        self.next_sequence = next_sequence;
        self.events.push(envelope.clone());
        Ok(envelope)
    }

    pub fn finish(self) -> Result<(Vec<OutputEventEnvelope>, EventCommitment), StreamVerifyError> {
        if self.events.is_empty() {
            return Err(StreamVerifyError::EmptyTranscript);
        }
        Ok((self.events, self.previous_event))
    }
}

fn verify_signed_event(
    expected_key: &PublicKey,
    actual_key: &PublicKey,
    signer: ProducerId,
    signature: &Signature,
    preimage: Digest,
) -> Result<(), StreamVerifyError> {
    if actual_key != expected_key {
        return Err(StreamVerifyError::UnexpectedSigner);
    }
    if signer != ProducerId::from_public_key(expected_key) {
        return Err(StreamVerifyError::SignerMismatch);
    }
    verify_digest_signature(expected_key, signature, preimage)?;
    Ok(())
}

pub fn input_genesis(scheme: SchemeId, caller_key: &PublicKey) -> EventCommitment {
    let scheme = [scheme.to_byte()];
    let key_kind = [caller_key.kind().to_byte()];
    EventCommitment::from_digest(hash_tuple(
        tags::STREAM_INPUT_GENESIS_V2,
        &[&scheme, &key_kind, caller_key.bytes()],
    ))
}

pub fn output_genesis(input: InputCommitment, stream_id: StreamId) -> EventCommitment {
    EventCommitment::from_digest(hash_tuple(
        tags::STREAM_OUTPUT_GENESIS_V2,
        &[input.as_bytes(), stream_id.as_bytes()],
    ))
}

pub fn verify_input_event_envelopes(
    scheme: SchemeId,
    caller_key: &PublicKey,
    events: &[InputEventEnvelope],
) -> Result<InputCommitment, StreamVerifyError> {
    for event in events {
        event.verify(caller_key)?;
    }
    verify_input_event_chain(
        scheme,
        caller_key,
        events.iter().map(InputEventEnvelope::event),
    )
}

fn verify_input_event_chain<'a>(
    scheme: SchemeId,
    caller_key: &PublicKey,
    events: impl IntoIterator<Item = &'a SignedInputEvent>,
) -> Result<InputCommitment, StreamVerifyError> {
    let mut previous = input_genesis(scheme, caller_key);
    let mut saw_event = false;
    for (expected_sequence, event) in events.into_iter().enumerate() {
        saw_event = true;
        let body = event.body();
        if body.scheme() != scheme {
            return Err(StreamVerifyError::SchemeMismatch);
        }
        let expected_sequence =
            u64::try_from(expected_sequence).map_err(|_| StreamVerifyError::SequenceOverflow)?;
        if body.sequence() != expected_sequence {
            return Err(StreamVerifyError::SequenceMismatch {
                expected: expected_sequence,
                actual: body.sequence(),
            });
        }
        if body.previous_event() != previous {
            return Err(StreamVerifyError::PreviousEventMismatch);
        }
        previous = event.event_commitment();
    }

    if saw_event {
        Ok(InputCommitment::from_terminal_event(previous))
    } else {
        Err(StreamVerifyError::EmptyTranscript)
    }
}

pub fn verify_output_event_envelopes(
    scheme: SchemeId,
    input: InputCommitment,
    producer_key: &PublicKey,
    events: &[OutputEventEnvelope],
) -> Result<EventCommitment, StreamVerifyError> {
    verify_output_event_envelope_iter(scheme, input, producer_key, events.iter())
}

/// Verify one signed output envelope as the exact next link in a stream.
pub fn verify_output_event_continuation(
    scheme: SchemeId,
    input: InputCommitment,
    producer_key: &PublicKey,
    expected_sequence: u64,
    expected_previous: EventCommitment,
    event: &OutputEventEnvelope,
) -> Result<EventCommitment, StreamVerifyError> {
    event.verify(producer_key)?;
    let body = event.event().body();
    if body.scheme() != scheme {
        return Err(StreamVerifyError::SchemeMismatch);
    }
    if body.input() != input {
        return Err(StreamVerifyError::InputCommitmentMismatch);
    }
    if body.stream_id() != StreamId::from_input_commitment(input) {
        return Err(StreamVerifyError::StreamIdMismatch);
    }
    if body.sequence() != expected_sequence {
        return Err(StreamVerifyError::SequenceMismatch {
            expected: expected_sequence,
            actual: body.sequence(),
        });
    }
    if body.previous_event() != expected_previous {
        return Err(StreamVerifyError::PreviousEventMismatch);
    }
    Ok(event.event_commitment())
}

pub(crate) fn verify_output_event_envelope_iter<'a>(
    scheme: SchemeId,
    input: InputCommitment,
    producer_key: &PublicKey,
    events: impl Iterator<Item = &'a OutputEventEnvelope>,
) -> Result<EventCommitment, StreamVerifyError> {
    let mut previous = output_genesis(input, StreamId::from_input_commitment(input));
    let mut saw_event = false;
    for (expected_sequence, event) in events.enumerate() {
        saw_event = true;
        let expected_sequence =
            u64::try_from(expected_sequence).map_err(|_| StreamVerifyError::SequenceOverflow)?;
        previous = verify_output_event_continuation(
            scheme,
            input,
            producer_key,
            expected_sequence,
            previous,
            event,
        )?;
    }
    if saw_event {
        Ok(previous)
    } else {
        Err(StreamVerifyError::EmptyTranscript)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamVerifyError {
    #[error("stream transcript is empty")]
    EmptyTranscript,
    #[error("event scheme does not match transcript scheme")]
    SchemeMismatch,
    #[error("event sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("event previous commitment does not match transcript chain")]
    PreviousEventMismatch,
    #[error("event signer does not match expected key")]
    UnexpectedSigner,
    #[error("event signer id does not match public key")]
    SignerMismatch,
    #[error("output event input commitment does not match transcript input")]
    InputCommitmentMismatch,
    #[error("output event stream id does not match transcript input")]
    StreamIdMismatch,
    #[error("event sequence exceeded u64 range")]
    SequenceOverflow,
    #[error("event payload bytes do not match the signed payload commitment")]
    PayloadMismatch,
    #[error("signature verification failed: {0}")]
    Signature(#[from] SignatureError),
}

#[cfg(test)]
mod tests;
