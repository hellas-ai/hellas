use crate::commitment::TagError;
use crate::signature_wire::{
    public_key_from_pb, public_key_to_pb, signature_from_pb, signature_to_pb,
};
#[cfg(test)]
use crate::{Assurance, Operation, scheme_id};
use crate::{
    CanonicalizationId, Digest, EventCommitment, InputCommitment, InputEventBody,
    InputEventBodyParts, InputEventEnvelope, OutputEventBody, OutputEventBodyParts,
    OutputEventEnvelope, ProducerId, SchemeId, SignedInputEvent, SignedOutputEvent, StreamId,
    StreamVerifyError,
};

use crate::pb::execute as pb;

pub fn input_event_to_pb(event: &InputEventEnvelope) -> pb::InputEventEnvelope {
    let body = event.event().body();
    pb::InputEventEnvelope {
        body: Some(pb::InputEventBody {
            scheme: u32::from(body.scheme().to_byte()),
            sequence: body.sequence(),
            previous_event: body.previous_event().as_bytes().to_vec(),
            kind: body.kind().to_string(),
            payload_commitment: body.payload().as_bytes().to_vec(),
            signer: body.signer().as_bytes().to_vec(),
            canonicalization_id: body.canonicalization().as_bytes().to_vec(),
        }),
        signature: Some(signature_to_pb(event.event().signature())),
        public_key: Some(public_key_to_pb(event.event().public_key())),
        payload: event.payload().to_vec(),
    }
}

pub fn input_event_from_pb(
    event: pb::InputEventEnvelope,
) -> Result<InputEventEnvelope, StreamEnvelopeError> {
    let body = event.body.ok_or(StreamEnvelopeError::MissingBody)?;
    let signature = event
        .signature
        .ok_or(StreamEnvelopeError::MissingSignature)?;
    let public_key = event
        .public_key
        .ok_or(StreamEnvelopeError::MissingPublicKey)?;
    let public_key = public_key_from_pb(public_key)?;
    let signed = SignedInputEvent::from_parts(
        InputEventBody::from_parts(InputEventBodyParts {
            scheme: scheme_from_u32(body.scheme)?,
            sequence: body.sequence,
            previous_event: EventCommitment::from_digest(digest_from_bytes(
                "previous_event",
                &body.previous_event,
            )?),
            kind: body.kind,
            payload: digest_from_bytes("payload_commitment", &body.payload_commitment)?,
            signer: ProducerId::from_digest(digest_from_bytes("signer", &body.signer)?),
            canonicalization: CanonicalizationId::from_digest(digest_from_bytes(
                "canonicalization_id",
                &body.canonicalization_id,
            )?),
        }),
        signature_from_pb(signature)?,
        public_key,
    )?;
    Ok(InputEventEnvelope::new(signed, event.payload)?)
}

pub fn output_event_to_pb(event: &OutputEventEnvelope) -> pb::OutputEventEnvelope {
    let body = event.event().body();
    pb::OutputEventEnvelope {
        body: Some(pb::OutputEventBody {
            scheme: u32::from(body.scheme().to_byte()),
            input_commitment: body.input().as_bytes().to_vec(),
            stream_id: body.stream_id().as_bytes().to_vec(),
            sequence: body.sequence(),
            previous_event: body.previous_event().as_bytes().to_vec(),
            kind: body.kind().to_string(),
            payload_commitment: body.payload().as_bytes().to_vec(),
            signer: body.signer().as_bytes().to_vec(),
            canonicalization_id: body.canonicalization().as_bytes().to_vec(),
        }),
        signature: Some(signature_to_pb(event.event().signature())),
        public_key: Some(public_key_to_pb(event.event().public_key())),
        payload: event.payload().to_vec(),
    }
}

pub fn output_event_from_pb(
    event: pb::OutputEventEnvelope,
) -> Result<OutputEventEnvelope, StreamEnvelopeError> {
    let body = event.body.ok_or(StreamEnvelopeError::MissingBody)?;
    let signature = event
        .signature
        .ok_or(StreamEnvelopeError::MissingSignature)?;
    let public_key = event
        .public_key
        .ok_or(StreamEnvelopeError::MissingPublicKey)?;
    let public_key = public_key_from_pb(public_key)?;
    let signed = SignedOutputEvent::from_parts(
        OutputEventBody::from_parts(OutputEventBodyParts {
            scheme: scheme_from_u32(body.scheme)?,
            input: InputCommitment::from_digest(digest_from_bytes(
                "input_commitment",
                &body.input_commitment,
            )?),
            stream_id: StreamId::from_digest(digest_from_bytes("stream_id", &body.stream_id)?),
            sequence: body.sequence,
            previous_event: EventCommitment::from_digest(digest_from_bytes(
                "previous_event",
                &body.previous_event,
            )?),
            kind: body.kind,
            payload: digest_from_bytes("payload_commitment", &body.payload_commitment)?,
            signer: ProducerId::from_digest(digest_from_bytes("signer", &body.signer)?),
            canonicalization: CanonicalizationId::from_digest(digest_from_bytes(
                "canonicalization_id",
                &body.canonicalization_id,
            )?),
        }),
        signature_from_pb(signature)?,
        public_key,
    )?;
    Ok(OutputEventEnvelope::new(signed, event.payload)?)
}

fn scheme_from_u32(value: u32) -> Result<SchemeId, StreamEnvelopeError> {
    let value = u8::try_from(value).map_err(|_| StreamEnvelopeError::SchemeOutOfRange(value))?;
    Ok(SchemeId::from_byte(value)?)
}

fn digest_from_bytes(name: &'static str, bytes: &[u8]) -> Result<Digest, StreamEnvelopeError> {
    let bytes: [u8; Digest::LEN] = fixed_bytes(name, bytes)?;
    Ok(Digest::from_bytes(bytes))
}

fn fixed_bytes<const N: usize>(
    name: &'static str,
    bytes: &[u8],
) -> Result<[u8; N], StreamEnvelopeError> {
    bytes
        .try_into()
        .map_err(|_| StreamEnvelopeError::WrongLength {
            field: name,
            expected: N,
            actual: bytes.len(),
        })
}

#[derive(Debug, thiserror::Error)]
pub enum StreamEnvelopeError {
    #[error("stream event envelope is missing body")]
    MissingBody,
    #[error("stream event envelope is missing signature")]
    MissingSignature,
    #[error("stream event envelope is missing public key")]
    MissingPublicKey,
    #[error("{field} must be {expected} bytes, got {actual}")]
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("scheme id {0} does not fit in one byte")]
    SchemeOutOfRange(u32),
    #[error("unknown scheme id: {0}")]
    Scheme(#[from] TagError),
    #[error("signature error: {0}")]
    Signature(#[from] crate::SignatureError),
    #[error("signature wire error: {0}")]
    SignatureWire(#[from] crate::signature_wire::SignatureWireError),
    #[error("stream verification error: {0}")]
    Stream(#[from] StreamVerifyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CanonicalizationId, InputTranscriptBuilder, OutputTranscriptBuilder, ProducerSigningKey,
        input_genesis,
    };

    fn key(byte: u8) -> ProducerSigningKey {
        ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
    }

    fn canon() -> CanonicalizationId {
        CanonicalizationId::from_bytes(b"openai.responses.v1")
    }

    #[test]
    fn input_event_round_trips_through_proto() {
        let caller = key(1);
        let mut builder = InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon(),
        );
        builder
            .push("request.body", br#"{"model":"gpt-test"}"#.to_vec())
            .unwrap();
        let (events, _) = builder.finish().unwrap();

        let decoded = input_event_from_pb(input_event_to_pb(&events[0])).unwrap();

        assert_eq!(decoded, events[0]);
    }

    #[test]
    fn output_event_round_trips_through_proto() {
        let caller = key(1);
        let producer = key(2);
        let mut input_builder = InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon(),
        );
        input_builder.push("request.body", b"{}".to_vec()).unwrap();
        let (_, input) = input_builder.finish().unwrap();
        let mut output_builder = OutputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            input,
            &producer,
            canon(),
        );
        output_builder
            .push("response.delta", br#"{"delta":"ok"}"#.to_vec())
            .unwrap();
        let (events, _) = output_builder.finish().unwrap();

        let decoded = output_event_from_pb(output_event_to_pb(&events[0])).unwrap();

        assert_eq!(decoded, events[0]);
    }

    #[test]
    fn input_event_decode_rejects_bad_digest_length() {
        let caller = key(1);
        let mut builder = InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon(),
        );
        builder.push("request.body", b"{}".to_vec()).unwrap();
        let (events, _) = builder.finish().unwrap();
        let mut pb = input_event_to_pb(&events[0]);
        pb.body.as_mut().unwrap().previous_event.pop();

        assert!(matches!(
            input_event_from_pb(pb).unwrap_err(),
            StreamEnvelopeError::WrongLength {
                field: "previous_event",
                expected: 32,
                actual: 31,
            }
        ));
    }

    #[test]
    fn input_event_decode_preserves_signed_body_signer() {
        let caller = key(1);
        let mut builder = InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon(),
        );
        builder.push("request.body", b"{}".to_vec()).unwrap();
        let (events, _) = builder.finish().unwrap();
        let mut pb = input_event_to_pb(&events[0]);
        pb.body.as_mut().unwrap().signer = [0x11; 32].to_vec();

        assert!(matches!(
            input_event_from_pb(pb).unwrap_err(),
            StreamEnvelopeError::Stream(StreamVerifyError::SignerMismatch)
        ));
    }

    #[test]
    fn input_event_decode_does_not_recompute_previous_event() {
        let caller = key(1);
        let mut builder = InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon(),
        );
        builder.push("request.body", b"{}".to_vec()).unwrap();
        let (events, _) = builder.finish().unwrap();
        let mut pb = input_event_to_pb(&events[0]);
        pb.body.as_mut().unwrap().previous_event = input_genesis(
            scheme_id(Operation::Evaluate, Assurance::ProducerSigned),
            &caller.public_key(),
        )
        .as_bytes()
        .to_vec();

        let decoded = input_event_from_pb(pb).unwrap();

        assert_eq!(
            decoded.event().body().previous_event(),
            input_genesis(
                scheme_id(Operation::Evaluate, Assurance::ProducerSigned),
                &caller.public_key(),
            )
        );
    }
}
