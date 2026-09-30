use super::*;

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
}

fn canon(name: &str) -> CanonicalizationId {
    CanonicalizationId::from_bytes(name.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn input_transcript(caller: &ProducerSigningKey) -> (Vec<InputEventEnvelope>, InputCommitment) {
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        caller,
        canon("openai.responses.v1"),
    );
    builder
        .push("input", br#"{"model":"gpt-test"}"#.to_vec())
        .unwrap();
    builder.push("input", b"end".to_vec()).unwrap();
    builder.finish().unwrap()
}

fn output_transcript(
    producer: &ProducerSigningKey,
    input: InputCommitment,
) -> (Vec<OutputEventEnvelope>, EventCommitment) {
    let mut builder = OutputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        input,
        producer,
        canon("openai.responses.v1"),
    );
    builder
        .push(
            "output",
            br#"{"type":"response.output_text.delta","delta":"hi"}"#.to_vec(),
        )
        .unwrap();
    builder
        .push("output", br#"{"type":"response.completed"}"#.to_vec())
        .unwrap();
    builder.finish().unwrap()
}

#[test]
fn input_transcript_verifies_from_input_genesis() {
    let caller = key(1);
    let (events, input) = input_transcript(&caller);

    assert_eq!(
        verify_input_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller.public_key(),
            &events,
        )
        .unwrap(),
        input
    );
}

#[test]
fn output_transcript_verifies_from_output_genesis() {
    let caller = key(1);
    let producer = key(2);
    let (_, input) = input_transcript(&caller);
    let (events, _) = output_transcript(&producer, input);

    verify_output_event_envelopes(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        input,
        &producer.public_key(),
        &events,
    )
    .unwrap();
}

#[test]
fn output_envelope_heap_accounting_uses_allocated_capacities() {
    let caller = key(1);
    let producer = key(2);
    let (_, input) = input_transcript(&caller);
    let (events, _) = output_transcript(&producer, input);
    let original = &events[0];
    let rebuilt = rebuild_output_envelope(original, &|parts| {
        let mut kind = String::with_capacity(parts.kind.len() + 97);
        kind.push_str(&parts.kind);
        parts.kind = kind;
    });
    let mut payload = Vec::with_capacity(rebuilt.payload().len() + 113);
    payload.extend_from_slice(rebuilt.payload());
    let envelope = OutputEventEnvelope::new(rebuilt.event, payload)
        .expect("capacity does not change signed bytes");

    let expected = envelope
        .event
        .body
        .kind
        .capacity()
        .checked_add(envelope.payload.capacity())
        .unwrap();
    assert_eq!(envelope.retained_heap_bytes(), Some(expected));
    assert!(
        expected > envelope.event().body().kind().len() + envelope.payload().len(),
        "the fixture must distinguish allocation capacity from content length"
    );
    envelope.verify(&producer.public_key()).unwrap();
}

#[test]
fn wrong_caller_key_is_rejected() {
    let caller = key(1);
    let other = key(2);
    let (events, _) = input_transcript(&caller);

    assert_eq!(
        verify_input_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &other.public_key(),
            &events,
        )
        .unwrap_err(),
        StreamVerifyError::UnexpectedSigner
    );
}

#[test]
fn wrong_producer_key_is_rejected() {
    let caller = key(1);
    let producer = key(2);
    let other = key(3);
    let (_, input) = input_transcript(&caller);
    let (events, _) = output_transcript(&producer, input);

    assert_eq!(
        verify_output_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            input,
            &other.public_key(),
            &events,
        )
        .unwrap_err(),
        StreamVerifyError::UnexpectedSigner
    );
}

type Mutations<P> = Vec<(&'static str, Box<dyn Fn(&mut P)>)>;

fn flipped(digest: Digest) -> Digest {
    let mut bytes = digest.into_bytes();
    bytes[0] ^= 0x80;
    Digest::from_bytes(bytes)
}

fn rebuild_input_envelope(
    envelope: &InputEventEnvelope,
    mutate: &dyn Fn(&mut InputEventBodyParts),
) -> InputEventEnvelope {
    let body = envelope.event().body();
    let mut parts = InputEventBodyParts {
        scheme: body.scheme(),
        sequence: body.sequence(),
        previous_event: body.previous_event(),
        kind: body.kind().to_string(),
        payload: body.payload(),
        signer: body.signer(),
        canonicalization: body.canonicalization(),
    };
    mutate(&mut parts);
    let event = SignedInputEvent::from_parts(
        InputEventBody::from_parts(parts),
        *envelope.event().signature(),
        *envelope.event().public_key(),
    )
    .expect("signer unchanged");
    InputEventEnvelope::new(event, envelope.payload().to_vec()).expect("payload digest unchanged")
}

fn rebuild_output_envelope(
    envelope: &OutputEventEnvelope,
    mutate: &dyn Fn(&mut OutputEventBodyParts),
) -> OutputEventEnvelope {
    let body = envelope.event().body();
    let mut parts = OutputEventBodyParts {
        scheme: body.scheme(),
        input: body.input(),
        stream_id: body.stream_id(),
        sequence: body.sequence(),
        previous_event: body.previous_event(),
        kind: body.kind().to_string(),
        payload: body.payload(),
        signer: body.signer(),
        canonicalization: body.canonicalization(),
    };
    mutate(&mut parts);
    let event = SignedOutputEvent::from_parts(
        OutputEventBody::from_parts(parts),
        *envelope.event().signature(),
        *envelope.event().public_key(),
    )
    .expect("signer unchanged");
    OutputEventEnvelope::new(event, envelope.payload().to_vec()).expect("payload digest unchanged")
}

/// Every signed field of an input event, mutated in isolation with the
/// original signature kept, must fail verification.
#[test]
fn input_event_field_mutations_are_rejected() {
    let caller = key(1);
    let (events, _) = input_transcript(&caller);
    let envelope = &events[0];
    envelope.verify(&caller.public_key()).unwrap();

    let mutations: Mutations<InputEventBodyParts> = vec![
        (
            "scheme",
            Box::new(|p| p.scheme = scheme_id(Operation::Evaluate, Assurance::ProducerSigned)),
        ),
        ("sequence", Box::new(|p| p.sequence += 1)),
        (
            "previous_event",
            Box::new(|p| p.previous_event = EventCommitment::from_canonical_bytes(b"spliced")),
        ),
        ("kind", Box::new(|p| p.kind.push('x'))),
        (
            "canonicalization",
            Box::new(|p| p.canonicalization = canon("other.canonicalizer")),
        ),
    ];
    for (field, mutate) in mutations {
        let tampered = rebuild_input_envelope(envelope, mutate.as_ref());
        assert!(
            tampered.verify(&caller.public_key()).is_err(),
            "input event with mutated {field} must not verify"
        );
    }
}

/// Every signed field of an output event, mutated in isolation with the
/// original signature kept, must fail verification.
#[test]
fn output_event_field_mutations_are_rejected() {
    let caller = key(1);
    let producer = key(2);
    let (_, input) = input_transcript(&caller);
    let (events, _) = output_transcript(&producer, input);
    let envelope = &events[0];
    envelope.verify(&producer.public_key()).unwrap();

    let mutations: Mutations<OutputEventBodyParts> = vec![
        (
            "scheme",
            Box::new(|p| p.scheme = scheme_id(Operation::Evaluate, Assurance::ProducerSigned)),
        ),
        (
            "input",
            Box::new(|p| p.input = InputCommitment::from_digest(flipped(p.input.digest()))),
        ),
        (
            "stream_id",
            Box::new(|p| p.stream_id = StreamId::from_digest(flipped(p.stream_id.digest()))),
        ),
        ("sequence", Box::new(|p| p.sequence += 1)),
        (
            "previous_event",
            Box::new(|p| p.previous_event = EventCommitment::from_canonical_bytes(b"spliced")),
        ),
        ("kind", Box::new(|p| p.kind.push('x'))),
        (
            "canonicalization",
            Box::new(|p| p.canonicalization = canon("other.canonicalizer")),
        ),
    ];
    for (field, mutate) in mutations {
        let tampered = rebuild_output_envelope(envelope, mutate.as_ref());
        assert!(
            tampered.verify(&producer.public_key()).is_err(),
            "output event with mutated {field} must not verify"
        );
    }
}

/// The fields the signature cannot cover are guarded structurally:
/// payload bytes and the payload digest are cross-checked, the signer
/// is pinned to the public key at construction, and a flipped signature
/// byte fails outright.
#[test]
fn output_event_structural_mutations_are_rejected() {
    let caller = key(1);
    let producer = key(2);
    let other = key(3);
    let (_, input) = input_transcript(&caller);
    let (events, _) = output_transcript(&producer, input);
    let envelope = &events[0];

    // Substituted payload bytes are rejected at construction.
    assert_eq!(
        OutputEventEnvelope::new(envelope.event().clone(), b"forged".to_vec()).unwrap_err(),
        StreamVerifyError::PayloadMismatch
    );

    // A signer field claiming a different producer cannot be wrapped
    // around this public key.
    let body = envelope.event().body();
    let forged_signer = OutputEventBody::from_parts(OutputEventBodyParts {
        scheme: body.scheme(),
        input: body.input(),
        stream_id: body.stream_id(),
        sequence: body.sequence(),
        previous_event: body.previous_event(),
        kind: body.kind().to_string(),
        payload: body.payload(),
        signer: ProducerId::from_public_key(&other.public_key()),
        canonicalization: body.canonicalization(),
    });
    assert_eq!(
        SignedOutputEvent::from_parts(
            forged_signer,
            *envelope.event().signature(),
            *envelope.event().public_key(),
        )
        .unwrap_err(),
        StreamVerifyError::SignerMismatch
    );

    // A flipped signature byte fails verification.
    let mut signature_bytes = *envelope.event().signature().bytes();
    signature_bytes[7] ^= 0x01;
    let tampered = SignedOutputEvent::from_parts(
        envelope.event().body().clone(),
        Signature::Secp256k1(signature_bytes),
        *envelope.event().public_key(),
    )
    .unwrap();
    assert!(tampered.verify(&producer.public_key()).is_err());
}

#[test]
fn output_transcript_cannot_splice_to_different_input() {
    let caller = key(1);
    let producer = key(2);
    let (_, input) = input_transcript(&caller);
    let mut other_terminal = input.digest().into_bytes();
    other_terminal[0] ^= 0x80;
    let other_input = InputCommitment::from_digest(Digest::from_bytes(other_terminal));
    let (events, _) = output_transcript(&producer, input);

    assert_eq!(
        verify_output_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            other_input,
            &producer.public_key(),
            &events
        )
        .unwrap_err(),
        StreamVerifyError::InputCommitmentMismatch
    );
}

#[test]
fn stream_id_is_deterministic_from_input_commitment() {
    let caller = key(1);
    let (_, input) = input_transcript(&caller);

    assert_eq!(
        StreamId::from_input_commitment(input),
        StreamId::from_input_commitment(input)
    );
}

#[test]
fn canonicalization_id_affects_event_commitment() {
    let caller = key(1);
    let mut a = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        &caller,
        canon("a"),
    );
    let mut b = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        &caller,
        canon("b"),
    );
    let a = a.push("input", b"same".to_vec()).unwrap();
    let b = b.push("input", b"same".to_vec()).unwrap();

    assert_ne!(a, b);
}

#[test]
fn event_drop_or_reorder_is_rejected() {
    let caller = key(1);
    let (events, _) = input_transcript(&caller);

    assert_eq!(
        verify_input_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller.public_key(),
            &events[1..],
        )
        .unwrap_err(),
        StreamVerifyError::SequenceMismatch {
            expected: 0,
            actual: 1
        }
    );

    let reordered = vec![events[1].clone(), events[0].clone()];
    assert_eq!(
        verify_input_event_envelopes(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller.public_key(),
            &reordered,
        )
        .unwrap_err(),
        StreamVerifyError::SequenceMismatch {
            expected: 0,
            actual: 1
        }
    );
}

#[test]
fn event_envelope_rejects_payload_mismatch() {
    let caller = key(1);
    let (events, _) = input_transcript(&caller);

    assert_eq!(
        InputEventEnvelope::new(events[0].event().clone(), b"different".to_vec()).unwrap_err(),
        StreamVerifyError::PayloadMismatch
    );
}

#[test]
fn empty_builders_do_not_finish() {
    let caller = key(1);
    let producer = key(2);
    let (_, input) = input_transcript(&caller);

    assert_eq!(
        InputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            &caller,
            canon("openai.responses.v1"),
        )
        .finish()
        .unwrap_err(),
        StreamVerifyError::EmptyTranscript
    );
    assert_eq!(
        OutputTranscriptBuilder::new(
            scheme_id(Operation::Fetch, Assurance::ProducerSigned),
            input,
            &producer,
            canon("openai.responses.v1")
        )
        .finish()
        .unwrap_err(),
        StreamVerifyError::EmptyTranscript
    );
}

#[test]
fn input_event_commitment_vector_pinned() {
    let caller = key(1);
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        &caller,
        canon("openai.responses.v1"),
    );
    builder
        .push("input", br#"{"model":"gpt-test"}"#.to_vec())
        .unwrap();
    let (events, _) = builder.finish().unwrap();
    let actual = hex(events[0].event_commitment().as_bytes());

    assert_eq!(
        actual,
        "4f9db9f69e97d60b7355e3583226e221711c5d738554c128fd5dc56f7b7df6f5"
    );
}

/// The two bodies share one signature domain, so the canonical bytes are
/// what keep a signature from crossing over — and they cannot meet: an
/// input body opens with an eight-element array header and the input
/// tag, an output body with a ten-element header and the output tag.
/// Both halves are pinned against bodies sharing every field the two
/// types have in common, so a refactor that collapsed the distinction
/// would fail here rather than become a confusion risk.
#[test]
fn input_and_output_signature_preimages_cannot_meet() {
    let signer = key(1);
    let scheme = scheme_id(Operation::Evaluate, Assurance::ProducerSigned);
    let previous_event = EventCommitment::from_canonical_bytes(b"shared previous");
    let payload = Digest::hash(b"shared payload");
    let canonicalization = canon("shared.canonicalizer");
    let input = InputCommitment::from_digest(Digest::hash(b"shared input"));
    let input_body = InputEventBody::from_parts(InputEventBodyParts {
        scheme,
        sequence: 7,
        previous_event,
        kind: "shared".to_string(),
        payload,
        signer: signer.producer_id(),
        canonicalization,
    });
    let output_body = OutputEventBody::from_parts(OutputEventBodyParts {
        scheme,
        input,
        stream_id: StreamId::from_input_commitment(input),
        sequence: 7,
        previous_event,
        kind: "shared".to_string(),
        payload,
        signer: signer.producer_id(),
        canonicalization,
    });

    let input_bytes = input_body.canonical_bytes();
    let output_bytes = output_body.canonical_bytes();
    assert_eq!(input_bytes[0], 0x88, "input body opens with array(8)");
    assert_eq!(output_bytes[0], 0x8a, "output body opens with array(10)");
    assert!(
        input_bytes
            .windows(tags::STREAM_INPUT_EVENT_V2.len())
            .any(|window| window == tags::STREAM_INPUT_EVENT_V2.as_bytes())
    );
    assert!(
        output_bytes
            .windows(tags::STREAM_OUTPUT_EVENT_V2.len())
            .any(|window| window == tags::STREAM_OUTPUT_EVENT_V2.as_bytes())
    );

    assert_ne!(
        input_body.signature_preimage(),
        output_body.signature_preimage()
    );
}
