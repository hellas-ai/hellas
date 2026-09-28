use super::*;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, FetchProtocolError, build_input_events, build_output_events,
    encode_fetch_event_payload, encode_fetch_terminal_payload,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::stream::{input_event_to_pb, output_event_to_pb};
use hellas_rpc::{ContentId, JobTerms, ProducerSigningKey as SigningKey, RequestCommitment};

const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
}

fn fetch_request(caller: &SigningKey, service: &str, method: &str, payload: &[u8]) -> FetchRequest {
    let events = build_input_events(
        service,
        method,
        payload,
        ContentId::from_bytes([9; 32]),
        TEST_ASSURANCE,
        caller,
    )
    .unwrap();
    FetchRequest {
        input: events.iter().map(input_event_to_pb).collect(),
    }
}

fn finished_terminal_payload() -> Vec<u8> {
    encode_fetch_terminal_payload(&OutputEvent::Finished {
        stop_reason: StopReason::EndOfText,
        usage: None,
    })
    .unwrap()
}

fn terminal_event(events: &[OutputEventEnvelope]) -> OutputEventEnvelope {
    events.last().expect("fixture terminal event").clone()
}

fn fetch_finished(
    request: &FetchRequest,
    producer: &SigningKey,
    terminal_payload: &[u8],
) -> WorkFinished {
    let input = verified_fetch_input(request).unwrap().input_commitment;
    let events = build_output_events(input, TEST_ASSURANCE, terminal_payload, producer).unwrap();
    WorkFinished {
        terminal_output_event: events.last().map(output_event_to_pb),
        assurance_evidence: Vec::new(),
    }
}

fn trust_in(producers: &[&SigningKey]) -> ProducerTrust {
    ProducerTrust::keys(producers.iter().map(|key| key.public_key()))
}

fn input_commitment_for(request: &FetchRequest) -> InputCommitment {
    verified_fetch_input(request).unwrap().input_commitment
}

#[test]
fn fetch_finished_verifies_signed_output_transcript() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let terminal_payload = finished_terminal_payload();
    let finished = fetch_finished(&request, &producer, &terminal_payload);

    let input = input_commitment_for(&request);
    let outcome = parse_fetch_finished(finished, input, TEST_ASSURANCE).unwrap();
    let FetchOutcome::Completed {
        terminal,
        output_events,
    } = outcome
    else {
        panic!("expected completed fetch outcome");
    };
    assert_eq!(
        terminal,
        FetchTerminalPayload::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
            billable_units: 0,
        }
    );
    assert_eq!(output_events.len(), 1);
}

#[test]
fn fetch_ticket_must_name_the_pinned_provider_genesis() {
    let caller = key(1);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let provider_genesis = b"provider enrollment".to_vec();
    let actual_provider = ContentId::hash(&provider_genesis);
    let ticket = hellas_rpc::run_ticket::ticket_to_pb(
        JobTerms {
            request: RequestCommitment::from_digest(input.digest()),
            provider_genesis: actual_provider,
            assurance: TEST_ASSURANCE,
            amount: 1,
            ttl_ms: 1_000,
        },
        provider_genesis,
    )
    .unwrap();

    let error = validate_fetch_ticket(
        ticket,
        input,
        TEST_ASSURANCE,
        ContentId::from_bytes([0x42; 32]),
    )
    .unwrap_err();
    assert!(error.to_string().contains("pinned provider"));
}

#[test]
fn verify_chunk_rejects_untrusted_producer_key() {
    let caller = key(1);
    let producer = key(2);
    let trusted_producer = key(3);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let chunk = builder.push_event(br#"{"delta":"a"}"#.to_vec()).unwrap();

    let mut verifier =
        FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&trusted_producer]));
    let err = verifier.verify_chunk(chunk).unwrap_err();
    assert!(err.to_string().contains("untrusted producer key"));
}

#[test]
fn verify_chunk_accepts_trusted_producer_key() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let chunk = builder.push_event(br#"{"delta":"a"}"#.to_vec()).unwrap();

    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
    verifier.verify_chunk(chunk).unwrap();
}

#[test]
fn rejected_first_chunk_does_not_pin_its_producer() {
    let caller = key(1);
    let first_producer = key(2);
    let second_producer = key(3);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let other_request = fetch_request(&caller, "echo", "run", br#"{"x":2}"#);
    let input = input_commitment_for(&request);
    let other_input = input_commitment_for(&other_request);
    let invalid = FetchOutputTranscriptBuilder::new(other_input, TEST_ASSURANCE, &first_producer)
        .push_event(br#"{"delta":"wrong input"}"#.to_vec())
        .unwrap();
    let valid = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &second_producer)
        .push_event(br#"{"delta":"valid"}"#.to_vec())
        .unwrap();
    let mut verifier = FetchChunkVerifier::new(
        input,
        TEST_ASSURANCE,
        trust_in(&[&first_producer, &second_producer]),
    );

    assert!(
        verifier
            .verify_chunk(invalid)
            .unwrap_err()
            .to_string()
            .contains("input commitment mismatch")
    );
    verifier.verify_chunk(valid).unwrap();
    assert_eq!(verifier.producer_key, Some(second_producer.public_key()));
}

#[test]
fn multi_event_replay_framing_verifies_end_to_end() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let mut streamed = Vec::new();
    for delta in ["one", "two"] {
        let payload = encode_fetch_event_payload(&OutputEvent::TextDelta {
            index: 0,
            delta: delta.to_string(),
            channel: TextChannel::Output,
        })
        .unwrap();
        streamed.push(builder.push_event(payload).unwrap());
    }
    let output_events = builder.finish(finished_terminal_payload()).unwrap();
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
    let mut expected_position = 0_u64;

    for output_event in streamed {
        expected_position += output_event.payload().len() as u64;
        let wire = WorkEvent {
            kind: Some(work_event::Kind::Chunk(pb::WorkChunk {
                output_event: Some(output_event_to_pb(&output_event)),
            })),
        };
        let FetchExecutionEvent::Chunk { position, .. } =
            verify_fetch_work_event(&mut verifier, wire).unwrap()
        else {
            panic!("replay prefix should decode as a chunk");
        };
        assert_eq!(position, expected_position);
    }

    let terminal = WorkEvent {
        kind: Some(work_event::Kind::Finished(WorkFinished {
            terminal_output_event: output_events.last().map(output_event_to_pb),
            assurance_evidence: Vec::new(),
        })),
    };
    let FetchExecutionEvent::Done(FetchOutcome::Completed {
        output_events: verified,
        ..
    }) = verify_fetch_work_event(&mut verifier, terminal).unwrap()
    else {
        panic!("replay terminal should complete the transcript");
    };
    assert_eq!(verified, output_events);
}

#[test]
fn verifier_bounds_retained_streamed_event_count() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

    for _ in 0..MAX_FETCH_OUTPUT_EVENTS - 1 {
        verifier
            .verify_chunk(builder.push_event(Vec::new()).unwrap())
            .unwrap();
    }
    let error = verifier
        .verify_chunk(builder.push_event(Vec::new()).unwrap())
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains(&format!("{}-chunk limit", MAX_FETCH_OUTPUT_EVENTS - 1))
    );
    assert_eq!(verifier.events.len(), MAX_FETCH_OUTPUT_EVENTS - 1);
}

#[test]
fn verifier_bounds_retained_streamed_payload_bytes() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

    verifier
        .verify_chunk(
            builder
                .push_event(vec![0; MAX_FETCH_OUTPUT_PAYLOAD_BYTES])
                .unwrap(),
        )
        .unwrap();
    let error = verifier
        .verify_chunk(builder.push_event(vec![1]).unwrap())
        .unwrap_err();

    assert!(error.to_string().contains(&format!(
        "{MAX_FETCH_OUTPUT_PAYLOAD_BYTES}-byte signed payload limit"
    )));
    assert_eq!(verifier.events.len(), 1);
    assert_eq!(
        verifier.next_position,
        MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64
    );
}

#[test]
fn verifier_rejects_events_after_terminal_outcome() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
    let failed = || WorkEvent {
        kind: Some(work_event::Kind::Failed(pb::WorkFailed {
            position: 0,
            error: "failed".to_string(),
        })),
    };

    assert!(matches!(
        verify_fetch_work_event(&mut verifier, failed()).unwrap(),
        FetchExecutionEvent::Done(FetchOutcome::Failed { .. })
    ));
    let error = verify_fetch_work_event(&mut verifier, failed()).unwrap_err();
    assert!(error.to_string().contains("after its terminal outcome"));
}

#[test]
fn failure_position_must_match_verified_signed_prefix() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let chunk = builder.push_event(b"prefix".to_vec()).unwrap();
    let expected_position = chunk.payload().len() as u64;
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
    verifier.verify_chunk(chunk).unwrap();

    let failed = |position| WorkEvent {
        kind: Some(work_event::Kind::Failed(pb::WorkFailed {
            position,
            error: "failed".to_string(),
        })),
    };
    let error = verify_fetch_work_event(&mut verifier, failed(0)).unwrap_err();
    assert!(error.to_string().contains("failure position mismatch"));
    assert!(matches!(
        verify_fetch_work_event(&mut verifier, failed(expected_position)).unwrap(),
        FetchExecutionEvent::Done(FetchOutcome::Failed { .. })
    ));
}

#[test]
fn verify_terminal_rejects_untrusted_producer_without_streamed_chunks() {
    let caller = key(1);
    let producer = key(2);
    let trusted_producer = key(3);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let output_events = build_output_events(
        input,
        TEST_ASSURANCE,
        &finished_terminal_payload(),
        &producer,
    )
    .unwrap();

    let mut verifier =
        FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&trusted_producer]));
    let err = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();
    assert!(err.to_string().contains("untrusted producer key"));
}

#[test]
fn verify_terminal_accepts_trusted_producer_without_streamed_chunks() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let output_events = build_output_events(
        input,
        TEST_ASSURANCE,
        &finished_terminal_payload(),
        &producer,
    )
    .unwrap();

    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));
    verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap();
}

#[test]
fn malformed_terminal_payload_does_not_finalize_the_verifier() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let malformed = build_output_events(input, TEST_ASSURANCE, b"not DAG-CBOR", &producer).unwrap();
    let valid = build_output_events(
        input,
        TEST_ASSURANCE,
        &finished_terminal_payload(),
        &producer,
    )
    .unwrap();
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

    assert!(
        verifier
            .verify_terminal(terminal_event(&malformed))
            .unwrap_err()
            .to_string()
            .contains("terminal payload decode failed")
    );
    verifier.verify_terminal(terminal_event(&valid)).unwrap();
}

#[test]
fn verify_terminal_rejects_a_transcript_for_a_different_input() {
    let caller = key(1);
    let producer = key(2);
    let expected_request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let other_request = fetch_request(&caller, "echo", "run", br#"{"x":2}"#);
    let expected_input = input_commitment_for(&expected_request);
    let other_input = input_commitment_for(&other_request);
    let output_events = build_output_events(
        other_input,
        TEST_ASSURANCE,
        &finished_terminal_payload(),
        &producer,
    )
    .unwrap();
    let mut verifier =
        FetchChunkVerifier::new(expected_input, TEST_ASSURANCE, trust_in(&[&producer]));

    let error = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();

    assert!(error.to_string().contains("input commitment mismatch"));
}

#[test]
fn fetch_terminal_cannot_hide_an_unstreamed_response_event() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    builder
        .push_event(br#"{"delta":"hidden"}"#.to_vec())
        .unwrap();
    let output_events = builder.finish(finished_terminal_payload()).unwrap();
    let mut verifier = FetchChunkVerifier::new(input, TEST_ASSURANCE, trust_in(&[&producer]));

    let error = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();
    assert!(error.to_string().contains("sequence mismatch"));
}

#[test]
fn fetch_finished_rejects_tampered_output_event_payload() {
    let caller = key(1);
    let producer = key(2);
    let request = fetch_request(&caller, "echo", "run", br#"{"x":1}"#);
    let input = input_commitment_for(&request);
    let events = build_output_events(
        input,
        TEST_ASSURANCE,
        &finished_terminal_payload(),
        &producer,
    )
    .unwrap();
    let mut finished = WorkFinished {
        terminal_output_event: events.last().map(output_event_to_pb),
        assurance_evidence: Vec::new(),
    };
    finished
        .terminal_output_event
        .as_mut()
        .expect("fixture terminal event")
        .payload = br#"{"x":2}"#.to_vec();

    assert!(matches!(
        parse_fetch_finished(finished, input, TEST_ASSURANCE).unwrap_err(),
        ClientError::FetchStreamEnvelope { .. } | ClientError::FetchTranscript { .. }
    ));
}

#[test]
fn fetch_protocol_error_remains_source_typed() {
    let error = ClientError::FetchTranscript {
        source: FetchProtocolError::WrongInputEventCount { actual: 0 },
    };
    assert!(error.to_string().contains("fetch transcript"));
}
