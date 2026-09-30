use super::*;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateProtocolError, EvaluateStopReason, EvaluateTerminal,
    EvaluateUsage, encode_terminal_payload, input_commitment,
};
use hellas_rpc::execution_event::{WorkChunk, WorkEvent, WorkFailed, WorkFinished, work_event};
use hellas_rpc::stream::output_event_to_pb;
use hellas_rpc::{
    ContentId, EvaluateRequest, OutputTranscriptBuilder, ProducerSigningKey, Signature,
    SignedOutputEvent,
};

const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
}

fn verifier(
    input: InputCommitment,
    producer_key: PublicKey,
    max_output_tokens: u32,
) -> EvaluateChunkVerifier {
    EvaluateChunkVerifier::new(
        input,
        TEST_ASSURANCE,
        producer_key,
        max_output_tokens,
        1_000,
        vec![7],
    )
}

fn corrupt_signature(event: &OutputEventEnvelope) -> OutputEventEnvelope {
    let signature = match *event.event().signature() {
        Signature::Secp256k1(mut bytes) => {
            bytes[7] ^= 0x01;
            Signature::Secp256k1(bytes)
        }
        _ => panic!("the fixture uses a secp256k1 producer key"),
    };
    let signed = SignedOutputEvent::from_parts(
        event.event().body().clone(),
        signature,
        *event.event().public_key(),
    )
    .unwrap();
    OutputEventEnvelope::new(signed, event.payload().to_vec()).unwrap()
}

fn terminal_event(events: &[OutputEventEnvelope]) -> OutputEventEnvelope {
    events.last().expect("fixture terminal event").clone()
}

fn signed_terminal_without_shape_validation(
    input: InputCommitment,
    producer: &ProducerSigningKey,
    terminal: &EvaluateTerminal,
) -> OutputEventEnvelope {
    let mut builder = OutputTranscriptBuilder::new(
        scheme_id(Operation::Evaluate, TEST_ASSURANCE),
        input,
        producer,
        output_canonicalization(),
    );
    builder
        .push(
            TERMINAL_EVENT_KIND,
            encode_terminal_payload(terminal).unwrap(),
        )
        .unwrap();
    builder.finish().unwrap().0.pop().unwrap()
}

fn finished(events: &[OutputEventEnvelope]) -> WorkFinished {
    WorkFinished {
        terminal_output_event: Some(output_event_to_pb(
            events.last().expect("fixture terminal event"),
        )),
        assurance_evidence: Vec::new(),
    }
}

#[test]
fn rejected_producer_and_signature_do_not_advance_verifier_state() {
    let producer = key(2);
    let attacker = key(3);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let valid = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .push_token_delta(vec![10])
        .unwrap();
    let attacker_event = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &attacker)
        .push_token_delta(vec![99])
        .unwrap();
    let invalid_signature = corrupt_signature(&valid);
    let mut verifier = verifier(input, producer.public_key(), 1);

    assert!(matches!(
        verifier.verify_chunk(attacker_event),
        Err(ClientError::Protocol(_))
    ));
    assert!(matches!(
        verifier.verify_chunk(invalid_signature),
        Err(ClientError::Source { .. })
    ));
    let (position, delta) = verifier.verify_chunk(valid).unwrap();
    assert_eq!(position, 1);
    assert_eq!(delta.token_ids, vec![10]);
}

#[test]
fn output_position_cannot_exceed_requested_maximum() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let oversized = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .push_token_delta(vec![10, 11, 12])
        .unwrap();
    let valid = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .push_token_delta(vec![10, 11])
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 2);

    let error = verifier.verify_chunk(oversized).unwrap_err();
    assert!(error.to_string().contains("exceeds requested maximum 2"));
    assert_eq!(verifier.verify_chunk(valid).unwrap().0, 2);
}

#[test]
fn out_of_vocabulary_chunk_rejection_is_transactional_across_a_split_retry() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let first = builder.push_token_delta(vec![1]).unwrap();
    let invalid = builder.push_token_delta(vec![2, 10]).unwrap();
    let mut resumed = EvaluateOutputTranscriptBuilder::resume_verified(
        input,
        TEST_ASSURANCE,
        &producer,
        vec![first.clone()],
    )
    .unwrap();
    let retry = resumed.push_token_delta(vec![2, 9]).unwrap();
    let mut verifier = EvaluateChunkVerifier::new(
        input,
        TEST_ASSURANCE,
        producer.public_key(),
        3,
        10,
        Vec::new(),
    );

    assert_eq!(verifier.verify_chunk(first).unwrap().0, 1);
    let error = verifier.verify_chunk(invalid).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the committed vocabulary")
    );
    assert_eq!(verifier.verify_chunk(retry).unwrap().0, 3);
}

#[test]
fn signed_terminal_requires_the_exact_stop_witness_shape() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let usage = EvaluateUsage {
        input_units: 3,
        output_units: 0,
    };
    let missing = signed_terminal_without_shape_validation(
        input,
        &producer,
        &EvaluateTerminal {
            final_position: 0,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: None,
            text_artifact: Digest::from_bytes([5; 32]),
            usage,
            billable_units: 3,
        },
    );
    let extraneous = signed_terminal_without_shape_validation(
        input,
        &producer,
        &EvaluateTerminal {
            final_position: 0,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: Some(7),
            text_artifact: Digest::from_bytes([5; 32]),
            usage,
            billable_units: 3,
        },
    );

    let missing_error = verifier(input, producer.public_key(), 1)
        .verify_terminal(missing)
        .unwrap_err();
    assert!(
        missing_error
            .to_string()
            .contains("missing its matched stop token ID")
    );
    let extraneous_error = verifier(input, producer.public_key(), 1)
        .verify_terminal(extraneous)
        .unwrap_err();
    assert!(
        extraneous_error
            .to_string()
            .contains("unexpectedly carries matched stop token ID 7")
    );
}

#[test]
fn position_zero_stop_with_a_committed_witness_is_valid() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let events = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .finish(EvaluateTerminal {
            final_position: 0,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(7),
            text_artifact: Digest::from_bytes([5; 32]),
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 0,
            },
            billable_units: 3,
        })
        .unwrap();

    let output = verifier(input, producer.public_key(), 1)
        .verify_terminal(terminal_event(&events))
        .unwrap();
    assert_eq!(output.terminal.matched_stop_token_id, Some(7));
}

#[test]
fn terminal_first_transcript_checks_input_and_producer() {
    let producer = key(2);
    let other = key(3);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let output_events = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .finish(EvaluateTerminal {
            final_position: 0,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(7),
            text_artifact: Digest::from_bytes([5; 32]),
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 0,
            },
            billable_units: 3,
        })
        .unwrap();

    let mut wrong_producer = verifier(input, other.public_key(), 2);
    assert!(
        wrong_producer
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err()
            .to_string()
            .contains("wrong producer key")
    );

    let other_input = InputCommitment::from_digest(Digest::from_bytes([6; 32]));
    let mut wrong_input = verifier(other_input, producer.public_key(), 2);
    assert!(
        wrong_input
            .verify_terminal(terminal_event(&output_events))
            .unwrap_err()
            .to_string()
            .contains("input commitment mismatch")
    );

    let mut verifier = verifier(input, producer.public_key(), 2);
    assert_eq!(
        verifier
            .verify_terminal(terminal_event(&output_events))
            .unwrap()
            .terminal
            .final_position,
        0
    );
}

#[test]
fn verifies_streamed_prefix_and_terminal() {
    let runner = key(1);
    let producer = key(2);
    let request = EvaluateRequest {
        text_execution: Digest::from_bytes([9; 32]),
        runner_public_key: runner.public_key(),
        execution_environment: ContentId::from_bytes([8; 32]),
        nonce: [7; 32],
        assurance: TEST_ASSURANCE,
        retain: true,
    };
    let input = input_commitment(&request);
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
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

    let mut verifier = verifier(input, producer.public_key(), 3);
    let (position, delta) = verifier.verify_chunk(token_event).unwrap();
    assert_eq!(position, 2);
    assert_eq!(delta.token_ids, vec![10, 11]);
    verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap();
}

#[test]
fn terminal_cannot_hide_an_unstreamed_token_delta() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let streamed = builder.push_token_delta(vec![10]).unwrap();
    builder.push_token_delta(vec![11]).unwrap();
    let output_events = builder
        .finish(EvaluateTerminal {
            final_position: 2,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: None,
            text_artifact: Digest::from_bytes([5; 32]),
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 2,
            },
            billable_units: 5,
        })
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 2);
    verifier.verify_chunk(streamed).unwrap();

    let error = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();
    assert!(error.to_string().contains("sequence mismatch"));
}

#[test]
fn terminal_artifact_must_match_verified_streamed_tokens() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let execution = TextExecutionId::from_digest(Digest::from_bytes([6; 32]));
    let input_ids = vec![1, 2, 3];
    let forged_artifact = completed_text(execution, &input_ids, &[7])
        .artifact
        .output_id()
        .digest();
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let streamed = builder.push_token_delta(vec![9]).unwrap();
    let output_events = builder
        .finish(EvaluateTerminal {
            final_position: 1,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: None,
            text_artifact: forged_artifact,
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 1,
            },
            billable_units: 4,
        })
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 1)
        .with_text_artifact_expectation(execution, input_ids);
    verifier.verify_chunk(streamed).unwrap();

    let error = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the verified token stream")
    );
}

#[test]
fn stop_terminal_must_match_the_committed_stop_policy() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let execution = TextExecutionId::from_digest(Digest::from_bytes([6; 32]));
    let input_ids = vec![1];
    let artifact = completed_text(execution, &input_ids, &[9])
        .artifact
        .output_id()
        .digest();
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let streamed = builder.push_token_delta(vec![9]).unwrap();
    let output_events = builder
        .finish(EvaluateTerminal {
            final_position: 1,
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(8),
            text_artifact: artifact,
            usage: EvaluateUsage {
                input_units: 1,
                output_units: 1,
            },
            billable_units: 2,
        })
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 2)
        .with_text_artifact_expectation(execution, input_ids);
    verifier.verify_chunk(streamed).unwrap();

    let error = verifier
        .verify_terminal(terminal_event(&output_events))
        .unwrap_err();
    assert!(error.to_string().contains("uncommitted token 8"));
}

#[test]
fn rejects_wrong_request_commitment_length() {
    assert!(matches!(
        evaluate_input_from_request_commitment(&[0; 31]),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn evaluate_protocol_error_remains_source_typed() {
    let error = ClientError::EvaluateTranscript {
        source: EvaluateProtocolError::UnknownStopReason(9),
    };
    assert!(error.to_string().contains("evaluate transcript"));
}

#[test]
fn work_events_are_verified_end_to_end() {
    let runner = key(1);
    let producer = key(2);
    let request = EvaluateRequest {
        text_execution: Digest::from_bytes([9; 32]),
        runner_public_key: runner.public_key(),
        execution_environment: ContentId::from_bytes([8; 32]),
        nonce: [7; 32],
        assurance: TEST_ASSURANCE,
        retain: true,
    };
    let input = hellas_rpc::evaluate::input_commitment(&request);
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let chunk = builder.push_token_delta(vec![10, 11]).unwrap();
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

    let mut verifier = verifier(input, producer.public_key(), 3);
    let event = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&chunk)),
            })),
        },
        input,
    )
    .unwrap();
    assert!(matches!(
        event,
        EvaluateExecutionEvent::Chunk {
            position: 2,
            ref tokens
        } if tokens.len() == 8
    ));

    let event = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Finished(finished(&output_events))),
        },
        input,
    )
    .unwrap();
    assert!(matches!(
        event,
        EvaluateExecutionEvent::Done(EvaluateOutcome::Completed { .. })
    ));
}

#[test]
fn finished_latch_is_atomic_and_rejects_later_events() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let chunk = builder.push_token_delta(vec![10]).unwrap();
    let output_events = builder
        .finish(EvaluateTerminal {
            final_position: 1,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: None,
            text_artifact: Digest::from_bytes([5; 32]),
            usage: EvaluateUsage {
                input_units: 3,
                output_units: 1,
            },
            billable_units: 4,
        })
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 1);

    verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&chunk)),
            })),
        },
        input,
    )
    .unwrap();

    let malformed = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: None,
                assurance_evidence: Vec::new(),
            })),
        },
        input,
    )
    .unwrap_err();
    assert!(
        malformed
            .to_string()
            .contains("missing signed terminal event")
    );

    let completed = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Finished(finished(&output_events))),
        },
        input,
    )
    .unwrap();
    assert!(matches!(
        completed,
        EvaluateExecutionEvent::Done(EvaluateOutcome::Completed { .. })
    ));

    let second_terminal = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Finished(finished(&output_events))),
        },
        input,
    )
    .unwrap_err();
    assert!(second_terminal.to_string().contains("already finalized"));

    let later_chunk = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&chunk)),
            })),
        },
        input,
    )
    .unwrap_err();
    assert!(later_chunk.to_string().contains("already finalized"));
}

#[test]
fn work_failed_position_must_match_prefix_and_consumes_terminal_latch() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([4; 32]));
    let chunk = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .push_token_delta(vec![10])
        .unwrap();
    let mut verifier = verifier(input, producer.public_key(), 2);

    verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Chunk(WorkChunk {
                output_event: Some(output_event_to_pb(&chunk)),
            })),
        },
        input,
    )
    .unwrap();

    let wrong_position = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed {
                position: 0,
                error: "wrong position".to_string(),
            })),
        },
        input,
    )
    .unwrap_err();
    assert!(wrong_position.to_string().contains("expected 1, got 0"));

    let over_limit = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed {
                position: 3,
                error: "over limit".to_string(),
            })),
        },
        input,
    )
    .unwrap_err();
    assert!(
        over_limit
            .to_string()
            .contains("exceeds requested maximum 2")
    );

    let failed = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Failed(WorkFailed {
                position: 1,
                error: "worker stopped".to_string(),
            })),
        },
        input,
    )
    .unwrap();
    assert!(matches!(
        failed,
        EvaluateExecutionEvent::Done(EvaluateOutcome::Failed {
            position: 1,
            ref error
        }) if error == "worker stopped"
    ));

    let second_terminal = verify_evaluate_work_event(
        &mut verifier,
        WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: None,
                assurance_evidence: Vec::new(),
            })),
        },
        input,
    )
    .unwrap_err();
    assert!(second_terminal.to_string().contains("already finalized"));
}
