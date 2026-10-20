use super::*;

const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;
use hellas_auth::ProducerSigningKey;

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).unwrap()
}

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
fn evaluate_v4_domains_and_first_event_commitment_are_pinned() {
    assert_eq!(OUTPUT_CANONICALIZATION, b"hellas.evaluate.output.v4");
    assert_eq!(TOKEN_DELTA_EVENT_KIND, "evaluate.token_delta.v4");
    assert_eq!(TERMINAL_EVENT_KIND, "evaluate.terminal.v4");
    assert_eq!(TOKEN_DELTA_CODEC, "hellas.evaluate.output.token_delta.v4");
    assert_eq!(TERMINAL_CODEC, "hellas.evaluate.output.terminal.v4");
    assert_eq!(
        scheme_id(Operation::Evaluate, Assurance::ProducerSigned).to_byte(),
        0x00
    );

    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
    let event = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer)
        .push_token_delta(vec![10, 11])
        .unwrap();
    assert_eq!(
        hex(event.event_commitment().as_bytes()),
        "0fb828e10fa5cdffe684ff4028617384ee02f8b0f19a382a7cff386a28675883"
    );
}

#[test]
fn decoded_token_delta_must_not_be_empty() {
    let bytes = encode_token_delta_payload(&EvaluateTokenDelta {
        start_position: 0,
        token_ids: Vec::new(),
    })
    .unwrap();

    assert!(matches!(
        decode_token_delta_payload(&bytes),
        Err(EvaluateProtocolError::EmptyTokenDelta)
    ));
}

#[test]
fn decoded_token_delta_must_be_canonical_dag_cbor() {
    let canonical = encode_token_delta_payload(&EvaluateTokenDelta {
        start_position: 0,
        token_ids: vec![7],
    })
    .unwrap();
    let noncanonical = overlong_tuple_header(&canonical);
    assert!(matches!(
        decode_token_delta_payload(&noncanonical),
        Err(EvaluateProtocolError::Decode(_))
    ));
}

#[test]
fn decoded_terminal_must_be_canonical_dag_cbor() {
    let canonical = encode_terminal_payload(&EvaluateTerminal {
        final_position: 0,
        stop_reason: EvaluateStopReason::MAX_OUTPUT,
        matched_stop_token_id: None,
        text_artifact: Digest::from_bytes([4; 32]),
        usage: EvaluateUsage {
            input_units: 3,
            output_units: 0,
        },
        billable_units: 3,
    })
    .unwrap();
    let noncanonical = overlong_tuple_header(&canonical);
    assert!(matches!(
        decode_terminal_payload(&noncanonical),
        Err(EvaluateProtocolError::Decode(_))
    ));
}

#[test]
fn output_events_round_trip_through_shape_verifier() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let first = builder.push_token_delta(vec![10, 11]).unwrap();
    let terminal = EvaluateTerminal {
        final_position: 2,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(7),
        text_artifact: Digest::from_bytes([4; 32]),
        usage: EvaluateUsage {
            input_units: 7,
            output_units: 2,
        },
        billable_units: 9,
    };
    let events = builder.finish(terminal.clone()).unwrap();

    assert_eq!(events[0], first);
    let output = verify_output_events(input, TEST_ASSURANCE, &events).unwrap();
    assert_eq!(output.token_deltas.len(), 1);
    assert_eq!(output.token_deltas[0].token_ids, vec![10, 11]);
    assert_eq!(output.terminal, terminal);
}

#[test]
fn resume_appends_terminal_without_resigning_prefix() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let prefix = vec![builder.push_token_delta(vec![10]).unwrap()];
    let resumed = EvaluateOutputTranscriptBuilder::resume_verified(
        input,
        TEST_ASSURANCE,
        &producer,
        prefix.clone(),
    )
    .unwrap();
    let events = resumed
        .finish(EvaluateTerminal {
            final_position: 1,
            stop_reason: EvaluateStopReason::MAX_OUTPUT,
            matched_stop_token_id: None,
            text_artifact: Digest::from_bytes([4; 32]),
            usage: EvaluateUsage {
                input_units: 0,
                output_units: 1,
            },
            billable_units: 1,
        })
        .unwrap();

    assert_eq!(events[0], prefix[0]);
    verify_output_events_for_producer(input, TEST_ASSURANCE, &producer.public_key(), &events)
        .unwrap();
}

#[test]
fn terminal_position_must_match_token_deltas() {
    let producer = key(2);
    let input = InputCommitment::from_digest(Digest::from_bytes([3; 32]));
    let mut builder = EvaluateOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    builder.push_token_delta(vec![10]).unwrap();

    assert!(matches!(
        builder
            .finish(EvaluateTerminal {
                final_position: 2,
                stop_reason: EvaluateStopReason::STOP_TOKEN,
                matched_stop_token_id: Some(7),
                text_artifact: Digest::from_bytes([4; 32]),
                usage: EvaluateUsage {
                    input_units: 0,
                    output_units: 2,
                },
                billable_units: 2,
            })
            .unwrap_err(),
        EvaluateProtocolError::TerminalPositionMismatch {
            expected: 1,
            actual: 2
        }
    ));
}

#[test]
fn terminal_stop_reason_requires_exact_witness_shape() {
    let usage = EvaluateUsage {
        input_units: 0,
        output_units: 0,
    };
    let mut terminal = EvaluateTerminal {
        final_position: 0,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: None,
        text_artifact: Digest::from_bytes([4; 32]),
        usage,
        billable_units: 0,
    };
    assert!(matches!(
        validate_terminal(&terminal),
        Err(EvaluateProtocolError::MissingMatchedStopTokenId)
    ));

    terminal.stop_reason = EvaluateStopReason::MAX_OUTPUT;
    terminal.matched_stop_token_id = Some(7);
    assert!(matches!(
        validate_terminal(&terminal),
        Err(EvaluateProtocolError::UnexpectedMatchedStopTokenId { token_id: 7 })
    ));

    terminal.stop_reason = EvaluateStopReason::STOP_TOKEN;
    assert!(validate_terminal(&terminal).is_ok());
    terminal.stop_reason = EvaluateStopReason::MAX_OUTPUT;
    terminal.matched_stop_token_id = None;
    assert!(validate_terminal(&terminal).is_ok());
}
