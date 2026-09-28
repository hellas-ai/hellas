use super::*;

const TEST_ASSURANCE: Assurance = Assurance::ProducerSigned;

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
}

fn environment() -> ContentId {
    ContentId::from_bytes([9; 32])
}

fn json_string_of_size(size: usize) -> Vec<u8> {
    assert!(size >= 2);
    let mut body = Vec::with_capacity(size);
    body.push(b'\"');
    body.resize(size - 1, b'a');
    body.push(b'\"');
    body
}

fn unchecked_input_events(body: Vec<u8>) -> Vec<InputEventEnvelope> {
    let caller = key(1);
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, TEST_ASSURANCE),
        &caller,
        input_canonicalization(),
    );
    builder
        .push("assurance", vec![TEST_ASSURANCE.to_byte()])
        .unwrap();
    builder
        .push("execution.environment", environment().as_bytes().to_vec())
        .unwrap();
    builder.push("request.nonce", vec![7; 32]).unwrap();
    builder.push("service", b"openai".to_vec()).unwrap();
    builder.push("method", b"responses".to_vec()).unwrap();
    builder.push("request.retain", vec![1]).unwrap();
    builder.push("request.body", body).unwrap();
    builder.push("input.end", Vec::new()).unwrap();
    builder.finish().unwrap().0
}

fn raw_input_events(service: Vec<u8>, method: Vec<u8>) -> Vec<InputEventEnvelope> {
    let caller = key(1);
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, TEST_ASSURANCE),
        &caller,
        input_canonicalization(),
    );
    builder
        .push("assurance", vec![TEST_ASSURANCE.to_byte()])
        .unwrap();
    builder
        .push("execution.environment", environment().as_bytes().to_vec())
        .unwrap();
    builder.push("request.nonce", vec![0; 32]).unwrap();
    builder.push("service", service).unwrap();
    builder.push("method", method).unwrap();
    builder.push("request.retain", vec![1]).unwrap();
    builder.push("request.body", br#"{}"#.to_vec()).unwrap();
    builder.push("input.end", Vec::new()).unwrap();
    builder.finish().unwrap().0
}

#[test]
fn input_events_round_trip_through_shape_verifier() {
    let caller = key(1);
    let events = build_input_events(
        "openai",
        "responses",
        br#"{"model":"gpt"}"#,
        environment(),
        TEST_ASSURANCE,
        &caller,
    )
    .unwrap();

    let input = verify_input_events(&events).unwrap();

    assert_eq!(input.assurance, TEST_ASSURANCE);
    assert_eq!(input.caller_key, caller.public_key());
    assert_eq!(input.service, "openai");
    assert_eq!(input.method, "responses");
    assert_eq!(input.body.as_bytes(), br#"{"model":"gpt"}"#);
    assert_eq!(input.retention, Retention::Retain);
}

#[test]
fn input_count_is_rejected_before_chain_verification() {
    let mut events = build_input_events(
        "openai",
        "responses",
        br#"{}"#,
        environment(),
        TEST_ASSURANCE,
        &key(1),
    )
    .unwrap();
    // The appended envelope has a valid signature in isolation but cannot
    // be a valid continuation of the finished eight-event transcript.
    events.push(events[0].clone());

    assert!(matches!(
        verify_input_events(&events),
        Err(FetchProtocolError::WrongInputEventCount { actual: 9 })
    ));
}

#[test]
fn protobuf_shape_is_bounded_before_domain_conversion() {
    let events = build_input_events(
        "openai",
        "responses",
        br#"{}"#,
        environment(),
        TEST_ASSURANCE,
        &key(1),
    )
    .unwrap();
    let mut protobuf = events
        .iter()
        .map(crate::stream::input_event_to_pb)
        .collect::<Vec<_>>();
    protobuf[3].payload = vec![b'x'; MAX_FETCH_ROUTE_COMPONENT_BYTES + 1];

    assert!(matches!(
        validate_input_event_pb_shape(&protobuf),
        Err(FetchProtocolError::RouteComponentLimit {
            field: "service",
            actual,
        }) if actual == MAX_FETCH_ROUTE_COMPONENT_BYTES + 1
    ));
}

#[test]
fn request_body_limit_accepts_the_exact_boundary() {
    let caller = key(1);
    let body = json_string_of_size(MAX_FETCH_REQUEST_BODY_BYTES);
    let events = build_input_events(
        "openai",
        "responses",
        &body,
        environment(),
        TEST_ASSURANCE,
        &caller,
    )
    .unwrap();

    assert_eq!(verify_input_events(&events).unwrap().body.as_bytes(), body);
    let request = crate::pb::fetch::FetchRequest {
        input: events
            .iter()
            .map(crate::stream::input_event_to_pb)
            .collect(),
    };
    assert!(prost::Message::encoded_len(&request) < hellas_wire::frame::MAX_FRAME_BYTES);
}

#[test]
fn request_body_limit_rejects_build_and_authenticated_verify_oversize() {
    let caller = key(1);
    let body = json_string_of_size(MAX_FETCH_REQUEST_BODY_BYTES + 1);
    assert!(matches!(
        build_input_events(
            "openai",
            "responses",
            &body,
            environment(),
            TEST_ASSURANCE,
            &caller,
        ),
        Err(FetchProtocolError::RequestBodyLimit { actual })
            if actual == MAX_FETCH_REQUEST_BODY_BYTES + 1
    ));

    let events = unchecked_input_events(body);
    assert!(matches!(
        verify_input_events(&events),
        Err(FetchProtocolError::RequestBodyLimit { actual })
            if actual == MAX_FETCH_REQUEST_BODY_BYTES + 1
    ));
}

#[test]
fn ephemeral_retention_round_trips_in_signed_input() {
    let caller = key(1);
    let events = build_input_events_with_retention(
        "openai",
        "responses",
        br#"{"store":false}"#,
        environment(),
        TEST_ASSURANCE,
        &caller,
        Retention::Ephemeral,
    )
    .unwrap();

    assert_eq!(
        verify_input_events(&events).unwrap().retention,
        Retention::Ephemeral
    );
}

#[test]
fn input_retention_commitment_vector_is_pinned() {
    let caller = key(1);
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, TEST_ASSURANCE),
        &caller,
        input_canonicalization(),
    );
    builder
        .push("assurance", vec![TEST_ASSURANCE.to_byte()])
        .unwrap();
    builder
        .push("execution.environment", environment().as_bytes().to_vec())
        .unwrap();
    builder.push("request.nonce", vec![7; 32]).unwrap();
    builder.push("service", b"openai".to_vec()).unwrap();
    builder.push("method", b"responses".to_vec()).unwrap();
    builder.push("request.retain", vec![0]).unwrap();
    builder
        .push("request.body", br#"{"input":"private"}"#.to_vec())
        .unwrap();
    builder.push("input.end", Vec::new()).unwrap();
    let (_events, commitment) = builder.finish().unwrap();

    assert_eq!(
        commitment.digest().to_string(),
        "88391071758ee944f6f1da90c88a4e37216fe2e4764b70c2fce74e4a28181fba"
    );
}

#[test]
fn identical_requests_get_fresh_commitments() {
    let caller = key(1);
    let first = build_input_events(
        "openai",
        "responses",
        br#"{}"#,
        environment(),
        TEST_ASSURANCE,
        &caller,
    )
    .unwrap();
    let second = build_input_events(
        "openai",
        "responses",
        br#"{}"#,
        environment(),
        TEST_ASSURANCE,
        &caller,
    )
    .unwrap();
    assert_ne!(
        verify_input_events(&first).unwrap().input_commitment,
        verify_input_events(&second).unwrap().input_commitment
    );
}

#[test]
fn output_events_round_trip_through_shape_verifier() {
    let caller = key(1);
    let producer = key(2);
    let input = verify_input_events(
        &build_input_events(
            "openai",
            "responses",
            br#"{"model":"gpt"}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap(),
    )
    .unwrap()
    .input_commitment;
    let events =
        build_output_events(input, TEST_ASSURANCE, br#"{"id":"resp"}"#, &producer).unwrap();

    let output = verify_output_events(input, TEST_ASSURANCE, &events).unwrap();
    let (payloads, terminal) = output.output_event_payloads();

    assert_eq!(output.producer_key, producer.public_key());
    assert!(payloads.is_empty());
    assert_eq!(terminal, br#"{"id":"resp"}"#);
}

#[test]
fn output_events_reject_a_different_assurance() {
    let caller = key(1);
    let producer = key(2);
    let input = verify_input_events(
        &build_input_events(
            "openai",
            "responses",
            br#"{}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap(),
    )
    .unwrap()
    .input_commitment;
    let events = build_output_events(input, TEST_ASSURANCE, br#"{}"#, &producer).unwrap();

    assert!(matches!(
        verify_output_events(input, Assurance::AppleAppAttest, &events).unwrap_err(),
        FetchProtocolError::Stream(StreamVerifyError::SchemeMismatch)
    ));
}

#[test]
fn streaming_output_events_round_trip_through_shape_verifier() {
    let caller = key(1);
    let producer = key(2);
    let input = verify_input_events(
        &build_input_events(
            "openai",
            "responses",
            br#"{"model":"gpt"}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap(),
    )
    .unwrap()
    .input_commitment;
    let mut builder = FetchOutputTranscriptBuilder::new(input, TEST_ASSURANCE, &producer);
    let first = builder
        .push_event(b"semantic-output-event-1".to_vec())
        .unwrap();
    let second = builder
        .push_event(b"semantic-output-event-2".to_vec())
        .unwrap();
    let events = builder.finish(b"semantic-terminal".to_vec()).unwrap();

    assert_eq!(events[0], first);
    assert_eq!(events[1], second);
    let output = verify_output_events(input, TEST_ASSURANCE, &events).unwrap();
    let (payloads, terminal) = output.output_event_payloads();

    assert_eq!(output.producer_key, producer.public_key());
    assert_eq!(
        payloads,
        &[
            b"semantic-output-event-1".to_vec(),
            b"semantic-output-event-2".to_vec()
        ]
    );
    assert_eq!(terminal, b"semantic-terminal");
}

#[test]
fn input_rejects_empty_service() {
    let events = raw_input_events(Vec::new(), b"responses".to_vec());

    assert!(matches!(
        verify_input_events(&events).unwrap_err(),
        FetchProtocolError::EmptyService
    ));
}

#[test]
fn input_builder_bounds_each_route_component() {
    let caller = key(1);
    let maximum = "x".repeat(MAX_FETCH_ROUTE_COMPONENT_BYTES);
    build_input_events(
        &maximum,
        &maximum,
        br#"{}"#,
        environment(),
        TEST_ASSURANCE,
        &caller,
    )
    .unwrap();
    let overlong = "x".repeat(MAX_FETCH_ROUTE_COMPONENT_BYTES + 1);

    assert!(matches!(
        build_input_events(
            &overlong,
            "responses",
            br#"{}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap_err(),
        FetchProtocolError::RouteComponentLimit {
            field: "service",
            actual,
        } if actual == MAX_FETCH_ROUTE_COMPONENT_BYTES + 1
    ));
    assert!(matches!(
        build_input_events(
            "openai",
            &overlong,
            br#"{}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap_err(),
        FetchProtocolError::RouteComponentLimit {
            field: "method",
            actual,
        } if actual == MAX_FETCH_ROUTE_COMPONENT_BYTES + 1
    ));
}

#[test]
fn input_verifier_bounds_signed_route_components() {
    let events = raw_input_events(
        b"openai".to_vec(),
        vec![b'x'; MAX_FETCH_ROUTE_COMPONENT_BYTES + 1],
    );

    assert!(matches!(
        verify_input_events(&events).unwrap_err(),
        FetchProtocolError::RouteComponentLimit {
            field: "method",
            actual,
        } if actual == MAX_FETCH_ROUTE_COMPONENT_BYTES + 1
    ));
}

#[test]
fn input_rejects_wrong_canonicalization() {
    let caller = key(1);
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, TEST_ASSURANCE),
        &caller,
        CanonicalizationId::from_bytes(b"wrong.input.v2"),
    );
    builder
        .push("assurance", vec![TEST_ASSURANCE.to_byte()])
        .unwrap();
    builder
        .push("execution.environment", environment().as_bytes().to_vec())
        .unwrap();
    builder.push("request.nonce", vec![0; 32]).unwrap();
    builder.push("service", b"openai".to_vec()).unwrap();
    builder.push("method", b"responses".to_vec()).unwrap();
    builder.push("request.retain", vec![1]).unwrap();
    builder.push("request.body", br#"{}"#.to_vec()).unwrap();
    builder.push("input.end", Vec::new()).unwrap();
    let (events, _) = builder.finish().unwrap();

    assert!(matches!(
        verify_input_events(&events).unwrap_err(),
        FetchProtocolError::InputCanonicalizationMismatch { index: 0 }
    ));
}

#[test]
fn output_rejects_unsigned_terminal_payload_change() {
    let caller = key(1);
    let producer = key(2);
    let input = verify_input_events(
        &build_input_events(
            "openai",
            "responses",
            br#"{}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap(),
    )
    .unwrap()
    .input_commitment;
    let events = build_output_events(input, TEST_ASSURANCE, br#"{"ok":true}"#, &producer).unwrap();

    assert!(matches!(
        OutputEventEnvelope::new(events[0].event().clone(), br#"{"ok":false}"#.to_vec(),)
            .unwrap_err(),
        StreamVerifyError::PayloadMismatch
    ));
}

#[test]
fn output_rejects_wrong_canonicalization() {
    let caller = key(1);
    let producer = key(2);
    let input = verify_input_events(
        &build_input_events(
            "openai",
            "responses",
            br#"{}"#,
            environment(),
            TEST_ASSURANCE,
            &caller,
        )
        .unwrap(),
    )
    .unwrap()
    .input_commitment;
    let mut builder = OutputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, TEST_ASSURANCE),
        input,
        &producer,
        CanonicalizationId::from_bytes(b"wrong.output.v2"),
    );
    builder
        .push("response.terminal", br#"{}"#.to_vec())
        .unwrap();
    let (events, _) = builder.finish().unwrap();

    assert!(matches!(
        verify_output_events(input, TEST_ASSURANCE, &events).unwrap_err(),
        FetchProtocolError::OutputCanonicalizationMismatch { index: 0 }
    ));
}
