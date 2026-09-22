use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn example() -> CausalLmEnvironment {
    CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([1; 32]), 1_024),
        "model",
        vec![ContentRef::new(ContentId::from_bytes([2; 32]), 4_096)],
        vec![StaticSlice::new(0, 32, 64), StaticSlice::new(0, 96, 128)],
        vec![4_608],
        49_152,
        8_192,
        CausalLmGenerationSchedule {
            fixed_capacity: 8_192,
            prefill_chunk_tokens: 256,
        },
    )
    .unwrap()
}

#[test]
fn retained_heap_bytes_use_owned_buffer_capacities_without_serializing() {
    let mut environment = example();
    environment.entrypoint.reserve(96);
    environment.static_objects.reserve(7);
    environment.static_inputs.reserve(31);
    environment.state_bytes_per_capacity.reserve(5);

    let expected = std::mem::size_of::<CausalLmEnvironment>()
        + environment.entrypoint.capacity()
        + environment.static_objects.capacity() * std::mem::size_of::<ContentRef>()
        + environment.static_inputs.capacity() * std::mem::size_of::<StaticSlice>()
        + environment.state_bytes_per_capacity.capacity() * std::mem::size_of::<u64>();
    let length_only = std::mem::size_of::<CausalLmEnvironment>()
        + environment.entrypoint.len()
        + environment.static_objects.len() * std::mem::size_of::<ContentRef>()
        + environment.static_inputs.len() * std::mem::size_of::<StaticSlice>()
        + environment.state_bytes_per_capacity.len() * std::mem::size_of::<u64>();

    assert_eq!(environment.retained_heap_bytes(), Some(expected));
    assert!(expected > length_only, "fixture must retain spare capacity");
}

#[test]
fn canonical_environment_round_trips_and_builds_the_exact_application() {
    let expected = example();
    let bytes = expected.canonical_bytes();
    let actual = CausalLmEnvironment::from_canonical_bytes(&bytes).unwrap();

    assert_eq!(
        hex(&bytes),
        concat!(
            "88", // eight environment fields
            "82",
            "5820",
            "0101010101010101010101010101010101010101010101010101010101010101",
            "190400", // program: content id, 1,024 bytes
            "65",
            "6d6f64656c", // entrypoint: "model"
            "81",         // one static object
            "82",
            "5820",
            "0202020202020202020202020202020202020202020202020202020202020202",
            "191000", // 4,096 bytes
            "82",     // two ordered static slices
            "83",
            "00",
            "1820",
            "1840", // object 0, offset 32, 64 bytes
            "83",
            "00",
            "1860",
            "1880", // object 0, offset 96, 128 bytes
            "81",
            "191200", // one state, 4,608 bytes per capacity
            "19c000", // vocabulary size 49,152
            "192000", // maximum capacity 8,192
            "82",     // generation schedule
            "192000", // fixed capacity 8,192
            "190100", // prefill chunk 256
        )
    );
    assert_eq!(actual, expected);
    assert_eq!(actual.content_id(), ContentId::hash(&bytes));
    assert_eq!(
        actual.content_id().to_string(),
        "840d556c9f216b65b6585198f1d6a7c33cff8c659a180b8753f669536aa1940c"
    );
    let manifest = actual.manifest();
    assert_eq!(manifest.application().evaluator(), CATENA_GPU_EVALUATOR);
    assert_eq!(manifest.application().adaptor(), CAUSAL_LM_ADAPTOR);
}

#[test]
fn generation_schedule_is_committed_and_required() {
    let environment = example();
    let scheduled = environment
        .clone()
        .with_generation_schedule(CausalLmGenerationSchedule {
            fixed_capacity: 8192,
            prefill_chunk_tokens: 128,
        })
        .unwrap();
    let bytes = scheduled.canonical_bytes();
    assert_eq!(bytes[0], 0x88);
    assert_eq!(
        CausalLmEnvironment::from_canonical_bytes(&bytes).unwrap(),
        scheduled
    );
    assert_ne!(scheduled.content_id(), environment.content_id());
    assert_ne!(
        scheduled.manifest().content_id(),
        environment.manifest().content_id()
    );
    for (fixed_capacity, prefill_chunk_tokens) in [(0, 1), (8193, 1), (8192, 0), (2, 3)] {
        assert!(
            environment
                .clone()
                .with_generation_schedule(CausalLmGenerationSchedule {
                    fixed_capacity,
                    prefill_chunk_tokens,
                })
                .is_err()
        );
    }
    let mut incomplete = environment.canonical_bytes();
    incomplete[0] = 0x87;
    incomplete.truncate(incomplete.len() - 7);
    assert!(CausalLmEnvironment::from_canonical_bytes(&incomplete).is_err());
}

#[test]
fn slice_ranges_and_state_sizes_are_checked() {
    let mut invalid_slice = example();
    invalid_slice.static_inputs[0] = StaticSlice::new(0, 4_080, 32);
    assert!(matches!(
        invalid_slice.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("exceeds object")
    ));

    let mut invalid_state = example();
    invalid_state.state_bytes_per_capacity[0] = u64::MAX - 3;
    assert!(matches!(
        invalid_state.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("allocation overflows")
    ));

    let mut misaligned_state = example();
    misaligned_state.state_bytes_per_capacity[0] = 2;
    assert!(matches!(
        misaligned_state.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("divisible by four")
    ));

    let mut aggregate_state = example();
    aggregate_state.maximum_capacity = 1;
    aggregate_state.generation_schedule = CausalLmGenerationSchedule {
        fixed_capacity: 1,
        prefill_chunk_tokens: 1,
    };
    aggregate_state.state_bytes_per_capacity = vec![MAX_STATE_BYTES, 4];
    assert!(matches!(
        aggregate_state.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("states total")
    ));

    let mut excessive_capacity = example();
    excessive_capacity.maximum_capacity = MAXIMUM_CAPACITY + 1;
    assert!(matches!(
        excessive_capacity.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("maximum capacity")
    ));
}

#[test]
fn every_static_object_is_unique_reachable_and_safely_sliced() {
    let mut unused = example();
    unused
        .static_objects
        .push(ContentRef::new(ContentId::from_bytes([3; 32]), 64));
    assert!(matches!(
        unused.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("not reachable")
    ));

    let mut duplicate = example();
    duplicate.static_objects.push(duplicate.static_objects[0]);
    duplicate.static_inputs.push(StaticSlice::new(1, 0, 1));
    assert!(matches!(
        duplicate.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("repeats content id")
    ));

    let mut overflowed_slice = example();
    overflowed_slice.static_inputs[0] = StaticSlice::new(0, u64::MAX, 1);
    assert!(matches!(
        overflowed_slice.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("range overflowed")
    ));
}

#[test]
fn logical_static_slice_bytes_are_bounded_including_repeated_views() {
    let mut exact = example();
    exact.static_objects[0] =
        ContentRef::new(exact.static_objects[0].id(), MAX_CAUSAL_LM_STATIC_BYTES);
    exact.static_inputs = vec![StaticSlice::new(0, 0, MAX_CAUSAL_LM_STATIC_BYTES)];
    exact.validate().expect("exact logical static-byte limit");

    exact.static_inputs.push(StaticSlice::new(0, 0, 1));
    assert!(matches!(
        exact.validate(),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("static inputs total")
    ));
}

#[test]
fn decoder_rejects_trailing_and_noncanonical_data() {
    let mut trailing = example().canonical_bytes();
    trailing.push(0);
    assert!(CausalLmEnvironment::from_canonical_bytes(&trailing).is_err());

    let canonical = example().canonical_bytes();
    let mut noncanonical = vec![0x98, 0x08];
    noncanonical.extend_from_slice(&canonical[1..]);
    assert!(matches!(
        CausalLmEnvironment::from_canonical_bytes(&noncanonical),
        Err(CausalLmEnvironmentError::Canonical(error))
            if error.to_string().contains("non-canonical")
    ));

    let mut oversized = vec![0; MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1];
    oversized[0] = 0x88;
    assert!(matches!(
        CausalLmEnvironment::from_canonical_bytes(&oversized),
            Err(CausalLmEnvironmentError::Invalid(message)) if message.contains("over")
    ));

    let mut excessive_objects = DagCborEncoder::new();
    excessive_objects.array(8);
    encode_content_ref(
        &mut excessive_objects,
        ContentRef::new(ContentId::from_bytes([1; 32]), 1),
    );
    excessive_objects.str("model");
    excessive_objects.array((MAX_STATIC_OBJECTS + 1) as u64);
    for _ in 0..=MAX_STATIC_OBJECTS {
        excessive_objects.u64(0);
    }
    assert!(matches!(
        CausalLmEnvironment::from_canonical_bytes(&excessive_objects.into_bytes()),
        Err(CausalLmEnvironmentError::Invalid(message))
            if message.contains("static objects")
    ));
}
