use super::*;
use hellas_rpc::ProducerSigningKey;
use hellas_rpc::fetch::{
    build_input_events_with_retention, build_output_events, verify_input_events,
};

fn key(byte: u8) -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([byte; 32]).expect("valid test key")
}

fn root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hellas-fetch-tests")
        .join(format!("{name}-{}", Uuid::new_v4().simple()))
}

fn fs_store(dir: &Path) -> FsFetchTranscriptStore {
    let store = FsFetchTranscriptStore::new(dir);
    store.init().unwrap();
    store
}

fn fs_store_with_capacity(dir: &Path, capacity: usize) -> FsFetchTranscriptStore {
    let store = FsFetchTranscriptStore::with_capacity(dir, capacity);
    store.init().unwrap();
    store
}

fn retained_file_count(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "running" || extension == "dagcbor")
        })
        .count()
}

fn sample_transcript() -> (FetchQuote, FetchTranscript, PublicKey, PublicKey) {
    sample_transcript_with_retention(hellas_rpc::Retention::Retain)
}

fn sample_transcript_with_retention(
    retention: hellas_rpc::Retention,
) -> (FetchQuote, FetchTranscript, PublicKey, PublicKey) {
    let caller = key(1);
    let producer = key(2);
    let producer_key = producer.public_key();

    let input_events = build_input_events_with_retention(
        "openai",
        "responses",
        br#"{"model":"gpt-test"}"#,
        hellas_rpc::ContentId::from_bytes([9; 32]),
        hellas_rpc::Assurance::ProducerSigned,
        &caller,
        retention,
    )
    .unwrap();
    let verified = verify_input_events(&input_events).unwrap();
    let caller_key = verified.caller_key;
    let quote = FetchQuote::from_verified(&verified, input_events);
    let output_events = build_output_events(
        verified.input_commitment,
        verified.assurance,
        br#"{"status":"completed"}"#,
        &producer,
    )
    .unwrap();
    let transcript = FetchTranscript::from_quote(&quote, output_events);
    (quote, transcript, caller_key, producer_key)
}

fn trusted_state(
    store: FsFetchTranscriptStore,
    caller: PublicKey,
) -> FetchStateMachine<FsFetchTranscriptStore> {
    FetchStateMachine::new(store, FetchCallerPolicy::new([caller]))
}

fn trusted_memory_state(caller: PublicKey) -> FetchStateMachine<MemoryFetchTranscriptStore> {
    FetchStateMachine::new(
        MemoryFetchTranscriptStore::default(),
        FetchCallerPolicy::new([caller]),
    )
}

fn signed_input(
    caller: &ProducerSigningKey,
    retention: hellas_rpc::Retention,
    body: &[u8],
) -> Vec<InputEventEnvelope> {
    build_input_events_with_retention(
        "openai",
        "responses",
        body,
        hellas_rpc::ContentId::from_bytes([9; 32]),
        hellas_rpc::Assurance::ProducerSigned,
        caller,
        retention,
    )
    .unwrap()
}

fn transcript_for(
    caller: &ProducerSigningKey,
    producer: &ProducerSigningKey,
    retention: hellas_rpc::Retention,
    body: &[u8],
) -> (FetchQuote, FetchTranscript) {
    let body = serde_json::to_vec(&String::from_utf8_lossy(body)).unwrap();
    let input = signed_input(caller, retention, &body);
    let verified = verify_input_events(&input).unwrap();
    let quote = FetchQuote::from_verified(&verified, input);
    let output = build_output_events(
        quote.input_commitment,
        quote.assurance,
        br#"{"status":"completed"}"#,
        producer,
    )
    .unwrap();
    let transcript = FetchTranscript::from_quote(&quote, output);
    (quote, transcript)
}

fn exercise_retained_capacity<S>(store: S)
where
    S: FetchTranscriptStore + Clone,
{
    let caller = key(21);
    let producer = key(22);
    let (first, first_transcript) =
        transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (second, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    let (ephemeral, _) = transcript_for(
        &caller,
        &producer,
        hellas_rpc::Retention::Ephemeral,
        b"ephemeral",
    );
    let first_input = first.input_commitment;
    let second_input = second.input_commitment;
    let ephemeral_input = ephemeral.input_commitment;
    let mut state =
        FetchStateMachine::new(store.clone(), FetchCallerPolicy::new([caller.public_key()]));

    state.quote_input(first.input).unwrap();
    state.start(first_input).unwrap();
    state.quote_input(second.input).unwrap();
    assert!(matches!(
        state.start(second_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));

    // Ephemeral work never reserves durable transcript capacity.
    state.quote_input(ephemeral.input).unwrap();
    state.start(ephemeral_input).unwrap();
    state.fail(ephemeral_input, "test cleanup").unwrap();

    // A running marker already owns this distinct-input slot, so its
    // running -> completed transition is allowed even while full.
    state
        .complete_output(
            first_input,
            first_transcript.output_events().to_vec(),
            &producer.public_key(),
        )
        .unwrap();
    store.put_completed(&first_transcript).unwrap();
    assert!(matches!(
        state.start(second_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));
}

fn exercise_zero_retained_capacity<S>(store: S)
where
    S: FetchTranscriptStore,
{
    let caller = key(23);
    let producer = key(24);
    let (retained, _) = transcript_for(
        &caller,
        &producer,
        hellas_rpc::Retention::Retain,
        b"retained",
    );
    let (ephemeral, _) = transcript_for(
        &caller,
        &producer,
        hellas_rpc::Retention::Ephemeral,
        b"ephemeral",
    );
    let retained_input = retained.input_commitment;
    let ephemeral_input = ephemeral.input_commitment;
    let mut state = FetchStateMachine::new(store, FetchCallerPolicy::new([caller.public_key()]));

    state.quote_input(retained.input).unwrap();
    assert!(matches!(
        state.start(retained_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 0 })
    ));
    state.quote_input(ephemeral.input).unwrap();
    state.start(ephemeral_input).unwrap();
}

#[test]
fn memory_retained_capacity_counts_running_and_completed_once() {
    exercise_retained_capacity(MemoryFetchTranscriptStore::with_capacity(1));
}

#[test]
fn filesystem_retained_capacity_counts_running_and_completed_once() {
    let dir = root("fs-retained-capacity");
    exercise_retained_capacity(fs_store_with_capacity(&dir, 1));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn zero_retained_capacity_disables_new_memory_retention() {
    exercise_zero_retained_capacity(MemoryFetchTranscriptStore::with_capacity(0));
}

#[test]
fn zero_retained_capacity_disables_new_filesystem_retention() {
    let dir = root("fs-zero-retained-capacity");
    exercise_zero_retained_capacity(fs_store_with_capacity(&dir, 0));
    assert_eq!(retained_file_count(&dir), 0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_running_marker_still_consumes_memory_capacity() {
    let caller = key(25);
    let producer = key(26);
    let (first, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (second, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    let first_input = first.input_commitment;
    let second_input = second.input_commitment;
    let store = MemoryFetchTranscriptStore::with_capacity(1);
    let mut state =
        FetchStateMachine::new(store.clone(), FetchCallerPolicy::new([caller.public_key()]));
    state.quote_input(first.input).unwrap();
    state.start(first_input).unwrap();
    state.fail(first_input, "provider outcome unknown").unwrap();

    let mut recovered =
        FetchStateMachine::new(store, FetchCallerPolicy::new([caller.public_key()]));
    recovered.quote_input(second.input).unwrap();
    assert!(matches!(
        recovered.start(second_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));
}

#[test]
fn failed_running_marker_still_consumes_filesystem_capacity_after_reload() {
    let dir = root("fs-failed-capacity-reload");
    let caller = key(27);
    let producer = key(28);
    let (first, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (second, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    let first_input = first.input_commitment;
    let second_input = second.input_commitment;
    {
        let mut state = FetchStateMachine::new(
            fs_store_with_capacity(&dir, 1),
            FetchCallerPolicy::new([caller.public_key()]),
        );
        state.quote_input(first.input).unwrap();
        state.start(first_input).unwrap();
        state.fail(first_input, "provider outcome unknown").unwrap();
    }

    let mut recovered = FetchStateMachine::new(
        fs_store_with_capacity(&dir, 1),
        FetchCallerPolicy::new([caller.public_key()]),
    );
    recovered.quote_input(second.input).unwrap();
    assert!(matches!(
        recovered.start(second_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));
    assert!(
        dir.join(format!("{}.running", first_input.digest()))
            .is_file()
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn filesystem_capacity_metadata_rejects_disagreeing_processes() {
    let dir = root("fs-capacity-mismatch");
    fs_store_with_capacity(&dir, 1);
    let mismatched = FsFetchTranscriptStore::with_capacity(&dir, 2);
    let error = mismatched.init().unwrap_err();
    assert!(matches!(
        &error,
        FetchStoreError::CapacityConfiguration {
            configured: 2,
            persisted: 1,
            ..
        }
    ));
    assert!(error.to_string().contains(&dir.display().to_string()));
    assert!(
        error
            .to_string()
            .contains("stop every process sharing store root")
    );
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn filesystem_store_narrows_an_existing_root_to_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = root("fs-private-root");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

    fs_store(&dir);

    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn filesystem_capacity_directory_lock_wait_is_bounded_after_child_replacement() {
    let dir = root("fs-bounded-capacity-lock");
    let store = fs_store(&dir);
    assert!(!dir.join(".retained-transcript-capacity.lock").exists());
    let held = crate::private_fs::open_directory(&dir).unwrap();
    held.lock().unwrap();
    // This was the old lock name. Removing and recreating it must have no
    // bearing on a transaction lock held on the root directory inode.
    let obsolete_child = dir.join(".retained-transcript-capacity.lock");
    fs::write(&obsolete_child, b"replacement").unwrap();
    fs::remove_file(&obsolete_child).unwrap();
    let started = Instant::now();

    let error = store.capacity_lock().unwrap_err();

    assert_eq!(
        match error {
            FetchStoreError::Io(error) => error.kind(),
            other => panic!("unexpected lock error: {other}"),
        },
        io::ErrorKind::WouldBlock
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn filesystem_capacity_metadata_rejects_a_fifo_without_blocking() {
    let dir = root("fs-capacity-fifo");
    fs::create_dir_all(&dir).unwrap();
    let metadata = dir.join(".retained-transcript-capacity");
    let status = std::process::Command::new("mkfifo")
        .arg(&metadata)
        .status()
        .unwrap();
    assert!(status.success(), "the fixture needs a FIFO");
    let store = FsFetchTranscriptStore::new(&dir);

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(store.init());
    });
    let error = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("Fetch capacity metadata open blocked on a FIFO")
        .expect_err("capacity metadata must be a regular file");
    assert!(
        matches!(error, FetchStoreError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
    );
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn completed_transcript_rejects_a_fifo_without_blocking() {
    let dir = root("fs-transcript-fifo");
    let store = fs_store(&dir);
    let caller = key(92);
    let producer = key(93);
    let (quote, _) = transcript_for(
        &caller,
        &producer,
        hellas_rpc::Retention::Retain,
        b"request",
    );
    let status = std::process::Command::new("mkfifo")
        .arg(store.path(quote.input_commitment))
        .status()
        .unwrap();
    assert!(status.success(), "the fixture needs a FIFO");

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(store.get_completed(quote.input_commitment));
    });
    let error = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("completed transcript open blocked on a FIFO")
        .expect_err("completed transcript must be a regular file");
    assert!(
        matches!(error, FetchStoreError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn legacy_over_capacity_filesystem_store_starts_and_replays_without_eviction() {
    let dir = root("fs-legacy-over-capacity");
    fs::create_dir_all(&dir).unwrap();
    let caller = key(29);
    let producer = key(30);
    let (first, first_transcript) =
        transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (second, second_transcript) =
        transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    for transcript in [&first_transcript, &second_transcript] {
        let bytes = canonical_dag_cbor(transcript).unwrap();
        atomic_create_no_clobber(
            &dir.join(format!(
                "{}.dagcbor",
                transcript.input_commitment().digest()
            )),
            &bytes,
        )
        .unwrap();
    }

    // This models upgrading an existing evidence directory while setting
    // a lower cap than the evidence already present. Startup and reads are
    // allowed; the cap applies only to a new distinct retained input.
    let store = fs_store_with_capacity(&dir, 1);
    let state =
        FetchStateMachine::new(store.clone(), FetchCallerPolicy::new([caller.public_key()]));
    assert_eq!(
        state
            .replay_completed(
                first.input_commitment,
                &producer.public_key(),
                &caller.public_key(),
            )
            .unwrap()
            .transcript,
        first_transcript
    );
    assert_eq!(
        state
            .replay_completed(
                second.input_commitment,
                &producer.public_key(),
                &caller.public_key(),
            )
            .unwrap()
            .transcript,
        second_transcript
    );
    let (third, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"third");
    let third_input = third.input_commitment;
    let mut state = FetchStateMachine::new(store, FetchCallerPolicy::new([caller.public_key()]));
    state.quote_input(third.input).unwrap();
    assert!(matches!(
        state.start(third_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));
    assert_eq!(retained_file_count(&dir), 2);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn concurrent_distinct_filesystem_starts_share_one_capacity_reservation() {
    use std::sync::Barrier;

    let dir = root("fs-concurrent-capacity");
    let caller = key(31);
    let producer = key(32);
    let (first, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (second, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    let first_input = first.input_commitment;
    let second_input = second.input_commitment;
    let policy = FetchCallerPolicy::new([caller.public_key()]);
    let mut first_state = FetchStateMachine::new(fs_store_with_capacity(&dir, 1), policy.clone());
    let mut second_state = FetchStateMachine::new(fs_store_with_capacity(&dir, 1), policy);
    first_state.quote_input(first.input).unwrap();
    second_state.quote_input(second.input).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        let result = first_state.start(first_input);
        (first_state, first_input, result)
    });
    let second = std::thread::spawn(move || {
        barrier.wait();
        let result = second_state.start(second_input);
        (second_state, second_input, result)
    });
    let results = [first.join().unwrap(), second.join().unwrap()];

    assert_eq!(
        results
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count(),
        1
    );
    assert_eq!(retained_file_count(&dir), 1);
    for (mut state, input, result) in results {
        if let Err(error) = result {
            // The winner may spend more than the bounded lock wait in fsync
            // or waiting to be scheduled. That is a transient admission
            // refusal, not a second capacity reservation. Once both threads
            // have joined, the loser must observe the durable capacity limit.
            assert!(
                matches!(
                    error,
                    FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
                ) || is_bounded_capacity_contention(&error),
                "unexpected concurrent start rejection: {error}"
            );
            assert!(!state.store.has_running(input).unwrap());
            assert!(matches!(
                state.start(input).unwrap_err(),
                FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
            ));
            assert!(!state.store.has_running(input).unwrap());
        } else {
            assert!(state.store.has_running(input).unwrap());
        }
    }
    assert_eq!(retained_file_count(&dir), 1);
    let _ = fs::remove_dir_all(dir);
}

fn is_bounded_capacity_contention(error: &FetchStateError) -> bool {
    const TIMEOUT: &str = "timed out waiting for the fetch transcript capacity lock";
    match error {
        FetchStateError::Store(FetchStoreError::Io(error)) => {
            error.kind() == io::ErrorKind::WouldBlock && error.to_string() == TIMEOUT
        }
        FetchStateError::StartMarkerRollback { start, cleanup } => {
            let expected = format!("I/O error: {TIMEOUT}");
            start == &expected && cleanup == &expected
        }
        _ => false,
    }
}

#[cfg(unix)]
#[test]
fn a_bounded_start_and_cleanup_lock_timeout_preserves_the_winning_reservation() {
    let dir = root("fs-capacity-timeout-retry");
    let caller = key(31);
    let producer = key(32);
    let (winner, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"first");
    let (loser, _) = transcript_for(&caller, &producer, hellas_rpc::Retention::Retain, b"second");
    let winner_input = winner.input_commitment;
    let loser_input = loser.input_commitment;
    let mut state = FetchStateMachine::new(
        fs_store_with_capacity(&dir, 1),
        FetchCallerPolicy::new([caller.public_key()]),
    );
    state.quote_input(winner.input).unwrap();
    state.quote_input(loser.input).unwrap();
    state.start(winner_input).unwrap();

    // Keep the root lock held until start and its cleanup both time out.
    // This exercises the real bounded-lock failure without relying on a
    // particular disk speed or scheduler interleaving.
    let held = crate::private_fs::open_directory(&dir).unwrap();
    held.lock().unwrap();
    let error = state.start(loser_input).unwrap_err();
    assert!(matches!(error, FetchStateError::StartMarkerRollback { .. }));
    assert!(is_bounded_capacity_contention(&error), "{error}");
    drop(held);

    assert!(state.store.has_running(winner_input).unwrap());
    assert!(!state.store.has_running(loser_input).unwrap());
    assert!(matches!(
        state.start(loser_input).unwrap_err(),
        FetchStateError::Store(FetchStoreError::Capacity { capacity: 1 })
    ));
    assert!(state.store.has_running(winner_input).unwrap());
    assert!(!state.store.has_running(loser_input).unwrap());
    assert_eq!(retained_file_count(&dir), 1);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unique_nonce_quote_flood_is_bounded_by_ticket_count() {
    let caller = key(1);
    let mut state = FetchStateMachine::with_limits(
        MemoryFetchTranscriptStore::default(),
        FetchCallerPolicy::new([caller.public_key()]),
        2,
        usize::MAX,
    );
    let first = signed_input(&caller, hellas_rpc::Retention::Retain, b"{}");
    let second = signed_input(&caller, hellas_rpc::Retention::Retain, b"{}");
    let third = signed_input(&caller, hellas_rpc::Retention::Retain, b"{}");

    let first = state.quote_input(first).unwrap().0.input_commitment;
    let second = state.quote_input(second).unwrap().0.input_commitment;
    assert_ne!(first, second, "fresh nonces must produce distinct tickets");
    assert!(matches!(
        state.quote_input(third).unwrap_err(),
        FetchStateError::TicketCapacity { capacity: 2 }
    ));
    assert_eq!(state.tickets.len(), 2);
}

#[test]
fn signed_input_payloads_have_a_hard_aggregate_bound() {
    let caller = key(1);
    let inputs = [
        signed_input(
            &caller,
            hellas_rpc::Retention::Retain,
            br#"{"input":"one"}"#,
        ),
        signed_input(
            &caller,
            hellas_rpc::Retention::Retain,
            br#"{"input":"two"}"#,
        ),
        signed_input(
            &caller,
            hellas_rpc::Retention::Retain,
            br#"{"input":"tri"}"#,
        ),
    ];
    let one_quote = {
        let verified = verify_input_events(&inputs[0]).unwrap();
        FetchQuote::from_verified(&verified, inputs[0].clone())
    };
    let one_input_bytes = accounted_input_bytes(&one_quote).unwrap();
    let capacity = one_input_bytes * 2;
    let mut state = FetchStateMachine::with_limits(
        MemoryFetchTranscriptStore::default(),
        FetchCallerPolicy::new([caller.public_key()]),
        10,
        capacity,
    );

    state.quote_input(inputs[0].clone()).unwrap();
    state.quote_input(inputs[1].clone()).unwrap();
    assert!(matches!(
        state.quote_input(inputs[2].clone()).unwrap_err(),
        FetchStateError::InputCapacity {
            requested,
            capacity: actual_capacity,
        } if requested > actual_capacity && actual_capacity == capacity
    ));
    assert_eq!(state.tickets.len(), 2);
    assert_eq!(MAX_FETCH_IN_MEMORY_INPUT_BYTES, 32 * 1024 * 1024);
}

#[test]
fn quote_admission_prunes_only_expired_quoted_state() {
    let caller = key(1);
    let now = Instant::now();
    let first = signed_input(&caller, hellas_rpc::Retention::Ephemeral, b"{}");
    let second = signed_input(&caller, hellas_rpc::Retention::Ephemeral, b"{}");
    let mut state = FetchStateMachine::with_limits(
        MemoryFetchTranscriptStore::default(),
        FetchCallerPolicy::new([caller.public_key()]),
        1,
        usize::MAX,
    );

    let first = state.quote_input_at(first, now).unwrap().0.input_commitment;
    let second = state
        .quote_input_at(second, now + QUOTE_TTL)
        .unwrap()
        .0
        .input_commitment;

    assert!(matches!(
        state.quoted(first),
        Err(FetchStateError::NotFound)
    ));
    assert_eq!(state.quoted(second).unwrap().input_commitment, second);
}

#[test]
fn queued_and_running_state_never_expires_under_admission_pruning() {
    let caller = key(1);
    let now = Instant::now();
    let first = signed_input(&caller, hellas_rpc::Retention::Ephemeral, b"{}");
    let second = signed_input(&caller, hellas_rpc::Retention::Ephemeral, b"{}");
    let first_input = verify_input_events(&first).unwrap().input_commitment;
    let mut state = FetchStateMachine::with_limits(
        MemoryFetchTranscriptStore::default(),
        FetchCallerPolicy::new([caller.public_key()]),
        1,
        usize::MAX,
    );

    state.quote_input_at(first, now).unwrap();
    state.queue(first_input).unwrap();
    assert!(matches!(
        state
            .quote_input_at(second.clone(), now + QUOTE_TTL)
            .unwrap_err(),
        FetchStateError::TicketCapacity { capacity: 1 }
    ));
    state.start(first_input).unwrap();
    assert!(matches!(
        state
            .quote_input_at(second.clone(), now + QUOTE_TTL + QUOTE_TTL)
            .unwrap_err(),
        FetchStateError::TicketCapacity { capacity: 1 }
    ));
    state.fail(first_input, "test cleanup").unwrap();
    state
        .quote_input_at(second, now + QUOTE_TTL + QUOTE_TTL)
        .unwrap();
}

#[test]
fn transcript_verifies_both_directions() {
    let (_quote, transcript, caller, producer) = sample_transcript();

    let verified = transcript.verify(&producer).unwrap();

    assert_eq!(verified.caller_key, caller);
}

#[test]
fn retention_gates_running_and_completed_fetch_files() {
    let dir = root("retention");
    let store = fs_store(&dir);
    let (quote, transcript, caller, producer) =
        sample_transcript_with_retention(hellas_rpc::Retention::Ephemeral);
    let input = quote.input_commitment;
    let mut state = trusted_state(store.clone(), caller);

    state.quote_input(quote.input).unwrap();
    state.start(input).unwrap();
    assert_eq!(retained_file_count(&dir), 0);
    state
        .complete_output(input, transcript.output_events().to_vec(), &producer)
        .unwrap();
    assert_eq!(retained_file_count(&dir), 0);
    assert!(state.tickets.is_empty());
    assert!(matches!(
        state
            .replay_completed(input, &producer, &caller)
            .unwrap_err(),
        FetchStateError::NotFound
    ));

    let (quote, transcript, caller, producer) = sample_transcript();
    let input = quote.input_commitment;
    let mut retained_state = trusted_state(store, caller);
    retained_state.quote_input(quote.input).unwrap();
    retained_state.start(input).unwrap();
    assert!(dir.join(format!("{}.running", input.digest())).is_file());
    retained_state
        .complete_output(input, transcript.output_events().to_vec(), &producer)
        .unwrap();
    assert!(dir.join(format!("{}.dagcbor", input.digest())).is_file());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn cannot_start_same_ticket_twice() {
    let dir = root("double-start");
    let store = fs_store(&dir);
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let input = quote.input_commitment;
    let mut state = trusted_state(store, caller);
    state.quote_input(quote.input.clone()).unwrap();

    state.start(input).unwrap();
    assert!(matches!(
        state.start(input).unwrap_err(),
        FetchStateError::AlreadyRunning
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn concurrent_state_machines_cannot_both_start_same_ticket() {
    let dir = root("exclusive-start");
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let input = quote.input_commitment;
    // Two processes sharing one store root, both holding the ticket.
    let mut first = trusted_state(fs_store(&dir), caller);
    let mut second = trusted_state(fs_store(&dir), caller);
    first.quote_input(quote.input.clone()).unwrap();
    second.quote_input(quote.input.clone()).unwrap();

    first.start(input).unwrap();

    // The loser must refuse to run; only one provider call can exist.
    assert!(matches!(
        second.start(input).unwrap_err(),
        FetchStateError::Indeterminate
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn crashed_running_ticket_is_indeterminate_after_restart() {
    let dir = root("crash-running");
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let input = quote.input_commitment;
    {
        let mut state = trusted_state(fs_store(&dir), caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        // Crash here: the provider may or may not have been called.
    }

    let store = fs_store(&dir);
    assert!(store.has_running(input).unwrap());
    // The marker is an operator-readable record of what may have run.
    let record: FetchRunningRecord =
        serde_json::from_slice(&fs::read(store.running_path(input)).unwrap()).unwrap();
    assert_eq!(record.service, "openai");
    assert_eq!(record.method, "responses");
    assert_eq!(record.idempotency_key, input.digest().to_string());
    assert!(!record.caller_public_key.is_empty());
    let mut recovered = trusted_state(store, caller);
    assert!(matches!(
        recovered.quote_input(quote.input.clone()).unwrap_err(),
        FetchStateError::Indeterminate
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completed_ticket_clears_running_marker_and_replays_after_restart() {
    let dir = root("complete-clears-marker");
    let (quote, transcript, caller, producer) = sample_transcript();
    let input = quote.input_commitment;
    {
        let mut state = trusted_state(fs_store(&dir), caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        state
            .complete_output(input, transcript.output_events().to_vec(), &producer)
            .unwrap();
    }

    let store = fs_store(&dir);
    assert!(!store.has_running(input).unwrap());
    let mut recovered = trusted_state(store, caller);
    // Re-quoting a completed input succeeds so the caller can replay.
    recovered.quote_input(quote.input.clone()).unwrap();
    let replayed = recovered
        .replay_completed(input, &producer, &caller)
        .unwrap();
    assert_eq!(replayed.transcript.input_commitment(), input);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_ticket_is_indeterminate_after_restart() {
    let dir = root("crash-failed");
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let input = quote.input_commitment;
    {
        let mut state = trusted_state(fs_store(&dir), caller);
        state.quote_input(quote.input.clone()).unwrap();
        state.start(input).unwrap();
        state.fail(input, "provider exploded").unwrap();
        // The transient state is gone, but the durable running marker
        // still makes the provider call indeterminate.
        assert!(state.tickets.is_empty());
    }

    let mut recovered = trusted_state(fs_store(&dir), caller);
    assert!(matches!(
        recovered.quote_input(quote.input.clone()).unwrap_err(),
        FetchStateError::Indeterminate
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn quote_input_verifies_and_stores_ticket() {
    let dir = root("quote-input");
    let store = fs_store(&dir);
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let mut state = trusted_state(store, caller);

    let (stored, _verified) = state.quote_input(quote.input.clone()).unwrap();

    assert_eq!(stored.input_commitment, quote.input_commitment);
    assert_eq!(
        state
            .start(stored.input_commitment)
            .unwrap()
            .input_commitment,
        quote.input_commitment
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn quote_input_rejects_untrusted_caller() {
    let dir = root("unauthorized-caller");
    let store = fs_store(&dir);
    let (quote, _transcript, _caller, _producer) = sample_transcript();
    let untrusted = key(9).public_key();
    let mut state = FetchStateMachine::new(store, FetchCallerPolicy::new([untrusted]));

    assert!(matches!(
        state.quote_input(quote.input.clone()).unwrap_err(),
        FetchStateError::UnauthorizedCaller
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completed_ticket_replays_transcript() {
    let dir = root("replay");
    let store = fs_store(&dir);
    let (quote, transcript, caller, producer) = sample_transcript();
    let input = quote.input_commitment;
    let mut state = trusted_state(store, caller);
    state.quote_input(quote.input.clone()).unwrap();
    state.start(input).unwrap();
    let completed = state
        .complete_output(input, transcript.output_events().to_vec(), &producer)
        .unwrap();

    assert_eq!(completed, transcript);
    assert_eq!(
        state
            .replay_completed(input, &producer, &caller)
            .unwrap()
            .transcript,
        transcript
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completed_input_can_be_quoted_again_for_replay() {
    let (quote, transcript, caller, producer) = sample_transcript();
    let input = quote.input_commitment;
    let mut state = trusted_memory_state(caller);
    state.quote_input(quote.input.clone()).unwrap();
    state.start(input).unwrap();
    state
        .complete_output(input, transcript.output_events().to_vec(), &producer)
        .unwrap();

    let (repeated, _verified) = state.quote_input(quote.input.clone()).unwrap();

    assert_eq!(repeated.input_commitment, input);
    assert_eq!(
        state
            .replay_completed(input, &producer, &caller)
            .unwrap()
            .transcript,
        transcript
    );
}

#[test]
fn memory_store_rejects_conflicting_completion() {
    let (_quote, first, _caller, _producer) = sample_transcript();
    let mut second = first.clone();
    second.output = Vec::new();
    let store = MemoryFetchTranscriptStore::default();

    store.put_completed(&first).unwrap();

    assert!(matches!(
        store.put_completed(&second).unwrap_err(),
        FetchStoreError::Conflict { input } if input == first.input_commitment()
    ));
}

#[test]
fn completion_rejects_untrusted_producer_key() {
    let dir = root("wrong-producer");
    let store = fs_store(&dir);
    let (quote, transcript, caller, _producer) = sample_transcript();
    let wrong_producer = key(9).public_key();
    let input = quote.input_commitment;
    let mut state = trusted_state(store, caller);
    state.quote_input(quote.input.clone()).unwrap();
    state.start(input).unwrap();

    assert!(matches!(
        state
            .complete_output(input, transcript.output_events().to_vec(), &wrong_producer)
            .unwrap_err(),
        FetchStateError::Verify(FetchTranscriptError::ProducerKeyMismatch)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completion_rejects_transcript_that_does_not_match_quote() {
    let dir = root("quote-mismatch");
    let store = fs_store(&dir);
    let (quote, mut transcript, caller, producer) = sample_transcript();
    let input = quote.input_commitment;
    transcript.input.clear();
    let mut state = trusted_state(store, caller);
    state.quote_input(quote.input.clone()).unwrap();
    state.start(input).unwrap();

    assert!(matches!(
        state
            .complete_transcript(transcript, &producer)
            .unwrap_err(),
        FetchStateError::QuoteMismatch
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_ticket_does_not_replay() {
    let dir = root("failed");
    let store = fs_store(&dir);
    let (quote, _transcript, caller, _producer) = sample_transcript();
    let input = quote.input_commitment;
    let mut state = trusted_state(store, caller);
    state.quote_input(quote.input.clone()).unwrap();
    state.start(input).unwrap();
    state.fail(input, "provider failed").unwrap();

    assert!(matches!(
        state
            .replay_completed(input, &key(2).public_key(), &caller)
            .unwrap_err(),
        FetchStateError::NotFound
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completed_transcript_survives_store_reload() {
    let dir = root("reload");
    let store = fs_store(&dir);
    let (_quote, transcript, _caller, _producer) = sample_transcript();
    let input = transcript.input_commitment();
    store.put_completed(&transcript).unwrap();

    let reloaded = fs_store(&dir);
    assert_eq!(reloaded.get_completed(input).unwrap(), Some(transcript));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn completed_store_put_is_idempotent_for_same_bytes() {
    let dir = root("idempotent-put");
    let store = fs_store(&dir);
    let (_quote, transcript, _caller, _producer) = sample_transcript();

    store.put_completed(&transcript).unwrap();
    store.put_completed(&transcript).unwrap();
    let _ = fs::remove_dir_all(dir);
}
