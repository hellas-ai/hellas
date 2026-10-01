use super::{
    BoundTerm, Canonical, CanonicalDecode, InputAddressed, OutputAddressed, OutputId, SourceRef,
    TextArtifact, TextExecution, TextPolicy, TextState, TokenId, TokenIds,
};

fn output_id<T>(byte: u8) -> OutputId<T> {
    OutputId::from_bytes([byte; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn token_artifact_heap_accounting_uses_owned_capacities() {
    let mut token_buffer = Vec::with_capacity(32);
    token_buffer.extend([TokenId::new(1), TokenId::new(2)]);
    let tokens = TokenIds::new(token_buffer);

    let mut stop_buffer = Vec::with_capacity(16);
    stop_buffer.extend([TokenId::new(3), TokenId::new(4)]);
    let policy = TextPolicy::new(8, stop_buffer);

    assert_eq!(
        tokens.retained_heap_bytes(),
        Some(tokens.tokens.capacity() * std::mem::size_of::<TokenId>())
    );
    assert_eq!(
        policy.retained_heap_bytes(),
        Some(policy.stop_token_ids.capacity() * std::mem::size_of::<TokenId>())
    );
    assert!(tokens.tokens.capacity() > tokens.tokens.len());
    assert!(policy.stop_token_ids.capacity() > policy.stop_token_ids.len());
}

/// Golden bytes, captured from this schema's previous home in
/// `hellas-executor`, decoded field by field.
///
/// Round-tripping cannot catch a field order that moves in the
/// encoder and the decoder together, and every id below is the hash
/// of these exact bytes: an artifact that re-encoded differently
/// would silently re-address every stored blob. So the bytes are the
/// assertion, not the values they decode to.
#[test]
fn canonical_bytes_are_pinned_by_golden_vectors() {
    let tokens = TokenIds::from([1, 2, 300_000]);
    assert_eq!(
        hex(&tokens.canonical_bytes()),
        concat!(
            "82", // array(2)
            "781c",
            "68656c6c61732e6576616c756174652e746f6b656e5f6964732e7631", // schema tag
            "83",                                                       // array(3) tokens
            "01",
            "02",
            "1a000493e0", // 1, 2, 300000
        )
    );

    let policy = TextPolicy::from_u32_stop_tokens(16, [5, 4]);
    assert_eq!(
        hex(&policy.canonical_bytes()),
        concat!(
            "83", // array(3)
            "781e",
            "68656c6c61732e6576616c756174652e746578742e706f6c6963792e7631",
            "10", // max_new_tokens = 16
            "82",
            "04",
            "05", // sorted stop ids
        )
    );

    let identity = TextArtifact::identity(output_id::<BoundTerm>(7));
    assert_eq!(
        hex(&identity.canonical_bytes()),
        concat!(
            "82", // array(2)
            "7829",
            "68656c6c61732e6576616c756174652e746578742e61727469666163742e6964656e746974792e7633",
            "5820",
            "0707070707070707070707070707070707070707070707070707070707070707",
        )
    );

    let state = TextState::new(tokens.output_id());
    assert_eq!(
        hex(&state.canonical_bytes()),
        concat!(
            "82",
            "781d",
            "68656c6c61732e6576616c756174652e746578742e73746174652e7631",
            "5820",
            "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
        )
    );

    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        tokens.output_id(),
        policy.output_id(),
    );
    assert_eq!(
        hex(&execution.canonical_bytes()),
        concat!(
            "84", // array(4)
            "7821",
            "68656c6c61732e6576616c756174652e746578742e657865637574696f6e2e7631",
            "82", // source array(2)
            "7820",
            "68656c6c61732e6576616c756174652e736f757263652e6f75747075742e7631",
            "5820",
            "d43171953821e475764c09fd8e520e17b486a50212fdf2be6465f83b8ca84544",
            "5820",
            "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
            "5820",
            "3540781322ed7b80e3459cf7b40106c9a7472dd2cf2d6e8e9d5d4d25ae11aa60",
        )
    );

    let artifact = TextArtifact::output(
        execution.input_id(),
        3,
        state.output_id(),
        tokens.output_id(),
    );
    assert_eq!(
        hex(&artifact.canonical_bytes()),
        concat!(
            "85",
            "7827",
            "68656c6c61732e6576616c756174652e746578742e61727469666163742e6f75747075742e7631",
            "5820",
            "027834450d115db494c56e25410383db314f7e820f8dceb76da9ca7a45ca8080",
            "03", // position
            "5820",
            "4a7cc97833bc25d2340ce377de92c012f336858cfeb8e2859f67fd12975916b8",
            "5820",
            "2ea3d70455fb7c175feeffc0a307b7c97fb60980926e66118b8baf8fd0cd6db2",
        )
    );

    assert_eq!(
        hex(identity.output_id().as_bytes()),
        "d43171953821e475764c09fd8e520e17b486a50212fdf2be6465f83b8ca84544"
    );
    assert_eq!(
        hex(execution.input_id().as_bytes()),
        "027834450d115db494c56e25410383db314f7e820f8dceb76da9ca7a45ca8080"
    );
}

#[test]
fn token_ids_are_output_addressed_values() {
    let a = TokenIds::from([1, 2, 3]);
    let b = TokenIds::from([1, 2, 3]);
    let c = TokenIds::from([3, 2, 1]);

    assert_eq!(
        a.as_slice(),
        &[TokenId::new(1), TokenId::new(2), TokenId::new(3)]
    );
    assert_eq!(a.output_id(), b.output_id());
    assert_ne!(a.output_id(), c.output_id());
}

#[test]
fn negative_model_token_ids_are_rejected_at_the_boundary() {
    assert_eq!(TokenId::try_from(7_i32).unwrap(), TokenId::new(7));
    let err = TokenId::try_from(-1_i32).unwrap_err();
    assert_eq!(err.value(), -1);
}

#[test]
fn policy_canonicalizes_stop_ids() {
    let a = TextPolicy::from_u32_stop_tokens(16, [2, 1, 2]);
    let b = TextPolicy::from_u32_stop_tokens(16, [1, 2]);
    assert_eq!(a.stop_token_ids(), &[TokenId::new(1), TokenId::new(2)]);
    assert_eq!(a.output_id(), b.output_id());
}

#[test]
fn text_state_is_output_addressed_by_token_artifact() {
    let a = TextState::new(TokenIds::from([1, 2, 3]).output_id());
    let b = TextState::new(TokenIds::from([1, 2, 3]).output_id());
    let c = TextState::new(TokenIds::from([1, 2, 4]).output_id());

    assert_eq!(a.tokens(), b.tokens());
    assert_eq!(a.output_id(), b.output_id());
    assert_ne!(a.output_id(), c.output_id());
}

#[test]
fn identity_is_output_addressed_genesis() {
    let identity = TextArtifact::identity(output_id::<BoundTerm>(7));
    let other_environment = TextArtifact::identity(output_id::<BoundTerm>(8));
    let prompt_tokens = TokenIds::from([1]).output_id();
    let policy = TextPolicy::from_u32_stop_tokens(4, []).output_id();
    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        prompt_tokens,
        policy,
    );

    assert_ne!(identity.output_id(), other_environment.output_id());
    assert_ne!(
        execution.input_id().as_bytes(),
        identity.output_id().as_bytes()
    );
}

#[test]
fn execution_input_id_changes_when_source_changes() {
    let identity = TextArtifact::identity(output_id::<BoundTerm>(7));
    let prompt_tokens = TokenIds::from([1]).output_id();
    let policy = TextPolicy::from_u32_stop_tokens(4, []).output_id();
    let first = TextExecution::new(
        SourceRef::output(identity.output_id()),
        prompt_tokens,
        policy,
    );
    let second = TextExecution::new(SourceRef::input(first.input_id()), prompt_tokens, policy);

    assert_ne!(first.input_id(), second.input_id());
}

#[test]
fn output_artifact_id_changes_when_generated_tokens_change() {
    let execution = TextExecution::new(
        SourceRef::output(TextArtifact::identity(output_id::<BoundTerm>(7)).output_id()),
        TokenIds::from([1]).output_id(),
        TextPolicy::from_u32_stop_tokens(4, []).output_id(),
    )
    .input_id();
    let a = TextArtifact::output(
        execution,
        5,
        TextState::new(TokenIds::from([1]).output_id()).output_id(),
        TokenIds::from([1]).output_id(),
    );
    let b = TextArtifact::output(
        execution,
        5,
        TextState::new(TokenIds::from([1]).output_id()).output_id(),
        TokenIds::from([2]).output_id(),
    );

    assert_ne!(a.output_id(), b.output_id());
}

#[test]
fn canonical_text_objects_decode_round_trip() {
    let tokens = TokenIds::from([1, 2, 3]);
    assert_eq!(
        TokenIds::from_canonical_bytes(&tokens.canonical_bytes()).unwrap(),
        tokens
    );

    let policy = TextPolicy::from_u32_stop_tokens(16, [4, 5]);
    assert_eq!(
        TextPolicy::from_canonical_bytes(&policy.canonical_bytes()).unwrap(),
        policy
    );

    let state = TextState::new(tokens.output_id());
    assert_eq!(
        TextState::from_canonical_bytes(&state.canonical_bytes()).unwrap(),
        state
    );

    let identity = TextArtifact::identity(output_id::<BoundTerm>(7));
    assert_eq!(
        TextArtifact::from_canonical_bytes(&identity.canonical_bytes()).unwrap(),
        identity
    );

    let execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        tokens.output_id(),
        policy.output_id(),
    );
    assert_eq!(
        TextExecution::from_canonical_bytes(&execution.canonical_bytes()).unwrap(),
        execution
    );

    let artifact = TextArtifact::output(
        execution.input_id(),
        3,
        state.output_id(),
        tokens.output_id(),
    );
    assert_eq!(
        TextArtifact::from_canonical_bytes(&artifact.canonical_bytes()).unwrap(),
        artifact
    );
}

#[test]
fn decoder_rejects_trailing_bytes() {
    let mut bytes = TokenIds::from([1]).canonical_bytes();
    bytes.push(0);

    let err = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
    assert!(err.to_string().contains("trailing bytes"));
}

#[test]
fn decoder_rejects_wrong_schema() {
    let mut bytes = TokenIds::from([1]).canonical_bytes();
    let schema_start = bytes
        .iter()
        .position(|byte| *byte == b'h')
        .expect("schema tag starts with h");
    bytes[schema_start] = b'x';

    let err = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
    assert!(err.to_string().contains("schema tag"));
}

#[test]
fn decoder_rejects_impossible_array_length_before_allocation() {
    let mut bytes = TokenIds::from([]).canonical_bytes();
    assert_eq!(bytes.pop(), Some(0x80), "empty token array is final field");
    bytes.extend([0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    let error = TokenIds::from_canonical_bytes(&bytes).unwrap_err();
    assert!(error.to_string().contains("encoded bytes remain"));
}
