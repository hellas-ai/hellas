use super::*;
use hellas_kernel::NetworkId;
use hellas_rpc::peers::PeerId;

#[test]
fn recovery_skips_only_permanent_delivery_refusals() {
    use hellas_client::work::CollectResultError;
    use hellas_work::work::{DeliverError, WorkRefusal};

    for (refusal, permanent) in [
        (WorkRefusal::Declined, true),
        (WorkRefusal::Expired, true),
        (WorkRefusal::NotReady, false),
        (WorkRefusal::Unavailable, false),
    ] {
        let delivery = || DeliverError::Refused {
            refusal,
            reason: "provider diagnostic".to_owned(),
        };
        assert_eq!(permanently_refused_delivery(&delivery().into()), permanent);
        assert_eq!(
            permanently_refused_delivery(&CollectResultError::Deliver(delivery()).into()),
            permanent,
        );
    }
    assert!(!permanently_refused_delivery(
        &DeliverError::Malformed("result").into()
    ));
    assert!(!permanently_refused_delivery(&anyhow::anyhow!(
        "connection lost"
    )));
}

#[test]
fn relative_deadlines_are_ordered_from_the_current_cursor() {
    let args = RunArgs {
        work_config: "work.json".into(),
        journal_root: "journal".into(),
        provider: SecretKey::generate().public(),
        provider_addrs: Vec::new(),
        bond: hex::encode([1_u8; 32]),
        payment_coins: vec![hex::encode([2_u8; 32])],
        omission_bond: 3,
        prepared_input: "input.bin".into(),
        output: None,
        acceptance_blocks: 4,
        terminal_blocks: 5,
        payment_blocks: 6,
        timeout_secs: 7,
        settle: false,
    };
    assert_eq!(
        relative_deadlines(10, &args).unwrap(),
        JobDeadlines {
            acceptance: 14,
            terminal: 19,
            payment: 25,
        },
    );
}

#[test]
fn payment_coin_parser_refuses_the_fifth_coin() {
    let values = (0..=MAX_PARTY_INPUTS)
        .map(|byte| hex::encode([byte as u8; 32]))
        .collect::<Vec<_>>();
    assert!(coins(&values).is_err());
}

#[test]
fn fixed_hex_names_wrong_widths() {
    let error = fixed_hex::<32>("--bond", "00").unwrap_err().to_string();
    assert!(error.contains("1 bytes; expected 32"), "{error}");
}

#[test]
fn genesis_check_compares_the_configured_digest_with_block_ones_parent() {
    let configured = [0x31; 32];
    assert!(check_genesis_payload(&configured, &configured).is_ok());

    let observed_parent = [0x32; 32];
    let error = check_genesis_payload(&configured, &observed_parent)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&hex::encode(observed_parent)), "{error}");
    assert!(error.contains(&hex::encode(configured)), "{error}");
}

#[test]
fn peer_id_hex_is_the_route_spelling() {
    let key = SecretKey::generate();
    let peer = PeerId::from_bytes(*key.public().as_bytes());
    assert_eq!(
        hex::encode(peer.as_bytes()),
        hex::encode(key.public().as_bytes())
    );
}

#[test]
fn terms_are_bound_to_the_configured_network() {
    let network = NetworkId::new("paid-work-cli-test").unwrap();
    let policy = hellas_rpc::protocol::work::PaidChannelPolicyV1 {
        compute_credit_limit: 4,
        delivery_credit_limit: 5,
    };
    assert_ne!(
        private_policy_commitment(network, &[7; 32], &policy),
        private_policy_commitment(
            NetworkId::new("paid-work-cli-other").unwrap(),
            &[7; 32],
            &policy,
        ),
    );
}

#[cfg(feature = "llm")]
#[test]
fn prepare_input_builds_a_bundle_from_an_environment_and_prompt() {
    use hellas_rpc::{CausalLmEnvironment, ContentId, ContentRef, PublicKey};

    let root = tempfile::tempdir().unwrap();
    let environment_path = root.path().join("model.environment");
    let tokenizer_path = root.path().join("tokenizer.json");
    let output = root.path().join("paid-input.bin");
    let environment = CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([9; 32]), 1),
        "main",
        Vec::new(),
        Vec::new(),
        vec![4],
        3,
        128,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 128,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    std::fs::write(&environment_path, environment.canonical_bytes()).unwrap();
    std::fs::write(
        &tokenizer_path,
        br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"world":1,"<unk>":2},"unk_token":"<unk>"}}"#,
    )
    .unwrap();
    let transport = SecretKey::generate();
    let settlement = Secp256k1Signer::from_secret_scalar([7; 32]).unwrap();
    prepare_input(
        PrepareInputArgs {
            environment: environment_path,
            tokenizer: tokenizer_path,
            prompt: "hello world".to_owned(),
            max_new_tokens: 8,
            stop_token_ids: vec![2],
            out: output.clone(),
        },
        &transport,
        &settlement,
    )
    .unwrap();

    let prepared = read_prepared_input(&output).unwrap();
    let parts = prepared.parts().unwrap();
    assert_eq!(
        parts
            .prompt_tokens
            .as_slice()
            .iter()
            .map(|token| token.as_u32())
            .collect::<Vec<_>>(),
        [0, 1],
    );
    assert_eq!(parts.text_policy.max_new_tokens(), 8);
    assert_eq!(
        parts.evaluate_request.runner_public_key,
        PublicKey::Secp256k1(settlement.party_key().to_bytes()),
    );
    assert!(parts.evaluate_request.retain);
    assert_eq!(
        parts.evaluate_request.execution_environment,
        environment.manifest().content_id(),
    );
}
