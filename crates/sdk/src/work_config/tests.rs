use super::*;
use hellas_rpc::ContentId;
use hellas_work::model::{
    fetch::{FetchPolicyV2, FetchRoutePolicy, fetch_route_commitment},
    work::EvaluatePolicyV2,
};
use serde_json::{Value, json};

fn config() -> WorkConfig {
    WorkConfig {
        chain: ChainCrossCheck {
            network: NetworkId::new("hellas-devnet-1").unwrap(),
            genesis_payload_digest: Digest::from_bytes([1; 32]),
            threshold_identity: hex::decode(concat!(
                "97f1d3a73197d7942695638c4fa9ac0fc",
                "3688c4f9774b905a14e3a3f171bac586",
                "c55e83ff97a1aeffb3af00adb22c6bb",
            ))
            .unwrap(),
            genesis: None,
        },
        validators: (1..=VALIDATOR_COUNT)
            .map(|i| format!("ws://127.0.0.1:900{i}"))
            .collect(),
        journal_root: PathBuf::from("/var/lib/hellas/work"),
        routes: WorkRoutes::try_from_iter([WorkRoute {
            peer: PeerId::from_bytes([0x31; 32]),
            bond: EdgeId::from_bytes([0x41; 32]),
            client: Key::from_bytes([2; 33]),
        }])
        .unwrap(),
        policy_salt: [0x5a; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        work_policy: EvaluatePolicyV2 {
            allowed_environment: ContentId::from_bytes([0x11; 32]),
            generation_policy_digest: Digest::from_bytes([0x12; 32]),
            identity_source_digest: Digest::from_bytes([0x13; 32]),
            max_prompt_tokens: 512,
            max_new_tokens: 128,
            max_stop_token_ids: 4,
            max_spool_bytes: 1_048_576,
            max_encoded_result_frame: 262_144,
            max_encoded_prepared_input: 1_048_576,
        }
        .into(),
        payment_policy: JobPaymentPolicyV2 {
            fixed_price: 10,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        },
        poll: Duration::from_millis(250),
        max_observation_age: Duration::from_millis(5_000),
        expected_payment_values: EdgeValues::new(100, 50, Fees::new(0, 0, 0, 0)),
        min_omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
    }
}

fn file(config: &WorkConfig) -> Value {
    let mut policies = json!({
        "policy_salt": hex::encode(config.policy_salt),
        "channel": {"compute_credit_limit": config.channel_policy.compute_credit_limit, "delivery_credit_limit": config.channel_policy.delivery_credit_limit},
        "payment": {
            "fixed_price": config.payment_policy.fixed_price,
            "dispatch_margin_blocks": config.payment_policy.dispatch_margin_blocks,
            "delivery_margin_blocks": config.payment_policy.delivery_margin_blocks,
            "oracle_grace_blocks": config.payment_policy.oracle_grace_blocks,
        },
    });
    match &config.work_policy {
        WorkPolicy::Evaluate(p) => {
            policies["execution"] = json!({
                "allowed_environment": p.allowed_environment.to_string(),
                "generation_policy_digest": hex::encode(p.generation_policy_digest.as_bytes()),
                "identity_source_digest": hex::encode(p.identity_source_digest.as_bytes()),
                "max_prompt_tokens": p.max_prompt_tokens, "max_new_tokens": p.max_new_tokens,
                "max_stop_token_ids": p.max_stop_token_ids, "max_spool_bytes": p.max_spool_bytes,
                "max_encoded_result_frame": p.max_encoded_result_frame,
                "max_encoded_prepared_input": p.max_encoded_prepared_input,
            })
        }
        WorkPolicy::Fetch {
            policy: p,
            route,
            contract,
        } => {
            let mut fetch = json!({
                "allowed_environment": p.allowed_environment.to_string(), "contract": contract,
                "max_request_body_bytes": p.max_request_body_bytes,
                "max_output_events": p.max_output_events, "max_output_bytes": p.max_output_bytes,
                "max_spool_bytes": p.max_spool_bytes, "max_encoded_result_frame": p.max_encoded_result_frame,
                "max_encoded_prepared_input": p.max_encoded_prepared_input,
            });
            match route {
                FetchRoutePolicy::SealedRoute { service, method } => {
                    fetch["service"] = json!(service);
                    fetch["method"] = json!(method);
                }
                FetchRoutePolicy::OpenFetch {
                    require_spki_pin,
                    allowed_hosts,
                } => {
                    fetch["open_fetch"] = json!({"require_spki_pin": require_spki_pin, "allowed_hosts": allowed_hosts});
                }
            }
            policies["fetch"] = fetch;
        }
    }
    json!({
        "chain": {
            "network_id": config.chain.network.as_str(),
            "genesis_payload_digest": hex::encode(config.chain.genesis_payload_digest.as_bytes()),
            "threshold_identity": hex::encode(&config.chain.threshold_identity),
            "genesis": config.chain.genesis,
        },
        "validators": config.validators, "journal": {"root": config.journal_root},
        "routes": config.routes.iter().map(|r| json!({
            "peer": hex::encode(r.peer.as_bytes()), "bond": hex::encode(r.bond.to_bytes()), "client": hex::encode(r.client.to_bytes()),
        })).collect::<Vec<_>>(),
        "policies": policies, "poll_ms": config.poll.as_millis(),
        "max_observation_age_ms": config.max_observation_age.as_millis(),
        "expected_payment_values": {"value": 100, "reserve": 50, "close_fees": {"base": 0, "slot": 0, "proof": 0, "lifetime": 0}},
        "min_omit_response_blocks": config.min_omit_response_blocks,
    })
}

fn load(config: &WorkConfig) -> Result<WorkConfig> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("work.json");
    std::fs::write(&path, file(config).to_string()).unwrap();
    load_work_config(&path).map_err(|error| match error {
        WorkConfigError::File { source, .. } => *source,
        other => other,
    })
}

fn accepts(config: WorkConfig) -> WorkConfig {
    let loaded = load(&config).unwrap();
    let typed = config.validate().unwrap();
    assert_eq!(typed.chain, loaded.chain);
    assert_eq!(typed.validators, loaded.validators);
    assert_eq!(typed.journal_root, loaded.journal_root);
    assert_eq!(typed.routes, loaded.routes);
    assert_eq!(typed.policy_salt, loaded.policy_salt);
    assert_eq!(typed.channel_policy, loaded.channel_policy);
    assert_eq!(typed.work_policy, loaded.work_policy);
    assert_eq!(typed.payment_policy, loaded.payment_policy);
    assert_eq!(typed.poll, loaded.poll);
    assert_eq!(typed.max_observation_age, loaded.max_observation_age);
    assert_eq!(
        typed.expected_payment_values,
        loaded.expected_payment_values
    );
    assert_eq!(
        typed.min_omit_response_blocks,
        loaded.min_omit_response_blocks
    );
    typed
}

fn refuses(config: WorkConfig) {
    let loaded = load(&config).unwrap_err();
    let typed = config.validate().unwrap_err();
    assert_eq!(
        std::mem::discriminant(&typed),
        std::mem::discriminant(&loaded)
    );
    assert_eq!(typed.to_string(), loaded.to_string());
}

#[test]
fn typed_and_loaded_configs_normalize_identically() {
    let mut c = config();
    c.validators[0] = " WSS://EXAMPLE.COM:443 ".into();
    let c = accepts(c);
    assert_eq!(c.validators[0], "wss://example.com/");
    assert_eq!(c.validators[1], "ws://127.0.0.1:9002/");
    let node = c.node_config(PathBuf::from("node"), None).unwrap();
    assert_eq!(node.validators, c.validators);
    accepts(c); // Normalization is idempotent.
}

#[test]
fn typed_and_loaded_validator_refusals_match() {
    for entry in [
        "",
        "not a URL",
        "mailto:validators@example.com",
        "http://example.com",
        "https://example.com",
        "ftp://example.com",
    ] {
        let mut c = config();
        c.validators[0] = entry.into();
        refuses(c);
    }
    let mut c = config();
    c.validators.pop();
    refuses(c);
    let mut c = config();
    c.validators.push("ws://extra.example".into());
    refuses(c);
    let mut c = config();
    c.validators[0] = " WS://EXAMPLE.COM:80 ".into();
    c.validators[5] = "ws://example.com/".into();
    refuses(c);
}

#[test]
fn typed_and_loaded_chain_timing_and_journal_refusals_match() {
    for identity in [vec![], vec![0; 48], vec![1; 16]] {
        let mut c = config();
        c.chain.threshold_identity = identity;
        refuses(c);
    }
    let mut c = config();
    c.chain.network = NetworkId::new("custom-network").unwrap();
    refuses(c);
    let mut c = config();
    c.chain.genesis = Some(chain_genesis(c.chain.network, &None).unwrap());
    c.chain.network = NetworkId::new("custom-network").unwrap();
    refuses(c);
    let mut c = config();
    c.journal_root = PathBuf::new();
    refuses(c);
    let mut c = config();
    c.poll = Duration::ZERO;
    refuses(c);
    for age in [
        Duration::ZERO,
        Duration::from_millis(249),
        Duration::from_millis(250),
    ] {
        let mut c = config();
        c.max_observation_age = age;
        refuses(c);
    }
    let mut c = config();
    c.min_omit_response_blocks = MIN_OMIT_RESPONSE_BLOCKS - 1;
    refuses(c);
}

#[test]
fn typed_and_loaded_payment_and_evaluate_refusals_match() {
    for index in 0..4 {
        let mut c = config();
        *match index {
            0 => &mut c.payment_policy.fixed_price,
            1 => &mut c.payment_policy.dispatch_margin_blocks,
            2 => &mut c.payment_policy.delivery_margin_blocks,
            _ => &mut c.payment_policy.oracle_grace_blocks,
        } = 0;
        refuses(c);
    }
    for index in 0..5 {
        let mut c = config();
        let WorkPolicy::Evaluate(p) = &mut c.work_policy else {
            unreachable!()
        };
        match index {
            0 => p.max_prompt_tokens = 0,
            1 => p.max_new_tokens = 0,
            2 => p.max_spool_bytes = 0,
            3 => p.max_encoded_result_frame = 0,
            _ => p.max_encoded_prepared_input = 0,
        }
        refuses(c);
    }
    let mut c = config();
    let WorkPolicy::Evaluate(p) = &mut c.work_policy else {
        unreachable!()
    };
    p.max_stop_token_ids = 0;
    accepts(c);
}

fn fetch_config(route: FetchRoutePolicy) -> WorkConfig {
    let mut c = config();
    let contract = hellas_rpc::FetchContract::http().unwrap();
    c.work_policy = WorkPolicy::Fetch {
        policy: FetchPolicyV2 {
            allowed_environment: contract.manifest_id(),
            route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
            max_request_body_bytes: 4096,
            max_output_events: 64,
            max_output_bytes: 16384,
            max_spool_bytes: 65536,
            max_encoded_result_frame: 65536,
            max_encoded_prepared_input: 65536,
        },
        route,
        contract,
    };
    c
}

#[test]
fn typed_and_loaded_fetch_policies_and_refusals_match() {
    let sealed = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    accepts(fetch_config(sealed.clone()));
    accepts(fetch_config(FetchRoutePolicy::open_fetch(
        true,
        vec!["api.example.com".into()],
    )));
    for index in 0..7 {
        let mut c = fetch_config(sealed.clone());
        let WorkPolicy::Fetch { policy, .. } = &mut c.work_policy else {
            unreachable!()
        };
        match index {
            0 => policy.max_request_body_bytes = 0,
            1 => policy.max_output_events = 0,
            2 => policy.max_output_bytes = 0,
            3 => policy.max_spool_bytes = 0,
            4 => policy.max_encoded_result_frame = 0,
            5 => policy.max_encoded_prepared_input = 0,
            _ => policy.allowed_environment = ContentId::from_bytes([0xff; 32]),
        }
        refuses(c);
    }
    refuses(fetch_config(FetchRoutePolicy::SealedRoute {
        service: String::new(),
        method: "responses".into(),
    }));
}
