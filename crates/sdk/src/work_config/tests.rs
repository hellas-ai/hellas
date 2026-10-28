use super::*;
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
        poll: Duration::from_millis(250),
        max_observation_age: Duration::from_millis(5_000),
    }
}

fn file(config: &WorkConfig) -> Value {
    json!({
        "chain": {
            "network_id": config.chain.network.as_str(),
            "genesis_payload_digest": hex::encode(config.chain.genesis_payload_digest.as_bytes()),
            "threshold_identity": hex::encode(&config.chain.threshold_identity),
            "genesis": config.chain.genesis,
        },
        "validators": config.validators, "journal": {"root": config.journal_root},
        "poll_ms": config.poll.as_millis(),
        "max_observation_age_ms": config.max_observation_age.as_millis(),
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
    assert_eq!(typed.poll, loaded.poll);
    assert_eq!(typed.max_observation_age, loaded.max_observation_age);
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
}
