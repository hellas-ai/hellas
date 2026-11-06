use super::*;
use hellas_chain::genesis::Chain;
use serde_json::json;

#[test]
fn a_single_authenticated_route_is_usable() {
    let root = tempfile::tempdir().unwrap();
    let mut config =
        WorkConfig::for_chain(ChainProfile::known(Chain::Devnet), root.path()).unwrap();
    config.chain = config
        .chain
        .with_validators(vec![" WSS://EXAMPLE.COM:443 ".into()])
        .unwrap();
    let config = config.validate().unwrap();
    assert_eq!(config.chain.validators(), ["wss://example.com/"]);
    assert_eq!(config.network().as_str(), "hellas-devnet-1");
    assert!(config.node_config(root.path().join("node"), None).is_ok());
}

#[test]
fn custom_light_profile_needs_no_execution_genesis_or_payload() {
    let root = tempfile::tempdir().unwrap();
    let mut trust = ChainProfile::known(Chain::Devnet).trust().clone();
    trust.network_id = "custom-light-1".into();
    let path = root.path().join("chain.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "consensus_digest": "12".repeat(32),
            "trust": trust,
            "validators": ["ws://127.0.0.1:9080"],
        }))
        .unwrap(),
    )
    .unwrap();
    let profile = load_chain_profile(&path).unwrap();
    assert!(!profile.has_execution());
    let config = WorkConfig::for_chain(profile, root.path()).unwrap();
    assert_eq!(config.network().as_str(), "custom-light-1");
    assert!(config.node_config(root.path().join("node"), None).is_err());
}

#[test]
fn custom_full_genesis_can_derive_h0_at_node_start() {
    use commonware_cryptography::{Hasher as _, Sha256};
    let root = tempfile::tempdir().unwrap();
    let mut genesis: hellas_chain::genesis::Genesis =
        serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_1_JSON).unwrap();
    genesis.network_id = "custom-execution-1".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = ChainProfile::known(Chain::Devnet).trust().clone();
    trust.network_id = genesis.network_id.clone();
    trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
    let profile = ChainProfile::custom(CustomChainFile {
        consensus_digest: hex::encode(hellas_chain::genesis_digest(&genesis).0),
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: Some(genesis_json),
        genesis_payload: None,
    })
    .unwrap();
    let node = WorkConfig::for_chain(profile, root.path())
        .unwrap()
        .node_config(root.path().join("node"), None)
        .unwrap();
    assert!(node.genesis_payload().is_none());
}

#[test]
fn a_registered_id_cannot_rebind_pins_but_can_change_routes() {
    let known = ChainProfile::known(Chain::Devnet);
    let changed_route = ChainProfile::custom(CustomChainFile {
        consensus_digest: hex::encode(known.consensus_digest()),
        trust: known.trust().clone(),
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: None,
        genesis_payload: None,
    })
    .unwrap();
    assert_eq!(changed_route.known_chain(), Some(Chain::Devnet));
    assert!(changed_route.has_execution());
    let error = ChainProfile::custom(CustomChainFile {
        consensus_digest: "00".repeat(32),
        trust: known.trust().clone(),
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: None,
        genesis_payload: None,
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("this binary is out of date for devnet; please update")
    );
}

#[test]
fn static_paid_client_refuses_an_expiring_threshold_key() {
    let root = tempfile::tempdir().unwrap();
    let known = ChainProfile::known(Chain::Devnet);
    let mut trust = known.trust().clone();
    trust.network_id = "custom-rotating-1".into();
    trust.epochs[0].end_height = Some(2);
    let mut next = trust.epochs[0].clone();
    next.epoch = 1;
    next.start_height = 2;
    next.end_height = None;
    trust.epochs.push(next);
    let profile = ChainProfile::custom(CustomChainFile {
        consensus_digest: hex::encode(known.consensus_digest()),
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: None,
        genesis_payload: None,
    })
    .unwrap();
    let error = WorkConfig::for_chain(profile, root.path()).unwrap_err();
    assert!(error.to_string().contains("one open trusted epoch"));
}
