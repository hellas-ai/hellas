use super::*;
use hellas_chain::genesis::Chain;
use hellas_private::StoreLocation;

#[test]
fn a_single_authenticated_route_is_usable() {
    let root = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(root.path());
    let mut config = WorkConfig::for_chain(ChainProfile::known(Chain::Devnet), &location).unwrap();
    config.chain = config
        .chain
        .with_validators(vec![" WSS://EXAMPLE.COM:443 ".into()])
        .unwrap();
    let config = config.validate().unwrap();
    assert_eq!(config.chain.validators(), ["wss://example.com/"]);
    assert_eq!(config.network().as_str(), "hellas-devnet-2");
    assert!(config.node_config(None).is_ok());
}

#[test]
fn custom_full_genesis_can_derive_h0_at_node_start() {
    use commonware_cryptography::{Hasher as _, Sha256};
    let root = tempfile::tempdir().unwrap();
    let mut genesis: hellas_chain::genesis::Genesis =
        serde_json::from_str(hellas_chain::genesis::HELLAS_DEVNET_2_JSON).unwrap();
    genesis.network_id = "custom-execution-1".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = ChainProfile::known(Chain::Devnet).trust().clone();
    trust.network_id = genesis.network_id.clone();
    trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
    let profile = ChainProfile::custom(CustomChainFile {
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json,
    })
    .unwrap();
    let location = StoreLocation::for_test(root.path());
    let node = WorkConfig::for_chain(profile, &location)
        .unwrap()
        .node_config(None)
        .unwrap();
    assert_eq!(node.genesis().network_id, "custom-execution-1");
}

#[test]
fn a_registered_id_cannot_rebind_pins_but_can_change_routes() {
    let known = ChainProfile::known(Chain::Devnet);
    let changed_route = ChainProfile::custom(CustomChainFile {
        trust: known.trust().clone(),
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: known.genesis_json().to_owned(),
    })
    .unwrap();
    assert_eq!(changed_route.known_chain(), Some(Chain::Devnet));
    let mut changed_genesis = known.genesis().clone();
    changed_genesis.allocations[0].balance += 1;
    let changed_json = serde_json::to_string(&changed_genesis).unwrap();
    let mut changed_trust = known.trust().clone();
    use commonware_cryptography::{Hasher as _, Sha256};
    changed_trust.genesis_sha256 = hex::encode(Sha256::hash(changed_json.as_bytes()));
    let error = ChainProfile::custom(CustomChainFile {
        trust: changed_trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json: changed_json,
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("this binary is out of date for devnet; please update")
    );
}

#[test]
fn paid_client_accepts_scheduled_keys_while_static_node_rejects_them() {
    let root = tempfile::tempdir().unwrap();
    let known = ChainProfile::known(Chain::Devnet);
    let mut genesis = known.genesis().clone();
    genesis.network_id = "custom-rotating-1".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = known.trust().clone();
    trust.network_id = "custom-rotating-1".into();
    use commonware_cryptography::{Hasher as _, Sha256};
    trust.genesis_sha256 = hex::encode(Sha256::hash(genesis_json.as_bytes()));
    trust.epochs[0].end_height = Some(2);
    let mut next = trust.epochs[0].clone();
    next.epoch = 1;
    next.start_height = 2;
    next.end_height = None;
    trust.epochs.push(next);
    let profile = ChainProfile::custom(CustomChainFile {
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
        genesis_json,
    })
    .unwrap();
    let location = StoreLocation::for_test(root.path());
    let config = WorkConfig::for_chain(profile, &location).unwrap();
    assert!(config.node_config(None).is_err());
    let error = config.threshold_identity().unwrap_err();
    assert!(error.to_string().contains("one open trusted epoch"));
}
