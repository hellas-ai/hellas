use super::*;
use hellas_private::StoreLocation;

#[test]
fn a_single_authenticated_route_is_usable() {
    let root = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(root.path());
    let mut config =
        WorkConfig::for_chain(hellas_genesis::test_support::profile(), &location).unwrap();
    config.chain = config
        .chain
        .with_validators(vec![" WSS://EXAMPLE.COM:443 ".into()])
        .unwrap();
    assert_eq!(config.chain.validators(), ["wss://example.com/"]);
    assert_eq!(config.network().as_str(), "test-network");
}

#[test]
fn paid_client_accepts_scheduled_keys_without_a_static_threshold() {
    let root = tempfile::tempdir().unwrap();
    let fixture = hellas_genesis::test_support::profile();
    let mut genesis = fixture.genesis().clone();
    genesis.network_id = "custom-rotating-1".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = fixture.trust().clone();
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
    let error = config.chain.static_threshold_identity().unwrap_err();
    assert!(error.to_string().contains("one open trusted epoch"));
}
