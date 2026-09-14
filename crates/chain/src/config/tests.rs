use super::*;
use crate::domain::{SettlementKey, addr_from_signing_key, secp256r1_key_from_seed};
use hellas_kernel::Secp256k1Signer;

fn secp256k1_key_from_scalar(scalar: u8) -> SettlementKey {
    let mut secret = [0_u8; 32];
    secret[31] = scalar;
    SettlementKey::from(
        Secp256k1Signer::from_secret_scalar(secret)
            .expect("small non-zero scalar")
            .party_key(),
    )
}

fn config_with_genesis(address: String) -> ValidatorConfig {
    let private_key = ed25519::PrivateKey::from_seed(1);
    let public_key = hex::encode(private_key.public_key().encode());
    ValidatorConfig {
        private_key: encode_private_key(&private_key),
        threshold_share: String::new(),
        threshold_polynomial: String::new(),
        listen_port: 0,
        metrics_port: None,
        light_client_bind: None,
        relay_urls: Vec::new(),
        genesis: Genesis {
            schema_version: crate::genesis::GENESIS_SCHEMA_VERSION,
            network_id: crate::genesis::HELLAS_DEVNET_1_ID.to_string(),
            validators: vec![GenesisValidator {
                public_key,
                label: "validator-0".to_string(),
            }],
            allocations: vec![GenesisEntry {
                address,
                balance: 10,
            }],
        },
        peers: Vec::new(),
    }
}

#[cfg(feature = "validator")]
#[test]
fn an_omitted_light_client_bind_keeps_the_listener_off() {
    let config = config_with_genesis("owner".to_string());
    let rendered = toml::to_string(&config).expect("serialize validator config");
    assert!(!rendered.contains("light_client_bind"));

    let loaded: ValidatorConfig =
        toml::from_str(&rendered).expect("load a config written before any bind was asked for");
    assert!(loaded.light_client_bind.is_none());
}

#[cfg(feature = "validator")]
#[test]
fn a_light_client_bind_is_an_address_by_parse_and_not_by_spelling() {
    let mut config = config_with_genesis("owner".to_string());
    let bind = SocketAddr::from(([0, 0, 0, 0], 31_246));
    config.light_client_bind = Some(bind);
    let rendered = toml::to_string(&config).expect("serialize validator config");
    assert!(
        rendered.contains("light_client_bind = \"0.0.0.0:31246\""),
        "{rendered}"
    );

    let loaded: ValidatorConfig = toml::from_str(&rendered).expect("load configured bind");
    assert_eq!(loaded.light_client_bind, Some(bind));
    // The gateway refuses a non-loopback bind because its routes reach
    // the executor. This one answers what a relay already publishes, so
    // an exposed address is accepted rather than refused.
    assert!(!loaded.light_client_bind.unwrap().ip().is_loopback());

    // Loopback is a property of the parsed address, not of how it is
    // written: `127.0.0.2` is loopback and is not the string
    // `127.0.0.1`.
    let quiet: ValidatorConfig =
        toml::from_str(&rendered.replace("0.0.0.0:31246", "127.0.0.2:31246"))
            .expect("load a loopback bind spelled another way");
    assert!(quiet.light_client_bind.unwrap().ip().is_loopback());

    // A host name is not an address. It is refused at load rather than
    // carried as a string for something later to match on.
    assert!(
        toml::from_str::<ValidatorConfig>(&rendered.replace("0.0.0.0:31246", "localhost:31246"))
            .is_err(),
        "a host name is not a bind address",
    );
}

#[test]
fn genesis_parser_rejects_bytes_valid_on_neither_curve() {
    let entry = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]).to_string();
    let err = parse_genesis_settlement_key(&entry).expect_err("invalid point encoding");
    assert!(matches!(
        err,
        ConfigError::InvalidGenesisSettlementPoint { entry: actual } if actual == entry
    ));
}

#[test]
fn genesis_parser_accepts_a_valid_p256_point() {
    let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
    let key = SettlementKey::from(address);
    assert_eq!(
        parse_genesis_settlement_key(&key.to_string()).expect("valid P-256 genesis owner"),
        key
    );
}

#[test]
fn genesis_parser_accepts_a_valid_secp256k1_point() {
    let key = secp256k1_key_from_scalar(2);
    assert_eq!(
        parse_genesis_settlement_key(&key.to_string()).expect("valid secp256k1 genesis owner"),
        key
    );
}

#[test]
fn genesis_parser_accepts_secp256k1_scalar_3() {
    let key = secp256k1_key_from_scalar(3);
    assert!(
        UserAddress::try_from(key).is_err(),
        "scalar 3 must remain the vector that a P-256-only parser rejects"
    );
    assert_eq!(
        parse_genesis_settlement_key(&key.to_string()).expect("secp256k1 scalar 3 genesis owner"),
        key
    );
}

#[test]
fn genesis_parser_accepts_secp256k1_scalar_4() {
    let key = secp256k1_key_from_scalar(4);
    assert!(
        UserAddress::try_from(key).is_ok(),
        "scalar 4 must remain the old accidental cross-curve pass"
    );
    assert_eq!(
        parse_genesis_settlement_key(&key.to_string()).expect("secp256k1 scalar 4 genesis owner"),
        key
    );
}

#[test]
fn genesis_committee_must_include_local_identity() {
    let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
    let mut config = config_with_genesis(SettlementKey::from(address).to_string());
    let other = ed25519::PrivateKey::from_seed(2);
    config.genesis.validators[0].public_key = hex::encode(other.public_key().encode());

    assert!(matches!(
        config.participants(),
        Err(ConfigError::MissingLocalValidator)
    ));
}

#[test]
fn peer_topology_must_cover_exact_genesis_committee() {
    let address = addr_from_signing_key(&secp256r1_key_from_seed(7));
    let mut config = config_with_genesis(SettlementKey::from(address).to_string());
    let other = ed25519::PrivateKey::from_seed(2);
    config.genesis.validators.push(GenesisValidator {
        public_key: hex::encode(other.public_key().encode()),
        label: "validator-1".to_string(),
    });

    assert!(matches!(
        config.peer_address_map(),
        Err(ConfigError::PeerSetMismatch)
    ));
}

#[test]
fn any_valid_genesis_network_id_is_accepted_and_carried() {
    let address =
        SettlementKey::from(addr_from_signing_key(&secp256r1_key_from_seed(7))).to_string();
    for id in ["hellas-devnet-1", "another-network", "someone-elses-net"] {
        let mut config = config_with_genesis(address.clone());
        config.genesis.network_id = id.to_string();

        config.validate_genesis().expect("a valid genesis is valid");
        assert_eq!(
            config.network_id().expect("id fits").as_str(),
            id,
            "the configured network must be the one the node signs under",
        );
    }
}
