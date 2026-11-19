use super::*;

#[test]
fn compiled_networks_have_distinct_identities_and_bound_documents() {
    use sha2::{Digest as _, Sha256};
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut validators = BTreeSet::new();
    let mut accounts = BTreeSet::new();
    for &network in Network::ALL {
        let data = network.network();
        let profile = ChainProfile::known(network);
        profile.genesis().validate().unwrap();
        profile.trust().validate().unwrap();
        assert!(names.insert(network.name()));
        assert!(ids.insert(data.id()));
        assert_eq!(profile.genesis_json(), data.json);
        assert_eq!(profile.network_id(), profile.genesis().network_id);
        assert_eq!(
            profile.trust().genesis_sha256,
            hex::encode(Sha256::digest(data.json))
        );
        for selector in [network.name(), &data.id()] {
            assert_eq!(Network::parse(selector), Some(network));
            assert_eq!(known_network(selector), Some(data));
        }
        assert!(profile.known_genesis_payload_pin().is_some());
        let rebound = ChainProfile::custom(profile.to_file()).unwrap();
        assert_eq!(rebound.known_chain(), Some(network));
        assert_eq!(rebound.state_key(), profile.state_key());
        for validator in &profile.genesis().validators {
            assert!(validators.insert(validator.public_key.clone()));
        }
        for allocation in &profile.genesis().allocations {
            assert!(accounts.insert(allocation.address.clone()));
        }
    }
    assert_eq!(
        known_network_names().into_iter().collect::<BTreeSet<_>>(),
        names
    );
    assert_eq!(Network::parse("unknown-network"), None);
}

fn fixture() -> Genesis {
    Genesis {
        schema_version: GENESIS_SCHEMA_VERSION,
        network_id: "test-network".to_string(),
        validators: vec![
            GenesisValidator {
                public_key: "11".repeat(32),
                label: "validator-a".to_string(),
            },
            GenesisValidator {
                public_key: "22".repeat(32),
                label: "validator-b".to_string(),
            },
        ],
        allocations: vec![GenesisAllocation {
            address: "example-address".to_string(),
            balance: 100,
        }],
    }
}

#[test]
fn json_and_toml_round_trip_the_same_document() {
    let genesis = fixture();
    genesis.validate().unwrap();

    let json = serde_json::to_string(&genesis).unwrap();
    let from_json: Genesis = serde_json::from_str(&json).unwrap();
    let toml = toml::to_string(&genesis).unwrap();
    let from_toml: Genesis = toml::from_str(&toml).unwrap();

    assert_eq!(from_json, genesis);
    assert_eq!(from_toml, genesis);
}

/// A refusal case: what is wrong, how to break the fixture, the error.
type Malformed = (&'static str, fn(&mut Genesis), GenesisError);

/// A custom chain file is untrusted input: every malformed document is
/// refused with the error that names what is wrong with it.
#[test]
fn validate_refuses_each_malformed_document() {
    let cases: &[Malformed] = &[
        (
            "future schema",
            |g| g.schema_version = 2,
            GenesisError::UnsupportedSchema(2),
        ),
        (
            "empty network id",
            |g| g.network_id.clear(),
            GenesisError::InvalidNetworkId,
        ),
        (
            "uppercase network id",
            |g| g.network_id = "Hellas-1".into(),
            GenesisError::InvalidNetworkId,
        ),
        (
            "network id with a space",
            |g| g.network_id = "hellas 1".into(),
            GenesisError::InvalidNetworkId,
        ),
        (
            "64-byte network id",
            |g| g.network_id = "a".repeat(64),
            GenesisError::InvalidNetworkId,
        ),
        (
            "no validators",
            |g| g.validators.clear(),
            GenesisError::EmptyCommittee,
        ),
        (
            "31-byte key",
            |g| g.validators[0].public_key = "11".repeat(31),
            GenesisError::InvalidValidatorKey,
        ),
        (
            "uppercase key",
            |g| g.validators[0].public_key = "AA".repeat(32),
            GenesisError::InvalidValidatorKey,
        ),
        (
            "non-hex key",
            |g| g.validators[0].public_key = "gg".repeat(32),
            GenesisError::InvalidValidatorKey,
        ),
        (
            "duplicate key",
            |g| g.validators[1].public_key = "11".repeat(32),
            GenesisError::DuplicateValidatorKey("11".repeat(32)),
        ),
        (
            "empty label",
            |g| g.validators[0].label.clear(),
            GenesisError::InvalidValidatorLabel,
        ),
        (
            "uppercase label",
            |g| g.validators[0].label = "Validator-a".into(),
            GenesisError::InvalidValidatorLabel,
        ),
        (
            "64-byte label",
            |g| g.validators[0].label = "a".repeat(64),
            GenesisError::InvalidValidatorLabel,
        ),
        (
            "duplicate label",
            |g| g.validators[1].label = "validator-a".into(),
            GenesisError::DuplicateValidatorLabel("validator-a".into()),
        ),
        (
            "empty allocation address",
            |g| g.allocations[0].address.clear(),
            GenesisError::EmptyAllocationAddress,
        ),
        (
            "duplicate allocation address",
            |g| g.allocations.push(g.allocations[0].clone()),
            GenesisError::DuplicateAllocationAddress("example-address".into()),
        ),
    ];
    for (name, corrupt, expected) in cases {
        let mut genesis = fixture();
        corrupt(&mut genesis);
        assert_eq!(genesis.validate().as_ref(), Err(expected), "{name}");
    }
}
