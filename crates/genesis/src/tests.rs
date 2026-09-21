use super::*;

fn fixture() -> Genesis {
    Genesis {
        schema_version: GENESIS_SCHEMA_VERSION,
        network_id: HELLAS_DEVNET_1_ID.to_string(),
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

/// The id constant and the document are two copies of one fact;
/// this is what keeps them from drifting apart.
/// Every shipped document must parse, validate, and declare the id
/// the registry claims for it. A registry entry that lies about its
/// own id would put a node on a network it did not ask for.
#[test]
fn every_known_network_document_declares_the_id_the_registry_claims() {
    assert!(!KNOWN_NETWORKS.is_empty());
    for network in KNOWN_NETWORKS {
        let genesis: Genesis = serde_json::from_str(network.json)
            .unwrap_or_else(|err| panic!("{} document parses: {err}", network.name));
        genesis
            .validate()
            .unwrap_or_else(|err| panic!("{} document validates: {err}", network.name));
        assert_eq!(genesis.network_id, network.id, "{}", network.name);
        assert_eq!(known_network(network.name), Some(network));
        assert_eq!(known_network(network.id), Some(network));
    }
    assert_eq!(known_network("mainnet"), None);
    assert_eq!(known_network(""), None);
}

/// No two shipped networks may share a name, an id, or — the one
/// that actually matters — a validator committee. Two networks with
/// the same committee are one network wearing two names, and every
/// separation argument above it is decoration.
#[test]
fn shipped_networks_share_no_name_id_committee_or_account() {
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();

    for network in KNOWN_NETWORKS {
        assert!(
            names.insert(network.name),
            "duplicate name {}",
            network.name
        );
        assert!(ids.insert(network.id), "duplicate id {}", network.id);

        let genesis: Genesis = serde_json::from_str(network.json).unwrap();
        for validator in &genesis.validators {
            assert!(
                keys.insert(validator.public_key.clone()),
                "{} reuses validator key {}",
                network.name,
                validator.public_key,
            );
        }
        for allocation in &genesis.allocations {
            assert!(
                addresses.insert(allocation.address.clone()),
                "{} reuses funded account {}",
                network.name,
                allocation.address,
            );
        }
    }
}

/// The shipped documents are pinned by their bytes, not by the
/// facts a parser can be talked into agreeing with. `include_str!`
/// takes a path, and a path is a thing that can be re-pointed by a
/// move, a symlink, or a directory rename — after which every
/// assertion above still passes while the committee has changed.
/// Two networks differing in one hex digit are two networks, and a
/// node that joined the wrong one has forked.
#[test]
fn shipped_documents_hash_to_the_bytes_that_were_reviewed() {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(HELLAS_DEVNET_1_JSON.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "6e5e8d2b35f62724380afd2735ff8677f503bfc0c008e7bc8935e9a1214099bb"
    );
}

#[test]
fn canonical_devnet_genesis_is_valid_and_matches_its_id_constant() {
    let genesis: Genesis = serde_json::from_str(HELLAS_DEVNET_1_JSON).unwrap();
    genesis.validate().unwrap();
    assert_eq!(genesis.network_id, HELLAS_DEVNET_1_ID);
    assert_eq!(genesis.validators.len(), 6);
    assert_eq!(genesis.allocations.len(), 3);
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

#[test]
fn rejects_duplicate_committee_identity_or_label() {
    let mut duplicate_key = fixture();
    duplicate_key.validators[1].public_key = duplicate_key.validators[0].public_key.clone();
    assert!(matches!(
        duplicate_key.validate(),
        Err(GenesisError::DuplicateValidatorKey(_))
    ));

    let mut duplicate_label = fixture();
    duplicate_label.validators[1].label = duplicate_label.validators[0].label.clone();
    assert!(matches!(
        duplicate_label.validate(),
        Err(GenesisError::DuplicateValidatorLabel(_))
    ));
}

#[test]
fn rejects_short_or_noncanonical_public_keys() {
    for key in ["11".repeat(31), "AA".repeat(32), "gg".repeat(32)] {
        let mut genesis = fixture();
        genesis.validators[0].public_key = key;
        assert_eq!(genesis.validate(), Err(GenesisError::InvalidValidatorKey));
    }
}
