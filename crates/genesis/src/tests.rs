use super::*;

fn fixture() -> Genesis {
    Genesis {
        schema_version: GENESIS_SCHEMA_VERSION,
        network_id: HELLAS_DEVNET_3_ID.to_string(),
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
    use sha2::{Digest as _, Sha256};

    assert!(!KNOWN_NETWORKS.is_empty());
    assert_eq!(Chain::default(), KNOWN_NETWORKS[0].chain);
    for network in KNOWN_NETWORKS {
        let genesis: Genesis = serde_json::from_str(network.json)
            .unwrap_or_else(|err| panic!("{} document parses: {err}", network.name));
        genesis
            .validate()
            .unwrap_or_else(|err| panic!("{} document validates: {err}", network.name));
        assert_eq!(genesis.network_id, network.id, "{}", network.name);
        let trust: TrustDocument = serde_json::from_str(network.trust_json).unwrap();
        trust.validate().unwrap();
        assert_eq!(trust.network_id, network.id, "{} trust id", network.name);
        assert_eq!(
            trust.genesis_sha256,
            hex::encode(Sha256::digest(network.json)),
            "{} trust must bind exact shipped genesis bytes",
            network.name
        );
        let mut routes = BTreeSet::new();
        assert!(!network.validators.is_empty());
        for route in network.validators {
            let parsed = url::Url::parse(route).unwrap();
            assert!(parsed.host_str().is_some() && matches!(parsed.scheme(), "ws" | "wss"));
            assert!(routes.insert(parsed.to_string()), "duplicate shipped route");
        }
        assert_eq!(network.chain.name(), network.name);
        assert_eq!(Chain::parse(network.name), Some(network.chain));
        assert_eq!(Chain::parse(network.id), Some(network.chain));
        assert_eq!(known_network(network.name), Some(network));
        assert_eq!(known_network(network.id), Some(network));
    }
    assert_eq!(known_network("mainnet"), None);
    assert_eq!(known_network("hellas-devnet-1"), None);
    assert_eq!(known_network(""), None);
    assert_eq!(Chain::parse("mainnet"), None);
}

/// No two shipped networks may share a name, an id, or — the one
/// that actually matters — a validator committee. Two networks with
/// the same committee are one network wearing two names, and every
/// separation argument above it is decoration.
#[test]
fn shipped_networks_share_no_name_id_committee_or_account() {
    let mut names = BTreeSet::new();
    let mut chains = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();

    for network in KNOWN_NETWORKS {
        assert!(
            chains.insert(network.chain),
            "duplicate compiled Chain selector"
        );
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

    let digest = Sha256::digest(HELLAS_DEVNET_3_JSON.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "e7d27dbc4744f08b3e8ca3c0656b698ca3bcaa0f1d184cacce8cb8af2711c3d1"
    );
}

#[test]
fn canonical_devnet_genesis_is_valid_and_matches_its_id_constant() {
    let genesis: Genesis = serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap();
    genesis.validate().unwrap();
    assert_eq!(genesis.network_id, HELLAS_DEVNET_3_ID);
    assert_eq!(genesis.validators.len(), 6);
    assert_eq!(genesis.allocations.len(), 103);
}

#[test]
fn every_public_faucet_account_has_exactly_931145_credits() {
    let genesis: Genesis = serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap();
    let accounts: Vec<FaucetAccount> = serde_json::from_str(HELLAS_DEVNET_3_FAUCET_JSON).unwrap();
    assert_eq!(accounts.len(), 100);
    let mut addresses = BTreeSet::new();
    for (index, account) in accounts.iter().enumerate() {
        assert_eq!(usize::from(account.index), index);
        assert!(addresses.insert(&account.address));
        assert_eq!(account.secret_scalar.len(), 64);
        assert!(
            account
                .secret_scalar
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let allocation = genesis
            .allocations
            .iter()
            .find(|a| a.address == account.address)
            .expect("each published account is funded in the shipped genesis");
        assert_eq!(allocation.balance, 931_145, "faucet account {index}");
    }
    genesis.validate().unwrap();
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
