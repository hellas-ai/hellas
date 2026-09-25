use super::*;
use hellas_kernel::{EdgeValues, Fees, Key, NetworkId};
use hellas_rpc::peers::PeerId;
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::*;
use hellas_rpc::protocol::work_profile::PaidWorkPolicy;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use std::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};
type CliResult<T> = anyhow::Result<T>;

#[test]
fn fetch_policy_loads_and_cannot_be_combined_with_evaluate() {
    let mut value = config();
    value["policies"]["fetch"] = serde_json::json!({
        "allowed_environment": hex32(0x11),
        "service": "openai", "method": "responses",
        "max_request_body_bytes": 4096, "max_output_events": 64,
        "max_output_bytes": 16384, "max_spool_bytes": 65536,
        "max_encoded_result_frame": 65536, "max_encoded_prepared_input": 65536,
        "dispatch_margin_blocks": 4, "delivery_margin_blocks": 2,
        "oracle_grace_blocks": 6, "fixed_price": 10,
    });
    assert!(load(value.clone()).is_err());
    value["policies"]
        .as_object_mut()
        .unwrap()
        .remove("execution");
    let loaded = load(value.clone()).unwrap();
    assert!(matches!(
        loaded.execution_policy,
        PaidWorkPolicy::Fetch { .. }
    ));
    assert_eq!(
        PaidWorkPolicy::decode(&loaded.execution_policy.encode()).unwrap(),
        loaded.execution_policy
    );
    value["policies"].as_object_mut().unwrap().remove("fetch");
    assert!(load(value).is_err());
}

fn hex32(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn route(peer: u8, bond: u8, client: u8) -> serde_json::Value {
    serde_json::json!({
        "peer": hex32(peer),
        "bond": hex32(bond),
        "client": hex::encode([client; 33]),
    })
}

fn validators() -> Vec<serde_json::Value> {
    (1..=VALIDATOR_COUNT)
        .map(|index| serde_json::Value::String(format!("http://127.0.0.1:900{index}")))
        .collect()
}

/// A threshold identity the consensus verifier accepts.
///
/// The BLS12-381 G1 generator, compressed: a real point in the real
/// subgroup, so what this fixture proves is that the loader runs
/// consensus's own decoder rather than a length check wearing its
/// name.
fn threshold_identity() -> String {
    hex::encode(THRESHOLD_IDENTITY)
}

const THRESHOLD_IDENTITY: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];

fn config() -> serde_json::Value {
    serde_json::json!({
        "chain": {
            "network_id": "hellas-devnet",
            "genesis_payload_digest": hex32(0x01),
            "threshold_identity": threshold_identity(),
        },
        "validators": validators(),
        "journal": {
            "root": "/var/lib/hellas/work",
        },
        "routes": [route(0x31, 0x41, 0x02)],
        "policies": {
            "policy_salt": hex32(0x5a),
            "channel": {
                "compute_credit_limit": 40,
                "delivery_credit_limit": 40,
            },
            "execution": {
                "allowed_environment": hex32(0x11),
                "generation_policy_digest": hex32(0x12),
                "identity_source_digest": hex32(0x13),
                "max_prompt_tokens": 512,
                "max_new_tokens": 128,
                "max_stop_token_ids": 4,
                "max_spool_bytes": 1_048_576_u64,
                "max_encoded_result_frame": 262_144,
                "max_encoded_quote_response": 1_048_576_u64,
                "dispatch_margin_blocks": 4,
                "delivery_margin_blocks": 2,
                "oracle_grace_blocks": 6,
                "fixed_price": 10,
            },
        },
        "poll_ms": 250,
        "expected_payment_values": {
            "value": PAYMENT_VALUE,
            "reserve": PAYMENT_RESERVE,
            "close_fees": { "base": 0, "slot": 0, "proof": 0, "lifetime": 0 },
        },
        "min_omit_response_blocks": hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    })
}

fn write(dir: &tempfile::TempDir, value: &serde_json::Value) -> PathBuf {
    let path = dir.path().join("work-config.json");
    fs::write(&path, value.to_string()).unwrap();
    path
}

fn load(value: serde_json::Value) -> CliResult<WorkConfig> {
    let dir = tempfile::tempdir().unwrap();
    Ok(load_work_config(&write(&dir, &value))?)
}

/// Delete `field` from the object at `path`.
fn without(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
    let mut cursor = &mut value;
    for step in path {
        cursor = cursor.get_mut(step).unwrap();
    }
    cursor.as_object_mut().unwrap().remove(field).unwrap();
    value
}

fn with(mut value: serde_json::Value, field: &str, entry: serde_json::Value) -> serde_json::Value {
    value
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), entry);
    value
}

#[test]
fn a_work_config_round_trips_from_a_file() {
    let loaded = load(config()).expect("the fixture config loads");

    assert_eq!(loaded.chain.network.as_str(), "hellas-devnet");
    assert_eq!(
        loaded.chain.genesis_payload_digest,
        Digest::from_bytes([0x01; 32]),
    );
    assert_eq!(loaded.chain.threshold_identity, THRESHOLD_IDENTITY.to_vec());
    assert_eq!(loaded.validators.len(), VALIDATOR_COUNT);
    assert_eq!(loaded.journal_root, PathBuf::from("/var/lib/hellas/work"));
    let peer = PeerId::from_bytes([0x31; 32]);
    let route = loaded
        .routes
        .iter()
        .find(|route| route.peer == peer)
        .expect("the bilateral route is loaded under its peer");
    assert_eq!(route.bond, EdgeId::from_bytes([0x41; EdgeId::LENGTH]));
    assert_eq!(route.client, Key::from_bytes([0x02; Key::LENGTH]));
    assert_eq!(loaded.policy_salt, [0x5a; 32]);
    assert_eq!(loaded.channel_policy.compute_credit_limit, 40);
    assert_eq!(loaded.execution_policy.fixed_price(), 10);
    assert_eq!(
        match loaded.execution_policy {
            PaidWorkPolicy::Evaluate(policy) => policy.max_stop_token_ids,
            _ => panic!("expected Evaluate policy"),
        },
        4
    );
    assert_eq!(loaded.poll, Duration::from_millis(250));
    assert_eq!(
        loaded.expected_payment_values,
        EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
    );
    assert_eq!(
        loaded.min_omit_response_blocks,
        hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS
    );
}

#[test]
fn two_routes_cannot_name_the_same_peer() {
    let routes = serde_json::json!([route(0x31, 0x41, 0x02), route(0x31, 0x42, 0x03),]);
    let error = format!(
        "{:?}",
        load(with(config(), "routes", routes))
            .expect_err("one authenticated peer cannot resolve to two routes"),
    );
    assert!(
        error.contains("names peer") && error.contains("twice"),
        "unexpected error: {error}",
    );
}

#[test]
fn two_routes_cannot_name_the_same_bond() {
    let routes = serde_json::json!([route(0x31, 0x41, 0x02), route(0x32, 0x41, 0x03),]);
    let error = format!(
        "{:?}",
        load(with(config(), "routes", routes))
            .expect_err("one provider journal cannot resolve from two peers"),
    );
    assert!(
        error.contains("names bond") && error.contains("twice"),
        "unexpected error: {error}",
    );
}

/// Every required field is required, and the refusal names it.
#[test]
fn a_missing_field_is_refused_by_name() {
    for (path, field) in [
        (&[][..], "poll_ms"),
        (&[][..], "min_omit_response_blocks"),
        (&[][..], "expected_payment_values"),
        (&["expected_payment_values"][..], "reserve"),
        (&["expected_payment_values", "close_fees"][..], "lifetime"),
        (&[][..], "validators"),
        (&[][..], "routes"),
        (&["chain"][..], "threshold_identity"),
        (&["chain"][..], "genesis_payload_digest"),
        (&["journal"][..], "root"),
        (&["policies"][..], "policy_salt"),
        (&["policies", "execution"][..], "fixed_price"),
    ] {
        let error = format!(
            "{:?}",
            load(without(config(), path, field))
                .expect_err("a config missing a required field is refused"),
        );
        assert!(
            error.contains(field),
            "the refusal for a missing {field} does not name it: {error}",
        );
    }
}

/// The two fields that were deleted from the design cannot be
/// configured back into existence.
#[test]
fn a_deleted_field_is_refused_by_name() {
    for field in ["start_validity_blocks", "mutual_margin_blocks"] {
        let error = format!(
            "{:?}",
            load(with(config(), field, serde_json::json!(64))).unwrap_err(),
        );
        assert!(
            error.contains(field),
            "the refusal for {field} does not name it: {error}",
        );
    }
}

/// The three journal caps the journal fixes for itself cannot be
/// configured back into existence.
///
/// [`MAX_ACTIVE_JOURNAL_BYTES`], [`MAX_ACTIVE_FRAMES`] and
/// [`MAX_CHECKPOINT_BYTES`] are constants the journal enforces on
/// itself. A file still naming them is an operator writing 128 MiB
/// and getting 64 with nothing said, so the loader refuses it by the
/// name they wrote.
///
/// [`MAX_ACTIVE_JOURNAL_BYTES`]: hellas_work::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES
/// [`MAX_ACTIVE_FRAMES`]: hellas_work::work_store::journal::MAX_ACTIVE_FRAMES
/// [`MAX_CHECKPOINT_BYTES`]: hellas_work::work_store::journal::MAX_CHECKPOINT_BYTES
#[test]
fn a_journal_cap_the_journal_fixes_is_refused_by_name() {
    for field in [
        "max_active_bytes",
        "max_active_frames",
        "max_checkpoint_bytes",
    ] {
        let error = format!(
            "{:?}",
            load(with_unknown(config(), &["journal"], field))
                .expect_err("a cap the journal fixes is not an operator's to set"),
        );
        assert!(
            error.contains(field),
            "the refusal for {field} does not name it: {error}",
        );
    }
}

#[test]
fn a_fan_out_is_exactly_six_distinct_validators() {
    let five = validators()[..5].to_vec();
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(five))).unwrap_err(),
    );
    assert!(error.contains("exactly 6"), "unexpected error: {error}");

    let mut duplicated = validators();
    duplicated[5] = duplicated[0].clone();
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(duplicated))).unwrap_err(),
    );
    assert!(error.contains("twice"), "unexpected error: {error}");
}

/// A validator entry has to be an address, not merely a string.
///
/// `"not a URL"` is trimmed, non-empty, and distinct from the other
/// five, which is all the loader used to ask. It is also nothing this
/// node can ever fan a write to, and the first symptom of that would
/// be one validator out of six that never answers.
#[test]
fn a_validator_that_is_not_a_url_is_refused() {
    let mut malformed = validators();
    malformed[3] = serde_json::Value::String("not a URL".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(malformed))).unwrap_err(),
    );
    assert!(error.contains("not a URL"), "unexpected error: {error}");

    // A URL with no host parses and is still not a validator.
    let mut hostless = validators();
    hostless[0] = serde_json::Value::String("mailto:ops@example.com".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(hostless))).unwrap_err(),
    );
    assert!(error.contains("no host"), "unexpected error: {error}");
}

/// Two spellings of one address are one validator, not two.
///
/// Distinctness is a question about addresses. `HTTP://127.0.0.1:9001`
/// and `http://127.0.0.1:9001/` differ as strings and name the same
/// node, so a string comparison would accept a fan-out to five.
#[test]
fn a_validator_named_twice_in_two_spellings_is_refused() {
    let mut spelled = validators();
    spelled[5] = serde_json::Value::String("HTTP://127.0.0.1:9001".to_string());
    let error = format!(
        "{:?}",
        load(with(config(), "validators", serde_json::json!(spelled))).unwrap_err(),
    );
    assert!(error.contains("twice"), "unexpected error: {error}");
}

/// The loaded list is the normalised one, because that is what gets
/// dialled and what was compared.
#[test]
fn validators_are_loaded_normalised() {
    let loaded = load(config()).expect("the fixture config loads");
    assert_eq!(
        loaded.validators[0], "http://127.0.0.1:9001/",
        "the parsed URL, not the string the operator typed",
    );
}

/// A zero execution-policy field is refused at load, by the
/// protocol's own check.
///
/// Every one of these is a value both parties sign, and each zero is
/// an absent bound rather than a small one. Copying them through
/// unchecked moves the refusal to the first admission, with a
/// counterparty already waiting.
#[test]
fn a_zero_execution_policy_field_is_refused() {
    for field in [
        "fixed_price",
        "max_prompt_tokens",
        "max_new_tokens",
        "max_spool_bytes",
        "max_encoded_result_frame",
        "max_encoded_quote_response",
        "dispatch_margin_blocks",
        "delivery_margin_blocks",
        "oracle_grace_blocks",
    ] {
        let mut value = config();
        value["policies"]["execution"][field] = serde_json::json!(0);
        let Err(refusal) = load(value) else {
            panic!("a zero {field} loaded");
        };
        let error = format!("{refusal:?}");
        assert!(
            error.contains(field),
            "the refusal for a zero {field} does not name it: {error}",
        );
    }

    // The one bound that may be zero: a channel admitting no stop
    // tokens is a channel whose jobs run to `max_new_tokens`.
    let mut value = config();
    value["policies"]["execution"]["max_stop_token_ids"] = serde_json::json!(0);
    let loaded = load(value).expect("no stop tokens is a usable channel");
    assert_eq!(
        match loaded.execution_policy {
            PaidWorkPolicy::Evaluate(policy) => policy.max_stop_token_ids,
            _ => panic!("expected Evaluate policy"),
        },
        0
    );
}

#[test]
fn a_threshold_identity_consensus_cannot_decode_is_refused() {
    // A prefix of a real identity: hexadecimal, non-empty, and not a
    // point. A length check wearing consensus's name would take it.
    let mut broken = THRESHOLD_IDENTITY.to_vec();
    broken.truncate(32);
    let chain = serde_json::json!({
        "network_id": "hellas-devnet",
        "genesis_payload_digest": hex32(0x01),
        "threshold_identity": hex::encode(&broken),
    });
    let error = format!("{:?}", load(with(config(), "chain", chain)).unwrap_err());
    assert!(
        error.contains("threshold_identity"),
        "unexpected error: {error}",
    );
}

#[test]
fn a_watcher_that_never_polls_is_refused() {
    let error = format!(
        "{:?}",
        load(with(config(), "poll_ms", serde_json::json!(0))).unwrap_err(),
    );
    assert!(error.contains("poll_ms"), "unexpected error: {error}");
}

// ── The provider policy and its journals ─────────────────────────

use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Parties,
    Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::protocol::work::private_policy_commitment;
use hellas_rpc::protocol::work_setup::WorkSetupError;
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint};
use hellas_work::work_store::{Role, SetupScan, SetupStore};

/// The window the fixture's terms admit.
const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS + 4;
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-devnet") else {
        panic!("the fixture configuration's network id is one");
    };
    network
}

/// Inserts `field` into the object at `path`, which the schema does
/// not define.
fn with_unknown(mut value: serde_json::Value, path: &[&str], field: &str) -> serde_json::Value {
    let mut cursor = &mut value;
    for step in path {
        cursor = cursor.get_mut(step).unwrap();
    }
    cursor
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), serde_json::json!(1));
    value
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn bond_terms() -> WorkStakeBondTerms {
    bond_terms_staked_by(&signer(0x22))
}

/// The same bond, staked by whichever key this node settles with.
///
/// A provider signs its own bond, so the staking party is not a
/// fixture constant when the key comes from an identity file.
fn bond_terms_staked_by(provider: &Secp256k1Signer) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider.party_key(), signer(0x21).party_key()),
        timeout: BlockHeight::new(500),
        timeout_outputs: List::take([Payout::new(provider.party_key(), 64); MAX_EDGE_OUTPUTS], 1),
        max_job_price: 40,
    }
}

/// The provider's stake funding: its own coins, none of the
/// client's.
fn bond_funding() -> Funding {
    Funding::new(coins(&[0xa1]), coins(&[]))
}

/// The edge the bond opens at, which is also the key the setup
/// journal is opened under.
fn bond_edge() -> EdgeId {
    Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
}

/// The terms a client proposes over that bond.
///
/// The commitment is opened against the *configuration's* own salt
/// and credit policy, because that is what a provider's admission
/// re-derives: terms committing to any other policy are refused
/// rather than countersigned. The Start span is the profile's fixed
/// maximum, so tests aimed at later admission gates reach them.
fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(
            network(),
            &[0x5a; 32],
            &PaidChannelPolicyV1 {
                compute_credit_limit: 40,
                delivery_credit_limit: 40,
            },
        ),
        omit_response_blocks: WINDOW,
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
        omission_bond: OMISSION_BOND,
    }
}

fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0xc0; EdgeId::LENGTH])
}

/// Opens a provider's setup journal under its own directory, with
/// its immutable history floor armed.
///
/// The floor is armed here because a provider's own first revision
/// is refused without one: recovery arming is not a step evidence
/// gates, it is the step every later one is refused before.
fn setup_endpoint(dir: &tempfile::TempDir, admission: PaymentAdmission) -> SetupEndpoint {
    let store = match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    };
    let mut endpoint = SetupEndpoint::new(store, signer(0x22), admission);
    if let Err(error) = endpoint.arm_scan(SetupScan {
        height: 7,
        payload: [0x47; 32],
    }) {
        panic!("the fixture arms its immutable history floor: {error}");
    }
    endpoint
}

/// The policy the fixture configuration makes.
fn policy() -> ProviderChannelPolicy {
    load(config())
        .expect("the fixture configuration loads")
        .provider_policy()
}

fn admits() -> PaymentAdmission {
    PaymentAdmission::Admits(Box::new(policy()))
}

fn write_provider_offer(dir: &tempfile::TempDir) {
    let mut endpoint = setup_endpoint(dir, admits());
    endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect("the provider offer is durable");
}

fn config_for_route(root: &Path, client: Key) -> WorkConfig {
    load(with(
        with(
            config(),
            "journal",
            serde_json::json!({ "root": root.display().to_string() }),
        ),
        "routes",
        serde_json::json!([{
            "peer": hex32(0x51),
            "bond": hex::encode(bond_edge().to_bytes()),
            "client": hex::encode(client.to_bytes()),
        }]),
    ))
    .expect("the route fixture configuration loads")
}

#[test]
fn a_route_loads_and_verifies_its_journals_client_taker() {
    let dir = tempfile::tempdir().unwrap();
    write_provider_offer(&dir);
    let loaded = config_for_route(dir.path(), signer(0x21).party_key());

    validate_work_routes(&loaded).expect("the route and its provider journal name the same client");
    assert_eq!(loaded.routes.len(), 1);
}

#[test]
fn a_route_is_refused_when_its_journal_names_another_client_taker() {
    let dir = tempfile::tempdir().unwrap();
    write_provider_offer(&dir);
    let expected = signer(0x23).party_key();
    let journal_client = signer(0x21).party_key();
    let loaded = config_for_route(dir.path(), expected);

    let error = format!(
        "{:#}",
        validate_work_routes(&loaded)
            .expect_err("the configured client must be the bond terms' taker"),
    );
    assert!(
        error.contains(&hex::encode(expected.to_bytes()))
            && error.contains(&hex::encode(journal_client.to_bytes()))
            && error.contains("taker"),
        "unexpected error: {error}",
    );
}

#[test]
fn a_route_is_refused_when_its_journal_is_not_under_the_configured_root() {
    let elsewhere = tempfile::tempdir().unwrap();
    write_provider_offer(&elsewhere);
    let configured = tempfile::tempdir().unwrap();
    let loaded = config_for_route(configured.path(), signer(0x21).party_key());

    let error = format!(
        "{:#}",
        validate_work_routes(&loaded)
            .expect_err("a route cannot reach a journal outside journal.root"),
    );
    assert!(
        error.contains("not under journal.root")
            && error.contains(&configured.path().display().to_string()),
        "unexpected error: {error}",
    );
}

/// Every field of the policy is one the operator wrote, and arrives
/// as written.
#[test]
fn a_configuration_makes_its_policy_field_for_field() {
    let policy = policy();
    assert_eq!(policy.network, network());
    assert_eq!(policy.policy_salt, [0x5a; 32]);
    assert_eq!(policy.channel_policy.compute_credit_limit, 40);
    assert_eq!(policy.execution_policy.fixed_price(), 10);
    assert_eq!(
        policy.expected_payment_values,
        EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0)),
    );
    assert_eq!(
        policy.min_omit_response_blocks,
        hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS
    );
}

/// The configured window is the provider's own gate at admission:
/// terms under it are refused by name, and the same terms clear a
/// configuration that asks for less.
#[test]
fn terms_under_the_configured_window_are_refused_at_admission() {
    let strict = load(with(
        config(),
        "min_omit_response_blocks",
        serde_json::json!(WINDOW + 1),
    ))
    .expect("a stricter window is a configuration")
    .provider_policy();
    assert_eq!(
        strict
            .admit(payment_edge(), payment_terms())
            .map(|descriptor| descriptor.channel().payment_edge()),
        Err(WorkSetupError::ResponseWindowBelowMinimum {
            window: WINDOW,
            minimum: WINDOW + 1,
        }),
    );
    assert!(policy().admit(payment_edge(), payment_terms()).is_ok());
}

/// A window the kernel would refuse at every open is refused when the
/// file is read, not at the first client.
#[test]
fn a_window_under_the_kernels_minimum_is_refused_by_the_loader() {
    let error = format!(
        "{:?}",
        load(with(
            config(),
            "min_omit_response_blocks",
            serde_json::json!(hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS - 1),
        ))
        .expect_err("a window under the kernel's minimum is refused"),
    );
    assert!(
        error.contains("min_omit_response_blocks"),
        "unexpected error: {error}",
    );
}

/// A `ProviderChannelPolicy` is built from a configuration, and a
/// `SetupEndpoint` over that — which is the pair nothing in this crate
/// could construct at all.
#[test]
fn a_setup_endpoint_is_built_from_the_loaded_policy() {
    let dir = tempfile::tempdir().unwrap();
    let mut endpoint = setup_endpoint(&dir, admits());

    assert!(endpoint.state().revision().is_none());
    let state = endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect("the endpoint signs and journals its bond proposal");

    assert_eq!(state.revision(), Some(1));
}

/// A restarted node rebuilds the endpoint from what serve holds: the
/// configured journal root, the stored identity, and the journals
/// themselves.
///
/// This is the whole of the gap. `SetupStore::open` is keyed by a
/// bond edge and a role, and a `SetupEndpoint` needs a settlement
/// key: the configuration below carries none of the three, the bond
/// edge is recovered from the file, the role from its header, and
/// the key from the identity `identity init` wrote. Re-proposing the
/// retained bond is what proves the rebuilt endpoint is the one that
/// wrote the journal — a different key signs different bytes, and
/// the journal refuses a revision that rewrites the one it holds.
#[test]
fn a_restarted_node_rebuilds_its_endpoint_from_the_root_and_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("work-journals");
    let loaded = load(with(
        config(),
        "journal",
        serde_json::json!({ "root": root.display().to_string() }),
    ))
    .expect("the fixture configuration loads");
    let admission = PaymentAdmission::Admits(Box::new(loaded.provider_policy()));

    // The identity `identity init` wrote, and the key it settles
    // with. Nothing in the configuration above names either.
    let identity_path = dir.path().join("identity");
    let identity = crate::identity::load_or_create(Some(&identity_path))
        .expect("the operator's identity is created once");
    let settlement = crate::identity::settlement_signer(&identity);
    let terms = bond_terms_staked_by(&settlement);
    let bond_edge = Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(terms.clone()));

    // The first process: one setup journal under the configured
    // root, staking the bond this node's own key is the maker of.
    {
        let store = SetupStore::open(
            &loaded.journal_root,
            loaded.chain.network,
            bond_edge,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .expect("the journal opens under the configured root");
        let mut endpoint = SetupEndpoint::new(store, settlement.clone(), admission.clone());
        endpoint
            .arm_scan(SetupScan {
                height: 7,
                payload: [0x47; 32],
            })
            .expect("the immutable history floor is armed");
        endpoint
            .propose_bond(loaded.chain.network, bond_funding(), terms.clone())
            .expect("the endpoint signs and journals its bond proposal");
    }

    // The restart: the root and the network, and no bond edge or
    // role anywhere in the configuration to be told them by.
    let found =
        hellas_work::work_store::discover_setups(&loaded.journal_root, loaded.chain.network)
            .expect("the configured root enumerates");
    assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
    let [discovered] = found.setups.as_slice() else {
        panic!("one journal was written, one is found: {:?}", found.setups);
    };
    assert_eq!(discovered.bond_edge, bond_edge);
    assert_eq!(discovered.role, Role::Provider);

    let store = SetupStore::open(
        &loaded.journal_root,
        loaded.chain.network,
        discovered.bond_edge,
        discovered.role,
        &Secp256k1Verifier::new(),
    )
    .expect("the discovered journal reopens");
    assert_eq!(store.state().revision(), Some(1));
    let mut endpoint = SetupEndpoint::new(
        store,
        crate::identity::settlement_signer(&identity),
        admission.clone(),
    );

    let state = endpoint
        .propose_bond(loaded.chain.network, bond_funding(), terms)
        .expect("the rebuilt endpoint answers for the journal it reopened");

    assert_eq!(state.revision(), Some(1));
}

#[test]
fn observer_freshness_must_leave_time_for_a_poll() {
    let poll = config()["poll_ms"].as_u64().unwrap();
    for age in [0, poll] {
        let error = load(with(
            config(),
            "max_observation_age_ms",
            serde_json::json!(age),
        ))
        .unwrap_err();
        assert!(format!("{error:#}").contains("max_observation_age_ms"));
    }
    let configured = load(with(
        config(),
        "max_observation_age_ms",
        serde_json::json!(poll + 1),
    ))
    .unwrap();
    assert_eq!(
        configured.max_observation_age,
        std::time::Duration::from_millis(poll + 1)
    );
}
