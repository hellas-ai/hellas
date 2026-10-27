use super::*;
use std::{fs, path::PathBuf, time::Duration};
type CliResult<T> = anyhow::Result<T>;
const THRESHOLD_IDENTITY: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];
fn hex32(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn validators() -> Vec<serde_json::Value> {
    (1..=VALIDATOR_COUNT)
        .map(|index| serde_json::Value::String(format!("http://127.0.0.1:900{index}")))
        .collect()
}

fn threshold_identity() -> String {
    hex::encode(THRESHOLD_IDENTITY)
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
fn config() -> serde_json::Value {
    serde_json::json!({
        "chain": {"network_id":"hellas-devnet-1", "genesis_payload_digest":hex32(1), "threshold_identity":threshold_identity()},
        "validators":validators(), "journal":{"root":"/var/lib/hellas/work"}, "poll_ms":250,
    })
}
#[test]
fn process_configuration_contains_chain_and_observation_bounds() {
    let loaded = load(config()).unwrap();
    assert_eq!(loaded.chain.network.as_str(), "hellas-devnet-1");
    assert_eq!(loaded.chain.genesis_payload_digest.as_bytes(), &[1; 32]);
    assert_eq!(loaded.chain.threshold_identity, THRESHOLD_IDENTITY);
    assert_eq!(loaded.journal_root, PathBuf::from("/var/lib/hellas/work"));
    assert_eq!(loaded.poll, Duration::from_millis(250));
    assert_eq!(loaded.max_observation_age, Duration::from_secs(5));
}
#[test]
fn policy_and_client_routes_are_rejected_in_process_configuration() {
    for field in [
        "routes",
        "policies",
        "expected_payment_values",
        "min_omit_response_blocks",
    ] {
        assert!(
            load(with(config(), field, serde_json::json!({}))).is_err(),
            "removed {field}"
        );
    }
}
#[test]
fn chain_pins_and_storage_are_required() {
    for (path, field) in [
        (vec![], "chain"),
        (vec![], "validators"),
        (vec![], "journal"),
        (vec![], "poll_ms"),
        (vec!["chain"], "network_id"),
        (vec!["chain"], "genesis_payload_digest"),
        (vec!["chain"], "threshold_identity"),
        (vec!["journal"], "root"),
    ] {
        assert!(
            load(without(config(), &path, field)).is_err(),
            "missing {field}"
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

#[test]
fn validators_are_loaded_normalised() {
    let loaded = load(config()).expect("the fixture config loads");
    assert_eq!(
        loaded.validators[0], "http://127.0.0.1:9001/",
        "the parsed URL, not the string the operator typed",
    );
}

#[test]
fn a_threshold_identity_consensus_cannot_decode_is_refused() {
    // A prefix of a real identity: hexadecimal, non-empty, and not a
    // point. A length check wearing consensus's name would take it.
    let mut broken = THRESHOLD_IDENTITY.to_vec();
    broken.truncate(32);
    let chain = serde_json::json!({
        "network_id": "hellas-devnet-1",
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
