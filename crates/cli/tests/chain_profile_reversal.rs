#![cfg_attr(
    feature = "validator",
    expect(
        clippy::disallowed_methods,
        reason = "inventory class A/B/C: test timing fixtures pending their rollout"
    )
)]
#![cfg(feature = "validator")]

use hellas_chain::{
    chain_dir::ChainDir,
    genesis::{Chain, ChainProfile, CustomChainFile},
};
use hellas_private::Durability::Crash;
use sha2::Digest as _;
use std::{
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hellas"));
    command
        .env("HOME", home)
        .env_remove("HELLAS_HOME")
        .env_remove("CREDENTIALS_DIRECTORY");
    command
}

#[test]
fn known_chain_rejects_generated_validator_outside_genesis_before_state() {
    let home = tempfile::tempdir().unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let generated = cli(home.path())
        .args([
            "chain",
            "validator",
            "config",
            "-n",
            "1",
            "--seed",
            "719",
            "--start-port",
            &port.to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let config = home.path().join("validator.toml");
    std::fs::write(&config, generated.stdout).unwrap();
    let stderr = home.path().join("run.stderr");
    let mut run = cli(home.path());
    run.args(["chain", "validator", "run", "--config"])
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()));
    let mut child = OwnedChild(run.spawn().unwrap());
    let state = home.path().join(".hellas/chains");
    let deadline = Instant::now() + hellas_channel::test_support::HANG_GUARD;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break Some(status);
        }
        if state.exists() || Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!state.exists(), "invalid validator reached chain state");
    assert!(status.is_some_and(|status| !status.success()));
    let error = std::fs::read_to_string(stderr).unwrap();
    assert!(
        error.contains("validator identity is not in the genesis committee"),
        "{error}"
    );
}

#[test]
fn state_generation_resets_only_the_selected_validator_and_keeps_shared_identity() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let identity = cli(root.path())
        .arg("--home")
        .arg(&home)
        .args(["--software-root", "identity", "init"])
        .output()
        .unwrap();
    assert!(
        identity.status.success(),
        "{}",
        String::from_utf8_lossy(&identity.stderr)
    );
    let shared_identity = std::fs::read(home.join("identity")).unwrap();

    let a = ChainProfile::known(Chain::Devnet);
    let mut genesis = a.genesis().clone();
    genesis.network_id = "custom-reset-test".into();
    let genesis_json = serde_json::to_string(&genesis).unwrap();
    let mut trust = a.trust().clone();
    trust.network_id = genesis.network_id.clone();
    trust.genesis_sha256 = hex::encode(sha2::Sha256::digest(genesis_json.as_bytes()));
    let b_path = root.path().join("b.json");
    std::fs::write(
        &b_path,
        serde_json::to_vec(&serde_json::json!({
            "genesis_json": &genesis_json,
            "trust": &trust,
            "validators": ["ws://127.0.0.1:9080"],
        }))
        .unwrap(),
    )
    .unwrap();
    let b = ChainProfile::custom(CustomChainFile {
        genesis_json,
        trust,
        validators: vec!["ws://127.0.0.1:9080".into()],
    })
    .unwrap();
    let a_state = ChainDir::open(&home, &a, Crash).unwrap().validator();
    let b_state = ChainDir::open(&home, &b, Crash).unwrap().validator();
    assert_ne!(a_state, b_state);

    let reset = |config: Option<&Path>, generation: &str| {
        let mut command = cli(root.path());
        command.arg("--home").arg(&home);
        if let Some(config) = config {
            command.arg("--chain-config").arg(config);
        }
        let output = command
            .args([
                "chain",
                "validator",
                "state-generation",
                "--generation",
                generation,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    reset(None, "1");
    std::fs::write(a_state.join("retained"), b"chain A").unwrap();
    let invalid = cli(root.path())
        .arg("--home")
        .arg(&home)
        .args([
            "chain",
            "validator",
            "state-generation",
            "--generation",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert_eq!(std::fs::read(a_state.join("retained")).unwrap(), b"chain A");
    reset(Some(&b_path), "1");
    std::fs::write(b_state.join("retained"), b"chain B").unwrap();
    reset(None, "1");
    assert_eq!(std::fs::read(a_state.join("retained")).unwrap(), b"chain A");
    assert_eq!(std::fs::read(b_state.join("retained")).unwrap(), b"chain B");
    reset(None, "2");
    assert!(!a_state.join("retained").exists());
    assert_eq!(std::fs::read(b_state.join("retained")).unwrap(), b"chain B");
    assert_eq!(
        std::fs::read(home.join("identity")).unwrap(),
        shared_identity
    );
}
