#![cfg_attr(
    feature = "validator",
    expect(
        clippy::disallowed_methods,
        reason = "inventory class A/B/C: test timing fixtures pending their rollout"
    )
)]
#![cfg(feature = "validator")]

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
