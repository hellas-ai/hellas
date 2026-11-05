use std::process::Command;

#[cfg(not(feature = "heavy"))]
#[test]
fn light_provider_rejects_compute_before_initializing_identity() {
    let directory = tempfile::tempdir().unwrap();
    let config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/faucet-provider.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path().join("data"))
        .args([
            "serve",
            "--software-root",
            "--paid-work-config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("heavy CLI"));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn local_tasks_do_not_initialize_an_identity_or_wallet() {
    for task in ["transcribe", "image", "text"] {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
            .current_dir(directory.path())
            .env("HOME", directory.path())
            .env("XDG_DATA_HOME", directory.path().join("data"))
            .args([task, "--local", "--model", "missing-model"])
            .args(if task == "transcribe" {
                ["--audio", "missing.wav"]
            } else {
                ["--prompt", "hello"]
            })
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        let expected = if cfg!(feature = "heavy") {
            "No such file or directory"
        } else {
            "local execution needs the heavy hellas build"
        };
        assert!(error.contains(expected), "{error}");
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            0,
            "local preparation initialized identity state"
        );
    }
}

#[test]
fn initialize_identity_and_owner_key_with_bare_filenames() {
    let directory = tempfile::tempdir().unwrap();
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_hellas"))
            .current_dir(directory.path())
            .args(arguments)
            .output()
            .unwrap()
    };
    let output = run(&[
        "--identity",
        "laptop.identity",
        "--software-root",
        "identity",
        "init",
        "--passkey-out",
        "owner.passkey",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(directory.path().join("laptop.identity").is_file());
    let key = std::fs::read(directory.path().join("owner.passkey")).unwrap();
    hellas_kernel::SoftPasskey::from_secret_scalar(key.try_into().unwrap()).unwrap();
    let output = run(&["--identity", "laptop.identity", "identity", "show-holder"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
