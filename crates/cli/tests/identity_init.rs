use std::process::Command;

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
        "--home",
        ".",
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
    assert!(directory.path().join("identity").is_file());
    let key = std::fs::read(directory.path().join("owner.passkey")).unwrap();
    hellas_kernel::SoftPasskey::from_secret_scalar(key.try_into().unwrap()).unwrap();
    let output = run(&["--home", ".", "identity", "show-holder"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn one_home_selects_identity_and_chain_state_key() {
    let root = tempfile::tempdir().unwrap();
    let from_home = root.path().join("os-home");
    let from_env = root.path().join("env-home");
    let explicit = root.path().join("explicit-home");
    std::fs::create_dir(&from_home).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_hellas"))
            .env("HOME", &from_home)
            .env("HELLAS_HOME", &from_env)
            .args(args)
            .output()
            .unwrap()
    };
    let key = run(&["--chain", "devnet", "chain", "state-key"]);
    assert!(
        key.status.success(),
        "{}",
        String::from_utf8_lossy(&key.stderr)
    );
    let key = String::from_utf8(key.stdout).unwrap();
    assert_eq!(key.trim().len(), 64);
    assert!(
        key.trim()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let default = run(&["chain", "state-key"]);
    assert_eq!(default.stdout, key.as_bytes());

    let output = run(&["--software-root", "identity", "init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(from_env.join("identity").is_file());
    assert!(!from_home.join(".hellas/identity").exists());

    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .env("HOME", &from_home)
        .env("HELLAS_HOME", &from_env)
        .arg("--home")
        .arg(&explicit)
        .args(["--software-root", "identity", "init"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(explicit.join("identity").is_file());

    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .env("HOME", &from_home)
        .env_remove("HELLAS_HOME")
        .args(["--software-root", "identity", "init"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(from_home.join(".hellas/identity").is_file());
}
