use std::process::Command;

#[test]
fn identity_init_creates_the_device_identity_and_principal_key_in_a_relative_home() {
    let directory = tempfile::tempdir().unwrap();
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_hellas"))
            .current_dir(directory.path())
            .args(arguments)
            .output()
            .unwrap()
    };
    let output = run(&["--home", ".", "identity", "init"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(directory.path().join("identity").is_file());
    let key = std::fs::read(directory.path().join("principal.key")).unwrap();
    hellas_kernel::SoftPasskey::from_secret_scalar(key.try_into().unwrap()).unwrap();
}

#[test]
fn home_flag_overrides_environment_and_os_home() {
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
    let output = run(&["identity", "init"]);
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
        .args(["identity", "init"])
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
        .args(["identity", "init"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(from_home.join(".hellas/identity").is_file());
}
