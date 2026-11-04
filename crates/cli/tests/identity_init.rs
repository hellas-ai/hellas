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
