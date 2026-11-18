use std::process::Command;

#[test]
fn faucet_requires_an_accounts_file_before_creating_state() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .arg("--home")
        .arg(home.path())
        .arg("faucet")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--accounts <FILE>"));
    assert!(!home.path().join("principal.key").exists());
    assert!(!home.path().join("identity").exists());
}
