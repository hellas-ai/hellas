use std::{path::Path, process::Command};

#[test]
fn program_reads_a_checkpoint_without_creating_an_identity() {
    let home = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
    let evaluator =
        hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip, "gfx1151");
    let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
        .arg("--home")
        .arg(home.path())
        .arg("program")
        .arg(source)
        .args(["--backend", &evaluator])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with(&evaluator)
    );
    assert!(!home.path().join("identity").exists());
    assert!(!home.path().join("principal.key").exists());
}
