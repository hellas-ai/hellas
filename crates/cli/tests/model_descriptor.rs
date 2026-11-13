use std::{path::Path, process::Command};

#[test]
fn describe_and_program_work_without_an_identity_or_original_weights() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let full = root.path().join("model.gguf");
    let descriptor = root.path().join("model");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/package/mini-qwen3.gguf"),
        &full,
    )
    .unwrap();
    let run = |args: &[&std::ffi::OsStr]| {
        let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
            .arg("--home")
            .arg(&home)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let evaluator = hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip);
    let full_program = run(&[
        "program".as_ref(),
        full.as_os_str(),
        "--backend".as_ref(),
        evaluator.as_ref(),
    ]);
    run(&[
        "model".as_ref(),
        "describe".as_ref(),
        full.as_os_str(),
        "-o".as_ref(),
        descriptor.as_os_str(),
    ]);
    std::fs::remove_file(&full).unwrap();
    assert_eq!(
        full_program,
        run(&[
            "program".as_ref(),
            descriptor.as_os_str(),
            "--backend".as_ref(),
            evaluator.as_ref()
        ])
    );
    assert!(!home.join("identity").exists());
    assert!(!home.join("principal.key").exists());
}
