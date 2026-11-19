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

#[cfg(feature = "compute")]
#[test]
fn local_model_commands_refuse_descriptors_before_reading_render_inputs() {
    let root = tempfile::tempdir().unwrap();
    for (fixture, metadata, command) in [
        (
            "../client/src/model/package/mini-qwen3.gguf",
            "header.gguf",
            vec!["text", "--prompt", "hello"],
        ),
        (
            "../client/src/model/whisper/mini",
            "config.json",
            vec!["transcribe", "--audio", "absent.wav"],
        ),
    ] {
        let descriptor = root.path().join(command[0]);
        let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
            .arg("model")
            .arg("describe")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture))
            .arg("-o")
            .arg(&descriptor)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for corrupt_metadata in [false, true] {
            // Refusal does not depend on usable metadata, audio input, or a GPU.
            if corrupt_metadata {
                std::fs::write(descriptor.join(metadata), []).unwrap();
            }
            let output = Command::new(env!("CARGO_BIN_EXE_hellas"))
                .arg("--home")
                .arg(root.path().join("home"))
                .args(&command)
                .arg("--model")
                .arg(&descriptor)
                .arg("--local")
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("local execution requires the full model weights, not a descriptor"),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
