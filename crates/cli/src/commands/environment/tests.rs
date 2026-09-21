use super::{EnvironmentSettings, atomic_write, build, inspect};
use super::{index_ref, verify};
use hellas_rpc::{CausalLmEnvironment, ContentId, ContentRef};
use hellas_store::ContentStore;
use std::path::{Path, PathBuf};

fn validate(settings: EnvironmentSettings, object_lengths: &[u64]) -> CausalLmEnvironment {
    let objects = object_lengths
        .iter()
        .enumerate()
        .map(|(index, bytes)| ContentRef::new(ContentId::from_bytes([index as u8 + 2; 32]), *bytes))
        .collect();
    let environment = CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([1; 32]), 1),
        settings.entrypoint,
        objects,
        settings
            .static_inputs
            .into_iter()
            .map(|slice| hellas_rpc::StaticSlice::new(slice.object, slice.offset, slice.bytes))
            .collect(),
        settings.state_bytes_per_capacity,
        settings.vocabulary_size,
        settings.maximum_capacity,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: settings.generation.fixed_capacity,
            prefill_chunk_tokens: settings.generation.prefill_chunk_tokens,
        },
    )
    .unwrap();
    environment
}

#[test]
fn parses_human_toml_settings() {
    let settings: EnvironmentSettings = toml::from_str(
        r#"entrypoint = "model"
static_objects = ["weights.safetensors"]
state_bytes_per_capacity = [1024]
vocabulary_size = 32000
maximum_capacity = 4096

[generation]
fixed_capacity = 4096
prefill_chunk_tokens = 64

[[static_inputs]]
object = 0
offset = 8
bytes = 16
"#,
    )
    .unwrap();
    assert_eq!(settings.entrypoint, "model");
    assert_eq!(settings.static_inputs[0].object, 0);
}

#[test]
fn rejects_unknown_human_settings() {
    let error = toml::from_str::<EnvironmentSettings>(
        r#"entrypoint = "model"
state_bytes_per_capacity = [1024]
vocabulary_size = 32000
maximum_capacity = 4096
[generation]
fixed_capacity = 4096
prefill_chunk_tokens = 64
unexpected = true
"#,
    )
    .unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn build_rejects_oversized_settings_before_indexing_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let settings = directory.path().join("oversized.toml");
    let output = directory.path().join("model.environment");
    std::fs::write(
        &settings,
        vec![0; hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1],
    )
    .unwrap();

    let error = build(&directory.path().join("missing.hex"), &settings, &output)
        .expect_err("oversized settings must be refused before artifact indexing");
    let message = error.to_string();
    assert!(message.contains("environment settings"), "{message}");
    assert!(message.contains("byte limit"), "{message}");
    assert!(!output.exists());
}

#[test]
fn inspect_rejects_oversized_environment_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let environment = directory.path().join("oversized.environment");
    std::fs::write(
        &environment,
        vec![0; hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES + 1],
    )
    .unwrap();

    let error = inspect(&environment).expect_err("oversized environment must be refused");
    let message = error.to_string();
    assert!(message.contains("environment"), "{message}");
    assert!(message.contains("byte limit"), "{message}");
}

#[cfg(unix)]
#[test]
fn inspect_rejects_a_device_before_reading_from_it() {
    let error =
        inspect(Path::new("/dev/zero")).expect_err("environment metadata must be an ordinary file");
    assert!(error.to_string().contains("failed to open environment"));
    assert!(format!("{error:#}").contains("not a regular file"));
}

#[cfg(unix)]
#[test]
fn atomic_output_does_not_follow_a_preexisting_fixed_temporary_symlink() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("model.environment");
    let victim = directory.path().join("operator-data");
    let preexisting_temporary = output.with_extension("tmp");
    std::fs::write(&victim, b"must survive").unwrap();
    symlink(&victim, &preexisting_temporary).unwrap();

    atomic_write(&output, b"complete environment").unwrap();

    assert_eq!(std::fs::read(&output).unwrap(), b"complete environment");
    assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");
    assert!(
        std::fs::symlink_metadata(&preexisting_temporary)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn concurrent_atomic_outputs_publish_one_complete_private_file() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("model.environment");
    let publishers = 12_usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(publishers + 1));
    let mut threads = Vec::new();
    for marker in 1..=publishers {
        let payload = vec![u8::try_from(marker).unwrap(); marker * 4096];
        let output = output.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            atomic_write(&output, &payload)
        }));
    }
    barrier.wait();
    for thread in threads {
        thread.join().unwrap().unwrap();
    }

    let published = std::fs::read(&output).unwrap();
    let marker = usize::from(*published.first().expect("published file is not empty"));
    assert!((1..=publishers).contains(&marker));
    assert_eq!(
        published,
        vec![u8::try_from(marker).unwrap(); marker * 4096]
    );
    let final_name = output.file_name().unwrap().to_string_lossy();
    let temporary_prefix = format!(".{final_name}.");
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(&temporary_prefix) || !name.ends_with(".environment.tmp")
            }),
        "successful publication must clean every unique temporary"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn failed_atomic_output_removes_its_unique_temporary() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("model.environment");
    std::fs::create_dir(&output).unwrap();

    atomic_write(&output, b"cannot replace a directory")
        .expect_err("renaming a file over a directory must fail");

    let temporary_prefix = format!(".{}.", output.file_name().unwrap().to_string_lossy());
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.starts_with(&temporary_prefix) || !name.ends_with(".environment.tmp")
            }),
        "failed publication left a unique temporary behind"
    );
}

#[test]
fn atomic_output_requires_an_existing_parent() {
    let directory = tempfile::tempdir().unwrap();
    let missing_parent = directory.path().join("not-created");
    let output = missing_parent.join("model.environment");

    atomic_write(&output, b"complete environment")
        .expect_err("publication must not create an unsynced parent hierarchy");

    assert!(!missing_parent.exists());
    assert!(!output.exists());
}

#[test]
fn checked_in_model_settings_match_the_pinned_generated_records() {
    // These identities pin every ordered static slice, not just the counts
    // below. Update them only when regenerating from the revision named in
    // each settings file or deliberately changing its committed schedule.
    assert_eq!(
        ContentId::hash(include_bytes!(
            "../../../../../examples/smollm2.environment.toml"
        ))
        .to_string(),
        "ce93212873a10c4b336b6e24d86a7d3b06deac85c133395c4c825c6c6b9fab2b"
    );
    assert_eq!(
        ContentId::hash(include_bytes!(
            "../../../../../examples/qwen3.environment.toml"
        ))
        .to_string(),
        "68d831ee06da3a2716c49f310b25ad753b20eb7a13cf2486678c96131aa7995a"
    );
    let smol: EnvironmentSettings = toml::from_str(include_str!(
        "../../../../../examples/smollm2.environment.toml"
    ))
    .unwrap();
    assert_eq!(smol.entrypoint, "smollm2");
    assert_eq!(smol.static_objects.len(), 1);
    assert_eq!(smol.static_inputs.len(), 272);
    let smol = validate(smol, &[269_060_552]);
    assert_eq!(smol.vocabulary_size(), 49_152);
    assert_eq!(smol.maximum_capacity(), 8_192);

    let qwen: EnvironmentSettings = toml::from_str(include_str!(
        "../../../../../examples/qwen3.environment.toml"
    ))
    .unwrap();
    assert_eq!(qwen.entrypoint, "qwen3");
    assert_eq!(qwen.static_objects.len(), 2);
    assert_eq!(qwen.static_inputs.len(), 579);
    let qwen = validate(qwen, &[49_693_950_144, 11_401_853_280]);
    assert_eq!(qwen.vocabulary_size(), 151_936);
    assert_eq!(qwen.maximum_capacity(), 32_768);
    assert_eq!(
        qwen.generation_schedule(),
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 32_768,
            prefill_chunk_tokens: 64,
        }
    );
}

#[tokio::test]
async fn schedule_changes_only_metadata_without_reopening_static_objects() {
    let directory = tempfile::tempdir().unwrap();
    let environment = provider_ready_environment(directory.path());
    let original =
        CausalLmEnvironment::from_canonical_bytes(&std::fs::read(&environment).unwrap()).unwrap();
    std::fs::remove_file(directory.path().join("weights.bin")).unwrap();
    std::fs::remove_file(directory.path().join("model.hex")).unwrap();
    let out = directory.path().join("scheduled.environment");
    super::run(super::EnvironmentCommand::Schedule {
        environment,
        fixed_capacity: 64,
        prefill_chunk_tokens: 16,
        out: out.clone(),
    })
    .await
    .unwrap();
    let scheduled =
        CausalLmEnvironment::from_canonical_bytes(&std::fs::read(out).unwrap()).unwrap();
    assert_eq!(scheduled.program(), original.program());
    assert_eq!(scheduled.static_objects(), original.static_objects());
    assert_ne!(
        scheduled.manifest().content_id(),
        original.manifest().content_id()
    );
}

fn provider_ready_environment(directory: &Path) -> PathBuf {
    let program_path = directory.join("model.hex");
    let weights_path = directory.join("weights.bin");
    std::fs::write(&program_path, b"fn model() { return; }").unwrap();
    std::fs::write(&weights_path, b"weights").unwrap();

    let store = ContentStore::new();
    let program = index_ref(&store, &program_path, "program").unwrap();
    let weights = index_ref(&store, &weights_path, "weights").unwrap();
    let environment = CausalLmEnvironment::new(
        program,
        "model",
        vec![weights],
        vec![hellas_rpc::StaticSlice::new(0, 0, weights.bytes())],
        vec![4],
        32,
        64,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 64,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let path = directory.join("model.environment");
    std::fs::write(&path, environment.canonical_bytes()).unwrap();
    path
}

#[test]
fn verify_proves_a_complete_local_environment_closure() {
    let directory = tempfile::tempdir().unwrap();
    let environment = provider_ready_environment(directory.path());

    verify(
        &environment,
        &[],
        &[directory.path().to_path_buf()],
        None,
        false,
    )
    .unwrap();
}

#[test]
fn verify_rejects_a_root_with_only_junk_or_an_incomplete_environment() {
    let directory = tempfile::tempdir().unwrap();
    let environment = provider_ready_environment(directory.path());
    std::fs::remove_file(directory.path().join("weights.bin")).unwrap();
    std::fs::write(directory.path().join("junk"), b"not model content").unwrap();

    let error = verify(
        &environment,
        &[],
        &[directory.path().to_path_buf()],
        None,
        false,
    )
    .expect_err("a missing referenced object must fail readiness");
    assert!(error.to_string().contains("static object 0"), "{error:#}");
    assert!(
        error.to_string().contains("not locally available"),
        "{error:#}"
    );
}

#[test]
fn verify_does_not_treat_the_environment_argument_as_implicit_content() {
    let directory = tempfile::tempdir().unwrap();
    let environment = provider_ready_environment(directory.path());
    let empty = tempfile::tempdir().unwrap();

    let error = verify(
        &environment,
        &[],
        &[empty.path().to_path_buf()],
        None,
        false,
    )
    .expect_err("the provider content view must contain the environment itself");
    assert!(error.to_string().contains("environment"), "{error:#}");
    assert!(
        error.to_string().contains("not locally available"),
        "{error:#}"
    );
}
