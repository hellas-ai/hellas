use super::*;
use crate::model::{GpuDialect, evaluator};

fn whisper_full(path: &Path) {
    std::fs::create_dir(path).unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/whisper/mini");
    for name in crate::model::whisper::METADATA
        .into_iter()
        .chain([crate::model::whisper::WEIGHTS_FILE])
    {
        std::fs::copy(fixture.join(name), path.join(name)).unwrap();
    }
}

#[tokio::test]
async fn mixed_model_layouts_are_rejected_before_rendering() {
    let root = tempfile::tempdir().unwrap();
    let evaluator = evaluator(GpuDialect::Hip);
    let full = root.path().join("whisper");
    whisper_full(&full);
    let descriptor = root.path().join("whisper-descriptor");
    ModelPackage::describe(&full, &descriptor).await.unwrap();
    std::fs::copy(
        descriptor.join("descriptor.json"),
        full.join("descriptor.json"),
    )
    .unwrap();
    let error = ModelPackage::open(&full, &evaluator)
        .await
        .err()
        .expect("a descriptor manifest beside full Whisper weights must be rejected");
    assert!(
        error.to_string().contains("mixed model layout"),
        "{error:#}"
    );

    let qwen = root.path().join("qwen");
    ModelPackage::describe(&fixture(), &qwen).await.unwrap();
    std::fs::copy(full.join("config.json"), qwen.join("config.json")).unwrap();
    let error = ModelPackage::open(&qwen, &evaluator)
        .await
        .err()
        .expect("GGUF and Whisper metadata cannot select competing model kinds");
    assert!(
        error.to_string().contains("mixed model layout"),
        "{error:#}"
    );

    std::fs::write(descriptor.join("model_index.json"), b"{}").unwrap();
    let error = ModelPackage::open(&descriptor, &evaluator)
        .await
        .err()
        .expect("Flux and descriptor metadata cannot coexist");
    assert!(
        error.to_string().contains("mixed model layout"),
        "{error:#}"
    );
}

#[tokio::test]
async fn gguf_header_requires_a_descriptor_manifest() {
    let root = tempfile::tempdir().unwrap();
    let descriptor = root.path().join("qwen");
    ModelPackage::describe(&fixture(), &descriptor)
        .await
        .unwrap();
    std::fs::remove_file(descriptor.join("descriptor.json")).unwrap();
    let error = ModelPackage::open(&descriptor, &evaluator(GpuDialect::Hip))
        .await
        .err()
        .expect("a GGUF header is not a full model package");
    assert!(
        error
            .to_string()
            .contains("header.gguf requires descriptor.json"),
        "{error:#}"
    );
}

#[tokio::test]
async fn whisper_metadata_bounds_apply_to_full_packages_and_descriptors() {
    let root = tempfile::tempdir().unwrap();
    let full = root.path().join("whisper");
    whisper_full(&full);
    let descriptor = root.path().join("descriptor");
    ModelPackage::describe(&full, &descriptor).await.unwrap();
    for dir in [&full, &descriptor] {
        for name in crate::model::whisper::METADATA {
            let path = dir.join(name);
            let valid = std::fs::read(&path).unwrap();
            let mut oversized = valid.clone();
            oversized.resize((64 << 20) + 1, b' ');
            std::fs::write(&path, oversized).unwrap();
            let error = ModelPackage::open(dir, &evaluator(GpuDialect::Hip))
                .await
                .err()
                .expect("opening Whisper metadata must enforce its byte limit");
            assert!(
                error.to_string().contains("file exceeds byte limit"),
                "{name}: {error:#}"
            );
            std::fs::write(path, valid).unwrap();
        }
    }
}

pub(super) async fn same_job(full: &ComputeJob, descriptor: &ComputeJob) {
    assert_eq!(
        full.environment.canonical_bytes().unwrap(),
        descriptor.environment.canonical_bytes().unwrap()
    );
    assert_eq!(
        full.plan.canonical_bytes().unwrap(),
        descriptor.plan.canonical_bytes().unwrap()
    );
    assert_eq!(full.inputs, descriptor.inputs);
    for object in &full.environment.sources {
        let full = hellas_channel::content::read(
            &full.content.0,
            &full.content.1,
            *object,
            object.bytes(),
        )
        .await
        .unwrap();
        let described = hellas_channel::content::read(
            &descriptor.content.0,
            &descriptor.content.1,
            *object,
            object.bytes(),
        )
        .await
        .unwrap();
        assert_eq!(full, described);
    }
    for asset in &descriptor.environment.assets {
        assert!(matches!(
            hellas_channel::content::read(
                &descriptor.content.0,
                &descriptor.content.1,
                asset.object,
                asset.object.bytes()
            )
            .await,
            Err(hellas_store::content::Error::Missing)
        ));
    }
}

#[tokio::test]
async fn descriptors_render_identical_jobs_without_the_original_weights() {
    let root = tempfile::tempdir().unwrap();
    for kind in [ModelKind::Text, ModelKind::Transcription] {
        let full = root.path().join("full");
        if kind == ModelKind::Text {
            std::fs::copy(fixture(), &full).unwrap();
        } else {
            whisper_full(&full);
        }
        let evaluators = [evaluator(GpuDialect::Hip), evaluator(GpuDialect::Cuda)];
        let packages = ModelPackage::open_many(&full, evaluators.clone(), None)
            .await
            .unwrap();
        let descriptor = root.path().join(format!("{kind:?}"));
        let weights = ModelPackage::describe(&full, &descriptor).await.unwrap();
        assert_eq!(ModelKind::of(&descriptor).unwrap(), kind);
        assert!(
            crate::model::descriptor::classify(&descriptor)
                .unwrap()
                .is_descriptor()
        );
        assert_eq!(
            crate::model::descriptor::classify(&descriptor)
                .unwrap()
                .weights_path(&descriptor),
            None
        );
        assert!(std::fs::metadata(&descriptor).unwrap().is_dir());
        if kind == ModelKind::Text {
            let header = gguf::read_header(&mut File::open(&full).unwrap()).unwrap();
            let bytes = std::fs::read(ModelPackage::gguf_path(&descriptor).unwrap()).unwrap();
            assert_eq!(bytes.len() as u64, header.data_offset);
            assert_eq!(bytes, std::fs::read(&full).unwrap()[..bytes.len()]);
            use catena_models::tokenizer::QwenTokenizer;
            let original = QwenTokenizer::from_gguf(&full).unwrap().unwrap();
            let described = QwenTokenizer::from_gguf(ModelPackage::gguf_path(&descriptor).unwrap())
                .unwrap()
                .unwrap();
            assert!(described.chat_template().is_some());
            assert_eq!(original.chat_template(), described.chat_template());
            assert_eq!(
                original.encode("hi").unwrap(),
                described.encode("hi").unwrap()
            );
            std::fs::remove_file(&full).unwrap();
        } else {
            assert!(
                !descriptor
                    .join(crate::model::whisper::WEIGHTS_FILE)
                    .exists()
            );
            for name in crate::model::whisper::METADATA {
                assert_eq!(
                    std::fs::read(full.join(name)).unwrap(),
                    std::fs::read(descriptor.join(name)).unwrap()
                );
            }
            std::fs::remove_dir_all(&full).unwrap();
        }
        let described = ModelPackage::open_many(&descriptor, evaluators, None)
            .await
            .unwrap();
        for (evaluator, package) in packages {
            let described = &described[&evaluator];
            assert_eq!(package.program().unwrap(), described.program().unwrap());
            let requests = match kind {
                ModelKind::Text => vec![
                    ModelRequest::Text {
                        prompt_ids: &[2, 1],
                        max_new: 2,
                        stops: &[0, 0],
                    },
                    ModelRequest::Text {
                        prompt_ids: &[1],
                        max_new: 1,
                        stops: &[],
                    },
                ],
                ModelKind::Transcription => vec![
                    ModelRequest::Transcription {
                        samples: &[0.; 400],
                        language: Some("en"),
                        max_new_tokens: 4,
                    },
                    ModelRequest::Transcription {
                        samples: &[0.; 400],
                        language: None,
                        max_new_tokens: 2,
                    },
                ],
                ModelKind::Image => unreachable!(),
            };
            for request in requests {
                let full = package.render_job(&request).await.unwrap();
                assert_eq!(full.environment.assets[0].object, weights);
                same_job(&full, &described.render_job(&request).await.unwrap()).await;
            }
        }
    }
}

#[tokio::test]
async fn gguf_descriptors_reject_invalid_ranges_and_payloads() {
    let root = tempfile::tempdir().unwrap();
    let descriptor = root.path().join("qwen");
    ModelPackage::describe(&fixture(), &descriptor)
        .await
        .unwrap();
    let evaluator = evaluator(GpuDialect::Hip);
    let wrong = ContentRef::for_bytes(b"not the weights");
    assert!(
        ModelPackage::describe(&fixture(), &descriptor)
            .await
            .is_err()
    );
    assert!(
        ModelPackage::describe(&descriptor, &root.path().join("copy"))
            .await
            .is_err()
    );
    let manifest = descriptor.join("descriptor.json");
    let valid = std::fs::read(&manifest).unwrap();
    std::fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({"weights": wrong})).unwrap(),
    )
    .unwrap();
    assert!(ModelPackage::open(&descriptor, &evaluator).await.is_err());
    std::fs::write(&manifest, &valid).unwrap();
    use std::io::Write;
    File::options()
        .append(true)
        .open(ModelPackage::gguf_path(&descriptor).unwrap())
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(ModelPackage::open(&descriptor, &evaluator).await.is_err());
}

#[tokio::test]
async fn whisper_descriptors_reject_invalid_weight_lengths_and_generation_metadata() {
    let root = tempfile::tempdir().unwrap();
    let full = root.path().join("whisper");
    whisper_full(&full);
    let length = root.path().join("wrong-length");
    let weights = ModelPackage::describe(&full, &length).await.unwrap();
    std::fs::write(
        length.join("descriptor.json"),
        serde_json::to_vec(&serde_json::json!({
            "weights": ContentRef::new(weights.id(), weights.bytes() - 2)
        }))
        .unwrap(),
    )
    .unwrap();
    let error = ModelPackage::open(&length, &evaluator(GpuDialect::Hip))
        .await
        .err()
        .expect("Whisper descriptor length must match its tensor layout");
    assert!(
        error
            .to_string()
            .contains("derived weight file has wrong length"),
        "{error:#}"
    );

    let generation = root.path().join("wrong-generation");
    ModelPackage::describe(&full, &generation).await.unwrap();
    let path = generation.join("generation_config.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    metadata["no_timestamps_token_id"] = serde_json::json!(u32::MAX);
    std::fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let error = ModelPackage::open(&generation, &evaluator(GpuDialect::Hip))
        .await
        .err()
        .expect("Whisper descriptor generation metadata must be validated");
    assert!(
        error
            .to_string()
            .contains("generation token exceeds vocabulary"),
        "{error:#}"
    );
}

#[tokio::test]
async fn descriptor_manifest_cases_are_independently_strict() {
    let root = tempfile::tempdir().unwrap();
    let whisper = root.path().join("whisper");
    whisper_full(&whisper);
    for (family, full) in [("qwen", fixture()), ("whisper", whisper)] {
        for case in [
            "unknown",
            "missing",
            "null",
            "bad-id",
            "empty",
            "duplicate",
            "oversized",
        ] {
            let descriptor = root.path().join(format!("{family}-{case}"));
            let weights = ModelPackage::describe(&full, &descriptor).await.unwrap();
            let object = serde_json::to_string(&weights).unwrap();
            let (manifest, reason) = match case {
                "unknown" => (
                    format!("{{\"weights\":{object},\"version\":1}}"),
                    "unknown field",
                ),
                "missing" => ("{}".into(), "missing field"),
                "null" => ("{\"weights\":null}".into(), "invalid type"),
                "bad-id" => (
                    format!(
                        "{{\"weights\":{{\"id\":\"invalid\",\"bytes\":{}}}}}",
                        weights.bytes()
                    ),
                    "",
                ),
                "empty" => (
                    serde_json::to_string(&serde_json::json!({
                        "weights": ContentRef::new(weights.id(), 0)
                    }))
                    .unwrap(),
                    "descriptor weights are empty",
                ),
                "duplicate" => (
                    format!("{{\"weights\":{object},\"weights\":{object}}}"),
                    "duplicate field",
                ),
                "oversized" => (
                    format!("{{\"weights\":{object}}}{}", " ".repeat(4096)),
                    "file exceeds byte limit",
                ),
                _ => unreachable!(),
            };
            std::fs::write(descriptor.join("descriptor.json"), manifest).unwrap();
            let error = ModelPackage::open_many(
                &descriptor,
                [evaluator(GpuDialect::Hip), evaluator(GpuDialect::Cuda)],
                None,
            )
            .await
            .err()
            .expect("each malformed manifest must fail against otherwise-valid metadata");
            assert!(
                error.to_string().contains(reason),
                "{family}/{case}: {error:#}"
            );
        }
    }
}

#[tokio::test]
async fn a_descriptor_does_not_supply_the_providers_weights() {
    use hellas_store::content::{
        ContentStore, DiskStore, IndexMode, LocalStore, PinName, PinPolicy, PinValue, Reservations,
        Target,
    };
    let root = tempfile::tempdir().unwrap();
    let descriptor = root.path().join("descriptor");
    let weights = ModelPackage::describe(&fixture(), &descriptor)
        .await
        .unwrap();
    let store = DiskStore::open(
        hellas_private::StoreLocation::for_test(&root.path().join("store")),
        vec![descriptor],
        IndexMode::Resume,
        None,
        Reservations::ram(32 << 20),
        false,
    )
    .await
    .unwrap();
    store.finish_recovery().await.unwrap();
    let local = LocalStore::Disk(store.clone());
    let name = PinName::new("weights".into()).unwrap();
    let value = PinValue {
        target: Target::Object(weights),
        policy: PinPolicy::Jobs,
        expires: None,
    };
    assert!(
        store
            .set_pin(&Scope::Owner, &name, None, Some(value.clone()))
            .await
            .is_err()
    );
    assert!(matches!(
        hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes()).await,
        Err(hellas_store::content::Error::Missing)
    ));
    let full = root.path().join("weights.gguf");
    let mut bytes = std::fs::read(fixture()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&full, &bytes).unwrap();
    assert_ne!(
        store.inspect_files(vec![full.clone()]).await.unwrap()[&full],
        weights
    );
    store
        .rescan(vec![full.clone()], IndexMode::Resume)
        .await
        .unwrap();
    assert!(
        store
            .set_pin(&Scope::Owner, &name, None, Some(value.clone()))
            .await
            .is_err()
    );
    assert!(
        hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes())
            .await
            .is_err()
    );
    // Replace the immutable package, rather than relying on the filesystem
    // clock to distinguish two in-place writes within the same tick.
    let replacement = root.path().join("replacement.gguf");
    std::fs::copy(fixture(), &replacement).unwrap();
    std::fs::rename(replacement, &full).unwrap();
    assert_eq!(
        ContentRef::for_bytes(&std::fs::read(&full).unwrap()),
        weights
    );
    assert_eq!(
        store.inspect_files(vec![full.clone()]).await.unwrap()[&full],
        weights
    );
    store.rescan(vec![full], IndexMode::Resume).await.unwrap();
    store
        .set_pin(&Scope::Owner, &name, None, Some(value))
        .await
        .unwrap();
    assert_eq!(
        *hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes())
            .await
            .unwrap(),
        std::fs::read(fixture()).unwrap()
    );
}
