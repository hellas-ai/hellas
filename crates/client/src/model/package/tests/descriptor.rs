use super::*;
use crate::model::{GpuDialect, evaluator};

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
            std::fs::create_dir(&full).unwrap();
            let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/whisper/mini");
            for name in crate::model::whisper::METADATA
                .into_iter()
                .chain([crate::model::whisper::WEIGHTS_FILE])
            {
                std::fs::copy(fixture.join(name), full.join(name)).unwrap();
            }
        }
        let evaluators = [evaluator(GpuDialect::Hip), evaluator(GpuDialect::Cuda)];
        let packages = ModelPackage::open_many(&full, evaluators.clone())
            .await
            .unwrap();
        let descriptor = root.path().join(format!("{kind:?}"));
        let weights = ModelPackage::describe(&full, &descriptor).await.unwrap();
        assert_eq!(ModelKind::of(&descriptor), kind);
        assert!(ModelPackage::is_descriptor(&descriptor));
        assert_eq!(ModelPackage::weights_path(&descriptor), None);
        assert!(std::fs::metadata(&descriptor).unwrap().is_dir());
        if kind == ModelKind::Text {
            let header = gguf::read_header(&mut File::open(&full).unwrap()).unwrap();
            let bytes = std::fs::read(ModelPackage::gguf_path(&descriptor)).unwrap();
            assert_eq!(bytes.len() as u64, header.data_offset);
            assert_eq!(bytes, std::fs::read(&full).unwrap()[..bytes.len()]);
            use catena_models::tokenizer::QwenTokenizer;
            let original = QwenTokenizer::from_gguf(&full).unwrap().unwrap();
            let described = QwenTokenizer::from_gguf(ModelPackage::gguf_path(&descriptor))
                .unwrap()
                .unwrap();
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
        let described = ModelPackage::open_many(&descriptor, evaluators)
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
async fn descriptors_reject_invalid_ranges_payloads_and_supplied_weight_identities() {
    let root = tempfile::tempdir().unwrap();
    let descriptor = root.path().join("qwen");
    ModelPackage::describe(&fixture(), &descriptor)
        .await
        .unwrap();
    let evaluator = evaluator(GpuDialect::Hip);
    let wrong = ContentRef::for_bytes(b"not the weights");
    assert!(
        ModelPackage::open_with_weights(&descriptor, &evaluator, Some(wrong))
            .await
            .is_err()
    );
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
        .open(ModelPackage::gguf_path(&descriptor))
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(ModelPackage::open(&descriptor, &evaluator).await.is_err());
    std::fs::write(&manifest, b"{\"weights\": null, \"version\": 1}").unwrap();
    assert!(
        ModelPackage::open_many(&descriptor, [evaluator])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_descriptor_does_not_supply_the_providers_weights() {
    use hellas_store::content::{DiskStore, IndexMode, LocalStore, Reservations};
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
    let local = LocalStore::Disk(store.clone());
    assert!(matches!(
        hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes()).await,
        Err(hellas_store::content::Error::Missing)
    ));
    let full = root.path().join("weights.gguf");
    let mut bytes = std::fs::read(fixture()).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&full, &bytes).unwrap();
    store
        .rescan(vec![full.clone()], IndexMode::Resume)
        .await
        .unwrap();
    assert!(
        hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes())
            .await
            .is_err()
    );
    std::fs::copy(fixture(), &full).unwrap();
    store.rescan(vec![full], IndexMode::Resume).await.unwrap();
    assert_eq!(
        *hellas_channel::content::read(&local, &Scope::Owner, weights, weights.bytes())
            .await
            .unwrap(),
        std::fs::read(fixture()).unwrap()
    );
}
