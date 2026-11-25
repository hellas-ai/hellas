use super::*;
use crate::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_rpc::{ContentRef, JsonBytes, protocol::invocation::output::Outcome};
use std::path::Path;

fn fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/model/whisper/mini"
    ))
}

#[tokio::test]
async fn jobs_bind_original_ranges_and_only_cast_float_weights() {
    let path = fixture();
    let bytes = std::fs::read(path.join("model.safetensors")).unwrap();
    let object = ContentRef::for_bytes(&bytes);
    let package = ModelPackage::open(
        path,
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    let job = package
        .render_job(&ModelRequest::Transcription {
            samples: &[0.; 400],
            language: Some("en"),
            max_new_tokens: 4,
        })
        .await
        .unwrap();
    let model = &job.environment.model;
    assert_eq!(model.assets.len(), CHECKPOINT.len());
    for asset in &model.assets {
        let bytes = std::fs::read(path.join(&asset.name)).unwrap();
        assert_eq!(asset.object, ContentRef::for_bytes(&bytes));
        if asset.name != "model.safetensors" {
            let staged = hellas_channel::content::read(
                &job.content.0,
                &job.content.1,
                asset.object,
                asset.object.bytes(),
            )
            .await
            .unwrap();
            assert_eq!(&staged[..], bytes);
        }
    }
    assert!(
        hellas_channel::content::read(&job.content.0, &job.content.1, object, object.bytes())
            .await
            .is_err()
    );
    let [setup, transcribe] = job.plan.calls.as_slice() else {
        panic!("expected setup and transcription")
    };
    assert_eq!(setup.entry, "whisper.setup");
    assert_eq!(transcribe.entry, "whisper.transcribe");
    assert_eq!(
        transcribe.args[1..7],
        [
            Arg::U64(4),
            Arg::U64(5),
            Arg::U64(4),
            Arg::U64(6),
            Arg::U64(7),
            Arg::U64(3)
        ]
    );
    let config = Config::read(path).unwrap();
    let names = catena_models::whisper::graph::encoder_names(&config)
        .into_iter()
        .chain(catena_models::whisper::graph::cross_names(&config))
        .chain(catena_models::whisper::graph::decoder_names(&config));
    let (base, header) =
        catena_models::weights::read_safetensors_header(bytes.as_slice(), object.bytes()).unwrap();
    let tensors = header
        .tensors()
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut i = 0;
    for (arg, name) in transcribe.args[10..].iter().zip(names) {
        let tensor = &tensors[&name];
        let (start, end) = tensor.data_offsets;
        let range = Arg::Asset {
            name: "model.safetensors".into(),
            offset: (base + start) as u64,
            bytes: (end - start) as u64,
        };
        if tensor.dtype == safetensors::Dtype::BF16 {
            assert_eq!(*arg, range);
        } else {
            assert_eq!(setup.args[i], range);
            let Bind::Name(slot) = &setup.bind[i] else {
                panic!("missing setup output")
            };
            assert_eq!(*arg, Arg::Slot { name: slot.clone() });
            i += 1;
        }
    }
    assert_eq!(i, setup.args.len());
    assert!(i > 0 && i < transcribe.args.len() - 10);
    assert_eq!(
        job.plan.outputs[0].kind,
        OutputKind::Buffer { max_bytes: 56 }
    );
    assert_eq!(
        job.inputs.iter().find(|a| a.name == "features").unwrap(),
        &floats("features", &audio::log_mel(&[0.; 400]).unwrap())
    );
}

#[tokio::test]
async fn decode_validates_the_result_header_and_decodes_client_side() {
    let model = ModelPackage::open(
        fixture(),
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    let output = |values: &[u64]| InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: vec![Artifact::new(
            OUTPUT,
            "catena.bytes.v1",
            values.iter().flat_map(|n| n.to_le_bytes()).collect(),
        )],
        metadata: JsonBytes(
            hellas_rpc::canonical_dag_cbor(&RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let ModelResponse::Transcription(result) =
        model.decode(&output(&[2, 5, 1, 0, 1, 0, 0])).unwrap()
    else {
        panic!()
    };
    assert_eq!(result.text, "hi there");
    assert_eq!(result.tokens, [0, 1]);
    assert_eq!(result.language, "en");
    assert!(!result.truncated);
    for values in [
        [5, 5, 1, 0, 1, 0, 0],
        [2, 5, 2, 0, 1, 0, 0],
        [2, 4, 1, 0, 1, 0, 0],
        [2, 5, 1, 8, 1, 0, 0],
    ] {
        assert!(model.decode(&output(&values)).is_err());
    }
    assert!(
        model
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: Some("xx"),
                max_new_tokens: 1
            })
            .await
            .is_err()
    );
    assert!(
        model
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: None,
                max_new_tokens: 5
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn changing_tokenizer_bytes_changes_model_and_manifest() {
    let original = fixture();
    let directory = tempfile::tempdir().unwrap();
    for name in CHECKPOINT {
        std::fs::copy(original.join(name), directory.path().join(name)).unwrap();
    }
    let tokenizer = directory.path().join("tokenizer.json");
    let bytes = std::fs::read(&tokenizer).unwrap();
    std::fs::write(tokenizer, [bytes.as_slice(), b"\n"].concat()).unwrap();
    let evaluator = crate::model::evaluator(crate::model::GpuDialect::Hip);
    let before = ModelPackage::open(original, &evaluator).await.unwrap();
    let after = ModelPackage::open(directory.path(), &evaluator)
        .await
        .unwrap();
    assert_ne!(
        before.model().content_id().unwrap(),
        after.model().content_id().unwrap()
    );
    assert_ne!(before.programs().unwrap(), after.programs().unwrap());
}
