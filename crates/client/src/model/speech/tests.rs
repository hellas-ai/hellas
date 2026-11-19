use super::*;
use crate::model::{GpuDialect, ModelKind, ModelPackage, ModelRequest, ModelResponse};
use hellas_rpc::protocol::invocation::output::Outcome;

fn fixture(dir: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/speech/fixture");
    for name in METADATA {
        std::fs::copy(source.join(name), dir.join(name)).unwrap();
    }
}

#[tokio::test]
async fn converted_mms_and_descriptor_render_the_same_portable_synthesis_job() {
    let root = tempfile::tempdir().unwrap();
    let checkpoint = root.path().join("checkpoint");
    std::fs::create_dir(&checkpoint).unwrap();
    fixture(&checkpoint);
    let mut tensors = std::collections::BTreeMap::new();
    for (name, binding) in tts::bindings() {
        if binding.normalized {
            let prefix = name.strip_suffix(".weight").unwrap();
            tensors.insert(
                format!("{prefix}.weight_v"),
                (
                    binding.shape.clone(),
                    vec![1f32; binding.shape.iter().product()],
                ),
            );
            tensors.insert(
                format!("{prefix}.weight_g"),
                (vec![binding.shape[0], 1, 1], vec![1f32; binding.shape[0]]),
            );
        } else {
            tensors.insert(
                name,
                (
                    binding.shape.clone(),
                    vec![0f32; binding.shape.iter().product()],
                ),
            );
        }
    }
    let bytes: Vec<_> = tensors
        .iter()
        .map(|(name, (shape, values))| {
            (
                name,
                shape,
                values
                    .iter()
                    .flat_map(|x| x.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let tensor_views = bytes.iter().map(|(name, shape, data)| {
        (
            name.as_str(),
            safetensors::tensor::TensorView::new(safetensors::Dtype::F32, (*shape).clone(), data)
                .unwrap(),
        )
    });
    safetensors::tensor::serialize_to_file(
        tensor_views,
        None,
        &checkpoint.join("model.safetensors"),
    )
    .unwrap();
    drop(bytes);
    drop(tensors);
    let full = root.path().join("mms");
    let object = convert_speech(&checkpoint, &full).unwrap();
    let desc = root.path().join("descriptor");
    assert_eq!(ModelPackage::describe(&full, &desc).await.unwrap(), object);
    assert!(!desc.join(WEIGHTS_FILE).exists());
    assert_eq!(ModelKind::of(&full).unwrap(), ModelKind::Speech);
    assert_eq!(ModelKind::of(&desc).unwrap(), ModelKind::Speech);
    assert!(ModelPackage::require_local_weights(&desc).is_err());
    for dialect in [GpuDialect::Hip, GpuDialect::Cuda] {
        let evaluator = crate::model::evaluator(dialect);
        let a = ModelPackage::open(&full, &evaluator).await.unwrap();
        let b = ModelPackage::open(&desc, &evaluator).await.unwrap();
        assert_eq!(a.program().unwrap(), b.program().unwrap());
        let request = ModelRequest::Speech {
            text: "Hello",
            speed: 1.,
        };
        let a = a.render_job(&request).await.unwrap();
        let b = b.render_job(&request).await.unwrap();
        assert_eq!(a.plan, b.plan);
        assert_eq!(a.inputs, b.inputs);
        assert_eq!(a.environment, b.environment);
        assert_eq!(a.plan.calls[0].entry, "tts.synthesize");
        assert_eq!(a.plan.calls[0].args.len(), 7 + tts::bindings().len());
        assert_eq!(a.environment.assets[0].object, object);
    }
}

fn output(samples: &[f32], count: u64, status: u64) -> InvocationOutput {
    let mut waveform = vec![0u8; tts::MAX_SAMPLES * 4];
    for (slot, sample) in waveform.chunks_exact_mut(4).zip(samples) {
        slot.copy_from_slice(&sample.to_le_bytes());
    }
    InvocationOutput {
        outcome: Outcome::Succeeded,
        metadata: hellas_rpc::JsonBytes(vec![]),
        artifacts: vec![
            Artifact::new(
                RESULT,
                "catena.bytes.v1",
                [count.to_le_bytes(), status.to_le_bytes()].concat(),
            ),
            Artifact::new(WAVEFORM, "catena.bytes.v1", waveform),
        ],
    }
}
#[test]
fn output_descriptor_is_checked_and_only_valid_samples_enter_wav() {
    let audio = Speech::decode(&output(&[-2., 0., 0.5, 2.], 4, 0)).unwrap();
    let encoded = audio.wav().unwrap();
    let mut wav = hound::WavReader::new(Cursor::new(encoded)).unwrap();
    assert_eq!(wav.spec().channels, 1);
    assert_eq!(wav.spec().sample_rate, 16000);
    assert_eq!(
        wav.samples::<i16>().map(Result::unwrap).collect::<Vec<_>>(),
        [-32767, 0, 16384, 32767]
    );
    for invalid in [
        output(&[], 0, 0),
        output(&[], tts::MAX_SAMPLES as u64 + 1, 0),
        output(&[0.], 1, 1),
        output(&[f32::NAN], 1, 0),
    ] {
        assert!(Speech::decode(&invalid).is_err());
    }
    let mut extra = output(&[0.], 1, 0);
    extra
        .artifacts
        .push(Artifact::new("extra", "catena.bytes.v1", vec![]));
    assert!(Speech::decode(&extra).is_err());
    let _response = ModelResponse::Speech(audio);
}
