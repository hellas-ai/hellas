use super::*;
use crate::model::{GpuDialect, ModelKind, ModelPackage, ModelRequest};
use hellas_rpc::protocol::invocation::output::Outcome;
use std::io::Cursor;

#[tokio::test]
async fn original_mms_ranges_prepare_once_for_different_utterances() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_test_checkpoint(root.path())?;
    assert_eq!(ModelKind::of(root.path())?, ModelKind::Speech);
    let object = hellas_store::content::file_content(&root.path().join("model.safetensors"))?;
    for (dialect, arch) in [(GpuDialect::Hip, "gfx1151"), (GpuDialect::Cuda, "sm_120")] {
        let model =
            ModelPackage::open(root.path(), &crate::model::evaluator(dialect, arch)).await?;
        let request = |text, voice| ModelRequest::Speech {
            text,
            voice,
            speed: 1.,
        };
        assert!(model.render_job(&request("Hello", "other")).await.is_err());
        let job = model.render_job(&request("Hello", "default")).await?;
        let other = model.render_job(&request("Goodbye", "default")).await?;
        assert_eq!(job.environment.model.assets.len(), CHECKPOINT.len());
        let weight = job
            .environment
            .model
            .assets
            .iter()
            .find(|a| a.name == "model.safetensors")
            .unwrap();
        assert_eq!(weight.object, object);
        let [setup, synth] = job.plan.calls.as_slice() else {
            panic!("expected setup then synthesis")
        };
        assert_eq!(setup.entry, tts::preparation::SETUP_ENTRY);
        assert_eq!(setup, &other.plan.calls[0]);
        assert_ne!(job.inputs, other.inputs);
        assert_eq!(setup.bind.len(), tts::bindings().len());
        assert_eq!(setup.args.len(), 492);
        assert!(setup.args.iter().all(|arg| matches!(arg, Arg::Asset { name, offset, bytes }
            if name == "model.safetensors" && *offset > 8 && *bytes > 0 && offset + bytes <= object.bytes())));
        assert_eq!(synth.entry, "tts.synthesize");
        assert_eq!(synth.args.len(), 7 + setup.bind.len());
        assert!(
            synth.args[7..]
                .iter()
                .all(|arg| matches!(arg, Arg::Slot { .. }))
        );
    }
    Ok(())
}

fn output(samples: &[f32], count: u64, status: u64) -> InvocationOutput {
    let mut waveform = vec![0u8; tts::MAX_SAMPLES * 4];
    for (slot, sample) in waveform.as_chunks_mut::<4>().0.iter_mut().zip(samples) {
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
    let audio = Speech::decode_mms(&output(&[-2., 0., 0.5, 2.], 4, 0)).unwrap();
    let encoded = audio.wav_bytes().unwrap();
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
        assert!(Speech::decode_mms(&invalid).is_err());
    }
    let mut extra = output(&[0.], 1, 0);
    extra
        .artifacts
        .push(Artifact::new("extra", "catena.bytes.v1", vec![]));
    assert!(Speech::decode_mms(&extra).is_err());
}
