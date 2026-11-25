use super::*;
use hellas_rpc::protocol::invocation::output::Outcome;

#[test]
fn voice_names_and_catalog_files_cannot_leave_their_directory() {
    for name in ["Easton", "Lucía-Sol", "The Snow Queen"] {
        validate_voice(name).unwrap();
    }
    for name in ["", ".", "..", "a/b", "..\\b", "a\nb", &"x".repeat(65)] {
        assert!(validate_voice(name).is_err(), "{name:?}");
    }
    let easton = r#"{"name":"Easton","filename":"voices/abc.safetensors"}"#;
    let zoey = r#"{"name":"Zoey","filename":"voices/xyz.safetensors"}"#;
    assert_eq!(catalog(&[easton, zoey].join("\n")).unwrap().len(), 2);
    for invalid in [
        r#"{"name":"Up","filename":"../abc.safetensors"}"#,
        r#"{"name":"Root","filename":"/abc.safetensors"}"#,
        r#"{"name":"Back","filename":"voices\\abc.safetensors"}"#,
        r#"{"name":"No","filename":"abc.json"}"#,
        easton,
    ] {
        assert!(catalog(&[easton, invalid].join("\n")).is_err(), "{invalid}");
    }
}

#[test]
fn voices_must_be_whole_frames_that_leave_room_for_text() {
    assert_eq!(phonon::voice_frames(&[1, 512, 250]).unwrap(), 250);
    assert!(phonon::voice_frames(&[1, 512, 0]).is_err());
    assert!(phonon::voice_frames(&[1, 256, 250]).is_err());
}

#[tokio::test]
async fn one_model_selects_f32_and_bf16_voices_by_range() -> Result<()> {
    use crate::model::native::{Kind, Origin, Snapshot};
    use safetensors::{Dtype, tensor::TensorView};

    let root = tempfile::tempdir()?;
    let root = root.path();
    for (directory, names) in [
        ("model", phonon::MODEL_FILES.as_slice()),
        ("codec", phonon::CODEC_FILES.as_slice()),
    ] {
        std::fs::create_dir_all(root.join(directory))?;
        for name in names {
            let path = root.join(directory).join(name);
            if name.ends_with(".safetensors") {
                safetensors::serialize_to_file(
                    [("dummy", TensorView::new(Dtype::BF16, vec![1], &[0, 0])?)],
                    None,
                    &path,
                )?;
            } else {
                std::fs::write(path, b"{}")?;
            }
        }
    }
    let voices = root.join("voices");
    std::fs::create_dir_all(&voices)?;
    std::fs::write(
        voices.join(phonon::VOICE_CATALOG),
        "{\"name\":\"Easton\",\"filename\":\"one.safetensors\"}\n{\"name\":\"Zoey\",\"filename\":\"two.safetensors\"}",
    )?;
    for (file, dtype, frames) in [
        ("one.safetensors", Dtype::F32, 3),
        ("two.safetensors", Dtype::BF16, 5),
    ] {
        let data = vec![0; 512 * frames * dtype.bitsize() / 8];
        safetensors::serialize_to_file(
            [(
                "speaker_wavs",
                TensorView::new(dtype, vec![1, 512, frames], &data)?,
            )],
            None,
            &voices.join(file),
        )?;
    }
    let source = Arc::new(
        Snapshot::open(
            Origin::Local(root.to_owned()),
            Kind::Phonon,
            Default::default(),
        )?
        .resolve(None)?,
    );
    let (env, content) = source.environment("test").await?;
    // A split local install and an assembled snapshot describe exactly the same model.
    let spec = crate::model::ModelSpec {
        model: root.join("model/model.safetensors"),
        codec: Some(root.join("codec/model.safetensors")),
        voices: Some(voices.join(phonon::VOICE_CATALOG)),
    };
    let original_id = env.model.content_id()?;
    let immutable = crate::model::ModelSpec {
        model: format!("hellas://{original_id}").into(),
        ..spec.clone()
    };
    assert!(
        immutable
            .identify()
            .await
            .unwrap_err()
            .to_string()
            .contains("already commits")
    );
    assert_eq!(spec.identify().await?, original_id);
    let files = spec.files().await?;
    assert!(files.hub.is_empty());
    assert!(files.local.contains(&voices.join("two.safetensors")));

    // Alternate filenames at acquisition keep canonical names in the model.
    let alternate = tempfile::tempdir()?;
    std::fs::copy(
        root.join("codec/config.json"),
        alternate.path().join("config.json"),
    )?;
    let codec = alternate.path().join("custom.safetensors");
    std::fs::copy(root.join("codec/model.safetensors"), &codec)?;
    let spec = crate::model::ModelSpec {
        codec: Some(codec),
        ..spec
    };
    assert_eq!(spec.identify().await?, original_id);
    std::fs::write(alternate.path().join("config.json"), br#"{"variant":2}"#)?;
    let other_codec_id = spec.identify().await?;
    assert_ne!(other_codec_id, original_id);
    let catalog_path = voices.join("custom.jsonl");
    std::fs::write(
        &catalog_path,
        r#"{"name":"Easton","filename":"one.safetensors"}"#,
    )?;
    let spec = crate::model::ModelSpec {
        voices: Some(catalog_path),
        ..spec
    };
    let other_voices_id = spec.identify().await?;
    assert_ne!(other_voices_id, other_codec_id);
    let phonon = Phonon {
        tokenizer: tokenizers::Tokenizer::from_bytes(include_bytes!(
            "../../whisper/mini/tokenizer.json"
        ))
        .map_err(anyhow::Error::msg)?,
        source,
        program: Program {
            source: String::new(),
            raw: vec![],
            outputs: 0,
            setup: vec![],
            synth: vec![],
            latents: [Binding::Prepared(0), Binding::Prepared(1)],
        },
    };
    let first = phonon.render_job(&env, &content, "hi", "default", 1.)?;
    let second = phonon.render_job(&env, &content, "hi", "Zoey", 1.)?;
    assert_eq!(first.environment, second.environment);
    assert_eq!(first.plan.calls[1].entry, VOICE_ENTRY);
    assert!(
        matches!(&first.plan.calls[1].args[0], Arg::Asset { name, bytes, .. }
        if name == "voices/one.safetensors" && *bytes == 3 * 512 * 4)
    );
    assert_eq!(second.plan.calls[1].entry, "phonon.setup");
    assert!(
        matches!(&second.plan.calls[1].args[0], Arg::Asset { name, bytes, .. }
        if name == "voices/two.safetensors" && *bytes == 5 * 512 * 2)
    );
    assert_eq!(second.plan.calls[1].args[1], Arg::U64(5));
    assert!(
        phonon
            .render_job(&env, &content, "hi", "unknown", 1.)
            .is_err()
    );
    Ok(())
}

fn output(utterances: &[(&[f32], u64, u64)]) -> InvocationOutput {
    InvocationOutput {
        outcome: Outcome::Succeeded,
        metadata: hellas_rpc::JsonBytes(vec![]),
        artifacts: utterances
            .iter()
            .enumerate()
            .flat_map(|(i, (samples, count, status))| {
                [
                    Artifact::new(
                        format!("result-{i:02}"),
                        "catena.bytes.v1",
                        [count.to_le_bytes(), status.to_le_bytes()].concat(),
                    ),
                    Artifact::new(
                        format!("waveform-{i:02}"),
                        "catena.bytes.v1",
                        samples.iter().flat_map(|x| x.to_le_bytes()).collect(),
                    ),
                ]
            })
            .collect(),
    }
}

#[test]
fn utterances_are_joined_by_pauses_and_statuses_are_checked() {
    let audio = decode(&output(&[(&[0.5, 0.25, 9.], 2, 0), (&[-0.5], 1, 0)])).unwrap();
    assert_eq!(audio.sample_rate, 24_000);
    let mut expected = vec![0.5, 0.25];
    expected.resize(2 + phonon::PAUSE_SAMPLES, 0.);
    expected.push(-0.5);
    assert_eq!(audio.samples, expected);
    for invalid in [
        output(&[]),
        output(&[(&[0.5], 1, 1)]),
        output(&[(&[0.5], 2, 0)]),
        output(&[(&[f32::NAN], 1, 0)]),
    ] {
        assert!(decode(&invalid).is_err());
    }
    for (artifact, extra) in [(0, 8), (1, 1)] {
        let mut ragged = output(&[(&[0.5], 1, 0)]);
        let mut bytes = ragged.artifacts[artifact].bytes.as_bytes().to_vec();
        bytes.resize(bytes.len() + extra, 0);
        ragged.artifacts[artifact] = Artifact::new(
            ragged.artifacts[artifact].name.clone(),
            "catena.bytes.v1",
            bytes,
        );
        assert!(decode(&ragged).is_err(), "{artifact}");
    }
    let mut missing = output(&[(&[0.5], 1, 0), (&[0.5], 1, 0)]);
    missing.artifacts.remove(2);
    assert!(decode(&missing).is_err());
}
