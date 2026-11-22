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
    let catalog = [
        r#"{"name": "Easton", "filename": "voices/abc.safetensors"}"#,
        r#"{"name": "Up", "filename": "../abc.safetensors"}"#,
        r#"{"name": "Root", "filename": "/abc.safetensors"}"#,
        r#"{"name": "Back", "filename": "voices\\abc.safetensors"}"#,
    ]
    .join("\n");
    assert_eq!(
        voice_file(&catalog, "Easton").unwrap(),
        "voices/abc.safetensors"
    );
    for name in ["Up", "Root", "Back", "Missing", "../Easton"] {
        assert!(voice_file(&catalog, name).is_err(), "{name}");
    }
}

#[test]
fn voices_must_be_whole_frames_that_leave_room_for_text() {
    assert_eq!(voice_frames(250 * 1024).unwrap(), 250);
    for bytes in [0, 1023, 1025, 8192 * 1024, 8161 * 1024] {
        assert!(voice_frames(bytes).is_err(), "{bytes}");
    }
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
