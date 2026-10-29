use super::*;
use crate::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_rpc::{JsonBytes, protocol::invocation::output::Outcome};

fn checkpoint(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("config.json"), r#"{"model_type":"whisper","d_model":2,"num_mel_bins":80,"encoder_layers":1,"decoder_layers":1,"encoder_attention_heads":1,"decoder_attention_heads":1,"encoder_ffn_dim":4,"decoder_ffn_dim":4,"max_source_positions":1500,"max_target_positions":8,"vocab_size":8,"decoder_start_token_id":4,"eos_token_id":3,"activation_function":"gelu"}"#).unwrap();
    std::fs::write(dir.join("generation_config.json"), r#"{"lang_to_id":{"<|en|>":5},"task_to_id":{"transcribe":6},"no_timestamps_token_id":7,"suppress_tokens":[2],"begin_suppress_tokens":[0,3]}"#).unwrap();
    std::fs::write(dir.join("tokenizer.json"), r#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hi":0,"there":1,"[UNK]":2,"eos":3,"sot":4,"en":5,"task":6,"no":7},"unk_token":"[UNK]"}}"#).unwrap();
    let config = Config::read(dir).unwrap();
    let tensors: Vec<_> = tensors(&config)
        .into_iter()
        .enumerate()
        .map(|(i, (name, shape))| {
            let elements: usize = shape.iter().product();
            let (dtype, bytes) = if i % 2 == 0 {
                (
                    safetensors::Dtype::F32,
                    (0..elements)
                        .flat_map(|n| {
                            [
                                1f32,
                                f32::from_bits(0x3f808000),
                                f32::from_bits(0x3f818000),
                                f32::from_bits(0x7f800001),
                            ][n % 4]
                                .to_le_bytes()
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                (
                    safetensors::Dtype::BF16,
                    (0..elements)
                        .flat_map(|n| [0u16, 0x8000, 0x3f80, 0x7f81, 0xffff][n % 5].to_le_bytes())
                        .collect(),
                )
            };
            (name, shape, dtype, bytes)
        })
        .collect();
    safetensors::serialize_to_file(
        tensors.iter().map(|(name, shape, dtype, bytes)| {
            (
                name,
                safetensors::tensor::TensorView::new(*dtype, shape.clone(), bytes).unwrap(),
            )
        }),
        None,
        &dir.join("model.safetensors"),
    )
    .unwrap();
}

#[test]
fn converted_asset_and_program_are_stable_and_ship_with_every_job() {
    let root = tempfile::tempdir().unwrap();
    let checkpoint_dir = root.path().join("checkpoint");
    checkpoint(&checkpoint_dir);
    let converted = root.path().join("converted");
    let object = convert_whisper(&checkpoint_dir, &converted).unwrap();
    let bytes = std::fs::read(converted.join(WEIGHTS_FILE)).unwrap();
    assert_eq!(object, ContentRef::for_bytes(&bytes));
    let cfg = Config::read(&checkpoint_dir).unwrap();
    let expected: Vec<_> = tensors(&cfg)
        .iter()
        .enumerate()
        .flat_map(|(i, (_, shape))| {
            (0..shape.iter().product::<usize>()).flat_map(move |n| {
                let bits = if i % 2 == 0 {
                    [0x3f80u16, 0x3f80, 0x3f82, 0x7fc0][n % 4]
                } else {
                    [0u16, 0x8000, 0x3f80, 0x7f81, 0xffff][n % 5]
                };
                bits.to_le_bytes()
            })
        })
        .collect();
    assert_eq!(
        bytes, expected,
        "F32 nearest-even conversion and all BF16 bits in graph order"
    );
    let second = root.path().join("second");
    assert_eq!(convert_whisper(&checkpoint_dir, &second).unwrap(), object);
    let model = ModelPackage::open(&converted).unwrap();
    for _ in 0..2 {
        let job = model
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: Some("en"),
                max_new_tokens: 4,
            })
            .unwrap();
        hellas_rpc::protocol::invocation::InvocationInput {
            parameters: JsonBytes(job.plan.canonical_bytes().unwrap()),
            artifacts: job.inputs.clone(),
        }
        .validate()
        .unwrap();
        assert_eq!(job.environment.assets[0].object, object);
        assert!(job.content.read(object).is_err());
        assert_eq!(job.environment.sources.len(), 1);
        assert_eq!(
            job.environment.sources[0],
            ContentRef::new(
                "a48635a262943cd85bb0896314b92281ef21581b05e710bf3ecaba29812f3861"
                    .parse()
                    .unwrap(),
                347973,
            ),
        );
        assert!(job.content.read(job.environment.sources[0]).is_ok());
        assert!(job.plan.step.is_none());
        assert_eq!(job.plan.calls[0].entry, "whisper.transcribe");
        assert_eq!(job.plan.calls[0].args.len(), 10 + tensors(&cfg).len());
        assert_eq!(
            job.plan.calls[0].args[1..7],
            [
                Arg::U64(4),
                Arg::U64(5),
                Arg::U64(4),
                Arg::U64(6),
                Arg::U64(7),
                Arg::U64(3)
            ]
        );
        assert_eq!(
            job.plan.outputs[0].kind,
            OutputKind::Buffer { max_bytes: 56 }
        );
        assert_eq!(
            *job.inputs.iter().find(|a| a.name == "features").unwrap(),
            floats("features", &audio::log_mel(&[0.; 400]).unwrap())
        );
    }
}

#[test]
fn shipped_whisper_program_matches_catena_models() {
    let model =
        ModelPackage::open(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/whisper/mini"))
            .unwrap();
    let job = model
        .render_job(&ModelRequest::Transcription {
            samples: &[0.; 400],
            language: Some("en"),
            max_new_tokens: 4,
        })
        .unwrap();
    let config =
        Config::read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/whisper/mini"))
            .unwrap();
    crate::model::program::assert_shipped_module(&job, &graph::bundle(&config, false).unwrap());
}

#[test]
fn masks_match_the_upstream_language_text_and_first_token_rules() {
    let root = tempfile::tempdir().unwrap();
    checkpoint(root.path());
    let (config, generation, _) = metadata(root.path()).unwrap();
    let n = f32::NEG_INFINITY;
    assert_eq!(
        generation.masks(&config),
        [
            vec![n, n, n, n, n, 0., n, n],
            vec![0., 0., n, 0., n, n, n, n],
            vec![n, 0., 0., n, 0., 0., 0., 0.],
        ]
    );
}

#[test]
fn decode_validates_the_result_header_and_decodes_client_side() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    checkpoint(&original);
    let converted = root.path().join("converted");
    convert_whisper(&original, &converted).unwrap();
    let model = ModelPackage::open(&converted).unwrap();
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
            .is_err()
    );
    assert!(
        model
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: None,
                max_new_tokens: 5
            })
            .is_err()
    );
}
