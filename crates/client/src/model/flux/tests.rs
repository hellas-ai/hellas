use super::*;
use crate::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_rpc::{JsonBytes, protocol::invocation::output::Outcome};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/flux/fixture")
}
fn request() -> ImageRequest<'static> {
    ImageRequest {
        prompt: "a small red fox",
        seed: 42,
        width: 16,
        height: 16,
        steps: 1,
    }
}

/// The same FluxPipeline used by catena-models' flux2-klein command, with its
/// native seeded noise and then the client's exported --noise input.
#[test]
#[ignore = "needs HIP, HELLAS_TEST_FLUX_SNAPSHOT and HELLAS_TEST_FLUX_REFERENCE_DIR"]
fn flux_reference_checks_seeded_noise() {
    use catena_models::flux::pipeline::{FluxPipeline, GenerationOptions};
    let snapshot = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_SNAPSHOT").unwrap());
    let directory = PathBuf::from(std::env::var("HELLAS_TEST_FLUX_REFERENCE_DIR").unwrap());
    std::fs::create_dir_all(&directory).unwrap();
    let noise_path = directory.join("noise.f32");
    let noise: Vec<_> = noise(42, 512, 512)
        .unwrap()
        .into_iter()
        .flat_map(f32::to_le_bytes)
        .collect();
    std::fs::write(&noise_path, &noise).unwrap();
    let pipeline = FluxPipeline::new(snapshot).unwrap();
    let mut options = GenerationOptions {
        prompt: "a small red fox".into(),
        seed: 42,
        width: 512,
        height: 512,
        steps: 4,
        output: directory.join("native.png"),
        dump_dir: None,
        noise: None,
    };
    pipeline.generate(&options).unwrap();
    options.noise = Some(noise_path);
    options.output = directory.join("noise.png");
    pipeline.generate(&options).unwrap();
    let native = std::fs::read(directory.join("native.png")).unwrap();
    let explicit = std::fs::read(&options.output).unwrap();
    assert_eq!(
        ContentRef::for_bytes(&native),
        ContentRef::for_bytes(&explicit),
        "native seed and client --noise must produce identical PNGs"
    );
    println!(
        "Flux reference: seed42, 512x512, steps4, noise={}, png={}",
        ContentRef::for_bytes(&noise).id(),
        ContentRef::for_bytes(&explicit).id()
    );
}

#[test]
fn image_job_bundles_three_stages_and_passes_state_in_slots() {
    let package = ModelPackage::open(&fixture()).unwrap();
    let request = request();
    let job = package.render_job(&ModelRequest::Image(request)).unwrap();
    hellas_rpc::protocol::invocation::InvocationInput {
        parameters: JsonBytes(job.plan.canonical_bytes().unwrap()),
        artifacts: job.inputs.clone(),
    }
    .validate()
    .unwrap();
    assert_eq!(job.environment.sources.len(), 1);
    assert_eq!(job.environment.assets.len(), 3);
    assert!(
        job.environment
            .assets
            .iter()
            .all(|a| job.content.read(a.object).is_err())
    );
    assert!(job.plan.step.is_none());
    let calls = &job.plan.calls;
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls.iter().map(|c| c.entry.as_str()).collect::<Vec<_>>(),
        ["flux.encode-text", "flux.denoise", "flux.decode-image"]
    );
    assert_eq!(
        calls.iter().map(|c| c.args.len()).collect::<Vec<_>>(),
        [300, 171, 143]
    );
    assert_eq!(calls[0].bind, [Bind::Name("conditioning".into())]);
    assert_eq!(
        calls[1].args[1],
        Arg::Slot {
            name: "conditioning".into()
        }
    );
    assert_eq!(calls[1].bind, [Bind::Name("latents".into())]);
    assert_eq!(
        calls[2].args[0],
        Arg::Slot {
            name: "latents".into()
        }
    );
    assert_eq!(calls[2].bind, [Bind::Name(OUTPUT.into())]);
    assert_eq!(
        job.plan.outputs,
        [Declared {
            slot: OUTPUT.into(),
            kind: OutputKind::Buffer {
                max_bytes: 16 * 16 * 12
            }
        }]
    );
    let tokens = text::tokenize(&fixture(), request.prompt).unwrap();
    assert_eq!(
        job.inputs[1].bytes.as_bytes(),
        tokens
            .ids
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    );
    assert_eq!(calls[0].args[1], Arg::U64(tokens.valid as u64));
    assert_eq!(job.inputs[0].bytes.as_bytes().len(), 128 * 4);
    let next = package
        .render_job(&ModelRequest::Image(ImageRequest {
            seed: 43,
            ..request
        }))
        .unwrap();
    assert_ne!(job.inputs[0].bytes, next.inputs[0].bytes);
    assert_eq!(
        job.environment, next.environment,
        "seed is input, not program identity"
    );
}

#[test]
fn shipped_flux_program_matches_catena_models() {
    let request = request();
    let package = ModelPackage::open(&fixture()).unwrap();
    let job = package.render_job(&ModelRequest::Image(request)).unwrap();
    let config = Config::read(&fixture()).unwrap();
    let model = config
        .source(request.width, request.height, request.steps)
        .unwrap();
    crate::model::program::assert_shipped_module(&job, &model);
}

#[test]
fn image_bounds_are_checked_before_rendering_or_allocating_noise() {
    let model = ModelPackage::open(&fixture()).unwrap();
    for (width, height, steps) in [
        (0, 16, 1),
        (15, 16, 1),
        (528, 16, 1),
        (16, 528, 1),
        (usize::MAX, 16, 1),
        (16, 16, 0),
        (16, 16, MAX_STEPS + 1),
    ] {
        assert!(
            model
                .render_job(&ModelRequest::Image(ImageRequest {
                    width,
                    height,
                    steps,
                    ..request()
                }))
                .is_err()
        );
    }
    assert!(noise(0, usize::MAX, 512).is_err());
    assert!(
        ImageRequest {
            width: 512,
            height: 512,
            steps: MAX_STEPS,
            ..request()
        }
        .validate()
        .is_ok()
    );
    assert!(
        ImageRequest {
            prompt: "",
            ..request()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn tokenizer_ids_outside_the_model_vocabulary_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    for name in METADATA.into_iter().chain(["assets.json"]) {
        let target = directory.path().join(name);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(fixture().join(name), target).unwrap();
    }
    let path = directory.path().join("tokenizer/tokenizer.json");
    let mut tokenizer: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let text = format!(
        "<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n",
        request().prompt
    );
    tokenizer["model"]["vocab"][text] = serde_json::json!(151936);
    std::fs::write(path, serde_json::to_vec(&tokenizer).unwrap()).unwrap();
    assert_eq!(
        text::tokenize(directory.path(), request().prompt)
            .unwrap()
            .ids[0],
        151936
    );
    let package = ModelPackage::open(directory.path()).unwrap();
    let error = package
        .render_job(&ModelRequest::Image(request()))
        .err()
        .expect("out-of-vocabulary token refused");
    assert!(error.to_string().contains("token exceeds vocabulary"));
}

#[test]
fn converted_weights_match_upstream_storage_and_reject_invalid_tensors() {
    use safetensors::{Dtype, tensor::TensorView};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("model.safetensors");
    let f32_bits = [0x3f800000u32, 0x3f808000, 0x3f818000, 0x7f800001];
    let f32_bytes: Vec<_> = f32_bits.into_iter().flat_map(u32::to_le_bytes).collect();
    let bf16_bits = [0u16, 0x8000, 0x7f81, 0xffff];
    let bf16_bytes: Vec<_> = bf16_bits.into_iter().flat_map(u16::to_le_bytes).collect();
    safetensors::serialize_to_file(
        [
            (
                "float",
                TensorView::new(Dtype::F32, vec![4], &f32_bytes).unwrap(),
            ),
            (
                "bf16",
                TensorView::new(Dtype::BF16, vec![4], &bf16_bytes).unwrap(),
            ),
            (
                "half",
                TensorView::new(Dtype::F16, vec![4], &bf16_bytes).unwrap(),
            ),
        ],
        None,
        &path,
    )
    .unwrap();
    let checkpoint = catena_models::weights::Weights::open(&path).unwrap();
    for (name, f32, expected) in [
        ("float", true, f32_bytes),
        (
            "float",
            false,
            [0x3f80u16, 0x3f80, 0x3f82, 0x7fc0]
                .into_iter()
                .flat_map(u16::to_le_bytes)
                .collect(),
        ),
        ("bf16", false, bf16_bytes),
        (
            "bf16",
            true,
            bf16_bits
                .into_iter()
                .flat_map(|v| ((v as u32) << 16).to_le_bytes())
                .collect(),
        ),
    ] {
        let mut bytes = Vec::new();
        weights::write(
            &mut bytes,
            &checkpoint,
            &weights::Tensor {
                name: name.into(),
                shape: vec![4],
                f32,
            },
        )
        .unwrap();
        assert_eq!(bytes, expected, "{name} storage f32={f32}");
    }
    for (name, shape) in [("float", vec![2]), ("half", vec![4])] {
        let mut bytes = Vec::new();
        assert!(
            weights::write(
                &mut bytes,
                &checkpoint,
                &weights::Tensor {
                    name: name.into(),
                    shape,
                    f32: false
                }
            )
            .is_err()
        );
        assert!(bytes.is_empty());
    }
}

#[test]
fn image_output_is_checked_and_png_quantization_matches_upstream() {
    let model = ModelPackage::open(&fixture()).unwrap();
    let mut values = vec![0f32; 16 * 16 * 3];
    values[..6].copy_from_slice(&[-1., 0.5 / 255., 1.5 / 255., 0.5, 1., 2.]);
    let output = |values: &[f32]| InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: vec![Artifact::new(
            OUTPUT,
            "catena.bytes.v1",
            values.iter().flat_map(|v| v.to_le_bytes()).collect(),
        )],
        metadata: JsonBytes(
            hellas_rpc::canonical_dag_cbor(&RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let ModelResponse::Image(image) = model.decode(&output(&values)).unwrap() else {
        panic!("image response")
    };
    assert!(image.png(32, 16).is_err());
    let png = image.png(16, 16).unwrap();
    let mut reader = png::Decoder::new(std::io::Cursor::new(png))
        .read_info()
        .unwrap();
    let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
    let frame = reader.next_frame(&mut pixels).unwrap();
    assert_eq!((frame.width, frame.height), (16, 16));
    assert_eq!(&pixels[..6], &[0, 0, 2, 128, 255, 255]);
    values[0] = f32::NAN;
    assert!(model.decode(&output(&values)).is_err());
    assert!(model.decode(&output(&[])).is_err());
    let mut invalid = output(&[0., 0., 0.]);
    invalid.artifacts[0].format = "catena.f32le.v1".into();
    assert!(model.decode(&invalid).is_err());
    invalid.outcome =
        Outcome::Failed(hellas_rpc::protocol::invocation::output::FailureReason::Execution);
    assert!(model.decode(&invalid).is_err());
}
