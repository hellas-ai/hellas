use super::*;

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/package/mini-qwen3.gguf")
}

#[test]
fn canonical_qwen3_job_bytes_are_stable() {
    let package = ModelPackage::open(&fixture()).unwrap();
    let job = package.render_job(&[2, 1], 2, &[0, 0]).unwrap();
    assert_eq!(
        job.environment.canonical_bytes().unwrap(),
        include_bytes!("qwen3-environment.cbor")
    );
    assert_eq!(
        job.plan.canonical_bytes().unwrap(),
        include_bytes!("qwen3-plan.cbor")
    );
}

#[test]
fn tiny_gguf_renders_the_complete_qwen3_step_job() {
    let package = ModelPackage::open(&fixture()).unwrap();
    let job = package.render_job(&[2, 1], 2, &[0, 0]).unwrap();

    let [source] = job.environment.sources[..] else {
        panic!("one rendered source")
    };
    assert!(
        std::str::from_utf8(&job.content.read(source).unwrap())
            .unwrap()
            .contains("qwen3")
    );
    let root = job.environment.canonical_bytes().unwrap();
    assert_eq!(
        *job.content.read(ContentRef::for_bytes(&root)).unwrap(),
        root
    );
    let [ref asset] = job.environment.assets[..] else {
        panic!("one weights asset")
    };
    assert_eq!(asset.name, "weights");
    assert_eq!(
        asset.object.bytes(),
        std::fs::metadata(fixture()).unwrap().len()
    );
    assert!(matches!(
        job.content.read(asset.object),
        Err(hellas_channel::content::ContentError::Missing)
    ));

    assert_eq!(
        job.inputs,
        vec![Artifact::new(
            "prompt",
            "catena.u64le.v1",
            [2u64, 1].iter().flat_map(|n| n.to_le_bytes()).collect()
        )]
    );
    assert_eq!(
        job.plan.calls,
        vec![Call {
            entry: "qwen3.init".into(),
            args: vec![Arg::U64(4)],
            bind: vec![Bind::Name("s0".into()), Bind::Name("s1".into())],
        }]
    );
    assert!(job.plan.outputs.is_empty());
    let step = job.plan.step.unwrap();
    assert_eq!(step.entry, "qwen3");
    assert_eq!(
        step.args[..5],
        [
            StepArg::FirstThen {
                first: Arg::Input {
                    object: "prompt".into()
                },
                then: Arg::Slot {
                    name: "next".into()
                }
            },
            StepArg::Arg(Arg::Slot { name: "s0".into() }),
            StepArg::Arg(Arg::Slot { name: "s1".into() }),
            StepArg::Arg(Arg::U64(4)),
            StepArg::FirstThen {
                first: Arg::U64(0),
                then: Arg::Counter { base: 1 }
            },
        ]
    );
    // The table order deliberately differs from the entry's weight order.
    let header = gguf::read_header(&mut File::open(fixture()).unwrap()).unwrap();
    let range = |name: &str| {
        let t = header.tensors.iter().find(|t| t.name == name).unwrap();
        StepArg::Arg(Arg::Asset {
            name: "weights".into(),
            offset: t.offset,
            bytes: t.bytes,
        })
    };
    assert_eq!(step.args.len(), 5 + 14);
    assert_eq!(step.args[5], range("token_embd.weight"));
    assert_eq!(
        step.args[5],
        *step.args.last().unwrap(),
        "tied output embedding aliases the same GGUF range"
    );
    assert_eq!(
        step.bind,
        vec![
            Bind::Name("s0".into()),
            Bind::Name("s1".into()),
            Bind::Discard,
            Bind::Name("next".into())
        ]
    );
    assert_eq!(step.emit, "next");
    assert_eq!(
        step.stop,
        Stop {
            any_of: vec![0, 3],
            max_steps: 2
        }
    );
}

#[test]
fn empty_oversized_and_out_of_vocabulary_requests_are_refused() {
    let package = ModelPackage::open(&fixture()).unwrap();
    assert!(package.render_job(&[], 1, &[]).is_err());
    assert!(package.render_job(&[2], 0, &[]).is_err());
    assert!(package.render_job(&[2], 128, &[]).is_err());
    assert!(package.render_job(&[2], u64::MAX, &[]).is_err());
    assert!(package.render_job(&[4], 1, &[]).is_err());
    assert!(package.render_job(&[2], 1, &[4]).is_err());
    assert!(package.render_job(&[2], 127, &[3]).is_ok());
}
