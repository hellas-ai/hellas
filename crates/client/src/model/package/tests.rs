impl ModelPackage {
    async fn text_job(
        &self,
        prompt_ids: &[u64],
        max_new: u64,
        stops: &[u64],
    ) -> Result<ComputeJob> {
        self.render_job(&ModelRequest::Text {
            prompt_ids,
            max_new,
            stops,
        })
        .await
    }
}
use super::*;
use crate::model::gguf;
use hellas_rpc::{ContentRef, protocol::invocation::compute::*};
use std::fs::File;

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/package/mini-qwen3.gguf")
}

#[tokio::test]
async fn canonical_qwen3_job_bytes_are_stable() {
    let package = ModelPackage::open(
        &fixture(),
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    let job = package.text_job(&[2, 1], 2, &[0, 0]).await.unwrap();
    assert_eq!(
        job.environment.canonical_bytes().unwrap(),
        include_bytes!("qwen3-environment.cbor")
    );
    assert_eq!(
        job.plan.canonical_bytes().unwrap(),
        include_bytes!("qwen3-plan.cbor")
    );
}

/// `hellas program` prints what `serve --program` admits: it must be the
/// manifest of every job the model renders, whatever the request.
#[tokio::test]
async fn program_is_the_manifest_every_rendered_job_runs() {
    let qwen = ModelPackage::open(
        &fixture(),
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    for (prompt, max_new) in [(&[2, 1][..], 2), (&[1][..], 1)] {
        let job = qwen.text_job(prompt, max_new, &[0]).await.unwrap();
        let manifest = job
            .environment
            .manifest(&crate::model::evaluator(crate::model::GpuDialect::Hip))
            .unwrap()
            .content_id();
        assert_eq!(qwen.program().unwrap().manifest, manifest);
    }
    let whisper = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/model/whisper/mini");
    let whisper = ModelPackage::open(
        &whisper,
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    for (language, max_new_tokens) in [(Some("en"), 4), (None, 2)] {
        let job = whisper
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language,
                max_new_tokens,
            })
            .await
            .unwrap();
        let manifest = job
            .environment
            .manifest(&crate::model::evaluator(crate::model::GpuDialect::Hip))
            .unwrap()
            .content_id();
        assert_eq!(whisper.program().unwrap().manifest, manifest);
    }
}

#[tokio::test]
async fn tiny_gguf_renders_the_complete_qwen3_step_job() {
    let package = ModelPackage::open(
        &fixture(),
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    let job = package.text_job(&[2, 1], 2, &[0, 0]).await.unwrap();

    let [source] = job.environment.sources[..] else {
        panic!("one rendered source")
    };
    assert!(
        std::str::from_utf8(
            &hellas_channel::content::read(
                &job.content.0,
                &job.content.1,
                source,
                (source).bytes()
            )
            .await
            .unwrap()
        )
        .unwrap()
        .contains("qwen3")
    );
    let root = job.environment.canonical_bytes().unwrap();
    assert_eq!(
        *hellas_channel::content::read(
            &job.content.0,
            &job.content.1,
            ContentRef::for_bytes(&root),
            (ContentRef::for_bytes(&root)).bytes()
        )
        .await
        .unwrap(),
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
        hellas_channel::content::read(
            &job.content.0,
            &job.content.1,
            asset.object,
            (asset.object).bytes()
        )
        .await,
        Err(hellas_store::content::Error::Missing)
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

#[tokio::test]
async fn empty_oversized_and_out_of_vocabulary_requests_are_refused() {
    let package = ModelPackage::open(
        &fixture(),
        &crate::model::evaluator(crate::model::GpuDialect::Hip),
    )
    .await
    .unwrap();
    assert!(package.text_job(&[], 1, &[]).await.is_err());
    assert!(package.text_job(&[2], 0, &[]).await.is_err());
    assert!(package.text_job(&[2], 128, &[]).await.is_err());
    assert!(package.text_job(&[2], u64::MAX, &[]).await.is_err());
    assert!(package.text_job(&[4], 1, &[]).await.is_err());
    assert!(package.text_job(&[2], 1, &[4]).await.is_err());
    assert!(package.text_job(&[2], 127, &[3]).await.is_ok());
}

mod qwen35;
