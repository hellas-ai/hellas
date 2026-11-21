use super::*;
use crate::model::{GpuDialect, ModelKind, evaluator};
use hellas_rpc::{
    JsonBytes,
    protocol::invocation::{
        Artifact,
        compute::RunMetadata,
        output::{InvocationOutput, Outcome},
    },
};
use serde_json::json;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/model/package")
        .join(name)
}

fn body() -> Value {
    json!({
        "state": "charged twice",
        "questions": {
            "refund": {"type": "noul", "instructions": "refund?"},
            "team": {
                "type": "choice",
                "instructions": "team?",
                "criteria": {"billing": "charges", "technical": "faults"}
            },
            "urgency": {"type": "score", "instructions": "urgent?", "criteria": ["wait", "now"]}
        }
    })
}

#[tokio::test]
async fn decisions_prefill_each_question_and_read_its_logits() {
    let path = fixture("mini-d1");
    assert_eq!(ModelKind::of(&path).unwrap(), ModelKind::Decision);
    let package = ModelPackage::open(&path, &evaluator(GpuDialect::Hip))
        .await
        .unwrap();
    assert_eq!(package.kind(), ModelKind::Decision);
    let decision = Decision::open(&path).unwrap();
    let request = decision.prepare(body()).unwrap();
    assert_eq!(request.model(), None);

    let job = package.render_job(&request.job()).await.unwrap();
    let entries: Vec<_> = job.plan.calls.iter().map(|c| c.entry.as_str()).collect();
    assert_eq!(entries, ["qwen3.init", "qwen3"].repeat(3));
    assert!(job.plan.step.is_none());
    let names = |prefix: &str| -> Vec<_> { (0..3).map(|i| format!("{prefix}-{i:02}")).collect() };
    assert_eq!(
        job.inputs.iter().map(|a| &a.name).collect::<Vec<_>>(),
        names("prompt").iter().collect::<Vec<_>>()
    );
    assert_eq!(
        job.plan.outputs.iter().map(|d| &d.slot).collect::<Vec<_>>(),
        names("logits").iter().collect::<Vec<_>>()
    );
    for (input, prompt) in job.inputs.iter().zip(&request.prompts) {
        let bytes: Vec<u8> = prompt.iter().flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(input.bytes.as_bytes(), bytes);
    }
    let error = package
        .render_job(&ModelRequest::Text {
            prompt_ids: &[1],
            max_new: 1,
            stops: &[],
        })
        .await
        .err()
        .expect("a decision model generates no text");
    assert!(error.to_string().contains("do not generate text"));

    // Favor "yes", the first choice and the last score: BF16 2.0 is 0x4000.
    let vocabulary = 102;
    let favored = [
        request.prepared[0].groups[0][0],
        request.prepared[1].groups[0][0],
        request.prepared[2].groups[1][0],
    ];
    let output = InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: names("logits")
            .into_iter()
            .zip(favored)
            .map(|(name, id)| {
                let mut logits = vec![0u8; vocabulary * 2];
                logits[id as usize * 2 + 1] = 0x40;
                Artifact::new(name, "catena.bytes.v1", logits)
            })
            .collect(),
        metadata: JsonBytes(
            hellas_rpc::canonical_dag_cbor(&RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let response = decision
        .respond("mini", &request, package.decode(&output).unwrap())
        .unwrap();
    assert_eq!(response["model"], "mini");
    let tokens: usize = request.prompts.iter().map(Vec::len).sum();
    assert_eq!(
        response["usage"],
        json!({"input_tokens": tokens, "output_tokens": 0})
    );
    let answers = &response["answers"];
    assert!(answers["refund"]["noul"].as_f64().unwrap() > 0.5);
    assert_eq!(answers["team"]["choice"], "billing");
    assert_eq!(answers["urgency"]["score"], 1.0);

    let mut short = output;
    short.artifacts.pop();
    assert!(
        decision
            .respond("mini", &request, package.decode(&short).unwrap())
            .is_err()
    );
}

#[tokio::test]
async fn decisions_reject_images_and_text_models() {
    let decision = Decision::open(&fixture("mini-d1")).unwrap();
    let mut png = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png, 1, 1);
        encoder.set_color(png::ColorType::Rgb);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&[0, 0, 0])
            .unwrap();
    }
    use base64::Engine as _;
    let image = format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    );
    for key in ["images", "files"] {
        let mut body = body();
        body[key] = json!([image]);
        let error = decision.prepare(body).err().expect("images are rejected");
        assert!(error.is::<InvalidRequest>());
        assert!(error.to_string().contains("text only"), "{error}");
    }
    let error = decision
        .prepare(json!({"questions": {}}))
        .err()
        .expect("a request needs state");
    assert!(error.is::<InvalidRequest>());

    let text = fixture("mini-qwen3.gguf");
    assert_eq!(ModelKind::of(&text).unwrap(), ModelKind::Text);
    assert!(Decision::open(&text).is_err());
    let package = ModelPackage::open(&text, &evaluator(GpuDialect::Hip))
        .await
        .unwrap();
    let error = package
        .render_job(&ModelRequest::Decision {
            prompts: &[vec![1]],
        })
        .await
        .err()
        .expect("a text model answers no decisions");
    assert!(error.to_string().contains("does not answer decisions"));
}
