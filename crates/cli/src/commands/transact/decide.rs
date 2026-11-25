//! `hellas decide`: one decision request, expanded here into a prompt per
//! question and run as a Compute job.
use super::*;
#[cfg(test)]
use hellas_client::model::ModelPackage;
use std::io::Read;

const MAX_REQUEST_BYTES: usize = 1 << 20;

#[derive(Debug, Args)]
pub struct DecideArgs {
    #[command(flatten)]
    placement: ModelArgs,
    /// Request JSON file; `-` reads standard input.
    #[arg(long, value_name = "FILE", default_value = "-")]
    request: PathBuf,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn decide(mut args: DecideArgs, context: &Context) -> super::super::CliResult<()> {
    let body = if args.request == Path::new("-") {
        let mut body = Vec::new();
        std::io::stdin()
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        ensure!(
            body.len() <= MAX_REQUEST_BYTES,
            "request exceeds {MAX_REQUEST_BYTES} bytes"
        );
        body
    } else {
        super::super::read_bounded_regular_file(&args.request, "request", MAX_REQUEST_BYTES)?
    };
    let body = serde_json::from_slice(&body).context("request is not JSON")?;
    let package = args.placement.open(context, None).await?;
    let preparing = package.clone();
    let request = tokio::task::spawn_blocking(move || preparing.decision_request(body)).await??;
    // The model's name is its file's, as on a gateway route.
    let name = package.gguf_name()?;
    ensure!(
        request.model().is_none_or(|model| model == name),
        "request names another model than {name}"
    );
    let rendered = package.render_job(&request.job()).await?;
    args.placement
        .run(
            context,
            &package,
            rendered,
            |_| args.output.clone(),
            |response| {
                let response = package.decision_response(name, &request, response)?;
                println!("{response}");
                Ok(())
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn decision_plan_validates_against_the_compiled_bundle() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/package/mini-d1.gguf");
        let package = ModelPackage::open(
            &path,
            &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
        )
        .await
        .unwrap();
        let request = package
            .decision_request(serde_json::json!({
                "state": "charged twice",
                "questions": {
                    "refund": {"type": "noul", "instructions": "refund?"},
                    "urgency": {"type": "score", "instructions": "urgent?", "criteria": ["wait", "now"]}
                }
            }))
            .unwrap();
        let job = package.render_job(&request.job()).await.unwrap();
        super::check_rendered_plan(&job, 1, |plan| {
            use hellas_rpc::protocol::invocation::compute::{OutputKind, ValueKind};
            plan.outputs[0].kind = OutputKind::Scalar(ValueKind::U64);
        })
        .await;
    }
}
