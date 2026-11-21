//! `hellas decide`: one decision request, expanded here into a prompt per
//! question and run as a Compute job.
use super::*;
use hellas_client::model::{ModelPackage, decision::Decision};
use std::io::Read;

const MAX_REQUEST_BYTES: usize = 1 << 20;

#[derive(Debug, Args)]
pub struct DecideArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// d1 decision GGUF or descriptor; the provider holds the matching weights.
    #[arg(long, value_name = "PATH")]
    model: PathBuf,
    /// Request JSON file; `-` reads standard input.
    #[arg(long, value_name = "FILE", default_value = "-")]
    request: PathBuf,
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn decide(mut args: DecideArgs, context: Context) -> super::super::CliResult<()> {
    context
        .model_command(async {
            args.target.models = vec![args.model.clone()];
            let evaluator = args.target.renderer()?;
            let content = args.target.content(&context).await?;
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
                super::super::read_bounded_regular_file(
                    &args.request,
                    "request",
                    MAX_REQUEST_BYTES,
                )?
            };
            let body = serde_json::from_slice(&body).context("request is not JSON")?;
            let model = args.model.clone();
            let (decision, request) = tokio::task::spawn_blocking(move || {
                let decision = Decision::open(&model)?;
                let request = decision.prepare(body)?;
                anyhow::Ok((decision, request))
            })
            .await??;
            let package =
                ModelPackage::open_many(&args.model, [evaluator.clone()], content.as_ref())
                    .await?
                    .remove(&evaluator)
                    .context("model evaluator is not prepared")?;
            let rendered = package.render_job(&request.job()).await?;
            // The envelope names the model as the request does, else by its file.
            let name = match request.model() {
                Some(name) => name.to_owned(),
                None => args
                    .model
                    .file_stem()
                    .and_then(|name| name.to_str())
                    .context("model needs a UTF-8 name")?
                    .to_owned(),
            };
            let target = args.target;
            run_quoted(
                &args.client,
                target,
                &context,
                args.pay,
                None,
                async |price| compute_job(price, evaluator, rendered).await,
                |_| args.output.clone(),
                |_, completed, _| {
                    let response =
                        decision.respond(&name, &request, package.decode(&completed.output)?)?;
                    println!("{response}");
                    std::io::stdout().lock().flush()?;
                    Ok(())
                },
            )
            .await
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn decision_plan_validates_against_the_compiled_bundle() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/package/mini-d1");
        let package = ModelPackage::open(
            &path,
            &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
        )
        .await
        .unwrap();
        let request = Decision::open(&path)
            .unwrap()
            .prepare(serde_json::json!({
                "state": "charged twice",
                "questions": {
                    "refund": {"type": "noul", "instructions": "refund?"},
                    "urgency": {"type": "score", "instructions": "urgent?", "criteria": ["wait", "now"]}
                }
            }))
            .unwrap();
        let job = package.render_job(&request.job()).await.unwrap();
        let object = job.environment.sources[0];
        let source = hellas_channel::content::read(
            &job.content.0,
            &job.content.1,
            object,
            hellas_rpc::protocol::invocation::compute::MAX_SOURCE_BYTES,
        )
        .await
        .unwrap();
        let source = String::from_utf8(source.to_vec()).unwrap();
        let module = hellas_executor::catena::compile::compile_sources(
            &[source],
            catena_lang::codegen::GpuDialect::Hip,
        )
        .unwrap();
        let inputs = job
            .inputs
            .iter()
            .map(|a| {
                (
                    a.name.clone(),
                    hellas_rpc::ContentRef::for_bytes(a.bytes.as_bytes()),
                )
            })
            .collect();
        let limits = hellas_rpc::protocol::invocation::Limits {
            max_upload_bytes: 4 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 1,
            execution_timeout_ms: 90000,
        };
        let validate = |plan| {
            hellas_executor::catena::validate::validate(
                &module,
                &job.environment,
                &inputs,
                plan,
                &limits,
            )
        };
        validate(&job.plan).unwrap();
        // The logits are a buffer, not a scalar.
        let mut scalar = job.plan.clone();
        scalar.outputs[0].kind = hellas_rpc::protocol::invocation::compute::OutputKind::Scalar(
            hellas_rpc::protocol::invocation::compute::ValueKind::U64,
        );
        assert!(validate(&scalar).is_err());
    }
}
