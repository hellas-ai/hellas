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
    client: ClientArgs,
    /// Local or pinned Hub d1 GGUF; the provider holds the matching weights.
    #[arg(long, value_name = "MODEL")]
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
            let (evaluator, package) = args
                .target
                .open_model(&args.client, &context, &mut args.model)
                .await?;
            let preparing = package.clone();
            let request =
                tokio::task::spawn_blocking(move || preparing.decision_request(body)).await??;
            // The model's name is its file's, as on a gateway route.
            let name = package.gguf_name()?;
            ensure!(
                request.model().is_none_or(|model| model == name),
                "request names another model than {name}"
            );
            let rendered = package.render_job(&request.job()).await?;
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
                    let response = package.decision_response(
                        name,
                        &request,
                        package.decode(&completed.output)?,
                    )?;
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
