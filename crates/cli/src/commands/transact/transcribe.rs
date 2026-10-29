use super::*;
use hellas_channel::content::InvocationContent;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, wav};

#[derive(Debug, Args)]
pub struct TranscribeArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Converted Whisper client package directory.
    #[arg(long, value_name = "DIR")]
    model: PathBuf,
    #[arg(long, value_name = "WAV")]
    audio: PathBuf,
    #[arg(long)]
    language: Option<String>,
    #[arg(long, default_value_t = 256)]
    max_tokens: usize,
    #[arg(long)]
    payment: u64,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn transcribe(args: TranscribeArgs, context: Context) -> super::super::CliResult<()> {
    let package = ModelPackage::open(&args.model)?;
    let samples = wav::decode(&super::super::read_bounded_regular_file(
        &args.audio,
        "WAV",
        wav::MAX_WAV_BYTES,
    )?)?;
    let rendered = package.render_job(&ModelRequest::Transcription {
        samples: &samples,
        language: args.language.as_deref(),
        max_new_tokens: args.max_tokens,
    })?;
    let job = Job::compute(
        args.payment,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        InvocationContent::Ephemeral(rendered.content),
    )?;
    let directory = args
        .client
        .root(&context)
        .join("jobs")
        .join(job.digest().to_string());
    job.save(&directory)?;
    eprintln!("job: {}", directory.display());
    bounded(
        args.client.timeout,
        async {
            let options = args
                .client
                .options(&context, job.price(), job.assurance())
                .await?;
            let mut purchase = args.client.purchase(&context, &job, &options).await?;
            let endpoint = bind_paid_endpoint(context.transport.clone()).await?;
            let result = execute(
                &args.client,
                &context,
                &job,
                options,
                endpoint.clone(),
                &mut purchase,
            )
            .await;
            endpoint.close().await;
            let result = result?;
            if let Some(directory) = &args.output {
                save_outputs(directory, &job, &result)?;
            }
            let ModelResponse::Transcription(transcription) = package.decode(&result.output)?
            else {
                bail!("expected transcription");
            };
            println!("{}", transcription.text);
            std::io::stdout().lock().flush()?;
            purchase.reported()?;
            Ok(())
        },
        |timeout| {
            format!("transcription exceeded {timeout:?}; retry the saved job folder to resume")
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn whisper_plan_validates_against_the_compiled_bundle() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
        let package = ModelPackage::open(&path).unwrap();
        let mut job = package
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: Some("en"),
                max_new_tokens: 4,
            })
            .unwrap();
        let source =
            String::from_utf8((*job.content.read(job.environment.sources[0]).unwrap()).clone())
                .unwrap();
        let module = hellas_executor::catena::compile::compile_sources(
            &[source],
            catena_lang::codegen::GpuDialect::Hip,
        )
        .unwrap();
        let mut content = job.content.clone();
        let inputs = job
            .inputs
            .iter()
            .map(|a| (a.name.clone(), content.insert(a.bytes.as_bytes().to_vec())))
            .collect();
        content.insert(std::fs::read(path.join("weights.bf16")).unwrap());
        let content = InvocationContent::Ephemeral(content);
        let limits = hellas_rpc::protocol::invocation::Limits {
            max_upload_bytes: 4 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 64,
            execution_timeout_ms: 90000,
        };
        hellas_executor::catena::validate::validate(
            &module,
            &job.environment,
            &inputs,
            &job.plan,
            &limits,
            &content,
        )
        .unwrap();
        job.plan.calls[0].args[0] = hellas_rpc::protocol::invocation::compute::Arg::U64(0);
        assert!(
            hellas_executor::catena::validate::validate(
                &module,
                &job.environment,
                &inputs,
                &job.plan,
                &limits,
                &content
            )
            .is_err()
        );
    }
}
