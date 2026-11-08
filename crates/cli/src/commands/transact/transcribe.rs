use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, wav};

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "offer"])))]
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
    #[arg(long, required_unless_present = "offer", conflicts_with = "offer", value_parser = clap::value_parser!(u64).range(1..))]
    payment: Option<u64>,
    #[command(flatten)]
    grant: grant::GrantArgs,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn transcribe(args: TranscribeArgs, context: Context) -> super::super::CliResult<()> {
    let package = ModelPackage::open(&args.model).await?;
    let samples = wav::decode(&super::super::read_bounded_regular_file(
        &args.audio,
        "WAV",
        wav::MAX_WAV_BYTES,
    )?)?;
    let rendered = package
        .render_job(&ModelRequest::Transcription {
            samples: &samples,
            language: args.language.as_deref(),
            max_new_tokens: args.max_tokens,
        })
        .await?;
    let job = Job::compute(
        args.payment.unwrap_or(0),
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        rendered.content,
    )
    .await?;
    let directory = args
        .client
        .root(&context)
        .join("jobs")
        .join(job.digest().to_string());
    job.save(&directory).await?;
    eprintln!("job: {}", directory.display());
    bounded(
        &context,
        args.client.timeout,
        async {
            if args.grant.offer.is_some() {
                let mut result = grant::execute(&args.grant, &args.client, &context, &job).await?;
                if let Some(directory) = &args.output { result.save(directory, &job)?; }
                result.ensure_succeeded()?;
                let ModelResponse::Transcription(transcription) = package.decode(&result.retained.output)? else { bail!("expected transcription") };
                println!("{}", transcription.text);
                std::io::stdout().lock().flush()?;
                result.attempt.reported()?;
                return Ok(());
            }
            purchase_and_execute(&args.client, &context, &job, |result| {
            if let Some(directory) = &args.output {
                save_outputs(directory, &job, result)?;
            }
            let ModelResponse::Transcription(transcription) = package.decode(&result.output)?
            else {
                bail!("expected transcription");
            };
            println!("{}", transcription.text);
            std::io::stdout().lock().flush()?;
            Ok(())
            }).await
        },
        |timeout| {
            format!("transcription exceeded {timeout:?}; use the saved job folder to recover the existing attempt")
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn whisper_plan_validates_against_the_compiled_bundle() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/whisper/mini");
        let package = ModelPackage::open(&path).await.unwrap();
        let mut job = package
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: Some("en"),
                max_new_tokens: 4,
            })
            .await
            .unwrap();
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
            max_steps: 64,
            execution_timeout_ms: 90000,
        };
        hellas_executor::catena::validate::validate(
            &module,
            &job.environment,
            &inputs,
            &job.plan,
            &limits,
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
            )
            .is_err()
        );
    }
}
