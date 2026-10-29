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
