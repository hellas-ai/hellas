use super::*;
#[cfg(test)]
use hellas_client::model::ModelPackage;
use hellas_client::model::{ModelRequest, ModelResponse, wav};

#[derive(Debug, Args)]
pub struct TranscribeArgs {
    #[command(flatten)]
    placement: ModelArgs,
    #[arg(long, value_name = "WAV")]
    audio: PathBuf,
    #[arg(long)]
    language: Option<String>,
    #[arg(long, default_value_t = 256)]
    max_tokens: usize,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn transcribe(
    mut args: TranscribeArgs,
    context: &Context,
) -> super::super::CliResult<()> {
    let samples = wav::decode(&super::super::read_bounded_regular_file(
        &args.audio,
        "WAV",
        wav::MAX_WAV_BYTES,
    )?)?;
    let package = args.placement.open(context, None).await?;
    let rendered = package
        .render_job(&ModelRequest::Transcription {
            samples: &samples,
            language: args.language.as_deref(),
            max_new_tokens: args.max_tokens,
        })
        .await?;
    args.placement
        .run(
            context,
            &package,
            rendered,
            |_| args.output.clone(),
            |response| {
                let ModelResponse::Transcription(transcription) = response else {
                    bail!("expected transcription");
                };
                println!("{}", transcription.text);
                Ok(())
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
        let package = ModelPackage::open(
            &path,
            &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
        )
        .await
        .unwrap();
        let job = package
            .render_job(&ModelRequest::Transcription {
                samples: &[0.; 400],
                language: Some("en"),
                max_new_tokens: 4,
            })
            .await
            .unwrap();
        super::check_rendered_plan(&job, 64, |plan| {
            plan.calls[0].args[0] = hellas_rpc::protocol::invocation::compute::Arg::U64(0);
        })
        .await;
    }
}
