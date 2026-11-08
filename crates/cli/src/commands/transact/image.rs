use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, flux::ImageRequest};

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("execution_target").required(true).multiple(true).args(["provider", "offer"])))]
pub struct ImageArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Converted Flux2 Klein package directory.
    #[arg(long, value_name = "DIR")]
    model: PathBuf,
    #[arg(long)]
    prompt: String,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    #[arg(long, default_value_t = 512)]
    width: usize,
    #[arg(long, default_value_t = 512)]
    height: usize,
    #[arg(long, default_value_t = 4)]
    steps: usize,
    #[arg(long, required_unless_present = "offer", conflicts_with = "offer", value_parser = clap::value_parser!(u64).range(1..))]
    payment: Option<u64>,
    #[command(flatten)]
    grant: grant::GrantArgs,
    #[arg(short = 'o', long, default_value = "image.png", value_name = "PNG")]
    output: PathBuf,
}

pub async fn image(args: ImageArgs, context: Context) -> super::super::CliResult<()> {
    let request = ImageRequest {
        prompt: &args.prompt,
        seed: args.seed,
        width: args.width,
        height: args.height,
        steps: args.steps,
    };
    let (package, job, directory) = prepare(
        &args.model,
        request,
        args.payment.unwrap_or(0),
        &args.client.root(&context),
    )
    .await?;
    eprintln!("job: {}", directory.display());
    bounded(
        &context,
        args.client.timeout,
        async {
            if args.grant.offer.is_some() {
                let mut result = grant::execute(&args.grant, &args.client, &context, &job).await?;
                result.save(&directory.join("result"), &job)?;
                result.ensure_succeeded()?;
                let ModelResponse::Image(image) = package.decode(&result.retained.output)? else { bail!("expected image") };
                std::fs::write(&args.output, image.png(args.width, args.height)?)?;
                println!("{}", args.output.display());
                std::io::stdout().lock().flush()?;
                result.attempt.reported()?;
                return Ok(());
            }
            purchase_and_execute(&args.client, &context, &job, |result| {
            let ModelResponse::Image(image) = package.decode(&result.output)? else {
                bail!("expected image");
            };
            let png = image.png(args.width, args.height)?;
            std::fs::write(&args.output, png)?;
            save_outputs(&directory.join("result"), &job, result)?;
            println!("{}", args.output.display());
            std::io::stdout().lock().flush()?;
            Ok(())
            }).await
        },
        |timeout| {
            format!("image generation exceeded {timeout:?}; use the saved job folder to recover the existing attempt")
        },
    )
    .await
}

async fn prepare(
    model: &Path,
    request: ImageRequest<'_>,
    payment: u64,
    root: &Path,
) -> anyhow::Result<(ModelPackage, Job, PathBuf)> {
    request.validate()?;
    let package = ModelPackage::open(model).await?;
    let rendered = package.render_job(&ModelRequest::Image(request)).await?;
    let job = Job::compute(
        payment,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        rendered.content,
    )
    .await?;
    let directory = root.join("jobs").join(job.digest().to_string());
    job.save(&directory).await?;
    Ok((package, job, directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn image_cli_prepares_a_saved_job_with_provider_held_weights() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/flux/fixture");
        let root = tempfile::tempdir().unwrap();
        let (_, job, directory) = prepare(
            &model,
            ImageRequest {
                prompt: "a red fox",
                seed: 42,
                width: 16,
                height: 16,
                steps: 1,
            },
            20,
            root.path(),
        )
        .await
        .unwrap();
        let loaded = Job::load(&directory).await.unwrap();
        assert_eq!(loaded.digest(), job.digest());
        let JobInput::Compute {
            environment,
            plan,
            content,
            ..
        } = loaded.input()
        else {
            panic!()
        };
        assert_eq!(plan.calls.len(), 3);
        assert_eq!(environment.sources.len(), 1);
        assert!(
            content
                .0
                .open_verified(&content.1, environment.sources[0], None)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(environment.assets.len(), 3);
        for asset in &environment.assets {
            assert!(
                content
                    .0
                    .open_verified(&content.1, asset.object, None)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
