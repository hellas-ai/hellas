use super::*;
use hellas_channel::content::InvocationContent;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, flux::ImageRequest};

#[derive(Debug, Args)]
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
    #[arg(long)]
    payment: u64,
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
        args.payment,
        &args.client.root(&context),
    )?;
    eprintln!("job: {}", directory.display());
    bounded(
        args.client.timeout,
        async {
            let (mut purchase, result) = purchase_and_execute(&args.client, &context, &job).await?;
            let ModelResponse::Image(image) = package.decode(&result.output)? else {
                bail!("expected image");
            };
            let png = image.png(args.width, args.height)?;
            std::fs::write(&args.output, png)?;
            save_outputs(&directory.join("result"), &job, &result)?;
            println!("{}", args.output.display());
            std::io::stdout().lock().flush()?;
            purchase.reported()?;
            Ok(())
        },
        |timeout| {
            format!("image generation exceeded {timeout:?}; use the saved job folder to recover the existing attempt")
        },
    )
    .await
}

fn prepare(
    model: &Path,
    request: ImageRequest<'_>,
    payment: u64,
    root: &Path,
) -> anyhow::Result<(ModelPackage, Job, PathBuf)> {
    request.validate()?;
    let package = ModelPackage::open(model)?;
    let rendered = package.render_job(&ModelRequest::Image(request))?;
    let job = Job::compute(
        payment,
        rendered.environment,
        rendered.plan,
        rendered.inputs,
        InvocationContent::Ephemeral(rendered.content),
    )?;
    let directory = root.join("jobs").join(job.digest().to_string());
    job.save(&directory)?;
    Ok((package, job, directory))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_cli_prepares_a_saved_job_with_provider_held_weights() {
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
        .unwrap();
        let loaded = Job::load(&directory).unwrap();
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
        assert!(content.read(environment.sources[0]).is_ok());
        assert_eq!(environment.assets.len(), 3);
        assert!(environment.assets.iter().all(|asset| matches!(
            content.read(asset.object),
            Err(hellas_channel::content::ContentError::Missing)
        )));
    }
}
