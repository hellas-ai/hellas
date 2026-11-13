use super::*;
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
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
    #[arg(short = 'o', long, default_value = "image.png", value_name = "PNG")]
    output: PathBuf,
}

pub async fn image(mut args: ImageArgs, context: Context) -> super::super::CliResult<()> {
    context
        .model_command(async {
            args.target.models = vec![args.model.clone()];
            let request = ImageRequest {
                prompt: &args.prompt,
                seed: args.seed,
                width: args.width,
                height: args.height,
                steps: args.steps,
            };
            request.validate()?;
            let evaluator = args.target.renderer()?;
            let content = args.target.content(&context).await?;
            let package =
                ModelPackage::open_many(&args.model, [evaluator.clone()], content.as_ref())
                    .await?
                    .remove(&evaluator)
                    .context("model evaluator is not prepared")?;
            let rendered = package.render_job(&ModelRequest::Image(request)).await?;
            let target = args.target;
            run_quoted(
                &args.client,
                target,
                &context,
                args.pay,
                None,
                async |price| compute_job(price, evaluator, rendered).await,
                |directory| Some(directory.join("result")),
                |_, completed, _| {
                    let ModelResponse::Image(image) = package.decode(&completed.output)? else {
                        bail!("expected image");
                    };
                    std::fs::write(&args.output, image.png(args.width, args.height)?)?;
                    println!("{}", args.output.display());
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
    async fn image_cli_prepares_a_saved_job_with_provider_held_weights() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/flux/fixture");
        let root = tempfile::tempdir().unwrap();
        let rendered = ModelPackage::open(
            &model,
            &hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
        )
        .await
        .unwrap()
        .render_job(&ModelRequest::Image(ImageRequest {
            prompt: "a red fox",
            seed: 42,
            width: 16,
            height: 16,
            steps: 1,
        }))
        .await
        .unwrap();
        let job = Job::compute(
            20,
            hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip),
            rendered.environment,
            rendered.plan,
            rendered.inputs,
            rendered.content,
        )
        .await
        .unwrap();
        let directory = root.path().join("job");
        job.save(&directory).await.unwrap();
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
