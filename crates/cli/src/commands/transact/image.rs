use super::*;
use hellas_client::model::{ModelRequest, ModelResponse, flux::ImageRequest};

#[derive(Debug, Args)]
pub struct ImageArgs {
    #[command(flatten)]
    placement: ModelArgs,
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
    #[arg(short = 'o', long, default_value = "image.png", value_name = "PNG")]
    output: PathBuf,
}

pub async fn image(mut args: ImageArgs, context: &Context) -> super::super::CliResult<()> {
    let request = ImageRequest {
        prompt: &args.prompt,
        seed: args.seed,
        width: args.width,
        height: args.height,
        steps: args.steps,
    };
    request.validate()?;
    let package = args.placement.open(context, None).await?;
    let rendered = package.render_job(&ModelRequest::Image(request)).await?;
    args.placement
        .run(
            context,
            &package,
            rendered,
            |directory| Some(directory.join("result")),
            |response| {
                let ModelResponse::Image(image) = response else {
                    bail!("expected image");
                };
                std::fs::write(&args.output, image.png(args.width, args.height)?)?;
                println!("{}", args.output.display());
                Ok(())
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn image_cli_prepares_a_saved_job_with_provider_held_weights() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/flux/fixture");
        let root = tempfile::tempdir().unwrap();
        let rendered =
            hellas_client::model::flux::fixture(&model, hellas_client::model::GpuDialect::Hip)
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
        assert_eq!(plan.calls.len(), 5);
        assert_eq!(environment.sources.len(), 1);
        assert!(
            content
                .0
                .open_verified(&content.1, environment.sources[0], None)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            environment
                .model
                .assets
                .iter()
                .filter(|a| a.name.ends_with(".safetensors"))
                .count(),
            3
        );
        for asset in &environment.model.assets {
            let saved = content
                .0
                .open_verified(&content.1, asset.object, None)
                .await
                .unwrap();
            assert_eq!(saved.is_none(), asset.name.ends_with(".safetensors"));
        }
    }
}
