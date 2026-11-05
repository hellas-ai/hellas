use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse, flux::ImageRequest};

#[derive(Debug, Args)]
pub struct ImageArgs {
    #[command(flatten)]
    task: task::TaskArgs,
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
    #[arg(short = 'o', long, default_value = "image.png", value_name = "PNG")]
    output: PathBuf,
}

impl ImageArgs {
    pub fn is_local(&self) -> bool {
        self.task.is_local()
    }
}

pub async fn image(args: ImageArgs, context: Option<Context>) -> super::super::CliResult<()> {
    let request = ImageRequest {
        prompt: &args.prompt,
        seed: args.seed,
        width: args.width,
        height: args.height,
        steps: args.steps,
    };
    request.validate()?;
    let package = ModelPackage::open(&args.model)?;
    let rendered = package.render_job(&ModelRequest::Image(request))?;
    let job = args.task.job(rendered, &args.model)?;
    let mut completion = args.task.execute(&job, context.as_ref()).await?;
    let ModelResponse::Image(image) = package.decode(&completion.output)? else {
        bail!("expected image")
    };
    std::fs::write(&args.output, image.png(args.width, args.height)?)?;
    println!("{}", args.output.display());
    std::io::stdout().lock().flush()?;
    task::deliver_and_settle(&mut completion).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn image_targets_preserve_the_same_canonical_input() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("../client/src/model/flux/fixture");
        let provider = format!("{}@{}", "11".repeat(32), "22".repeat(32));
        let mut targets = vec![
            vec!["--offer", "friend.image"],
            vec!["--provider", &provider, "--payment", "20"],
        ];
        if cfg!(feature = "heavy") {
            targets.push(vec!["--local"]);
        }
        let mut digest = None;
        for target in targets {
            let crate::Commands::Image(args) = crate::Cli::try_parse_from(
                [
                    "hellas",
                    "image",
                    "--model",
                    model.to_str().unwrap(),
                    "--prompt",
                    "fox",
                ]
                .into_iter()
                .chain(target),
            )
            .unwrap()
            .command
            else {
                unreachable!()
            };
            let package = ModelPackage::open(&model).unwrap();
            let rendered = package
                .render_job(&ModelRequest::Image(ImageRequest {
                    prompt: "fox",
                    seed: 42,
                    width: 16,
                    height: 16,
                    steps: 1,
                }))
                .unwrap();
            let job = args.task.job(rendered, &model).unwrap();
            let actual = job.input().tracking_digest();
            assert_eq!(*digest.get_or_insert(actual), actual);
        }
    }
}
