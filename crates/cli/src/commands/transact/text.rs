//! `hellas text`: one chat turn, tokenized here in the model's chat format
//! and run as a Compute job.
use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_presentation::{ChatMessage, TextPresentation};

#[derive(Debug, Args)]
pub struct TextArgs {
    #[command(flatten)]
    placement: ModelArgs,
    #[arg(long)]
    prompt: String,
    #[arg(long)]
    system: Option<String>,
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..))]
    max_tokens: u64,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn text(mut args: TextArgs, context: &Context) -> super::super::CliResult<()> {
    let package = args.placement.open(context, None).await?;
    let (presentation, rendered) = prepare(&args, &package).await?;
    args.placement
        .run(
            context,
            &package,
            rendered,
            |_| args.output.clone(),
            |response| {
                let ModelResponse::Tokens(tokens) = response else {
                    bail!("expected generated tokens");
                };
                println!("{}", presentation.decode(&tokens)?);
                Ok(())
            },
        )
        .await
}

async fn prepare(
    args: &TextArgs,
    package: &Arc<ModelPackage>,
) -> anyhow::Result<(TextPresentation, hellas_client::model::ComputeJob)> {
    let metadata = package.clone();
    let presentation =
        tokio::task::spawn_blocking(move || TextPresentation::from_gguf(metadata.gguf_path()?))
            .await??;
    let messages: Vec<_> = args
        .system
        .iter()
        .map(|system| ("system", system))
        .chain([("user", &args.prompt)])
        .map(|(role, content)| ChatMessage {
            role: role.into(),
            content: content.clone(),
            ..Default::default()
        })
        .collect();
    let prompt: Vec<u64> = presentation
        .encode_chat(&messages, &[])?
        .into_iter()
        .map(u64::from)
        .collect();
    let rendered = package
        .render_job(&ModelRequest::Text {
            prompt_ids: &prompt,
            max_new: args.max_tokens,
            stops: &[],
        })
        .await?;
    Ok((presentation, rendered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[tokio::test]
    async fn text_cli_renders_one_chat_turn_as_a_compute_job() {
        let model = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../client/src/model/package/mini-qwen3.gguf");
        let model = model.display().to_string();
        let evaluator =
            hellas_client::model::evaluator(hellas_client::model::GpuDialect::Hip, "gfx1151");
        let parse = |system: &[&str]| {
            let mut argv = vec![
                "hellas",
                "text",
                "--model",
                &model,
                "--prompt",
                "hello",
                "--max-tokens",
                "3",
                "--access",
                "box.access",
                "--backend",
                &evaluator,
            ];
            argv.extend(system);
            let crate::Commands::Job(crate::commands::transact::JobCommand::Text(args)) =
                crate::Cli::try_parse_from(argv).unwrap().command
            else {
                panic!("text");
            };
            args
        };
        let render = async |args: TextArgs| {
            let package = Arc::new(
                ModelPackage::open(&args.placement.model, &args.placement.target.renderer()?)
                    .await?,
            );
            prepare(&args, &package).await
        };
        let (presentation, job) = render(parse(&[])).await.unwrap();
        let (_, with_system) = render(parse(&["--system", "be brief"])).await.unwrap();
        assert_ne!(job.inputs, with_system.inputs);
        let (plan, inputs) = (job.plan, job.inputs);
        assert_eq!(plan.step.as_ref().unwrap().stop.max_steps, 3);
        let prompt = presentation
            .encode_chat(
                &[ChatMessage {
                    role: "user".into(),
                    content: "hello".into(),
                    ..Default::default()
                }],
                &[],
            )
            .unwrap();
        let encoded: Vec<u8> = prompt
            .iter()
            .flat_map(|&token| u64::from(token).to_le_bytes())
            .collect();
        assert!(
            inputs
                .iter()
                .any(|input| input.bytes.as_bytes().ends_with(&encoded))
        );
    }
}
