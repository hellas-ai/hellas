//! `hellas text`: one Qwen3 chat turn, tokenized here and run as a Compute job.
use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_presentation::{ChatMessage, ChatTemplate, TextPresentation};

#[derive(Debug, Args)]
pub struct TextArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Qwen3 GGUF; the provider holds the same weights.
    #[arg(long, value_name = "FILE")]
    model: PathBuf,
    #[arg(long)]
    prompt: String,
    #[arg(long)]
    system: Option<String>,
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u64).range(1..))]
    max_tokens: u64,
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
    #[arg(short = 'o', long, value_name = "DIR")]
    output: Option<PathBuf>,
}

pub async fn text(args: TextArgs, context: Context) -> super::super::CliResult<()> {
    let (package, presentation, rendered) = prepare(&args).await?;
    let mut target = args.target;
    target.models = vec![args.model.clone()];
    run_quoted(
        &args.client,
        target,
        &context,
        args.pay,
        None,
        async |price| {
            Ok(Job::compute(
                price,
                rendered.environment,
                rendered.plan,
                rendered.inputs,
                rendered.content,
            )
            .await?)
        },
        |_| args.output.clone(),
        |_, completed, _| {
            let ModelResponse::Tokens(tokens) = package.decode(&completed.output)? else {
                bail!("expected generated tokens");
            };
            println!("{}", presentation.decode(&tokens)?);
            std::io::stdout().lock().flush()?;
            Ok(())
        },
    )
    .await
}

async fn prepare(
    args: &TextArgs,
) -> anyhow::Result<(
    ModelPackage,
    TextPresentation,
    hellas_client::model::ComputeJob,
)> {
    let model = args.model.clone();
    let presentation = tokio::task::spawn_blocking(move || {
        TextPresentation::from_gguf(&model)
            .map(|presentation| presentation.with_chat_template(Some(ChatTemplate::Qwen3)))
    })
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
        .encode_chat(&messages)?
        .into_iter()
        .map(u64::from)
        .collect();
    let package = ModelPackage::open(&args.model).await?;
    let rendered = package
        .render_job(&ModelRequest::Text {
            prompt_ids: &prompt,
            max_new: args.max_tokens,
            stops: &[],
        })
        .await?;
    Ok((package, presentation, rendered))
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
            ];
            argv.extend(system);
            let crate::Commands::Text(args) = crate::Cli::try_parse_from(argv).unwrap().command
            else {
                panic!("text");
            };
            args
        };
        let (_, presentation, job) = prepare(&parse(&[])).await.unwrap();
        let (_, _, with_system) = prepare(&parse(&["--system", "be brief"])).await.unwrap();
        assert_ne!(job.inputs, with_system.inputs);
        let (plan, inputs) = (job.plan, job.inputs);
        assert_eq!(plan.step.as_ref().unwrap().stop.max_steps, 3);
        let prompt = presentation
            .encode_chat(&[ChatMessage {
                role: "user".into(),
                content: "hello".into(),
                ..Default::default()
            }])
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
