use super::*;
use hellas_client::model::{ModelPackage, ModelRequest, ModelResponse};
use hellas_presentation::TextPresentation;

#[derive(Debug, Args)]
pub struct TextArgs {
    #[command(flatten)]
    task: task::TaskArgs,
    /// GGUF model with tokenizer metadata.
    #[arg(long, value_name = "GGUF")]
    model: PathBuf,
    /// Plain text to continue.
    #[arg(long)]
    prompt: String,
    #[arg(long, default_value_t = 128)]
    max_tokens: u64,
}

impl TextArgs {
    pub fn is_local(&self) -> bool {
        self.task.is_local()
    }
}

pub async fn text(args: TextArgs, context: Option<Context>) -> super::super::CliResult<()> {
    let presentation = TextPresentation::from_gguf(&args.model)?;
    let prompt = presentation
        .encode(&args.prompt)?
        .into_iter()
        .map(u64::from)
        .collect::<Vec<_>>();
    let package = ModelPackage::open(&args.model)?;
    let rendered = package.render_job(&ModelRequest::Text {
        prompt_ids: &prompt,
        max_new: args.max_tokens,
        stops: &[],
    })?;
    let job = args.task.job(rendered, &args.model)?;
    let mut completion = args.task.execute(&job, context.as_ref()).await?;
    let ModelResponse::Tokens(tokens) = package.decode(&completion.output)? else {
        bail!("expected text tokens")
    };
    println!("{}", presentation.decode(&tokens)?);
    std::io::stdout().lock().flush()?;
    task::deliver_and_settle(&mut completion).await?;
    Ok(())
}
