use super::*;
use hellas_client::model::{ModelRequest, ModelResponse};
use std::io::Read;

#[derive(Debug, Args)]
pub struct SpeakArgs {
    #[command(flatten)]
    client: ClientArgs,
    /// Local speech model directory or pinned Hub checkpoint.
    #[arg(long, value_name = "MODEL")]
    model: PathBuf,
    /// Text to synthesize. Reads standard input when omitted.
    #[arg(long)]
    text: Option<String>,
    #[arg(long, default_value = "default")]
    voice: String,
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: TargetArgs,
    #[arg(short = 'o', long, value_name = "WAV")]
    output: PathBuf,
}

pub async fn speak(mut args: SpeakArgs, context: Context) -> super::super::CliResult<()> {
    context
        .model_command(async {
            let text = speech_text(args.text, std::io::stdin())?;
            let (evaluator, package) = args
                .target
                .open_model(&args.client, &context, &mut args.model)
                .await?;
            let rendered = package
                .render_job(&ModelRequest::Speech {
                    text: &text,
                    voice: &args.voice,
                    speed: 1.0,
                })
                .await?;
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
                    let ModelResponse::Speech(audio) = package.decode(&completed.output)? else {
                        bail!("expected speech");
                    };
                    std::fs::write(&args.output, audio.wav_bytes()?)?;
                    println!("{}", args.output.display());
                    std::io::stdout().lock().flush()?;
                    Ok(())
                },
            )
            .await
        })
        .await
}

fn speech_text(text: Option<String>, stdin: impl Read) -> anyhow::Result<String> {
    // Same input limit as the speech endpoint.
    const MAX_BYTES: usize = 16384;
    let text = match text {
        Some(text) => text,
        None => {
            let mut text = String::new();
            stdin.take(MAX_BYTES as u64 + 1).read_to_string(&mut text)?;
            text
        }
    };
    ensure!(
        !text.trim().is_empty() && text.len() <= MAX_BYTES,
        "speech requires nonempty text up to {MAX_BYTES} bytes"
    );
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn speak_reads_stdin_unless_text_is_supplied() {
        let parse = |extra: &[&str]| {
            let base = [
                "hellas",
                "speak",
                "--model",
                "model",
                "--access",
                "shared.access",
                "-o",
                "out.wav",
            ];
            let cli =
                crate::Cli::try_parse_from(base.into_iter().chain(extra.iter().copied())).unwrap();
            let crate::Commands::Speak(args) = cli.command else {
                panic!()
            };
            args
        };
        let args = parse(&[]);
        assert_eq!(args.voice, "default");
        assert_eq!(speech_text(args.text, &b"Hello."[..]).unwrap(), "Hello.");
        let args = parse(&["--text", "Good morning.", "--voice", "Easton"]);
        assert_eq!(args.voice, "Easton");
        assert_eq!(
            speech_text(args.text, std::io::empty()).unwrap(),
            "Good morning."
        );
        assert!(speech_text(None, &b" "[..]).is_err());
        assert!(speech_text(None, vec![b'x'; 16385].as_slice()).is_err());
    }
}
