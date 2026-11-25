use super::*;
use hellas_client::model::{ModelRequest, ModelResponse};
use std::io::Read;

#[derive(Debug, Args)]
pub struct SpeakArgs {
    #[command(flatten)]
    placement: ModelArgs,
    #[command(flatten)]
    companions: crate::hub::Companions,
    /// Text to synthesize. Reads standard input when omitted.
    #[arg(long)]
    text: Option<String>,
    #[arg(long, default_value = "default")]
    voice: String,
    #[arg(short = 'o', long, value_name = "WAV")]
    output: PathBuf,
}

pub async fn speak(mut args: SpeakArgs, context: &Context) -> super::super::CliResult<()> {
    let text = speech_text(args.text, std::io::stdin())?;
    let package = args.placement.open(context, Some(&args.companions)).await?;
    let rendered = package
        .render_job(&ModelRequest::Speech {
            text: &text,
            voice: &args.voice,
            speed: 1.0,
        })
        .await?;
    args.placement
        .run(
            context,
            &package,
            rendered,
            |directory| Some(directory.join("result")),
            |response| {
                let ModelResponse::Speech(audio) = response else {
                    bail!("expected speech");
                };
                std::fs::write(&args.output, audio.wav_bytes()?)?;
                println!("{}", args.output.display());
                Ok(())
            },
        )
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
            let crate::Commands::Job(crate::commands::transact::JobCommand::Speak(args)) =
                cli.command
            else {
                panic!()
            };
            args
        };
        let args = parse(&[]);
        assert_eq!(args.voice, "default");
        assert_eq!(speech_text(args.text, &b"Hello."[..]).unwrap(), "Hello.");
        let args = parse(&[
            "--text",
            "Good morning.",
            "--voice",
            "Easton",
            "--codec",
            "local-codec",
            "--voices",
            "hf://org/voices@release",
        ]);
        let spec = args.companions.spec(&args.placement.model);
        assert_eq!(spec.codec, Some("local-codec".into()));
        assert_eq!(spec.voices, Some("hf://org/voices@release".into()));
        assert_eq!(args.voice, "Easton");
        assert_eq!(
            speech_text(args.text, std::io::empty()).unwrap(),
            "Good morning."
        );
        assert!(speech_text(None, &b" "[..]).is_err());
        assert!(speech_text(None, vec![b'x'; 16385].as_slice()).is_err());
    }
}
