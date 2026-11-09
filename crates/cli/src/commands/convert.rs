//! One-line model conversion: fetch a published checkpoint at one immutable
//! commit, convert it, and keep only the converted package. The same commit
//! converts to the same content on every machine, so a provider and its
//! users who convert it separately name the same weights.
use super::CliResult;
use anyhow::{Context as _, ensure};
use std::path::Path;

/// `ORG/NAME@COMMIT`: a HuggingFace model repository at a 40-hex commit.
#[derive(Clone, Debug)]
pub struct Checkpoint(hellas_store::hf::Repo);

impl std::str::FromStr for Checkpoint {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        ensure!(
            !value.starts_with("hf://"),
            "name the checkpoint as ORG/NAME@COMMIT"
        );
        let repo = hellas_store::hf::Repo::from_uri(&format!("hf://{value}"))?;
        ensure!(
            hellas_store::hf::immutable_sha(&repo.revision),
            "pin the checkpoint to a 40-hex commit: ORG/NAME@COMMIT"
        );
        Ok(Self(repo))
    }
}

impl Checkpoint {
    /// Download `files` verbatim into `directory`.
    fn fetch<'a>(
        &self,
        directory: &Path,
        files: impl IntoIterator<Item = &'a str>,
    ) -> CliResult<()> {
        for file in files {
            let path = directory.join(file);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            eprintln!("fetching {}@{}/{file}", self.0.id, self.0.revision);
            let mut out = std::io::BufWriter::new(std::fs::File::create(&path)?);
            self.0.download(file, &mut out)?;
            std::io::Write::flush(&mut out)?;
        }
        Ok(())
    }
}

/// A scratch directory beside `output`, which must not exist yet.
fn scratch(output: &Path) -> CliResult<tempfile::TempDir> {
    ensure!(!output.try_exists()?, "{} already exists", output.display());
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    tempfile::Builder::new()
        .prefix(".checkpoint-")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "failed to create a scratch directory in {}",
                parent.display()
            )
        })
}

pub fn whisper(checkpoint: &Checkpoint, output: &Path) -> CliResult<()> {
    let scratch = scratch(output)?;
    checkpoint.fetch(scratch.path(), hellas_client::model::whisper::CHECKPOINT)?;
    let object = hellas_client::model::whisper::convert_whisper(scratch.path(), output)?;
    println!(
        "weights: {} ({} bytes), {}",
        object.id(),
        object.bytes(),
        output
            .join(hellas_client::model::whisper::WEIGHTS_FILE)
            .display()
    );
    Ok(())
}

pub fn flux(checkpoint: &Checkpoint, output: &Path) -> CliResult<()> {
    use hellas_client::model::flux;
    let scratch = scratch(output)?;
    checkpoint.fetch(scratch.path(), flux::CHECKPOINT)?;
    let shards = flux::text_shards(scratch.path())?;
    checkpoint.fetch(scratch.path(), shards.iter().map(String::as_str))?;
    for asset in flux::convert_flux(scratch.path(), output)? {
        println!(
            "{}: {} ({} bytes), {}",
            asset.name,
            asset.object.id(),
            asset.object.bytes(),
            output.join(format!("{}.bin", asset.name)).display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Checkpoint;

    #[test]
    fn a_checkpoint_is_one_repository_at_one_commit() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let checkpoint: Checkpoint = format!("openai/whisper-tiny@{commit}").parse().unwrap();
        assert_eq!(checkpoint.0.id, "openai/whisper-tiny");
        assert_eq!(checkpoint.0.revision, commit);
        for value in [
            "openai/whisper-tiny".to_owned(),
            "openai/whisper-tiny@main".to_owned(),
            format!("hf://openai/whisper-tiny@{commit}"),
            format!("whisper-tiny@{commit}"),
            format!("openai/../x@{commit}"),
        ] {
            assert!(value.parse::<Checkpoint>().is_err(), "{value}");
        }
    }
}
