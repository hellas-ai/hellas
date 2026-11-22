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
pub fn speech(checkpoint: &Checkpoint, output: &Path) -> CliResult<()> {
    let scratch = scratch(output)?;
    checkpoint.fetch(scratch.path(), hellas_client::model::speech::CHECKPOINT)?;
    let object = hellas_client::model::speech::convert_speech(scratch.path(), output)?;
    println!(
        "weights: {} ({} bytes), {}",
        object.id(),
        object.bytes(),
        output
            .join(hellas_client::model::speech::WEIGHTS_FILE)
            .display()
    );
    Ok(())
}

pub fn phonon(
    model: &Checkpoint,
    codec: &str,
    voices: &str,
    names: &[String],
    output: &Path,
) -> CliResult<()> {
    use hellas_client::model::speech::phonon;
    let mut distinct = std::collections::BTreeSet::new();
    for name in names {
        phonon::validate_voice(name)?;
        ensure!(
            distinct.insert(name.to_lowercase()),
            "voice {name:?} is named twice"
        );
    }
    let scratch = scratch(output)?;
    let codec: Checkpoint = format!("{}@{codec}", phonon::CODEC_REPO).parse()?;
    let catalog: Checkpoint = format!("{}@{voices}", phonon::VOICE_REPO).parse()?;
    let directory = |name: &str| scratch.path().join(name);
    model.fetch(&directory("model"), phonon::MODEL_FILES)?;
    codec.fetch(&directory("codec"), phonon::CODEC_FILES)?;
    catalog.fetch(&directory("voices"), [phonon::VOICE_CATALOG])?;
    let listing = String::from_utf8(super::read_bounded_regular_file(
        &directory("voices").join(phonon::VOICE_CATALOG),
        "voice catalog",
        1 << 20,
    )?)?;
    let mut selected = Vec::new();
    for name in names {
        // The catalog names the file: check it before it becomes a local path.
        let file = phonon::voice_file(&listing, name)?;
        catalog.fetch(&directory("voices"), [file.as_str()])?;
        selected.push((name.clone(), directory("voices").join(file)));
    }
    for asset in phonon::convert(&directory("model"), &directory("codec"), &selected, output)? {
        println!(
            "{}: {} ({} bytes)",
            asset.name,
            asset.object.id(),
            asset.object.bytes()
        );
    }
    Ok(())
}

pub fn flux(checkpoint: &Checkpoint, output: &Path) -> CliResult<()> {
    use hellas_client::model::flux;
    let scratch = scratch(output)?;
    // A published transformer is one file, or shards named by an index.
    let transformer = if checkpoint.0.publishes(flux::TRANSFORMER_INDEX)? {
        flux::TRANSFORMER_INDEX
    } else {
        flux::TRANSFORMER
    };
    checkpoint.fetch(
        scratch.path(),
        flux::CHECKPOINT.into_iter().chain([transformer]),
    )?;
    let mut shards = flux::shards(scratch.path(), flux::TEXT_INDEX)?;
    shards.extend(flux::shards(scratch.path(), transformer)?);
    checkpoint.fetch(scratch.path(), shards.iter().map(String::as_str))?;
    for asset in flux::convert_flux(scratch.path(), transformer, output)? {
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

#[cfg(test)]
mod phonon_tests {
    use hellas_client::model::{GpuDialect, ModelKind, ModelPackage, ModelRequest, evaluator};
    use std::path::PathBuf;

    #[test]
    fn repeated_or_unsafe_voices_are_refused_before_any_download() {
        let commit = "ab".repeat(20);
        let model = format!("org/model@{commit}").parse().unwrap();
        let root = tempfile::tempdir().unwrap();
        for (names, message) in [
            (["Easton", "easton"], "named twice"),
            (["Easton", "../Zoey"], "invalid voice name"),
        ] {
            let names = names.map(String::from);
            let error = super::phonon(&model, &commit, &commit, &names, &root.path().join("out"))
                .unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
        }
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    /// Converts the published snapshots and checks every rendered call against
    /// the signatures of the compiled program.
    #[tokio::test]
    #[ignore = "needs HELLAS_TEST_PHONON_MODEL, HELLAS_TEST_PHONON_CODEC and HELLAS_TEST_PHONON_VOICE"]
    async fn converted_phonon_plans_validate_against_the_compiled_bundle() {
        let path = |name: &str| PathBuf::from(std::env::var(name).unwrap());
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("phonon");
        let assets = hellas_client::model::speech::phonon::convert(
            &path("HELLAS_TEST_PHONON_MODEL"),
            &path("HELLAS_TEST_PHONON_CODEC"),
            &[("Easton".into(), path("HELLAS_TEST_PHONON_VOICE"))],
            &package,
        )
        .unwrap();
        assert_eq!(assets.len(), 2);
        assert_eq!(ModelKind::of(&package).unwrap(), ModelKind::Speech);
        let model = ModelPackage::open(&package, &evaluator(GpuDialect::Hip))
            .await
            .unwrap();
        let speech = |text: &'static str, voice: &'static str, speed| ModelRequest::Speech {
            text,
            voice,
            speed,
        };
        for request in [
            speech("Hello.", "Other", 1.),
            speech("Hello.", "Easton", 2.),
        ] {
            assert!(model.render_job(&request).await.is_err());
        }
        let long = "The quick brown fox jumps over the lazy dog. ".repeat(12);
        let long: &'static str = long.leak();
        let short = model
            .render_job(&speech("Hello.", "Easton", 1.))
            .await
            .unwrap();
        let job = model.render_job(&speech(long, "Easton", 1.)).await.unwrap();
        // Each weight starts where a separately allocated tensor could.
        for call in &job.plan.calls {
            for arg in &call.args {
                if let hellas_rpc::protocol::invocation::compute::Arg::Asset { offset, .. } = arg {
                    assert_eq!(offset % 4, 0);
                }
            }
        }
        assert_eq!(short.plan.calls.len(), 2);
        assert!(job.plan.calls.len() > 2);
        assert_eq!(job.environment, short.environment);
        let source = hellas_channel::content::read(
            &job.content.0,
            &job.content.1,
            job.environment.sources[0],
            hellas_rpc::protocol::invocation::compute::MAX_SOURCE_BYTES,
        )
        .await
        .unwrap();
        let module = hellas_executor::catena::compile::compile_sources(
            &[String::from_utf8(source.to_vec()).unwrap()],
            catena_lang::codegen::GpuDialect::Hip,
        )
        .unwrap();
        let limits = hellas_rpc::protocol::invocation::Limits {
            max_upload_bytes: 16 << 20,
            max_output_bytes: 64 << 20,
            max_steps: 1,
            execution_timeout_ms: 90000,
        };
        for job in [short, job] {
            let inputs = job
                .inputs
                .iter()
                .map(|a| {
                    (
                        a.name.clone(),
                        hellas_rpc::ContentRef::for_bytes(a.bytes.as_bytes()),
                    )
                })
                .collect();
            hellas_executor::catena::validate::validate(
                &module,
                &job.environment,
                &inputs,
                &job.plan,
                &limits,
            )
            .unwrap();
        }
    }
}
