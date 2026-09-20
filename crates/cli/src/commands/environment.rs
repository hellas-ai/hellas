//! Build and inspect canonical causal-LM environments.
//!
//! Settings paths are local content-location hints only. They are resolved for
//! hashing and never enter the canonical bytes.

use anyhow::Context;
use clap::Subcommand;
use hellas_rpc::{
    CausalLmEnvironment, CausalLmGenerationSchedule, ContentId, ContentRef,
    MAX_CAUSAL_LM_ENVIRONMENT_BYTES, StaticSlice,
};
use hellas_store::ContentStore;
use serde::Deserialize;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::commands::CliResult;

const MAX_TEMPORARY_CREATE_ATTEMPTS: usize = 128;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Subcommand)]
pub enum EnvironmentCommand {
    /// Build a canonical causal-LM environment from Catena source and TOML settings.
    Build {
        /// Catena `.hex` source program to content-address. The provider's
        /// safe runtime compiles it only after an execution is authorized.
        #[arg(long, value_name = "CATENA_SOURCE")]
        program: PathBuf,
        /// TOML causal-LM ABI settings. Relative static-object paths are resolved
        /// beside this file but are not recorded in the environment.
        #[arg(long, value_name = "MODEL.toml")]
        settings: PathBuf,
        /// Canonical environment output. This is metadata, not a model archive.
        #[arg(long, value_name = "MODEL.environment")]
        out: PathBuf,
    },
    /// Commit a fixed prefill schedule to existing verified environment metadata.
    Schedule {
        #[arg(long, value_name = "FILE")]
        environment: PathBuf,
        #[arg(long)]
        fixed_capacity: u64,
        #[arg(long)]
        prefill_chunk_tokens: u32,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Strict-decode an environment and print its deterministic manifest identity.
    Inspect {
        /// Canonical environment file to inspect.
        #[arg(long, value_name = "FILE")]
        environment: PathBuf,
    },
    /// Prove that one environment and every object it references are locally available.
    Verify {
        /// Canonical environment whose complete local closure must be present.
        #[arg(long, value_name = "FILE")]
        environment: PathBuf,
        /// Individual local files to index. Repeat for multiple objects.
        #[arg(long = "content", value_name = "PATH")]
        content_paths: Vec<PathBuf>,
        /// Directory trees to adopt into the local content view. No network
        /// fetch is performed. Repeat for multiple roots.
        #[arg(long = "content-root", value_name = "DIR")]
        content_roots: Vec<PathBuf>,
        /// Optional fast-resume index to load and update after verification.
        #[arg(long = "content-index", value_name = "FILE")]
        content_index: Option<PathBuf>,
        /// Re-hash every local file instead of trusting fast-resume metadata.
        #[arg(long)]
        recheck: bool,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentSettings {
    entrypoint: String,
    #[serde(default)]
    static_objects: Vec<PathBuf>,
    #[serde(default)]
    static_inputs: Vec<StaticInputSettings>,
    state_bytes_per_capacity: Vec<u64>,
    vocabulary_size: u64,
    maximum_capacity: u64,
    #[serde(default)]
    generation: Option<GenerationSettings>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationSettings {
    fixed_capacity: u64,
    prefill_chunk_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticInputSettings {
    object: u32,
    offset: u64,
    bytes: u64,
}

pub async fn run(command: EnvironmentCommand) -> CliResult {
    match command {
        EnvironmentCommand::Schedule {
            environment,
            fixed_capacity,
            prefill_chunk_tokens,
            out,
        } => {
            let bytes = read_bounded_metadata(&environment, "environment")?;
            let environment = CausalLmEnvironment::from_canonical_bytes(&bytes)?
                .with_generation_schedule(CausalLmGenerationSchedule {
                    fixed_capacity,
                    prefill_chunk_tokens,
                })?;
            let bytes = environment.canonical_bytes();
            atomic_write(&out, &bytes)?;
            print_environment(&environment, &bytes, &out);
            Ok(())
        }
        EnvironmentCommand::Build {
            program,
            settings,
            out,
        } => build(&program, &settings, &out),
        EnvironmentCommand::Inspect { environment } => inspect(&environment),
        EnvironmentCommand::Verify {
            environment,
            content_paths,
            content_roots,
            content_index,
            recheck,
        } => verify(
            &environment,
            &content_paths,
            &content_roots,
            content_index.as_deref(),
            recheck,
        ),
    }
}

fn build(program_path: &Path, settings_path: &Path, out: &Path) -> CliResult {
    let settings_bytes = read_bounded_metadata(settings_path, "environment settings")?;
    let settings_text = std::str::from_utf8(&settings_bytes)
        .with_context(|| format!("settings {} are not valid UTF-8", settings_path.display()))?;
    let settings: EnvironmentSettings = toml::from_str(settings_text)
        .with_context(|| format!("failed to parse settings {}", settings_path.display()))?;
    let store = ContentStore::new();
    let program = index_ref(&store, program_path, "Catena program")?;
    let settings_dir = settings_path.parent().unwrap_or_else(|| Path::new("."));
    let objects = settings
        .static_objects
        .into_iter()
        .map(|path| {
            let path = if path.is_absolute() {
                path
            } else {
                settings_dir.join(path)
            };
            index_ref(&store, &path, "static object")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inputs = settings
        .static_inputs
        .into_iter()
        .map(|slice| StaticSlice::new(slice.object, slice.offset, slice.bytes))
        .collect();
    let environment = CausalLmEnvironment::new(
        program,
        settings.entrypoint,
        objects,
        inputs,
        settings.state_bytes_per_capacity,
        settings.vocabulary_size,
        settings.maximum_capacity,
    )
    .map_err(|error| anyhow::anyhow!("invalid causal-LM environment: {error}"))?;
    let environment = match settings.generation {
        Some(schedule) => environment.with_generation_schedule(CausalLmGenerationSchedule {
            fixed_capacity: schedule.fixed_capacity,
            prefill_chunk_tokens: schedule.prefill_chunk_tokens,
        })?,
        None => environment,
    };
    let bytes = environment.canonical_bytes();
    atomic_write(out, &bytes)?;
    print_environment(&environment, &bytes, out);
    Ok(())
}

fn inspect(path: &Path) -> CliResult {
    let bytes = read_bounded_metadata(path, "environment")?;
    let environment = CausalLmEnvironment::from_canonical_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid canonical environment: {error}"))?;
    print_environment(&environment, &bytes, path);
    Ok(())
}

/// Validate one concrete provider-ready causal-LM closure without compiling it
/// or touching the network. The environment path is a description of what to
/// check, not an implicit content source: it must also be present through a
/// configured `--content` or `--content-root`, exactly as it must be for
/// `serve`.
fn verify(
    environment_path: &Path,
    content_paths: &[PathBuf],
    content_roots: &[PathBuf],
    content_index: Option<&Path>,
    recheck: bool,
) -> CliResult {
    anyhow::ensure!(
        !content_paths.is_empty() || !content_roots.is_empty(),
        "environment verification requires at least one --content or --content-root"
    );

    let bytes = read_bounded_metadata(environment_path, "environment")?;
    let environment = CausalLmEnvironment::from_canonical_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid canonical environment: {error}"))?;
    let store = match (content_index, recheck) {
        (Some(index_path), false) => index_content(content_paths, content_roots, index_path)?,
        _ => populate_content(content_paths, content_roots, content_index, recheck)?,
    };

    require_local_content(
        &store,
        environment.content_id(),
        u64::try_from(bytes.len()).context("environment length does not fit u64")?,
        "environment",
    )?;
    require_local_content(
        &store,
        environment.program().id(),
        environment.program().bytes(),
        "program",
    )?;
    for (index, object) in environment.static_objects().iter().enumerate() {
        require_local_content(
            &store,
            object.id(),
            object.bytes(),
            &format!("static object {index}"),
        )?;
    }

    let manifest = environment.manifest();
    println!("ready       {}", manifest.content_id());
    println!("environment {}", environment.content_id());
    println!("program     {}", environment.program().id());
    println!("static objects {}", environment.static_objects().len());
    Ok(())
}

fn require_local_content(
    store: &ContentStore,
    id: ContentId,
    bytes: u64,
    label: &str,
) -> CliResult {
    let opened = store
        .open_verified(id.digest(), bytes)
        .with_context(|| format!("{label} {id} failed local verification"))?;
    anyhow::ensure!(opened.is_some(), "{label} {id} is not locally available");
    Ok(())
}

/// Read only bounded causal-LM metadata. Programs and static objects continue
/// through [`ContentStore`] and are never copied into this buffer.
fn read_bounded_metadata(path: &Path, label: &str) -> CliResult<Vec<u8>> {
    super::read_bounded_regular_file(path, label, MAX_CAUSAL_LM_ENVIRONMENT_BYTES)
}

fn index_ref(store: &ContentStore, path: &Path, label: &str) -> CliResult<ContentRef> {
    let indexed = store
        .index(path)
        .with_context(|| format!("failed to index {label} {}", path.display()))?;
    Ok(ContentRef::new(
        ContentId::from_bytes(*indexed.id.as_bytes()),
        indexed.len,
    ))
}

fn print_environment(environment: &CausalLmEnvironment, bytes: &[u8], path: &Path) {
    let manifest = environment.manifest();
    let manifest_bytes = manifest.canonical_bytes();
    println!(
        "environment {} ({} bytes) {}",
        ContentId::hash(bytes),
        bytes.len(),
        path.display()
    );
    println!(
        "manifest    {} ({} bytes)",
        ContentId::hash(&manifest_bytes),
        manifest_bytes.len()
    );
    println!(
        "application ({}, {})",
        manifest.application().evaluator(),
        manifest.application().adaptor()
    );
    println!("root        {}", manifest.root());
    println!(
        "program     {} {} bytes",
        environment.program().id(),
        environment.program().bytes()
    );
    for (index, object) in environment.static_objects().iter().enumerate() {
        println!("static[{index}]   {} {} bytes", object.id(), object.bytes());
    }
    println!("static inputs {}", environment.static_inputs().len());
    println!(
        "state bytes/capacity {:?}",
        environment.state_bytes_per_capacity()
    );
    println!("entrypoint  {}", environment.entrypoint());
    println!("vocabulary  {}", environment.vocabulary_size());
    println!("capacity    {}", environment.maximum_capacity());
    if let Some(schedule) = environment.generation_schedule() {
        println!(
            "generation  fixed_capacity={} prefill_chunk_tokens={}",
            schedule.fixed_capacity, schedule.prefill_chunk_tokens
        );
    }
}

/// Publish complete environment metadata and make both its bytes and directory
/// entry durable before reporting success. The operator must pre-create the
/// output parent and keep it and its ancestors stable and trusted while the
/// write runs; this function does not pretend that recursive directory creation
/// became crash-durable by syncing only the final leaf.
fn atomic_write(path: &Path, bytes: &[u8]) -> CliResult {
    use std::io::Write as _;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let (temporary, mut file) = create_temporary(path, parent).with_context(|| {
        format!(
            "failed to create temporary output beside {}",
            path.display()
        )
    })?;
    let mut published = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        published = true;
        sync_directory(parent)?;
        Ok::<_, std::io::Error>(())
    })();
    if !published {
        let _ = std::fs::remove_file(&temporary);
    }
    result.with_context(|| format!("failed to atomically write {}", path.display()))
}

fn create_temporary(path: &Path, parent: &Path) -> std::io::Result<(PathBuf, File)> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} has no file name", path.display()),
        )
    })?;
    let mut last_collision = None;
    for _ in 0..MAX_TEMPORARY_CREATE_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(
            ".{}.{sequence}.environment.tmp",
            std::process::id()
        ));
        let temporary = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique environment temporary file",
        )
    }))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(path)?
            .sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub fn index_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: &Path,
) -> CliResult<ContentStore> {
    populate_content(paths, roots, Some(index_path), false)
}

fn populate_content(
    paths: &[PathBuf],
    roots: &[PathBuf],
    index_path: Option<&Path>,
    recheck: bool,
) -> CliResult<ContentStore> {
    let store = ContentStore::new();
    let remembered = if recheck {
        0
    } else {
        index_path.map_or(0, |path| store.records().load(path))
    };
    for path in paths {
        store
            .index(path)
            .with_context(|| format!("failed to index local content {}", path.display()))?;
    }
    let mut adopted = 0usize;
    for root in roots {
        adopted += store
            .adopt(root)
            .with_context(|| format!("failed to adopt local content root {}", root.display()))?
            .len();
    }
    if let Some(index_path) = index_path {
        store
            .records()
            .save(index_path)
            .with_context(|| format!("failed to save content index {}", index_path.display()))?;
    }
    info!(
        remembered,
        indexed = store.len(),
        adopted,
        "indexed local content"
    );
    Ok(store)
}

#[cfg(test)]
mod tests;
