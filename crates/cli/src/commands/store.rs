//! Operating the content store from the command line.
//!
//! These commands index existing content, inspect the persisted index, and
//! fetch exact content-addressed files. Compilation and execution consume
//! verified descriptors through the evaluator; the store does neither.

use std::path::{Path, PathBuf};

use clap::Subcommand;
use hellas_store::ContentStore;
use hellas_store::hf::{HfCas, Repo, RepoKind};
use hellas_store::hf_cache::HfCache;
use hellas_xet::XetHash;

use crate::commands::CliResult;

#[derive(Subcommand)]
pub enum StoreCommand {
    /// Index a HuggingFace cache without copying its contents
    Adopt {
        /// Cache root (default: HF_HUB_CACHE, else HF_HOME/hub, else
        /// ~/.cache/huggingface/hub)
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Where to persist what was hashed
        #[arg(long)]
        records: Option<PathBuf>,
        /// Hash everything again, ignoring any existing record
        #[arg(long)]
        recheck: bool,
    },
    /// Show what a persisted record holds
    Status {
        #[arg(long)]
        records: Option<PathBuf>,
    },
    /// Fetch one content id from HuggingFace and verify it
    Fetch {
        /// Xet file hash, 64 hex characters
        #[arg(long)]
        id: String,
        /// Repository the read token is minted for, `org/name`
        #[arg(long)]
        repo: String,
        /// Treat the repository as a dataset rather than a model
        #[arg(long)]
        dataset: bool,
        #[arg(long, default_value = "main")]
        revision: String,
        /// Where to write the content
        #[arg(long)]
        out: PathBuf,
    },
}

pub async fn run(command: StoreCommand, root: Option<PathBuf>) -> CliResult {
    let default_records = root.as_deref().map(hellas_store::state::records_path_at);
    match command {
        StoreCommand::Adopt {
            cache,
            records,
            recheck,
        } => adopt(cache, records.or(default_records), recheck),
        StoreCommand::Status { records } => status(records.or(default_records)),
        StoreCommand::Fetch {
            id,
            repo,
            dataset,
            revision,
            out,
        } => fetch(&id, &repo, dataset, &revision, &out),
    }
}

fn records_path(explicit: Option<PathBuf>) -> CliResult<PathBuf> {
    explicit
        .or_else(hellas_store::state::records_path)
        .ok_or_else(|| anyhow::anyhow!("no home directory; pass --records"))
}

fn adopt(cache: Option<PathBuf>, records: Option<PathBuf>, recheck: bool) -> CliResult {
    let cache = match cache {
        Some(root) => HfCache::new(root),
        None => HfCache::discover()
            .ok_or_else(|| anyhow::anyhow!("no HuggingFace cache found; pass --cache"))?,
    };
    let records_path = records_path(records)?;

    let store = ContentStore::new();
    let loaded = if recheck {
        0
    } else {
        store.records().load(&records_path)
    };

    let started = std::time::Instant::now();
    let adopted = cache.adopt_into(&store)?;
    let elapsed = started.elapsed();
    let saved = store.records().save(&records_path)?;

    println!("cache      {}", cache.root().display());
    println!(
        "known      {loaded} remembered from {}",
        records_path.display()
    );
    println!("adopted    {adopted} blobs in {elapsed:.2?}");
    println!("contents   {} distinct", store.len());
    println!("records    {saved} saved");
    Ok(())
}

fn status(records: Option<PathBuf>) -> CliResult {
    let path = records_path(records)?;
    let store = ContentStore::new();
    let loaded = store.records().load(&path);
    println!("records    {}", path.display());
    println!("remembered {loaded} files");
    if loaded == 0 && !path.exists() {
        println!("\nNothing adopted yet. Try: hellas store adopt");
    }
    Ok(())
}

fn fetch(id: &str, repo: &str, dataset: bool, revision: &str, out: &Path) -> CliResult {
    let id: XetHash = id
        .parse()
        .map_err(|_| anyhow::anyhow!("--id must be 64 hex characters"))?;
    let source = HfCas::new(Repo {
        kind: if dataset {
            RepoKind::Dataset
        } else {
            RepoKind::Model
        },
        id: repo.to_string(),
        revision: revision.to_string(),
    });

    let store = ContentStore::new();
    let started = std::time::Instant::now();
    // `materialize` re-indexes and refuses to keep anything that does
    // not hash to `id`, so reaching the print below is itself the proof
    // the bytes are the ones asked for.
    let indexed = store.materialize(id, out, &source)?;
    println!("id         {}", indexed.id);
    println!("bytes      {}", indexed.len);
    println!("chunks     {}", indexed.chunks.len());
    println!("written    {} in {:.2?}", out.display(), started.elapsed());
    Ok(())
}
