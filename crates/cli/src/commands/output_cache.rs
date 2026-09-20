use futures::{StreamExt, TryStreamExt};
use hellas_rpc::cache::control::CacheController;
use hellas_rpc::services::cache_control::{CacheControl, CacheControlClientImpl};
use hellas_wire::{ServiceMarker, iroh::IrohTransport};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Subcommand, builder::TypedValueParser};
use hellas_rpc::cache::{CacheKey, CacheKind, CacheOptions, CachePolicy, CacheStore};
use hellas_rpc::pb::host as pb;
use hellas_rpc::pb::host::manage_cache_request::Operation;
use hellas_rpc::pb::host::manage_cache_response::Result as Reply;
use hellas_store::cache::FsCacheStore;

#[derive(Args)]
pub struct OutputCacheArgs {
    #[arg(long, global = true, value_parser = cache_kind_parser())]
    kind: Option<CacheKind>,
    #[arg(long, global = true)]
    pub key: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    /// Manage a running process over its owner-only local RPC socket
    #[arg(long, global = true, conflicts_with = "node_id")]
    socket: Option<PathBuf>,
    /// Administer a remote node over its authenticated Iroh connection
    #[arg(long, global = true)]
    pub node_id: Option<iroh::EndpointId>,
    #[arg(long, global = true, requires = "node_id")]
    node_addr: Vec<std::net::SocketAddr>,
    #[command(subcommand)]
    command: OutputCacheCommand,
}

fn cache_kind_parser() -> impl TypedValueParser<Value = CacheKind> {
    clap::builder::PossibleValuesParser::new(CacheKind::ALL.map(CacheKind::as_str))
        .try_map(|kind| kind.parse::<CacheKind>())
}

#[derive(Subcommand)]
pub enum OutputCacheCommand {
    /// List recorded identities, timestamps, and sizes
    List,
    /// Print one complete transcript (requires --kind and --key)
    Show,
    /// Count recordings and their referenced bytes (not total store disk usage)
    Stats,
    /// Copy selected recordings into a new, self-contained store snapshot
    Export {
        #[arg(long)]
        to: PathBuf,
    },
    /// Remove one identity, or all entries matching the filters
    Remove {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Clear matching mappings and invalidate in-flight recordings
    #[command(alias = "reset")]
    Clear {
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove oldest recordings until the selected limits are met
    Prune {
        #[arg(long)]
        older_than_secs: Option<u64>,
        #[arg(long)]
        max_entries: Option<u64>,
        #[arg(long)]
        max_bytes: Option<u64>,
        #[arg(long)]
        dry_run: bool,
    },
}

enum Access {
    Local(CacheController),
    #[cfg(unix)]
    Socket(CacheControlClientImpl<hellas_wire::mux::MuxTransport>),
    Iroh(CacheControlClientImpl<IrohTransport>),
}

impl Access {
    async fn call(&self, operation: Operation) -> anyhow::Result<Vec<Reply>> {
        let request = pb::ManageCacheRequest {
            operation: Some(operation),
        };
        let responses: Vec<pb::ManageCacheResponse> = match self {
            Self::Local(controller) => {
                let controller = controller.clone();
                tokio::task::spawn_blocking(move || controller.manage(request))
                    .await??
                    .try_collect()
                    .await?
            }
            _ => {
                let mut call = match self {
                    #[cfg(unix)]
                    Self::Socket(client) => client.manage_cache(request).await?,
                    Self::Iroh(client) => client.manage_cache(request).await?,
                    _ => unreachable!(),
                };
                let responses = call.by_ref().try_collect().await?;
                call.finish()?;
                responses
            }
        };
        responses
            .into_iter()
            .map(|r| {
                r.result
                    .ok_or_else(|| anyhow::anyhow!("cache RPC returned no result"))
            })
            .collect()
    }

    async fn one(&self, operation: Operation) -> anyhow::Result<Reply> {
        let mut replies = self.call(operation).await?;
        anyhow::ensure!(replies.len() == 1, "expected one cache RPC result");
        Ok(replies.pop().unwrap())
    }

    async fn entries(&self, filter: pb::CacheFilter) -> anyhow::Result<Vec<pb::CacheEntry>> {
        self.call(Operation::List(filter))
            .await?
            .into_iter()
            .map(|r| match r {
                Reply::Entry(entry) => Ok(entry),
                _ => anyhow::bail!("unexpected cache RPC result"),
            })
            .collect()
    }

    async fn read(&self, key: pb::CacheKey) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for reply in self.call(Operation::Read(key)).await? {
            let Reply::Data(data) = reply else {
                anyhow::bail!("unexpected cache RPC result")
            };
            bytes.extend(data);
        }
        Ok(bytes)
    }
}

pub async fn run(
    args: OutputCacheArgs,
    root: Option<PathBuf>,
    identity: Option<&Path>,
) -> super::CliResult {
    let writable = matches!(
        args.command,
        OutputCacheCommand::Remove { dry_run: false, .. }
            | OutputCacheCommand::Clear { dry_run: false }
            | OutputCacheCommand::Prune { dry_run: false, .. }
    );
    let mut endpoint = None;
    let access = if let Some(node_id) = args.node_id {
        anyhow::ensure!(
            root.is_none(),
            "--node-id and --store-dir are mutually exclusive"
        );
        let identity = crate::identity::load_existing(identity)?;
        let ep = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(identity.transport_key.clone())
            .bind()
            .await?;
        let addr = iroh::EndpointAddr::from_parts(
            node_id,
            args.node_addr.into_iter().map(iroh::TransportAddr::Ip),
        );
        let connection = ep.connect(addr, CacheControl::ALPN.as_bytes()).await?;
        endpoint = Some(ep);
        Access::Iroh(CacheControlClientImpl::new(IrohTransport::new(connection)))
    } else if let Some(socket) = &args.socket {
        anyhow::ensure!(
            root.is_none(),
            "--socket and --store-dir are mutually exclusive"
        );
        #[cfg(not(unix))]
        anyhow::bail!("local cache RPC requires Unix sockets");
        #[cfg(unix)]
        Access::Socket(
            hellas_rpc::services::cache_control::CacheControlClientImpl::new(
                hellas_wire::unix::connect(socket).await?,
            ),
        )
    } else {
        Access::Local(CacheController::new(&CacheOptions {
            policy: if writable {
                CachePolicy::Record
            } else {
                CachePolicy::ReplayOnly
            },
            store: Some(Arc::new(
                FsCacheStore::open(&store_dir(root)?, writable).map_err(anyhow::Error::msg)?,
            )),
        }))
    };
    let filter = pb::CacheFilter {
        kind: args.kind.map(|kind| kind.to_string()),
        identity: args.key.clone(),
    };
    let exact_key = || -> anyhow::Result<pb::CacheKey> {
        Ok(hellas_rpc::cache::control::key_to_pb(
            CacheKey::new(
                args.kind
                    .ok_or_else(|| anyhow::anyhow!("--kind is required"))?,
                args.key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("--key is required"))?,
            )
            .map_err(anyhow::Error::msg)?,
        ))
    };
    match args.command {
        OutputCacheCommand::Show => {
            let bytes = access.read(exact_key()?).await?;
            let value = if args.kind == Some(CacheKind::Evaluate) {
                let transcript: hellas_rpc::cache::Transcript<
                    hellas_rpc::cache::EvaluateEvent,
                    hellas_rpc::provenance::ExecutionProvenance,
                > = serde_ipld_dagcbor::from_slice(&bytes)?;
                serde_json::to_value(transcript)?
            } else {
                let transcript: hellas_rpc::cache::Transcript<
                    hellas_rpc::output::OutputEvent,
                    hellas_rpc::output::Provenance,
                > = serde_ipld_dagcbor::from_slice(&bytes)?;
                serde_json::to_value(transcript)?
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputCacheCommand::List => {
            let entries = access.entries(filter).await?;
            if args.json {
                let entries: Vec<_> = entries
                    .into_iter()
                    .map(|entry| {
                        let key = entry
                            .key
                            .ok_or_else(|| anyhow::anyhow!("cache entry has no key"))?;
                        Ok(serde_json::json!({
                            "kind": key.kind, "identity": key.identity, "output": entry.output,
                            "recorded_at": entry.recorded_at, "bytes": entry.bytes,
                        }))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for entry in entries {
                    let key = entry
                        .key
                        .ok_or_else(|| anyhow::anyhow!("cache entry has no key"))?;
                    println!(
                        "{}/{}\t{}\t{}\t{}",
                        key.kind, key.identity, entry.output, entry.recorded_at, entry.bytes
                    );
                }
            }
        }
        OutputCacheCommand::Stats => {
            let Reply::Stats(stats) = access.one(Operation::Stats(filter)).await? else {
                anyhow::bail!("unexpected cache RPC result")
            };
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"entries": stats.entries, "bytes": stats.bytes})
                );
            } else {
                println!(
                    "{} entries, {} referenced bytes",
                    stats.entries, stats.bytes
                );
            }
        }
        OutputCacheCommand::Export { to } => {
            std::fs::create_dir(&to)?;
            let snapshot = FsCacheStore::open(&to, true).map_err(anyhow::Error::msg)?;
            for entry in access.entries(filter).await? {
                let key = entry
                    .key
                    .ok_or_else(|| anyhow::anyhow!("cache entry has no key"))?;
                let bytes = access.read(key.clone()).await?;
                snapshot
                    .insert(
                        &CacheKey::new(
                            key.kind.parse().map_err(anyhow::Error::msg)?,
                            &key.identity,
                        )
                        .map_err(anyhow::Error::msg)?,
                        &bytes,
                        entry.recorded_at,
                    )
                    .map_err(anyhow::Error::msg)?;
            }
        }
        command => {
            let (all, dry_run, prune) = match command {
                OutputCacheCommand::Remove { all, dry_run } => (all, dry_run, None),
                OutputCacheCommand::Clear { dry_run } => (true, dry_run, None),
                OutputCacheCommand::Prune {
                    older_than_secs,
                    max_entries,
                    max_bytes,
                    dry_run,
                } => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    (
                        false,
                        dry_run,
                        Some(pb::CachePrune {
                            recorded_before: older_than_secs.map(|age| now.saturating_sub(age)),
                            max_entries,
                            max_bytes,
                        }),
                    )
                }
                _ => unreachable!(),
            };
            let Reply::Evict(result) = access
                .one(Operation::Evict(pb::EvictCacheEntries {
                    filter: Some(filter),
                    prune,
                    dry_run,
                    all,
                }))
                .await?
            else {
                anyhow::bail!("unexpected cache RPC result")
            };
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"dry_run": result.dry_run, "entries": result.entries})
                );
            } else {
                println!(
                    "{} {} entries",
                    if result.dry_run {
                        "would remove"
                    } else {
                        "removed"
                    },
                    result.entries
                );
            }
        }
    }
    if let Some(endpoint) = endpoint {
        endpoint.close().await;
    }
    Ok(())
}

fn store_dir(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    explicit
        .or_else(hellas_store::state::dir)
        .ok_or_else(|| anyhow::anyhow!("no store location; set HELLAS_STORE_DIR or --store-dir"))
}

pub fn options(policy: CachePolicy, root: Option<PathBuf>) -> anyhow::Result<CacheOptions> {
    let store = if policy == CachePolicy::Off {
        None
    } else {
        Some(Arc::new(
            FsCacheStore::open(&store_dir(root)?, policy == CachePolicy::Record)
                .map_err(anyhow::Error::msg)?,
        ) as Arc<dyn CacheStore + Send + Sync>)
    };
    Ok(CacheOptions { policy, store })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn export_copies_only_live_entries_without_overwriting_existing_directories() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source");
        let destination = directory.path().join("snapshot");
        let store = FsCacheStore::open(&root, true).unwrap();
        let live = CacheKey::hash(CacheKind::Proxy, &[b"live"]);
        let removed = CacheKey::hash(CacheKind::Proxy, &[b"removed"]);
        store.insert(&live, b"live output", 42).unwrap();
        store.insert(&removed, b"removed output", 43).unwrap();
        store.remove(&removed).unwrap();
        drop(store);
        let args = || OutputCacheArgs {
            kind: None,
            key: None,
            json: false,
            socket: None,
            node_id: None,
            node_addr: Vec::new(),
            command: OutputCacheCommand::Export {
                to: destination.clone(),
            },
        };
        run(args(), Some(root.clone()), None).await.unwrap();
        assert!(run(args(), Some(root), None).await.is_err());
        let snapshot = FsCacheStore::open(&destination, false).unwrap();
        assert_eq!(snapshot.get(&live).unwrap().unwrap(), b"live output");
        assert!(snapshot.get(&removed).unwrap().is_none());
        assert_eq!(
            std::fs::read_dir(destination.join("objects"))
                .unwrap()
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rpc_cli_uses_the_live_writer_and_reads_large_entries_in_chunks() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = directory.path().join("store");
        let socket = directory.path().join("control.sock");
        let store = Arc::new(FsCacheStore::open(&root, true).unwrap());
        let key = CacheKey::hash(CacheKind::Proxy, &[b"live"]);
        let bytes = vec![7; 150000];
        store.insert(&key, &bytes, 42).unwrap();
        let options = CacheOptions {
            policy: CachePolicy::Record,
            store: Some(store.clone()),
        };
        let _server = crate::commands::local_control::serve(Some(&socket), &options).unwrap();
        assert!(FsCacheStore::open(&root, true).is_err());
        let access = Access::Socket(
            hellas_rpc::services::cache_control::CacheControlClientImpl::new(
                hellas_wire::unix::connect(&socket).await.unwrap(),
            ),
        );
        assert_eq!(
            access
                .read(hellas_rpc::cache::control::key_to_pb(key.clone()))
                .await
                .unwrap(),
            bytes
        );
        let snapshot = directory.path().join("snapshot");
        run(
            OutputCacheArgs {
                kind: None,
                key: None,
                json: true,
                socket: Some(socket.clone()),
                node_id: None,
                node_addr: Vec::new(),
                command: OutputCacheCommand::Export {
                    to: snapshot.clone(),
                },
            },
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            FsCacheStore::open(&snapshot, false)
                .unwrap()
                .get(&key)
                .unwrap()
                .unwrap(),
            bytes
        );
        run(
            OutputCacheArgs {
                kind: None,
                key: None,
                json: true,
                socket: Some(socket),
                node_id: None,
                node_addr: Vec::new(),
                command: OutputCacheCommand::Clear { dry_run: false },
            },
            None,
            None,
        )
        .await
        .unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}
