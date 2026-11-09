//! Owner content operations over authenticated daemon RPC or a checked local upper.
use crate::{commands::CliResult, identity::LocalIdentity};
use anyhow::{Context as _, ensure};
use clap::{Args, Subcommand};
use futures::StreamExt as _;
use hellas_authority::{authenticator::Authenticator, node::SessionKey};
use hellas_private::StoreLocation;
use hellas_rpc::{ContentRef, services::resolve::ResolveClientImpl};
use hellas_sdk::node_control::profile::ClientProfile;
use hellas_store::content::{self, config::Reconciler, owner_pin as find_pin, *};
use hellas_wire::StreamTransport;
use std::{future::Future, io::Write as _, net::SocketAddr, path::PathBuf};

#[derive(Args)]
pub struct StoreArgs {
    /// Private Owner credential and independently provisioned daemon trust.
    #[arg(long, global = true)]
    pub profile: Option<PathBuf>,
    /// Local daemon socket; defaults to <home>/provider/control.sock.
    #[arg(
        long,
        global = true,
        requires = "profile",
        conflicts_with = "addresses"
    )]
    pub control_socket: Option<PathBuf>,
    /// Direct addresses for the remote node paired with --profile.
    #[arg(long = "address", global = true, requires = "profile")]
    pub addresses: Vec<SocketAddr>,
    /// [content] for in-process operation; paid-work-owned uppers require daemon RPC.
    #[arg(long, global = true, conflicts_with = "profile")]
    pub content_config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: StoreCommand,
}

#[derive(Subcommand)]
pub enum StoreCommand {
    /// Hash lower files into fastresume records; local only, including while the daemon runs.
    Index {
        /// Files or directories; defaults to configured lower layers.
        paths: Vec<PathBuf>,
        #[arg(long)]
        recheck: bool,
    },
    /// Inspect the object or tree at a pin and optional relative path.
    Stat {
        pin: String,
        #[arg(long, default_value = "")]
        path: String,
    },
    /// Read verified bytes from a pin and optional relative path.
    Read {
        pin: String,
        #[arg(long, default_value = "")]
        path: String,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        end: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Acquire hf://repo@sha, https://URL, or peer://NODE and publish a pin atomically.
    Acquire {
        source: String,
        #[arg(long)]
        pin: String,
        #[arg(long, default_value = "owner")]
        policy: String,
        /// Expected ContentId; supply --bytes with it.
        #[arg(long, requires = "bytes")]
        expect: Option<String>,
        /// Exact source bytes (required for HTTPS and an expected ContentId).
        #[arg(long)]
        bytes: Option<u64>,
        /// Optional HTTPS transport digest; distinct from ContentId.
        #[arg(long)]
        sha256: Option<String>,
        /// HF leaf or a path inside the peer source pin.
        #[arg(long)]
        path: Option<String>,
        /// Source pin for peer://NODE.
        #[arg(long)]
        source_pin: Option<String>,
    },
    /// Set, enumerate or remove pins with compare-and-swap.
    Pin {
        #[command(subcommand)]
        command: PinCommand,
    },
    /// Collect unpinned upper objects.
    Collect,
    /// Resolve an HF revision once, printing its immutable SHA and tree reference.
    Resolve { uri: String },
}

#[derive(Subcommand)]
pub enum PinCommand {
    Set {
        name: String,
        id: String,
        #[arg(long)]
        bytes: u64,
        #[arg(long)]
        tree: bool,
        /// owner, jobs, granted, public, or channel:ID.
        #[arg(long, default_value = "owner")]
        policy: String,
        #[arg(long)]
        expires_ms: Option<u64>,
    },
    Ls {
        #[arg(default_value = "")]
        prefix: String,
    },
    Rm {
        name: String,
    },
}

fn ram() -> Reservations {
    Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES)
}
fn target(value: Target) {
    let kind = match value {
        Target::Object(_) => "object",
        Target::Tree(_) => "tree",
    };
    println!(
        "{kind}\t{}\t{}",
        value.object().id(),
        value.object().bytes()
    );
}

pub async fn run(
    args: StoreArgs,
    home: &StoreLocation,
    identity: Option<&LocalIdentity>,
    passkey: Option<&dyn Authenticator>,
) -> CliResult<()> {
    if args.profile.is_none() {
        ensure!(
            args.control_socket.is_none() && args.addresses.is_empty(),
            "daemon addressing requires --profile"
        );
        let reconcile = args.content_config.is_some();
        let loaded =
            crate::content_configuration::ContentConfiguration::load(args.content_config, vec![])?;
        let config = loaded.config().clone();
        if let StoreCommand::Index { paths, recheck } = args.command {
            return index(&config, home, paths, recheck).await;
        }
        let store = config.open(home, ram(), true).await.context(
            "opening the local upper; use --profile for an authenticated daemon connection",
        )?;
        let result = async {
            store.finish_recovery().await?;
            // Only an explicit file declares a desired set; a bare owner
            // command must not treat absent configuration as deleting config/*.
            if reconcile { Reconciler::new(config.clone())?.apply(&store, config).await?; }
            let peer = if matches!(&args.command, StoreCommand::Acquire { source, .. } if source.starts_with("peer://")) {
                let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0).bind().await?;
                store.clone().with_peers(hellas_wire::iroh::Pool::for_service::<hellas_rpc::services::content::Content>(endpoint.clone(), Default::default()));
                Some(endpoint)
            } else { None };
            let resolving = store.clone();
            let result = execute(&store, args.command, move |uri| async move {
                let repo = hellas_store::hf::Repo::from_uri(&uri)?;
                Ok(resolving.resolve_hf(&Scope::Owner, repo).await?)
            }).await;
            if let Some(endpoint) = peer { endpoint.close().await; }
            result
        }.await;
        store.close().await;
        return result;
    }
    ensure!(
        !matches!(args.command, StoreCommand::Index { .. }),
        "store index is local only; use --content-config rather than --profile"
    );
    let identity = identity.context("daemon operations require the holding device identity")?;
    let path = args.profile.as_deref().unwrap();
    let pinned = ClientProfile::remote_node(path)?;
    let profile = ClientProfile::load(path)?;
    let key = passkey.map_or(SessionKey::Node(&identity.node_key), SessionKey::Passkey);
    if let Some((node, mut addresses)) = pinned {
        addresses.extend(args.addresses);
        ensure!(
            args.control_socket.is_none(),
            "a paired remote profile cannot use --control-socket"
        );
        let (endpoint, client, _) =
            crate::commands::admin::connect_remote(identity, node, addresses, &profile, key)
                .await?;
        let result = remote(client.transport().clone(), args.command).await;
        endpoint.close().await;
        result
    } else {
        ensure!(
            args.addresses.is_empty(),
            "--address requires a profile paired with a remote node"
        );
        let (client, _) =
            crate::commands::admin::connect_local(profile, args.control_socket, home, key).await?;
        // A failed connection or authentication never falls back to local Owner.
        remote(client.transport().clone(), args.command).await
    }
}

async fn remote<T>(transport: T, command: StoreCommand) -> CliResult<()>
where
    T: StreamTransport + Clone + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: Send + 'static,
{
    let resolver = ResolveClientImpl::new(transport.clone());
    let store = RemoteStore::new(transport, ram());
    execute(&store, command, move |uri| async move {
        let reply = resolver
            .resolve(hellas_rpc::pb::resolve::ResolveRequest { uri })
            .await?;
        let tree = reply.tree.context("Resolve reply has no tree")?;
        let object = ContentRef::new(hellas_rpc::ContentId::from_slice(&tree.id)?, tree.bytes);
        Ok((reply.commit_sha, object))
    })
    .await
}

async fn execute<S, F, R>(store: &S, command: StoreCommand, resolve: F) -> CliResult<()>
where
    S: ContentStore,
    F: FnOnce(String) -> R,
    R: Future<Output = CliResult<(String, ContentRef)>>,
{
    match command {
        StoreCommand::Index { .. } => unreachable!("index handled before connection"),
        StoreCommand::Stat { pin, path } => {
            let at = Path::new(PinName::new(pin)?, path)?;
            target(
                store
                    .stat(&Scope::Owner, &at)
                    .await?
                    .context("content not found")?
                    .target,
            );
        }
        StoreCommand::Read {
            pin,
            path,
            start,
            end,
            out,
        } => {
            let at = Path::new(PinName::new(pin)?, path)?;
            let object = store
                .stat(&Scope::Owner, &at)
                .await?
                .context("content not found")?
                .target
                .object();
            let mut reader = store
                .read(&Scope::Owner, &at, start..end.unwrap_or(object.bytes()))
                .await?;
            let mut out: Box<dyn std::io::Write + Send> = match out {
                Some(path) => Box::new(std::fs::File::create(path)?),
                None => Box::new(std::io::stdout()),
            };
            while let Some(chunk) = reader.bytes.next().await {
                out.write_all(&chunk?)?;
            }
            out.flush()?;
        }
        StoreCommand::Acquire {
            source,
            pin,
            policy: selected,
            expect,
            bytes,
            sha256,
            path,
            source_pin,
        } => {
            let expect = expect
                .map(|id| -> CliResult<_> {
                    Ok(ContentRef::new(
                        id.parse()?,
                        bytes.context("--expect requires --bytes")?,
                    ))
                })
                .transpose()?;
            ensure!(
                !pin.starts_with("config/"),
                "config/ pins belong to content configuration"
            );
            let pin = PinTarget {
                name: PinName::new(pin)?,
                policy: selected.parse()?,
            };
            let source = if source.starts_with("hf://") {
                ensure!(
                    bytes.is_none() || expect.is_some(),
                    "HF --bytes requires --expect"
                );
                ensure!(
                    sha256.is_none() && source_pin.is_none(),
                    "HF has no --sha256 or --source-pin"
                );
                let repo = hellas_store::hf::Repo::from_uri(&source)?;
                ensure!(
                    hellas_store::hf::immutable_sha(&repo.revision),
                    "acquire requires hf://repo@sha; run hellas store resolve first to print the immutable SHA"
                );
                eprintln!("commit: {}", repo.revision);
                Source::HfXet {
                    commit: repo.revision.clone(),
                    repo,
                    path,
                }
            } else if let Some(node) = source.strip_prefix("peer://") {
                ensure!(
                    bytes.is_none() || expect.is_some(),
                    "peer --bytes requires --expect"
                );
                ensure!(sha256.is_none(), "peer source has no --sha256");
                let node: iroh::EndpointId = node.parse()?;
                Source::Peer {
                    node: *node.as_bytes(),
                    at: Path::new(
                        PinName::new(source_pin.context("peer source requires --source-pin")?)?,
                        path.unwrap_or_default(),
                    )?,
                }
            } else {
                ensure!(
                    path.is_none() && source_pin.is_none(),
                    "HTTPS has no --path or --source-pin"
                );
                Source::Https {
                    url: source.parse()?,
                    bytes: bytes.context("HTTPS requires --bytes")?,
                    sha256: sha256
                        .map(|sha| hellas_auth::hex::parse(&sha))
                        .transpose()?,
                }
            };
            let acquired = store.acquire(&Scope::Owner, source, expect, pin).await?;
            println!(
                "id\t{}\nbytes\t{}",
                acquired.object.id(),
                acquired.object.bytes()
            );
        }
        StoreCommand::Pin { command } => match command {
            PinCommand::Set {
                name,
                id,
                bytes,
                tree,
                policy: selected,
                expires_ms,
            } => {
                ensure!(
                    !name.starts_with("config/"),
                    "config/ pins belong to content configuration"
                );
                let name = PinName::new(name)?;
                let object = ContentRef::new(id.parse()?, bytes);
                let value = PinValue {
                    target: if tree {
                        Target::Tree(object)
                    } else {
                        Target::Object(object)
                    },
                    policy: selected.parse()?,
                    expires: expires_ms.map(hellas_auth::authority::UnixMillis),
                };
                let previous = find_pin(store, &name).await?;
                store
                    .set_pin(&Scope::Owner, &name, previous.as_ref(), Some(value))
                    .await?;
            }
            PinCommand::Rm { name } => {
                let name = PinName::new(name)?;
                let previous = find_pin(store, &name).await?.context("pin not found")?;
                store
                    .set_pin(&Scope::Owner, &name, Some(&previous), None)
                    .await?;
            }
            PinCommand::Ls { prefix } => {
                let mut cursor = Cursor::default();
                loop {
                    let page = store.pins(&Scope::Owner, &prefix, cursor).await?;
                    for (name, value) in page.pins {
                        println!(
                            "{}\t{}\t{}\t{:?}\t{:?}",
                            name.as_str(),
                            value.target.object().id(),
                            value.target.object().bytes(),
                            value.policy,
                            value.expires
                        );
                    }
                    match page.next {
                        Some(next) => cursor = next,
                        None => break,
                    }
                }
            }
        },
        StoreCommand::Collect => {
            let result = store.collect(&Scope::Owner).await?;
            println!("objects\t{}\nbytes\t{}", result.objects, result.bytes);
        }
        StoreCommand::Resolve { uri } => {
            let (sha, tree) = resolve(uri).await?;
            println!("commit\t{sha}");
            target(Target::Tree(tree));
        }
    }
    Ok(())
}

async fn index(
    config: &content::config::Config,
    home: &StoreLocation,
    paths: Vec<PathBuf>,
    recheck: bool,
) -> CliResult<()> {
    let config = config.clone();
    let upper = config.upper(home);
    tokio::task::spawn_blocking(move || -> CliResult<()> {
        hellas_private::create_dir_all_durable(&upper)?;
        let path = upper.join("fastresume.bin");
        let records = hellas_store::fastresume::Records::default();
        let _ = records.load(&path);
        let paths = if paths.is_empty() {
            config.lower
        } else {
            paths
        };
        ensure!(
            !paths.is_empty(),
            "store index requires paths or configured lower layers"
        );
        let pool = ram();
        hellas_store::fastresume::walk_lower(&paths, |path| {
            let indexed = records.index_file(path, &pool, recheck)?;
            println!("{}\t{}\t{}", indexed.id, indexed.len, path.display());
            Ok(())
        })?;
        let saved = records.save(&upper.join("fastresume.bin"))?;
        eprintln!("indexed {saved} file identities");
        Ok(())
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::path::Path as FsPath;

    fn args(config: &FsPath, command: StoreCommand) -> StoreArgs {
        StoreArgs {
            profile: None,
            control_socket: None,
            addresses: vec![],
            content_config: Some(config.into()),
            command,
        }
    }
    #[tokio::test]
    async fn local_index_and_commands_share_the_verified_store_and_paid_ownership_refuses_fallback()
    {
        let root = tempfile::tempdir().unwrap();
        let home = StoreLocation::for_test(root.path());
        let lower = root.path().join("lower");
        std::fs::create_dir(&lower).unwrap();
        let body = b"ordinary indexed weights";
        let object = ContentRef::for_bytes(body);
        std::fs::write(lower.join("weights"), body).unwrap();
        let config = root.path().join("content.toml");
        std::fs::write(&config, format!("[content]\nupper = 'upper'\nlower = ['lower']\nindex = 'require'\n[content.pins]\n'config/weights' = {{ expect = '{}', bytes = {} }}\n", object.id(), object.bytes())).unwrap();
        run(
            args(
                &config,
                StoreCommand::Index {
                    paths: vec![],
                    recheck: false,
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(
            !root.path().join("upper/content.sqlite").exists(),
            "local indexing does not open or clean the upper"
        );
        run(
            args(
                &config,
                StoreCommand::Stat {
                    pin: "config/weights".into(),
                    path: String::new(),
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap();
        let out = root.path().join("slice");
        run(
            args(
                &config,
                StoreCommand::Read {
                    pin: "config/weights".into(),
                    path: String::new(),
                    start: 2,
                    end: Some(9),
                    out: Some(out.clone()),
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), &body[2..9]);
        run(
            args(
                &config,
                StoreCommand::Pin {
                    command: PinCommand::Set {
                        name: "alias".into(),
                        id: object.id().to_string(),
                        bytes: object.bytes(),
                        tree: false,
                        policy: "owner".into(),
                        expires_ms: None,
                    },
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap();
        run(
            args(
                &config,
                StoreCommand::Pin {
                    command: PinCommand::Rm {
                        name: "alias".into(),
                    },
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap();
        run(args(&config, StoreCommand::Collect), &home, None, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(lower.join("weights")).unwrap(), body);
        let node = DiskStore::open(
            home.child("upper"),
            vec![lower],
            IndexMode::Require,
            None,
            ram(),
            false,
        )
        .await
        .unwrap();
        let scope = node
            .open_work(
                JobId {
                    channel: hellas_auth::Digest::hash(b"paid channel"),
                    id: hellas_auth::Digest::hash(b"paid work"),
                },
                vec![],
                0,
            )
            .await
            .unwrap();
        node.end_work(&scope).await.unwrap();
        node.close().await;
        drop(node);
        let refused = root.path().join("must-not-exist");
        let error = run(
            args(
                &config,
                StoreCommand::Read {
                    pin: "config/weights".into(),
                    path: String::new(),
                    start: 0,
                    end: None,
                    out: Some(refused.clone()),
                },
            ),
            &home,
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.chain().any(|error| {
            error
                .to_string()
                .contains("run the command against the daemon")
        }));
        assert!(!refused.exists());
    }

    #[tokio::test]
    async fn mutable_hf_acquire_cannot_create_or_overwrite_an_unrequested_resolve_pin() {
        let store = MemoryStore::new(ram());
        hellas_channel::content::upload_bytes(
            &store,
            &Scope::Owner,
            b"explicit owner alias",
            Some(PinTarget {
                name: PinName::new(format!("hf/org/repo@{}", "a".repeat(40))).unwrap(),
                policy: PinPolicy::Public,
            }),
        )
        .await
        .unwrap();
        let before = store
            .pins(&Scope::Owner, "", Cursor::default())
            .await
            .unwrap()
            .pins;
        for source in ["hf://org/repo", "hf://org/repo@main"] {
            let error = execute(
                &store,
                StoreCommand::Acquire {
                    source: source.into(),
                    pin: "requested/model".into(),
                    policy: "jobs".into(),
                    expect: None,
                    bytes: None,
                    sha256: None,
                    path: None,
                    source_pin: None,
                },
                |_| async {
                    panic!("Acquire must not invoke the pinning Resolve operation");
                },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("run hellas store resolve first"));
            assert_eq!(
                store
                    .pins(&Scope::Owner, "", Cursor::default())
                    .await
                    .unwrap()
                    .pins,
                before
            );
        }
    }

    #[tokio::test]
    async fn source_byte_arguments_are_enforced_instead_of_silently_ignored() {
        let store = MemoryStore::new(ram());
        let node = iroh::SecretKey::from_bytes(&[9; 32]).public();
        for source in [
            format!("hf://org/repo@{}", "a".repeat(40)),
            format!("peer://{node}"),
        ] {
            let source_pin = source
                .starts_with("peer://")
                .then(|| "public/source".to_owned());
            let error = execute(
                &store,
                StoreCommand::Acquire {
                    source,
                    pin: "destination".into(),
                    policy: "owner".into(),
                    expect: None,
                    bytes: Some(1),
                    sha256: None,
                    path: None,
                    source_pin,
                },
                |_| async { anyhow::bail!("unexpected Resolve") },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("--bytes requires --expect"));
        }
        // HTTPS consumes standalone bytes. This deliberately invalid scheme
        // reaches the real backend URL check, rather than being rejected by an
        // unrelated expectation requirement or making a network request.
        let error = execute(
            &store,
            StoreCommand::Acquire {
                source: "http://localhost/file".into(),
                pin: "destination".into(),
                policy: "owner".into(),
                expect: None,
                bytes: Some(1),
                sha256: None,
                path: None,
                source_pin: None,
            },
            |_| async { anyhow::bail!("unexpected Resolve") },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("HTTPS source URL"));
        assert!(
            store
                .pins(&Scope::Owner, "", Cursor::default())
                .await
                .unwrap()
                .pins
                .is_empty()
        );
    }

    #[test]
    fn store_surface_has_only_scoped_operations_and_explicit_daemon_credentials() {
        for command in [
            vec!["stat", "weights"],
            vec!["read", "weights"],
            vec!["collect"],
            vec!["pin", "ls"],
            vec!["resolve", "hf://org/repo"],
            vec![
                "acquire",
                "hf://org/repo@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--pin",
                "weights",
            ],
        ] {
            let args = ["hellas", "store"].into_iter().chain(command);
            assert!(crate::Cli::try_parse_from(args).is_ok());
        }
        assert!(
            crate::Cli::try_parse_from([
                "hellas",
                "store",
                "--control-socket",
                "daemon",
                "collect"
            ])
            .is_err()
        );
    }
}
