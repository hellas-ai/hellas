//! The node's declared content file and its filesystem reload trigger.
use anyhow::{Context, Result};
use hellas_store::content::{
    DiskStore,
    config::{Config, Reconciler},
};
use notify::{EventKind, RecursiveMode, Watcher};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tokio::{sync::watch, task::JoinHandle};

/// A file or directory served to jobs, and every object it holds.
type Content = (PathBuf, Vec<hellas_rpc::ContentRef>);

pub(crate) struct ContentConfiguration {
    path: Option<PathBuf>,
    content: Vec<Content>,
    config: Config,
    default_upper: Option<PathBuf>,
    watcher: Option<notify::RecommendedWatcher>,
    changes: watch::Receiver<()>,
}

impl ContentConfiguration {
    /// Every regular file under each of `content` (a file or a directory) is
    /// served to jobs that name it, as one `config/content-NNNN` Jobs pin.
    /// They are hashed once, here.
    pub(crate) fn load(path: Option<PathBuf>, content: Vec<PathBuf>) -> Result<Self> {
        let path = path.map(std::path::absolute).transpose()?;
        let content: Vec<Content> = content
            .into_iter()
            .map(|root| {
                let root = std::path::absolute(&root)?;
                let objects = files(&root)?
                    .iter()
                    .map(|file| {
                        hellas_store::content::file_content(file)
                            .with_context(|| format!("failed to hash {}", file.display()))
                    })
                    .collect::<Result<_>>()?;
                Ok((root, objects))
            })
            .collect::<Result<_>>()?;
        let (changed, changes) = watch::channel(());
        let watcher = if let Some(path) = &path {
            let file = path.clone();
            let mut watcher = notify::recommended_watcher(
                move |event: notify::Result<notify::Event>| match event {
                    Ok(event)
                        if !matches!(event.kind, EventKind::Access(_))
                            && event.paths.iter().any(|path| path == &file) =>
                    {
                        changed.send_replace(());
                    }
                    Err(error) => tracing::warn!(%error, "content configuration watch failed"),
                    _ => {}
                },
            )?;
            // Watch the parent so atomic replacement keeps the trigger alive.
            watcher.watch(
                path.parent()
                    .context("content configuration needs a parent")?,
                RecursiveMode::NonRecursive,
            )?;
            Some(watcher)
        } else {
            None
        };
        let config = read(path.as_deref(), &content)?;
        Ok(Self {
            path,
            content,
            config,
            default_upper: None,
            watcher,
            changes,
        })
    }

    #[cfg(feature = "compute")]
    pub(crate) fn with_default_upper(mut self, upper: PathBuf) -> Self {
        if self.config.upper.is_none() {
            self.config.upper = Some(upper.clone());
        }
        self.default_upper = Some(upper);
        self
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) async fn start(self, store: DiskStore) -> Result<ContentReload> {
        let reconciler = Reconciler::new(self.config.clone())?;
        reconciler.apply(&store, self.config.clone()).await?;
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(self.run(store, reconciler, stopped));
        Ok(ContentReload { stop, task })
    }

    async fn run(
        self,
        store: DiskStore,
        reconciler: Reconciler,
        mut stopped: watch::Receiver<bool>,
    ) {
        let _watcher = self.watcher;
        let mut changes = self.changes;
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                changed = changes.changed() => if changed.is_err() { break; },
            }
            let result = async {
                let mut config = read(self.path.as_deref(), &self.content)?;
                if config.upper.is_none() {
                    config.upper = self.default_upper.clone();
                }
                reconciler.apply(&store, config).await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, "content configuration reload failed");
            }
        }
    }
}

pub(crate) struct ContentReload {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl ContentReload {
    pub(crate) async fn shutdown(self) -> Result<()> {
        self.stop.send_replace(true);
        self.task.await?;
        Ok(())
    }
}

/// The regular files at `root`: itself, or every one under it, in path order.
fn files(root: &Path) -> Result<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("failed to read {}", root.display()))?;
    if metadata.is_file() {
        return Ok(vec![root.to_owned()]);
    }
    anyhow::ensure!(
        metadata.is_dir(),
        "{} is not a regular file or directory",
        root.display()
    );
    let mut found = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?;
    entries.sort();
    for entry in entries {
        let kind = std::fs::symlink_metadata(&entry)?.file_type();
        if kind.is_file() {
            found.push(entry);
        } else if kind.is_dir() {
            found.extend(files(&entry)?);
        }
    }
    Ok(found)
}

fn read(path: Option<&Path>, content: &[Content]) -> Result<Config> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct File {
        #[serde(default)]
        content: Config,
    }
    let mut config = match path {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str::<File>(&text)
                .with_context(|| format!("failed to parse {}", path.display()))?
                .content
        }
        None => Config::default(),
    };
    if let Some(parent) = path.and_then(Path::parent) {
        if let Some(upper) = &mut config.upper {
            *upper = parent.join(&*upper);
        }
        for lower in &mut config.lower {
            *lower = parent.join(&*lower);
        }
    }
    use hellas_store::content::config::{Declaration, Object};
    anyhow::ensure!(
        content.is_empty()
            || !config
                .pins
                .keys()
                .any(|name| name.starts_with("config/content-")),
        "config/content-* is reserved for --content"
    );
    let mut index = 0;
    for (root, objects) in content {
        config.lower.push(root.clone());
        for object in objects {
            config.pins.insert(
                format!("config/content-{index:04}"),
                Declaration::Object(Object {
                    url: None,
                    path: None,
                    bytes: Some(object.bytes()),
                    expect: Some(object.id().to_string()),
                    sha256: None,
                    policy: None,
                }),
            );
            index += 1;
        }
    }
    config.validate()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_store::content::{ContentStore, Cursor, PinName, PinPolicy, Reservations, Scope};

    fn document(pin: &str) -> String {
        let object = hellas_rpc::ContentRef::for_bytes(b"weights");
        format!(
            "[content]\nupper = 'upper'\nlower = ['lower']\n[content.pins]\n'config/{pin}' = {{ bytes = {}, expect = '{}' }}\n",
            object.bytes(),
            object.id()
        )
    }

    #[test]
    fn explicit_files_fail_closed_and_paths_are_relative_to_the_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("content.toml");
        assert!(ContentConfiguration::load(Some(path.clone()), vec![]).is_err());
        std::fs::write(&path, "[content]\nunknown = true\n").unwrap();
        assert!(ContentConfiguration::load(Some(path.clone()), vec![]).is_err());
        std::fs::write(&path, document("model")).unwrap();
        let loaded = ContentConfiguration::load(Some(path), vec![]).unwrap();
        assert_eq!(
            loaded
                .config
                .upper(&hellas_private::StoreLocation::for_test(root.path()))
                .as_path(),
            root.path().join("upper")
        );
        assert_eq!(loaded.config.lower, vec![root.path().join("lower")]);
    }

    #[test]
    fn content_paths_serve_every_file_they_hold_as_reserved_jobs_pins() {
        let root = tempfile::tempdir().unwrap();
        let package = root.path().join("package");
        std::fs::create_dir_all(package.join("nested")).unwrap();
        std::fs::write(package.join("weights"), b"weights").unwrap();
        std::fs::write(package.join("nested/config.json"), b"{}").unwrap();
        let single = root.path().join("model.gguf");
        std::fs::write(&single, b"gguf").unwrap();
        let loaded =
            ContentConfiguration::load(None, vec![package.clone(), single.clone()]).unwrap();
        assert_eq!(loaded.config.lower, vec![package.clone(), single.clone()]);
        let pinned: Vec<_> = loaded
            .config
            .pins
            .iter()
            .map(|(name, declaration)| {
                let hellas_store::content::config::Declaration::Object(object) = declaration else {
                    panic!("{name}")
                };
                (name.clone(), object.expect.clone().unwrap())
            })
            .collect();
        let id = |bytes: &[u8]| hellas_rpc::ContentRef::for_bytes(bytes).id().to_string();
        assert_eq!(
            pinned,
            [
                ("config/content-0000".into(), id(b"{}")),
                ("config/content-0001".into(), id(b"weights")),
                ("config/content-0002".into(), id(b"gguf")),
            ]
        );
        assert!(ContentConfiguration::load(None, vec![root.path().join("missing")]).is_err());
        let path = root.path().join("content.toml");
        std::fs::write(&path, document("content-0000")).unwrap();
        assert!(ContentConfiguration::load(Some(path), vec![package]).is_err());
    }

    #[tokio::test]
    async fn atomic_replacements_reload_the_declared_set_and_shutdown_joins_the_watcher() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("content.toml");
        std::fs::create_dir(root.path().join("lower")).unwrap();
        std::fs::write(root.path().join("lower/weights"), b"weights").unwrap();
        std::fs::write(&path, document("before")).unwrap();
        let loaded = ContentConfiguration::load(Some(path.clone()), vec![]).unwrap();
        let store = loaded
            .config
            .open(
                &hellas_private::StoreLocation::for_test(root.path()),
                Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
                false,
            )
            .await
            .unwrap();
        store.finish_recovery().await.unwrap();
        let reload = loaded.start(store.clone()).await.unwrap();
        for expected in ["after", "final"] {
            let replacement = root.path().join("replacement.toml");
            std::fs::write(&replacement, document(expected)).unwrap();
            std::fs::rename(&replacement, &path).unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                loop {
                    let page = store
                        .pins(&Scope::Owner, "config/", Cursor::default())
                        .await
                        .unwrap();
                    if page.pins.len() == 1
                        && page.pins[0].0 == PinName::new(format!("config/{expected}")).unwrap()
                    {
                        assert_eq!(page.pins[0].1.policy, PinPolicy::Jobs);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        reload.shutdown().await.unwrap();
        store.close().await;
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_quiesces_the_actual_node_while_owned_configuration_is_still_blocked() {
        use futures::FutureExt;
        use hellas_sdk::node_control::host::{HostHandle, HostOptions, ProviderFactory};
        use hellas_store::content::{PinValue, Target};
        use std::sync::{Arc, Mutex};
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("content.toml");
        std::fs::create_dir(root.path().join("lower")).unwrap();
        std::fs::write(&path, "[content]\nupper = 'upper'\n").unwrap();
        let loaded = ContentConfiguration::load(Some(path.clone()), vec![]).unwrap();
        let store = loaded
            .config
            .open(
                &hellas_private::StoreLocation::for_test(root.path()),
                Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
                false,
            )
            .await
            .unwrap();
        store.finish_recovery().await.unwrap();
        hellas_channel::content::upload_object(&store, b"weights")
            .await
            .unwrap();
        let identity = crate::identity::load_or_create(&root.path().join("identity")).unwrap();
        let provider = hellas_sdk::ProviderOptions {
            content: store.clone(),
            executor: hellas_executor::ExecutorSpawnConfig::new(
                Arc::new(identity.node_key.clone()),
                hellas_executor::FetchRouteRegistry::default(),
            ),
            grants: None,
            port: Some(0),
            build: "shutdown-test".into(),
            graffiti: vec![],
            discovery: false,
            work: None,
            secret_key: identity.transport_key.clone(),
            open_identity: identity.open_identity(),
        };
        let node = HostHandle::start(HostOptions {
            content: store.clone(),
            transport: None,
            start_provider: true,
            control: None,
            gateway: None,
            provider: Some(ProviderFactory {
                prepare: None,
                start: Arc::new(move |control| {
                    assert!(control.is_none());
                    let provider = provider.clone();
                    Box::pin(async move { Ok(hellas_sdk::start_fetch_provider(provider).await?) })
                }),
            }),
        })
        .await
        .unwrap();
        let mut endpoint = node.provider_endpoint();
        assert!(endpoint.borrow().is_some());
        let reconciler = Reconciler::new(loaded.config.clone()).unwrap();
        reconciler
            .apply(&store, loaded.config.clone())
            .await
            .unwrap();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(loaded.run(store.clone(), reconciler.clone(), stopped));
        let reload = ContentReload { stop, task };
        let (entered, received) = tokio::sync::oneshot::channel();
        let entered = Arc::new(Mutex::new(Some(entered)));
        let (release, wait) = std::sync::mpsc::sync_channel(0);
        let wait = Arc::new(Mutex::new(wait));
        let scope = Scope::Owner.bind(
            move || {
                let entered = entered.clone();
                let wait = wait.clone();
                async move {
                    Ok(move || {
                        if let Some(entered) = entered.lock().unwrap().take() {
                            entered.send(()).unwrap();
                            wait.lock().unwrap().recv().unwrap();
                        }
                        Ok(())
                    })
                }
            },
            std::future::pending,
        );
        let held_store = store.clone();
        let writer = tokio::spawn(async move {
            held_store
                .set_pin(
                    &scope,
                    &PinName::new("private/gate".into()).unwrap(),
                    None,
                    Some(PinValue {
                        target: Target::Object(hellas_rpc::ContentRef::for_bytes(b"weights")),
                        policy: PinPolicy::Owner,
                        expires: None,
                    }),
                )
                .await
                .unwrap();
        });
        received.await.unwrap();
        let replacement = root.path().join("replacement.toml");
        std::fs::write(&replacement, document("after")).unwrap();
        std::fs::rename(replacement, path).unwrap();
        // Witness the actual owned application holding the reconciler mutex
        // while it waits for the real Core gate before initiating shutdown.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while reconciler.current().now_or_never().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let shutting = tokio::spawn(crate::commands::serve::shutdown_content(
            node,
            reload,
            store.clone(),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while endpoint.borrow().is_some() {
                endpoint.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(
            !shutting.is_finished(),
            "owned configuration still waits for its effect"
        );
        release.send(()).unwrap();
        writer.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), shutting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
