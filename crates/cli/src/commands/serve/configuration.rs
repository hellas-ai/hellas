//! In-process configuration on the normal host's serialized provider lifecycle.
use super::*;
use hellas_sdk::node_control::{configuration::*, host::*};
use std::path::Path;

pub(super) async fn start_host<R: hellas_attestation::RootProver + Send + Sync + 'static>(
    mut provider: hellas_sdk::ProviderOptions<R>,
    grants: Option<hellas_sdk::grant_config::GrantConfig>,
    path: Option<PathBuf>,
    transport: Option<iroh::Endpoint>,
) -> CliResult<HostHandle> {
    let path = path.map(std::path::absolute).transpose()?;
    let control = prepare_provider(&mut provider, grants).await?;
    let transport = match (transport, &control) {
        (Some(endpoint), _) => Some(endpoint),
        (None, Some((_, config))) => Some(
            bind_transport(
                provider.secret_key.clone(),
                provider.port,
                config.remote.clone(),
            )
            .await?,
        ),
        (None, None) => None,
    };
    if let Some(path) = &path {
        clean_unused_keys(path)?;
    }
    let prepare = path.clone().map(|path| -> ProviderPrepare {
        Arc::new(move |update| Ok(Box::new(StagedConfiguration::prepare(&path, update)?)))
    });
    let factory = ProviderFactory {
        prepare,
        start: Arc::new(move |control| {
            let mut provider = provider.clone();
            let path = path.clone();
            Box::pin(async move {
                let metadata = match &path {
                    Some(path) => {
                        provider.executor.fetch_routes = load_fetch_config(path)?;
                        Some(metadata(&read(path)?))
                    }
                    None => None,
                };
                if let Some(control) = control {
                    provider = provider.on_host(control)?;
                }
                let handle = hellas_sdk::start_fetch_provider(provider).await?;
                Ok(match metadata {
                    Some(metadata) => handle.with_configuration(metadata),
                    None => handle,
                })
            })
        }),
    };
    Ok(HostHandle::start(HostOptions {
        transport,
        start_provider: true,
        control,
        provider: Some(factory),
        gateway: None,
    })
    .await?)
}
fn read(path: &Path) -> CliResult<FetchConfigFile> {
    Ok(serde_json::from_slice(
        &hellas_private::read_bounded_regular_file(path, 64 * 1024)?,
    )?)
}
fn metadata(config: &FetchConfigFile) -> ProviderMetadata {
    ProviderMetadata {
        revision: config.revision,
        endpoints: config
            .routes
            .iter()
            .filter_map(|route| {
                let FetchDestination::Http { config } = &route.destination else {
                    return None;
                };
                Some(EndpointMetadata {
                    service: route.service.clone(),
                    method: route.method.clone(),
                    allowed_hosts: config.allowed_hosts.clone(),
                    keys: config.credentials.keys().cloned().collect(),
                })
            })
            .collect(),
    }
}
struct StagedConfiguration {
    path: PathBuf,
    old: Vec<u8>,
    stage: Option<tempfile::TempPath>,
    metadata: ProviderMetadata,
    committed: bool,
    retain_keys: bool,
}
impl StagedConfiguration {
    fn prepare(path: &Path, update: ProviderUpdate) -> CliResult<Self> {
        use std::io::Write as _;
        let parent = path.parent().context("configuration needs a parent")?;
        anyhow::ensure!(
            !std::fs::metadata(path)?.permissions().readonly()
                && !std::fs::metadata(parent)?.permissions().readonly(),
            "configuration is read-only"
        );
        let old = hellas_private::read_bounded_regular_file(path, 64 * 1024)?;
        let mut prepared = Self {
            path: path.into(),
            old,
            stage: None,
            metadata: ProviderMetadata::default(),
            committed: false,
            retain_keys: false,
        };
        let bytes = prepare_update(path, &prepared.old, update)?;
        prepared.metadata = metadata(&serde_json::from_slice(&bytes)?);
        let mut stage = hellas_private::private_tempfile(parent, ".configure-", ".json")?;
        stage.write_all(&bytes)?;
        stage.as_file().sync_all()?;
        prepared.stage = Some(stage.into_temp_path());
        Ok(prepared)
    }
}
impl PreparedProviderConfiguration for StagedConfiguration {
    fn commit(&mut self) -> Result<ProviderMetadata, ProviderErrorBox> {
        let stage = self
            .stage
            .as_ref()
            .ok_or("configuration already committed")?;
        std::fs::rename(stage, &self.path)?;
        self.committed = true;
        hellas_private::sync_directory(self.path.parent().ok_or("configuration needs a parent")?)?;
        self.stage = None;
        Ok(self.metadata.clone())
    }
    fn rollback(&mut self) -> Result<(), ProviderErrorBox> {
        if self.committed {
            if let Err(error) = hellas_private::write_atomically(&self.path, ".rollback", &self.old)
            {
                self.retain_keys = true;
                return Err(error.into());
            }
            self.committed = false;
        }
        Ok(())
    }
}
impl Drop for StagedConfiguration {
    fn drop(&mut self) {
        if self.retain_keys {
            return;
        }
        if let Err(error) = clean_unused_keys(&self.path) {
            tracing::warn!(%error, "provider configuration key cleanup failed");
        }
    }
}
fn prepare_update(path: &Path, old: &[u8], update: ProviderUpdate) -> CliResult<Vec<u8>> {
    let mut file: FetchConfigFile = serde_json::from_slice(old)?;
    anyhow::ensure!(
        file.revision == update.expected_revision,
        "stale provider configuration revision"
    );
    match update.change.context("configuration change is required")? {
        UpstreamChange::SetEndpoint(endpoint) => {
            anyhow::ensure!(
                !endpoint.service.is_empty()
                    && !endpoint.method.is_empty()
                    && !endpoint.allowed_hosts.is_empty(),
                "endpoint must name a route and hosts"
            );
            let replacement = hellas_providers::HttpProviderConfig {
                allowed_hosts: endpoint.allowed_hosts,
                allow_private_addresses: endpoint.allow_private_addresses,
                credentials: Default::default(),
            };
            if let Some(route) = file
                .routes
                .iter_mut()
                .find(|route| route.service == endpoint.service && route.method == endpoint.method)
            {
                let FetchDestination::Http { config } = &mut route.destination else {
                    anyhow::bail!("route is not HTTP")
                };
                config.allowed_hosts = replacement.allowed_hosts;
                config.allow_private_addresses = replacement.allow_private_addresses;
            } else {
                anyhow::ensure!(file.routes.len() < 16, "too many upstream routes");
                file.routes.push(FetchConfigRoute {
                    service: endpoint.service,
                    method: endpoint.method,
                    destination: FetchDestination::Http {
                        config: replacement,
                    },
                    capabilities: Default::default(),
                });
            }
        }
        UpstreamChange::RemoveEndpoint(UpstreamRoute { service, method }) => {
            let position = file
                .routes
                .iter()
                .position(|r| r.service == service && r.method == method)
                .context("unknown route")?;
            file.routes.remove(position);
        }
        UpstreamChange::RemoveKey(UpstreamKeyId {
            service,
            method,
            key,
        }) => {
            anyhow::ensure!(
                http(&mut file, &service, &method)?
                    .credentials
                    .remove(&key)
                    .is_some(),
                "unknown upstream key"
            );
        }
        change @ (UpstreamChange::AddKey(_) | UpstreamChange::ReplaceKey(_)) => {
            let replace = matches!(change, UpstreamChange::ReplaceKey(_));
            let (UpstreamChange::AddKey(key) | UpstreamChange::ReplaceKey(key)) = change else {
                anyhow::bail!("invalid key update")
            };
            anyhow::ensure!(
                !key.key.is_empty()
                    && key.key.len() <= 128
                    && !key.secret.is_empty()
                    && key.secret.len() <= 16 * 1024,
                "invalid upstream key"
            );
            let config = http(&mut file, &key.service, &key.method)?;
            anyhow::ensure!(
                config.credentials.contains_key(&key.key) == replace,
                "add requires a new key ID; replace requires an existing ID"
            );
            anyhow::ensure!(
                config.credentials.len() < 64 || replace,
                "too many upstream keys"
            );
            for origin in &key.allowed_origins {
                let url = reqwest::Url::parse(origin)?;
                anyhow::ensure!(
                    url.scheme() == "https"
                        && url.host_str().is_some_and(|host| config
                            .allowed_hosts
                            .iter()
                            .any(|allowed| allowed == host)),
                    "key must use an existing endpoint host"
                );
            }
            let key_root = key_directory(path)?;
            check_key_directory(&key_root)?;
            hellas_private::create_dir_all_durable(&key_root)?;
            check_key_directory(&key_root)?;
            hellas_private::restrict_directory(&key_root)?;
            let parent = key_root.as_path();
            let temporary = hellas_private::private_tempfile(parent, ".upstream-key-", ".json")?;
            let secret = serde_json::to_vec(&serde_json::json!({"secret":key.secret}))?;
            use std::io::Write;
            let mut temporary = temporary;
            temporary.write_all(&secret)?;
            temporary.as_file().sync_all()?;
            let (_, secret_path) = temporary.keep()?;
            hellas_private::sync_directory(parent)?;
            let trust_roots = config
                .credentials
                .get(&key.key)
                .and_then(|old| old.trust_roots.clone());
            config.credentials.insert(
                key.key,
                hellas_providers::HttpCredentialConfig {
                    allowed_origins: key.allowed_origins,
                    allowed_paths: key.allowed_paths,
                    allowed_methods: key.allowed_methods,
                    trust_roots,
                    header_name: key.header_name,
                    source: hellas_providers::HttpSecretConfig {
                        secret_env: None,
                        secret_store: None,
                        secret_file: Some(secret_path),
                        secret_field: Some("secret".into()),
                        refresh: None,
                        prefix: key.prefix,
                    },
                },
            );
        }
    }
    // Compile every route through the same parser/provider validation as startup.
    for route in &file.routes {
        route
            .destination
            .clone()
            .into_entry(route.capabilities.clone().into_policy()?)?;
    }
    file.revision = file
        .revision
        .checked_add(1)
        .context("configuration revision exhausted")?;
    let bytes = serde_json::to_vec(&file)?;
    anyhow::ensure!(
        bytes.len() <= 64 * 1024,
        "provider configuration exceeds limit"
    );
    Ok(bytes)
}
fn http<'a>(
    file: &'a mut FetchConfigFile,
    service: &str,
    method: &str,
) -> CliResult<&'a mut hellas_providers::HttpProviderConfig> {
    let route = file
        .routes
        .iter_mut()
        .find(|route| route.service == service && route.method == method)
        .context("unknown endpoint")?;
    match &mut route.destination {
        FetchDestination::Http { config } => Ok(config),
        _ => anyhow::bail!("route is not HTTP"),
    }
}

// Only files created by this configuration writer are collected. User-supplied
// file/environment/refresh sources are never deleted or copied into status.
fn clean_unused_keys(path: &Path) -> CliResult<()> {
    let file = read(path)?;
    let used: std::collections::BTreeSet<_> = file
        .routes
        .iter()
        .flat_map(|route| match &route.destination {
            FetchDestination::Http { config } => config
                .credentials
                .values()
                .filter_map(|key| key.source.secret_file.as_ref())
                .collect::<Vec<_>>(),
            _ => vec![],
        })
        .collect();
    let key_root = key_directory(path)?;
    check_key_directory(&key_root)?;
    if !key_root.try_exists()? {
        return Ok(());
    }
    let parent = key_root.as_path();
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".upstream-key-")
            && entry.file_type()?.is_file()
            && !used.contains(&entry.path())
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    hellas_private::sync_directory(parent)?;
    Ok(())
}

fn key_directory(path: &Path) -> CliResult<PathBuf> {
    let mut name = path
        .file_name()
        .context("configuration needs a file name")?
        .to_os_string();
    name.push(".keys");
    Ok(path.with_file_name(name))
}

fn check_key_directory(path: &Path) -> CliResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "managed key directory must be an ordinary directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn apply(path: &Path, update: ProviderUpdate) -> CliResult<()> {
        let mut prepared = StagedConfiguration::prepare(path, update)?;
        prepared.commit().map_err(anyhow::Error::from_boxed)?;
        Ok(())
    }

    fn endpoint() -> UpstreamChange {
        UpstreamChange::SetEndpoint(UpstreamEndpoint {
            service: "api".into(),
            method: "fetch".into(),
            allowed_hosts: vec!["example.com".into()],
            allow_private_addresses: false,
        })
    }
    fn key(secret: &str) -> UpstreamKey {
        UpstreamKey {
            service: "api".into(),
            method: "fetch".into(),
            key: "account".into(),
            allowed_origins: vec!["https://example.com".into()],
            allowed_paths: vec!["/v1/responses".into()],
            allowed_methods: vec!["POST".into()],
            header_name: "authorization".into(),
            prefix: "Bearer ".into(),
            secret: secret.into(),
        }
    }
    #[test]
    fn key_updates_are_add_only_or_replace_only_and_status_contains_no_secret() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fetch.json");
        hellas_private::write_atomically(&path, ".writing", br#"{"routes":[]}"#).unwrap();
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 0,
                change: Some(endpoint()),
            },
        )
        .unwrap();
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 1,
                change: Some(UpstreamChange::AddKey(key("first-private-key"))),
            },
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(
            apply(
                &path,
                ProviderUpdate {
                    expected_revision: 2,
                    change: Some(UpstreamChange::AddKey(key("replacement-through-add")))
                }
            )
            .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
        let status = serde_json::to_string(&metadata(&read(&path).unwrap())).unwrap();
        assert!(status.contains("account"));
        assert!(!status.contains("private-key"));
        assert!(!status.contains("secret_file"));
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 2,
                change: Some(UpstreamChange::ReplaceKey(key("second-private-key"))),
            },
        )
        .unwrap();
        clean_unused_keys(&path).unwrap();
        let files: Vec<_> = std::fs::read_dir(key_directory(&path).unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1);
        assert!(files.iter().all(|p| {
            !String::from_utf8_lossy(&std::fs::read(p).unwrap()).contains("first-private-key")
        }));
        assert!(
            apply(
                &path,
                ProviderUpdate {
                    expected_revision: 2,
                    change: Some(UpstreamChange::RemoveKey(UpstreamKeyId {
                        service: "api".into(),
                        method: "fetch".into(),
                        key: "account".into()
                    }))
                }
            )
            .is_err()
        );
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 3,
                change: Some(UpstreamChange::RemoveKey(UpstreamKeyId {
                    service: "api".into(),
                    method: "fetch".into(),
                    key: "account".into(),
                })),
            },
        )
        .unwrap();
        clean_unused_keys(&path).unwrap();
        assert_eq!(
            std::fs::read_dir(key_directory(&path).unwrap())
                .unwrap()
                .count(),
            0
        );
    }
    #[test]
    fn cleanup_and_failed_apply_are_confined_to_one_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let a = directory.path().join("a.json");
        let b = directory.path().join("b.json");
        for path in [&a, &b] {
            hellas_private::write_atomically(path, ".writing", br#"{"routes":[]}"#).unwrap();
            apply(
                path,
                ProviderUpdate {
                    expected_revision: 0,
                    change: Some(endpoint()),
                },
            )
            .unwrap();
            apply(
                path,
                ProviderUpdate {
                    expected_revision: 1,
                    change: Some(UpstreamChange::AddKey(key("retained-key"))),
                },
            )
            .unwrap();
        }
        let b_before = std::fs::read(&b).unwrap();
        let a_before = std::fs::read(&a).unwrap();
        let mut invalid = key("abandoned-key");
        invalid.header_name = "invalid header name".into();
        assert!(
            apply(
                &a,
                ProviderUpdate {
                    expected_revision: 2,
                    change: Some(UpstreamChange::ReplaceKey(invalid))
                }
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&a).unwrap(), a_before);
        assert_eq!(
            std::fs::read_dir(key_directory(&a).unwrap())
                .unwrap()
                .count(),
            1
        );
        clean_unused_keys(&a).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b_before);
        assert_eq!(
            std::fs::read_dir(key_directory(&b).unwrap())
                .unwrap()
                .count(),
            1
        );
        load_fetch_config(&a).unwrap();
        load_fetch_config(&b).unwrap();
    }
    #[test]
    fn staged_replacement_retains_old_keys_until_commit_succeeds_or_rolls_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fetch.json");
        std::fs::write(&path, br#"{"routes":[]}"#).unwrap();
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 0,
                change: Some(endpoint()),
            },
        )
        .unwrap();
        apply(
            &path,
            ProviderUpdate {
                expected_revision: 1,
                change: Some(UpstreamChange::AddKey(key("original-key"))),
            },
        )
        .unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut prepared = StagedConfiguration::prepare(
            &path,
            ProviderUpdate {
                expected_revision: 2,
                change: Some(UpstreamChange::ReplaceKey(key("new-key"))),
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "preparation cannot change live config"
        );
        assert_eq!(
            std::fs::read_dir(key_directory(&path).unwrap())
                .unwrap()
                .count(),
            2
        );
        prepared.commit().unwrap();
        assert_eq!(
            std::fs::read_dir(key_directory(&path).unwrap())
                .unwrap()
                .count(),
            2,
            "old key remains available until startup outcome"
        );
        prepared.rollback().unwrap();
        drop(prepared);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read_dir(key_directory(&path).unwrap())
                .unwrap()
                .count(),
            1
        );
        load_fetch_config(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_symlinked_key_directory() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let protected = outside.path().join(".upstream-key-protected.json");
        std::fs::write(&protected, "retained").unwrap();
        let path = directory.path().join("fetch.json");
        std::fs::write(&path, br#"{"routes":[]}"#).unwrap();
        std::os::unix::fs::symlink(outside.path(), key_directory(&path).unwrap()).unwrap();
        assert!(clean_unused_keys(&path).is_err());
        assert_eq!(std::fs::read_to_string(protected).unwrap(), "retained");
    }
}
