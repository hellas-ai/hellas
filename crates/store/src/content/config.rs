//! Declared node content, reconciled through the ordinary scoped store operations.
use super::{owner_pin as pin, owner_pins as snapshot, *};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

const MANAGED: &str = "config/";
const STAGING: &str = "config/.acquire/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes(pub u64);
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Value {
            Integer(u64),
            Text(String),
        }
        match Value::deserialize(deserializer)? {
            Value::Integer(bytes) => Ok(Self(bytes)),
            Value::Text(text) => {
                let text = text.trim();
                let at = text
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(text.len());
                let number = text[..at]
                    .parse::<u64>()
                    .map_err(serde::de::Error::custom)?;
                let scale = match text[at..].trim() {
                    "" | "B" => 1,
                    "KiB" => 1_u64 << 10,
                    "MiB" => 1_u64 << 20,
                    "GiB" => 1_u64 << 30,
                    "TiB" => 1_u64 << 40,
                    _ => return Err(serde::de::Error::custom("unknown byte unit")),
                };
                number
                    .checked_mul(scale)
                    .map(Self)
                    .ok_or_else(|| serde::de::Error::custom("byte count overflow"))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Policy {
    Name(String),
    Channel { channel: String },
}
impl Policy {
    fn value(&self) -> Result<PinPolicy> {
        match self {
            Self::Name(name) => name.parse(),
            Self::Channel { channel } => format!("channel:{channel}").parse(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Declaration {
    Hf(String),
    Object(Object),
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub url: Option<String>,
    pub path: Option<String>,
    pub bytes: Option<u64>,
    pub expect: Option<String>,
    pub sha256: Option<String>,
    pub policy: Option<Policy>,
}
impl Declaration {
    fn policy(&self) -> Result<PinPolicy> {
        match self {
            Self::Hf(_) => Ok(PinPolicy::Jobs),
            Self::Object(object) => object
                .policy
                .as_ref()
                .map(Policy::value)
                .transpose()
                .map(|policy| policy.unwrap_or(PinPolicy::Jobs)),
        }
    }
    fn specification(&self) -> Result<(Option<Source>, Option<ContentRef>)> {
        let (url, path, expected, sha256) = match self {
            Self::Hf(uri) => (Some(uri.as_str()), None, None, None),
            Self::Object(object) => {
                let expected = match (&object.expect, object.bytes) {
                    (Some(id), Some(bytes)) => Some(ContentRef::new(
                        id.parse()
                            .map_err(|_| Error::Invalid("declared ContentId"))?,
                        bytes,
                    )),
                    (None, None) => None,
                    _ => {
                        return Err(Error::Invalid(
                            "declared identity requires both expect and bytes",
                        ));
                    }
                };
                let sha256 = object
                    .sha256
                    .as_deref()
                    .map(hellas_auth::hex::parse)
                    .transpose()
                    .map_err(|_| Error::Invalid("HTTPS SHA-256"))?;
                (object.url.as_deref(), object.path.clone(), expected, sha256)
            }
        };
        let source = match url {
            Some(uri) if uri.starts_with("hf://") => {
                if sha256.is_some() {
                    return Err(Error::Invalid("HF source has no transport SHA-256"));
                }
                let repo = crate::hf::Repo::from_uri(uri)
                    .map_err(|_| Error::Invalid("HF repository URI"))?;
                if !crate::hf::immutable_sha(&repo.revision) {
                    return Err(Error::Invalid(
                        "configured HF source requires an immutable commit SHA",
                    ));
                }
                if let Some(path) = &path {
                    tree::validate_path(path, false)?;
                }
                Some(Source::HfXet {
                    commit: repo.revision.clone(),
                    repo,
                    path,
                })
            }
            Some(uri) => {
                if path.is_some() {
                    return Err(Error::Invalid("path is only for an HF source"));
                }
                let url = url::Url::parse(uri).map_err(|_| Error::Invalid("HTTPS source URL"))?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err(Error::Invalid("HTTPS source URL"));
                }
                let bytes = match self {
                    Self::Object(object) => object.bytes,
                    _ => None,
                }
                .ok_or(Error::Invalid("HTTPS source requires bytes"))?;
                Some(Source::Https { url, sha256, bytes })
            }
            None => {
                if path.is_some() || sha256.is_some() || expected.is_none() {
                    return Err(Error::Invalid(
                        "local declaration requires expect and bytes",
                    ));
                }
                None
            }
        };
        Ok((source, expected))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum MissPolicy {
    Name(RefuseName),
    Allow {
        allow_list: BTreeMap<String, Object>,
    },
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefuseName {
    Refuse,
}
impl Default for MissPolicy {
    fn default() -> Self {
        Self::Name(RefuseName::Refuse)
    }
}
impl MissPolicy {
    fn policy(&self) -> Result<Arc<dyn OnMiss>> {
        Ok(match self {
            Self::Name(RefuseName::Refuse) => Arc::new(Refuse),
            Self::Allow { allow_list } => {
                let mut sources = BTreeMap::new();
                for (id, object) in allow_list {
                    if object.policy.is_some() {
                        return Err(Error::Invalid(
                            "AllowList acquisitions use the requesting work lifetime",
                        ));
                    }
                    let id = id
                        .parse()
                        .map_err(|_| Error::Invalid("AllowList ContentId"))?;
                    let bytes = object
                        .bytes
                        .ok_or(Error::Invalid("AllowList requires bytes"))?;
                    let mut object = object.clone();
                    if object.expect.as_ref().is_some_and(|expected| {
                        expected.parse::<hellas_rpc::ContentId>().ok() != Some(id)
                    }) {
                        return Err(Error::Invalid("AllowList identity mismatch"));
                    }
                    object.expect = Some(id.to_string());
                    let (source, _) = Declaration::Object(object).specification()?;
                    sources.insert(
                        id,
                        (
                            bytes,
                            source.ok_or(Error::Invalid("AllowList requires a source"))?,
                        ),
                    );
                }
                Arc::new(AllowList(sources))
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policies {
    #[serde(default)]
    pub on_miss: MissPolicy,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub upper: Option<PathBuf>,
    #[serde(default)]
    pub lower: Vec<PathBuf>,
    #[serde(default)]
    pub index: IndexMode,
    pub capacity: Option<Bytes>,
    #[serde(default)]
    pub pins: BTreeMap<String, Declaration>,
    #[serde(default)]
    pub policy: Policies,
}
impl Config {
    /// The declared upper, or `<home>/store`; either way with home's durability.
    pub fn upper(&self, home: &StoreLocation) -> StoreLocation {
        match &self.upper {
            Some(upper) => StoreLocation::from_home(upper, home.durability()),
            None => home.child("store"),
        }
    }
    pub fn validate(&self) -> Result<()> {
        for (name, declaration) in &self.pins {
            PinName::new(name.clone())?;
            if !name.starts_with(MANAGED) || name.starts_with(STAGING) {
                return Err(Error::Invalid(
                    "declarations belong to config/, excluding config/.acquire/",
                ));
            }
            declaration.policy()?;
            declaration.specification()?;
        }
        self.policy.on_miss.policy()?;
        Ok(())
    }
    pub async fn open(
        &self,
        home: &StoreLocation,
        ram: Reservations,
        owner_only: bool,
    ) -> Result<DiskStore> {
        self.validate()?;
        DiskStore::open(
            self.upper(home),
            self.lower.clone(),
            self.index,
            self.capacity.map(|bytes| bytes.0),
            ram,
            owner_only,
        )
        .await
    }
}

/// One node's serialized reconciler. An application owns its cleanup even if
/// the requesting future is dropped. Applied declaration digests follow pin commits.
#[derive(Clone)]
pub struct Reconciler(Arc<tokio::sync::Mutex<Config>>);
impl Reconciler {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self(Arc::new(tokio::sync::Mutex::new(config))))
    }
    pub async fn current(&self) -> Config {
        self.0.lock().await.clone()
    }
    pub async fn apply(&self, store: &DiskStore, config: Config) -> Result<()> {
        config.validate()?;
        let current = self.0.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut current = current.lock().await;
            if current.upper != config.upper
                || current.capacity != config.capacity
                || config
                    .upper
                    .as_ref()
                    .is_some_and(|upper| *upper != *store.core.disk.as_ref().unwrap().root)
                || store.core.disk.as_ref().unwrap().quota.limit()
                    != config.capacity.map_or(u64::MAX, |bytes| bytes.0)
            {
                return Err(Error::Invalid(
                    "changing content upper or capacity requires restart",
                ));
            }
            store
                .core
                .access(&Scope::Owner, |core| core.require_ready())
                .await?;
            store.rescan(config.lower.clone(), config.index).await?;
            remove(&store, snapshot(&store, STAGING).await?).await?;
            for (name, declaration) in &config.pins {
                let name = PinName::new(name.clone())?;
                let (source, expected) = declaration.specification()?;
                let digest = Digest::hash(
                    &serde_ipld_dagcbor::to_vec(declaration)
                        .map_err(|_| Error::Invalid("canonical declaration"))?,
                );
                if store.core.declaration_applied(name.clone(), digest).await? {
                    continue;
                }
                let target = expected.map(|object| match &source {
                    Some(Source::HfXet { path: None, .. }) => Target::Tree(object),
                    _ => Target::Object(object),
                });
                let staging = PinName::new(format!(
                    "{STAGING}{}",
                    hellas_auth::Digest::hash(name.as_str().as_bytes())
                ))?;
                let staged: Result<()> = async {
                    let present = match target {
                        Some(target) => {
                            store
                                .core
                                .access(&Scope::Owner, move |core| core.target_present(target))
                                .await?
                        }
                        None => false,
                    };
                    if present {
                        store
                            .set_pin(
                                &Scope::Owner,
                                &staging,
                                None,
                                Some(PinValue {
                                    target: target.unwrap(),
                                    policy: PinPolicy::Owner,
                                    expires: None,
                                }),
                            )
                            .await?;
                    } else if let Some(source) = source {
                        store
                            .acquire(
                                &Scope::Owner,
                                source,
                                target.map(Target::object),
                                PinTarget {
                                    name: staging.clone(),
                                    policy: PinPolicy::Owner,
                                },
                            )
                            .await?;
                    }
                    let target = if target.is_some() {
                        target
                    } else {
                        pin(&store, &staging).await?.map(|pin| pin.target)
                    }
                    .ok_or(Error::Invalid("declared content target"))?;
                    let previous = pin(&store, &name).await?;
                    let next = PinValue {
                        target,
                        policy: declaration.policy()?,
                        expires: None,
                    };
                    let name = name.clone();
                    store
                        .core
                        .effect_with_declaration(
                            &Scope::Owner,
                            Some((name.clone(), digest)),
                            move |core| {
                                core.set_pin_sync(
                                    &Scope::Owner,
                                    &name,
                                    previous.as_ref(),
                                    Some(next),
                                )
                            },
                        )
                        .await?;
                    Ok(())
                }
                .await;
                let cleanup: Result<()> = async {
                    if let Some(value) = pin(&store, &staging).await? {
                        store
                            .set_pin(&Scope::Owner, &staging, Some(&value), None)
                            .await?;
                    }
                    Ok(())
                }
                .await;
                staged?;
                cleanup?;
            }
            let stale = snapshot(&store, MANAGED)
                .await?
                .into_iter()
                .filter(|(name, _)| !config.pins.contains_key(name.as_str()))
                .collect();
            remove(&store, stale).await?;
            store.set_on_miss(config.policy.on_miss.policy()?)?;
            *current = config;
            Ok(())
        })
        .await
        .map_err(|_| Error::Invalid("content reconciler task"))?
    }
}
async fn remove(store: &DiskStore, pins: BTreeMap<PinName, PinValue>) -> Result<()> {
    for (name, value) in pins {
        store
            .set_pin(&Scope::Owner, &name, Some(&value), None)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    fn name(value: &str) -> PinName {
        PinName::new(value.into()).unwrap()
    }
    fn declaration(bytes: &[u8], policy: Option<Policy>) -> Declaration {
        let object = ContentRef::for_bytes(bytes);
        Declaration::Object(Object {
            url: None,
            path: None,
            bytes: Some(object.bytes()),
            expect: Some(object.id().to_string()),
            sha256: None,
            policy,
        })
    }
    fn config(root: &std::path::Path) -> Config {
        Config {
            upper: Some(root.join("upper")),
            lower: vec![root.join("lower")],
            ..Default::default()
        }
    }
    async fn node(config: &Config) -> DiskStore {
        let home = StoreLocation::for_test(config.upper.as_ref().unwrap());
        config
            .open(&home, Reservations::ram(16 << 20), false)
            .await
            .unwrap()
    }
    async fn owner(store: &DiskStore, key: &str, bytes: &[u8]) {
        let object = ContentRef::for_bytes(bytes);
        let mut upload = store
            .upload(
                &Scope::Owner,
                object,
                Some(PinTarget {
                    name: name(key),
                    policy: PinPolicy::Owner,
                }),
            )
            .await
            .unwrap();
        upload
            .declare(&hellas_xet::chunk(bytes), true)
            .await
            .unwrap();
        if !upload.complete() {
            upload.accept_chunk(bytes).await.unwrap();
        }
        assert!(upload.complete());
    }
    #[test]
    fn configuration_requires_immutable_sources() {
        for uri in ["hf://org/repo", "hf://org/repo@main", "hf://org/repo@tag"] {
            let config: Config =
                serde_json::from_value(serde_json::json!({"pins":{"config/model":uri}})).unwrap();
            assert!(config.validate().is_err());
        }
        let config: Config = serde_json::from_value(serde_json::json!({
            "pins":{"config/model":format!("hf://org/repo@{}", "f".repeat(40))},
            "capacity":"2 TiB", "index":"require",
            "policy":{"on_miss":"refuse"}
        }))
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.capacity.unwrap().0, 2_u64 << 40);
        assert_eq!(config.index, IndexMode::Require);
    }
    #[tokio::test]
    async fn hf_declarations_use_only_their_managed_pin_and_cached_trees_need_no_hub() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path());
        config.lower.clear();
        let sha = "a".repeat(40);
        let uri = format!("hf://org/repo@{sha}");
        config
            .pins
            .insert("config/model".into(), Declaration::Hf(uri.clone()));
        let mut store = node(&config).await;
        store.finish_recovery().await.unwrap();
        let hf_name = format!("hf/org/repo@{sha}");
        owner(&store, &hf_name, b"unrelated owner's HF alias").await;
        let previous = pin(&store, &name(&hf_name)).await.unwrap().unwrap();
        let protected = PinValue {
            policy: PinPolicy::Public,
            ..previous.clone()
        };
        store
            .set_pin(
                &Scope::Owner,
                &name(&hf_name),
                Some(&previous),
                Some(protected.clone()),
            )
            .await
            .unwrap();
        let weights = b"configured model weights";
        let (base, serving) = super::super::acquire::tests::hub(|_| {
            vec![
            (format!("/api/models/org/repo/tree/{sha}?recursive=true"), 200,
             serde_json::json!([{"type":"file", "path":"weights.bin", "size":weights.len()}]).to_string().into_bytes()),
            (format!("/org/repo/resolve/{sha}/weights.bin"), 200, weights.to_vec()),
        ]
        });
        store.core.hf_hub = Some(base);
        let reconciler = Reconciler::new(config.clone()).unwrap();
        reconciler.apply(&store, config.clone()).await.unwrap();
        serving.join().unwrap();
        assert_eq!(
            pin(&store, &name(&hf_name)).await.unwrap(),
            Some(protected.clone())
        );
        let target = pin(&store, &name("config/model"))
            .await
            .unwrap()
            .unwrap()
            .target;
        assert!(matches!(target, Target::Tree(_)));
        let object = target.object();
        store.core.hf_hub = Some("http://127.0.0.1:1".into());
        reconciler.apply(&store, config.clone()).await.unwrap();
        store.close().await;
        store = node(&config).await;
        store.finish_recovery().await.unwrap();
        store.core.hf_hub = Some("http://127.0.0.1:1".into());
        Reconciler::new(config.clone())
            .unwrap()
            .apply(&store, config.clone())
            .await
            .unwrap();
        // A stopped-node edit must consult the persisted declaration, not new current config.
        store.close().await;
        let changed_sha = "b".repeat(40);
        config.pins.insert(
            "config/model".into(),
            Declaration::Hf(format!("hf://org/repo@{changed_sha}")),
        );
        store = node(&config).await;
        store.finish_recovery().await.unwrap();
        let changed_weights = b"changed configured weights";
        let (base, serving) = super::super::acquire::tests::hub(|_| {
            vec![
            (format!("/api/models/org/repo/tree/{changed_sha}?recursive=true"), 200, serde_json::json!([{"type":"file","path":"weights.bin","size":changed_weights.len()}]).to_string().into_bytes()),
            (format!("/org/repo/resolve/{changed_sha}/weights.bin"),200,changed_weights.to_vec()),
        ]
        });
        store.core.hf_hub = Some(base);
        let reconciler = Reconciler::new(config.clone()).unwrap();
        reconciler.apply(&store, config.clone()).await.unwrap();
        let changed = pin(&store, &name("config/model"))
            .await
            .unwrap()
            .unwrap()
            .target
            .object();
        assert_ne!(changed, object);
        serving.join().unwrap();
        config.pins.insert(
            "config/model".into(),
            Declaration::Object(Object {
                url: Some(uri),
                path: None,
                bytes: Some(object.bytes()),
                expect: Some(object.id().to_string()),
                sha256: None,
                policy: None,
            }),
        );
        store.core.hf_hub = Some("http://127.0.0.1:1".into());
        reconciler.apply(&store, config.clone()).await.unwrap();
        config.pins.clear();
        reconciler.apply(&store, config).await.unwrap();
        assert_eq!(pin(&store, &name(&hf_name)).await.unwrap(), Some(protected));
        let collected = store.collect(&Scope::Owner).await.unwrap();
        assert_eq!(
            collected.bytes,
            object.bytes() + weights.len() as u64 + changed.bytes() + changed_weights.len() as u64
        );
        assert_eq!(
            store.stats().unwrap().used,
            previous.target.object().bytes()
        );
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn lower_reconciliation_defaults_to_jobs_and_config_wins_over_owner_edits() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("lower")).unwrap();
        let bytes = b"converted model weights";
        std::fs::write(root.path().join("lower/weights"), bytes).unwrap();
        let mut config = config(root.path());
        config
            .pins
            .insert("config/model".into(), declaration(bytes, None));
        let mut store = node(&config).await;
        let reconciler = Reconciler::new(config.clone()).unwrap();
        assert!(matches!(
            reconciler.apply(&store, config.clone()).await,
            Err(Error::Denied)
        ));
        store.finish_recovery().await.unwrap();
        owner(&store, "private/unmanaged", b"owner bytes").await;
        reconciler.apply(&store, config.clone()).await.unwrap();
        let initial = pin(&store, &name("config/model")).await.unwrap().unwrap();
        assert_eq!(initial.policy, PinPolicy::Jobs);
        let private = PinValue {
            policy: PinPolicy::Owner,
            ..initial.clone()
        };
        store
            .set_pin(
                &Scope::Owner,
                &name("config/model"),
                Some(&initial),
                Some(private.clone()),
            )
            .await
            .unwrap();
        reconciler.apply(&store, config.clone()).await.unwrap();
        assert_eq!(
            pin(&store, &name("config/model")).await.unwrap(),
            Some(initial)
        );
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
        config.pins.insert(
            "config/model".into(),
            declaration(bytes, Some(Policy::Name("public".into()))),
        );
        store.close().await;
        store = node(&config).await;
        store.finish_recovery().await.unwrap();
        let reconciler = Reconciler::new(config.clone()).unwrap();
        reconciler.apply(&store, config.clone()).await.unwrap();
        assert_eq!(
            pin(&store, &name("config/model"))
                .await
                .unwrap()
                .unwrap()
                .policy,
            PinPolicy::Public
        );
        config.pins.clear();
        reconciler.apply(&store, config).await.unwrap();
        assert!(pin(&store, &name("config/model")).await.unwrap().is_none());
        assert!(
            pin(&store, &name("private/unmanaged"))
                .await
                .unwrap()
                .is_some()
        );
        store.close().await;
    }
    #[tokio::test]
    async fn failed_desired_set_keeps_completed_pins_and_defers_stale_removal() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("lower")).unwrap();
        std::fs::write(root.path().join("lower/weights"), b"weights").unwrap();
        let mut config = config(root.path());
        let store = node(&config).await;
        store.finish_recovery().await.unwrap();
        owner(&store, "config/stale", b"previous configuration").await;
        owner(
            &store,
            "config/.acquire/interrupted",
            b"interrupted application",
        )
        .await;
        let reconciler = Reconciler::new(config.clone()).unwrap();
        config.pins.insert(
            "config/first".into(),
            declaration(b"weights", Some(Policy::Name("public".into()))),
        );
        config
            .pins
            .insert("config/missing".into(), declaration(b"not present", None));
        assert!(reconciler.apply(&store, config).await.is_err());
        assert_eq!(
            pin(&store, &name("config/first"))
                .await
                .unwrap()
                .unwrap()
                .policy,
            PinPolicy::Public
        );
        assert!(pin(&store, &name("config/stale")).await.unwrap().is_some());
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
        assert!(reconciler.current().await.pins.is_empty());
        store.close().await;
    }
    #[tokio::test]
    async fn cancelling_a_requester_finishes_acquisition_and_cleans_its_internal_pin() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("lower")).unwrap();
        let mut config = config(root.path());
        let bytes = b"downloaded model weights";
        let (entered, received) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let (url, http, serving) = super::super::acquire::tests::https_with(bytes, move || {
            entered.send(()).unwrap();
            wait.recv().unwrap();
        });
        let mut object = match declaration(bytes, None) {
            Declaration::Object(object) => object,
            _ => unreachable!(),
        };
        object.url = Some(url.to_string());
        config
            .pins
            .insert("config/download".into(), Declaration::Object(object));
        let mut store = node(&config).await;
        store.core.http = http;
        store.finish_recovery().await.unwrap();
        let reconciler = Reconciler::new(config.clone()).unwrap();
        owner(&store, "config/download", b"previous model weights").await;
        let previous = pin(&store, &name("config/download"))
            .await
            .unwrap()
            .unwrap();
        let shared = PinValue {
            policy: PinPolicy::Jobs,
            ..previous.clone()
        };
        store
            .set_pin(
                &Scope::Owner,
                &name("config/download"),
                Some(&previous),
                Some(shared.clone()),
            )
            .await
            .unwrap();
        let applying = {
            let reconciler = reconciler.clone();
            let store = store.clone();
            let config = config.clone();
            tokio::spawn(async move { reconciler.apply(&store, config).await })
        };
        received.await.unwrap();
        store
            .set_pin(
                &Scope::Owner,
                &name("config/download"),
                Some(&shared),
                Some(PinValue {
                    policy: PinPolicy::Owner,
                    ..shared.clone()
                }),
            )
            .await
            .unwrap();
        applying.abort();
        assert!(applying.await.unwrap_err().is_cancelled());
        assert!(reconciler.current().now_or_never().is_none());
        release.send(()).unwrap();
        assert!(
            reconciler
                .current()
                .await
                .pins
                .contains_key("config/download")
        );
        let value = pin(&store, &name("config/download"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value.target, Target::Object(ContentRef::for_bytes(bytes)));
        assert_eq!(value.policy, PinPolicy::Jobs);
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
        serving.join().unwrap();
        // The HTTP fixture is gone. A successful second pass proves verified
        // cached content does not start another download.
        reconciler.apply(&store, config).await.unwrap();
        store.close().await;
    }
}
