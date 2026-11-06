//! Declared node content, reconciled through the ordinary scoped store operations.
use super::*;
use serde::Deserialize;
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
                    "KB" => 1000,
                    "MB" => 1000_u64.pow(2),
                    "GB" => 1000_u64.pow(3),
                    "TB" => 1000_u64.pow(4),
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

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Policy {
    Name(String),
    Channel { channel: String },
}
impl Policy {
    fn value(&self) -> Result<PinPolicy> {
        Ok(match self {
            Self::Name(name) => match name.as_str() {
                "owner" => PinPolicy::Owner,
                "jobs" => PinPolicy::Jobs,
                "granted" => PinPolicy::Granted,
                "public" => PinPolicy::Public,
                _ => return Err(Error::Invalid("declared pin policy")),
            },
            Self::Channel { channel } => PinPolicy::Channel(
                channel
                    .parse()
                    .map_err(|_| Error::Invalid("channel pin policy"))?,
            ),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Declaration {
    Hf(String),
    Object(Object),
}

#[derive(Clone, Debug, Deserialize)]
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
                if repo.revision.len() != 40
                    || !repo.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
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

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Watermark {
    Bytes(Bytes),
    Percent(String),
}
impl Watermark {
    fn bytes(&self, capacity: u64) -> Result<u64> {
        match self {
            Self::Bytes(bytes) => Ok(bytes.0),
            Self::Percent(value) => {
                let percent: u64 = value
                    .strip_suffix('%')
                    .ok_or(Error::Invalid("eviction percentage"))?
                    .parse()
                    .map_err(|_| Error::Invalid("eviction percentage"))?;
                if percent > 100 {
                    return Err(Error::Invalid("eviction percentage"));
                }
                Ok((u128::from(capacity) * u128::from(percent) / 100) as u64)
            }
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LruConfig {
    pub high_water: Watermark,
    pub low_water: Watermark,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvictionConfig {
    pub lru: LruConfig,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policies {
    #[serde(default)]
    pub on_miss: MissPolicy,
    pub eviction: Option<EvictionConfig>,
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
    pub fn upper(&self) -> Result<PathBuf> {
        self.upper
            .clone()
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".hellas/store"))
            })
            .ok_or(Error::Invalid("content.upper is required without HOME"))
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
        if let Some(eviction) = &self.policy.eviction {
            let (high, low) = match (&eviction.lru.high_water, &eviction.lru.low_water) {
                (Watermark::Bytes(high), Watermark::Bytes(low)) => (high.0, low.0),
                (high @ Watermark::Percent(_), low @ Watermark::Percent(_)) => {
                    (high.bytes(100)?, low.bytes(100)?)
                }
                _ => {
                    return Err(Error::Invalid(
                        "eviction watermarks must use the same units",
                    ));
                }
            };
            if low >= high {
                return Err(Error::Invalid(
                    "eviction low_water must be below high_water",
                ));
            }
        }
        Ok(())
    }
    pub fn lru(&self, stats: &StoreStats) -> Result<Option<Lru>> {
        self.policy
            .eviction
            .as_ref()
            .map(|config| {
                let capacity = self
                    .capacity
                    .map(|bytes| bytes.0)
                    .unwrap_or_else(|| stats.used.saturating_add(stats.free));
                let high_water = config.lru.high_water.bytes(capacity)?;
                let low_water = config.lru.low_water.bytes(capacity)?;
                if low_water >= high_water && capacity != 0 {
                    return Err(Error::Invalid(
                        "eviction low_water must be below high_water",
                    ));
                }
                Ok(Lru {
                    high_water,
                    low_water,
                })
            })
            .transpose()
    }
    pub async fn open(&self, ram: Reservations) -> Result<DiskStore> {
        self.validate()?;
        DiskStore::open(
            self.upper()?,
            self.lower.clone(),
            self.index,
            self.capacity.map(|bytes| bytes.0),
            ram,
        )
        .await
    }
}

/// One node's serialized reconciler. An application owns its cleanup even if
/// the requesting future is dropped; no additional durable ownership is needed.
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
    /// Run opt-in background LRU on store changes, without a polling interval.
    /// A host owns this future and drops it before closing its shared store.
    pub async fn evict(&self, store: &DiskStore) -> Result<()> {
        loop {
            let changed = store.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let config = self.0.lock().await;
                let stats = store.stats()?;
                if let Some(lru) = config.lru(&stats)?
                    && stats.used > lru.high_water
                {
                    while store.stats()?.used > lru.low_water {
                        let collected = store
                            .core
                            .access(&Scope::Owner, |core| core.collect_sync(&Scope::Owner, true))
                            .await?;
                        if collected.objects == 0 {
                            break;
                        }
                    }
                }
            }
            changed.await;
        }
    }
    pub async fn apply(&self, store: &DiskStore, config: Config) -> Result<()> {
        config.validate()?;
        let current = self.0.clone();
        let store = store.clone();
        tokio::spawn(async move {
            let mut current = current.lock().await;
            if current.upper()? != config.upper()?
                || current.capacity != config.capacity
                || store.core.disk.as_ref().unwrap().root != config.upper()?
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
            config.lru(&store.stats()?)?;
            store.rescan(config.lower.clone(), config.index).await?;
            remove(&store, snapshot(&store, STAGING).await?).await?;
            for (name, declaration) in &config.pins {
                let name = PinName::new(name.clone())?;
                let (source, expected) = declaration.specification()?;
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
                        policy: previous
                            .as_ref()
                            .map(|pin| pin.policy.clone())
                            .unwrap_or(declaration.policy()?),
                        expires: previous.as_ref().and_then(|pin| pin.expires),
                    };
                    if previous.as_ref() != Some(&next) {
                        store
                            .set_pin(&Scope::Owner, &name, previous.as_ref(), Some(next))
                            .await?;
                    }
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
            store.core.changed.notify_waiters();
            Ok(())
        })
        .await
        .map_err(|_| Error::Invalid("content reconciler task"))?
    }
}
async fn pin(store: &DiskStore, name: &PinName) -> Result<Option<PinValue>> {
    Ok(store
        .pins(&Scope::Owner, name.as_str(), Cursor::default())
        .await?
        .pins
        .into_iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value))
}
async fn snapshot(store: &DiskStore, prefix: &str) -> Result<BTreeMap<PinName, PinValue>> {
    let mut cursor = Cursor::default();
    let mut pins = BTreeMap::new();
    loop {
        let page = store.pins(&Scope::Owner, prefix, cursor).await?;
        pins.extend(page.pins);
        match page.next {
            Some(next) => cursor = next,
            None => return Ok(pins),
        }
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
        config.open(Reservations::ram(16 << 20)).await.unwrap()
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
    fn configuration_requires_immutable_sources_and_rejects_unknown_policy_builtins() {
        for uri in ["hf://org/repo", "hf://org/repo@main", "hf://org/repo@tag"] {
            let config: Config =
                serde_json::from_value(serde_json::json!({"pins":{"config/model":uri}})).unwrap();
            assert!(config.validate().is_err());
        }
        let config: Config = serde_json::from_value(serde_json::json!({
            "pins":{"config/model":format!("hf://org/repo@{}", "f".repeat(40))},
            "capacity":"2 TiB", "index":"require",
            "policy":{"on_miss":"refuse", "eviction":{"lru":{"high_water":"90%", "low_water":"80%"}}}
        })).unwrap();
        config.validate().unwrap();
        assert_eq!(config.capacity.unwrap().0, 2_u64 << 40);
        assert_eq!(config.index, IndexMode::Require);
        let lru = config.lru(&StoreStats::default()).unwrap().unwrap();
        assert_eq!(
            lru.high_water,
            ((u128::from(2_u64 << 40) * 90) / 100) as u64
        );
        for policy in [
            serde_json::json!({"on_miss":"budget"}),
            serde_json::json!({"on_miss":{"allow_list":{}, "budget":{"bytes_per_day":1}}}),
            serde_json::json!({"on_miss":{"budget":{"bytes_per_day":1}}}),
            serde_json::json!({"eviction":{"lru":{"high_water":"80%", "low_water":"90%"}}}),
        ] {
            let parsed = serde_json::from_value::<Config>(serde_json::json!({"policy":policy}));
            assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
        }
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
        assert_eq!(collected.bytes, object.bytes() + weights.len() as u64);
        assert_eq!(
            store.stats().unwrap().used,
            previous.target.object().bytes()
        );
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn background_eviction_is_opt_in_and_stops_at_low_water_preserving_pins() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config(root.path());
        config.lower.clear();
        let store = node(&config).await;
        store.finish_recovery().await.unwrap();
        let len = 64 * 1024;
        for value in 1..=4 {
            owner(&store, &format!("private/{value}"), &vec![value; len]).await;
        }
        owner(&store, "private/empty", b"").await;
        let empty = pin(&store, &name("private/empty")).await.unwrap().unwrap();
        store
            .set_pin(&Scope::Owner, &name("private/empty"), Some(&empty), None)
            .await
            .unwrap();
        // Protect the fourth object and make the third the most recently read.
        for value in 1..=2 {
            let object = ContentRef::for_bytes(&vec![value; len]);
            drop(
                LocalStore::Disk(store.clone())
                    .open_verified(&Scope::Owner, object, None)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let newest = ContentRef::for_bytes(&vec![3; len]);
        drop(
            LocalStore::Disk(store.clone())
                .open_verified(&Scope::Owner, newest, None)
                .await
                .unwrap()
                .unwrap(),
        );
        for value in 1..=3 {
            let key = name(&format!("private/{value}"));
            let previous = pin(&store, &key).await.unwrap().unwrap();
            store
                .set_pin(&Scope::Owner, &key, Some(&previous), None)
                .await
                .unwrap();
        }
        let reconciler = Reconciler::new(config.clone()).unwrap();
        let eviction = reconciler.evict(&store);
        tokio::pin!(eviction);
        assert!(futures::poll!(eviction.as_mut()).is_pending());
        assert_eq!(store.stats().unwrap().used, 4 * len as u64);
        config.policy.eviction = Some(EvictionConfig {
            lru: LruConfig {
                high_water: Watermark::Bytes(Bytes(3 * len as u64)),
                low_water: Watermark::Bytes(Bytes(2 * len as u64)),
            },
        });
        reconciler.apply(&store, config).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    result = &mut eviction => panic!("eviction ended: {result:?}"),
                    _ = tokio::task::yield_now() => {
                        if store.stats().unwrap().used == 2 * len as u64 { break; }
                    }
                }
            }
        })
        .await
        .unwrap();
        assert!(
            store
                .core
                .access(&Scope::Owner, move |core| core
                    .target_present(Target::Object(newest)))
                .await
                .unwrap()
        );
        assert!(
            store
                .stat(
                    &Scope::Owner,
                    &Path::new(name("private/4"), String::new()).unwrap()
                )
                .await
                .unwrap()
                .is_some()
        );
        let oldest = ContentRef::for_bytes(&vec![1; len]);
        assert!(
            !store
                .core
                .access(&Scope::Owner, move |core| core
                    .target_present(Target::Object(oldest)))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn lower_reconciliation_defaults_to_jobs_and_preserves_live_owner_overrides() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("lower")).unwrap();
        let bytes = b"converted model weights";
        std::fs::write(root.path().join("lower/weights"), bytes).unwrap();
        let mut config = config(root.path());
        config
            .pins
            .insert("config/model".into(), declaration(bytes, None));
        let store = node(&config).await;
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
            Some(private)
        );
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
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
        assert_eq!(value.policy, PinPolicy::Owner);
        assert!(snapshot(&store, STAGING).await.unwrap().is_empty());
        serving.join().unwrap();
        // The HTTP fixture is gone. A successful second pass proves verified
        // cached content does not start another download.
        reconciler.apply(&store, config).await.unwrap();
        store.close().await;
    }
}
