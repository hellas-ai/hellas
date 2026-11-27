use super::{
    core::Core,
    storage::{Buffer, Data},
    *,
};
use futures::StreamExt;
use hellas_rpc::{ContentId, ContentRef};
use hellas_xet::Chunk;
use std::{collections::BTreeMap, io::Write};

pub(crate) struct Staged {
    object: ContentRef,
    data: Data,
    chunks: Vec<Chunk>,
}
pub(super) const HTTPS_LENGTH_REQUIRED: &str =
    "HTTPS response has no usable Content-Length; supply --bytes";

pub fn validate_https(url: &url::Url) -> Result<()> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("HTTPS source URL"));
    }
    Ok(())
}

fn finish(mut bytes: Buffer, expected: Option<ContentRef>) -> Result<Staged> {
    let chunks = bytes.canonical()?;
    indexed_stage(bytes, expected, chunks)
}

fn indexed_stage(
    bytes: Buffer,
    expected: Option<ContentRef>,
    chunks: Vec<Chunk>,
) -> Result<Staged> {
    let object = ContentRef::new(
        ContentId::from_bytes(hellas_xet::file_hash(&chunks).into_bytes()),
        bytes.len(),
    );
    if expected.is_some_and(|expected| expected != object) {
        return Err(Error::Invalid("acquisition content mismatch"));
    }
    let data = bytes.finish(object, chunks.clone())?;
    Ok(Staged {
        object,
        data,
        chunks,
    })
}
fn hf_error(error: crate::hf::FetchError) -> Error {
    match error {
        crate::hf::FetchError::Capacity => Error::Capacity,
        crate::hf::FetchError::NotFound(repo) => Error::HfNotFound(repo),
        crate::hf::FetchError::Unauthorized(repo) => Error::HfUnauthorized(repo),
        crate::hf::FetchError::Malformed(reason) if reason == crate::hf::LEGACY_CHUNKING => {
            Error::Invalid(crate::hf::LEGACY_CHUNKING)
        }
        _ => Error::Invalid("HF acquisition failed"),
    }
}
#[derive(Clone)]
pub(crate) enum Publication {
    Acquire(AcquirePin),
    Model(PinTarget),
}

impl From<AcquirePin> for Publication {
    fn from(pin: AcquirePin) -> Self {
        Self::Acquire(pin)
    }
}

async fn publish(
    store: &Core,
    scope: &Scope,
    stages: BTreeMap<ContentId, Staged>,
    target: Target,
    pin: impl Into<Publication>,
    hub_alias: Option<PinName>,
    requester: Option<(Core, Scope)>,
) -> Result<Acquisition> {
    let pin = pin.into();
    let object = target.object();
    let published_alias = hub_alias
        .clone()
        .filter(|_| matches!(pin, Publication::Acquire(AcquirePin::Automatic { .. })));
    let root = store
        .effect(scope, move |store| {
            store.require_ready()?;
            if let Publication::Acquire(AcquirePin::Named(pin)) = &pin {
                store.check_acquisition(pin, &requester)?;
            }
            store.publish_acquired(
                stages
                    .into_values()
                    .map(|stage| (stage.object, stage.data, stage.chunks))
                    .collect(),
                target,
                pin,
                hub_alias,
                requester,
            )
        })
        .await?;
    Ok(Acquisition {
        object,
        target,
        root,
        hub_alias: published_alias,
        commit: None,
    })
}

fn hf_tree_alias(repo: &crate::hf::Repo) -> Result<PinName> {
    let prefix = if repo.kind == crate::hf::RepoKind::Dataset {
        "hf-dataset"
    } else {
        "hf"
    };
    PinName::new(format!("{prefix}/{}@{}", repo.id, repo.revision))
}
pub(crate) async fn memory(
    store: &Core,
    scope: &Scope,
    source: Source,
    expect: Option<ContentRef>,
    pin: Publication,
    requester: Option<(Core, Scope)>,
    hint: bool,
) -> Result<Acquisition> {
    match source {
        Source::Https { url, sha256, bytes } => {
            validate_https(&url)?;
            if let (Some(expect), Some(bytes)) = (expect, bytes)
                && expect.bytes() != bytes
            {
                return Err(Error::Invalid("source length contract"));
            }
            // A declared length reserves before the request; otherwise the
            // response length reserves, and `fill` still verifies it exactly.
            let declared = bytes
                .or(expect.map(|object| object.bytes()))
                .map(|bytes| Ok::<_, Error>((bytes, store.reserve(bytes)?)))
                .transpose()?;
            let core = store.clone();
            let http = store.http.clone();
            let stage = tokio::task::spawn_blocking(move || {
                let response = http
                    .get(url.as_str())
                    .header("Accept-Encoding", "identity")
                    .call()
                    .map_err(|_| Error::Invalid("HTTPS request failed"))?;
                if response.status() != 200 {
                    return Err(Error::Invalid("HTTPS response status"));
                }
                let (bytes, charge) = match declared {
                    Some(declared) => declared,
                    None => {
                        let bytes = response
                            .headers()
                            .get("content-length")
                            .and_then(|length| length.to_str().ok()?.parse().ok())
                            .ok_or(Error::Invalid(HTTPS_LENGTH_REQUIRED))?;
                        (bytes, core.reserve(bytes)?)
                    }
                };
                let mut body = Buffer::new(&core, bytes, charge)?;
                let chunks = body.fill(response.into_body().into_reader(), sha256, &core.pool)?;
                indexed_stage(body, expect, chunks)
            })
            .await
            .map_err(|_| Error::Invalid("acquisition worker failed"))??;
            let target = Target::Object(stage.object);
            publish(
                store,
                scope,
                BTreeMap::from([(stage.object.id(), stage)]),
                target,
                pin,
                None,
                requester,
            )
            .await
        }
        Source::Peer { id, seeds } => {
            if expect.is_some_and(|expect| expect.id() != id) {
                return Err(Error::Invalid("peer expectation"));
            }
            let pool = store
                .state
                .lock()
                .map_err(|_| Error::Invalid("store lock"))?
                .peers
                .clone()
                .filter(|_| !seeds.is_empty())
                .ok_or_else(super::locator::no_peer)?;
            let at = Path::new(PinName::object(id), String::new())?;
            for seed in seeds {
                let Ok(transport) = pool.transport(seed).await else {
                    continue;
                };
                let remote = RemoteStore::new(transport, store.pool.clone());
                let Ok(Some(found)) = remote.stat(&Scope::Public, &at).await else {
                    continue;
                };
                let root = found.target;
                if hint && !matches!(root, Target::Object(_)) {
                    continue;
                }
                if root.object().id() != id || expect.is_some_and(|expect| expect != root.object())
                {
                    continue;
                }
                match peer_stages(store, &remote, &at, root).await {
                    Ok(stages) => {
                        return publish(store, scope, stages, root, pin, None, requester).await;
                    }
                    Err(
                        Error::Denied
                        | Error::Missing
                        | Error::Conflict
                        | Error::Remote(_)
                        | Error::Invalid(_),
                    ) => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(super::locator::no_peer())
        }
        Source::HfXet { mut repo, path } => {
            repo.validate().map_err(hf_error)?;
            if let Some(path) = &path {
                super::tree::validate_path(path, false)?;
            }
            if hint && (repo.default_branch || !crate::hf::immutable_sha(&repo.revision)) {
                let core = store.clone();
                let source = repo.clone();
                repo.revision = tokio::task::spawn_blocking(move || {
                    let default_branch = source.default_branch;
                    core.hf(source)
                        .resolve_revision(default_branch, &core.pool)
                        .map_err(hf_error)
                })
                .await
                .map_err(|_| Error::Invalid("resolve worker failed"))??;
                repo.default_branch = false;
            }
            if !crate::hf::immutable_sha(&repo.revision) {
                return Err(Error::Invalid("HF immutable commit"));
            }
            let hub_alias = path.is_none().then(|| hf_tree_alias(&repo)).transpose()?;
            let core = store.clone();
            let source_repo = repo.clone();
            let (stages, root, files) = tokio::task::spawn_blocking(move || {
                let cas = core.hf(source_repo);
                hf_stages(&cas, &core, path.as_deref(), expect, true, hint)
            })
            .await
            .map_err(|_| Error::Invalid("HF worker failed"))??;
            let mut acquisition =
                publish(store, scope, stages, root, pin, hub_alias, requester).await?;
            acquisition.commit = Some(repo.revision.clone());
            if repo.kind == crate::hf::RepoKind::Model {
                store
                    .record_hub_files(&repo.id, &repo.revision, files)
                    .await?;
            }
            Ok(acquisition)
        }
    }
}
async fn peer_stages(
    store: &Core,
    remote: &dyn ContentStore,
    at: &Path,
    root: Target,
) -> Result<BTreeMap<ContentId, Staged>> {
    let mut stages: BTreeMap<ContentId, Staged> = BTreeMap::new();
    let mut expanded = std::collections::BTreeSet::new();
    let mut pending = vec![(root, String::new(), None)];
    while let Some((target, path, _queue_charge)) = pending.pop() {
        let object = target.object();
        if matches!(target, Target::Tree(_)) && object.bytes() > MAX_TREE_BYTES as u64 {
            return Err(Error::Invalid("peer tree byte limit"));
        }
        if stages
            .get(&object.id())
            .is_some_and(|stage| stage.object != object)
        {
            return Err(Error::Invalid("conflicting peer reference"));
        }
        if !stages.contains_key(&object.id()) {
            let charge = stage_charge(store, &stages, object.bytes())?;
            let path = Path::new(at.pin.clone(), join_path(&at.path, &path))?;
            let mut read = remote
                .read(&Scope::Public, &path, 0..object.bytes())
                .await?;
            if read.object != object {
                return Err(Error::Conflict);
            }
            let core = store.clone();
            let mut bytes = core
                .clone()
                .run(move |core| Buffer::new(&core, object.bytes(), charge))
                .await?;
            while let Some(chunk) = read.bytes.next().await {
                let chunk = chunk?;
                bytes = store
                    .run(move |_| {
                        bytes.write_all(&chunk)?;
                        Ok(bytes)
                    })
                    .await?;
            }
            let stage = store.run(move |_| finish(bytes, Some(object))).await?;
            stages.insert(object.id(), stage);
        }
        if let Target::Tree(_) = target {
            if !expanded.insert(object.id()) {
                continue;
            }
            let data = stages[&object.id()].data.clone();
            let entries = store
                .run(move |_| Ok(Tree::decode(&data.load(object)?)?.entries().to_vec()))
                .await?;
            for (name, child) in &entries {
                let path = join_path(&path, name);
                super::tree::validate_path(&path, false)?;
                let queue_charge = store
                    .pool
                    .reserve((path.len() + std::mem::size_of::<Target>()) as u64)?;
                pending.push((*child, path, Some(queue_charge)));
            }
        }
    }
    Ok(stages)
}

impl DiskStore {
    /// Import a verified object through an already established peer connection.
    pub async fn acquire_peer_object(
        &self,
        remote: &dyn ContentStore,
        at: &Path,
        expect: ContentRef,
        pin: PinTarget,
    ) -> Result<()> {
        if pin.holds(self, Target::Object(expect)).await? {
            return Ok(());
        }
        self.core
            .retry_capacity(&Scope::Owner, |core| {
                let pin = pin.clone();
                async move {
                    core.access(&Scope::Owner, |core| core.require_ready())
                        .await?;
                    let target = Target::Object(expect);
                    let stages = peer_stages(&core, remote, at, target).await?;
                    publish(
                        &core,
                        &Scope::Owner,
                        stages,
                        target,
                        Publication::Model(pin),
                        None,
                        None,
                    )
                    .await?;
                    Ok(())
                }
            })
            .await
    }
}

fn join_path(parent: &str, name: &str) -> String {
    match (parent, name) {
        ("", child) => child.to_owned(),
        (base, "") => base.to_owned(),
        (base, child) => format!("{base}/{child}"),
    }
}
fn stage_charge(
    core: &Core,
    stages: &BTreeMap<ContentId, Staged>,
    bytes: u64,
) -> Result<Arc<super::reservation::Reservation>> {
    let result = core.data_pool().reserve(bytes);
    if matches!(&result, Err(Error::Capacity)) {
        let needed = stages.values().try_fold(bytes, |bytes, stage| {
            bytes
                .checked_add(stage.object.bytes())
                .ok_or(Error::Capacity)
        })?;
        core.capacity(needed, result)
    } else {
        result
    }
}
fn hf_file(
    cas: &crate::hf::HfCas,
    file: &crate::hf::RepoFile,
    core: &Core,
    stages: &BTreeMap<ContentId, Staged>,
    expect: Option<ContentRef>,
) -> Result<Staged> {
    let advertised = file.advertised().map_err(hf_error)?;
    if expect.is_some_and(|expect| {
        advertised.is_some_and(|advertised| expect != advertised) || expect.bytes() != file.size
    }) {
        return Err(Error::Invalid("HF expected reference"));
    }
    let charge = stage_charge(core, stages, file.size)?;
    let mut bytes = Buffer::new(core, file.size, charge)?;
    if let Some(advertised) = advertised {
        cas.write_xet(advertised.id().digest(), file.size, &mut bytes, &core.pool)
            .map_err(hf_error)?;
        finish(bytes, Some(advertised))
    } else {
        let chunks = bytes.fill(
            cas.small_file(&file.path).map_err(hf_error)?,
            file.lfs_sha256().map_err(hf_error)?,
            &core.pool,
        )?;
        indexed_stage(bytes, expect, chunks)
    }
}
type HfStages = (
    BTreeMap<ContentId, Staged>,
    Target,
    BTreeMap<String, ContentRef>,
);
fn hf_stages(
    cas: &crate::hf::HfCas,
    core: &Core,
    path: Option<&str>,
    expect: Option<ContentRef>,
    weights: bool,
    file_only: bool,
) -> Result<HfStages> {
    let (mut files, _metadata) = cas.files(&core.pool).map_err(hf_error)?;
    let mut stages = BTreeMap::new();
    if let Some(file) = path.and_then(|path| files.iter().find(|file| file.path == path)) {
        let stage = hf_file(cas, file, core, &stages, expect)?;
        let root = Target::Object(stage.object);
        stages.insert(stage.object.id(), stage);
        return Ok((
            stages,
            root,
            BTreeMap::from([(file.path.clone(), root.object())]),
        ));
    }
    if file_only {
        return Err(Error::Missing);
    }
    let prefix = path.map_or_else(String::new, |path| format!("{path}/"));
    if path.is_some() {
        files.retain(|file| file.path.starts_with(&prefix));
        if files.is_empty() {
            return Err(Error::Missing);
        }
    }
    let mut leaves = BTreeMap::new();
    for file in &files {
        let object = if let Some(object) = file.advertised().map_err(hf_error)? {
            object
        } else {
            let stage = hf_file(cas, file, core, &stages, None)?;
            let object = stage.object;
            stages.insert(object.id(), stage);
            object
        };
        if leaves.insert(file.path.clone(), object).is_some() {
            return Err(Error::Invalid("duplicate Hub file"));
        }
    }
    let tree_entries = leaves
        .iter()
        .map(|(name, object)| (name[prefix.len()..].to_owned(), *object))
        .collect();
    let root = trees(tree_entries, core, &mut stages)?;
    if expect.is_some_and(|expect| expect != root) {
        return Err(Error::Invalid("HF tree expectation"));
    }
    if weights {
        for file in &files {
            let object = leaves[&file.path];
            if !stages.contains_key(&object.id()) {
                let stage = hf_file(cas, file, core, &stages, Some(object))?;
                stages.insert(object.id(), stage);
            }
        }
    }
    Ok((stages, Target::Tree(root), leaves))
}
fn trees(
    leaves: BTreeMap<String, ContentRef>,
    core: &Core,
    stages: &mut BTreeMap<ContentId, Staged>,
) -> Result<ContentRef> {
    let mut directories: BTreeMap<String, Vec<(String, Target)>> =
        BTreeMap::from([(String::new(), Vec::new())]);
    for (path, object) in leaves {
        super::tree::validate_path(&path, false)?;
        let (directory, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        directories
            .entry(directory.into())
            .or_default()
            .push((name.into(), Target::Object(object)));
        let mut parent = directory;
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            directories.entry(prefix.into()).or_default();
            parent = prefix;
        }
    }
    while let Some((path, entries)) = directories.pop_last() {
        let tree = Tree::new(entries)?;
        let bytes = tree.bytes();
        let charge = stage_charge(core, stages, bytes.len() as u64)?;
        let mut buffer = Buffer::new(core, bytes.len() as u64, charge)?;
        buffer.write_all(&bytes)?;
        let stage = finish(buffer, None)?;
        let object = stage.object;
        stages.entry(object.id()).or_insert(stage);
        if path.is_empty() {
            return Ok(object);
        }
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        directories
            .entry(parent.into())
            .or_default()
            .push((name.into(), Target::Tree(object)));
    }
    Err(Error::Invalid("tree root"))
}
impl Core {
    /// Resolve learns immutable names and small-file IDs, without downloading weights.
    pub async fn resolve_hf(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, ContentRef)> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        if self.disk.as_ref().is_some_and(|disk| !disk.ready()) {
            return Err(Error::Denied);
        }
        self.access(scope, |core| core.require_ready()).await?;
        let sha = self.lock_hf(repo.clone()).await?;
        let repo = crate::hf::Repo {
            revision: sha.clone(),
            default_branch: false,
            ..repo
        };
        let checking = scope.clone();
        self.retry_capacity(scope, move |core| {
            let (scope, repo) = (checking.clone(), repo.clone());
            async move { core.resolve_hf_once(&scope, repo).await }
        })
        .await
    }
    pub(crate) async fn lock_hf(&self, repo: crate::hf::Repo) -> Result<String> {
        if !repo.default_branch && crate::hf::immutable_sha(&repo.revision) {
            repo.validate().map_err(hf_error)?;
            return Ok(repo.revision.to_ascii_lowercase());
        }
        let core = self.clone();
        tokio::task::spawn_blocking(move || {
            let default_branch = repo.default_branch;
            core.hf(repo)
                .resolve_revision(default_branch, &core.pool)
                .map_err(hf_error)
        })
        .await
        .map_err(|_| Error::Invalid("resolve worker failed"))?
    }
    async fn resolve_hf_once(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, ContentRef)> {
        self.access(scope, |core| core.require_ready()).await?;
        let core = self.clone();
        let alias = hf_tree_alias(&repo)?;
        let sha = repo.revision.clone();
        let (stages, root, _) = tokio::task::spawn_blocking(move || {
            hf_stages(&core.hf(repo), &core, None, None, false, false)
        })
        .await
        .map_err(|_| Error::Invalid("resolve worker failed"))??;
        let pin = AcquirePin::Automatic {
            policy: None,
            alias: None,
        };
        let object = publish(self, scope, stages, root, pin, Some(alias), None)
            .await?
            .object;
        Ok((sha, object))
    }
}

#[cfg(test)]
pub(crate) mod tests;
