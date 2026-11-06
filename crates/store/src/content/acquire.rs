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
fn finish(mut bytes: Buffer, expected: Option<ContentRef>) -> Result<Staged> {
    let chunks = bytes.canonical()?;
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
    if matches!(error, crate::hf::FetchError::Capacity) {
        Error::Capacity
    } else {
        Error::Invalid("HF acquisition failed")
    }
}
async fn publish(
    store: &Core,
    scope: &Scope,
    stages: BTreeMap<ContentId, Staged>,
    target: Target,
    pin: PinTarget,
    requester: Option<(Core, Scope)>,
) -> Result<Acquisition> {
    let object = target.object();
    store
        .effect(scope, move |store| {
            store.require_ready()?;
            store.check_acquisition(&pin, &requester)?;
            store.publish_acquired(
                stages
                    .into_values()
                    .map(|stage| (stage.object, stage.data, stage.chunks))
                    .collect(),
                target,
                pin,
                requester,
            )
        })
        .await?;
    Ok(Acquisition { object })
}
pub(crate) async fn memory(
    store: &Core,
    scope: &Scope,
    source: Source,
    expect: Option<ContentRef>,
    pin: PinTarget,
    requester: Option<(Core, Scope)>,
) -> Result<Acquisition> {
    PinName::new(pin.name.as_str().to_owned())?;
    match source {
        Source::Https { url, sha256, bytes } => {
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(Error::Invalid("HTTPS source URL"));
            }
            if expect.is_some_and(|expect| expect.bytes() != bytes) {
                return Err(Error::Invalid("source length contract"));
            }
            let charge = store.data_pool().reserve(bytes)?;
            let core = store.clone();
            let http = store.http.clone();
            let stage = tokio::task::spawn_blocking(move || {
                let response = http
                    .get(url.as_str())
                    .call()
                    .map_err(|_| Error::Invalid("HTTPS request failed"))?;
                if response.status() != 200 {
                    return Err(Error::Invalid("HTTPS response status"));
                }
                let mut body = Buffer::new(&core, bytes, charge)?;
                body.fill(response.into_body().into_reader(), sha256, &core.pool)?;
                finish(body, expect)
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
                requester,
            )
            .await
        }
        Source::Peer { node, at } => {
            let pool = store
                .peers
                .as_ref()
                .ok_or(Error::Invalid("no peer connection pool"))?;
            let node =
                iroh::EndpointId::from_bytes(&node).map_err(|_| Error::Invalid("peer identity"))?;
            let transport = pool
                .transport(node)
                .await
                .map_err(|_| Error::Invalid("peer connection failed"))?;
            let remote = RemoteStore::new(transport, store.pool.clone());
            let root = remote
                .stat(&Scope::Public, &at)
                .await?
                .ok_or(Error::Missing)?
                .target;
            if expect.is_some_and(|expect| expect != root.object()) {
                return Err(Error::Invalid("peer expectation"));
            }
            let mut stages = BTreeMap::new();
            let mut longest = BTreeMap::new();
            let mut pending = vec![(root, String::new(), None)];
            while let Some((target, path, _queue_charge)) = pending.pop() {
                let object = target.object();
                if matches!(target, Target::Tree(_)) && object.bytes() > MAX_TREE_BYTES as u64 {
                    return Err(Error::Invalid("peer tree byte limit"));
                }
                if let std::collections::btree_map::Entry::Vacant(e) = stages.entry(object.id()) {
                    let charge = store.data_pool().reserve(object.bytes())?;
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
                    e.insert(stage);
                }
                if let Target::Tree(_) = target {
                    if longest
                        .get(&object.id())
                        .is_some_and(|old| *old >= path.len())
                    {
                        continue;
                    }
                    longest.insert(object.id(), path.len());
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
            publish(store, scope, stages, root, pin, requester).await
        }
        Source::HfXet { repo, commit, path } => {
            repo.validate().map_err(hf_error)?;
            if !crate::hf::immutable_sha(&commit) || repo.revision != commit {
                return Err(Error::Invalid("HF immutable commit"));
            }
            if let Some(path) = &path {
                super::tree::validate_path(path, false)?;
            }
            let core = store.clone();
            let (stages, root) = tokio::task::spawn_blocking(move || {
                let cas = core.hf(repo);
                hf_stages(&cas, &core, path.as_deref(), expect, true)
            })
            .await
            .map_err(|_| Error::Invalid("HF worker failed"))??;
            publish(store, scope, stages, root, pin, requester).await
        }
    }
}
fn join_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.into()
    } else {
        format!("{parent}/{name}")
    }
}
fn hf_file(
    cas: &crate::hf::HfCas,
    file: &crate::hf::RepoFile,
    core: &Core,
    expect: Option<ContentRef>,
) -> Result<Staged> {
    let charge = core.data_pool().reserve(file.size)?;
    let advertised = file
        .xet_hash
        .as_ref()
        .map(|hash| {
            hash.parse::<ContentId>()
                .map(|id| ContentRef::new(id, file.size))
                .map_err(|_| Error::Invalid("Hub Xet hash"))
        })
        .transpose()?;
    if expect.is_some_and(|expect| {
        advertised.is_some_and(|advertised| expect != advertised) || expect.bytes() != file.size
    }) {
        return Err(Error::Invalid("HF expected reference"));
    }
    let mut bytes = Buffer::new(core, file.size, charge)?;
    if let Some(advertised) = advertised {
        cas.write_xet(
            advertised.id().digest(),
            file.size,
            None,
            &mut bytes,
            &core.pool,
        )
        .map_err(hf_error)?;
    } else {
        if file.lfs.is_some() {
            return Err(Error::Invalid("legacy LFS has no canonical Xet identity"));
        }
        bytes.fill(
            cas.small_file(&file.path).map_err(hf_error)?,
            None,
            &core.pool,
        )?;
    }
    finish(bytes, expect.or(advertised))
}
fn hf_stages(
    cas: &crate::hf::HfCas,
    core: &Core,
    path: Option<&str>,
    expect: Option<ContentRef>,
    weights: bool,
) -> Result<(BTreeMap<ContentId, Staged>, Target)> {
    let (files, _metadata) = cas.files(&core.pool).map_err(hf_error)?;
    let mut stages = BTreeMap::new();
    if let Some(path) = path {
        let file = files
            .iter()
            .find(|file| file.path == path)
            .ok_or(Error::Missing)?;
        let stage = hf_file(cas, file, core, expect)?;
        let root = Target::Object(stage.object);
        stages.insert(stage.object.id(), stage);
        return Ok((stages, root));
    }
    let mut leaves = BTreeMap::new();
    for file in &files {
        let object = if let Some(hash) = &file.xet_hash {
            ContentRef::new(
                hash.parse()
                    .map_err(|_| Error::Invalid("Hub Xet identity"))?,
                file.size,
            )
        } else {
            let stage = hf_file(cas, file, core, None)?;
            let object = stage.object;
            stages.insert(object.id(), stage);
            object
        };
        if leaves.insert(file.path.clone(), object).is_some() {
            return Err(Error::Invalid("duplicate Hub file"));
        }
    }
    let root = trees(leaves, core, &mut stages)?;
    if expect.is_some_and(|expect| expect != root) {
        return Err(Error::Invalid("HF tree expectation"));
    }
    if weights {
        for file in &files {
            if let Some(hash) = &file.xet_hash {
                let object = ContentRef::new(
                    hash.parse()
                        .map_err(|_| Error::Invalid("Hub Xet identity"))?,
                    file.size,
                );
                if let std::collections::btree_map::Entry::Vacant(e) = stages.entry(object.id()) {
                    let stage = hf_file(cas, file, core, Some(object))?;
                    e.insert(stage);
                }
            }
        }
    }
    Ok((stages, Target::Tree(root)))
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
        let charge = core.data_pool().reserve(bytes.len() as u64)?;
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
        let core = self.clone();
        let resolving = repo.clone();
        let sha = tokio::task::spawn_blocking(move || {
            core.hf(resolving)
                .resolve_revision(&core.pool)
                .map_err(hf_error)
        })
        .await
        .map_err(|_| Error::Invalid("resolve worker failed"))??;
        let repo = crate::hf::Repo {
            revision: sha.clone(),
            ..repo
        };
        loop {
            let result = self.resolve_hf_once(scope, repo.clone()).await;
            if !matches!(result, Err(Error::Capacity)) || self.disk.is_none() {
                return result;
            }
            if self
                .access(scope, |core| core.collect_sync(&Scope::Owner, true))
                .await?
                .objects
                == 0
            {
                return result;
            }
        }
    }
    async fn resolve_hf_once(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, ContentRef)> {
        self.access(scope, |core| core.require_ready()).await?;
        let core = self.clone();
        let id = repo.id.clone();
        let sha = repo.revision.clone();
        let (stages, root) = tokio::task::spawn_blocking(move || {
            hf_stages(&core.hf(repo), &core, None, None, false)
        })
        .await
        .map_err(|_| Error::Invalid("resolve worker failed"))??;
        let pin = PinTarget {
            name: PinName::new(format!("hf/{id}@{sha}"))?,
            policy: PinPolicy::Owner,
        };
        let object = publish(self, scope, stages, root, pin, None).await?.object;
        Ok((sha, object))
    }
}

#[cfg(test)]
pub(crate) mod tests;
