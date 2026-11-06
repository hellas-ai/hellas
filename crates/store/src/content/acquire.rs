use super::{reservation::Reservation, *};
use bytes::Bytes;
use futures::StreamExt;
use hellas_rpc::{ContentId, ContentRef};
use hellas_xet::{Chunk, MAX_CHUNK_SIZE, XetFileHasher};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, io::Read, sync::Arc};

pub(crate) struct Staged {
    object: ContentRef,
    bytes: Bytes,
    chunks: Vec<Chunk>,
    charge: Arc<Reservation>,
}
fn finish(
    bytes: Vec<u8>,
    expected: Option<ContentRef>,
    charge: Arc<Reservation>,
) -> Result<Staged> {
    let mut hasher = XetFileHasher::new();
    hasher.update(&bytes);
    let chunks = hasher.finalize_chunks();
    let object = ContentRef::new(
        ContentId::from_bytes(hellas_xet::file_hash(&chunks).into_bytes()),
        bytes.len() as u64,
    );
    if expected.is_some_and(|expected| expected != object) {
        return Err(Error::Invalid("acquisition content mismatch"));
    }
    Ok(Staged {
        object,
        bytes: Bytes::from(bytes),
        chunks,
        charge,
    })
}
/// Exact-length bounded streaming copy, shared by HTTPS and git-stored HF files.
fn read_bytes(mut reader: impl Read, len: u64, sha256: Option<[u8; 32]>) -> Result<Vec<u8>> {
    let capacity = usize::try_from(len).map_err(|_| Error::Capacity)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    bytes.resize(capacity, 0);
    let mut hash = Sha256::new();
    let mut filled = 0;
    while filled < capacity {
        let end = filled.saturating_add(MAX_CHUNK_SIZE).min(capacity);
        let read = reader.read(&mut bytes[filled..end])?;
        if read == 0 {
            return Err(Error::Invalid("source shorter than declared bytes"));
        }
        hash.update(&bytes[filled..filled + read]);
        filled += read;
    }
    let mut sentinel = [0];
    if reader.read(&mut sentinel)? != 0
        || sha256.is_some_and(|expected| hash.finalize().as_slice() != expected)
    {
        return Err(Error::Invalid("source length or SHA-256"));
    }
    Ok(bytes)
}
fn hf_error(error: crate::hf::FetchError) -> Error {
    if matches!(error, crate::hf::FetchError::Capacity) {
        Error::Capacity
    } else {
        Error::Invalid("HF acquisition failed")
    }
}
fn publish(
    store: &MemoryStore,
    stages: BTreeMap<ContentId, Staged>,
    target: Target,
    pin: PinTarget,
) -> Result<Acquisition> {
    let object = target.object();
    store.publish_acquired(
        stages
            .into_values()
            .map(|stage| (stage.object, stage.bytes, stage.chunks, stage.charge))
            .collect(),
        target,
        pin,
    )?;
    Ok(Acquisition { object })
}
pub(crate) async fn memory(
    store: &MemoryStore,
    source: Source,
    expect: Option<ContentRef>,
    pin: PinTarget,
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
            let charge = store.pool.reserve(bytes)?;
            let http = store.http.clone();
            let stage = tokio::task::spawn_blocking(move || {
                let response = http
                    .get(url.as_str())
                    .call()
                    .map_err(|_| Error::Invalid("HTTPS request failed"))?;
                if response.status() != 200 {
                    return Err(Error::Invalid("HTTPS response status"));
                }
                let bytes = read_bytes(response.into_body().into_reader(), bytes, sha256)?;
                finish(bytes, expect, charge)
            })
            .await
            .map_err(|_| Error::Invalid("acquisition worker failed"))??;
            let target = Target::Object(stage.object);
            publish(
                store,
                BTreeMap::from([(stage.object.id(), stage)]),
                target,
                pin,
            )
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
                    let charge = store.pool.reserve(object.bytes())?;
                    let path = Path::new(at.pin.clone(), join_path(&at.path, &path))?;
                    let mut read = remote
                        .read(&Scope::Public, &path, 0..object.bytes())
                        .await?;
                    if read.object != object {
                        return Err(Error::Conflict);
                    }
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(
                            usize::try_from(object.bytes()).map_err(|_| Error::Capacity)?,
                        )
                        .map_err(|_| Error::Capacity)?;
                    while let Some(chunk) = read.bytes.next().await {
                        let chunk = chunk?;
                        if bytes.len() as u64 + chunk.len() as u64 > object.bytes() {
                            return Err(Error::Invalid("peer length"));
                        }
                        bytes.extend_from_slice(&chunk);
                    }
                    // Canonical hashing is blocking work, even with a verified peer list.
                    let stage =
                        tokio::task::spawn_blocking(move || finish(bytes, Some(object), charge))
                            .await
                            .map_err(|_| Error::Invalid("hash worker failed"))??;
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
                    for (name, child) in Tree::decode(&stages[&object.id()].bytes)?.entries() {
                        let path = join_path(&path, name);
                        super::tree::validate_path(&path, false)?;
                        let queue_charge = store
                            .pool
                            .reserve((path.len() + std::mem::size_of::<Target>()) as u64)?;
                        pending.push((*child, path, Some(queue_charge)));
                    }
                }
            }
            publish(store, stages, root, pin)
        }
        Source::HfXet { repo, commit, path } => {
            repo.validate().map_err(hf_error)?;
            if !crate::hf::immutable_sha(&commit) || repo.revision != commit {
                return Err(Error::Invalid("HF immutable commit"));
            }
            if let Some(path) = &path {
                super::tree::validate_path(path, false)?;
            }
            let pool = store.pool.clone();
            let (stages, root) = tokio::task::spawn_blocking(move || {
                let cas = crate::hf::HfCas::new(repo);
                hf_stages(&cas, &pool, path.as_deref(), expect, true)
            })
            .await
            .map_err(|_| Error::Invalid("HF worker failed"))??;
            publish(store, stages, root, pin)
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
    pool: &Reservations,
    expect: Option<ContentRef>,
) -> Result<Staged> {
    let charge = pool.reserve(file.size)?;
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
    let bytes = if let Some(advertised) = advertised {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(file.size).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        cas.write_xet(advertised.id().digest(), file.size, None, &mut bytes, pool)
            .map_err(hf_error)?;
        bytes
    } else {
        if file.lfs.is_some() {
            return Err(Error::Invalid("legacy LFS has no canonical Xet identity"));
        }
        read_bytes(
            cas.small_file(&file.path).map_err(hf_error)?,
            file.size,
            None,
        )?
    };
    finish(bytes, expect.or(advertised), charge)
}
fn hf_stages(
    cas: &crate::hf::HfCas,
    pool: &Reservations,
    path: Option<&str>,
    expect: Option<ContentRef>,
    weights: bool,
) -> Result<(BTreeMap<ContentId, Staged>, Target)> {
    let (files, _metadata) = cas.files(pool).map_err(hf_error)?;
    let mut stages = BTreeMap::new();
    if let Some(path) = path {
        let file = files
            .iter()
            .find(|file| file.path == path)
            .ok_or(Error::Missing)?;
        let stage = hf_file(cas, file, pool, expect)?;
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
            let stage = hf_file(cas, file, pool, None)?;
            let object = stage.object;
            stages.insert(object.id(), stage);
            object
        };
        if leaves.insert(file.path.clone(), object).is_some() {
            return Err(Error::Invalid("duplicate Hub file"));
        }
    }
    let root = trees(leaves, pool, &mut stages)?;
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
                    let stage = hf_file(cas, file, pool, Some(object))?;
                    e.insert(stage);
                }
            }
        }
    }
    Ok((stages, Target::Tree(root)))
}
fn trees(
    leaves: BTreeMap<String, ContentRef>,
    pool: &Reservations,
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
        let charge = pool.reserve(bytes.len() as u64)?;
        let stage = finish(bytes, None, charge)?;
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
impl MemoryStore {
    /// Resolve learns immutable names and small-file IDs, without downloading weights.
    pub async fn resolve_hf(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, ContentRef)> {
        if !matches!(scope, Scope::Owner) {
            return Err(Error::Denied);
        }
        let pool = self.pool.clone();
        let id = repo.id.clone();
        let (sha, stages, root) = tokio::task::spawn_blocking(move || {
            let sha = crate::hf::HfCas::new(repo.clone())
                .resolve_revision(&pool)
                .map_err(hf_error)?;
            let repo = crate::hf::Repo {
                revision: sha.clone(),
                ..repo
            };
            let (stages, root) = hf_stages(&crate::hf::HfCas::new(repo), &pool, None, None, false)?;
            Ok::<_, Error>((sha, stages, root))
        })
        .await
        .map_err(|_| Error::Invalid("resolve worker failed"))??;
        let pin = PinTarget {
            name: PinName::new(format!("hf/{id}@{sha}"))?,
            policy: PinPolicy::Owner,
        };
        let object = publish(self, stages, root, pin)?.object;
        Ok((sha, object))
    }
}

#[cfg(test)]
mod tests;
