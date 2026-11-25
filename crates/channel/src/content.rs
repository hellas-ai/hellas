//! Application closure orchestration over the shared content store.
use hellas_auth::Digest;
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::content::{
    ContentStore, Cursor, DiskStore, Error, LocalStore, PinName, PinPolicy, PinTarget, Scope,
    ScopeKind, UploadSession, chunk_page,
};

pub(crate) mod tree;
pub(crate) use tree::{job_tree, tree_reservation};

pub const MAX_PROGRAM_ROOT_BYTES: usize = 1 << 20;
pub const MAX_CONTENT_BYTES: usize = crate::work_store::journal::MAX_ACTIVE_JOURNAL_BYTES as usize;
pub const DEFAULT_MAX_STAGING_BYTES: u64 = MAX_CONTENT_BYTES as u64;

/// Finish conditional Compute rules with the provider's own acquisition history.
/// Opening a scoped staging carrier only admits the signed root and input until this succeeds.
pub async fn match_program(
    store: &LocalStore,
    scope: &Scope,
    policy: &hellas_rpc::protocol::invocation::InvocationPolicy,
    manifest: &hellas_rpc::ProgramManifest,
    opened_root: Option<&[u8]>,
) -> Result<std::collections::BTreeSet<String>, Error> {
    use hellas_rpc::protocol::invocation::{HubRepo, ModelOrigins, compute::Environment};
    let origins = if policy.needs_model_origins(manifest) {
        let loaded;
        let bytes = match opened_root {
            Some(bytes) => bytes,
            None => {
                loaded = root(store, scope, manifest.root()).await?;
                &loaded
            }
        };
        if ContentId::hash(bytes) != manifest.root() {
            return Err(Error::Denied);
        }
        let model = Environment::from_canonical_bytes(bytes)
            .map_err(|_| Error::Invalid("compute root"))?
            .model;
        let mut files = std::collections::BTreeMap::new();
        for asset in &model.assets {
            if let std::collections::btree_map::Entry::Vacant(entry) = files.entry(asset.object) {
                let origins = store
                    .verified_hub_files(asset.object)
                    .await?
                    .into_iter()
                    .map(|(repo, _, _)| {
                        HubRepo::try_from(repo).map_err(|_| Error::Invalid("stored Hub repo"))
                    })
                    .collect::<Result<_, _>>()?;
                entry.insert(origins);
            }
        }
        Some(ModelOrigins::new(&model, &files).map_err(|_| Error::Denied)?)
    } else {
        None
    };
    if !policy.admits_manifest(manifest, origins.as_ref()) {
        return Err(Error::Denied);
    }
    Ok(policy.pure_setup_entries(manifest, origins.as_ref()))
}
pub async fn read(
    store: &LocalStore,
    scope: &Scope,
    object: ContentRef,
    maximum: u64,
) -> Result<bytes::Bytes, Error> {
    if object.bytes() > maximum {
        return Err(Error::Invalid("application content byte limit"));
    }
    let reader = store
        .open_verified(scope, object, None)
        .await?
        .ok_or(Error::Missing)?;
    read_reader(reader, object, &store.ram_pool()).await
}

pub(crate) async fn read_reader(
    reader: hellas_store::content::VerifiedReader,
    object: ContentRef,
    pool: &hellas_store::content::Reservations,
) -> Result<bytes::Bytes, Error> {
    reader.read_all(object, pool).await
}

pub fn object_pin(object: ContentRef) -> Result<PinTarget, Error> {
    Ok(PinTarget {
        name: PinName::new(format!("object/{}", object.id()))?,
        policy: PinPolicy::Owner,
    })
}

pub async fn root(store: &LocalStore, scope: &Scope, id: ContentId) -> Result<bytes::Bytes, Error> {
    let object = if let ScopeKind::Work { closure, .. } = &scope.kind {
        *closure
            .iter()
            .find(|object| object.id() == id)
            .ok_or(Error::Missing)?
    } else {
        let at =
            hellas_store::content::Path::new(PinName::new(format!("object/{id}"))?, String::new())?;
        store
            .stat(scope, &at)
            .await?
            .ok_or(Error::Missing)?
            .target
            .object()
    };
    read(store, scope, object, MAX_PROGRAM_ROOT_BYTES as u64).await
}

/// Client-owned sources use explicit Owner object pins.
pub async fn upload_object(store: &impl ContentStore, bytes: &[u8]) -> Result<ContentRef, Error> {
    upload_bytes(
        store,
        &Scope::Owner,
        bytes,
        Some(object_pin(ContentRef::for_bytes(bytes))?),
    )
    .await
}

pub async fn upload_bytes(
    store: &impl ContentStore,
    scope: &Scope,
    bytes: &[u8],
    pin: Option<PinTarget>,
) -> Result<ContentRef, Error> {
    fill(
        store
            .upload(scope, ContentRef::for_bytes(bytes), pin)
            .await?,
        bytes,
    )
    .await
}

pub(crate) async fn stage(
    store: &DiskStore,
    scope: &Scope,
    bytes: &[u8],
) -> Result<ContentRef, Error> {
    fill(
        store
            .stage_output(scope, ContentRef::for_bytes(bytes))
            .await?,
        bytes,
    )
    .await
}

async fn fill(mut session: UploadSession, bytes: &[u8]) -> Result<ContentRef, Error> {
    let object = ContentRef::for_bytes(bytes);
    if session.object() != object {
        return Err(Error::Invalid("application upload reference"));
    }
    if session.complete() {
        return Ok(object);
    }
    let chunks = hellas_xet::chunk(bytes);
    let mut cursor = Cursor::default();
    loop {
        let page = chunk_page(object, &chunks, cursor)?;
        session.declare(&page.chunks, page.next.is_none()).await?;
        match page.next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    let mut offset = 0;
    for chunk in chunks {
        let end = offset + chunk.data_len as usize;
        session.accept_chunk(&bytes[offset..end]).await?;
        offset = end;
    }
    if !session.complete() {
        return Err(Error::Missing);
    }
    Ok(object)
}

pub(crate) fn channel_pin(
    channel: Digest,
    work: Digest,
    proposal: bool,
) -> Result<PinTarget, Error> {
    Ok(PinTarget {
        name: PinName::new(if proposal {
            format!("channel/{channel}/proposal/{work}")
        } else {
            format!("channel/{channel}/{work}")
        })?,
        policy: PinPolicy::Channel(channel),
    })
}
