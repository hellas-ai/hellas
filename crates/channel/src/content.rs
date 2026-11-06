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
