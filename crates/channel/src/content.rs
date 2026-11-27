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

/// The paid router and both funding services open the first frame exactly once.
pub struct WorkUpload {
    request: hellas_rpc::pb::work::AcceptWorkRequest,
    opening: hellas_rpc::pb::content::WorkOpening,
    exporter: [u8; 32],
    requests: hellas_store::content::UploadRequests,
}
impl WorkUpload {
    pub fn request(&self) -> &hellas_rpc::pb::work::AcceptWorkRequest {
        &self.request
    }
    pub fn into_parts(
        self,
    ) -> (
        hellas_rpc::pb::content::WorkOpening,
        hellas_rpc::pb::work::AcceptWorkRequest,
        [u8; 32],
        hellas_store::content::UploadRequests,
    ) {
        (self.opening, self.request, self.exporter, self.requests)
    }
    pub async fn read(
        mut requests: hellas_store::content::UploadRequests,
        context: &hellas_wire::TransportContext,
    ) -> Result<Self, hellas_wire::WireStatus> {
        use futures::StreamExt;
        use hellas_rpc::pb::content::upload_request::Part;
        use prost::Message;
        let denied = || {
            hellas_wire::WireStatus::new(
                hellas_wire::WireCode::PermissionDenied,
                "invalid Work content opening",
            )
        };
        let mut first = requests.next().await.ok_or_else(denied)??;
        let Some(Part::Open(open)) = &mut first.part else {
            return Err(denied());
        };
        let opening = open.work.take().ok_or_else(denied)?;
        let request =
            hellas_rpc::pb::work::AcceptWorkRequest::decode(opening.signed_opening.as_slice())
                .map_err(|_| denied())?;
        let first_object = open.object.as_ref().ok_or_else(denied)?;
        // Funding authentication subsequently checks these exact root/input commitments.
        let matches = match &opening.root {
            Some(root) => first_object == root,
            None => hellas_rpc::protocol::content::decode_reference(&request.prepared_input)
                .is_some_and(|input| {
                    first_object.bytes == input.bytes()
                        && first_object.id.as_slice() == input.id().as_bytes()
                }),
        };
        if open.pin.is_some() || !matches {
            return Err(denied());
        }
        Ok(Self {
            request,
            opening,
            exporter: context.open_exporter.ok_or_else(denied)?,
            requests: futures::stream::once(async move { Ok(first) })
                .chain(requests)
                .boxed(),
        })
    }
}
/// The bound scope checks funding, cancellation and this reservation before each store effect.
pub async fn stage_work(
    service: &hellas_store::content::ContentService<LocalStore>,
    policy: &hellas_rpc::protocol::invocation::InvocationPolicy,
    manifest: &hellas_rpc::ProgramManifest,
    input: ContentRef,
) -> Result<Vec<ContentRef>, hellas_wire::WireStatus> {
    let bound = service.scope()?;
    let closure = work_closure(&service.store, &bound, policy, manifest, input)
        .await
        .map_err(upload_status)?;
    service
        .store
        .acquire_missing(&bound, closure.clone())
        .await
        .map_err(upload_status)?;
    Ok(closure)
}

pub fn upload_status(error: impl std::fmt::Display) -> hellas_wire::WireStatus {
    hellas_wire::WireStatus::new(hellas_wire::WireCode::PermissionDenied, error.to_string())
}

/// Read the authenticated model root and expand its verified content closure.
pub async fn work_closure(
    store: &LocalStore,
    scope: &Scope,
    policy: &hellas_rpc::protocol::invocation::InvocationPolicy,
    manifest: &hellas_rpc::ProgramManifest,
    prepared: ContentRef,
) -> Result<Vec<ContentRef>, Error> {
    let bytes = if manifest.model().is_some() {
        root(store, scope, manifest.root()).await?
    } else {
        bytes::Bytes::new()
    };
    policy
        .content_closure(manifest, &bytes, Some(prepared))
        .map_err(|_| Error::Invalid("invalid program content closure"))
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
    reader.read_all(object, &store.ram_pool()).await
}

/// Host-side work staging may read this reservation's as-yet-unpublished disk objects.
pub(crate) async fn read_staged(
    store: &LocalStore,
    scope: &Scope,
    object: ContentRef,
    maximum: u64,
) -> Result<bytes::Bytes, Error> {
    let LocalStore::Disk(node) = store else {
        return read(store, scope, object, maximum).await;
    };
    if object.bytes() > maximum {
        return Err(Error::Invalid("application content byte limit"));
    }
    node.open_staged(scope, object)
        .await?
        .ok_or(Error::Missing)?
        .read_all(object, &store.ram_pool())
        .await
}

pub fn object_pin(object: ContentRef) -> Result<PinTarget, Error> {
    Ok(PinTarget {
        name: PinName::object(object.id()),
        policy: PinPolicy::Owner,
    })
}

pub async fn root(store: &LocalStore, scope: &Scope, id: ContentId) -> Result<bytes::Bytes, Error> {
    if let ScopeKind::Work { closure, .. } = &scope.kind {
        let object = *closure
            .iter()
            .find(|object| object.id() == id)
            .ok_or(Error::Missing)?;
        return read_staged(store, scope, object, MAX_PROGRAM_ROOT_BYTES as u64).await;
    }
    let at = hellas_store::content::Path::new(PinName::object(id), String::new())?;
    let object = store
        .stat(scope, &at)
        .await?
        .ok_or(Error::Missing)?
        .target
        .object();
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
