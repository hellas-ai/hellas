use super::wire as w;
use super::*;
use futures::StreamExt;
use hellas_rpc::{
    ContentRef, call::BidiStreamingCall, pb::content as pb, services::content::ContentClientImpl,
};
use hellas_wire::StreamTransport;
use hellas_xet::{Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use std::sync::Arc;

type UploadCall = BidiStreamingCall<pb::UploadRequest, pb::UploadResponse>;
struct UploadState {
    call: Option<UploadCall>,
    active: bool,
}
pub(crate) struct RemoteSession {
    state: Arc<std::sync::Mutex<UploadState>>,
    call: Option<UploadCall>,
    work: bool,
    finished: bool,
}
impl RemoteSession {
    fn begin(state: Arc<std::sync::Mutex<UploadState>>, work: bool) -> Result<Self> {
        let call = {
            let mut idle = state.lock().map_err(|_| Error::Invalid("upload lock"))?;
            if idle.active {
                return Err(Error::Conflict);
            }
            idle.active = true;
            idle.call.take()
        };
        Ok(Self {
            state,
            call,
            work,
            finished: false,
        })
    }
    async fn finish_object(&mut self) -> Result<()> {
        if !self.work {
            self.close().await?;
        }
        let mut idle = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("upload lock"))?;
        idle.call = self.call.take();
        idle.active = false;
        self.finished = true;
        Ok(())
    }
    async fn close(&mut self) -> Result<()> {
        if let Some(mut call) = self.call.take() {
            call.close().await.map_err(w::error)?;
            match call.next().await {
                Some(Err(status)) => return Err(w::error(status)),
                Some(Ok(_)) => return Err(Error::Invalid("extra upload progress")),
                None => {}
            }
            call.finish().map_err(w::error)?;
        }
        Ok(())
    }
    pub(crate) async fn declare(
        &mut self,
        chunks: &[Chunk],
        complete: bool,
        verified: bool,
    ) -> Result<()> {
        let call = self.call.as_mut().ok_or(Error::Missing)?;
        call.send(pb::UploadRequest {
            part: Some(pb::upload_request::Part::List(pb::ChunkList {
                chunks: chunks.iter().map(super::page::wire_chunk).collect(),
                complete,
            })),
        })
        .await
        .map_err(w::error)?;
        let progress = call
            .next()
            .await
            .ok_or(Error::Invalid("missing upload progress"))?
            .map_err(w::error)?;
        if progress.next_chunk != 0 || progress.complete != verified {
            return Err(Error::Invalid("upload declaration progress"));
        }
        if verified {
            self.finish_object().await?;
        }
        Ok(())
    }
    pub(crate) async fn chunk(&mut self, bytes: &[u8], next: usize, complete: bool) -> Result<()> {
        let call = self.call.as_mut().ok_or(Error::Missing)?;
        call.send(pb::UploadRequest {
            part: Some(pb::upload_request::Part::Chunk(bytes.to_vec())),
        })
        .await
        .map_err(w::error)?;
        let progress = call
            .next()
            .await
            .ok_or(Error::Invalid("missing upload progress"))?
            .map_err(w::error)?;
        if progress.next_chunk != next as u64 || progress.complete != complete {
            return Err(Error::Invalid("upload payload progress"));
        }
        if complete {
            self.finish_object().await?;
        }
        Ok(())
    }
}
impl Drop for RemoteSession {
    fn drop(&mut self) {
        if !self.finished {
            // The session owns the in-flight call; no async mutex can hide it
            // from cancellation. Dropping it resets the wire stream.
            self.call.take();
            if let Ok(mut state) = self.state.lock() {
                state.active = false;
            }
        }
    }
}

/// Calls use the already-authenticated connection, never self-asserted scopes.
pub struct RemoteStore<T> {
    client: ContentClientImpl<T>,
    pool: Reservations,
    opening: Option<pb::WorkOpening>,
    upload: Arc<std::sync::Mutex<UploadState>>,
}
impl<T> RemoteStore<T>
where
    T: StreamTransport + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    pub fn new(transport: T, pool: Reservations) -> Self {
        Self {
            client: ContentClientImpl::new(transport),
            pool,
            opening: None,
            upload: Arc::new(std::sync::Mutex::new(UploadState {
                call: None,
                active: false,
            })),
        }
    }
    pub fn with_opening(mut self, opening: pb::WorkOpening) -> Self {
        self.opening = Some(opening);
        self
    }
    pub async fn finish_uploads(&self) -> Result<()> {
        let mut session = RemoteSession::begin(self.upload.clone(), false)?;
        session.finish_object().await
    }
}
impl<T> RemoteStore<T>
where
    T: StreamTransport + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    async fn manifest(
        &self,
        scope: &Scope,
        at: &Path,
    ) -> Result<(
        ContentRef,
        Vec<Chunk>,
        Vec<Arc<super::reservation::Reservation>>,
    )> {
        let object = self
            .stat(scope, at)
            .await?
            .ok_or(Error::Missing)?
            .target
            .object();
        let mut chunks = Vec::new();
        let mut charges = Vec::new();
        let mut cursor = Cursor {
            object: Some(object),
            ..Default::default()
        };
        let mut bytes = 0u64;
        loop {
            // Reserve a transport window before accepting the next metadata page.
            let page_buffer = self.pool.reserve(body_limit() as u64)?;
            let page = self.chunks(scope, at, cursor).await?;
            if page.object != object {
                return Err(Error::Conflict);
            }
            let count = chunks
                .len()
                .checked_add(page.chunks.len())
                .ok_or(Error::Capacity)?;
            if count as u64 > object.bytes() / MIN_CHUNK_SIZE as u64 + 1 {
                return Err(Error::Invalid("remote manifest count"));
            }
            for chunk in &page.chunks {
                bytes = bytes
                    .checked_add(chunk.data_len)
                    .filter(|bytes| *bytes <= object.bytes())
                    .ok_or(Error::Invalid("remote manifest bytes"))?;
            }
            let charge = self
                .pool
                .reserve((page.chunks.len() * std::mem::size_of::<Chunk>()) as u64)?;
            chunks.extend(page.chunks);
            charges.push(charge);
            drop(page_buffer);
            match page.next {
                Some(next)
                    if next.offset == chunks.len() as u64
                        && next.offset > cursor.offset
                        && next.object == Some(object) =>
                {
                    cursor = next
                }
                Some(_) => return Err(Error::Invalid("remote manifest cursor")),
                None => break,
            }
        }
        if chunks
            .iter()
            .rev()
            .skip(1)
            .any(|chunk| chunk.data_len < MIN_CHUNK_SIZE as u64)
            || bytes != object.bytes()
            || hellas_xet::file_hash(&chunks) != object.id().digest()
        {
            return Err(Error::Invalid("remote manifest commitment"));
        }
        Ok((object, chunks, charges))
    }
}
#[async_trait::async_trait]
impl<T> ContentStore for RemoteStore<T>
where
    T: StreamTransport + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    async fn stat(&self, _: &Scope, at: &Path) -> Result<Option<Stat>> {
        let response = self
            .client
            .stat(pb::StatRequest {
                at: Some(w::path(at)),
            })
            .await
            .map_err(w::error)?;
        response
            .target
            .map(w::target_from)
            .transpose()
            .map(|target| target.map(|target| Stat { target }))
    }
    async fn chunks(&self, _: &Scope, at: &Path, cursor: Cursor) -> Result<ChunkPage> {
        let response = self
            .client
            .chunks(pb::ChunksRequest {
                at: Some(w::path(at)),
                cursor: Some(w::cursor(cursor)),
            })
            .await
            .map_err(w::error)?;
        if prost::Message::encoded_len(&response) > body_limit() {
            return Err(Error::Invalid("remote chunk page size"));
        }
        let object = w::object(
            response
                .object
                .as_ref()
                .ok_or(Error::Invalid("missing chunk reference"))?,
        )?;
        if cursor.object.is_some_and(|old| old != object) {
            return Err(Error::Conflict);
        }
        let mut chunks = Vec::new();
        for chunk in response.chunks {
            if chunk.bytes == 0 || chunk.bytes > MAX_CHUNK_SIZE as u64 {
                return Err(Error::Invalid("remote chunk length"));
            }
            chunks.push(Chunk::new(
                hellas_xet::XetHash::from_slice(&chunk.hash)
                    .map_err(|_| Error::Invalid("remote chunk hash"))?,
                chunk.bytes,
            ));
        }
        Ok(ChunkPage {
            object,
            chunks,
            next: response.next.map(w::cursor_from).transpose()?,
        })
    }
    async fn read(
        &self,
        scope: &Scope,
        at: &Path,
        range: std::ops::Range<u64>,
    ) -> Result<ByteStream> {
        let (object, chunks, charges) = self.manifest(scope, at).await?;
        if range.start > range.end || range.end > object.bytes() {
            return Err(Error::Invalid("read range"));
        }
        let mut offset = 0u64;
        let mut selected = Vec::new();
        for chunk in chunks {
            let end = offset + chunk.data_len;
            if offset < range.end && end > range.start {
                selected.push((offset, chunk));
            }
            offset = end;
        }
        let mut call = self
            .client
            .read(pb::ReadRequest {
                at: Some(w::path(at)),
                start: range.start,
                end: range.end,
                expect: Some(super::page::wire_ref(object)),
            })
            .await
            .map_err(w::error)?;
        let stream = async_stream::try_stream! {
            let _charges = charges;
            let mut next = 0usize; let mut reference_seen = false;
            let mut pending: Option<pb::ReadResponse> = None;
            while let Some(response) = call.next().await {
                let response = response.map_err(w::error)?;
                if w::object(response.object.as_ref().ok_or(Error::Invalid("read reference"))?)? != object { Err(Error::Conflict)?; }
                reference_seen = true;
                if range.is_empty() {
                    if !response.data.is_empty() || response.offset != range.start || next != 0 { Err(Error::Invalid("empty ranged response"))?; }
                    next += 1; continue;
                }
                let (offset, chunk) = selected.get(next).ok_or(Error::Invalid("extra read chunk"))?;
                if response.offset != *offset || response.data.len() as u64 != chunk.data_len || hellas_xet::chunk(&response.data).as_slice() != [*chunk] { Err(Error::Invalid("read chunk verification"))?; }
                if let Some(previous) = pending.take() {
                    let mut boundary = previous.data.clone(); boundary.push(response.data[0]);
                    if hellas_xet::chunk(&boundary).first().is_none_or(|chunk| chunk.data_len != previous.data.len() as u64) { Err(Error::Invalid("read chunk boundary"))?; }
                    yield slice(previous, &range);
                }
                next += 1; pending = Some(response);
            }
            if !reference_seen || (!range.is_empty() && next != selected.len()) || (range.is_empty() && next != 1) { Err(Error::Invalid("incomplete ranged response"))?; }
            call.finish().map_err(w::error)?;
            if let Some(last) = pending { yield slice(last, &range); }
        };
        Ok(ByteStream {
            object,
            bytes: Box::pin(stream),
        })
    }
    async fn upload(
        &self,
        scope: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<UploadSession> {
        match &scope.kind {
            ScopeKind::Owner if pin.is_some() => {}
            ScopeKind::Work { closure, .. } if pin.is_none() && closure.contains(&object) => {}
            _ => return Err(Error::Denied),
        }
        let mut remote = RemoteSession::begin(
            self.upload.clone(),
            matches!(scope.kind, ScopeKind::Work { .. }),
        )?;
        let opening = if remote.call.is_none() {
            remote.call = Some(self.client.upload().await.map_err(w::error)?);
            self.opening.clone()
        } else {
            None
        };
        let active = remote.call.as_mut().ok_or(Error::Missing)?;
        active
            .send(pb::UploadRequest {
                part: Some(pb::upload_request::Part::Open(pb::UploadOpen {
                    object: Some(super::page::wire_ref(object)),
                    pin: pin.as_ref().map(w::pin_target),
                    work: opening,
                })),
            })
            .await
            .map_err(w::error)?;
        let progress = active
            .next()
            .await
            .ok_or(Error::Invalid("missing upload answer"))?
            .map_err(w::error)?;
        if !progress.missing {
            if !progress.complete {
                return Err(Error::Invalid("invalid missing answer"));
            }
            remote.finish_object().await?;
            return Ok(UploadSession::present(object));
        }
        if progress.next_chunk != 0 || progress.complete {
            return Err(Error::Invalid("invalid initial upload progress"));
        }
        Ok(UploadSession::remote(object, remote))
    }

    async fn acquire(
        &self,
        scope: &Scope,
        source: Source,
        expect: Option<ContentRef>,
        pin: PinTarget,
    ) -> Result<Acquisition> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        let mut call = self
            .client
            .acquire(pb::AcquireRequest {
                source: Some(w::source(source)),
                expect: expect.map(super::page::wire_ref),
                pin: Some(w::pin_target(&pin)),
            })
            .await
            .map_err(w::error)?;
        let mut result = None;
        while let Some(progress) = call.next().await {
            let progress = progress.map_err(w::error)?;
            if result.is_some() {
                return Err(Error::Invalid("progress after acquire completion"));
            }
            if let Some(object) = progress.complete {
                result = Some(w::object(&object)?);
            }
        }
        call.finish().map_err(w::error)?;
        let object = result.ok_or(Error::Invalid("missing acquisition result"))?;
        if expect.is_some_and(|expected| expected != object) {
            return Err(Error::Invalid("acquisition mismatch"));
        }
        Ok(Acquisition { object })
    }
    async fn set_pin(
        &self,
        scope: &Scope,
        name: &PinName,
        expected: Option<&PinValue>,
        new: Option<PinValue>,
    ) -> Result<()> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        self.client
            .set_pin(pb::SetPinRequest {
                name: name.as_str().into(),
                expected: expected.map(w::pin_value),
                value: new.as_ref().map(w::pin_value),
            })
            .await
            .map_err(w::error)?;
        Ok(())
    }
    async fn pins(&self, _: &Scope, prefix: &str, cursor: Cursor) -> Result<PinPage> {
        let response = self
            .client
            .list_pins(pb::ListPinsRequest {
                prefix: prefix.into(),
                cursor: Some(w::cursor(cursor)),
            })
            .await
            .map_err(w::error)?;
        if prost::Message::encoded_len(&response) > body_limit() {
            return Err(Error::Invalid("pin page size"));
        }
        Ok(PinPage {
            pins: response
                .pins
                .into_iter()
                .map(w::pin_from)
                .collect::<Result<_>>()?,
            next: response.next.map(w::cursor_from).transpose()?,
            cursor: w::cursor_from(
                response
                    .cursor
                    .ok_or(Error::Invalid("pin snapshot cursor"))?,
            )?,
        })
    }
    async fn watch(&self, _: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents> {
        let mut call = self
            .client
            .watch_pins(pb::WatchPinsRequest {
                prefix: prefix.into(),
                from: Some(w::cursor(from)),
            })
            .await
            .map_err(w::error)?;
        Ok(Box::pin(async_stream::try_stream! {
            while let Some(event) = call.next().await { yield w::event_from(event.map_err(w::error)?)?; }
            call.finish().map_err(w::error)?;
        }))
    }
    async fn collect(&self, scope: &Scope) -> Result<Collected> {
        if !matches!(scope.kind, ScopeKind::Owner) {
            return Err(Error::Denied);
        }
        let response = self
            .client
            .collect(pb::CollectRequest {})
            .await
            .map_err(w::error)?;
        Ok(Collected {
            objects: response.objects,
            bytes: response.bytes,
        })
    }
}

fn slice(response: pb::ReadResponse, range: &std::ops::Range<u64>) -> bytes::Bytes {
    let start = range.start.saturating_sub(response.offset) as usize;
    let end = (range.end - response.offset).min(response.data.len() as u64) as usize;
    bytes::Bytes::from(response.data).slice(start..end)
}
