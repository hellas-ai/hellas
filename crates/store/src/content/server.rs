//! One Content adapter. The host authenticates the opening and supplies the
//! scope; request fields never select Owner, Grant or Work authority.
use super::{wire as w, *};
use futures::{Stream, StreamExt};
use hellas_rpc::{call::ResponseStream, pb::content as pb, services::content::ContentHandler};
use hellas_wire::{TransportContext, WireCode, WireStatus};
use std::sync::{Arc, Mutex};

pub struct ContentService<S> {
    pub store: Arc<S>,
    writer: Option<hellas_wire::WriteAuthority>,
    /// Shared only with the trusted host, which widens Work after root validation.
    pub scope: Arc<Mutex<Scope>>,
}
macro_rules! resolve_handler {
    ($store:ty) => {
        impl hellas_rpc::services::resolve::ResolveHandler for ContentService<$store> {
            async fn resolve(
                &self,
                request: hellas_rpc::pb::resolve::ResolveRequest,
                _: TransportContext,
            ) -> std::result::Result<
                impl Into<hellas_rpc::call::WithTrailer<hellas_rpc::pb::resolve::ResolveResponse>>
                + Send,
                WireStatus,
            > {
                let repo = crate::hf::Repo::from_uri(&request.uri)
                    .map_err(|_| status(Error::Invalid("HF URI")))?;
                let (commit_sha, object) = self
                    .store
                    .resolve_hf(&self.scope()?, repo)
                    .await
                    .map_err(status)?;
                Ok(self.reply(hellas_rpc::pb::resolve::ResolveResponse {
                    commit_sha,
                    tree: Some(super::page::wire_ref(object)),
                }))
            }
        }
    };
}
resolve_handler!(MemoryStore);
resolve_handler!(DiskStore);
impl<S> Clone for ContentService<S> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            writer: self.writer.clone(),
            scope: self.scope.clone(),
        }
    }
}
impl<S> ContentService<S> {
    pub fn new(store: Arc<S>, scope: Scope) -> Self {
        Self {
            store,
            writer: None,
            scope: Arc::new(Mutex::new(scope)),
        }
    }
    pub fn with_write_authority(mut self, writer: hellas_wire::WriteAuthority) -> Self {
        self.writer = Some(writer);
        self
    }
    fn reply<R>(&self, value: R) -> hellas_rpc::call::WithTrailer<R> {
        let reply = hellas_rpc::call::WithTrailer::new(value);
        match &self.writer {
            Some(writer) => reply.with_write_authority(writer.clone()),
            None => reply,
        }
    }
    fn stream<R: Send + 'static>(&self, mut stream: ResponseStream<R>) -> ResponseStream<R> {
        let scope = self.scope();
        let stream = ResponseStream::new(async_stream::try_stream! {
            let scope = scope?;
            loop {
                let next = tokio::select! {
                    biased;
                    _ = scope.ended() => Err(status(Error::Denied)),
                    next = stream.next() => Ok(next),
                };
                match next {
                    Err(error) | Ok(Some(Err(error))) => {
                        // A terminal yield can suspend until the carrier writes its
                        // trailer. Release any queued inner effect before that handoff.
                        drop(stream);
                        Err::<(), _>(error)?;
                        return;
                    }
                    Ok(Some(Ok(item))) => yield item,
                    Ok(None) => break,
                }
            }
        });
        match &self.writer {
            Some(writer) => stream.with_write_authority(writer.clone()),
            None => stream,
        }
    }
    fn scope(&self) -> std::result::Result<Scope, WireStatus> {
        self.scope
            .lock()
            .map(|scope| scope.clone())
            .map_err(|_| WireStatus::internal("content scope"))
    }
}
fn status(error: Error) -> WireStatus {
    let (code, message) = match error {
        Error::Locked => (
            WireCode::Unavailable,
            "another process holds the content database",
        ),
        Error::Denied => (WireCode::PermissionDenied, "content access denied"),
        Error::WorkOwned => (
            WireCode::FailedPrecondition,
            "this store is owned by a node with paid work; run the command against the daemon",
        ),
        Error::Missing => (WireCode::NotFound, "content is missing"),
        Error::Conflict => (WireCode::Aborted, "pin or cursor changed"),
        Error::Capacity => (WireCode::ResourceExhausted, "content reservation exhausted"),
        Error::Invalid(message) => (WireCode::InvalidArgument, message),
        Error::Io(_) => (WireCode::Internal, "content IO failed"),
    };
    WireStatus::new(code, message)
}
fn required<T>(value: Option<T>) -> std::result::Result<T, WireStatus> {
    value.ok_or_else(|| status(Error::Invalid("missing content field")))
}
impl<S: ContentStore + 'static> ContentHandler for ContentService<S> {
    async fn stat(
        &self,
        r: pb::StatRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::StatResponse>> + Send,
        WireStatus,
    > {
        let at = w::path_from(required(r.at)?).map_err(status)?;
        Ok(self.reply(pb::StatResponse {
            target: self
                .store
                .stat(&self.scope()?, &at)
                .await
                .map_err(status)?
                .map(|stat| w::target(&stat.target)),
        }))
    }
    async fn chunks(
        &self,
        r: pb::ChunksRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::ChunksResponse>> + Send,
        WireStatus,
    > {
        let at = w::path_from(required(r.at)?).map_err(status)?;
        let cursor = r
            .cursor
            .map(w::cursor_from)
            .transpose()
            .map_err(status)?
            .unwrap_or_default();
        let page = self
            .store
            .chunks(&self.scope()?, &at, cursor.clone())
            .await
            .map_err(status)?;
        Ok(self.reply(pb::ChunksResponse {
            object: Some(super::page::wire_ref(page.object)),
            chunks: page.chunks.iter().map(super::page::wire_chunk).collect(),
            next: page.next.as_ref().map(w::cursor),
        }))
    }
    async fn read(
        &self,
        r: pb::ReadRequest,
        _: TransportContext,
    ) -> std::result::Result<ResponseStream<pb::ReadResponse>, WireStatus> {
        let at = w::path_from(required(r.at)?).map_err(status)?;
        let scope = self.scope()?;
        let mut read = self
            .store
            .read(&scope, &at, r.start..r.end)
            .await
            .map_err(status)?;
        let object = read.object;
        if r.expect
            .as_ref()
            .map(w::object)
            .transpose()
            .map_err(status)?
            .is_some_and(|expect| expect != object)
        {
            return Err(status(Error::Conflict));
        }
        Ok(self.stream(ResponseStream::new(async_stream::try_stream! {
            let mut offset = r.start;
            while let Some(bytes) = read.bytes.next().await {
                let data = bytes.map_err(status)?;
                if data.is_empty() {
                    continue;
                }
                let end = offset.checked_add(data.len() as u64)
                    .filter(|end| *end <= r.end)
                    .ok_or_else(|| status(Error::Invalid("extra read bytes")))?;
                yield pb::ReadResponse {
                    object: Some(super::page::wire_ref(object)),
                    offset,
                    data: data.to_vec(),
                };
                offset = end;
            }
            if offset != r.end {
                Err(status(Error::Invalid("short read")))?;
            }
            if r.start == r.end {
                yield pb::ReadResponse {
                    object: Some(super::page::wire_ref(object)),
                    offset,
                    data: vec![],
                };
            }

        })))
    }
    async fn upload(
        &self,
        mut requests: std::pin::Pin<
            Box<dyn Stream<Item = std::result::Result<pb::UploadRequest, WireStatus>> + Send>,
        >,
        _: TransportContext,
    ) -> std::result::Result<ResponseStream<pb::UploadResponse>, WireStatus> {
        let service = self.clone();
        Ok(self.stream(ResponseStream::new(async_stream::try_stream! {
            let mut session: Option<UploadSession> = None;
            while let Some(request) = requests.next().await {
                match required(request?.part)? {
                    pb::upload_request::Part::Open(open) => {
                        if session.is_some() {
                            Err(status(Error::Invalid("object already open")))?;
                        }
                        let scope = service.scope()?;
                        if open.work.is_some() && !matches!(scope.kind, ScopeKind::Work { .. }) {
                            Err(status(Error::Denied))?;
                        }
                        let object = w::object(&required(open.object)?).map_err(status)?;
                        let pin = open
                            .pin
                            .map(w::pin_target_from)
                            .transpose()
                            .map_err(status)?;
                        let upload = service
                            .store
                            .upload(&scope, object, pin)
                            .await
                            .map_err(status)?;
                        let present = upload.complete();
                        yield pb::UploadResponse {
                            next_chunk: upload.next_chunk() as u64,
                            missing: !present,
                            complete: present,
                        };
                        if !present {
                            session = Some(upload);
                        }
                    }
                    pb::upload_request::Part::List(list) => {
                        let upload = session
                            .as_mut()
                            .ok_or_else(|| status(Error::Invalid("declaration without open")))?;
                        let chunks = list
                            .chunks
                            .into_iter()
                            .map(w::chunk_from)
                            .collect::<Result<Vec<_>>>().map_err(status)?;
                        upload
                            .declare(&chunks, list.complete)
                            .await
                            .map_err(status)?;
                        let complete = upload.complete();
                        yield pb::UploadResponse {
                            next_chunk: upload.next_chunk() as u64,
                            missing: true,
                            complete,
                        };
                        if complete {
                            session = None;
                        }
                    }
                    pb::upload_request::Part::Chunk(bytes) => {
                        let upload = session
                            .as_mut()
                            .ok_or_else(|| status(Error::Invalid("payload without open")))?;
                        upload.accept_chunk(&bytes).await.map_err(status)?;
                        let complete = upload.complete();
                        yield pb::UploadResponse {
                            next_chunk: upload.next_chunk() as u64,
                            missing: true,
                            complete,
                        };
                        if complete {
                            session = None;
                        }
                    }
                }
            }
            if session.is_some() {
                Err(status(Error::Invalid("unfinished upload")))?;
            }
        })))
    }
    async fn acquire(
        &self,
        r: pb::AcquireRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::ContentRef>> + Send,
        WireStatus,
    > {
        let source = w::source_from(required(r.source)?).map_err(status)?;
        let expect = r
            .expect
            .as_ref()
            .map(w::object)
            .transpose()
            .map_err(status)?;
        let pin = w::pin_target_from(required(r.pin)?).map_err(status)?;
        let scope = self.scope()?;
        let acquired = tokio::select! {
            biased;
            _ = scope.ended() => return Err(status(Error::Denied)),
            acquired = self.store.acquire(&scope, source, expect, pin) => acquired.map_err(status)?,
        };
        Ok(self.reply(super::page::wire_ref(acquired.object)))
    }
    async fn set_pin(
        &self,
        r: pb::SetPinRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::SetPinResponse>> + Send,
        WireStatus,
    > {
        let name = PinName::new(r.name).map_err(status)?;
        let expected = r.expected.map(w::value_from).transpose().map_err(status)?;
        let new = r.value.map(w::value_from).transpose().map_err(status)?;
        self.store
            .set_pin(&self.scope()?, &name, expected.as_ref(), new)
            .await
            .map_err(status)?;
        Ok(self.reply(pb::SetPinResponse {}))
    }
    async fn list_pins(
        &self,
        r: pb::ListPinsRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::ListPinsResponse>> + Send,
        WireStatus,
    > {
        let page = self
            .store
            .pins(
                &self.scope()?,
                &r.prefix,
                r.cursor
                    .map(w::cursor_from)
                    .transpose()
                    .map_err(status)?
                    .unwrap_or_default(),
            )
            .await
            .map_err(status)?;
        Ok(self.reply(pb::ListPinsResponse {
            pins: page
                .pins
                .iter()
                .map(|(name, value)| w::pin(name, value))
                .collect(),
            next: page.next.as_ref().map(w::cursor),
            cursor: Some(w::cursor(&page.cursor)),
        }))
    }
    async fn watch_pins(
        &self,
        r: pb::WatchPinsRequest,
        _: TransportContext,
    ) -> std::result::Result<ResponseStream<pb::WatchPinsResponse>, WireStatus> {
        let events = self
            .store
            .watch(
                &self.scope()?,
                &r.prefix,
                r.from
                    .map(w::cursor_from)
                    .transpose()
                    .map_err(status)?
                    .unwrap_or_default(),
            )
            .await
            .map_err(status)?;
        Ok(self.stream(ResponseStream::new(
            events.map(|event| event.map(|event| w::event(&event)).map_err(status)),
        )))
    }
    async fn collect(
        &self,
        _: pb::CollectRequest,
        _: TransportContext,
    ) -> std::result::Result<
        impl Into<hellas_rpc::call::WithTrailer<pb::CollectResponse>> + Send,
        WireStatus,
    > {
        let collected = self.store.collect(&self.scope()?).await.map_err(status)?;
        Ok(self.reply(pb::CollectResponse {
            objects: collected.objects,
            bytes: collected.bytes,
        }))
    }
}

#[cfg(test)]
mod waiter_tests {
    use super::*;
    use std::task::{Context, Poll};

    #[tokio::test]
    async fn terminal_scope_drops_queued_watch_effect_before_yielding_its_error() {
        let authority = Arc::new(tokio::sync::Mutex::new(()));
        let (ended, _) = tokio::sync::watch::channel(false);
        let acquire = authority.clone();
        let end = ended.clone();
        let scope = Scope::Owner.bind(
            move || {
                let acquire = acquire.clone();
                async move {
                    let held = acquire.lock_owned().await;
                    Ok(move || {
                        let _ = &held;
                        Ok(())
                    })
                }
            },
            move || {
                let mut end = end.subscribe();
                async move {
                    let _ = end.wait_for(|ended| *ended).await;
                }
            },
        );
        let store = MemoryStore::new(Reservations::ram(1 << 20));
        let service = ContentService::new(Arc::new(store), scope);
        let mut response = service
            .watch_pins(
                pb::WatchPinsRequest {
                    prefix: String::new(),
                    from: None,
                },
                TransportContext::default(),
            )
            .await
            .unwrap();
        let held = authority.clone().lock_owned().await;
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            std::pin::Pin::new(&mut response).poll_next(&mut cx),
            Poll::Pending
        ));
        // The watch's actual Core effect is queued for this host writer.
        drop(held);
        ended.send_replace(true);
        assert!(response.next().await.unwrap().is_err());
        let next = tokio::time::timeout(crate::HANG_GUARD, authority.lock()).await;
        assert!(
            next.is_ok(),
            "terminal response retained the queued Core effect"
        );
        drop(response);
    }
}
