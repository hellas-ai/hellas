use super::*;
use futures::{Stream, StreamExt};
use hellas_rpc::{call::ResponseStream, pb::content as pb, services::content::ContentHandler};
use hellas_store::content::{
    ContentService, ContentStore, Error, LocalStore, RemoteStore, Scope, ScopeKind, VerifiedReader,
};

pub(super) fn content_refusal(error: Error) -> Refusal {
    let code = match error {
        Error::Conflict => WorkRefusal::Conflict,
        Error::Io(_) => WorkRefusal::Unavailable,
        Error::Capacity => WorkRefusal::Declined,
        _ => WorkRefusal::Invalid,
    };
    Refusal::new(code, error.to_string())
}
fn status(error: impl std::fmt::Display) -> WireStatus {
    WireStatus::new(hellas_wire::WireCode::PermissionDenied, error.to_string())
}
fn object(reference: &pb::ContentRef) -> Result<ContentRef, WireStatus> {
    Ok(ContentRef::new(
        ContentId::from_slice(&reference.id).map_err(status)?,
        reference.bytes,
    ))
}

fn current_scope(shared: &std::sync::Mutex<Scope>) -> Result<Scope, WireStatus> {
    shared
        .lock()
        .map(|scope| scope.clone())
        .map_err(|_| status(Error::Denied))
}
fn set_scope(shared: &std::sync::Mutex<Scope>, scope: Scope) -> Result<(), WireStatus> {
    *shared.lock().map_err(|_| status(Error::Denied))? = scope;
    Ok(())
}
// The existing carrier callback checks paid rights under the endpoint writer,
// releasing that writer on Pending. Scope's effect binding is still called only by Core.
struct ContentWrite {
    endpoint: Arc<crate::endpoint_lock::EndpointLock<ProviderEndpoint>>,
    authorization: PaidJobAuthorizationV2,
    connection: admission::Cancellation,
    denied: bool,
    work: Digest,
    reservation: u64,
    changes: Arc<tokio::sync::Notify>,
    changed: futures::future::BoxFuture<'static, ()>,
    cancelled: futures::future::BoxFuture<'static, ()>,
    timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    waiting: Option<
        futures::future::BoxFuture<
            'static,
            Result<crate::endpoint_lock::OwnedEndpointGuard<ProviderEndpoint>, ()>,
        >,
    >,
}
impl ContentWrite {
    fn new(
        host: &WorkService,
        scope: &Scope,
        authorization: PaidJobAuthorizationV2,
        connection: admission::Cancellation,
    ) -> Self {
        let ScopeKind::Work {
            job, reservation, ..
        } = scope.kind
        else {
            unreachable!()
        };
        let cancellation = connection.clone();
        Self {
            endpoint: host.endpoint.clone(),
            authorization,
            connection,
            denied: false,
            work: job.id,
            reservation,
            changes: host.changed.clone(),
            changed: Box::pin(host.changed.clone().notified_owned()),
            cancelled: Box::pin(async move { cancellation.cancelled().await }),
            timer: None,
            waiting: None,
        }
    }
}
impl hellas_wire::WriteAuthorization for ContentWrite {
    fn poll_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
        write: &mut dyn FnMut(
            &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<usize>>,
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let denied = || {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "paid content scope ended",
            )
        };
        if self.denied || self.cancelled.as_mut().poll(cx).is_ready() {
            self.denied = true;
            self.waiting = None;
            return Poll::Ready(Err(denied()));
        }
        while self.changed.as_mut().poll(cx).is_ready() {
            self.changed = Box::pin(self.changes.clone().notified_owned());
        }
        let waiting = self.waiting.get_or_insert_with(|| {
            let endpoint = self.endpoint.clone();
            Box::pin(async move { endpoint.lock_owned().await })
        });
        let held = match waiting.as_mut().poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(held)) => held,
            Poll::Ready(Err(())) => {
                self.denied = true;
                self.waiting = None;
                return Poll::Ready(Err(denied()));
            }
        };
        self.waiting = None;
        if self.connection.is_cancelled()
            || !held
                .close
                .store
                .has_content_scope(self.work, self.reservation)
            || held.check_content_authority(&self.authorization).is_err()
        {
            self.denied = true;
            return Poll::Ready(Err(denied()));
        }
        if let Some(remaining) = held.observation.as_ref().and_then(Observation::remaining) {
            let timer = self
                .timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(remaining)));
            timer
                .as_mut()
                .reset(tokio::time::Instant::now() + remaining);
            let _ = timer.as_mut().poll(cx);
        } else {
            self.timer = None;
        }
        write(cx)
    }
}
impl ClientEndpoint {
    pub(super) async fn retain_proposal(
        &mut self,
        work: Digest,
        authorization: &PaidJobAuthorizationV2,
        prepared: &PreparedInvocation,
        source: &(LocalStore, Scope),
    ) -> Result<(), ProposeError> {
        if authorization.retention != hellas_rpc::Retention::Retain {
            return Ok(());
        }
        let policy = hellas_rpc::protocol::invocation::InvocationPolicy::from_canonical_bytes(
            prepared.application_policy.as_bytes(),
        )
        .map_err(PaidWorkError::from)?;
        let manifest = prepared.manifest().map_err(PaidWorkError::from)?;
        let root = if policy.content_closure(&manifest, &[]).is_ok() {
            bytes::Bytes::new()
        } else {
            crate::content::root(&source.0, &source.1, manifest.root()).await?
        };
        let closure =
            crate::job::content_closure(&policy, &manifest, &root, authorization.input_content)?;
        let mut share = vec![authorization.input_content];
        let mut readers = Vec::new();
        for reference in closure {
            if reference == authorization.input_content {
                continue;
            }
            if let Some(reader) = source.0.open_verified(&source.1, reference, None).await? {
                share.push(reference);
                readers.push((reference, reader));
            }
        }
        let facts =
            crate::job::check_paid_input(self.state().channel(), authorization, &policy, prepared)?;
        let (store, scope) = self
            .store
            .open_content(
                work,
                authorization.retention,
                share,
                policy.limits.max_upload_bytes,
            )
            .await?;
        self.store
            .reserve_retained(work, facts.max_spool_bytes)
            .await?;
        crate::content::upload_bytes(
            &store,
            &scope,
            &prepared.canonical_bytes().map_err(PaidWorkError::from)?,
            None,
        )
        .await?;
        for (reference, reader) in readers {
            let mut upload = store.upload(&scope, reference, None).await?;
            if !upload.complete() {
                upload
                    .copy_from(reader, &self.store.content_store().ram_pool())
                    .await?;
            }
        }
        Ok(())
    }
}

pub(super) async fn transfer_proposal<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    request: AcceptWorkRequest,
    source: &(LocalStore, Scope),
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Clone + Send + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let exporter = transport
        .context()
        .open_exporter
        .ok_or(ProposeError::Malformed("upload connection exporter"))?;
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization)?;
    let (work, prepared, pool, retained) = {
        let mut client = endpoint.client().await?;
        let work = work_id(client.state().channel(), &authorization);
        client.load_retained_input(work).await?;
        let job = client
            .state()
            .job_by_id(work)
            .ok_or(ProposeError::NoOpenJob)?;
        let prepared = PreparedInvocation::from_canonical_bytes(
            job.prepared_input(),
            crate::content::MAX_CONTENT_BYTES,
        )
        .map_err(PaidWorkError::from)?;
        (
            work,
            prepared,
            client.store.content_store().ram_pool(),
            client.store.recoverable_content(work)?,
        )
    };
    let source = retained.as_ref().unwrap_or(source);
    let manifest = prepared.manifest().map_err(PaidWorkError::from)?;
    let policy = hellas_rpc::protocol::invocation::InvocationPolicy::from_canonical_bytes(
        prepared.application_policy.as_bytes(),
    )
    .map_err(PaidWorkError::from)?;
    let root = if policy.content_closure(&manifest, &[]).is_ok() {
        None
    } else {
        Some(crate::content::root(&source.0, &source.1, manifest.root()).await?)
    };
    let closure = crate::job::content_closure(
        &policy,
        &manifest,
        root.as_deref().unwrap_or_default(),
        authorization.input_content,
    )?;
    let mut opening = pb::WorkOpening {
        signed_opening: request.encode_to_vec(),
        manifest: manifest.canonical_bytes(),
        root: root.as_ref().map(|bytes| {
            let root = ContentRef::for_bytes(bytes);
            pb::ContentRef {
                id: root.id().as_bytes().to_vec(),
                bytes: root.bytes(),
            }
        }),
        binding_signature: vec![],
    };
    opening.binding_signature = endpoint
        .client()
        .await?
        .signer
        .sign(signing_hash(crate::job::opening_digest(
            &opening, &exporter,
        )))
        .as_bytes()
        .to_vec();
    let client = WorkClientImpl::new(transport.clone());
    // A prior acceptance needs no content transfer, including after restart or
    // input expiry. The precheck does not create a new acceptance from missing bytes.
    if retained.is_some() {
        let response = client.accept_work(request.clone()).await?;
        if matches!(response.outcome, Some(Outcome::Accepted(_))) {
            return endpoint.client().await?.accepted(&response).await;
        }
    }
    let remote = RemoteStore::new(transport, pool).with_opening(opening);
    let remote_scope = Scope::work(
        hellas_store::content::JobId {
            channel: authorization.channel_id,
            id: work,
        },
        closure.clone(),
        0,
    );
    let first = root
        .as_ref()
        .map(|bytes| ContentRef::for_bytes(bytes))
        .unwrap_or(authorization.input_content);
    let prepared_bytes: bytes::Bytes = prepared
        .canonical_bytes()
        .map_err(PaidWorkError::from)?
        .into();
    let transferred = async {
        for reference in std::iter::once(first)
            .chain(closure.into_iter().filter(|reference| *reference != first))
        {
            let reader = if reference == authorization.input_content {
                Some(VerifiedReader::Memory(std::io::Cursor::new(
                    prepared_bytes.clone(),
                )))
            } else if matches!(&source.1.kind, ScopeKind::Work { closure, .. } if !closure.contains(&reference)) {
                // A retained client share excludes provider-held assets. Probe
                // the signed remote closure without reading outside that share.
                None
            } else {
                source.0.open_verified(&source.1, reference, None).await?
            };
            remote
                .upload_reader(&remote_scope, reference, None, reader)
                .await?;
        }
        remote.finish_uploads().await?;
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = transferred {
        let response = client.accept_work(request.clone()).await?;
        // Preserve a fresh authority answer. Missing upload bytes may
        // also produce Invalid, so that ambiguous refusal keeps the transfer error.
        if matches!(&response.outcome, Some(Outcome::Accepted(_)))
            || matches!(
                &response.outcome,
                Some(Outcome::Refused(refusal))
                    if WorkRefusal::from_code(refusal.code)
                        .is_some_and(|code| code != WorkRefusal::Invalid)
            )
        {
            return endpoint.client().await?.accepted(&response).await;
        }
        return Err(error.into());
    }
    let response = client.accept_work(request).await?;
    endpoint.client().await?.accepted(&response).await
}

impl ProviderEndpoint {
    fn check_content_authority(&self, authorization: &PaidJobAuthorizationV2) -> Result<(), Error> {
        self.close
            .store
            .check_authority()
            .map_err(|_| Error::Denied)?;
        let work = work_id(self.state().channel(), authorization);
        if self.state().terminal_by_id(work).is_some() || self.state().close_settled().is_some() {
            return Err(Error::Denied);
        }
        if let Some(observation) = &self.observation {
            observation.check().map_err(|_| Error::Denied)?;
        }
        if let Some(job) = self
            .state()
            .job_by_id(work)
            .filter(|job| job.provider_signature().is_some())
        {
            if job.authorization() != authorization
                || job.result().is_some()
                || self.state().cursor().0 > authorization.terminal_deadline
            {
                return Err(Error::Denied);
            }
        } else {
            if self.state().close_prepared().is_some() || self.state().close_opened().is_some() {
                return Err(Error::Denied);
            }
            let ready = self.admitting().map_err(|_| Error::Denied)?;
            crate::job::check_authorization(
                ready.channel(),
                authorization,
                ready.invocation_policy(),
                ready.payment_policy(),
                self.state().cursor().0,
            )
            .map_err(|_| Error::Denied)?;
        }
        Ok(())
    }
}

impl WorkService {
    #[cfg(any(test, feature = "test-support"))]
    pub fn content_upload_count(&self) -> Result<usize, WireStatus> {
        self.content_uploads
            .lock()
            .map(|uploads| uploads.len())
            .map_err(|_| status(Error::Denied))
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn completed_content_upload(&self, work: Digest) -> Result<bool, WireStatus> {
        self.content_uploads
            .lock()
            .map(|uploads| uploads.get(&work).is_some_and(|(_, _, active)| !*active))
            .map_err(|_| status(Error::Denied))
    }
    fn complete_content_upload(&self, work: Digest, reservation: u64) -> Result<(), WireStatus> {
        let mut uploads = self
            .content_uploads
            .lock()
            .map_err(|_| status(Error::Denied))?;
        let (current, _, active) = uploads
            .get_mut(&work)
            .ok_or_else(|| status(Error::Denied))?;
        if *current != reservation {
            return Err(status(Error::Denied));
        }
        *active = false;
        Ok(())
    }
    pub(super) fn content_scope(
        &self,
        scope: Scope,
        authorization: PaidJobAuthorizationV2,
    ) -> Scope {
        self.bound_content_scope(scope, authorization, None)
    }
    fn bound_content_scope(
        &self,
        scope: Scope,
        authorization: PaidJobAuthorizationV2,
        connection: Option<admission::Cancellation>,
    ) -> Scope {
        let (channel, work, reservation) = match &scope.kind {
            ScopeKind::Work {
                job, reservation, ..
            } => (job.channel, job.id, *reservation),
            _ => return scope,
        };
        let endpoint = self.endpoint.clone();
        let service = self.clone();
        let check_connection = connection.clone();
        scope.bind(move || {
            let endpoint = endpoint.clone();
            let connection = check_connection.clone();
            async move {
                let held = endpoint.lock_owned().await.map_err(|_| Error::Denied)?;
                Ok(move || {
                    if connection.as_ref().is_some_and(admission::Cancellation::is_cancelled) { return Err(Error::Denied); }
                    if held.state().channel().id() != channel || work_id(held.state().channel(), &authorization) != work || !held.close.store.has_content_scope(work, reservation) { return Err(Error::Denied); }
                    held.check_content_authority(&authorization)
                })
            }
        }, move || {
            let connection = connection.clone();
            let service = service.clone();
            async move {
            let cancelled = async { match &connection { Some(connection) => connection.cancelled().await, None => std::future::pending().await } };
            tokio::pin!(cancelled);
            loop {
                let changed = service.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let remaining = {
                    let Ok(endpoint) = service.endpoint().await else { return; };
                    let work = work_id(endpoint.state().channel(), &authorization);
                    if !endpoint.close.store.has_content_scope(work, reservation) || endpoint.check_content_authority(&authorization).is_err() { return; }
                    endpoint.observation.as_ref().and_then(Observation::remaining)
                };
                let expiry = async { match remaining { Some(remaining) => tokio::time::sleep(remaining).await, None => std::future::pending().await } };
                tokio::select! { biased; _ = &mut cancelled => return, _ = changed => {}, _ = expiry => {} }
            }
            }
        })
    }
    fn pending_content_cleanup(&self, scope: &Scope) -> admission::CancelOnFailure {
        let ScopeKind::Work {
            job, reservation, ..
        } = &scope.kind
        else {
            unreachable!()
        };
        let (work, reservation) = (job.id, *reservation);
        let host = self.clone();
        admission::CancelOnFailure(vec![admission::Cancellation::with_cleanup(move || {
            let host = host.clone();
            tokio::spawn(async move {
                host.discard_pending_content(work, reservation).await;
            });
        })])
    }
    async fn discard_pending_content(&self, work: Digest, reservation: u64) {
        if let Ok(mut endpoint) = self.endpoint().await {
            let _ = endpoint
                .close
                .store
                .discard_unaccepted_content(work, reservation)
                .await;
            if let Ok(mut uploads) = self.content_uploads.lock()
                && uploads
                    .get(&work)
                    .is_some_and(|(current, _, _)| *current == reservation)
            {
                uploads.remove(&work);
            }
        }
        self.changed.notify_waiters();
    }

    pub async fn upload_stream(
        &self,
        mut requests: std::pin::Pin<
            Box<dyn Stream<Item = Result<pb::UploadRequest, WireStatus>> + Send>,
        >,
        context: TransportContext,
        connection: admission::Cancellation,
    ) -> Result<ResponseStream<pb::UploadResponse>, WireStatus> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| status(Error::Invalid("missing Work opening")))??;
        let Some(pb::upload_request::Part::Open(open)) = &first.part else {
            return Err(status(Error::Invalid("missing Work opening")));
        };
        let opening = open
            .work
            .as_ref()
            .ok_or_else(|| status(Error::Denied))?
            .clone();
        let request =
            AcceptWorkRequest::decode(opening.signed_opening.as_slice()).map_err(status)?;
        let exporter = context.open_exporter.ok_or_else(|| status(Error::Denied))?;
        let mut endpoint = self
            .endpoint
            .lock_owned()
            .await
            .map_err(|_| status(Error::Denied))?;
        let host = self.clone();
        let open = open.clone();
        // Admission and map insertion outlive a cancelled RPC together; dropping
        // the detached result then runs cleanup for the actual completed scope.
        let (authorization, manifest, policy, facts, root, store, scope, fresh, cleanup) =
            tokio::spawn(async move {
                let (authorization, _, work) = endpoint
                    .authenticate_proposal(&request)
                    .map_err(|error| status(error.reason))?;
                endpoint
                    .check_content_authority(&authorization)
                    .map_err(status)?;
                let signature =
                    signature(&opening.binding_signature).ok_or_else(|| status(Error::Denied))?;
                if !Secp256k1Verifier::new().verify_sig(
                    signature,
                    endpoint.state().channel().client_key(),
                    signing_hash(crate::job::opening_digest(&opening, &exporter)),
                ) {
                    return Err(status(Error::Denied));
                }
                let manifest = hellas_rpc::ProgramManifest::from_canonical_bytes(&opening.manifest)
                    .map_err(status)?;
                if manifest.content_id() != authorization.environment_commitment
                    || decode_reference(&request.prepared_input)
                        != Some(authorization.input_content)
                {
                    return Err(status(Error::Denied));
                }
                let policy = endpoint
                    .admitting()
                    .map_err(status)?
                    .invocation_policy()
                    .clone();
                let facts = policy.classify_manifest(&manifest).map_err(status)?;
                if facts.retention != authorization.retention
                    || authorization.input_content.bytes()
                        > u64::from(facts.max_encoded_prepared_input)
                {
                    return Err(status(Error::Denied));
                }
                let root = match &opening.root {
                    Some(root) => {
                        let root = object(root)?;
                        if root.id() != manifest.root()
                            || root.bytes() > crate::content::MAX_PROGRAM_ROOT_BYTES as u64
                        {
                            return Err(status(Error::Invalid("signed program root")));
                        }
                        Some(root)
                    }
                    None if policy.content_closure(&manifest, &[]).is_ok() => None,
                    None => return Err(status(Error::Invalid("missing signed root reference"))),
                };
                let first_object = root.unwrap_or(authorization.input_content);
                if open.pin.is_some()
                    || object(open.object.as_ref().ok_or_else(|| status(Error::Denied))?)?
                        != first_object
                {
                    return Err(status(Error::Denied));
                }
                if endpoint
                    .state()
                    .job_by_id(work)
                    .is_some_and(|job| job.provider_signature().is_some())
                {
                    return Err(WireStatus::new(
                        hellas_wire::WireCode::AlreadyExists,
                        "work is already accepted",
                    ));
                }
                {
                    let uploads = host
                        .content_uploads
                        .lock()
                        .map_err(|_| status(Error::Denied))?;
                    if uploads
                        .get(&work)
                        .is_some_and(|(_, owner, active)| *owner != exporter || *active)
                    {
                        return Err(status(Error::Conflict));
                    }
                }
                if endpoint.close.store.other_pending_content(work) {
                    return Err(status(Error::Conflict));
                }
                let fresh = !host
                    .content_uploads
                    .lock()
                    .map_err(|_| status(Error::Denied))?
                    .contains_key(&work);
                let (store, scope) = endpoint
                    .close
                    .store
                    .open_content(
                        work,
                        authorization.retention,
                        vec![first_object],
                        policy.limits.max_upload_bytes,
                    )
                    .await
                    .map_err(status)?;
                let cleanup = host.pending_content_cleanup(&scope);
                let ScopeKind::Work { reservation, .. } = scope.kind else {
                    return Err(status(Error::Denied));
                };
                host.content_uploads
                    .lock()
                    .map_err(|_| status(Error::Denied))?
                    .insert(work, (reservation, exporter, true));
                Ok::<_, WireStatus>((
                    authorization,
                    manifest,
                    policy,
                    facts,
                    root,
                    store,
                    scope,
                    fresh,
                    cleanup,
                ))
            })
            .await
            .map_err(|_| status(Error::Denied))??;
        let id = match scope.kind {
            ScopeKind::Work { job, .. } => job.id,
            _ => unreachable!(),
        };
        let reservation = match &scope.kind {
            ScopeKind::Work { reservation, .. } => *reservation,
            _ => unreachable!(),
        };
        let scope = self.bound_content_scope(scope, authorization, Some(connection.clone()));
        if fresh {
            let monitor = scope.clone();
            let host = self.clone();
            tokio::spawn(async move {
                monitor.ended().await;
                host.discard_pending_content(id, reservation).await;
            });
        }
        let writer = hellas_wire::WriteAuthority::new(ContentWrite::new(
            self,
            &scope,
            authorization,
            connection.clone(),
        ));
        let service =
            ContentService::new(Arc::new(store), scope).with_write_authority(writer.clone());
        let shared = service.scope.clone();
        let requests = requests.map(|request| request.and_then(|request| {
            if matches!(&request.part, Some(pb::upload_request::Part::Open(open)) if open.work.is_some()) {
                Err(status(Error::Invalid("duplicate Work opening")))
            } else { Ok(request) }
        }));
        let incoming = futures::stream::once(async move { Ok(first) }).chain(requests);
        let mut replies = service.upload(Box::pin(incoming), context).await?;
        let host = self.clone();
        Ok(ResponseStream::new(async_stream::try_stream! {
            let mut cleanup = cleanup;
            let mut widened = false;
            while let Some(reply) = replies.next().await {
                let reply = reply?;
                if !widened && reply.complete {
                    let (closure, local, bound) = {
                        let endpoint = host.endpoint().await.map_err(status)?;
                        endpoint.check_content_authority(&authorization).map_err(status)?;
                        let root_bytes = match root { Some(root) => endpoint.close.store.read_content(id, root).await.map_err(status)?, None => bytes::Bytes::new() };
                        let closure = crate::job::content_closure(&policy, &manifest, &root_bytes, authorization.input_content).map_err(status)?;
                        let (local, _) = endpoint.close.store.invocation_content(id).map_err(status)?;
                        let bound = current_scope(&shared)?;
                        (closure,local,bound)
                    };
                    local.acquire_missing(&bound,closure.clone()).await.map_err(status)?;
                    let mut endpoint = host.endpoint().await.map_err(status)?;
                    endpoint.check_content_authority(&authorization).map_err(status)?;
                    if !endpoint.close.store.has_content_scope(id,reservation) {Err(status(Error::Denied))?;}
                    let (_, scope) = endpoint.close.store.widen_content(id, closure, policy.limits.max_upload_bytes).await.map_err(status)?;
                    if authorization.retention == hellas_rpc::Retention::Retain { endpoint.close.store.reserve_retained(id, facts.max_spool_bytes).await.map_err(status)?; }
                    set_scope(&shared, host.bound_content_scope(scope, authorization, Some(connection.clone())))?;
                    widened = true;
                }
                yield reply;
            }
            {
                let endpoint = host.endpoint().await.map_err(status)?;
                let (_, scope) = endpoint.close.store.invocation_content(id).map_err(status)?;
                let ScopeKind::Work { closure, .. } = &scope.kind else { Err(status(Error::Denied))?; unreachable!() };
                for object in closure {
                    if endpoint.close.store.open_content_reader(id, *object).await.map_err(status)?.is_none() { Err(status(Error::Missing))?; }
                }
            }
            host.complete_content_upload(id, reservation)?;
            cleanup.0.clear();
        }).with_write_authority(writer))
    }
}

#[cfg(test)]
mod carrier_tests {
    use super::*;
    use crate::test_support::channel as fixture;
    use hellas_wire::WriteAuthorization as _;
    use std::{
        task::{Context, Poll},
        time::Duration,
    };

    #[tokio::test]
    async fn a_successful_carrier_write_leaves_no_dormant_authority_waiter() {
        let root = tempfile::tempdir().unwrap();
        let ready = fixture::ready();
        let endpoint = ProviderEndpoint::new(
            ready.clone(),
            fixture::store_at(root.path(), &ready, Role::Provider, fixture::CURSOR).await,
            fixture::provider(),
        )
        .unwrap();
        let service = WorkService::new(endpoint);
        let authorization = fixture::authorization();
        let work = work_id(ready.channel(), &authorization);
        let scope = service
            .endpoint()
            .await
            .unwrap()
            .close
            .store
            .open_content(work, authorization.retention, vec![], 0)
            .await
            .unwrap()
            .1;
        let connection = admission::Cancellation::new();
        let scope = service.bound_content_scope(scope, authorization, Some(connection.clone()));
        let mut writer = ContentWrite::new(&service, &scope, authorization, connection);
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            writer.poll_write(&mut cx, &mut |_| Poll::Ready(Ok(0))),
            Poll::Ready(Ok(0))
        ));
        let held = service.endpoint().await.unwrap();
        assert!(
            writer
                .poll_write(&mut cx, &mut |_| panic!("writer held"))
                .is_pending()
        );
        service.changed.notify_waiters();
        assert!(
            writer
                .poll_write(&mut cx, &mut |_| panic!("writer still held"))
                .is_pending()
        );
        drop(held);
        assert!(matches!(
            writer.poll_write(&mut cx, &mut |_| Poll::Ready(Ok(1))),
            Poll::Ready(Ok(1))
        ));
        // A native carrier need not poll this callback again until its next ACK.
        // Producing that ACK must be able to acquire the same actual writer.
        let next = tokio::time::timeout(Duration::from_secs(1), service.endpoint()).await;
        assert!(next.is_ok(), "a dormant callback owns the endpoint permit");
        drop(writer);
    }
}
