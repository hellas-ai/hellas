use super::*;
use futures::{Stream, StreamExt};
use hellas_rpc::{call::ResponseStream, pb::content as pb, services::content::ContentHandler};
use hellas_store::content::{ContentService, JobContent, JobId, LocalStore, ScopeKind};
use prost::Message;

fn status(error: impl std::fmt::Display) -> WireStatus {
    WireStatus::new(hellas_wire::WireCode::PermissionDenied, error.to_string())
}
fn object(reference: &pb::ContentRef) -> Result<hellas_rpc::ContentRef, WireStatus> {
    Ok(hellas_rpc::ContentRef::new(
        hellas_rpc::ContentId::from_slice(&reference.id).map_err(status)?,
        reference.bytes,
    ))
}
fn current_scope(
    shared: &std::sync::Mutex<hellas_store::content::Scope>,
) -> Result<hellas_store::content::Scope, WireStatus> {
    shared
        .lock()
        .map(|scope| scope.clone())
        .map_err(|_| status("content scope lock"))
}
fn identity(job: &JobContent) -> (JobId, u64) {
    match &job.scope().kind {
        ScopeKind::Work {
            job, reservation, ..
        } => (*job, *reservation),
        _ => unreachable!(),
    }
}
impl GrantService {
    fn complete_content_upload(
        &self,
        channel: ChannelId,
        reservation: u64,
    ) -> Result<(), WireStatus> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| status("service unavailable"))?;
        let (job, _, active) = held
            .contents
            .get_mut(&channel.0)
            .ok_or_else(|| status("content scope ended"))?;
        if identity(job).1 != reservation {
            return Err(status("content scope changed"));
        }
        *active = false;
        Ok(())
    }
    fn set_pending_content(
        &self,
        channel: ChannelId,
        job: JobContent,
    ) -> Result<(), NodeStoreError> {
        let mut held = self
            .inner
            .lock()
            .map_err(|_| NodeStoreError::WriterPoisoned)?;
        let current = held
            .contents
            .get_mut(&channel.0)
            .ok_or(NodeStoreError::Malformed)?;
        if identity(&current.0) != identity(&job) {
            return Err(NodeStoreError::Malformed);
        }
        current.0 = job;
        Ok(())
    }
    pub(crate) fn pending_content(
        &self,
        channel: ChannelId,
        work: Digest,
    ) -> Result<JobContent, WorkRefused> {
        self.inner
            .lock()
            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?
            .contents
            .get(&channel.0)
            .filter(|(job, _, _)| identity(job).0.id == work)
            .map(|(job, _, _)| job.clone())
            .ok_or_else(|| refused(GrantRefusalCode::Malformed))
    }
    pub(super) async fn end_pending(
        &self,
        channel: ChannelId,
        work: Digest,
        reservation: Option<u64>,
    ) -> Result<(), NodeStoreError> {
        let job = {
            let mut held = self
                .inner
                .lock()
                .map_err(|_| NodeStoreError::WriterPoisoned)?;
            match held.contents.get(&channel.0) {
                Some((job, _, _))
                    if identity(job).0.id == work
                        && reservation.is_none_or(|reservation| identity(job).1 == reservation) =>
                {
                    held.contents.remove(&channel.0)
                }
                _ => None,
            }
        };
        if let Some((job, _, _)) = job {
            job.end()
                .await
                .map_err(|_| NodeStoreError::WriterPoisoned)?;
        }
        Ok(())
    }
}
impl GrantWork {
    fn pending_content_cleanup(
        &self,
        job: &JobContent,
    ) -> hellas_channel::work::admission::CancelOnFailure {
        let (id, reservation) = identity(job);
        let work = self.clone();
        hellas_channel::work::admission::CancelOnFailure(vec![
            hellas_channel::work::admission::Cancellation::with_cleanup(move || {
                let work = work.clone();
                tokio::spawn(async move {
                    work.discard_pending_content(id, reservation).await;
                });
            }),
        ])
    }
    async fn discard_pending_content(&self, job: JobId, reservation: u64) {
        let Ok(store) = self.service.node.writer().await else {
            return;
        };
        // A failed append may have accepted this proposal without applying it
        // in memory. Its cancelled stream cannot settle that uncertainty.
        if store.check_authority().is_err() {
            return;
        }
        if store
            .state()
            .channel(ChannelId(job.channel))
            .and_then(|channel| channel.job_book().job_by_id(job.id))
            .is_some_and(|job| job.provider_signature().is_some())
        {
            return;
        }
        let _ = self
            .service
            .end_pending(ChannelId(job.channel), job.id, Some(reservation))
            .await;
        self.service.node.changed.notify_waiters();
    }
    pub async fn upload_stream(
        &self,
        mut requests: Pin<Box<dyn Stream<Item = Result<pb::UploadRequest, WireStatus>> + Send>>,
        context: TransportContext,
        connection: hellas_channel::work::admission::Cancellation,
    ) -> Result<ResponseStream<pb::UploadResponse>, WireStatus> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| status("missing Work opening"))??;
        let Some(pb::upload_request::Part::Open(open)) = &first.part else {
            return Err(status("missing Work opening"));
        };
        let opening = open
            .work
            .clone()
            .ok_or_else(|| status("missing Work opening"))?;
        let request =
            AcceptWorkRequest::decode(opening.signed_opening.as_slice()).map_err(status)?;
        let exporter = context
            .open_exporter
            .ok_or_else(|| status("missing connection exporter"))?;
        let mut store = self
            .service
            .node
            .store
            .lock_owned()
            .await
            .map_err(|_| status("authority writer unavailable"))?;
        let work = self.clone();
        let open = open.clone();
        let parent = connection.clone();
        let (authorization, manifest, policy, root, job, scope, writer, fresh, cleanup) =
            tokio::spawn(async move {
                let a = GrantJobAuthorizationV1::decode(&request.authorization).map_err(status)?;
                let client_signature = signature(&request.client_signature)
                    .map_err(|_| status("invalid client signature"))?;
                let client = work.access.proposal_owner().map_err(status)?;
                let id = store
                    .authenticate_proposal(&a, client, &client_signature)
                    .map_err(status)?;
                let now = work.service.node.observed_time(&store);
                work.access
                    .authorize(&store, a.grant_id, now)
                    .map_err(status)?;
                authorize_route(a.channel_id, request.route.as_ref())
                    .map_err(|_| status("invalid Work route"))?;
                hellas_auth::signature::verify_digest_signature(
                    &client.node.public_key(),
                    &super::signature(&opening.binding_signature)
                        .map_err(|_| status("invalid opening signature"))?,
                    hellas_channel::job::opening_digest(&opening, &exporter),
                )
                .map_err(status)?;
                // A new, authenticated opening may retire only this carrier's
                // completed pending proposal. An active or foreign upload keeps
                // its original owner even if this request is refused.
                let prior = {
                    let held = work
                        .service
                        .inner
                        .lock()
                        .map_err(|_| status("service unavailable"))?;
                    held.status.check().map_err(status)?;
                    held.contents
                        .get(&a.channel_id.0)
                        .filter(|(job, owner, active)| {
                            identity(job).0.id == id && *owner == exporter && !*active
                        })
                        .map(|(job, _, _)| job.clone())
                };
                let probe = store
                    .precheck_acceptance(&a, client, &client_signature, now)
                    .await;
                let probe = if prior.is_some() {
                    work.service
                        .finish_proposal(
                            a.channel_id,
                            id,
                            probe.map_err(|error| WorkRefused::from(&error)),
                        )
                        .await
                        .map_err(|_| status("proposal refused"))?
                } else {
                    probe.map_err(status)?
                };
                if probe.is_some() {
                    return Err(WireStatus::new(
                        hellas_wire::WireCode::AlreadyExists,
                        "work is already accepted",
                    ));
                }
                let prior_cleanup = prior.as_ref().map(|job| work.pending_content_cleanup(job));
                // Refresh after the durable probe: a new admission past its
                // acceptance deadline is refused explicitly.
                if work.service.node.observed_time(&store) > a.acceptance_deadline_ms {
                    return Err(WireStatus::new(
                        hellas_wire::WireCode::DeadlineExceeded,
                        "grant acceptance expired",
                    ));
                }
                let policy = store
                    .state()
                    .policy_for(&a)
                    .map_err(status)?
                    .invocation_policy
                    .clone();
                let manifest = hellas_rpc::ProgramManifest::from_canonical_bytes(&opening.manifest)
                    .map_err(status)?;
                let facts = policy.classify_manifest(&manifest).map_err(status)?;
                if manifest.content_id() != a.environment_commitment
                    || hellas_rpc::protocol::content::decode_reference(&request.prepared_input)
                        != Some(a.input_content)
                    || a.input_content.bytes() > u64::from(facts.max_encoded_prepared_input)
                {
                    return Err(status("opening differs from signed invocation"));
                }
                let root = match &opening.root {
                    Some(root) => {
                        let root = object(root)?;
                        if root.id() != manifest.root()
                            || root.bytes() > hellas_channel::content::MAX_PROGRAM_ROOT_BYTES as u64
                        {
                            return Err(status("invalid program root reference"));
                        }
                        Some(root)
                    }
                    None if policy.content_closure(&manifest, &[]).is_ok() => None,
                    None => return Err(status("missing program root reference")),
                };
                let first_object = root.unwrap_or(a.input_content);
                if open.pin.is_some()
                    || object(
                        open.object
                            .as_ref()
                            .ok_or_else(|| status("missing upload object"))?,
                    )? != first_object
                {
                    return Err(status("first upload object is not the signed root"));
                }
                let existing = {
                    let held = work
                        .service
                        .inner
                        .lock()
                        .map_err(|_| status("service unavailable"))?;
                    held.status.check().map_err(status)?;
                    if !matches!(held.status, ServiceStatus::Serving) {
                        return Err(status("service is not admitting work"));
                    }
                    match held.contents.get(&a.channel_id.0) {
                        Some((job, _, _)) if identity(job).0.id != id => {
                            return Err(status("another proposal occupies this channel"));
                        }
                        Some((_, owner, active)) if *owner != exporter || *active => {
                            return Err(status("another upload owns this proposal"));
                        }
                        existing => existing.map(|(job, _, _)| job.clone()),
                    }
                };
                let fresh = existing.is_none();
                let job = match existing {
                    Some(job) => job,
                    None => JobContent::new(
                        &work.service.content,
                        JobId {
                            channel: a.channel_id.0,
                            id,
                        },
                        vec![first_object],
                        policy.limits.max_upload_bytes,
                    )
                    .await
                    .map_err(status)?,
                };
                work.service
                    .inner
                    .lock()
                    .map_err(|_| status("service unavailable"))?
                    .contents
                    .insert(a.channel_id.0, (job.clone(), exporter, true));
                let cleanup = prior_cleanup.unwrap_or_else(|| work.pending_content_cleanup(&job));
                let (scope, writer) = work
                    .content_work_locked(&mut store, job.scope().clone(), a, parent)
                    .map_err(status)?;
                Ok::<_, WireStatus>((
                    a, manifest, policy, root, job, scope, writer, fresh, cleanup,
                ))
            })
            .await
            .map_err(|_| status("content admission failed"))??;
        let (id, reservation) = identity(&job);
        if fresh {
            let scope = scope.clone();
            let work = self.clone();
            tokio::spawn(async move {
                scope.ended().await;
                work.discard_pending_content(id, reservation).await;
            });
        }
        let service = ContentService::new(Arc::new(LocalStore::Job(job)), scope)
            .with_write_authority(writer.clone());
        let shared = service.scope.clone();
        let requests = requests.map(|request| request.and_then(|request| {
            if matches!(&request.part, Some(pb::upload_request::Part::Open(open)) if open.work.is_some()) { Err(status("duplicate Work opening")) } else { Ok(request) }
        }));
        let mut replies = service
            .upload(
                Box::pin(futures::stream::once(async move { Ok(first) }).chain(requests)),
                context,
            )
            .await?;
        let work = self.clone();
        Ok(ResponseStream::new(async_stream::try_stream! {
            let mut cleanup = cleanup;
            let mut widened = false;
            while let Some(reply) = replies.next().await {
                let reply = reply?;
                if !widened && reply.complete {
                    let (closure,local,bound) = {
                        let store = work.service.node.writer().await.map_err(status)?;
                        work.access.authorize(&store, authorization.grant_id, work.service.node.observed_time(&store)).map_err(status)?;
                        let job = work.service.pending_content(authorization.channel_id, id.id).map_err(|_| status("content scope ended"))?;
                        if identity(&job).1 != reservation { Err(status("content scope changed"))?; }
                        let local = LocalStore::Job(job.clone());
                        let bytes = match root { Some(root) => hellas_channel::content::read(&local, job.scope(), root, hellas_channel::content::MAX_PROGRAM_ROOT_BYTES as u64).await.map_err(status)?, None => bytes::Bytes::new() };
                        let closure = hellas_channel::job::content_closure(&policy, &manifest, &bytes, authorization.input_content).map_err(status)?;
                        let bound = current_scope(&shared)?;
                        (closure,local,bound)
                    };
                    local.acquire_missing(&bound,closure.clone()).await.map_err(status)?;
                    let mut store = work.service.node.writer().await.map_err(status)?;
                    work.access.authorize(&store, authorization.grant_id, work.service.node.observed_time(&store)).map_err(status)?;
                    let job = work.service.pending_content(authorization.channel_id, id.id).map_err(|_|status("content scope ended"))?;
                    if identity(&job).1 != reservation {Err(status("content scope changed"))?;}
                    let job = job.widen(closure, policy.limits.max_upload_bytes).await.map_err(status)?;
                    work.service.set_pending_content(authorization.channel_id, job.clone()).map_err(status)?;
                    let (scope, _) = work.content_work_locked(&mut store, job.scope().clone(), authorization, connection.clone()).map_err(status)?;
                    replace_scope(&shared, scope)?;
                    widened = true;
                }
                yield reply;
            }
            {
                let _store = work.service.node.writer().await.map_err(status)?;
                let job = work.service.pending_content(authorization.channel_id, id.id).map_err(|_| status("content scope ended"))?;
                let local = LocalStore::Job(job.clone());
                let ScopeKind::Work { closure, .. } = &job.scope().kind else { Err(status("invalid Work scope"))?; unreachable!() };
                if !local.missing_refs(job.scope(), closure.clone()).await.map_err(status)?.is_empty() { Err(status("incomplete Work closure"))?; }
            }
            work.service.complete_content_upload(authorization.channel_id, reservation)?;
            cleanup.0.clear();
        }).with_write_authority(writer))
    }
}
fn replace_scope(
    shared: &std::sync::Mutex<hellas_store::content::Scope>,
    scope: hellas_store::content::Scope,
) -> Result<(), WireStatus> {
    *shared
        .lock()
        .map_err(|_| status("content scope unavailable"))? = scope;
    Ok(())
}
