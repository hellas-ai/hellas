use super::*;
use hellas_rpc::{
    ContentId, ContentRef,
    pb::work::{UploadContentRequest, UploadContentResponse},
    protocol::content_upload::chunk_digest,
};

impl GrantWork {
    pub async fn upload(
        &self,
        request: &UploadContentRequest,
        context: &TransportContext,
    ) -> Result<UploadContentResponse, WireStatus> {
        let result = async {
            let exporter = context
                .open_exporter
                .ok_or_else(|| refused(GrantRefusalCode::Malformed))?;
            let a = GrantJobAuthorizationV1::decode(&request.authorization)
                .map_err(|_| refused(GrantRefusalCode::Malformed))?;
            let signature = signature(&request.client_signature)?;
            let mut store = self.service.node.writer().await?;
            let client = self.access.proposal_owner()?;
            let id = store.authenticate_proposal(&a, client, &signature)?;
            let object = ContentRef::new(
                ContentId::from_slice(&request.content_id)
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?,
                request.total_bytes,
            );
            hellas_auth::signature::verify_digest_signature(
                &client.node.public_key(),
                &super::signature(&request.chunk_signature)?,
                chunk_digest(
                    a.channel_id.0,
                    id,
                    object,
                    request.offset,
                    &request.chunk,
                    &exporter,
                ),
            )
            .map_err(|_| refused(GrantRefusalCode::Malformed))?;

            let result = async {
                let now = self.service.node.observed_time(&store);
                self.access.authorize(&store, a.grant_id, now)?;
                authorize_route(a.channel_id, request.route.as_ref())?;
                let caller = self.access.caller(&store, now)?;
                let client = ChannelClient::of(caller).map_err(NodeStoreError::from)?;
                let prior = store
                    .precheck_acceptance(&a, client, &signature, now)
                    .await?;
                let policy = store.state().policy_for(&a)?.invocation_policy.clone();
                let preflight = (|| -> Result<_, WorkRefused> {
                    if request.program_manifest.len() > 4096 {
                        return Err(refused(GrantRefusalCode::Malformed));
                    }
                    let manifest = hellas_rpc::ProgramManifest::from_canonical_bytes(
                        &request.program_manifest,
                    )
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                    if manifest.content_id() != a.environment_commitment {
                        return Err(refused(GrantRefusalCode::Malformed));
                    }
                    let facts = policy
                        .classify_manifest(&manifest)
                        .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                    if a.input_content.bytes() > u64::from(facts.max_encoded_prepared_input) {
                        return Err(refused(GrantRefusalCode::Malformed));
                    }
                    if request.program_root.len() > hellas_channel::content::MAX_PROGRAM_ROOT_BYTES
                    {
                        return Err(refused(GrantRefusalCode::Malformed));
                    }
                    let objects = hellas_channel::job::content_closure(
                        &policy,
                        &manifest,
                        &request.program_root,
                        a.input_content,
                    )
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                    if !objects.contains(&object) {
                        return Err(refused(GrantRefusalCode::Malformed));
                    }
                    Ok(objects)
                })();
                let objects = preflight?;
                if prior.is_some() {
                    return Ok(UploadContentResponse {
                        next_offset: object.bytes(),
                        refused: None,
                    });
                }
                let mut runtime = self
                    .service
                    .inner
                    .lock()
                    .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                runtime.status.check()?;
                if !matches!(runtime.status, ServiceStatus::Serving) {
                    return Err(refused(GrantRefusalCode::QueueCapacity));
                }
                for uploads in runtime.uploads.values_mut() {
                    uploads
                        .gc(now.0, false)
                        .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                }
                runtime.uploads.retain(|_, uploads| uploads.is_staged());
                let fresh = !runtime.uploads.contains_key(&a.channel_id.0);
                let uploads = runtime.uploads.entry(a.channel_id.0).or_insert_with(|| {
                    hellas_channel::content::UploadStore::memory(
                        a.channel_id.0,
                        self.service.upload_quota.clone(),
                        self.service.content.clone(),
                    )
                });
                uploads
                    .declare_closure(
                        id,
                        &objects,
                        a.acceptance_deadline_ms.0,
                        hellas_rpc::Retention::Ephemeral,
                        policy.limits.max_upload_bytes,
                    )
                    .map_err(|_| refused(GrantRefusalCode::StateCapacity))?;
                if !request.program_root.is_empty() {
                    uploads
                        .stage_complete(
                            id,
                            ContentRef::for_bytes(&request.program_root),
                            a.acceptance_deadline_ms.0,
                            hellas_rpc::Retention::Ephemeral,
                            policy.limits.max_upload_bytes,
                            &request.program_root,
                        )
                        .map_err(|_| refused(GrantRefusalCode::StateCapacity))?;
                }
                let staged = uploads.stage(
                    id,
                    object,
                    a.acceptance_deadline_ms.0,
                    hellas_rpc::Retention::Ephemeral,
                    policy.limits.max_upload_bytes,
                    request.offset,
                    &request.chunk,
                );
                let next = match staged {
                    Ok(next) => next,
                    Err(_) => {
                        if fresh {
                            uploads
                                .clear()
                                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                        }
                        return Err(refused(GrantRefusalCode::StateCapacity));
                    }
                };
                if next == object.bytes() && object == a.input_content {
                    let checked = (|| -> Result<(), WorkRefused> {
                        let bytes = uploads
                            .read(id, object, hellas_rpc::Retention::Ephemeral)
                            .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                        let input = PreparedInvocation::from_canonical_bytes(
                            &bytes,
                            hellas_channel::content::MAX_CONTENT_BYTES,
                        )
                        .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                        let context = WorkContext {
                            network: store.state().network(),
                            channel: a.channel_id.0,
                            client: client.signer(),
                            provider: grant_producer(store.state().provider()?)
                                .map_err(NodeStoreError::from)?,
                        };
                        hellas_channel::job::check_input(&context, &(&a).into(), &policy, &input)
                            .map(|_| ())
                            .map_err(|_| refused(GrantRefusalCode::Malformed))
                    })();
                    if let Err(error) = checked {
                        uploads
                            .clear()
                            .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                        return Err(error);
                    }
                }
                drop(runtime);
                if fresh {
                    let runtime = Arc::downgrade(&self.service.inner);
                    let clock = self.service.node.clock.clone();
                    tokio::spawn(async move {
                        loop {
                            let delay = a
                                .acceptance_deadline_ms
                                .0
                                .saturating_sub(clock().0)
                                .saturating_add(1);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                            let now = clock().0;
                            {
                                let Some(runtime) = runtime.upgrade() else {
                                    return;
                                };
                                if let Ok(mut runtime) = runtime.lock()
                                    && let Some(uploads) = runtime.uploads.get_mut(&a.channel_id.0)
                                {
                                    let _ = uploads.gc(now, false);
                                }
                            }
                            if now > a.acceptance_deadline_ms.0 {
                                return;
                            }
                        }
                    });
                }
                Ok(UploadContentResponse {
                    next_offset: next,
                    refused: None,
                })
            }
            .await;
            self.service.finish_proposal(a.channel_id, id, result)
        }
        .await;
        Ok(match result {
            Ok(response) => response,
            Err(refusal) => UploadContentResponse {
                next_offset: 0,
                refused: Some(refusal),
            },
        })
    }
}
