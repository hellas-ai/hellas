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
            let now = self.service.node.observed_time(&store);
            self.access.authorize(&store, a.grant_id, now)?;
            authorize_route(a.channel_id, request.route.as_ref())?;
            let caller = self.access.caller(&store, now)?;
            let client = ChannelClient::of(caller).map_err(NodeStoreError::from)?;
            let id = grant_work_id(store.state().network(), &a);
            let prior = store
                .precheck_acceptance(&a, client, &signature, now)
                .await?;
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
            if prior.is_some() {
                return Ok(UploadContentResponse {
                    next_offset: object.bytes(),
                });
            }
            let policy = store.state().policy_for(&a)?.work.clone();
            if object.bytes() > u64::from(policy.max_encoded_prepared_input()) {
                return Err(refused(GrantRefusalCode::Malformed));
            }
            let mut runtime = self
                .service
                .inner
                .lock()
                .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
            runtime.status.check()?;
            for uploads in runtime.uploads.values_mut() {
                uploads
                    .gc(now.0, false)
                    .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
            }
            runtime.uploads.retain(|_, uploads| uploads.is_staged());
            let fresh = !runtime.uploads.contains_key(&a.channel_id.0);
            let uploads = runtime.uploads.entry(a.channel_id.0).or_insert_with(|| {
                crate::content::UploadStore::memory(
                    a.channel_id.0,
                    self.service.upload_quota.clone(),
                )
            });
            let next = uploads
                .stage(
                    id,
                    object,
                    a.acceptance_deadline_ms.0,
                    policy.max_upload_bytes(),
                    request.offset,
                    &request.chunk,
                )
                .map_err(|_| refused(GrantRefusalCode::StateCapacity))?;
            if next == object.bytes() {
                let bytes = uploads
                    .read(id, object)
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                let input = PreparedWorkInput::decode(&bytes, crate::content::MAX_CONTENT_BYTES)
                    .map_err(|_| refused(GrantRefusalCode::Malformed))?;
                let context = WorkContext {
                    network: store.state().network(),
                    channel: a.channel_id.0,
                    client: client.signer(),
                    provider: grant_producer(store.state().provider()?)
                        .map_err(NodeStoreError::from)?,
                };
                if policy
                    .check_bound_input(&context, &(&a).into(), &input)
                    .is_err()
                {
                    uploads
                        .clear()
                        .map_err(|_| refused(GrantRefusalCode::StorageUnavailable))?;
                    return Err(refused(GrantRefusalCode::Malformed));
                }
            }
            drop(runtime);
            if fresh {
                let service = self.service.clone();
                tokio::spawn(async move {
                    let delay = a
                        .acceptance_deadline_ms
                        .0
                        .saturating_sub((service.node.clock)().0)
                        .saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    if let Ok(mut runtime) = service.inner.lock() {
                        if let Some(uploads) = runtime.uploads.get_mut(&a.channel_id.0) {
                            let _ = uploads.gc((service.node.clock)().0, false);
                        }
                    }
                });
            }
            Ok(UploadContentResponse { next_offset: next })
        }
        .await;
        result.map_err(|refusal: WorkRefused| {
            WireStatus::new(hellas_wire::WireCode::InvalidArgument, refusal.reason)
        })
    }
}
