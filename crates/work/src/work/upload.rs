use super::*;
use hellas_rpc::{
    pb::work::{UploadContentRequest, UploadContentResponse},
    protocol::content_upload::{CONTENT_CHUNK_BYTES, chunk_digest},
};

pub(super) fn content_refusal(error: crate::content::ContentError) -> Refusal {
    let code = match error {
        crate::content::ContentError::Storage(_) => WorkRefusal::Unavailable,
        crate::content::ContentError::ProposalLimit => WorkRefusal::Conflict,
        _ => WorkRefusal::Invalid,
    };
    Refusal::new(code, error.to_string())
}
impl ProviderEndpoint {
    pub fn upload_content(
        &mut self,
        request: &UploadContentRequest,
        context: &TransportContext,
    ) -> Result<u64, WireStatus> {
        self.upload(request, context)
            .map_err(|error| WireStatus::new(hellas_wire::WireCode::InvalidArgument, error.reason))
    }
    fn upload(
        &mut self,
        request: &UploadContentRequest,
        context: &TransportContext,
    ) -> Result<u64, Refusal> {
        let exporter = context
            .open_exporter
            .ok_or_else(|| Refusal::invalid("upload requires a bound connection"))?;
        let (authorization, _, id) = self.authenticate_proposal(&AcceptWorkRequest {
            route: request.route.clone(),
            authorization: request.authorization.clone(),
            client_signature: request.client_signature.clone(),
            prepared_input: Vec::new(),
        })?;
        let object = ContentRef::new(
            ContentId::from_slice(&request.content_id)
                .map_err(|_| Refusal::invalid("invalid content id"))?,
            request.total_bytes,
        );
        let signature = signature(&request.chunk_signature)
            .ok_or_else(|| Refusal::invalid("invalid chunk signature"))?;
        if !Secp256k1Verifier::new().verify_sig(
            signature,
            self.state().channel().client_key(),
            signing_hash(chunk_digest(
                authorization.channel_id,
                id,
                object,
                request.offset,
                &request.chunk,
                &exporter,
            )),
        ) {
            return Err(Refusal::invalid(
                "chunk signature does not bind these bytes to this connection",
            ));
        }
        self.close.store.gc_uploads()?;
        if self.prior_acceptance(&authorization, id)?.is_some() {
            let job = self
                .state()
                .job_by_id(id)
                .ok_or_else(|| Refusal::invalid("accepted input unavailable"))?;
            if ContentId::hash(job.prepared_input()) != object.id()
                || job.prepared_input().len() as u64 != object.bytes()
            {
                return Err(Refusal::invalid(
                    "object is outside the signed proposal's closure",
                ));
            }
            return Ok(object.bytes());
        }
        let ready = self
            .admitting()
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))?
            .clone();
        let policy = ready.work_policy();
        if object.bytes() > u64::from(policy.max_encoded_prepared_input()) {
            return Err(Refusal::invalid(
                "prepared input exceeds its encoded byte limit",
            ));
        }
        policy.check_authorization(
            ready.channel(),
            ready.payment_policy(),
            &authorization,
            self.state().cursor().0,
        )?;
        ready.check_signable(
            self.state().cursor().0,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        let next = self
            .close
            .store
            .uploads
            .stage(
                id,
                object,
                authorization.acceptance_deadline,
                policy.max_upload_bytes(),
                request.offset,
                &request.chunk,
            )
            .map_err(content_refusal)?;
        if next == object.bytes() {
            let bytes = self
                .close
                .store
                .uploads
                .read(id, object)
                .map_err(content_refusal)?;
            let result = PreparedWorkBundle::decode(&bytes, crate::content::MAX_CONTENT_BYTES)
                .map_err(|error| Refusal::invalid(error.to_string()))
                .and_then(|input| {
                    policy
                        .check_input(ready.channel(), &authorization, &input)
                        .map_err(Refusal::from)
                });
            if let Err(error) = result {
                self.close.store.uploads.clear().map_err(content_refusal)?;
                return Err(error);
            }
        }
        Ok(next)
    }
}
impl WorkService {
    pub async fn uploaded_content(&self) -> Result<hellas_store::ContentStore, EndpointError> {
        Ok(self.endpoint().await?.close.store.uploads.content_store())
    }
    pub async fn set_upload_quota(
        &self,
        quota: crate::content::UploadQuota,
    ) -> Result<(), EndpointError> {
        self.endpoint()
            .await?
            .close
            .store
            .uploads
            .set_quota(quota)
            .map_err(|_| EndpointError::NotAdmitting)
    }
    pub async fn upload(
        &self,
        request: &UploadContentRequest,
        context: &TransportContext,
    ) -> Result<UploadContentResponse, WireStatus> {
        let mut endpoint = self.endpoint().await.map_err(|error| {
            WireStatus::new(hellas_wire::WireCode::Unavailable, error.to_string())
        })?;
        endpoint
            .upload(request, context)
            .map(|next_offset| UploadContentResponse { next_offset })
            .map_err(|error| {
                WireStatus::new(
                    if error.code == WorkRefusal::Unavailable {
                        hellas_wire::WireCode::Unavailable
                    } else {
                        hellas_wire::WireCode::InvalidArgument
                    },
                    error.reason,
                )
            })
    }
}

pub(super) async fn send_proposal<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    request: AcceptWorkRequest,
) -> Result<Digest, ProposeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let exporter = transport
        .context()
        .open_exporter
        .ok_or(ProposeError::Malformed("upload connection exporter"))?;
    let reference = decode_reference(&request.prepared_input)
        .ok_or(ProposeError::Malformed("input reference"))?;
    let authorization = PaidJobAuthorizationV2::decode(&request.authorization)?;
    let id = {
        let client = endpoint.client().await?;
        work_id(client.state().channel(), &authorization)
    };
    let client = WorkClientImpl::new(transport);
    let mut offset = 0_u64;
    let mut probing = true;
    loop {
        let (chunk, chunk_signature) = {
            let endpoint = endpoint.client().await?;
            let bytes = endpoint
                .state()
                .job_by_id(id)
                .ok_or(ProposeError::NoOpenJob)?
                .prepared_input();
            let chunk = if probing {
                Vec::new()
            } else {
                bytes
                    .get(offset as usize..(offset as usize + CONTENT_CHUNK_BYTES).min(bytes.len()))
                    .ok_or(ProposeError::Malformed("upload offset"))?
                    .to_vec()
            };
            let signature = endpoint.signer.sign(signing_hash(chunk_digest(
                authorization.channel_id,
                id,
                reference,
                offset,
                &chunk,
                &exporter,
            )));
            (chunk, signature)
        };
        let end = offset + chunk.len() as u64;
        let uploaded = client
            .upload_content(UploadContentRequest {
                route: request.route.clone(),
                authorization: request.authorization.clone(),
                client_signature: request.client_signature.clone(),
                content_id: reference.id().as_bytes().to_vec(),
                total_bytes: reference.bytes(),
                offset,
                chunk,
                chunk_signature: chunk_signature.as_bytes().to_vec(),
            })
            .await?;
        if uploaded.next_offset > reference.bytes() || (!probing && uploaded.next_offset < end) {
            return Err(ProposeError::Malformed("upload offset"));
        }
        if uploaded.next_offset == reference.bytes() {
            break;
        }
        offset = uploaded.next_offset;
        probing = false;
    }
    let response = client.accept_work(request).await?;
    endpoint.client().await?.accepted(&response).await
}
