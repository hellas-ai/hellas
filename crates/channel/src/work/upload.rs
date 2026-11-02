use super::*;
use hellas_rpc::{
    pb::work::{UploadContentRequest, UploadContentResponse},
    protocol::content_upload::{CONTENT_CHUNK_BYTES, chunk_digest},
};
use std::collections::BTreeMap;

pub(super) fn content_refusal(error: crate::content::ContentError) -> Refusal {
    let code = match error {
        crate::content::ContentError::Storage(_) => WorkRefusal::Unavailable,
        crate::content::ContentError::ProposalLimit => WorkRefusal::Conflict,
        _ => WorkRefusal::Invalid,
    };
    Refusal::new(code, error.to_string())
}
fn upload_response(result: Result<u64, Refusal>) -> UploadContentResponse {
    match result {
        Ok(next_offset) => UploadContentResponse {
            next_offset,
            refused: None,
        },
        Err(error) => UploadContentResponse {
            next_offset: 0,
            refused: Some(WorkRefused {
                code: error.code.code() as i32,
                reason: error.reason,
                grant: None,
            }),
        },
    }
}

/// The signed fields shared by every probe and chunk of one proposal.
struct ProposalUpload {
    request: AcceptWorkRequest,
    authorization: PaidJobAuthorizationV2,
    id: Digest,
    manifest: Vec<u8>,
    program_root: Vec<u8>,
    exporter: [u8; 32],
}
impl ProposalUpload {
    async fn send_chunk<T>(
        &self,
        client: &WorkClientImpl<T>,
        endpoint: &mut impl ClientChannel,
        object: ContentRef,
        offset: u64,
        chunk: Vec<u8>,
    ) -> Result<u64, ProposeError>
    where
        T: StreamTransport + Sync,
        T::Error: std::error::Error + Send + Sync + 'static,
        T::Stream: 'static,
    {
        let signature = endpoint
            .client()
            .await?
            .signer
            .sign(signing_hash(chunk_digest(
                self.authorization.channel_id,
                self.id,
                object,
                offset,
                &chunk,
                &self.exporter,
            )));
        let end = offset + chunk.len() as u64;
        let probing = chunk.is_empty();
        let uploaded = client
            .upload_content(UploadContentRequest {
                route: self.request.route.clone(),
                authorization: self.request.authorization.clone(),
                client_signature: self.request.client_signature.clone(),
                program_manifest: self.manifest.clone(),
                program_root: self.program_root.clone(),
                content_id: object.id().as_bytes().to_vec(),
                total_bytes: object.bytes(),
                offset,
                chunk,
                chunk_signature: signature.as_bytes().to_vec(),
            })
            .await?;
        if let Some(refusal) = uploaded.refused {
            return match endpoint
                .client()
                .await?
                .accepted(&AcceptWorkResponse {
                    outcome: Some(Outcome::Refused(refusal)),
                })
                .await
            {
                Ok(_) => Err(ProposeError::Malformed("refusal answered as an acceptance")),
                Err(error) => Err(error),
            };
        }
        if uploaded.next_offset > object.bytes() || (!probing && uploaded.next_offset < end) {
            return Err(ProposeError::Malformed("upload offset"));
        }
        Ok(uploaded.next_offset)
    }
}
impl ProviderEndpoint {
    pub fn upload_content(
        &mut self,
        request: &UploadContentRequest,
        context: &TransportContext,
    ) -> Result<UploadContentResponse, WireStatus> {
        Ok(upload_response(self.upload(request, context)))
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
            let input = PreparedInvocation::from_canonical_bytes(
                job.prepared_input(),
                crate::content::MAX_CONTENT_BYTES,
            )
            .map_err(|e| Refusal::invalid(e.to_string()))?;
            let policy = hellas_rpc::protocol::invocation::InvocationPolicy::from_canonical_bytes(
                input.application_policy.as_bytes(),
            )
            .map_err(|e| Refusal::invalid(e.to_string()))?;
            let manifest = input
                .manifest()
                .map_err(|e| Refusal::invalid(e.to_string()))?;
            if request.program_manifest != manifest.canonical_bytes() {
                return Err(Refusal::invalid(
                    "manifest differs from accepted invocation",
                ));
            }
            let objects = crate::job::content_closure(
                &policy,
                &manifest,
                &request.program_root,
                authorization.input_content,
            )?;
            if !objects.contains(&object) {
                return Err(Refusal::invalid("object is outside the accepted closure"));
            }
            return Ok(object.bytes());
        }
        if self.state().close_prepared().is_some()
            || self.state().close_opened().is_some()
            || self.state().close_settled().is_some()
        {
            return Err(Refusal::new(WorkRefusal::Declined, "channel is closing"));
        }
        let ready = self
            .admitting()
            .map_err(|error| Refusal::new(endpoint_refusal(error), error.to_string()))?
            .clone();
        let policy = ready.invocation_policy();
        let preflight = (|| -> Result<Vec<ContentRef>, Refusal> {
            if request.program_manifest.len() > 4096 {
                return Err(Refusal::invalid("manifest exceeds metadata bound"));
            }
            let manifest =
                hellas_rpc::ProgramManifest::from_canonical_bytes(&request.program_manifest)
                    .map_err(|e| Refusal::invalid(e.to_string()))?;
            if manifest.content_id() != authorization.environment_commitment {
                return Err(Refusal::invalid("manifest differs from signed environment"));
            }
            let facts = policy
                .classify_manifest(&manifest)
                .map_err(|e| Refusal::invalid(e.to_string()))?;
            if authorization.retention != facts.retention
                || authorization.input_content.bytes() > u64::from(facts.max_encoded_prepared_input)
            {
                return Err(Refusal::invalid(
                    "input retention or length differs from admitted manifest",
                ));
            }
            crate::job::check_authorization(
                ready.channel(),
                &authorization,
                policy,
                ready.payment_policy(),
                self.state().cursor().0,
            )?;
            if request.program_root.len() > crate::content::MAX_PROGRAM_ROOT_BYTES {
                return Err(Refusal::invalid("program root exceeds metadata bound"));
            }
            let objects = crate::job::content_closure(
                policy,
                &manifest,
                &request.program_root,
                authorization.input_content,
            )?;
            if !objects.contains(&object) {
                return Err(Refusal::invalid(
                    "object is outside the signed proposal's closure",
                ));
            }
            Ok(objects)
        })();
        let objects = preflight?;
        ready.check_signable(
            self.state().cursor().0,
            authorization.terminal_deadline,
            authorization.payment_deadline,
        )?;
        self.close
            .store
            .uploads
            .declare_closure(
                id,
                &objects,
                authorization.acceptance_deadline,
                authorization.retention,
                policy.limits.max_upload_bytes,
            )
            .map_err(content_refusal)?;
        if !request.program_root.is_empty() {
            self.close
                .store
                .uploads
                .stage_complete(
                    id,
                    ContentRef::for_bytes(&request.program_root),
                    authorization.acceptance_deadline,
                    authorization.retention,
                    policy.limits.max_upload_bytes,
                    &request.program_root,
                )
                .map_err(content_refusal)?;
        }
        let next = self
            .close
            .store
            .uploads
            .stage(
                id,
                object,
                authorization.acceptance_deadline,
                authorization.retention,
                policy.limits.max_upload_bytes,
                request.offset,
                &request.chunk,
            )
            .map_err(content_refusal)?;
        if next == object.bytes() && object == authorization.input_content {
            let bytes = self
                .close
                .store
                .uploads
                .read(id, object, authorization.retention)
                .map_err(content_refusal)?;
            let result =
                PreparedInvocation::from_canonical_bytes(&bytes, crate::content::MAX_CONTENT_BYTES)
                    .map_err(|error| Refusal::invalid(error.to_string()))
                    .and_then(|input| {
                        crate::job::check_paid_input(
                            ready.channel(),
                            &authorization,
                            policy,
                            &input,
                        )
                        .map(|_| ())
                        .map_err(Refusal::from)
                    });
            if let Err(error) = result {
                self.close
                    .store
                    .uploads
                    .discard(id)
                    .map_err(content_refusal)?;
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
        Ok(upload_response(endpoint.upload(request, context)))
    }
}

pub(super) async fn send_proposal<T>(
    transport: T,
    endpoint: &mut impl ClientChannel,
    request: AcceptWorkRequest,
    content: &crate::content::InvocationContent,
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
    let (id, prepared_bytes) = {
        let client = endpoint.client().await?;
        let id = work_id(client.state().channel(), &authorization);
        let bytes = client
            .state()
            .job_by_id(id)
            .ok_or(ProposeError::NoOpenJob)?
            .prepared_input()
            .to_vec();
        (id, bytes)
    };
    let prepared = PreparedInvocation::from_canonical_bytes(
        &prepared_bytes,
        crate::content::MAX_CONTENT_BYTES,
    )
    .map_err(PaidWorkError::from)?;
    let manifest = prepared.manifest().map_err(PaidWorkError::from)?;
    let policy = hellas_rpc::protocol::invocation::InvocationPolicy::from_canonical_bytes(
        prepared.application_policy.as_bytes(),
    )
    .map_err(PaidWorkError::from)?;
    // The application decides whether an opening is needed; unrelated cached
    // objects must not change a self-contained program's upload.
    let program_root = if policy.content_closure(&manifest, &[]).is_ok() {
        Vec::new()
    } else {
        match content.read_bounded(
            manifest.root(),
            crate::content::MAX_PROGRAM_ROOT_BYTES as u64,
        ) {
            Ok(bytes) => bytes.as_ref().clone(),
            Err(crate::content::ContentError::Missing) => Vec::new(),
            Err(error) => return Err(error.into()),
        }
    };
    let objects = crate::job::content_closure(&policy, &manifest, &program_root, reference)?;
    let client = WorkClientImpl::new(transport);
    let upload = ProposalUpload {
        request,
        authorization,
        id,
        manifest: manifest.canonical_bytes(),
        program_root,
        exporter,
    };
    let mut offsets = BTreeMap::new();
    let retained_content = if upload.authorization.retention == hellas_rpc::Retention::Retain {
        let (target, previous) = {
            let endpoint = endpoint.client().await?;
            let previous = endpoint.store.uploads.retained_closure(id);
            if previous
                .as_ref()
                .is_some_and(|retained| retained.iter().any(|object| !objects.contains(object)))
            {
                return Err(ProposeError::Malformed(
                    "retained closure differs from proposal",
                ));
            }
            (endpoint.store.uploads.retention_target()?, previous)
        };
        if previous.is_some() {
            for object in &objects {
                let next = upload
                    .send_chunk(&client, endpoint, *object, 0, Vec::new())
                    .await?;
                offsets.insert(object.id(), next);
            }
            // A prior acceptance answers every probe as complete, even after
            // the provider's input content expires. Recover its co-signature
            // without rewriting a ticket or demanding local asset bytes.
            if objects
                .iter()
                .all(|object| offsets.get(&object.id()) == Some(&object.bytes()))
            {
                let response = client.accept_work(upload.request).await?;
                return endpoint.client().await?.accepted(&response).await;
            }
        }
        let root =
            (!upload.program_root.is_empty()).then(|| ContentRef::for_bytes(&upload.program_root));
        let mut seed = crate::content::EphemeralContent::default();
        seed.insert(prepared_bytes.clone());
        if root.is_some() {
            seed.insert(upload.program_root.clone());
        }
        let seed = crate::content::InvocationContent::Ephemeral(seed);
        target.retain(seed.clone(), reference).await?;
        let mut retained = vec![reference];
        if let Some(root) = root {
            target.retain(seed, root).await?;
            retained.push(root);
        }
        // Probe assets before reading them: model weights may exist only at
        // the provider. Keep the returned offsets for transmission, so each
        // object is probed once. Input/root are already retained locally and
        // can wait until transmission for their probes.
        for object in &objects {
            if *object == reference || Some(*object) == root {
                continue;
            }
            let next = match offsets.get(&object.id()) {
                Some(next) => *next,
                None => {
                    let next = upload
                        .send_chunk(&client, endpoint, *object, 0, Vec::new())
                        .await?;
                    offsets.insert(object.id(), next);
                    next
                }
            };
            if next < object.bytes() {
                target.retain(content.clone(), *object).await?;
                retained.push(*object);
            }
        }
        // Publish a complete recovery ticket before transmitting any body
        // chunks or asking for acceptance. A retry preserves the old ticket
        // until its replacement is durable.
        endpoint.client().await?.store.retain_closure(
            id,
            &retained,
            upload.authorization.terminal_deadline,
        )?;
        Some(target.content())
    } else {
        None
    };
    let source = retained_content.as_ref().unwrap_or(content);
    for object in objects {
        let mut offset = match offsets.remove(&object.id()) {
            Some(offset) => offset,
            None => {
                upload
                    .send_chunk(&client, endpoint, object, 0, Vec::new())
                    .await?
            }
        };
        while offset < object.bytes() {
            let chunk = if object == reference && retained_content.is_none() {
                let end = (offset as usize + CONTENT_CHUNK_BYTES).min(prepared_bytes.len());
                prepared_bytes
                    .get(offset as usize..end)
                    .ok_or(ProposeError::Malformed("upload offset"))?
                    .to_vec()
            } else {
                source.read_chunk(object, offset, CONTENT_CHUNK_BYTES)?
            };
            offset = upload
                .send_chunk(&client, endpoint, object, offset, chunk)
                .await?;
        }
    }
    let response = client.accept_work(upload.request).await?;
    endpoint.client().await?.accepted(&response).await
}
