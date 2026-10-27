//! Private grant sessions. The only clock is provider standing; no chain,
//! payment handshake, collateral, certificate or settlement is constructed.
use crate::node_control::profile::ClientProfile;
use crate::work_link::WorkLink;
use futures::{StreamExt, stream::BoxStream};
use hellas_auth::{
    Digest, ProducerSigningKey, PublicKey, Signature,
    authority::{GrantId, NodeKey, PrincipalId, UnixMillis},
};
use hellas_authority::model::grant::records::{
    check_grant_provider, grant_producer, grant_transport,
};
use hellas_client::ProviderTrustAnchor;
pub use hellas_client::{PinnedOffer, UnpinnedOffer};
use hellas_kernel::NetworkId;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::content_upload::{CONTENT_CHUNK_BYTES, chunk_digest, encode_reference},
};
use hellas_rpc::{
    EventCommitment, InputCommitment, Operation, OutputEventEnvelope, ProviderEnrollmentBundle,
    RequestCommitment, SchemeId, StreamId, output_genesis,
    pb::work::{
        AcceptWorkRequest, AcceptWorkResponse, GetStandingRequest, GetStandingResponse,
        GrantRefusalCode, GrantTerminalMetadata, GrantTerminalState, StreamResultRequest,
        WorkRefusalCode, WorkRefused, WorkRoute, WorkStreamEvent, accept_work_response,
        get_standing_response, work_stream_event,
    },
    scheme_id, verify_output_event_continuation,
};
use hellas_wire::StreamTransport as _;
use hellas_wire::iroh::IrohTransport;
use iroh::{Endpoint, EndpointId};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use {
    hellas_authority::grant_service::GrantService, hellas_authority::grant_service::GrantWork,
    hellas_authority::work_store::grant::GrantChannelState,
    hellas_authority::work_store::grant::GrantClientStore,
    hellas_authority::work_store::grant::NodeStoreError,
    hellas_authority::work_store::grant::SignedResult, hellas_channel::work::PaidProgress,
};
use {
    hellas_authority::model::grant::ChannelClient, hellas_authority::model::grant::ChannelId,
    hellas_authority::model::grant::GrantJobAuthorizationV1,
    hellas_authority::model::grant::grant_work_id,
    hellas_authority::model::grant::records::GrantError,
    hellas_authority::model::grant::records::GrantPolicy,
    hellas_authority::model::grant::records::SignedOffer,
    hellas_authority::model::grant::standing::Standing,
    hellas_authority::model::grant::standing::StandingLocator,
    hellas_channel::model::profile::PreparedWorkInput, hellas_channel::model::profile::WorkPolicy,
    hellas_channel::model::work::PaidJobResultV1, hellas_channel::model::work::PrivateRecord,
    hellas_channel::model::work::bound_result_digest,
    hellas_channel::model::work::decode_transcript, hellas_channel::model::work::encode_transcript,
};

#[derive(Debug, thiserror::Error)]
pub enum GrantClientError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Store(#[from] NodeStoreError),
    #[error("grant session is closed")]
    Closed,
    #[error(transparent)]
    Protocol(#[from] GrantProtocolError),
    #[error(transparent)]
    Client(#[from] hellas_client::ClientError),
    #[error(transparent)]
    Wire(#[from] hellas_wire::WireStatus),
    #[error(transparent)]
    Address(#[from] std::net::AddrParseError),
    #[error(transparent)]
    Work(#[from] hellas_channel::model::work::PaidWorkError),
    #[error(transparent)]
    Signature(#[from] hellas_auth::signature::SignatureError),
    #[error(transparent)]
    Length(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    UnknownEnum(#[from] prost::UnknownEnumValue),
    #[error(transparent)]
    FetchPayload(#[from] hellas_rpc::fetch::FetchPayloadError),
    #[error(transparent)]
    Progress(#[from] hellas_channel::work::BackendFault),
    #[error(transparent)]
    Canonical(#[from] hellas_rpc::protocol::value::CanonicalDecodeError),
    #[error(transparent)]
    TransportKey(#[from] iroh::KeyParsingError),
    #[error(transparent)]
    Stream(#[from] hellas_rpc::StreamVerifyError),
    #[error(transparent)]
    Evaluate(#[from] hellas_rpc::evaluate::EvaluateProtocolError),
    #[error("grant operation timed out; proposal recovery may be required")]
    Timeout,
    #[error("grant refused: {code:?} (current revision {current_revision})")]
    Refused {
        code: GrantRefusalCode,
        current_revision: u64,
        /// Provider-authenticated status, without a verifiable output transcript.
        terminal: Option<Box<GrantTerminalMetadata>>,
    },
    #[error("an earlier acceptance is unresolved; recover it before proposing more work")]
    RecoveryRequired,
    #[error("the acceptance deadline has not passed; lost request bodies cannot be retried yet")]
    RecoveryTooEarly,
}
#[derive(Debug, thiserror::Error)]
pub enum GrantProtocolError {
    #[error("missing standing outcome")]
    StandingOutcome,
    #[error("pending proposal missing")]
    PendingProposal,
    #[error("acceptance changed work id")]
    AcceptanceIdentity,
    #[error("missing acceptance outcome")]
    AcceptanceOutcome,
    #[error("input assurance differs from the pinned provider policy")]
    Assurance,
    #[error("result frame exceeds signed bound")]
    FrameBound,
    #[error("expected one terminal envelope")]
    TerminalCount,
    #[error("terminal transcript exceeds signed spool bound")]
    SpoolBound,
    #[error("event after terminal")]
    AfterTerminal,
    #[error("unexpected grant stream event")]
    StreamEvent,
    #[error("stream ended without result")]
    MissingResult,
    #[error("grant refusal omitted typed details")]
    RefusalDetails,
    #[error("unspecified grant refusal")]
    UnspecifiedRefusal,
    #[error("terminal metadata outside delivery")]
    UnexpectedTerminalMetadata,
    #[error("incoherent grant terminal metadata")]
    TerminalMetadata,
    #[error("terminal metadata belongs to another job")]
    TerminalIdentity,
    #[error("wrong prefix event kind")]
    PrefixKind,
    #[error("output exceeds its signed resource bounds")]
    OutputBound,
}

type Result<T> = std::result::Result<T, GrantClientError>;
#[derive(Clone)]
pub struct GrantTarget {
    pub network: NetworkId,
    pub provider: ProviderEnrollmentBundle,
    pub grant: GrantId,
    pub generation: u64,
    pub addresses: Vec<std::net::SocketAddr>,
}
impl GrantTarget {
    fn from_offer(offer: &PinnedOffer) -> Result<Self> {
        let offer = offer.offer();
        Ok(Self {
            network: offer.network,
            provider: offer.provider.clone(),
            grant: offer.grant.id,
            generation: offer.generation,
            addresses: offer
                .addresses
                .iter()
                .map(|a| a.parse().map_err(GrantClientError::from))
                .collect::<Result<_>>()?,
        })
    }
}
impl GrantTarget {
    fn resolve_transport(
        &self,
        transport: &GrantTransport,
        trust: &ProviderTrustAnchor,
        application: &Arc<ClientProfile>,
        signer: &Arc<ProducerSigningKey>,
    ) -> Result<SessionTransport> {
        trust
            .verify_enrollment(&self.provider)
            .map_err(GrantClientError::from)?;
        check_grant_provider(&self.provider)?;
        match transport {
            GrantTransport::Local(service) => Ok(SessionTransport::Local {
                service: service.clone(),
                application: application.clone(),
                signer: signer.clone(),
            }),
            GrantTransport::Remote(endpoint) => {
                let link = WorkLink::new(
                    EndpointId::from_bytes(&grant_transport(&self.provider)?)
                        .map_err(GrantClientError::from)?,
                    self.addresses.clone(),
                    endpoint.clone(),
                    trust.clone(),
                )
                .with_application(application.clone(), signer.clone());
                link.require_producer(self.provider.genesis.statement.producer_public_key)
                    .map_err(GrantClientError::from)?;
                Ok(SessionTransport::Remote(Box::new(link)))
            }
        }
    }
    /// Discover an allowance using an explicit application and pinned enrollment.
    /// Open authenticates the provider before the stable locator is disclosed.
    /// `client` is the principal the application credential acts for; `signer`
    /// is the node key that credential is bound to.
    pub async fn discover(
        &self,
        client: PrincipalId,
        signer: &ProducerSigningKey,
        transport: &GrantTransport,
        trust: &ProviderTrustAnchor,
        application: &Arc<ClientProfile>,
        timeout: Duration,
    ) -> Result<PinnedOffer> {
        let client = ChannelClient {
            principal: client,
            node: NodeKey::from_public_key(signer.public_key())
                .map_err(|_| GrantError::UnsupportedKey)?,
        };
        let transport =
            self.resolve_transport(transport, trust, application, &Arc::new(signer.clone()))?;
        let link = transport.connect(timeout, timeout).await?;
        let standing = GrantSession::query_standing(self, client, timeout, &link).await?;
        UnpinnedOffer::decode(&standing.offer.encode()?, standing.now)
            .and_then(|offer| offer.pin(trust))
            .map_err(GrantClientError::from)
    }
}
#[derive(Clone)]
pub struct GrantSessionOptions {
    pub target: PinnedOffer,
    /// The principal the application credential acts for.
    pub principal: PrincipalId,
    /// The node key the application credential is bound to; it signs every job.
    pub signer: Arc<ProducerSigningKey>,
    pub application: Arc<ClientProfile>,
    pub journal_root: PathBuf,
    /// Bounds each wait: standing, admission and the first delivered event
    /// together, then each later event. Signed job terms bound the total.
    pub timeout: Duration,
}
pub enum GrantTransport {
    Remote(Endpoint),
    Local(GrantService),
}
impl GrantTransport {
    pub async fn remote(
        key: iroh::SecretKey,
    ) -> std::result::Result<Self, iroh::endpoint::BindError> {
        Ok(Self::Remote(
            Endpoint::builder(iroh::endpoint::presets::N0)
                .secret_key(key)
                .bind()
                .await?,
        ))
    }
}

enum SessionTransport {
    Remote(Box<WorkLink>),
    Local {
        service: GrantService,
        application: Arc<ClientProfile>,
        signer: Arc<ProducerSigningKey>,
    },
    Closed,
}
impl SessionTransport {
    /// The remote session lasts at least `need` unless a fresh one cannot.
    async fn connect(&self, timeout: Duration, need: Duration) -> Result<Link> {
        match self {
            Self::Remote(link) => {
                let (transport, expires) = tokio::time::timeout(timeout, link.work_for(need))
                    .await
                    .map_err(|_| GrantClientError::Timeout)?
                    .map_err(GrantClientError::from)?;
                Ok(Link::Remote(transport, expires))
            }
            Self::Local {
                service,
                application,
                signer,
            } => {
                let caller = service
                    .node()
                    .authenticate_session(
                        &application.credential,
                        hellas_authority::node::SessionKey::Node(signer),
                    )
                    .await?;
                if caller.authority() != application.authority {
                    return Err(GrantError::Audience.into());
                }
                Ok(Link::Local(
                    service.for_caller(caller, application.authorization),
                    rand::random(),
                ))
            }
            Self::Closed => Err(GrantClientError::Closed),
        }
    }
}
enum Link {
    /// The host closes the connection, and cancels its work, when the
    /// authenticated session expires.
    Remote(IrohTransport, Option<tokio::time::Instant>),
    Local(GrantWork, [u8; 32]),
}
impl Link {
    fn expires(&self) -> Option<tokio::time::Instant> {
        match self {
            Self::Remote(_, expires) => *expires,
            Self::Local(_, _) => None,
        }
    }
    async fn standing(&self, request: GetStandingRequest) -> Result<GetStandingResponse> {
        match self {
            Self::Remote(t, _) => hellas_rpc::services::work::WorkClientImpl::new(
                IrohTransport::new(t.connection().clone()),
            )
            .get_standing(request)
            .await
            .map_err(GrantClientError::from),
            Self::Local(s, _) => Ok(s.standing(&request).await),
        }
    }
    async fn accept(
        &self,
        request: AcceptWorkRequest,
        work: Digest,
        input: Option<&[u8]>,
        signer: &ProducerSigningKey,
    ) -> Result<AcceptWorkResponse> {
        if let Some(bytes) = input {
            let reference = ContentRef::new(ContentId::hash(bytes), bytes.len() as u64);
            let exporter = match self {
                Self::Remote(transport, _) => transport
                    .context()
                    .open_exporter
                    .ok_or(GrantError::Signature)?,
                Self::Local(_, exporter) => *exporter,
            };
            let authorization = GrantJobAuthorizationV1::decode(&request.authorization)?;
            let mut offset = 0_u64;
            let mut probing = true;
            loop {
                let chunk = if probing {
                    Vec::new()
                } else {
                    bytes[offset as usize..(offset as usize + CONTENT_CHUNK_BYTES).min(bytes.len())]
                        .to_vec()
                };
                let end = offset + chunk.len() as u64;
                let signature = signer.sign_digest(chunk_digest(
                    authorization.channel_id.0,
                    work,
                    reference,
                    offset,
                    &chunk,
                    &exporter,
                ))?;
                let upload = hellas_rpc::pb::work::UploadContentRequest {
                    route: request.route.clone(),
                    authorization: request.authorization.clone(),
                    client_signature: request.client_signature.clone(),
                    content_id: reference.id().as_bytes().to_vec(),
                    total_bytes: reference.bytes(),
                    offset,
                    chunk,
                    chunk_signature: signature.bytes().to_vec(),
                };
                let response = match self {
                    Self::Remote(transport, _) => {
                        hellas_rpc::services::work::WorkClientImpl::new(IrohTransport::new(
                            transport.connection().clone(),
                        ))
                        .upload_content(upload)
                        .await?
                    }
                    Self::Local(service, _) => {
                        service
                            .upload(
                                &upload,
                                &hellas_wire::TransportContext {
                                    open_exporter: Some(exporter),
                                    ..Default::default()
                                },
                            )
                            .await?
                    }
                };
                if let Some(refusal) = response.refused {
                    return Ok(AcceptWorkResponse {
                        outcome: Some(accept_work_response::Outcome::Refused(refusal)),
                    });
                }
                if response.next_offset > reference.bytes()
                    || (!probing && response.next_offset < end)
                {
                    return Err(GrantError::Malformed.into());
                }
                if response.next_offset == reference.bytes() {
                    break;
                }
                offset = response.next_offset;
                probing = false;
            }
        }
        match self {
            Self::Remote(t, _) => hellas_rpc::services::work::WorkClientImpl::new(
                IrohTransport::new(t.connection().clone()),
            )
            .accept_work(request)
            .await
            .map_err(GrantClientError::from),
            Self::Local(s, _) => Ok(s.accept(&request).await),
        }
    }
    async fn stream(
        &self,
        request: StreamResultRequest,
    ) -> Result<BoxStream<'static, Result<WorkStreamEvent>>> {
        match self {
            Self::Remote(t, _) => {
                let mut stream = hellas_rpc::services::work::WorkClientImpl::new(
                    IrohTransport::new(t.connection().clone()),
                )
                .stream_result(request)
                .await
                .map_err(GrantClientError::from)?;
                Ok(Box::pin(async_stream::stream! {
                    while let Some(event) = stream.next().await { yield event.map_err(GrantClientError::from); }
                    if let Err(error) = stream.finish() { yield Err(GrantClientError::from(error)); }
                }))
            }
            Self::Local(s, _) => Ok(Box::pin(
                s.stream(request)
                    .map(|event| event.map_err(GrantClientError::from)),
            )),
        }
    }
}
pub struct GrantWorkResult {
    pub work_id: Digest,
    pub result: PaidJobResultV1,
    pub events: Vec<OutputEventEnvelope>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    None,
    Accepted(Digest),
    Refused(Digest),
}

pub struct GrantSession {
    options: GrantSessionOptions,
    transport: SessionTransport,
    target: GrantTarget,
    offer: SignedOffer,
    store: GrantClientStore,
    observed: UnixMillis,
    observed_at: Instant,
    pending_body: Option<(Digest, PreparedWorkInput)>,
}
impl GrantSession {
    pub async fn open(options: GrantSessionOptions, transport: GrantTransport) -> Result<Self> {
        if options.timeout.is_zero() {
            return Err(GrantError::Signature.into());
        }
        let client = ChannelClient {
            principal: options.principal,
            node: NodeKey::from_public_key(options.signer.public_key())
                .map_err(|_| GrantError::UnsupportedKey)?,
        };
        let target = GrantTarget::from_offer(&options.target)?;
        let transport = target.resolve_transport(
            &transport,
            options.target.trust(),
            &options.application,
            &options.signer,
        )?;
        let link = transport.connect(options.timeout, options.timeout).await?;
        let standing = Self::query_standing(&target, client, options.timeout, &link).await?;
        let offer = standing.offer;
        let channel = offer.offer().channel(client);
        let path = options.journal_root.join(hex::encode(channel.0.as_bytes()));
        let store = GrantClientStore::open(
            &path,
            target.network,
            target.provider.clone(),
            GrantChannelState {
                id: channel,
                grant: target.grant,
                generation: offer.offer().generation,
                client,
            },
            standing.now,
        )
        .await?;
        Ok(Self {
            options,
            transport,
            target,
            offer,
            store,
            observed: standing.now,
            observed_at: Instant::now(),
            pending_body: None,
        })
    }
    pub fn offer(&self) -> &SignedOffer {
        &self.offer
    }
    pub fn store(&self) -> &GrantClientStore {
        &self.store
    }
    fn now(&self) -> UnixMillis {
        UnixMillis(
            self.observed.0.saturating_add(
                self.observed_at
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64,
            ),
        )
        .max(self.store.now())
    }
    async fn link(&self) -> Result<Link> {
        self.transport
            .connect(self.options.timeout, self.options.timeout)
            .await
    }
    async fn query_standing(
        target: &GrantTarget,
        client: ChannelClient,
        timeout: Duration,
        link: &Link,
    ) -> Result<Standing> {
        let locator = StandingLocator {
            provider: target.provider.content_id(),
            grant: target.grant,
            client,
            generation: target.generation,
        };
        let request = GetStandingRequest {
            route: Some(WorkRoute::grant(locator.channel(target.network).0)),
            locator: locator.encode().to_vec(),
        };
        let response = tokio::time::timeout(timeout, link.standing(request))
            .await
            .map_err(|_| GrantClientError::Timeout)??;
        let bytes = match response.outcome {
            Some(get_standing_response::Outcome::Standing(bytes)) => bytes,
            Some(get_standing_response::Outcome::Refused(refusal)) => {
                return Err(refusal_error(&refusal, None)?);
            }
            None => return Err(GrantProtocolError::StandingOutcome.into()),
        };
        // Fresh TLS-bound status supplies the provider's monotone clock. The
        // client does not extend a grant by substituting its own wall clock.
        let standing = Standing::decode(&bytes, UnixMillis(0))?;
        let offer = standing.offer.offer();
        if offer.provider != target.provider
            || offer.network != target.network
            || offer.grant.id != target.grant
            || offer.generation < target.generation
            || offer.valid_until <= standing.now
        {
            return Err(GrantError::Audience.into());
        }
        Ok(standing)
    }
    pub async fn refresh(&mut self) -> Result<Standing> {
        let link = self.link().await?;
        let standing = Self::query_standing(
            &self.target,
            self.store.channel().client,
            self.options.timeout,
            &link,
        )
        .await?;
        if standing.offer.offer().channel(self.store.channel().client) != self.store.channel().id {
            return Err(GrantError::Generation.into());
        }
        if standing.offer.offer().grant.revision < self.offer.offer().grant.revision {
            return Err(GrantError::Revision(self.offer.offer().grant.revision).into());
        }
        self.observed = standing.now.max(self.store.now());
        self.observed_at = Instant::now();
        self.offer = standing.offer.clone();
        self.store.tick(self.now()).await?;
        Ok(standing)
    }
    /// Resolve only the existing proposal, without executing a replacement.
    /// When the body was lost, an accepted proof reports Accepted with no output.
    pub async fn recover(&mut self) -> Result<Recovery> {
        let Some(id) = self.store.book().pending_proposal() else {
            return Ok(Recovery::None);
        };
        let job = self
            .store
            .book()
            .job_by_id(id)
            .ok_or(GrantProtocolError::PendingProposal)?;
        let a = *job.authorization();
        let signature = job.client_signature();
        let prepared = self
            .pending_body
            .as_ref()
            .filter(|(work, _)| *work == id)
            .map(|(_, body)| body.encode().map_err(GrantClientError::from))
            .transpose()?;
        let probe = prepared.is_none();
        if probe {
            self.refresh().await?;
            if self.now() <= a.acceptance_deadline_ms {
                return Err(GrantClientError::RecoveryTooEarly);
            }
        }
        let request = AcceptWorkRequest {
            route: Some(WorkRoute::grant(a.channel_id.0)),
            authorization: a.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: prepared
                .as_ref()
                .map(|bytes| {
                    encode_reference(ContentRef::new(ContentId::hash(bytes), bytes.len() as u64))
                })
                .unwrap_or_default(),
        };
        let link = self.link().await?;
        let response = tokio::time::timeout(
            self.options.timeout,
            link.accept(request, id, prepared.as_deref(), &self.options.signer),
        )
        .await
        .map_err(|_| GrantClientError::Timeout)??;
        match self.apply_acceptance(id, response, probe).await {
            Ok(()) => Ok(Recovery::Accepted(id)),
            Err(error @ GrantClientError::Refused { .. }) => {
                if self.store.book().pending_proposal().is_none() {
                    Ok(Recovery::Refused(id))
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
    async fn apply_acceptance(
        &mut self,
        id: Digest,
        response: AcceptWorkResponse,
        probe: bool,
    ) -> Result<()> {
        match response.outcome {
            Some(accept_work_response::Outcome::Accepted(accepted)) => {
                if accepted.work_id != id.as_bytes() {
                    return Err(GrantProtocolError::AcceptanceIdentity.into());
                }
                let signature = Signature::Secp256k1(
                    accepted
                        .provider_signature
                        .as_slice()
                        .try_into()
                        .map_err(GrantClientError::from)?,
                );
                self.store.accepted(id, signature, self.now()).await?;
                self.pending_body = None;
                Ok(())
            }
            Some(accept_work_response::Outcome::Refused(refusal)) => {
                let error = refusal_error(&refusal, None)?;
                let conclusive = matches!(
                    WorkRefusalCode::try_from(refusal.code),
                    Ok(WorkRefusalCode::Invalid
                        | WorkRefusalCode::Expired
                        | WorkRefusalCode::Declined)
                );
                let malformed_probe = probe
                    && matches!(
                        error,
                        GrantClientError::Refused {
                            code: GrantRefusalCode::Malformed,
                            ..
                        }
                    );
                if conclusive && !malformed_probe {
                    self.store.refused(id, self.now()).await?;
                    self.pending_body = None;
                }
                Err(error)
            }
            None => Err(GrantProtocolError::AcceptanceOutcome.into()),
        }
    }
    pub async fn run(
        &mut self,
        policy_name: &str,
        input: PreparedWorkInput,
        progress: Option<PaidProgress>,
    ) -> Result<GrantWorkResult> {
        self.run_before(
            policy_name,
            input,
            progress,
            tokio::time::Instant::now() + self.options.timeout,
        )
        .await
    }

    /// `deadline` bounds standing, acceptance and the first delivered event.
    /// Later events must each arrive within the session timeout, and the whole
    /// delivery within the signed terminal deadline, which the job may use up
    /// to the allowance's `max_job_millis`. Cancellation preserves any signed
    /// proposal in the journal.
    pub async fn run_before(
        &mut self,
        policy_name: &str,
        input: PreparedWorkInput,
        progress: Option<PaidProgress>,
        deadline: tokio::time::Instant,
    ) -> Result<GrantWorkResult> {
        if deadline <= tokio::time::Instant::now() {
            return Err(GrantClientError::Timeout);
        }
        let (policy, id, mut stream, finish_by) =
            tokio::time::timeout_at(deadline, self.admit(policy_name, &input))
                .await
                .map_err(|_| GrantClientError::Timeout)??;
        let channel = self.store.channel().id;
        let idle = self.options.timeout;
        let mut prefixes =
            Prefixes::new(&policy.work, &input, grant_producer(&self.target.provider)?)?;
        let signed = tokio::time::timeout_at(finish_by, async {
            let mut next_by = deadline;
            while let Some(event) = tokio::time::timeout_at(next_by, stream.next())
                .await
                .map_err(|_| GrantClientError::Timeout)?
            {
                next_by = tokio::time::Instant::now() + idle;
                let event = event?;
                use prost::Message;
                if event.encoded_len() as u64 > u64::from(policy.work.max_encoded_result_frame()) {
                    return Err(GrantProtocolError::FrameBound.into());
                }
                match event.outcome {
                    Some(work_stream_event::Outcome::Prefix(bytes)) => {
                        for event in decode_transcript(
                            &bytes,
                            hellas_channel::work_store::journal::MAX_RECORD_BYTES,
                        )
                        .map_err(GrantClientError::from)?
                        {
                            prefixes.push(event.clone())?;
                            if let Some(progress) = &progress {
                                progress(event).map_err(GrantClientError::from)?;
                            }
                        }
                    }
                    Some(work_stream_event::Outcome::Terminal(terminal)) => {
                        let tail = decode_transcript(
                            &terminal.terminal_transcript,
                            hellas_channel::work_store::journal::MAX_RECORD_BYTES,
                        )
                        .map_err(GrantClientError::from)?;
                        if tail.len() != 1 {
                            return Err(GrantProtocolError::TerminalCount.into());
                        }
                        prefixes.events.extend(tail);
                        if encode_transcript(&prefixes.events)
                            .map_err(GrantClientError::from)?
                            .len() as u64
                            > policy.work.max_spool_bytes()
                        {
                            return Err(GrantProtocolError::SpoolBound.into());
                        }
                        let signed = SignedResult {
                            result: PaidJobResultV1::decode(&terminal.result)
                                .map_err(GrantClientError::from)?,
                            signature: Signature::Secp256k1(
                                terminal
                                    .provider_signature
                                    .as_slice()
                                    .try_into()
                                    .map_err(GrantClientError::from)?,
                            ),
                        };
                        if tokio::time::timeout_at(next_by, stream.next())
                            .await
                            .map_err(|_| GrantClientError::Timeout)?
                            .transpose()?
                            .is_some()
                        {
                            return Err(GrantProtocolError::AfterTerminal.into());
                        }
                        return Ok(signed);
                    }
                    Some(work_stream_event::Outcome::Refused(refusal)) => {
                        return Err(refusal_error(&refusal, Some((&self.target, channel, id)))?);
                    }
                    _ => return Err(GrantProtocolError::StreamEvent.into()),
                }
            }
            Err(GrantProtocolError::MissingResult.into())
        })
        .await
        .map_err(|_| GrantClientError::Timeout)??;
        self.store
            .complete(
                id,
                &policy.work,
                &input,
                &prefixes.events,
                signed.clone(),
                self.now(),
            )
            .await?;
        Ok(GrantWorkResult {
            work_id: id,
            result: signed.result,
            events: prefixes.events,
        })
    }

    /// Propose, have accepted and open delivery. The returned instant bounds
    /// the delivery by the signed terminal deadline plus one idle period for
    /// the provider to report the terminal state.
    async fn admit(
        &mut self,
        policy_name: &str,
        input: &PreparedWorkInput,
    ) -> Result<(
        GrantPolicy,
        Digest,
        BoxStream<'static, Result<WorkStreamEvent>>,
        tokio::time::Instant,
    )> {
        if self.store.book().pending_proposal().is_some() {
            return Err(GrantClientError::RecoveryRequired);
        }
        if input.assurance().map_err(GrantClientError::from)?
            != self.options.target.trust().required_assurance
        {
            return Err(GrantProtocolError::Assurance.into());
        }
        let standing = self.refresh().await?;
        let policy = self
            .offer
            .offer()
            .grant
            .policies
            .iter()
            .find(|p| p.name == policy_name)
            .ok_or(GrantError::OutOfScope)?
            .clone();
        self.options
            .target
            .trust()
            .verify_environment(policy.work.allowed_environment())?;
        let now = self.now();
        // The provider clock has advanced at least as far as this standing, so
        // measuring the signed limit from it never exceeds the allowance.
        let terminal = standing
            .now
            .0
            .checked_add(self.offer.offer().grant.max_job_millis.get())
            .ok_or(GrantError::Malformed)?;
        let idle = self.options.timeout;
        let link = self
            .transport
            .connect(
                idle,
                Duration::from_millis(terminal.saturating_sub(now.0)) + idle,
            )
            .await?;
        // Work must end, and report its terminal state, before the session
        // that delivers it expires; the host would cancel it at that instant.
        let terminal = link.expires().map_or(terminal, |expires| {
            let carried = expires
                .saturating_duration_since(tokio::time::Instant::now())
                .saturating_sub(idle)
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
            terminal.min(now.0.saturating_add(carried))
        });
        let span = terminal.saturating_sub(now.0);
        if span == 0 {
            return Err(GrantError::Expired.into());
        }
        let finish_by =
            tokio::time::Instant::now() + Duration::from_millis(span) + self.options.timeout;
        let channel = self.store.channel().id;
        let prepared = input.encode().map_err(GrantClientError::from)?;
        let a = GrantJobAuthorizationV1 {
            channel_id: channel,
            generation: self.store.channel().generation,
            grant_id: self.target.grant,
            grant_revision: self.offer.offer().grant.revision,
            resource_id: policy.resource,
            resource_revision: policy.revision,
            pricing_revision: policy.pricing.revision,
            work_policy_digest: policy.work.digest(self.target.network, channel.0),
            input_content: hellas_rpc::ContentRef::for_bytes(&prepared),
            prepared_input_digest: input
                .bound_digest(self.target.network, channel.0)
                .map_err(GrantClientError::from)?,
            proposal_nonce: self.store.next_nonce()?,
            acceptance_deadline_ms: UnixMillis(now.0 + (span / 2).min(30_000)),
            request_commitment: RequestCommitment::from_digest(
                input
                    .input_commitment()
                    .map_err(GrantClientError::from)?
                    .digest(),
            ),
            environment_commitment: policy.work.allowed_environment(),
            terminal_deadline_ms: UnixMillis(terminal),
            delivery_deadline_ms: UnixMillis(
                terminal.checked_add(300_000).ok_or(GrantError::Malformed)?,
            ),
        };
        let signature = self
            .store
            .propose(&self.offer, a, input, &self.options.signer, now)
            .await?;
        let id = grant_work_id(self.target.network, &a);
        self.pending_body = Some((id, input.clone()));

        let request = AcceptWorkRequest {
            route: Some(WorkRoute::grant(channel.0)),
            authorization: a.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: encode_reference(ContentRef::new(
                ContentId::hash(&prepared),
                prepared.len() as u64,
            )),
        };
        let response = tokio::time::timeout(
            self.options.timeout,
            link.accept(request, id, Some(&prepared), &self.options.signer),
        )
        .await
        .map_err(|_| GrantClientError::Timeout)??;
        self.apply_acceptance(id, response, false).await?;
        let delivery = StreamResultRequest {
            route: Some(WorkRoute::grant(channel.0)),
            work_id: id.as_bytes().to_vec(),
            client_signature: Vec::new(),
        };
        let stream = tokio::time::timeout(self.options.timeout, link.stream(delivery))
            .await
            .map_err(|_| GrantClientError::Timeout)??;
        Ok((policy, id, stream, finish_by))
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        let recovered = if self.store.book().pending_proposal().is_some() {
            self.recover().await.map(|_| ())
        } else {
            Ok(())
        };
        let drained = if let SessionTransport::Local { service, .. } = &self.transport {
            service.drain().await.map_err(GrantClientError::from)
        } else {
            Ok(())
        };
        self.transport = SessionTransport::Closed;
        drained.and(recovered)
    }
}
fn refusal_error(
    refusal: &WorkRefused,
    delivery: Option<(&GrantTarget, ChannelId, Digest)>,
) -> Result<GrantClientError> {
    let detail = refusal
        .grant
        .as_ref()
        .ok_or(GrantProtocolError::RefusalDetails)?;
    let code = GrantRefusalCode::try_from(detail.code).map_err(GrantClientError::from)?;
    if code == GrantRefusalCode::Unspecified {
        return Err(GrantProtocolError::UnspecifiedRefusal.into());
    }
    if let Some(terminal) = &detail.terminal {
        let (target, channel, id) =
            delivery.ok_or(GrantProtocolError::UnexpectedTerminalMetadata)?;
        let state = GrantTerminalState::try_from(terminal.state).map_err(GrantClientError::from)?;
        let coherent = match state {
            GrantTerminalState::Finished => {
                code == GrantRefusalCode::OutputUnavailable && !terminal.result.is_empty()
            }
            GrantTerminalState::Failed => code == GrantRefusalCode::Indeterminate,
            GrantTerminalState::Released => {
                code == GrantRefusalCode::Released && terminal.result.is_empty()
            }
            GrantTerminalState::Indeterminate => {
                code == GrantRefusalCode::Indeterminate && terminal.result.is_empty()
            }
            GrantTerminalState::Unspecified => false,
        };
        if !coherent
            || terminal.work_id != id.as_bytes()
            || terminal.result.is_empty() != terminal.provider_signature.is_empty()
        {
            return Err(GrantProtocolError::TerminalMetadata.into());
        }
        if !terminal.result.is_empty() {
            let result =
                PaidJobResultV1::decode(&terminal.result).map_err(GrantClientError::from)?;
            if result.work_id != id {
                return Err(GrantProtocolError::TerminalIdentity.into());
            }
            let signature = Signature::Secp256k1(
                terminal
                    .provider_signature
                    .as_slice()
                    .try_into()
                    .map_err(GrantClientError::from)?,
            );
            hellas_auth::signature::verify_digest_signature(
                &PublicKey::Secp256k1(grant_producer(&target.provider)?.to_bytes()),
                &signature,
                bound_result_digest(target.network, channel.0, &result),
            )
            .map_err(GrantClientError::from)?;
        }
    }
    Ok(GrantClientError::Refused {
        code,
        current_revision: detail.current_revision,
        terminal: detail.terminal.clone(),
    })
}
struct Prefixes {
    events: Vec<OutputEventEnvelope>,
    input: InputCommitment,
    key: PublicKey,
    scheme: SchemeId,
    previous: EventCommitment,
    kind: &'static str,
    tokens: u64,
    bytes: usize,
    payload: u64,
    max_tokens: u64,
    max_events: u64,
    max_payload: u64,
    max_spool: u64,
}
impl Prefixes {
    fn new(
        policy: &WorkPolicy,
        input: &PreparedWorkInput,
        producer: hellas_kernel::Key,
    ) -> Result<Self> {
        let (operation, kind, max_tokens, max_events, max_payload) = match (policy, input) {
            (WorkPolicy::Evaluate(_), PreparedWorkInput::Evaluate(input)) => (
                Operation::Evaluate,
                hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND,
                u64::from(
                    input
                        .parts()
                        .map_err(GrantClientError::from)?
                        .text_policy
                        .max_new_tokens(),
                ),
                u64::MAX,
                u64::MAX,
            ),
            (WorkPolicy::Fetch { policy, .. }, PreparedWorkInput::Fetch(_)) => (
                Operation::Fetch,
                hellas_rpc::fetch::OUTPUT_EVENT_KIND,
                0,
                u64::from(policy.max_output_events),
                u64::from(policy.max_output_bytes),
            ),
            _ => return Err(GrantError::OutOfScope.into()),
        };
        let commitment = input.input_commitment().map_err(GrantClientError::from)?;
        Ok(Self {
            events: vec![],
            input: commitment,
            key: PublicKey::Secp256k1(producer.to_bytes()),
            scheme: scheme_id(
                operation,
                input.assurance().map_err(GrantClientError::from)?,
            ),
            previous: output_genesis(commitment, StreamId::from_input_commitment(commitment)),
            kind,
            tokens: 0,
            bytes: 0,
            payload: 0,
            max_tokens,
            max_events,
            max_payload,
            max_spool: policy.max_spool_bytes(),
        })
    }
    fn push(&mut self, event: OutputEventEnvelope) -> Result<()> {
        self.previous = verify_output_event_continuation(
            self.scheme,
            self.input,
            &self.key,
            self.events.len() as u64,
            self.previous,
            &event,
        )
        .map_err(GrantClientError::from)?;
        if event.event().body().kind() != self.kind {
            return Err(GrantProtocolError::PrefixKind.into());
        }
        if self.kind == hellas_rpc::evaluate::TOKEN_DELTA_EVENT_KIND {
            self.tokens = self.tokens.saturating_add(
                hellas_rpc::evaluate::decode_token_delta_payload(event.payload())
                    .map_err(GrantClientError::from)?
                    .token_ids
                    .len() as u64,
            );
        } else {
            hellas_rpc::fetch::decode_fetch_event_payload(event.payload())
                .map_err(GrantClientError::from)?;
        }
        self.bytes = self
            .bytes
            .saturating_add(event.payload().len().saturating_mul(2).saturating_add(1024));
        self.payload = self.payload.saturating_add(event.payload().len() as u64);
        if self.tokens > self.max_tokens
            || self.events.len() as u64 + 1 >= self.max_events
            || self.payload > self.max_payload
            || self.bytes as u64 > self.max_spool
        {
            return Err(GrantProtocolError::OutputBound.into());
        }
        self.events.push(event);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
