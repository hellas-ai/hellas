//! Private grant sessions. The only clock is provider standing; no chain,
//! payment handshake, collateral, certificate or settlement is constructed.
use crate::work_link::WorkLink;
use futures::{StreamExt, stream::BoxStream};
use hellas_client::ProviderTrustAnchor;
pub use hellas_client::{PinnedOffer, UnpinnedOffer};
use hellas_kernel::NetworkId;
use hellas_rpc::{
    Digest, EventCommitment, InputCommitment, Operation, OutputEventEnvelope, ProducerSigningKey,
    ProviderEnrollmentBundle, PublicKey, RequestCommitment, SchemeId, Signature, StreamId,
    output_genesis,
    pb::work::{
        AcceptWorkRequest, AcceptWorkResponse, DeliverResultRequest, GetStandingRequest,
        GetStandingResponse, GrantRefusalCode, GrantTerminalMetadata, GrantTerminalState,
        WorkRefusalCode, WorkRefused, WorkRoute, WorkStreamEvent, accept_work_response,
        get_standing_response, work_stream_event,
    },
    protocol::{
        work::{
            PaidJobResultV1, PrivateRecord, bound_delivery_request_digest, bound_result_digest,
            decode_transcript, encode_transcript,
        },
        work_grant::{
            ChannelId, GrantId, GrantJobAuthorizationV1, Revision, UnixMillis, grant_work_id,
            records::{GrantError, Principal, SignedOffer},
            standing::{Standing, StandingLocator},
        },
        work_profile::{PreparedWorkInput, WorkPolicy},
    },
    scheme_id, verify_output_event_continuation,
};
use hellas_wire::{
    AuthLevel, PeerIdentity, StreamTransport, TransportContext, iroh::IrohTransport,
};
use hellas_work::{
    grant_service::GrantService,
    work::PaidProgress,
    work_store::grant::{GrantChannelState, GrantClientStore, GrantStoreError, SignedResult},
};
use iroh::{Endpoint, EndpointId};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
pub enum GrantClientError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Store(#[from] GrantStoreError),
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
    Work(#[from] hellas_rpc::protocol::work::PaidWorkError),
    #[error(transparent)]
    Signature(#[from] hellas_rpc::protocol::signature::SignatureError),
    #[error(transparent)]
    Length(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    UnknownEnum(#[from] prost::UnknownEnumValue),
    #[error(transparent)]
    FetchPayload(#[from] hellas_rpc::fetch::FetchPayloadError),
    #[error(transparent)]
    Progress(#[from] hellas_work::work::BackendFault),
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
        client: &Principal,
    ) -> Result<SessionTransport> {
        trust
            .verify_enrollment(&self.provider)
            .map_err(GrantClientError::from)?;
        self.provider.check_grant_provider()?;
        match transport {
            GrantTransport::Local(service) => Ok(SessionTransport::Local {
                service: service.clone(),
                context: TransportContext {
                    peer: Some(PeerIdentity(client.transport())),
                    auth_level: AuthLevel::Vouched,
                    // Local invocation has no TLS exporter; a fresh random
                    // binding separates this trusted in-process session.
                    open_exporter: Some(rand::random()),
                    rtt_ms: None,
                },
            }),
            GrantTransport::Remote(endpoint) => {
                let link = WorkLink::new(
                    EndpointId::from_bytes(&self.provider.grant_transport()?)
                        .map_err(GrantClientError::from)?,
                    self.addresses.clone(),
                    endpoint.clone(),
                    trust.clone(),
                );
                link.require_producer(self.provider.genesis.statement.producer_public_key)
                    .map_err(GrantClientError::from)?;
                Ok(SessionTransport::Remote(Box::new(link)))
            }
        }
    }
    /// Read-only owner bootstrap from an already management-pinned enrollment.
    /// Open authenticates the provider before the stable locator is disclosed.
    pub async fn discover(
        &self,
        client: &Principal,
        signer: &ProducerSigningKey,
        transport: &GrantTransport,
        trust: &ProviderTrustAnchor,
        timeout: Duration,
    ) -> Result<PinnedOffer> {
        if signer.public_key() != PublicKey::Secp256k1(client.producer().to_bytes())
            || matches!(transport, GrantTransport::Remote(e) if e.id().as_bytes() != &client.transport())
        {
            return Err(GrantError::Audience.into());
        }
        let transport = self.resolve_transport(transport, trust, client)?;
        let link = transport.connect(timeout).await?;
        let standing = GrantSession::query_standing(self, client, signer, timeout, &link).await?;
        UnpinnedOffer::decode(&standing.offer.encode()?, client.id(), standing.now)
            .and_then(|offer| offer.pin(trust))
            .map_err(GrantClientError::from)
    }
}
pub struct GrantSessionOptions {
    pub target: PinnedOffer,
    pub client: Principal,
    pub signer: Arc<ProducerSigningKey>,
    pub journal_root: PathBuf,
    pub timeout: Duration,
}
pub enum GrantTransport {
    Remote(Endpoint),
    Local(GrantService),
}
enum SessionTransport {
    Remote(Box<WorkLink>),
    Local {
        service: GrantService,
        context: TransportContext,
    },
    Closed,
}
impl SessionTransport {
    async fn connect(&self, timeout: Duration) -> Result<Link> {
        match self {
            Self::Remote(link) => Ok(Link::Remote(
                tokio::time::timeout(timeout, link.work())
                    .await
                    .map_err(|_| GrantClientError::Timeout)?
                    .map_err(GrantClientError::from)?,
            )),
            Self::Local { service, context } => Ok(Link::Local(service.clone(), context.clone())),
            Self::Closed => Err(GrantClientError::Closed),
        }
    }
}
enum Link {
    Remote(IrohTransport),
    Local(GrantService, TransportContext),
}
impl Link {
    fn exporter(&self) -> Result<[u8; 32]> {
        let exporter = match self {
            Self::Remote(t) => t.context().open_exporter,
            Self::Local(_, c) => c.open_exporter,
        };
        exporter.ok_or(GrantError::Unauthorized.into())
    }
    async fn standing(&self, request: GetStandingRequest) -> Result<GetStandingResponse> {
        match self {
            Self::Remote(t) => hellas_rpc::services::work::WorkClientImpl::new(IrohTransport::new(
                t.connection().clone(),
            ))
            .get_standing(request)
            .await
            .map_err(GrantClientError::from),
            Self::Local(s, c) => Ok(s.standing(&request, c)),
        }
    }
    async fn accept(&self, request: AcceptWorkRequest) -> Result<AcceptWorkResponse> {
        match self {
            Self::Remote(t) => hellas_rpc::services::work::WorkClientImpl::new(IrohTransport::new(
                t.connection().clone(),
            ))
            .accept_work(request)
            .await
            .map_err(GrantClientError::from),
            Self::Local(s, c) => Ok(s.accept(&request, c)),
        }
    }
    async fn stream(
        &self,
        request: DeliverResultRequest,
    ) -> Result<BoxStream<'static, Result<WorkStreamEvent>>> {
        match self {
            Self::Remote(t) => {
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
            Self::Local(s, c) => Ok(Box::pin(
                s.stream(request, c.clone())
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
        if options.timeout.is_zero()
            || options.signer.public_key()
                != PublicKey::Secp256k1(options.client.producer().to_bytes())
        {
            return Err(GrantError::Signature.into());
        }
        if let GrantTransport::Remote(endpoint) = &transport
            && endpoint.id().as_bytes() != &options.client.transport()
        {
            return Err(GrantError::Audience.into());
        }
        let target = GrantTarget::from_offer(&options.target)?;
        let transport =
            target.resolve_transport(&transport, options.target.trust(), &options.client)?;
        let link = transport.connect(options.timeout).await?;
        let standing = Self::query_standing(
            &target,
            &options.client,
            &options.signer,
            options.timeout,
            &link,
        )
        .await?;
        let offer = standing.offer;
        let channel = offer.offer().channel();
        let path = options.journal_root.join(hex::encode(channel.0.as_bytes()));
        let store = GrantClientStore::open(
            &path,
            target.network,
            target.provider.clone(),
            GrantChannelState {
                id: channel,
                grant: target.grant,
                generation: offer.offer().generation,
                client: options.client.clone(),
            },
            standing.now,
        )?;
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
        self.transport.connect(self.options.timeout).await
    }
    async fn query_standing(
        target: &GrantTarget,
        client: &Principal,
        signer: &ProducerSigningKey,
        timeout: Duration,
        link: &Link,
    ) -> Result<Standing> {
        let locator = StandingLocator {
            provider: target.provider.content_id(),
            grant: target.grant,
            client: client.id(),
            generation: target.generation,
        };
        let signature = signer
            .sign_digest(locator.digest(target.network, &link.exporter()?))
            .map_err(GrantClientError::from)?;
        let request = GetStandingRequest {
            route: Some(WorkRoute::grant(locator.channel(target.network))),
            locator: locator.encode().to_vec(),
            client_signature: signature.bytes().to_vec(),
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
        let standing = Standing::decode(&bytes, client.id(), UnixMillis(0))?;
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
            &self.options.client,
            &self.options.signer,
            self.options.timeout,
            &link,
        )
        .await?;
        if standing.offer.offer().channel() != self.store.channel().id {
            return Err(GrantError::Generation.into());
        }
        if standing.offer.offer().grant.revision < self.offer.offer().grant.revision {
            return Err(GrantError::Revision(self.offer.offer().grant.revision).into());
        }
        self.observed = standing.now.max(self.store.now());
        self.observed_at = Instant::now();
        self.offer = standing.offer.clone();
        self.store.tick(self.now())?;
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
            route: Some(WorkRoute::grant(a.channel_id)),
            authorization: a.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: prepared.unwrap_or_default(),
        };
        let link = self.link().await?;
        let response = tokio::time::timeout(self.options.timeout, link.accept(request))
            .await
            .map_err(|_| GrantClientError::Timeout)??;
        match self.apply_acceptance(id, response, probe) {
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
    fn apply_acceptance(
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
                self.store.accepted(id, signature, self.now())?;
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
                    self.store.refused(id, self.now())?;
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

    /// One absolute client budget includes queueing, standing, acceptance and
    /// delivery. Cancellation preserves any signed proposal in the journal.
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
        tokio::time::timeout_at(
            deadline,
            self.run_inner(policy_name, input, progress, deadline),
        )
        .await
        .map_err(|_| GrantClientError::Timeout)?
    }

    async fn run_inner(
        &mut self,
        policy_name: &str,
        input: PreparedWorkInput,
        progress: Option<PaidProgress>,
        deadline: tokio::time::Instant,
    ) -> Result<GrantWorkResult> {
        if self.store.book().pending_proposal().is_some() {
            return Err(GrantClientError::RecoveryRequired);
        }
        if input.assurance().map_err(GrantClientError::from)?
            != self.options.target.trust().required_assurance
        {
            return Err(GrantProtocolError::Assurance.into());
        }
        self.refresh().await?;
        let policy = self
            .offer
            .offer()
            .grant
            .policies
            .iter()
            .find(|p| p.name == policy_name)
            .ok_or(GrantError::OutOfScope)?
            .clone();
        let now = self.now();
        let span = self.offer.offer().grant.max_job_millis.get().min(
            deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        );
        if span == 0 {
            return Err(GrantError::Expired.into());
        }
        let channel = self.store.channel().id;
        let terminal = now.0.checked_add(span).ok_or(GrantError::Malformed)?;
        let a = GrantJobAuthorizationV1 {
            channel_id: channel,
            grant_id: self.target.grant,
            grant_revision: self.offer.offer().grant.revision,
            catalogue_revision: Revision(0),
            work_policy_digest: policy.work.digest(self.target.network, channel.0),
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
            .propose(&self.offer, a, &input, &self.options.signer, now)?;
        let id = grant_work_id(self.target.network, &a);
        self.pending_body = Some((id, input.clone()));
        let request = AcceptWorkRequest {
            route: Some(WorkRoute::grant(channel)),
            authorization: a.encode(),
            client_signature: signature.bytes().to_vec(),
            prepared_input: input.encode().map_err(GrantClientError::from)?,
        };
        let link = self.link().await?;
        let response = tokio::time::timeout(self.options.timeout, link.accept(request))
            .await
            .map_err(|_| GrantClientError::Timeout)??;
        self.apply_acceptance(id, response, false)?;
        let delivery = DeliverResultRequest {
            route: Some(WorkRoute::grant(channel)),
            work_id: id.as_bytes().to_vec(),
            client_signature: self
                .options
                .signer
                .sign_digest(bound_delivery_request_digest(
                    self.target.network,
                    channel.0,
                    id,
                    &link.exporter()?,
                ))
                .map_err(GrantClientError::from)?
                .bytes()
                .to_vec(),
        };
        let mut stream = tokio::time::timeout(self.options.timeout, link.stream(delivery))
            .await
            .map_err(|_| GrantClientError::Timeout)??;
        let mut prefixes =
            Prefixes::new(&policy.work, &input, self.target.provider.grant_producer()?)?;
        let signed = tokio::time::timeout(self.options.timeout, async {
            while let Some(event) = stream.next().await {
                let event = event?;
                use prost::Message;
                if event.encoded_len() as u64 > u64::from(policy.work.max_encoded_result_frame()) {
                    return Err(GrantProtocolError::FrameBound.into());
                }
                match event.outcome {
                    Some(work_stream_event::Outcome::Prefix(bytes)) => {
                        for event in decode_transcript(
                            &bytes,
                            hellas_work::work_store::journal::MAX_RECORD_BYTES,
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
                            hellas_work::work_store::journal::MAX_RECORD_BYTES,
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
                        if stream.next().await.transpose()?.is_some() {
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
        self.store.complete(
            id,
            &policy.work,
            &input,
            &prefixes.events,
            signed.clone(),
            self.now(),
        )?;
        Ok(GrantWorkResult {
            work_id: id,
            result: signed.result,
            events: prefixes.events,
        })
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
            hellas_rpc::signature::verify_digest_signature(
                &PublicKey::Secp256k1(target.provider.grant_producer()?.to_bytes()),
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
