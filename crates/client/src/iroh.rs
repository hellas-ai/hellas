use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_stream::try_stream;
use futures::{Stream, StreamExt};
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AssertionCounterStore, RegisteredAppleCredential,
    apple_app_attest_root_ca, apple_app_id_hash, register_apple, verify_apple_assertion,
};
use hellas_rpc::pb::courtesy::{QuoteResponse, QuoteTokensRequest, evaluate_start};
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, Ticket, open_response};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextArtifactId,
    TextExecution, TextExecutionId, TextPolicy, TokenIds,
};
use hellas_rpc::provenance::ExecutionProvenance;
use hellas_rpc::services::courtesy::{Courtesy, Open as CourtesyOpen, QuoteTokens};
use hellas_rpc::services::execute::ExecuteClientImpl;
use hellas_rpc::services::fetch::{CreateTicket as FetchCreateTicket, Fetch, Open as FetchOpen};
use hellas_rpc::{
    AppleAppAttestEnrollment, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR,
    CausalLmEnvironment, ContentId, Digest, Evaluate, EvaluateRequest, InputCommitment,
    MAX_STOP_TOKEN_IDS, PlatformCredential, PlatformEnrollment, ProducerSigningKey,
    ProgramManifest, ProviderEnrollmentBundle, PublicKey, RootKind,
};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::iroh::swarm::{DhtBackend, MdnsBackend, PeerExchangeBackend, ServiceRegistry};
use hellas_wire::{
    Metadata, MethodMarker, PeerIdentity, ServiceMarker, StreamTransport, WireStatus,
};
use iroh_mdns_address_lookup::MdnsAddressLookup;

use crate::error::ClientContext;
use crate::{
    ClientError, ClientResult, ExecutionRuntime, FetchChunkVerifier, FetchExecutionEvent,
    ProducerTrust, signed_run_ticket_request, validate_fetch_ticket, verified_fetch_input,
    verify_fetch_work_event,
};

/// One peer attempt gets a finite budget for dial, confidential Open, and the
/// cheap quote/ticket RPC. Long-running execution is deliberately outside this
/// deadline and keeps its application-level policy.
const PEER_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);

/// Discovery feeds may be intentionally long-lived. A finite caller looking
/// for an execution peer must nevertheless regain control if no new candidate
/// arrives.
const DISCOVERY_PROGRESS_TIMEOUT: Duration = Duration::from_secs(60);

/// Once a signed application terminal has arrived, only the wire End/trailer
/// remains. A peer cannot retain the caller forever by withholding that frame.
const TERMINAL_TRAILER_TIMEOUT: Duration = Duration::from_secs(30);

fn consume_discovery_attempt(attempts: &mut usize, max_attempts: usize) -> bool {
    *attempts = attempts.saturating_add(1);
    *attempts >= max_attempts
}

async fn with_peer_timeout<T>(
    timeout: Duration,
    context: impl Into<String>,
    operation: impl Future<Output = ClientResult<T>>,
) -> ClientResult<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|source| ClientError::source(context, source))?
}

async fn next_after_terminal<S>(
    stream: &mut S,
    terminal_seen: bool,
    timeout: Duration,
) -> ClientResult<Option<S::Item>>
where
    S: Stream + Unpin,
{
    if !terminal_seen {
        return Ok(stream.next().await);
    }
    tokio::time::timeout(timeout, stream.next())
        .await
        .map_err(|source| {
            ClientError::source(
                "remote peer withheld the wire trailer after its terminal outcome",
                source,
            )
        })
}

#[derive(Clone)]
pub struct AppleAppAttestTrust {
    pub app_id: String,
    pub allowed_cd_hashes: Vec<[u8; 32]>,
    pub counter_store: Arc<dyn AssertionCounterStore + Send + Sync>,
    credential: Arc<Mutex<Option<RegisteredAppleCredential>>>,
}

impl AppleAppAttestTrust {
    pub fn new(
        app_id: impl Into<String>,
        allowed_cd_hashes: Vec<[u8; 32]>,
        counter_store: Arc<dyn AssertionCounterStore + Send + Sync>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            allowed_cd_hashes,
            counter_store,
            credential: Arc::new(Mutex::new(None)),
        }
    }

    fn registered_credential(
        &self,
        enrollment: &AppleAppAttestEnrollment,
    ) -> ClientResult<RegisteredAppleCredential> {
        let mut registered = self.credential.lock().map_err(|_| {
            ClientError::protocol("provider App Attest enrollment credential cache is unavailable")
        })?;
        let credential = AppleCredential {
            attestation: enrollment.attestation_object.clone(),
            client_data_hash: enrollment.client_data_hash,
        };
        if let Some(existing) = registered.as_ref() {
            if existing.id != credential.content_id() {
                return Err(ClientError::protocol(
                    "provider App Attest enrollment changed after registration",
                ));
            }
            return Ok(existing.clone());
        }
        let verified = register_apple(
            &credential,
            apple_app_id_hash(&self.app_id),
            apple_app_attest_root_ca(),
            AnchorTime(enrollment.validation_time),
        )
        .map_err(|source| {
            ClientError::source("provider App Attest enrollment registration failed", source)
        })?;
        *registered = Some(verified.clone());
        Ok(verified)
    }
}

impl std::fmt::Debug for AppleAppAttestTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppleAppAttestTrust")
            .field("app_id", &self.app_id)
            .field("allowed_cd_hashes", &self.allowed_cd_hashes)
            .field("counter_store", &"<injected>")
            .field("credential", &"<verified requester-side>")
            .finish()
    }
}

impl PartialEq for AppleAppAttestTrust {
    fn eq(&self, other: &Self) -> bool {
        self.app_id == other.app_id
            && self.allowed_cd_hashes == other.allowed_cd_hashes
            && Arc::ptr_eq(&self.counter_store, &other.counter_store)
            && Arc::ptr_eq(&self.credential, &other.credential)
    }
}

impl Eq for AppleAppAttestTrust {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderTrustAnchor {
    pub expected_genesis: ContentId,
    pub required_assurance: Assurance,
    pub apple_app_attest: Option<AppleAppAttestTrust>,
}

/// Remote execution route carrying the out-of-band provider trust anchor even
/// while discovery is selecting an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionRoute {
    Local,
    RemoteDirect(RemoteNodeTarget),
    RemoteDiscovery {
        retries: usize,
        provider_trust: ProviderTrustAnchor,
    },
}

/// A remote dial target: the canonical iroh identity plus optional dial hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteNodeTarget {
    pub addr: ::iroh::EndpointAddr,
    pub provider_trust: ProviderTrustAnchor,
}

impl RemoteNodeTarget {
    pub fn node_id(&self) -> ::iroh::EndpointId {
        self.addr.id
    }

    pub fn direct(node_id: ::iroh::EndpointId, provider_trust: ProviderTrustAnchor) -> Self {
        Self {
            addr: ::iroh::EndpointAddr::from(node_id),
            provider_trust,
        }
    }
}

impl ExecutionRoute {
    /// Build a remote route from a peer id and optional direct-address hints.
    pub fn remote(
        node_id: Option<::iroh::EndpointId>,
        node_addrs: Vec<SocketAddr>,
        retries: usize,
        provider_trust: ProviderTrustAnchor,
    ) -> Self {
        match node_id {
            Some(node_id) => Self::RemoteDirect(RemoteNodeTarget {
                addr: ::iroh::EndpointAddr::from_parts(
                    node_id,
                    node_addrs.into_iter().map(::iroh::TransportAddr::Ip),
                ),
                provider_trust,
            }),
            None => Self::RemoteDiscovery {
                retries,
                provider_trust,
            },
        }
    }
}

/// Bound endpoint plus the per-service registry and connection pools built on it.
#[derive(Clone)]
pub struct RemoteRpc {
    endpoint: ::iroh::Endpoint,
    registry: ServiceRegistry,
}

/// Client discovery registry and its peer-exchange ingestion handle.
pub struct ClientDiscovery {
    pub registry: ServiceRegistry,
    pub peer_exchange: PeerExchangeBackend,
}

impl<L> ExecutionRuntime<L> {
    /// Bind a remote-capable runtime keyed by `secret_key`.
    pub async fn remote(secret_key: ::iroh::SecretKey) -> ClientResult<Self> {
        Self::default().with_remote(secret_key).await
    }

    /// Add a bound iroh endpoint and service registry to this runtime.
    pub async fn with_remote(mut self, secret_key: ::iroh::SecretKey) -> ClientResult<Self> {
        let endpoint = ::iroh::Endpoint::builder(::iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .client_context("failed to bind iroh endpoint for ExecutionRuntime")?;
        let discovery = build_client_registry(&endpoint).map_err(|source| {
            ClientError::protocol(format!("failed to configure service discovery: {source:#}"))
        })?;
        self.remote = Some(RemoteRpc {
            endpoint,
            registry: discovery.registry,
        });
        Ok(self)
    }

    /// Gracefully close the client endpoint after a finite remote operation.
    /// Long-lived callers such as the HTTP gateway keep their runtime instead.
    pub async fn close_remote(&self) {
        if let Some(remote) = &self.remote {
            remote.endpoint.close().await;
        }
    }

    /// Access the discovery registry configured for remote dispatch.
    pub fn remote_registry(&self) -> ClientResult<&ServiceRegistry> {
        self.remote
            .as_ref()
            .map(|remote| &remote.registry)
            .ok_or_else(remote_unavailable)
    }

    /// Dial one service through its shared connection pool.
    pub async fn remote_transport<S: ServiceMarker>(
        &self,
        target: &RemoteNodeTarget,
    ) -> ClientResult<IrohTransport> {
        let registry = self.remote_registry()?;
        registry
            .pool::<S>()
            .transport(target.addr.clone())
            .await
            .map_err(|source| {
                ClientError::source(
                    format!("failed to dial {} on {}", S::ALPN, target.node_id()),
                    source,
                )
            })
    }
}

fn remote_unavailable() -> ClientError {
    ClientError::protocol(
        "remote dispatch on a local-only runtime; construct via ExecutionRuntime::remote(...)",
    )
}

/// Build the native discovery registry shared by clients and the monitor.
pub fn build_client_registry(endpoint: &::iroh::Endpoint) -> ClientResult<ClientDiscovery> {
    let mdns = MdnsAddressLookup::builder()
        .advertise(false)
        .build(endpoint.id())
        .client_context("failed to start mDNS discovery")?;
    endpoint
        .address_lookup()
        .client_context("iroh endpoint has no address lookup registry")?
        .add(mdns.clone());

    let dht = DhtBackend::new(endpoint).client_context("failed to start DHT discovery")?;
    let peer_exchange = PeerExchangeBackend::new();

    let mut registry = ServiceRegistry::new(endpoint);
    registry.add(MdnsBackend::new(mdns));
    registry.add(dht);
    registry.add(peer_exchange.clone());

    Ok(ClientDiscovery {
        registry,
        peer_exchange,
    })
}

/// Authenticates a provider on this live connection before disclosing a request.
pub async fn confidential_open<M>(
    transport: &IrohTransport,
    trust: &ProviderTrustAnchor,
) -> ClientResult<PublicKey>
where
    M: MethodMarker<Request = OpenRequest, Response = OpenResponse>,
{
    let context = transport.context();
    let exporter = context.open_exporter.ok_or_else(|| {
        ClientError::protocol("live QUIC connection did not expose a confidential-open exporter")
    })?;
    let peer = context.peer.ok_or_else(|| {
        ClientError::protocol("live QUIC connection did not expose its remote peer identity")
    })?;
    let nonce: [u8; 32] = rand::random();
    let response = hellas_rpc::call::unary::<_, M>(
        transport,
        OpenRequest {
            nonce: nonce.to_vec(),
        },
        Metadata::new(),
    )
    .await
    .map_err(|status| ClientError::wire("provider declined confidential open", status))?;
    verify_open_response(
        trust,
        &exporter,
        &nonce,
        <M::Service as ServiceMarker>::ALPN.as_bytes(),
        peer,
        response,
    )
}

fn verify_open_response(
    trust: &ProviderTrustAnchor,
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    alpn: &[u8],
    peer: PeerIdentity,
    response: OpenResponse,
) -> ClientResult<PublicKey> {
    // The out-of-band pin is the trust anchor. Check it before interpreting
    // any attacker-controlled genesis fields or proof bytes.
    let actual_genesis = ContentId::hash(&response.provider_genesis);
    if actual_genesis != trust.expected_genesis {
        return Err(ClientError::protocol(format!(
            "provider genesis pin mismatch: expected {}, got {}",
            trust.expected_genesis, actual_genesis
        )));
    }

    let bundle = ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis)
        .map_err(|source| {
            ClientError::source("provider returned invalid enrollment bundle", source)
        })?;
    let genesis = &bundle.genesis;
    if trust.required_assurance == Assurance::AppleAppAttest
        && genesis.statement.root_kind != RootKind::SecureEnclave
    {
        return Err(ClientError::protocol(
            "Apple App Attest assurance requires a Secure Enclave provider root",
        ));
    }
    if genesis.statement.transport_public_key != PublicKey::Ed25519(peer.0) {
        return Err(ClientError::protocol(format!(
            "provider transport key mismatch: pinned genesis names {:?}, live QUIC peer is {peer:#}",
            genesis.statement.transport_public_key
        )));
    }
    let binding = hellas_rpc::open_proof_binding(
        exporter,
        nonce,
        &genesis.statement.producer_public_key,
        actual_genesis,
        alpn,
    );

    let producer_key = genesis.statement.producer_public_key;
    match genesis.statement.root_kind {
        RootKind::Software => {
            if !matches!(bundle.platform, PlatformEnrollment::Absent) {
                return Err(ClientError::protocol(
                    "software provider has unexpected platform enrollment",
                ));
            }
            let signature = match response.proof {
                Some(open_response::Proof::ProducerSignature(signature)) => signature,
                _ => {
                    return Err(ClientError::protocol(
                        "software provider open response is missing its producer signature",
                    ));
                }
            };
            let signature =
                hellas_rpc::run_ticket::signature_from_pb(signature).map_err(|source| {
                    ClientError::source("provider open signature is malformed", source)
                })?;
            hellas_rpc::signature::verify_digest_signature(
                &genesis.statement.producer_public_key,
                &signature,
                binding,
            )
            .map_err(|source| {
                ClientError::source("provider open signature verification failed", source)
            })
        }
        RootKind::SecureEnclave => {
            let PlatformEnrollment::AppleAppAttest(enrollment) = &bundle.platform else {
                return Err(ClientError::protocol(
                    "Secure Enclave provider bundle has no Apple App Attest enrollment",
                ));
            };
            let assertion = match response.proof {
                Some(open_response::Proof::AppleAppAttestAssertion(assertion)) => assertion,
                _ => {
                    return Err(ClientError::protocol(
                        "Apple provider open response is missing its App Attest assertion",
                    ));
                }
            };
            let apple = trust.apple_app_attest.as_ref().ok_or_else(|| {
                ClientError::protocol(
                    "pinned Apple provider requires an App Attest app identity and CDhash allowlist",
                )
            })?;
            let credential = apple.registered_credential(enrollment)?;
            if genesis.statement.platform_credential
                != PlatformCredential::Registered(credential.id)
                || genesis.statement.root_public_key != PublicKey::P256(credential.public_key)
            {
                return Err(ClientError::protocol(
                    "Apple provider genesis does not match its chain-verified credential",
                ));
            }
            let claims = verify_apple_assertion(
                &assertion,
                binding.as_bytes(),
                &credential,
                &ApplePolicy {
                    expected_rp_id_hash: apple_app_id_hash(&apple.app_id),
                    allowed_cd_hashes: apple.allowed_cd_hashes.clone(),
                },
            )
            .map_err(|source| {
                ClientError::source(
                    "provider App Attest open assertion verification failed",
                    source,
                )
            })?;
            apple
                .counter_store
                .advance(&credential.public_key, claims.counter)
                .map_err(|source| {
                    ClientError::source(
                        "provider App Attest open assertion counter advancement failed",
                        source,
                    )
                })
        }
    }?;
    Ok(producer_key)
}

fn validate_provider_trust_assurance(
    trust: &ProviderTrustAnchor,
    requested: Assurance,
) -> ClientResult<()> {
    if trust.required_assurance == requested {
        Ok(())
    } else {
        Err(ClientError::protocol(format!(
            "provider trust anchor requires {:?}, but the request asks for {:?}",
            trust.required_assurance, requested
        )))
    }
}

/// A token quote checked against the caller's request rather than trusted as
/// an interpretation supplied by the provider.
#[derive(Debug)]
pub struct ValidatedEvaluateQuote {
    pub ticket: Ticket,
    pub producer_key: PublicKey,
    pub text_execution: TextExecutionId,
}

/// Validate every deterministic field of a token quote and bind its ticket to
/// the returned canonical Evaluate request.
///
/// The provider chooses only the nonce. `expected_manifest_id` is the caller's
/// out-of-band pin; neither the request bodies nor the provider can replace it.
pub fn validate_evaluate_quote_response(
    request: &QuoteTokensRequest,
    expected_manifest_id: ContentId,
    expected_environment: &CausalLmEnvironment,
    response: QuoteResponse,
    expected_provider_genesis: Option<ContentId>,
) -> ClientResult<ValidatedEvaluateQuote> {
    validate_causal_lm_quote_request(request, expected_manifest_id, expected_environment)?;
    let prompt_tokens = u32::try_from(request.prompt_token_ids.len())
        .map_err(|_| ClientError::protocol("token quote prompt count exceeds u32"))?;
    if response.prompt_tokens != prompt_tokens {
        return Err(ClientError::protocol(format!(
            "provider reported {} prompt tokens for a {prompt_tokens}-token quote",
            response.prompt_tokens
        )));
    }

    let from = match request.start.as_ref().and_then(|start| start.kind.as_ref()) {
        Some(evaluate_start::Kind::Genesis(_)) => {
            let identity =
                TextArtifact::identity(BoundTermId::from_digest(expected_manifest_id.digest()));
            SourceRef::output(identity.output_id())
        }
        Some(evaluate_start::Kind::Artifact(artifact)) => {
            let digest = Digest::from_bytes(fixed_quote_field("artifact", &artifact.artifact)?);
            SourceRef::output(TextArtifactId::from_digest(digest))
        }
        None => {
            return Err(ClientError::protocol(
                "token quote is missing its evaluate start",
            ));
        }
    };
    let prompt_tokens = TokenIds::from_u32s(request.prompt_token_ids.iter().copied());
    let max_new_tokens = request
        .max_new_tokens
        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS);
    let policy =
        TextPolicy::from_u32_stop_tokens(max_new_tokens, request.stop_token_ids.iter().copied());
    let text_execution = TextExecution::new(from, prompt_tokens.output_id(), policy.output_id());

    let evaluate_pb = response
        .evaluate_request
        .ok_or_else(|| ClientError::protocol("quote_tokens response missing evaluate_request"))?;
    let evaluate_request = EvaluateRequest {
        text_execution: Digest::from_bytes(fixed_quote_field(
            "evaluate_request.text_execution",
            &evaluate_pb.text_execution,
        )?),
        runner_public_key: hellas_rpc::run_ticket::public_key_from_pb(
            evaluate_pb.runner_public_key.ok_or_else(|| {
                ClientError::protocol("evaluate request missing runner_public_key")
            })?,
        )
        .map_err(|source| ClientError::source("invalid evaluate runner_public_key", source))?,
        execution_environment: ContentId::from_bytes(fixed_quote_field(
            "evaluate_request.execution_environment",
            &evaluate_pb.execution_environment,
        )?),
        nonce: fixed_quote_field("evaluate_request.nonce", &evaluate_pb.nonce)?,
        assurance: hellas_rpc::run_ticket::assurance_from_pb(evaluate_pb.assurance)
            .map_err(|source| ClientError::source("invalid evaluate request assurance", source))?,
        retain: evaluate_pb.retain.unwrap_or(false),
    };
    let requested_runner = request
        .runner_public_key
        .clone()
        .ok_or_else(|| ClientError::protocol("token quote is missing runner_public_key"))
        .and_then(|key| {
            hellas_rpc::run_ticket::public_key_from_pb(key).map_err(|source| {
                ClientError::source("invalid requested runner_public_key", source)
            })
        })?;

    let text_execution = text_execution.input_id();
    if evaluate_request.text_execution != text_execution.digest()
        || evaluate_request.execution_environment != expected_manifest_id
        || evaluate_request.runner_public_key != requested_runner
        || evaluate_request.assurance.to_byte() as i32 != request.assurance
        || evaluate_request.retain != request.retain.unwrap_or(false)
    {
        return Err(ClientError::protocol(
            "provider's evaluate request does not match the token quote",
        ));
    }

    let ticket = response
        .ticket
        .ok_or_else(|| ClientError::protocol("quote_tokens response missing ticket"))?;
    let terms = hellas_rpc::run_ticket::job_terms_from_pb(&ticket)
        .map_err(|source| ClientError::source("invalid evaluate ticket terms", source))?;
    let expected_request = Evaluate::commit_request(&evaluate_request);
    if terms.request != expected_request {
        return Err(ClientError::protocol(
            "evaluate ticket is not bound to the returned evaluate request",
        ));
    }
    if terms.assurance != evaluate_request.assurance {
        return Err(ClientError::protocol(
            "evaluate ticket assurance does not match the committed request",
        ));
    }
    if let Some(expected) = expected_provider_genesis
        && terms.provider_genesis != expected
    {
        return Err(ClientError::protocol(format!(
            "evaluate ticket provider genesis mismatch: expected {expected}, got {}",
            terms.provider_genesis
        )));
    }
    let enrollment = ProviderEnrollmentBundle::from_canonical_bytes(&ticket.provider_genesis)
        .map_err(|source| ClientError::source("invalid evaluate provider enrollment", source))?;

    Ok(ValidatedEvaluateQuote {
        ticket,
        producer_key: enrollment.genesis.statement.producer_public_key,
        text_execution,
    })
}

/// Strictly validates the canonical Catena causal-LM environment against an
/// out-of-band manifest pin.
///
/// The generic manifest must name the exact Catena causal-LM application and
/// its root must be the content ID of the canonical application-owned
/// environment bytes. Tokenizers, templates, and decoding policy are not part
/// of either body.
///
/// # Errors
///
/// Returns [`ClientError`] for a non-canonical body, a manifest outside the
/// caller's pin, a different application, or a root mismatch.
pub fn validate_causal_lm_environment(
    expected_manifest_id: ContentId,
    program_manifest: &[u8],
    environment: &[u8],
) -> ClientResult<CausalLmEnvironment> {
    let environment = CausalLmEnvironment::from_canonical_bytes(environment)
        .map_err(|source| ClientError::source("invalid canonical causal-LM environment", source))?;
    validate_causal_lm_manifest(
        expected_manifest_id,
        program_manifest,
        environment.content_id(),
    )?;
    Ok(environment)
}

fn validate_causal_lm_manifest(
    expected_manifest_id: ContentId,
    program_manifest: &[u8],
    expected_root: ContentId,
) -> ClientResult<()> {
    let manifest = ProgramManifest::from_canonical_bytes(program_manifest)
        .map_err(|source| ClientError::source("invalid canonical program manifest", source))?;
    let manifest_id = manifest.content_id();
    if manifest_id != expected_manifest_id {
        return Err(ClientError::protocol(format!(
            "program manifest does not match caller pin: expected {expected_manifest_id}, got {manifest_id}"
        )));
    }
    if manifest.application().evaluator() != CATENA_GPU_EVALUATOR
        || manifest.application().adaptor() != CAUSAL_LM_ADAPTOR
    {
        return Err(ClientError::protocol(format!(
            "token Courtesy requires ({CATENA_GPU_EVALUATOR}, {CAUSAL_LM_ADAPTOR}), got ({:?}, {:?})",
            manifest.application().evaluator(),
            manifest.application().adaptor()
        )));
    }
    if manifest.root() != expected_root {
        return Err(ClientError::protocol(format!(
            "causal-LM environment does not match manifest root: expected {}, got {expected_root}",
            manifest.root(),
        )));
    }
    Ok(())
}

/// Strictly validate the two application-owned bodies and token bounds before
/// allowing a Courtesy request onto an adversarial transport.
///
/// # Errors
///
/// Returns [`ClientError`] when the request's manifest falls outside the
/// pinned environment contract or when its token invocation exceeds the
/// environment's vocabulary or capacity bounds.
pub fn validate_causal_lm_quote_request(
    request: &QuoteTokensRequest,
    expected_manifest_id: ContentId,
    expected_environment: &CausalLmEnvironment,
) -> ClientResult<()> {
    validate_causal_lm_manifest(
        expected_manifest_id,
        &request.program_manifest,
        expected_environment.content_id(),
    )?;

    if request.prompt_token_ids.is_empty() {
        return Err(ClientError::protocol(
            "token quote prompt_token_ids must not be empty",
        ));
    }
    if request.stop_token_ids.len() > MAX_STOP_TOKEN_IDS {
        return Err(ClientError::protocol(format!(
            "token quote has {} stop IDs, over the limit of {MAX_STOP_TOKEN_IDS}",
            request.stop_token_ids.len()
        )));
    }
    for (field, tokens) in [
        ("prompt_token_ids", request.prompt_token_ids.as_slice()),
        ("stop_token_ids", request.stop_token_ids.as_slice()),
    ] {
        if let Some(token) = tokens
            .iter()
            .copied()
            .find(|token| u64::from(*token) >= expected_environment.vocabulary_size())
        {
            return Err(ClientError::protocol(format!(
                "token quote {field} contains token {token}, but the environment vocabulary size is {}",
                expected_environment.vocabulary_size()
            )));
        }
    }

    let max_new_tokens = request
        .max_new_tokens
        .unwrap_or(hellas_rpc::DEFAULT_MAX_NEW_TOKENS);
    if max_new_tokens == 0 {
        return Err(ClientError::protocol(
            "token quote max_new_tokens must be greater than zero",
        ));
    }
    let total_tokens = u64::try_from(request.prompt_token_ids.len())
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(max_new_tokens));
    if total_tokens > expected_environment.maximum_capacity() {
        return Err(ClientError::protocol(format!(
            "token quote prompt plus max_new_tokens is {total_tokens} tokens, but the environment capacity is {}",
            expected_environment.maximum_capacity()
        )));
    }
    Ok(())
}

fn fixed_quote_field<const N: usize>(field: &str, bytes: &[u8]) -> ClientResult<[u8; N]> {
    bytes.try_into().map_err(|_| {
        ClientError::protocol(format!("{field} must be {N} bytes, got {}", bytes.len()))
    })
}

/// Bind unauthenticated transport metadata to the request commitment carried
/// by the already-validated ticket before exposing it as provenance.
pub fn validate_evaluate_quote_provenance(
    ticket: &Ticket,
    provenance: ExecutionProvenance,
) -> ClientResult<ExecutionProvenance> {
    let expected =
        fixed_quote_field::<32>("ticket.request_commitment", &ticket.request_commitment)?;
    if provenance.commitment_id != expected {
        return Err(ClientError::protocol(
            "evaluate quote provenance does not match the ticket request commitment",
        ));
    }
    Ok(provenance)
}

/// Open and quote prepared tokens on a specific peer.
///
/// The returned transport is the exact Open-bound Courtesy connection. The
/// caller must run the ticket on it rather than dialing a transferable Execute
/// leg whose connection was never attested.
pub async fn quote_tokens<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
    quote_req: &QuoteTokensRequest,
    expected_manifest_id: ContentId,
    expected_environment: &CausalLmEnvironment,
) -> ClientResult<(
    IrohTransport,
    Ticket,
    ExecutionProvenance,
    PublicKey,
    TextExecutionId,
)> {
    validate_causal_lm_quote_request(quote_req, expected_manifest_id, expected_environment)?;
    let requested_assurance = hellas_rpc::run_ticket::assurance_from_pb(quote_req.assurance)
        .map_err(|source| ClientError::source("invalid requested assurance", source))?;
    validate_provider_trust_assurance(&target.provider_trust, requested_assurance)?;
    let peer_id = target.node_id();
    let (transport, with_trailer) = with_peer_timeout(
        PEER_BOOTSTRAP_TIMEOUT,
        format!("node {peer_id} Courtesy bootstrap timed out"),
        async {
            let transport = runtime.remote_transport::<Courtesy>(target).await?;
            confidential_open::<CourtesyOpen>(&transport, &target.provider_trust).await?;
            let response = hellas_rpc::call::unary_with_trailer::<_, QuoteTokens>(
                &transport,
                quote_req.clone(),
                Metadata::new(),
            )
            .await
            .map_err(|status| {
                ClientError::wire(format!("node {peer_id} declined quote_tokens"), status)
            })?;
            Ok((transport, response))
        },
    )
    .await?;
    let validated = validate_evaluate_quote_response(
        quote_req,
        expected_manifest_id,
        expected_environment,
        with_trailer.response,
        Some(target.provider_trust.expected_genesis),
    )?;
    let provenance = hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata)
        .map_err(|source| {
            ClientError::source(
                format!(
                    "node {} response missing provenance metadata",
                    target.node_id()
                ),
                source,
            )
        })?;
    let provenance = validate_evaluate_quote_provenance(&validated.ticket, provenance)?;
    Ok((
        transport,
        validated.ticket,
        provenance,
        validated.producer_key,
        validated.text_execution,
    ))
}

/// Discover Courtesy peers until one returns a valid quote, retaining that
/// peer's Open-bound connection for RunTicket.
pub async fn discover_and_quote(
    registry: &ServiceRegistry,
    quote_req: &QuoteTokensRequest,
    expected_manifest_id: ContentId,
    expected_environment: &CausalLmEnvironment,
    retries: usize,
    provider_trust: &ProviderTrustAnchor,
) -> ClientResult<(
    IrohTransport,
    Ticket,
    ExecutionProvenance,
    PublicKey,
    TextExecutionId,
)> {
    validate_causal_lm_quote_request(quote_req, expected_manifest_id, expected_environment)?;
    let requested_assurance = hellas_rpc::run_ticket::assurance_from_pb(quote_req.assurance)
        .map_err(|source| ClientError::source("invalid requested assurance", source))?;
    validate_provider_trust_assurance(provider_trust, requested_assurance)?;
    let mut stream = Box::pin(registry.discover::<Courtesy>());
    let pool = registry.pool::<Courtesy>();
    let mut last_error: Option<ClientError> = None;
    let mut attempts = 0usize;
    let max_attempts = retries.saturating_add(1);

    loop {
        let peer = match tokio::time::timeout(DISCOVERY_PROGRESS_TIMEOUT, stream.next()).await {
            Ok(Some(peer)) => peer,
            Ok(None) => break,
            Err(source) => {
                return Err(ClientError::source(
                    "Courtesy discovery produced no peer before its progress deadline",
                    source,
                ));
            }
        };
        let peer = match peer {
            Ok(peer) => peer,
            Err(error) => {
                last_error = Some(ClientError::source("discovery feed error", error));
                if consume_discovery_attempt(&mut attempts, max_attempts) {
                    break;
                }
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        let (transport, with_trailer) = match with_peer_timeout(
            PEER_BOOTSTRAP_TIMEOUT,
            format!("node {peer_id} Courtesy bootstrap timed out"),
            async {
                let transport = pool.transport(peer_id).await.map_err(|error| {
                    ClientError::source(format!("failed to dial Courtesy on {peer_id}"), error)
                })?;
                confidential_open::<CourtesyOpen>(&transport, provider_trust).await?;
                let response = hellas_rpc::call::unary_with_trailer::<_, QuoteTokens>(
                    &transport,
                    quote_req.clone(),
                    Metadata::new(),
                )
                .await
                .map_err(|status| {
                    ClientError::wire(format!("node {peer_id} declined quote_tokens"), status)
                })?;
                Ok((transport, response))
            },
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let validated = match validate_evaluate_quote_response(
            quote_req,
            expected_manifest_id,
            expected_environment,
            with_trailer.response,
            Some(provider_trust.expected_genesis),
        ) {
            Ok(validated) => validated,
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        let provenance =
            match hellas_rpc::provenance::read_provenance_metadata(&with_trailer.metadata) {
                Ok(provenance) => provenance,
                Err(error) => {
                    last_error = Some(ClientError::source(
                        format!("peer {peer_id} response missing provenance metadata"),
                        error,
                    ));
                    if attempts >= max_attempts {
                        break;
                    }
                    continue;
                }
            };
        let provenance = match validate_evaluate_quote_provenance(&validated.ticket, provenance) {
            Ok(provenance) => provenance,
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
                continue;
            }
        };

        return Ok((
            transport,
            validated.ticket,
            provenance,
            validated.producer_key,
            validated.text_execution,
        ));
    }

    Err(last_error.unwrap_or_else(|| {
        ClientError::protocol(
            "discovery stream exhausted without a successful quote (no peers found)",
        )
    }))
}

struct PreparedFetch {
    transport: IrohTransport,
    ticket: Ticket,
    producer_key: PublicKey,
}

/// Create and validate a fetch ticket on a specific peer, retaining the exact
/// confidential-Open-bound connection and its authenticated producer key.
async fn prepare_fetch<L>(
    runtime: &ExecutionRuntime<L>,
    target: &RemoteNodeTarget,
    request: FetchRequest,
    input_commitment: InputCommitment,
    assurance: Assurance,
) -> ClientResult<PreparedFetch> {
    validate_provider_trust_assurance(&target.provider_trust, assurance)?;
    let peer_id = target.node_id();
    let (transport, producer_key, ticket) = with_peer_timeout(
        PEER_BOOTSTRAP_TIMEOUT,
        format!("node {peer_id} Fetch bootstrap timed out"),
        async {
            let transport = runtime.remote_transport::<Fetch>(target).await?;
            let producer_key =
                confidential_open::<FetchOpen>(&transport, &target.provider_trust).await?;
            let ticket = hellas_rpc::call::unary::<_, FetchCreateTicket>(
                &transport,
                request,
                Metadata::new(),
            )
            .await
            .map_err(|status| {
                ClientError::wire(
                    format!("node {peer_id} declined fetch create_ticket"),
                    status,
                )
            })?;
            Ok((transport, producer_key, ticket))
        },
    )
    .await?;
    let ticket = validate_fetch_ticket(
        ticket,
        input_commitment,
        assurance,
        target.provider_trust.expected_genesis,
    )?;
    Ok(PreparedFetch {
        transport,
        ticket,
        producer_key,
    })
}

/// Discover Fetch peers until one returns a valid ticket, retaining that
/// peer's confidential-Open-bound connection for RunTicket.
async fn discover_and_prepare_fetch(
    registry: &ServiceRegistry,
    request: &FetchRequest,
    input_commitment: InputCommitment,
    assurance: Assurance,
    retries: usize,
    provider_trust: &ProviderTrustAnchor,
) -> ClientResult<PreparedFetch> {
    validate_provider_trust_assurance(provider_trust, assurance)?;
    let mut stream = Box::pin(registry.discover::<Fetch>());
    let pool = registry.pool::<Fetch>();
    let mut last_error: Option<ClientError> = None;
    let mut attempts = 0usize;
    let max_attempts = retries.saturating_add(1);

    loop {
        let peer = match tokio::time::timeout(DISCOVERY_PROGRESS_TIMEOUT, stream.next()).await {
            Ok(Some(peer)) => peer,
            Ok(None) => break,
            Err(source) => {
                return Err(ClientError::source(
                    "Fetch discovery produced no peer before its progress deadline",
                    source,
                ));
            }
        };
        let peer = match peer {
            Ok(peer) => peer,
            Err(error) => {
                last_error = Some(ClientError::source("discovery feed error", error));
                if consume_discovery_attempt(&mut attempts, max_attempts) {
                    break;
                }
                continue;
            }
        };
        let peer_id = peer.id();
        attempts += 1;

        match with_peer_timeout(
            PEER_BOOTSTRAP_TIMEOUT,
            format!("node {peer_id} Fetch bootstrap timed out"),
            async {
                let transport = pool.transport(peer_id).await.map_err(|error| {
                    ClientError::source(format!("failed to dial Fetch on {peer_id}"), error)
                })?;
                let producer_key =
                    confidential_open::<FetchOpen>(&transport, provider_trust).await?;
                let ticket = hellas_rpc::call::unary::<_, FetchCreateTicket>(
                    &transport,
                    request.clone(),
                    Metadata::new(),
                )
                .await
                .map_err(|status| {
                    ClientError::wire(
                        format!("node {peer_id} declined fetch create_ticket"),
                        status,
                    )
                })?;
                let ticket = validate_fetch_ticket(
                    ticket,
                    input_commitment,
                    assurance,
                    provider_trust.expected_genesis,
                )?;
                Ok(PreparedFetch {
                    transport,
                    ticket,
                    producer_key,
                })
            },
        )
        .await
        {
            Ok(prepared) => return Ok(prepared),
            Err(error) => {
                last_error = Some(error);
                if attempts >= max_attempts {
                    break;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        ClientError::protocol("discovery stream exhausted without a successful fetch ticket")
    }))
}

pub fn fetch_execution_stream<L: Send + Sync>(
    runtime: ExecutionRuntime<L>,
    request: FetchRequest,
    route: ExecutionRoute,
    runner_key: Arc<ProducerSigningKey>,
) -> impl Stream<Item = ClientResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let verified_input = verified_fetch_input(&request)?;
        let input_commitment = verified_input.input_commitment;
        let assurance = verified_input.assurance;
        match route {
            ExecutionRoute::Local => Err(ClientError::protocol(
                "local fetch execution requires an embedded executor",
            ))?,
            ExecutionRoute::RemoteDirect(target) => {
                let prepared = prepare_fetch(
                    &runtime,
                    &target,
                    request,
                    input_commitment,
                    assurance,
                )
                .await?;
                let inner = execute_fetch_stream(
                    prepared,
                    input_commitment,
                    assurance,
                    runner_key.clone(),
                );
                futures::pin_mut!(inner);
                while let Some(event) = inner.next().await {
                    yield event?;
                }
            }
            ExecutionRoute::RemoteDiscovery {
                retries,
                provider_trust,
            } => {
                let prepared =
                    discover_and_prepare_fetch(
                        runtime.remote_registry()?,
                        &request,
                        input_commitment,
                        assurance,
                        retries,
                        &provider_trust,
                    )
                    .await?;
                let inner = execute_fetch_stream(
                    prepared,
                    input_commitment,
                    assurance,
                    runner_key.clone(),
                );
                futures::pin_mut!(inner);
                while let Some(event) = inner.next().await {
                    yield event?;
                }
            }
        }
    }
}

/// Run a fetch ticket over its already-authenticated Fetch transport.
fn execute_fetch_stream(
    prepared: PreparedFetch,
    input_commitment: InputCommitment,
    assurance: Assurance,
    runner_key: Arc<ProducerSigningKey>,
) -> impl Stream<Item = ClientResult<FetchExecutionEvent>> + Send {
    try_stream! {
        let PreparedFetch {
            transport,
            ticket,
            producer_key,
        } = prepared;
        let client = ExecuteClientImpl::new(transport);
        let run_ticket = signed_run_ticket_request(ticket, runner_key.as_ref())?;
        let mut wire = client
            .run_ticket(run_ticket)
            .await
            .map_err(|status| ClientError::wire("failed to start remote fetch run-ticket stream", status))?;
        let mut terminal = None;
        let mut verifier = FetchChunkVerifier::new(
            input_commitment,
            assurance,
            ProducerTrust::keys([producer_key]),
        );
        loop {
            let item = next_after_terminal(
                &mut wire,
                terminal.is_some(),
                TERMINAL_TRAILER_TIMEOUT,
            )
            .await?;
            let Some(item) = item else {
                break;
            };
            if terminal.is_some() {
                Err(ClientError::protocol(
                    "remote fetch run-ticket stream emitted an event after its terminal outcome"
                ))?;
            }
            let event = verify_fetch_work_event(
                &mut verifier,
                item.map_err(|status: WireStatus| {
                    ClientError::wire("remote fetch run-ticket stream failed", status)
                })?,
            )?;
            match event {
                FetchExecutionEvent::Chunk {
                    position,
                    output_event,
                    event,
                } => {
                    yield FetchExecutionEvent::Chunk {
                        position,
                        output_event,
                        event,
                    };
                }
                FetchExecutionEvent::Done(outcome) => {
                    terminal = Some(outcome);
                }
            }
        }
        wire.finish()
            .map_err(|status| ClientError::wire("remote fetch run-ticket stream trailer", status))?;
        let terminal = terminal.ok_or_else(|| {
            ClientError::protocol("remote fetch run-ticket stream ended Ok but emitted no Done event")
        })?;
        yield FetchExecutionEvent::Done(terminal);
        drop(client);
    }
}

#[cfg(test)]
mod tests;
