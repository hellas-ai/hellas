//! Native transport discovery and connection-bound provider authentication.
use crate::error::ClientContext;
use crate::{ClientError, ClientResult, ExecutionRuntime};
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AssertionCounterStore, RegisteredAppleCredential,
    apple_app_attest_root_ca, apple_app_id_hash, register_apple, verify_apple_assertion,
};
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::{
    AppleAppAttestEnrollment, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR,
    CausalLmEnvironment, ContentId, PlatformCredential, PlatformEnrollment, ProgramManifest,
    ProviderEnrollmentBundle, PublicKey, RootKind,
};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::iroh::swarm::{DhtBackend, MdnsBackend, PeerExchangeBackend, ServiceRegistry};
use hellas_wire::{Metadata, MethodMarker, PeerIdentity, ServiceMarker, StreamTransport};
use iroh_mdns_address_lookup::MdnsAddressLookup;
use std::sync::{Arc, Mutex};
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
                hellas_rpc::signature_wire::signature_from_pb(signature).map_err(|source| {
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
            "Evaluate requires ({CATENA_GPU_EVALUATOR}, {CAUSAL_LM_ADAPTOR}), got ({:?}, {:?})",
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

#[cfg(test)]
mod tests;
