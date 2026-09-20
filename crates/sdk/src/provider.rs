use std::path::PathBuf;
use std::sync::Arc;

use hellas_attestation::RootProver;
use hellas_executor::{
    ExecuteServer, Executor, ExecutorMetrics, ExecutorSpawnConfig, FetchAccessPolicy,
    FetchQuotaStoreBackend, FetchRoute, FetchRouteEntry, FetchRoutePolicy, FetchRouteRegistry,
    FetchServer, FetchTranscriptStoreBackend,
};
use hellas_rpc::open::OpenDispatcher;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::policy::ExecutePolicy;
use hellas_rpc::run_ticket::signature_to_pb;
use hellas_rpc::serve::MethodDispatcher;
use hellas_rpc::services::execute::RunTicket;
use hellas_rpc::services::fetch::{Fetch, Open as FetchOpen};
use hellas_rpc::{
    Assurance, OPEN_NONCE_LEN, ProviderEnrollmentBundle, PublicKey, RootProof, open_proof_binding,
};
use hellas_wire::iroh::{IrohTransport, IrohTransportError};
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireCode, WireStatus,
};
use iroh::{Endpoint, EndpointId, endpoint::presets};

use crate::ClientIdentity;

const MAX_ACTIVE_CONNECTIONS: usize = 64;
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct OpenAiProviderOptions<R> {
    pub port: Option<u16>,
    pub identity: ClientIdentity,
    pub enrollment: ProviderEnrollmentBundle,
    pub root: Arc<R>,
    pub state_directory: PathBuf,
    pub service: String,
    pub method: String,
    pub bearer_token: String,
    pub allowed_callers: Vec<PublicKey>,
    pub fetch_max_in_flight: usize,
    pub fetch_queue_capacity: usize,
    pub retained_transcript_capacity: usize,
    pub fetch_replay_max_in_flight: usize,
}

pub struct ProviderHandle {
    endpoint: Endpoint,
    accept_task: tokio::task::JoinHandle<()>,
}

impl ProviderHandle {
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }

    pub async fn shutdown(mut self) {
        self.accept_task.abort();
        let _ = (&mut self.accept_task).await;
        self.endpoint.close().await;
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

pub async fn start_openai_provider<R>(
    options: OpenAiProviderOptions<R>,
) -> anyhow::Result<ProviderHandle>
where
    R: RootProver + Send + Sync + 'static,
{
    anyhow::ensure!(
        !options.allowed_callers.is_empty(),
        "provider requires at least one allowed caller"
    );
    let upstream = Arc::new(hellas_providers::OpenAiResponsesFetchProvider::with_bearer(
        options.bearer_token,
    )?);
    let adaptor = Arc::new(hellas_providers::ResponsesFetchAdaptorFactory::new(
        hellas_rpc::FetchEnvironment::OpenAiResponses,
    ));
    let mut routes = FetchRouteRegistry::new();
    routes.register(
        FetchRoute::new(options.service, options.method),
        FetchRouteEntry::new(upstream, adaptor, FetchRoutePolicy::default())?,
    )?;
    let producer_key = Arc::new(options.identity.caller_key().clone());
    let access = FetchAccessPolicy::trusted_callers(options.allowed_callers).with_store(
        FetchQuotaStoreBackend::fs(options.state_directory.join("quota")),
    );
    let executor = Executor::spawn_configured(ExecutorSpawnConfig {
        output_cache: Default::default(),
        execute_policy: ExecutePolicy::Deny,
        queue_capacity: 1,
        metrics: Arc::new(ExecutorMetrics::default()),
        producer_key: producer_key.clone(),
        provider_genesis: Arc::new(options.enrollment.canonical_bytes()),
        assurance: Assurance::AppleAppAttest,
        fetch_access_policy: access,
        fetch_routes: routes,
        fetch_max_in_flight: options.fetch_max_in_flight,
        fetch_queue_capacity: options.fetch_queue_capacity,
        fetch_replay_max_in_flight: options.fetch_replay_max_in_flight,
        fetch_store: FetchTranscriptStoreBackend::fs_with_capacity(
            options.state_directory.join("transcripts"),
            options.retained_transcript_capacity,
        ),
    })
    .await?;

    let open = ProviderOpen {
        root: options.root,
        enrollment: options.enrollment,
    };
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(options.identity.transport_key())
        .alpns(vec![<Fetch as ServiceMarker>::ALPN.as_bytes().to_vec()]);
    if let Some(port) = options.port {
        builder = builder.bind_addr(format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?)?;
    }
    let endpoint = builder.bind().await?;
    let accept_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_CONNECTIONS));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let incoming = tokio::select! {
                completed = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "provider connection task failed");
                    }
                    continue;
                }
                incoming = accept_endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else {
                break;
            };
            let slot = match slots.clone().acquire_owned().await {
                Ok(slot) => slot,
                Err(_) => break,
            };
            let accepting = match incoming.accept() {
                Ok(accepting) => accepting,
                Err(error) => {
                    tracing::warn!(%error, "provider connection accept failed");
                    continue;
                }
            };
            let executor = executor.clone();
            let open = open.clone();
            connections.spawn(async move {
                let _slot = slot;
                let connection = match tokio::time::timeout(HANDSHAKE_TIMEOUT, accepting).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "provider connection handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("provider connection handshake timed out");
                        return;
                    }
                };
                if connection.alpn() != <Fetch as ServiceMarker>::ALPN.as_bytes() {
                    return;
                }
                let transport = Arc::new(IrohTransport::new(connection));
                let server = OpenDispatcher::<_, _, FetchOpen>::new(
                    MethodDispatcher::<_, _, RunTicket>::new(
                        ExecuteServer(executor.clone()),
                        FetchServer(executor),
                    ),
                    open,
                );
                loop {
                    match transport.accept().await {
                        Ok(Some(inbound)) => {
                            if let Err(error) =
                                Dispatcher::<IrohTransport>::dispatch(&server, inbound).await
                            {
                                tracing::warn!(%error, "provider RPC failed");
                                break;
                            }
                        }
                        Ok(None) | Err(IrohTransportError::Connection(_)) => break,
                        Err(error) => {
                            tracing::warn!(%error, "provider transport failed");
                            break;
                        }
                    }
                }
            });
        }
    });
    Ok(ProviderHandle {
        endpoint,
        accept_task,
    })
}

struct ProviderOpen<R> {
    root: Arc<R>,
    enrollment: ProviderEnrollmentBundle,
}

impl<R> Clone for ProviderOpen<R> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            enrollment: self.enrollment.clone(),
        }
    }
}

impl<R> hellas_rpc::open::OpenHandler for ProviderOpen<R>
where
    R: RootProver + Send + Sync + 'static,
{
    async fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> Result<OpenResponse, WireStatus> {
        let nonce: [u8; OPEN_NONCE_LEN] = request.nonce.try_into().map_err(|nonce: Vec<u8>| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!(
                    "confidential open nonce must be {OPEN_NONCE_LEN} bytes, got {}",
                    nonce.len()
                ),
            )
        })?;
        let exporter = context.open_exporter.ok_or_else(|| {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "transport does not expose a confidential-open exporter",
            )
        })?;
        let binding = open_proof_binding(
            &exporter,
            &nonce,
            &self.enrollment.genesis.statement.producer_public_key,
            self.enrollment.content_id(),
            alpn,
        );
        let proof = match self
            .root
            .prove_open_binding(binding)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "provider open proof generation failed");
                WireStatus::internal("provider open proof generation failed")
            })? {
            RootProof::Software(signature) => {
                open_response::Proof::ProducerSignature(signature_to_pb(&signature))
            }
            RootProof::AppleAppAttest(assertion) => {
                open_response::Proof::AppleAppAttestAssertion(assertion)
            }
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}
