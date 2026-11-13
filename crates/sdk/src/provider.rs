use std::sync::Arc;

use hellas_attestation::RootProver;
use hellas_rpc::open::OpenDispatcher;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::signature_wire::signature_to_pb;
use hellas_rpc::{OPEN_NONCE_LEN, ProviderEnrollmentBundle, RootProof, open_proof_binding};
use hellas_wire::iroh::IrohTransport;
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, TransportContext, WireCode, WireStatus,
};

/// Startup errors, before a provider accepts requests.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error(transparent)]
    Control(#[from] WireStatus),
    #[error("provider enrollment does not match this identity")]
    Identity,
    #[error(transparent)]
    Bind(#[from] iroh::endpoint::BindError),
    #[error(transparent)]
    Address(#[from] iroh::endpoint::InvalidSocketAddr),
    #[error("discovery could not start: {0}")]
    Discovery(String),
}

use crate::paid_provider::MountedSetup;
use crate::transport_admission::{IDLE_TIMEOUT, MAX_LIFETIME};
use crate::work_router::WorkRouter;
use hellas_rpc::services::node::{Node, NodeServer};
use hellas_rpc::services::work::Work;
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupServer};
use hellas_wire::serve::AccountingDispatcher;
use iroh::endpoint::Connection;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, warn};

/// Binds both IP sockets of an endpoint to `port`.
///
/// An iroh bind address replaces the default socket of its own address family
/// only, so binding just `0.0.0.0:port` left IPv6 on a port chosen anew at each
/// start. Peers keep every address they learned for an endpoint id and send a
/// new dial to all of them; once another endpoint holds the old IPv6 port, its
/// handshake answer fails the dial. On one port, a restarted node has the
/// addresses its peers already know.
pub(crate) fn bind_port(
    builder: iroh::endpoint::Builder,
    port: u16,
) -> Result<iroh::endpoint::Builder, iroh::endpoint::InvalidSocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    builder
        .bind_addr(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?
        .bind_addr_with_opts(
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
            // As for iroh's default IPv6 socket, a host without IPv6 still starts.
            iroh::endpoint::BindOpts::default().set_is_required(false),
        )
}

pub(crate) mod discovery;
mod node;
pub(crate) use node::NodeHandlerImpl;
const MAX_RPC_IN_FLIGHT_PER_CONNECTION: usize = 16;

const RPC_CONNECTION_IDLE_TIMEOUT: Duration = IDLE_TIMEOUT;

pub(crate) fn served_alpns(remote_control: bool) -> Vec<Vec<u8>> {
    let mut alpns = vec![
        Node::ALPN.as_bytes().to_vec(),
        hellas_rpc::services::content::Content::ALPN
            .as_bytes()
            .to_vec(),
    ];
    alpns.extend([
        WorkSetup::ALPN.as_bytes().to_vec(),
        Work::ALPN.as_bytes().to_vec(),
    ]);
    if remote_control {
        alpns.push(
            hellas_rpc::services::host_control::HostControl::ALPN
                .as_bytes()
                .to_vec(),
        );
    }
    alpns
}

#[derive(Clone)]
pub(crate) struct Services {
    pub open_identity: Arc<ProviderOpen>,
    pub node: NodeHandlerImpl,
    pub setup: MountedSetup,
    pub work: WorkRouter,
    pub control: crate::node_control::NodeControl,
    pub content: hellas_store::content::DiskStore,
}
impl Services {
    pub async fn serve(
        self,
        conn: Connection,
        mut quiesce: watch::Receiver<bool>,
    ) -> Result<(), ProviderError> {
        let alpn = conn.alpn().to_vec();
        let Self {
            open_identity,
            node: node_handler,
            setup,
            work,
            control: admin,
            content,
        } = self;
        let manager = node_handler.directory.manager();
        if alpn == hellas_rpc::services::content::Content::ALPN.as_bytes() {
            return serve_content(conn, content, quiesce).await;
        }
        if alpn == hellas_rpc::services::host_control::HostControl::ALPN.as_bytes() {
            return tokio::select! {
                _ = quiescing(&mut quiesce) => Ok(()),
                result = admin.serve_iroh(conn) => result.map_err(ProviderError::from),
            };
        }
        let transport = Arc::new(IrohTransport::new(conn));

        // Account for inbound requests and refresh last_seen_ms in the shared registry.
        if alpn == <Node as ServiceMarker>::ALPN.as_bytes() {
            let server = AccountingDispatcher::new(NodeServer(node_handler), manager);
            let _ = serve_loop(
                transport,
                server,
                quiesce,
                RPC_CONNECTION_IDLE_TIMEOUT,
                tokio::time::Instant::now() + MAX_LIFETIME,
            )
            .await;
            Ok(())
        } else if alpn == WorkSetup::ALPN.as_bytes() {
            let server = AccountingDispatcher::new(
                OpenDispatcher::<_, _, hellas_rpc::services::work_setup::Open>::new(
                    WorkSetupServer(setup),
                    open_identity.clone(),
                ),
                manager,
            );
            let _ = serve_loop(
                transport,
                server,
                quiesce,
                RPC_CONNECTION_IDLE_TIMEOUT,
                tokio::time::Instant::now() + MAX_LIFETIME,
            )
            .await;
            Ok(())
        } else if alpn == Work::ALPN.as_bytes() {
            let connection = tokio::select! {
                _ = quiescing(&mut quiesce) => return Ok(()),
                connection = tokio::time::timeout(IDLE_TIMEOUT, work.accept_iroh(&transport, open_identity.clone())) => {
                    let Ok(connection) = connection else { return Ok(()); };
                    connection?
                },
            };
            let server = AccountingDispatcher::new(connection, manager);
            let _ = serve_loop(
                transport,
                server,
                quiesce,
                RPC_CONNECTION_IDLE_TIMEOUT,
                tokio::time::Instant::now() + MAX_LIFETIME,
            )
            .await;
            Ok(())
        } else {
            warn!("Unknown ALPN: {:?}", String::from_utf8_lossy(&alpn));
            Ok(())
        }
    }
}

pub(crate) async fn serve_content(
    connection: Connection,
    content: hellas_store::content::DiskStore,
    mut quiesce: watch::Receiver<bool>,
) -> Result<(), ProviderError> {
    let service = hellas_store::content::ContentService::new(
        Arc::new(content),
        hellas_store::content::Scope::Public,
    );
    let serving = serve_loop(
        Arc::new(IrohTransport::new(connection)),
        hellas_rpc::services::content::ContentServer(service),
        quiesce.clone(),
        RPC_CONNECTION_IDLE_TIMEOUT,
        tokio::time::Instant::now() + MAX_LIFETIME,
    );
    // Public reads and watches carry no reply obligation during shutdown.
    tokio::select! {
        _ = quiescing(&mut quiesce) => {},
        _ = serving => {},
    }
    Ok(())
}

async fn quiescing(receiver: &mut watch::Receiver<bool>) {
    if receiver.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

pub(crate) async fn serve_loop<T, S>(
    transport: Arc<T>,
    server: S,
    mut quiesce: watch::Receiver<bool>,
    idle_timeout: Duration,
    deadline: tokio::time::Instant,
) -> Result<(), WireStatus>
where
    T: StreamTransport + Send + Sync + 'static,
    S: Dispatcher<T> + Send + Sync + 'static,
    S::Error: Send + Sync + 'static,
{
    let server = Arc::new(server);
    let (inbound_tx, mut inbound_rx) = mpsc::channel(MAX_RPC_IN_FLIGHT_PER_CONNECTION);
    let accept_transport = transport.clone();
    // One task owns `accept`: dispatch completion can therefore never cancel
    // a partially read Open frame. The bounded channel is the only hand-off.
    let mut accepting = JoinSet::new();
    accepting.spawn(async move {
        loop {
            match accept_transport.accept().await {
                Ok(Some(inbound)) => {
                    if inbound_tx.send(Ok(inbound)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = inbound_tx.send(Err(error)).await;
                    break;
                }
            }
        }
    });

    let mut dispatches = JoinSet::new();
    let lifetime = tokio::time::sleep_until(deadline);
    tokio::pin!(lifetime);
    let mut draining = false;
    let mut result = Ok(());
    loop {
        if dispatches.len() >= MAX_RPC_IN_FLIGHT_PER_CONNECTION {
            tokio::select! {
                _ = &mut lifetime => { result = Err(WireStatus::new(WireCode::PermissionDenied, "connection expired")); break; },
                _ = quiescing(&mut quiesce) => { draining = true; break; }
                completed = dispatches.join_next() => log_dispatch_result(completed),
            }
            continue;
        }

        let idle = dispatches.is_empty();
        let next = tokio::select! {
            biased;
            _ = &mut lifetime => { result = Err(WireStatus::new(WireCode::PermissionDenied, "connection expired")); break; },
            _ = quiescing(&mut quiesce) => { draining = true; break; }
            next = async {
                if idle {
                    match tokio::time::timeout(idle_timeout, inbound_rx.recv()).await {
                        Ok(next) => next,
                        Err(_) => { result = Err(WireStatus::new(WireCode::PermissionDenied, "connection idle")); None }
                    }
                } else {
                    inbound_rx.recv().await
                }
            } => next,
            completed = dispatches.join_next(), if !dispatches.is_empty() => {
                log_dispatch_result(completed);
                continue;
            }
        };

        match next {
            Some(Ok(inbound)) => {
                let server = server.clone();
                dispatches.spawn(async move { server.dispatch(inbound).await });
            }
            Some(Err(_)) => {
                debug!("provider transport ended");
                result = Err(WireStatus::new(WireCode::Unavailable, "connection ended"));
                break;
            }
            None => break,
        }
    }

    accepting.shutdown().await;
    if draining {
        while let Some(result) = dispatches.join_next().await {
            log_dispatch_result(Some(result));
        }
    } else {
        dispatches.shutdown().await;
    }
    result
}

fn log_dispatch_result<E>(result: Option<Result<Result<(), E>, tokio::task::JoinError>>)
where
    E: std::error::Error,
{
    match result {
        Some(Ok(Err(_))) => {
            // RPC errors can be derived from request content. Keep the trace
            // useful without copying prompt or token material into logs.
            warn!("dispatch error; request details suppressed");
        }
        Some(Err(error)) if !error.is_cancelled() => {
            warn!("RPC dispatch task failed; request details suppressed");
        }
        Some(Ok(Ok(())) | Err(_)) | None => {}
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "inventory class A/B/C: test timing fixtures pending their rollout"
)]
pub(crate) mod tests;

/// The shared confidential-open proof handler. Software enrollment roots are
/// discarded: the enrolled producer alone signs each live transport binding.
pub struct ProviderOpen {
    signer: Arc<hellas_auth::ProducerSigningKey>,
    root: Option<Arc<dyn RootProver>>,
    pub(crate) enrollment: ProviderEnrollmentBundle,
}

impl ProviderOpen {
    pub fn enrollment(&self) -> &ProviderEnrollmentBundle {
        &self.enrollment
    }

    pub fn new(
        signer: Arc<hellas_auth::ProducerSigningKey>,
        enrollment: ProviderEnrollmentBundle,
        root: Option<Arc<dyn RootProver>>,
    ) -> Result<Self, ProviderError> {
        if enrollment.genesis.statement.producer_public_key != signer.public_key() {
            return Err(ProviderError::Identity);
        }
        let root = match enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => None,
            hellas_rpc::RootKind::SecureEnclave => Some(root.ok_or(ProviderError::Identity)?),
        };
        Ok(Self {
            signer,
            root,
            enrollment,
        })
    }
}

impl Clone for ProviderOpen {
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            root: self.root.clone(),
            enrollment: self.enrollment.clone(),
        }
    }
}

impl hellas_rpc::open::OpenHandler for ProviderOpen {
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
        let proof = match self.enrollment.genesis.statement.root_kind {
            hellas_rpc::RootKind::Software => {
                open_response::Proof::ProducerSignature(signature_to_pb(
                    &self
                        .signer
                        .sign_digest(binding)
                        .map_err(|_| WireStatus::internal("provider signature failed"))?,
                ))
            }
            hellas_rpc::RootKind::SecureEnclave => match self
                .root
                .as_ref()
                .ok_or_else(|| WireStatus::internal("provider root is unavailable"))?
                .prove_open_binding(binding)
                .await
                .map_err(|_| WireStatus::internal("provider open assertion failed"))?
            {
                RootProof::AppleAppAttest(assertion) => {
                    open_response::Proof::AppleAppAttestAssertion(assertion)
                }
                _ => {
                    return Err(WireStatus::internal(
                        "provider root returned incompatible proof",
                    ));
                }
            },
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}
