//! Connection-owned HostControl. Hosts admit an authenticated carrier before
//! exposing RPC dispatch; every effect still checks current node authority.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use hellas_auth::{Digest, authority::*};
use hellas_rpc::{
    authentication::session_binding,
    pb::host::*,
    protocol::value::{BoundedCborError, canonical_dag_cbor, decode_bounded, encode_bounded},
    services::host_control::{
        HostControl, HostControlClientImpl, HostControlHandler, HostControlServer,
    },
};
use hellas_wire::{
    Dispatcher, ServiceMarker, StreamTransport, WireCode, WireStatus, iroh::IrohTransport,
};
use hellas_work::{
    node::{NodeCoordinator, SessionKey},
    work_store::grant::NodeStoreError,
};
use iroh::endpoint::Connection;
use std::{sync::Arc, time::Duration};
use tokio::{sync::Semaphore, time::Instant};

use crate::application_handshake as handshake;
mod admission;
pub mod host;
pub use admission::RemoteControlAdmission;
pub mod profile;
const MAX_CONNECTIONS: usize = 16;
const MAX_COMMAND_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A node service, including nodes without a Work provider. Connection slots
/// cover handshake, dispatch and shutdown; they are not permission grants.
#[derive(Clone)]
pub struct NodeControl {
    node: NodeCoordinator,
    work: Option<hellas_work::grant_service::WorkAdministration>,
    host: Option<host::Runtime>,
    local_slots: Arc<Semaphore>,
    remote_slots: Arc<Semaphore>,
    remote_admission: RemoteControlAdmission,
}

impl NodeControl {
    pub fn new(node: NodeCoordinator) -> Self {
        Self {
            node,
            work: None,
            host: None,
            local_slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            remote_slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            remote_admission: RemoteControlAdmission::default(),
        }
    }

    pub(crate) fn node(&self) -> NodeCoordinator {
        self.node.clone()
    }
    pub(crate) fn remote_admission(&self) -> RemoteControlAdmission {
        self.remote_admission.clone()
    }

    /// Compose Work control and authentication from one writer, never two node handles.
    pub fn with_work(work: hellas_work::grant_service::WorkAdministration) -> Self {
        let mut control = Self::new(work.node());
        control.work = Some(work);
        control
    }

    /// Enable only the explicitly admitted remote endpoints. The hosting endpoint
    /// must install this admission value as its handshake hook as well.
    pub fn with_remote_admission(mut self, admission: RemoteControlAdmission) -> Self {
        self.remote_admission = admission;
        self
    }

    /// Bind a private OS listener using independently provisioned TLS identity.
    /// The listener owns every connection task; await its shutdown before
    /// draining the node writer. Local capacity is independent of remote peers.
    pub fn bind_local(
        &self,
        path: impl AsRef<std::path::Path>,
        config: Arc<hellas_wire::tls::ServerConfig>,
    ) -> std::io::Result<hellas_wire::local::LocalControlServer> {
        let service = self.clone();
        hellas_wire::local::LocalControlServer::bind(path, move |stream| {
            let service = service.clone();
            let config = config.clone();
            async move {
                // Authentication refusals carry no user or credential details
                // into host logs. serve_tls owns the stream through shutdown.
                let _ = service.serve_tls(stream, config).await;
            }
        })
    }

    /// Own one negotiated HostControl connection through close. Cancellation,
    /// failed authentication and expiry close it and discard all session state.
    pub async fn serve_iroh(&self, connection: Connection) -> Result<(), WireStatus> {
        let _close = CloseConnection(Some(connection.clone()));
        if !self.remote_admission.allows(connection.remote_id()) {
            return Err(denied());
        }
        let _slot = self.remote_slots.try_acquire().map_err(|_| {
            WireStatus::new(WireCode::ResourceExhausted, "node control is at capacity")
        })?;
        let transport = checked_transport(connection)?;
        let binding = binding(&transport)?;
        let (session, deadline) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let (mut send, mut recv) = transport
                .connection()
                .accept_bi()
                .await
                .map_err(|_| denied())?;
            let authenticated = handshake::accept(
                &self.node,
                binding,
                &mut recv,
                &mut send,
                handshake::Framing::Substream,
            )
            .await?;
            handshake::acknowledge(&mut send, handshake::Framing::Substream).await?;
            Ok::<_, WireStatus>(authenticated)
        })
        .await
        .map_err(|_| denied())??;
        serve(
            transport,
            self.node.clone(),
            self.work.clone(),
            self.host.clone(),
            session,
            binding,
            deadline,
        )
        .await
    }

    /// Host an admitted native byte stream with caller-configured TLS trust.
    /// TLS and application authentication finish before the mux starts receiving.
    pub async fn serve_tls<S>(
        &self,
        stream: S,
        config: Arc<hellas_wire::tls::ServerConfig>,
    ) -> Result<(), WireStatus>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let _slot = self.local_slots.try_acquire().map_err(|_| {
            WireStatus::new(WireCode::ResourceExhausted, "node control is at capacity")
        })?;
        let (stream, context, session, binding, deadline) =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
                let (stream, context) =
                    hellas_wire::tls::accept(stream, config, HostControl::ALPN.as_bytes())
                        .await
                        .map_err(|_| denied())?;
                let binding = session_binding(&context, HostControl::ALPN.as_bytes())
                    .map_err(|_| denied())?;
                let (mut recv, mut send) = tokio::io::split(stream);
                let (session, deadline) = handshake::accept(
                    &self.node,
                    binding,
                    &mut recv,
                    &mut send,
                    handshake::Framing::ByteStream,
                )
                .await?;
                handshake::acknowledge(&mut send, handshake::Framing::ByteStream).await?;
                Ok::<_, WireStatus>((recv.unsplit(send), context, session, binding, deadline))
            })
            .await
            .map_err(|_| denied())??;
        let transport =
            hellas_wire::local::transport(stream, hellas_wire::mux::Role::Server, context)
                .map_err(|_| unavailable())?;
        serve(
            transport,
            self.node.clone(),
            self.work.clone(),
            self.host.clone(),
            session,
            binding,
            deadline,
        )
        .await
    }
}

/// Connect to a native socket/pipe with explicit server trust and an application
/// credential. Same-UID admission is never substituted for either proof.
pub async fn connect_local(
    path: impl AsRef<std::path::Path>,
    config: Arc<hellas_wire::tls::ClientConfig>,
    server: hellas_wire::tls::ServerName<'static>,
    authority: AuthorityId,
    credential: &CredentialSecret,
    key: SessionKey<'_>,
) -> Result<
    (
        HostControlClientImpl<hellas_wire::mux::MuxTransport>,
        SessionChallenge,
    ),
    WireStatus,
> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let stream = hellas_wire::local::connect_stream(path)
            .await
            .map_err(|_| unavailable())?;
        connect_tls(stream, config, server, authority, credential, key).await
    })
    .await
    .map_err(|_| denied())?
}

/// Authenticate a connection dialed to the caller's independently trusted server
/// identity. Neither authority nor transport binding is learned from the challenge.
/// Reconnect after expiry or any handshake failure; this function never retries.
/// Keep the returned transport with its client; no credential is retained in it.
pub async fn connect_iroh(
    connection: Connection,
    authority: AuthorityId,
    credential: &CredentialSecret,
    key: SessionKey<'_>,
) -> Result<(HostControlClientImpl<IrohTransport>, SessionChallenge), WireStatus> {
    let mut close = CloseConnection(Some(connection.clone()));
    let transport = checked_transport(connection)?;
    let binding = binding(&transport)?;
    let (_, challenge) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (mut send, mut recv) = transport
            .connection()
            .open_bi()
            .await
            .map_err(|_| denied())?;
        handshake::connect(
            authority,
            binding,
            credential,
            key,
            &mut recv,
            &mut send,
            handshake::Framing::Substream,
        )
        .await
    })
    .await
    .map_err(|_| denied())??;
    close.0 = None;
    Ok((HostControlClientImpl::new(transport), challenge))
}

/// Connect local TLS before sending any application credential. The supplied trust
/// store, server name and authority must be independently configured by the caller.
pub async fn connect_tls<S>(
    stream: S,
    config: Arc<hellas_wire::tls::ClientConfig>,
    server: hellas_wire::tls::ServerName<'static>,
    authority: AuthorityId,
    credential: &CredentialSecret,
    key: SessionKey<'_>,
) -> Result<
    (
        HostControlClientImpl<hellas_wire::mux::MuxTransport>,
        SessionChallenge,
    ),
    WireStatus,
>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (stream, context, challenge) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let (stream, context) =
            hellas_wire::tls::connect(stream, config, server, HostControl::ALPN.as_bytes())
                .await
                .map_err(|_| denied())?;
        let binding =
            session_binding(&context, HostControl::ALPN.as_bytes()).map_err(|_| denied())?;
        let (mut recv, mut send) = tokio::io::split(stream);
        let (_, challenge) = handshake::connect(
            authority,
            binding,
            credential,
            key,
            &mut recv,
            &mut send,
            handshake::Framing::ByteStream,
        )
        .await?;
        Ok::<_, WireStatus>((recv.unsplit(send), context, challenge))
    })
    .await
    .map_err(|_| denied())??;
    let transport = hellas_wire::local::transport(stream, hellas_wire::mux::Role::Client, context)
        .map_err(|_| unavailable())?;
    Ok((HostControlClientImpl::new(transport), challenge))
}

async fn serve<T>(
    transport: T,
    node: NodeCoordinator,
    work: Option<hellas_work::grant_service::WorkAdministration>,
    host: Option<host::Runtime>,
    session: AuthenticatedSession,
    binding: Digest,
    deadline: Instant,
) -> Result<(), WireStatus>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send,
    <T::Stream as hellas_wire::Stream>::SendHalf: 'static,
    <T::Stream as hellas_wire::Stream>::RecvHalf: 'static,
{
    let server = HostControlServer(ControlSession {
        node,
        work,
        host,
        session,
        binding,
    });
    tokio::time::timeout_at(deadline, async {
        loop {
            let inbound = tokio::time::timeout(IDLE_TIMEOUT, transport.accept())
                .await
                .map_err(|_| denied())?
                .map_err(|_| unavailable())?;
            let Some(inbound) = inbound else {
                return Ok(());
            };
            // Recheck the connection before request decoding. Handlers recheck
            // again with exact grants under the writer at the effect point.
            server.0.caller().await?;
            Dispatcher::<T>::dispatch(&server, inbound)
                .await
                .map_err(|_| unavailable())?;
        }
    })
    .await
    .map_err(|_| denied())?
}

fn checked_transport(connection: Connection) -> Result<IrohTransport, WireStatus> {
    if connection.alpn() != HostControl::ALPN.as_bytes() {
        return Err(denied());
    }
    Ok(IrohTransport::new(connection))
}
fn binding(transport: &IrohTransport) -> Result<Digest, WireStatus> {
    session_binding(&transport.context(), HostControl::ALPN.as_bytes()).map_err(|_| denied())
}

struct CloseConnection(Option<Connection>);
impl Drop for CloseConnection {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"node control closed");
        }
    }
}

struct ControlSession {
    node: NodeCoordinator,
    work: Option<hellas_work::grant_service::WorkAdministration>,
    host: Option<host::Runtime>,
    session: AuthenticatedSession,
    binding: Digest,
}
impl ControlSession {
    async fn caller(&self) -> Result<&AuthenticatedCaller, WireStatus> {
        self.node
            .session_caller(&self.session, self.binding)
            .await
            .map_err(node_error)
    }
}

#[allow(refining_impl_trait)]
impl HostControlHandler for ControlSession {
    async fn inspect_authority(
        &self,
        request: InspectAuthorityRequest,
    ) -> Result<InspectAuthorityResponse, WireStatus> {
        let caller = self.caller().await?;
        let query = decode_bounded(&request.query, MAX_COMMAND_BYTES).map_err(|_| invalid())?;
        let reply = self
            .node
            .inspect(caller, grant_id(&request.authorization)?, query)
            .await
            .map_err(node_error)?;
        Ok(InspectAuthorityResponse {
            reply: encode_bounded(&reply, hellas_work::model::grant::admin::MAX_ADMIN_BYTES)
                .map_err(|_| {
                    WireStatus::new(WireCode::ResourceExhausted, "authority reply exceeds limit")
                })?,
        })
    }

    async fn get_host_status(
        &self,
        request: GetHostStatusRequest,
    ) -> Result<HostStatus, WireStatus> {
        let caller = self.caller().await?;
        self.node
            .host_action(
                caller,
                grant_id(&request.authorization)?,
                hellas_work::node::HOST_STATUS,
                |status| self.status_reply(status),
            )
            .await
            .map_err(node_error)?
    }

    async fn set_machine_capacity(
        &self,
        request: SetMachineCapacityRequest,
    ) -> Result<MachineCapacity, WireStatus> {
        let caller = self.caller().await?;
        let limits = decode_bounded(&request.limits, MAX_COMMAND_BYTES).map_err(|_| invalid())?;
        let result = self
            .node
            .set_machine_capacity(
                caller,
                grant_id(&request.authorization)?,
                Revision(request.expected_revision),
                u16::try_from(request.max_in_flight).map_err(|_| invalid())?,
                limits,
            )
            .await
            .map_err(node_error)?;
        capacity(result)
    }

    async fn grant_control(
        &self,
        request: GrantControlRequest,
    ) -> Result<GrantControlResponse, WireStatus> {
        let caller = self.caller().await?;
        let command: GrantCommand =
            decode_bounded(&request.command, MAX_COMMAND_BYTES).map_err(|_| invalid())?;
        let record = self.node.grant(caller, command).await.map_err(node_error)?;
        Ok(GrantControlResponse {
            reply: canonical_dag_cbor(&record).map_err(|_| unavailable())?,
        })
    }

    async fn work_control(
        &self,
        request: WorkControlRequest,
    ) -> Result<WorkControlResponse, WireStatus> {
        let caller = self.caller().await?;
        if request.command.len() > MAX_COMMAND_BYTES {
            return Err(invalid());
        }
        let work = self
            .host
            .as_ref()
            .map(host::Runtime::work)
            .transpose()?
            .flatten()
            .or_else(|| self.work.clone())
            .ok_or_else(unsupported)?;
        let command = decode_bounded(&request.command, MAX_COMMAND_BYTES).map_err(|_| invalid())?;
        let result = work
            .execute(caller, grant_id(&request.authorization)?, command)
            .await
            .map_err(node_error)?;
        let reply = encode_bounded(&result, hellas_work::model::grant::admin::MAX_ADMIN_BYTES)
            .map_err(|error| match error {
                BoundedCborError::OutputLimit => {
                    WireStatus::new(WireCode::ResourceExhausted, "Work reply exceeds limit")
                }
                _ => unavailable(),
            })?;
        Ok(WorkControlResponse { reply })
    }

    async fn issue_credential(
        &self,
        request: IssueCredentialRequest,
    ) -> Result<IssueCredentialResponse, WireStatus> {
        let caller = self.caller().await?;
        let credential =
            decode_bounded(&request.credential, MAX_COMMAND_BYTES).map_err(|_| invalid())?;
        let record = self
            .node
            .issue_credential(caller, grant_id(&request.authorization)?, credential)
            .await
            .map_err(node_error)?;
        Ok(IssueCredentialResponse {
            record: canonical_dag_cbor(&record).map_err(|_| unavailable())?,
        })
    }

    async fn revoke_credential(
        &self,
        request: RevokeCredentialRequest,
    ) -> Result<RevokeCredentialResponse, WireStatus> {
        let caller = self.caller().await?;
        let id = CredentialId::try_from(request.credential_id.as_slice()).map_err(|_| invalid())?;
        let record = self
            .node
            .revoke_credential(
                caller,
                grant_id(&request.authorization)?,
                id,
                Revision(request.expected_revision),
            )
            .await
            .map_err(node_error)?;
        Ok(RevokeCredentialResponse {
            record: canonical_dag_cbor(&record).map_err(|_| unavailable())?,
        })
    }

    async fn set_provider_state(
        &self,
        request: SetProviderStateRequest,
    ) -> Result<HostStatus, WireStatus> {
        self.set_state(
            &request.authorization,
            host::Service::Provider,
            request.enabled,
        )
        .await
    }
    async fn set_gateway_state(
        &self,
        request: SetGatewayStateRequest,
    ) -> Result<HostStatus, WireStatus> {
        self.set_state(
            &request.authorization,
            host::Service::Gateway,
            request.enabled,
        )
        .await
    }
    async fn get_gateway_access(
        &self,
        request: GetGatewayAccessRequest,
    ) -> Result<GatewayAccess, WireStatus> {
        let authorization = grant_id(&request.authorization)?;
        let (access, address) = self
            .node
            .host_action(
                self.caller().await?,
                authorization,
                hellas_work::node::HOST_GATEWAY_ACCESS,
                |_| self.host.as_ref().ok_or_else(unsupported)?.access(),
            )
            .await
            .map_err(node_error)??;
        access.validate().await.map_err(|_| {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "gateway credential is not current",
            )
        })?;
        self.node
            .host_action(
                self.caller().await?,
                authorization,
                hellas_work::node::HOST_GATEWAY_ACCESS,
                |_| GatewayAccess {
                    address,
                    bearer: access.bearer(),
                },
            )
            .await
            .map_err(node_error)
    }

    async fn bind_provider(
        &self,
        request: BindProviderRequest,
    ) -> Result<BindProviderResponse, WireStatus> {
        use hellas_work::model::grant::records::{GrantError, MAX_ENROLLMENT_BYTES};
        let caller = self.caller().await?;
        if request.enrollment.len() > MAX_ENROLLMENT_BYTES {
            return Err(invalid());
        }
        let provider =
            hellas_rpc::ProviderEnrollmentBundle::from_canonical_bytes(&request.enrollment)
                .map_err(|_| invalid())?;
        let genesis = self
            .node
            .bind_provider(caller, grant_id(&request.authorization)?, provider)
            .await
            .map_err(|error| match error {
                NodeStoreError::Grant(
                    GrantError::Malformed
                    | GrantError::UnsupportedKey
                    | GrantError::UnsupportedRoot
                    | GrantError::Signature,
                ) => invalid(),
                NodeStoreError::ProviderBound => {
                    WireStatus::new(WireCode::FailedPrecondition, "provider already bound")
                }
                error => node_error(error),
            })?;
        Ok(BindProviderResponse {
            provider_genesis: genesis.as_bytes().to_vec(),
        })
    }
}

impl ControlSession {
    fn status_reply(
        &self,
        status: hellas_work::node::NodeStatus,
    ) -> Result<HostStatus, WireStatus> {
        let mut reply = HostStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            authority: status.authority.0.as_bytes().to_vec(),
            authority_revision: status.authority_revision.0,
            generation: status.generation,
            provider_configured: status.provider.is_some(),
            identity: status
                .provider
                .as_ref()
                .map(host::identity_status)
                .transpose()?,
            machine: status.machine.map(capacity).transpose()?,
            ..Default::default()
        };
        if let Some(host) = &self.host {
            host.decorate(&mut reply)?;
        }
        Ok(reply)
    }
    async fn set_state(
        &self,
        authorization: &[u8],
        service: host::Service,
        enabled: bool,
    ) -> Result<HostStatus, WireStatus> {
        let authorization = grant_id(authorization)?;
        let operation = match service {
            host::Service::Provider => hellas_work::node::HOST_PROVIDER_CONFIGURE,
            host::Service::Gateway => hellas_work::node::HOST_GATEWAY_CONFIGURE,
        };
        let receiver = self
            .node
            .host_action(self.caller().await?, authorization, operation, |_| {
                self.host
                    .as_ref()
                    .ok_or_else(unsupported)?
                    .enqueue(service, enabled)
            })
            .await
            .map_err(node_error)??;
        receiver.await.map_err(|_| unavailable())??;
        self.node
            .host_action(self.caller().await?, authorization, operation, |status| {
                self.status_reply(status)
            })
            .await
            .map_err(node_error)?
    }
}

fn capacity(value: hellas_work::node::MachineCapacity) -> Result<MachineCapacity, WireStatus> {
    Ok(MachineCapacity {
        revision: value.revision.0,
        max_in_flight: u32::from(value.max_in_flight.get()),
        limits: canonical_dag_cbor(&value.limits).map_err(|_| unavailable())?,
    })
}
fn grant_id(bytes: &[u8]) -> Result<GrantId, WireStatus> {
    GrantId::try_from(bytes).map_err(|_| invalid())
}
fn node_error(error: NodeStoreError) -> WireStatus {
    match error {
        // Auth and Work check target authority before comparing revisions.
        // Keep other target-dependent failures indistinguishable.
        NodeStoreError::Authority(AuthorityError::Revision) => WireStatus::new(
            WireCode::FailedPrecondition,
            "stale revision; inspect current metadata before retrying",
        ),
        NodeStoreError::Authority(AuthorityError::Invalid) => invalid(),
        NodeStoreError::Grant(hellas_work::model::grant::records::GrantError::Revision(_)) => {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "stale Work revision; inspect current metadata before retrying",
            )
        }
        NodeStoreError::Grant(hellas_work::model::grant::records::GrantError::Limits) => invalid(),
        NodeStoreError::Authority(_) => denied(),
        NodeStoreError::MissingMachine => unsupported(),
        _ => unavailable(),
    }
}
fn denied() -> WireStatus {
    WireStatus::new(
        WireCode::PermissionDenied,
        "node control authentication or authorization failed",
    )
}
fn invalid() -> WireStatus {
    WireStatus::new(WireCode::InvalidArgument, "invalid node control request")
}
fn unavailable() -> WireStatus {
    WireStatus::new(WireCode::Unavailable, "node control is unavailable")
}
fn unsupported() -> WireStatus {
    WireStatus::new(
        WireCode::Unimplemented,
        "operation is not mounted on this node",
    )
}

#[cfg(test)]
mod tests;
