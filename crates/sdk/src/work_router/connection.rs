//! Provider proof precedes application secrets. One connection then has one funding.
use super::*;
use crate::{application_handshake as handshake, node_control::profile::ClientProfile};
use hellas_auth::{Digest, ProducerSigningKey, authority::GrantId};
use hellas_rpc::{
    open::OpenHandler,
    services::work::{Open, Work, WorkServer},
};
use hellas_wire::{
    Dispatcher, Inbound, MethodMarker, ServiceMarker, Stream, StreamTransport, TransportError,
    iroh::IrohTransport,
};
use iroh::endpoint::Connection;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::OwnedSemaphorePermit,
};

const TIMEOUT: Duration = Duration::from_secs(10);
const PAYMENT: u8 = FundingKind::Payment as u8;
const GRANT: u8 = FundingKind::Grant as u8;

/// A host-owned connection admitted by WorkRouter. Its private funding/session
/// state cannot be supplied by request fields or constructed by a caller.
pub struct WorkConnection {
    server: WorkServer<ConnectionWork>,
    exporter: [u8; 32],
    _lease: ConnectionLease,
}
pub(super) struct ConnectionWork {
    funding: Funding,
}
enum Funding {
    Grants(GrantWork),
    Payment(MountedWork),
}
struct ConnectionLease {
    connection: Connection,
    slot: Option<OwnedSemaphorePermit>,
    public: Option<OwnedSemaphorePermit>,
    unverified: Option<admission::UnverifiedConnection>,
    expiry: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Some(expiry) = &self.expiry {
            expiry.abort();
        }
        self.connection
            .close(0u32.into(), b"Work connection closed");
    }
}

impl WorkRouter {
    /// Limit unauthenticated attempts per endpoint before provider proof. Pending
    /// handshakes do not hold session slots; public payment sessions retain their
    /// separate limit. Failed, cancelled and expired sessions close their connection.
    /// Only the public Open handshake is decoded before application authentication.
    pub async fn accept_iroh(
        &self,
        transport: &IrohTransport,
        open: impl OpenHandler,
    ) -> Result<WorkConnection, WireStatus> {
        let mut lease = ConnectionLease {
            connection: transport.connection().clone(),
            slot: None,
            public: None,
            unverified: None,
            expiry: None,
        };
        if lease.connection.alpn() != Work::ALPN.as_bytes() {
            return Err(denied());
        }
        let exporter = transport.open_exporter().map_err(|_| denied())?;
        lease.unverified = Some(
            self.unverified
                .admit(lease.connection.remote_id(), tokio::time::Instant::now())?,
        );
        let pending = self
            .pending
            .try_acquire()
            .map_err(|_| admission::capacity())?;
        let (funding, deadline) = tokio::time::timeout(TIMEOUT, async {
            let inbound = transport
                .accept()
                .await
                .map_err(|_| denied())?
                .ok_or_else(denied)?;
            if inbound.method_id != Open::METHOD_ID {
                return Err(denied());
            }
            hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, Open, _, _, _>(
                inbound,
                |request, context| open.open(request, context, Work::ALPN.as_bytes()),
            )
            .await
            .map_err(|_| denied())?;
            let (mut send, mut recv) = transport
                .connection()
                .accept_bi()
                .await
                .map_err(|_| denied())?;
            match recv.read_u8().await.map_err(|_| denied())? {
                PAYMENT => {
                    let payment = self.payment.as_ref().ok_or_else(denied)?.clone();
                    eof(&mut recv).await?;
                    lease.public = Some(
                        self.public
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| admission::capacity())?,
                    );
                    lease.slot = Some(
                        self.slots
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| admission::capacity())?,
                    );
                    send.write_all(&[PAYMENT]).await.map_err(|_| denied())?;
                    send.shutdown().await.map_err(|_| denied())?;
                    Ok((Funding::Payment(payment), None))
                }
                GRANT => {
                    let grants = self.grants.as_ref().ok_or_else(denied)?;
                    let mut authorization = [0; 16];
                    recv.read_exact(&mut authorization)
                        .await
                        .map_err(|_| denied())?;
                    let authorization = GrantId(authorization);
                    let binding = binding(&transport.context(), authorization)?;
                    let (session, deadline) = handshake::accept(
                        &grants.node(),
                        binding,
                        &mut recv,
                        &mut send,
                        handshake::Framing::Substream,
                    )
                    .await?;
                    if let Some(unverified) = lease.unverified.take() {
                        unverified.authenticated();
                    }
                    lease.slot = Some(
                        self.slots
                            .clone()
                            .try_acquire_owned()
                            .map_err(|_| admission::capacity())?,
                    );
                    handshake::acknowledge(&mut send, handshake::Framing::Substream).await?;
                    Ok((
                        Funding::Grants(grants.for_session(session, binding, authorization)),
                        Some(deadline),
                    ))
                }
                _ => Err(denied()),
            }
        })
        .await
        .map_err(|_| denied())??;
        drop(pending);
        if let Some(deadline) = deadline {
            let connection = lease.connection.clone();
            lease.expiry = Some(tokio::spawn(async move {
                tokio::time::sleep_until(deadline).await;
                connection.close(0u32.into(), b"Work session expired");
            }));
        }
        Ok(WorkConnection {
            server: WorkServer(ConnectionWork { funding }),
            exporter,
            _lease: lease,
        })
    }
}

impl Dispatcher<IrohTransport> for WorkConnection {
    type Error = TransportError;
    async fn dispatch(
        &self,
        mut inbound: Inbound<<IrohTransport as StreamTransport>::Stream>,
    ) -> Result<(), Self::Error> {
        let authenticated = inbound.context.open_exporter == Some(self.exporter)
            && match &self.server.0.funding {
                Funding::Grants(grants) => grants.authenticate().await.is_ok(),
                Funding::Payment(_) => true,
            };
        if !authenticated {
            inbound.stream.reset(WireCode::PermissionDenied);
            self._lease
                .connection
                .close(0u32.into(), b"Work session invalid");
            return Err(TransportError::Protocol(
                "Work session is no longer authenticated".into(),
            ));
        }
        Dispatcher::<IrohTransport>::dispatch(&self.server, inbound).await
    }
}

impl ConnectionWork {
    pub(super) fn handler<'a>(
        &'a self,
        context: &TransportContext,
        route: Option<&WorkRoute>,
    ) -> Result<Handler<'a>, WireStatus> {
        let route = route
            .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing Work route"))?;
        match (&self.funding, FundingKind::try_from(route.funding_kind)) {
            (Funding::Grants(grants), Ok(FundingKind::Grant)) => Ok(Handler::Grants(grants)),
            (Funding::Payment(payment), Ok(FundingKind::Payment)) => {
                Ok(match payment.handler(context, Some(route))? {
                    Some(service) => Handler::Payment(service),
                    None => Handler::Unavailable,
                })
            }
            _ => Err(denied()),
        }
    }
}

/// Called only after independently pinned confidential_open succeeded.
/// Returns when a grant session expires; payment connections have none.
pub(crate) async fn connect_work(
    transport: &IrohTransport,
    application: Option<(&ClientProfile, &ProducerSigningKey)>,
) -> Result<Option<tokio::time::Instant>, WireStatus> {
    tokio::time::timeout(TIMEOUT, async {
        let (mut send, mut recv) = transport
            .connection()
            .open_bi()
            .await
            .map_err(|_| denied())?;
        if let Some((application, identity)) = application {
            send.write_all(&[GRANT]).await.map_err(|_| denied())?;
            send.write_all(&application.authorization.0)
                .await
                .map_err(|_| denied())?;
            handshake::connect(
                application.authority,
                binding(&transport.context(), application.authorization)?,
                &application.credential,
                identity,
                &mut recv,
                &mut send,
                handshake::Framing::Substream,
            )
            .await
            .map(Some)
        } else {
            send.write_all(&[PAYMENT]).await.map_err(|_| denied())?;
            send.shutdown().await.map_err(|_| denied())?;
            if recv.read_u8().await.map_err(|_| denied())? != PAYMENT {
                return Err(denied());
            }
            eof(&mut recv).await.map(|()| None)
        }
    })
    .await
    .map_err(|_| denied())?
}

fn binding(context: &TransportContext, authorization: GrantId) -> Result<Digest, WireStatus> {
    let transport = hellas_rpc::authentication::session_binding(context, Work::ALPN.as_bytes())
        .map_err(|_| denied())?;
    Ok(hellas_auth::hash_tuple(
        "hellas.work.application.v1",
        &[transport.as_bytes(), &authorization.0],
    ))
}
async fn eof(recv: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<(), WireStatus> {
    if recv.read(&mut [0]).await.map_err(|_| denied())? != 0 {
        return Err(denied());
    }
    Ok(())
}
fn denied() -> WireStatus {
    WireStatus::new(
        WireCode::PermissionDenied,
        "Work connection authentication failed",
    )
}
