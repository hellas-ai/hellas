//! TLS 1.3 over native byte streams, including Unix sockets and named pipes.
//! Trust configurations come from the host/caller's policy, never peer input.
//! Hosts must bound handshake time and admit connections before calling accept.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use crate::transport::{OPEN_EXPORTER_LABEL, OPEN_EXPORTER_LEN, TransportContext};
pub use rustls::{ClientConfig, ServerConfig, pki_types::ServerName};
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: Arc<ServerConfig>,
    service: &[u8],
) -> io::Result<(tokio_rustls::server::TlsStream<S>, TransportContext)> {
    let stream = TlsAcceptor::from(config).accept(stream).await?;
    let connection = stream.get_ref().1;
    check_service(connection, service)?;
    let mut exporter = [0; OPEN_EXPORTER_LEN];
    connection
        .export_keying_material(&mut exporter, OPEN_EXPORTER_LABEL, None)
        .map_err(|_| binding_error())?;
    Ok((stream, context(exporter)))
}

pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    config: Arc<ClientConfig>,
    server: ServerName<'static>,
    service: &[u8],
) -> io::Result<(tokio_rustls::client::TlsStream<S>, TransportContext)> {
    let stream = TlsConnector::from(config).connect(server, stream).await?;
    let connection = stream.get_ref().1;
    check_service(connection, service)?;
    let mut exporter = [0; OPEN_EXPORTER_LEN];
    connection
        .export_keying_material(&mut exporter, OPEN_EXPORTER_LABEL, None)
        .map_err(|_| binding_error())?;
    Ok((stream, context(exporter)))
}

fn check_service(connection: &rustls::CommonState, service: &[u8]) -> io::Result<()> {
    if service.is_empty()
        || service.len() > 255
        || connection.alpn_protocol() != Some(service)
        || connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return Err(binding_error());
    }
    Ok(())
}
fn context(exporter: [u8; OPEN_EXPORTER_LEN]) -> TransportContext {
    // No UID or server certificate becomes application identity or permission.
    TransportContext {
        open_exporter: Some(exporter),
        ..Default::default()
    }
}
fn binding_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "TLS service binding is unavailable",
    )
}
