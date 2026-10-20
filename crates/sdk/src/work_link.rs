//! Connection-bound authentication shared by both Work fundings.
use crate::node_control::profile::ClientProfile;
use hellas_client::{ClientError, ClientResult};
use hellas_wire::{ServiceMarker, iroh::IrohTransport};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct WorkLink {
    pub(crate) endpoint: Endpoint,
    provider: EndpointAddr,
    pub(crate) trust: hellas_client::ProviderTrustAnchor,
    pub(crate) producer: std::sync::Mutex<Option<hellas_auth::PublicKey>>,
    // Open is authenticated once per exact connection and ALPN. Serialize dials
    // so concurrent callers cannot reuse a connection before its proof passes.
    setup_connection: tokio::sync::Mutex<Option<Session>>,
    work_connection: tokio::sync::Mutex<Option<Session>>,
    application: Option<(Arc<ClientProfile>, Arc<hellas_auth::ProducerSigningKey>)>,
}

/// A connection and the instant its grant session expires, if it has one.
type Session = (iroh::endpoint::Connection, Option<tokio::time::Instant>);

struct PendingConnection(Option<iroh::endpoint::Connection>);
impl Drop for PendingConnection {
    fn drop(&mut self) {
        if let Some(connection) = &self.0 {
            connection.close(0u32.into(), b"Work authentication incomplete");
        }
    }
}

impl WorkLink {
    pub(crate) fn new(
        provider: EndpointId,
        addresses: Vec<SocketAddr>,
        endpoint: Endpoint,
        trust: hellas_client::ProviderTrustAnchor,
    ) -> Self {
        Self {
            trust,
            producer: std::sync::Mutex::new(None),
            setup_connection: tokio::sync::Mutex::new(None),
            work_connection: tokio::sync::Mutex::new(None),
            application: None,
            endpoint,
            provider: EndpointAddr::from_parts(
                provider,
                addresses.into_iter().map(TransportAddr::Ip),
            ),
        }
    }

    pub(crate) fn with_application(
        mut self,
        application: Arc<ClientProfile>,
        signer: Arc<hellas_auth::ProducerSigningKey>,
    ) -> Self {
        self.application = Some((application, signer));
        self
    }

    pub(crate) fn require_producer(&self, key: hellas_auth::PublicKey) -> ClientResult<()> {
        let mut expected = self
            .producer
            .lock()
            .map_err(|_| ClientError::protocol("provider identity lock poisoned"))?;
        if expected.as_ref().is_some_and(|old| *old != key) {
            return Err(ClientError::protocol(
                "authenticated provider key differs from the pinned producer",
            ));
        }
        *expected = Some(key);
        Ok(())
    }

    pub(crate) async fn setup(&self) -> ClientResult<IrohTransport> {
        self.connect(
            hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes(),
            Duration::ZERO,
        )
        .await
        .map(|(transport, _)| transport)
    }

    pub(crate) async fn work(&self) -> ClientResult<IrohTransport> {
        self.work_for(Duration::ZERO)
            .await
            .map(|(transport, _)| transport)
    }

    /// A Work connection whose session lasts at least `need`, if a fresh one
    /// can; otherwise a fresh connection. Returns when its session expires.
    pub(crate) async fn work_for(
        &self,
        need: Duration,
    ) -> ClientResult<(IrohTransport, Option<tokio::time::Instant>)> {
        self.connect(hellas_rpc::services::work::Work::ALPN.as_bytes(), need)
            .await
    }

    async fn connect(
        &self,
        alpn: &[u8],
        need: Duration,
    ) -> ClientResult<(IrohTransport, Option<tokio::time::Instant>)> {
        let cache = if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
            &self.work_connection
        } else {
            &self.setup_connection
        };
        let mut cached = cache.lock().await;
        let usable_until = tokio::time::Instant::now() + need;
        if let Some((connection, expires)) = cached.as_ref().filter(|(c, expires)| {
            c.close_reason().is_none() && expires.is_none_or(|e| e > usable_until)
        }) {
            return Ok((IrohTransport::new(connection.clone()), *expires));
        }
        // A failed authentication never enters the cache. Reconnects repeat Open
        // and still have to match the producer pinned by the session.
        *cached = None;
        let connection = self
            .endpoint
            .connect(self.provider.clone(), alpn)
            .await
            .map_err(|source| {
                ClientError::source(
                    format!("cannot connect to provider {}", self.provider.id),
                    source,
                )
            })?;
        let mut pending = PendingConnection(Some(connection.clone()));
        let transport = IrohTransport::new(connection);
        let authenticated: ClientResult<Option<tokio::time::Instant>> = async {
            let trust = &self.trust;
            let producer = if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
                hellas_client::confidential_open::<hellas_rpc::services::work::Open>(
                    &transport, trust,
                )
                .await?
            } else {
                hellas_client::confidential_open::<hellas_rpc::services::work_setup::Open>(
                    &transport, trust,
                )
                .await?
            };
            self.require_producer(producer)?;
            if alpn != hellas_rpc::services::work::Work::ALPN.as_bytes() {
                return Ok(None);
            }
            crate::work_router::connect_work(
                &transport,
                self.application
                    .as_ref()
                    .map(|(profile, signer)| (profile.as_ref(), signer.as_ref())),
            )
            .await
            .map_err(|error| ClientError::wire("Work authentication failed", error))
        }
        .await;
        let expires = authenticated?;
        *cached = Some((transport.connection().clone(), expires));
        pending.0 = None;
        Ok((transport, expires))
    }
}
