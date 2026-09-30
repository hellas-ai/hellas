//! Connection-bound authentication shared by both Work fundings.
use hellas_client::{ClientError, ClientResult};
use hellas_wire::{ServiceMarker, iroh::IrohTransport};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use std::net::SocketAddr;

pub(crate) struct WorkLink {
    pub(crate) endpoint: Endpoint,
    provider: EndpointAddr,
    pub(crate) trust: hellas_client::ProviderTrustAnchor,
    pub(crate) producer: std::sync::Mutex<Option<hellas_rpc::PublicKey>>,
    // Open is authenticated once per exact connection and ALPN. Serialize dials
    // so concurrent callers cannot reuse a connection before its proof passes.
    setup_connection: tokio::sync::Mutex<Option<iroh::endpoint::Connection>>,
    work_connection: tokio::sync::Mutex<Option<iroh::endpoint::Connection>>,
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
            endpoint,
            provider: EndpointAddr::from_parts(
                provider,
                addresses.into_iter().map(TransportAddr::Ip),
            ),
        }
    }

    pub(crate) fn require_producer(&self, key: hellas_rpc::PublicKey) -> ClientResult<()> {
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

    #[cfg(feature = "paid-client")]
    pub(crate) async fn setup(&self) -> ClientResult<IrohTransport> {
        self.connect(hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes())
            .await
    }

    pub(crate) async fn work(&self) -> ClientResult<IrohTransport> {
        self.connect(hellas_rpc::services::work::Work::ALPN.as_bytes())
            .await
    }

    async fn connect(&self, alpn: &[u8]) -> ClientResult<IrohTransport> {
        let cache = if alpn == hellas_rpc::services::work::Work::ALPN.as_bytes() {
            &self.work_connection
        } else {
            &self.setup_connection
        };
        let mut cached = cache.lock().await;
        if let Some(connection) = cached.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(IrohTransport::new(connection.clone()));
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
        let transport = IrohTransport::new(connection);
        {
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
        }
        *cached = Some(transport.connection().clone());
        Ok(transport)
    }
}
