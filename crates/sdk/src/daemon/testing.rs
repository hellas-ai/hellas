//! Deterministic executors for integration tests, using the production daemon lifecycle.
use super::*;

pub struct Daemon {
    pub core: Arc<Core>,
    endpoint: iroh::Endpoint,
}
impl Daemon {
    pub async fn open(
        options: Options,
        document: Document,
        backends: BTreeMap<String, BackendEntry>,
    ) -> Self {
        let core = Core::open_with_backends(options, document, backends)
            .await
            .unwrap();
        let endpoint = core.iroh_endpoints().into_iter().next().unwrap();
        Self { core, endpoint }
    }
    pub fn node_id(&self) -> iroh::EndpointId {
        self.endpoint.id()
    }
    pub fn bound_sockets(&self) -> Vec<std::net::SocketAddr> {
        self.endpoint.bound_sockets()
    }
    pub fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }
    pub fn administration(&self) -> Option<hellas_authority::grant_service::WorkAdministration> {
        self.core.administration()
    }
    pub async fn shutdown(self) -> Result<()> {
        let result = self.core.shutdown().await;
        self.core.runtime.options.content.close().await;
        self.core.node().close().await;
        result
    }
}

/// Bootstrap fixture authority with the same inputs the daemon will restore.
pub async fn configuration(
    document: &Document,
) -> hellas_authority::model::grant::configuration::NodeConfiguration {
    document.configuration_for_test(&[]).await.unwrap()
}
