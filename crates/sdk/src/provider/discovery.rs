use super::ProviderError;
use hellas_wire::iroh::swarm::{DhtBackend, DhtPublisherConfig};
use iroh::Endpoint;
use iroh::endpoint_info::UserData;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

pub(crate) struct DiscoveryAdvertiser {
    _mdns: MdnsAddressLookup,
    shutdown: broadcast::Sender<()>,
    task: JoinHandle<()>,
}

impl DiscoveryAdvertiser {
    pub(crate) async fn shutdown(mut self) {
        let _ = self.shutdown.send(());
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}
impl Drop for DiscoveryAdvertiser {
    fn drop(&mut self) {
        // An abandoned provider must not leave its endpoint advertised.
        self.task.abort();
    }
}

pub(crate) fn start_server_advertising(
    endpoint: &Endpoint,
    alpns: &[Vec<u8>],
) -> Result<DiscoveryAdvertiser, ProviderError> {
    let encoded = hellas_wire::iroh::swarm::mdns::encode_alpns(alpns).ok_or_else(|| {
        ProviderError::Discovery("service ALPN metadata is too large for mDNS".into())
    })?;
    let user_data: UserData = encoded
        .parse()
        .map_err(|e| ProviderError::Discovery(format!("failed to encode service metadata: {e}")))?;
    endpoint.set_user_data_for_address_lookup(Some(user_data));

    let mdns = MdnsAddressLookup::builder()
        .build(endpoint.id())
        .map_err(|e| ProviderError::Discovery(format!("failed to start mDNS advertising: {e}")))?;
    endpoint
        .address_lookup()
        .map_err(|e| ProviderError::Discovery(e.to_string()))?
        .add(mdns.clone());

    let dht = DhtBackend::new(endpoint)
        .map_err(|e| ProviderError::Discovery(format!("failed to start DHT publisher: {e}")))?;
    let mut publisher = dht.create_publisher(DhtPublisherConfig::default());
    for alpn in alpns {
        publisher.add_service(alpn.clone());
    }
    let (shutdown, shutdown_rx) = broadcast::channel(1);
    let task = tokio::spawn(publisher.run(shutdown_rx));

    Ok(DiscoveryAdvertiser {
        _mdns: mdns,
        shutdown,
        task,
    })
}
