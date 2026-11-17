use super::ProviderError;
use hellas_wire::iroh::swarm::{DhtBackend, DhtPublisherConfig};
use iroh::Endpoint;
use iroh::address_lookup::AddressLookupBuilderError;
use iroh::endpoint_info::UserData;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

pub(crate) struct DiscoveryAdvertiser {
    _mdns: Option<MdnsAddressLookup>,
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
    start_advertising(endpoint, alpns, || {
        MdnsAddressLookup::builder().build(endpoint.id())
    })
}

fn start_advertising(
    endpoint: &Endpoint,
    alpns: &[Vec<u8>],
    mdns: impl FnOnce() -> Result<MdnsAddressLookup, AddressLookupBuilderError>,
) -> Result<DiscoveryAdvertiser, ProviderError> {
    let encoded = hellas_wire::iroh::swarm::mdns::encode_alpns(alpns).ok_or_else(|| {
        ProviderError::Discovery("service ALPN metadata is too large for mDNS".into())
    })?;
    let user_data: UserData = encoded
        .parse()
        .map_err(|e| ProviderError::Discovery(format!("failed to encode service metadata: {e}")))?;
    endpoint.set_user_data_for_address_lookup(Some(user_data));

    let mdns = match mdns() {
        Ok(mdns) => {
            endpoint
                .address_lookup()
                .map_err(|e| ProviderError::Discovery(e.to_string()))?
                .add(mdns.clone());
            Some(mdns)
        }
        Err(error) => {
            // Multicast is unavailable on some hosts and isolated networks.
            // Keep DHT publication and direct connections available there.
            tracing::warn!(
                ?error,
                "mDNS advertising unavailable; continuing with DHT discovery"
            );
            None
        }
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unavailable_mdns_keeps_direct_connections_alive() {
        const ALPN: &[u8] = b"discovery-fallback-test";
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let advertiser = start_advertising(&server, &[ALPN.to_vec()], || {
            Err(AddressLookupBuilderError::from_err(
                "mdns",
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "multicast unavailable",
                ),
            ))
        })
        .unwrap();
        assert!(advertiser._mdns.is_none());
        assert!(!advertiser.task.is_finished());

        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .bind()
            .await
            .unwrap();
        // A hang guard for the handshake, not a timing requirement.
        let (connected, accepted) =
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::join!(client.connect(server.addr(), ALPN), async {
                    server.accept().await.unwrap().await
                })
            })
            .await
            .unwrap();
        let connected = connected.unwrap();
        let accepted = accepted.unwrap();
        assert_eq!(connected.remote_id(), server.id());
        assert_eq!(accepted.remote_id(), client.id());

        connected.close(0_u32.into(), b"done");
        accepted.close(0_u32.into(), b"done");
        advertiser.shutdown().await;
        client.close().await;
        server.close().await;
    }
}
