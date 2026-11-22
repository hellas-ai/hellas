//! Bounded connection reuse after per-request credential and DNS validation.
use super::{fault, tls};
use hellas_executor::FetchProviderError;
use hellas_rpc::http_fetch::{HttpFetchRequest, HttpTls};
use reqwest::{Client, Url};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_CLIENTS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
struct Key {
    origin: String,
    addresses: Vec<SocketAddr>,
    tls: Option<HttpTls>,
}

#[derive(Debug, Default)]
pub(super) struct Clients(Mutex<VecDeque<(Key, Client)>>);

impl Clients {
    /// `addresses` must have passed the provider's current egress policy.
    /// No request bodies, authorization headers or credential values are cached.
    pub(super) fn get(
        &self,
        request: &HttpFetchRequest,
        url: &Url,
        mut addresses: Vec<SocketAddr>,
    ) -> Result<Client, FetchProviderError> {
        // DNS answer order may rotate without changing the permitted set.
        addresses.sort_unstable();
        addresses.dedup();
        let key = Key {
            origin: url.origin().ascii_serialization(),
            addresses,
            tls: request.tls.clone(),
        };
        if let Some(client) = Self::cached(&mut self.0.lock().unwrap(), &key) {
            return Ok(client);
        }
        // Build outside the lock. A concurrent miss may build a second client,
        // but the insertion check below shares one pool before either sends.
        let client = Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20 * 60))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(4)
            .resolve_to_addrs(url.host_str().expect("validated HTTPS URL"), &key.addresses)
            .https_only(key.tls.is_some())
            .tls_backend_preconfigured(match &key.tls {
                Some(settings) => tls::config(settings).map_err(fault)?,
                None => rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .map_err(|_| fault("TLS versions unavailable"))?
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
            })
            .build()
            .map_err(|_| fault("HTTPS client initialization failed"))?;
        let mut entries = self.0.lock().unwrap();
        if let Some(client) = Self::cached(&mut entries, &key) {
            return Ok(client);
        }
        if entries.len() == MAX_CLIENTS {
            entries.pop_front();
        }
        entries.push_back((key, client.clone()));
        Ok(client)
    }

    fn cached(entries: &mut VecDeque<(Key, Client)>, key: &Key) -> Option<Client> {
        let index = entries.iter().position(|(existing, _)| existing == key)?;
        let entry = entries.remove(index).unwrap();
        let client = entry.1.clone();
        entries.push_back(entry);
        Some(client)
    }
}
