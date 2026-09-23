//! Operator-owned account aliases. Files contain environment variable names,
//! never customer payloads or API keys.
use super::{HttpCredential, HttpEgressPolicy, HttpFetchProvider};
use hellas_executor::{FetchProviderError, FetchRouteEntry, FetchRoutePolicy};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProviderConfig {
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allow_private_addresses: bool,
    #[serde(default)]
    pub credentials: BTreeMap<String, HttpCredentialConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCredentialConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    pub secret_env: String,
    #[serde(default)]
    pub prefix: String,
}

impl HttpProviderConfig {
    pub fn into_entry(
        self,
        capabilities: FetchRoutePolicy,
    ) -> Result<FetchRouteEntry, FetchProviderError> {
        let mut credentials = BTreeMap::new();
        for (alias, config) in self.credentials {
            let secret = std::env::var(&config.secret_env)
                .map_err(|_| super::fault("account secret environment variable is unavailable"))?;
            if secret.is_empty() {
                return Err(super::fault("account secret is empty"));
            }
            credentials.insert(
                alias,
                HttpCredential {
                    allowed_origins: config.allowed_origins,
                    allowed_paths: config.allowed_paths,
                    allowed_methods: config.allowed_methods,
                    header_name: config.header_name,
                    header_value: format!("{}{secret}", config.prefix),
                },
            );
        }
        let provider = HttpFetchProvider::new(
            HttpEgressPolicy {
                allowed_hosts: self.allowed_hosts,
                allow_private_addresses: self.allow_private_addresses,
            },
            credentials,
        )?;
        FetchRouteEntry::new(
            std::sync::Arc::new(provider),
            std::sync::Arc::new(super::HttpFetchAdaptorFactory),
            capabilities,
        )
        .map_err(|_| super::fault("invalid HTTP Fetch route"))
    }
}
