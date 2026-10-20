//! Typed normal-host upstream changes. Secrets are inputs, never status outputs.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUpdate {
    pub expected_revision: u64,
    pub change: UpstreamChange,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UpstreamChange {
    SetEndpoint(UpstreamEndpoint),
    RemoveEndpoint { service: String, method: String },
    AddKey(UpstreamKey),
    ReplaceKey(UpstreamKey),
    RemoveKey { service: String, method: String, key: String },
}
impl ProviderUpdate {
    pub fn requires_passkey(&self) -> bool { !matches!(self.change, UpstreamChange::AddKey(_)) }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamEndpoint {
    pub service: String,
    pub method: String,
    pub allowed_hosts: Vec<String>,
    pub allow_private_addresses: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamKey {
    pub service: String,
    pub method: String,
    pub key: String,
    pub allowed_origins: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub header_name: String,
    pub prefix: String,
    pub secret: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub revision: u64,
    pub endpoints: Vec<EndpointMetadata>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct EndpointMetadata {
    pub service: String,
    pub method: String,
    pub allowed_hosts: Vec<String>,
    pub keys: Vec<String>,
}
