//! Normal host configuration uses its generated typed wire messages directly.
pub use hellas_rpc::pb::host::provider_update::Change as UpstreamChange;
pub use hellas_rpc::pb::host::{
    EndpointMetadata, ProviderMetadata, ProviderUpdate, UpstreamEndpoint, UpstreamKey,
    UpstreamKeyId, UpstreamRoute,
};

pub fn requires_passkey(update: &ProviderUpdate) -> bool {
    !matches!(update.change, Some(UpstreamChange::AddKey(_)))
}
