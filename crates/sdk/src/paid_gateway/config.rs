use super::{PaidWorkOptions, PoolError, Result};
use crate::trust_policy::TrustPolicyStore;
use crate::work_config::load_work_config;
use hellas_rpc::Assurance;
use iroh::EndpointId;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// Typed funding and admission options for an application-owned paid pool.
pub struct PaidGatewayOptions {
    pub providers: Vec<PaidWorkOptions>,
    pub max_pending_requests: usize,
}

impl PaidGatewayOptions {
    /// The check the paid gateway applies when it starts. Callers replacing a
    /// running pool use it to refuse invalid options before retiring anything.
    pub fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            return Err(PoolError::Invalid(
                "paid gateway requires at least one provider",
            ));
        }
        if self.max_pending_requests == 0
            || self.max_pending_requests > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(PoolError::Invalid(
                "max_pending_requests must be a positive supported semaphore capacity",
            ));
        }
        let mut journals = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for provider in &self.providers {
            provider.validate()?;
            if provider.timeout.is_none_or(|timeout| timeout.is_zero())
                || provider.acceptance_blocks == 0
                || provider.terminal_blocks == 0
                || provider.payment_blocks == 0
            {
                return Err(PoolError::Invalid(
                    "timeouts and deadline spans must be positive",
                ));
            }
            if !provider.journal_root.is_absolute() {
                return Err(PoolError::Invalid("journal_root must be absolute"));
            }
            if !journals.insert(&provider.journal_root) {
                return Err(PoolError::Invalid(
                    "paid providers must have distinct journal roots",
                ));
            }
            if !endpoints.insert(provider.provider) {
                return Err(PoolError::DuplicateProvider(provider.provider));
            }
        }
        Ok(())
    }
}

/// Load the operator JSON format used by both CLI and native hosts. File paths
/// must be absolute; existing assertion counters stay beside each channel journal.
pub fn load_pool_options(path: &Path, assurance: Assurance) -> Result<PaidGatewayOptions> {
    let bytes = hellas_private::read_bounded_regular_file(
        path,
        hellas_channel::work_store::journal::MAX_RECORD_BYTES,
    )
    .map_err(|source| PoolError::Read {
        path: path.into(),
        source,
    })?;
    let file: PoolFile = serde_json::from_slice(&bytes).map_err(|source| PoolError::Parse {
        path: path.into(),
        source,
    })?;
    let providers = file
        .providers
        .into_iter()
        .map(|p| {
            if !p.chain_config.is_absolute() {
                return Err(PoolError::Invalid("chain_config must be absolute"));
            }
            let config = load_work_config(&p.chain_config)?;
            let apple_trust = match (&file.trust_store, &p.trust_policy) {
                (Some(directory), Some(id)) if directory.is_absolute() => {
                    Some(TrustPolicyStore::new(directory).resolve(
                        id,
                        assurance,
                        std::sync::Arc::new(crate::FilesystemAssertionCounterStore::new(
                            p.journal_root.join("apple-counters"),
                        )),
                    )?)
                }
                (None, None) if assurance == Assurance::ProducerSigned => None,
                _ => {
                    return Err(PoolError::Invalid(
                        "Apple providers require an absolute trust_store and approved trust_policy",
                    ));
                }
            };
            let provider_addrs = p.provider_addrs;
            Ok(PaidWorkOptions {
                config,
                journal_root: p.journal_root,
                provider: p.provider,
                provider_addrs,
                apple_trust,
                assurance,
                expected_price: p.payment,
                acceptance_blocks: file.acceptance_blocks,
                terminal_blocks: file.terminal_blocks,
                payment_blocks: file.payment_blocks,
                timeout: Some(Duration::from_secs(file.timeout_secs)),
            })
        })
        .collect::<Result<_>>()?;
    let options = PaidGatewayOptions {
        providers,
        max_pending_requests: file.max_pending_requests,
    };
    options.validate()?;
    Ok(options)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
    trust_store: Option<PathBuf>,
    providers: Vec<ProviderFile>,
    #[serde(default = "acceptance_blocks")]
    acceptance_blocks: u64,
    #[serde(default = "terminal_blocks")]
    terminal_blocks: u64,
    #[serde(default = "payment_blocks")]
    payment_blocks: u64,
    #[serde(default = "timeout_secs")]
    timeout_secs: u64,
    #[serde(default = "max_pending_requests")]
    max_pending_requests: usize,
}
const fn acceptance_blocks() -> u64 {
    16
}
const fn terminal_blocks() -> u64 {
    64
}
const fn payment_blocks() -> u64 {
    32
}
const fn timeout_secs() -> u64 {
    300
}
const fn max_pending_requests() -> usize {
    64
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderFile {
    chain_config: PathBuf,
    journal_root: PathBuf,
    provider: EndpointId,
    #[serde(default)]
    provider_addrs: Vec<SocketAddr>,
    payment: u64,
    trust_policy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> serde_json::Value {
        serde_json::json!({"chain_config":"/config/chain.json", "journal_root":"/state/client", "provider":iroh::SecretKey::from_bytes(&[4;32]).public(),
            "payment":10})
    }
    #[test]
    fn software_pool_selects_node_and_price_without_a_policy_or_offer_copy() {
        let entry: ProviderFile = serde_json::from_value(provider()).unwrap();
        assert_eq!(entry.payment, 10);
        assert!(entry.trust_policy.is_none());
        for field in [
            "offer",
            "work_config",
            "bond",
            "omission_bond",
            "payment_coins",
        ] {
            let mut value = provider();
            value[field] = serde_json::json!({});
            assert!(
                serde_json::from_value::<ProviderFile>(value).is_err(),
                "removed {field}"
            );
        }
    }
    #[test]
    fn apple_pool_can_name_an_existing_independent_approval() {
        let mut value = provider();
        value["trust_policy"] = "reviewed-apple".into();
        let entry: ProviderFile = serde_json::from_value(value).unwrap();
        assert_eq!(entry.trust_policy.as_deref(), Some("reviewed-apple"));
    }
}
