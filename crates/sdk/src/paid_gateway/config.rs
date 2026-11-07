use super::{PaidWorkOptions, PoolError, Result};
use crate::trust_policy::TrustPolicyStore;
use crate::work_config::WorkConfig;
use hellas_rpc::Assurance;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

/// Per-provider routing and payment terms; the pool owns one shared chain.
#[derive(Clone)]
pub struct GatewayProviderOptions {
    pub provider: hellas_client::ProviderAddress,
    pub provider_addrs: Vec<SocketAddr>,
    pub apple_trust: Option<hellas_client::ProviderTrustAnchor>,
    pub assurance: Assurance,
    pub expected_price: u64,
    pub acceptance_blocks: u64,
    pub terminal_blocks: u64,
    pub payment_blocks: u64,
    pub timeout: Option<Duration>,
}

impl GatewayProviderOptions {
    pub fn with_config(self, config: WorkConfig) -> PaidWorkOptions {
        PaidWorkOptions {
            config,
            journal_kind: crate::paid_client::PaidJournalKind::Gateway,
            provider: self.provider,
            provider_addrs: self.provider_addrs,
            apple_trust: self.apple_trust,
            assurance: self.assurance,
            expected_price: self.expected_price,
            acceptance_blocks: self.acceptance_blocks,
            terminal_blocks: self.terminal_blocks,
            payment_blocks: self.payment_blocks,
            timeout: self.timeout,
        }
    }
}

/// Typed funding and admission options for an application-owned paid pool.
pub struct PaidGatewayOptions {
    pub config: WorkConfig,
    pub providers: Vec<GatewayProviderOptions>,
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
        let mut endpoints = BTreeSet::new();
        for provider in &self.providers {
            provider
                .clone()
                .with_config(self.config.clone())
                .validate()?;
            if provider.timeout.is_none_or(|timeout| timeout.is_zero())
                || provider.acceptance_blocks == 0
                || provider.terminal_blocks == 0
                || provider.payment_blocks == 0
            {
                return Err(PoolError::Invalid(
                    "timeouts and deadline spans must be positive",
                ));
            }
            if !endpoints.insert(provider.provider.node) {
                return Err(PoolError::DuplicateProvider(provider.provider.node));
            }
        }
        Ok(())
    }
}

/// Load the operator JSON format used by both CLI and native hosts. File paths
/// must be absolute; assertion counters live in the shared process home.
pub fn load_pool_options(
    path: &Path,
    assurance: Assurance,
    config: WorkConfig,
) -> Result<PaidGatewayOptions> {
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
            let apple_trust = match (&file.trust_store, &p.trust_policy) {
                (Some(directory), Some(id)) if directory.is_absolute() => {
                    Some(TrustPolicyStore::new(directory).resolve(
                        id,
                        assurance,
                        std::sync::Arc::new(crate::FilesystemAssertionCounterStore::in_home(
                            config.chain.home(),
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
            Ok(GatewayProviderOptions {
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
        config,
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
    300
}
const fn terminal_blocks() -> u64 {
    3000
}
const fn payment_blocks() -> u64 {
    600
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
    provider: hellas_client::ProviderAddress,
    #[serde(default)]
    provider_addrs: Vec<SocketAddr>,
    payment: u64,
    trust_policy: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> serde_json::Value {
        serde_json::json!({"provider":crate::test_support::address(iroh::SecretKey::from_bytes(&[4;32]).public()),
            "payment":10})
    }
    #[test]
    fn software_pool_selects_address_and_price_without_a_policy_or_offer_copy() {
        let entry: ProviderFile = serde_json::from_value(provider()).unwrap();
        assert_eq!(
            entry.provider,
            crate::test_support::address(iroh::SecretKey::from_bytes(&[4; 32]).public())
        );
        assert_eq!(entry.payment, 10);
        let mut node_only = provider();
        node_only["provider"] = iroh::SecretKey::from_bytes(&[4; 32])
            .public()
            .to_string()
            .into();
        let error = serde_json::from_value::<ProviderFile>(node_only)
            .err()
            .expect("a node ID alone is not a provider address");
        assert!(
            error.to_string().contains("ENROLLMENT_ID@NODE_ID"),
            "{error}"
        );
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
