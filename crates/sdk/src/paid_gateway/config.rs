use super::{PaidWorkOptions, PoolError, Result};
use crate::work_config::load_work_config;
use hellas_kernel::{CoinId, EdgeId, Funding, List, MAX_PARTY_INPUTS};
use hellas_rpc::{Assurance, ContentId};
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
    pub(super) fn validate(&self) -> Result<()> {
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
        let mut funding = BTreeSet::new();
        for provider in &self.providers {
            if provider.timeout.is_zero()
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
            let coins = provider
                .payment_funding
                .maker()
                .iter()
                .chain(provider.payment_funding.taker().iter())
                .collect::<Vec<_>>();
            if coins.is_empty() {
                return Err(PoolError::Invalid("paid provider needs payment coins"));
            }
            for coin in coins {
                if !funding.insert(*coin) {
                    return Err(PoolError::Invalid(
                        "a payment coin cannot fund two provider channels or appear twice",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Load the operator JSON format used by both CLI and native hosts. File paths
/// must be absolute; Apple counter state lives beside the channel journals.
pub fn load_pool_options(path: &Path, assurance: Assurance) -> Result<PaidGatewayOptions> {
    let bytes = hellas_private::read_bounded_regular_file(
        path,
        hellas_work::work_store::journal::MAX_RECORD_BYTES,
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
            if !p.work_config.is_absolute() {
                return Err(PoolError::Invalid("work_config must be absolute"));
            }
            if p.payment_coins.is_empty() || p.payment_coins.len() > MAX_PARTY_INPUTS {
                return Err(PoolError::Invalid("payment_coins must name 1 to 4 coins"));
            }
            let coins = p
                .payment_coins
                .iter()
                .map(|value| fixed("payment_coins", value).map(CoinId::from_bytes))
                .collect::<Result<Vec<_>>>()?;
            let slots = std::array::from_fn(|i| {
                coins
                    .get(i)
                    .copied()
                    .unwrap_or(CoinId::from_bytes([0; CoinId::LENGTH]))
            });
            let provider_trust = trust(&p, assurance)?;
            Ok(PaidWorkOptions {
                config: load_work_config(&p.work_config)?,
                journal_root: p.journal_root,
                provider: p.provider,
                provider_addrs: p.provider_addrs,
                provider_trust,
                bond: EdgeId::from_bytes(fixed("bond", &p.bond)?),
                payment_funding: Funding::new(
                    List::take(slots, coins.len()),
                    List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
                ),
                omission_bond: p.omission_bond,
                acceptance_blocks: file.acceptance_blocks,
                terminal_blocks: file.terminal_blocks,
                payment_blocks: file.payment_blocks,
                timeout: Duration::from_secs(file.timeout_secs),
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

fn trust(
    p: &ProviderFile,
    assurance: Assurance,
) -> Result<Option<hellas_client::ProviderTrustAnchor>> {
    if p.provider_genesis.is_none() && assurance == Assurance::ProducerSigned {
        if p.apple_app_id.is_some() || !p.apple_cd_hashes.is_empty() {
            return Err(PoolError::Invalid("Apple trust requires provider_genesis"));
        }
        return Ok(None);
    }
    let expected_genesis = p.provider_genesis.ok_or(PoolError::Invalid(
        "attested paid providers require provider_genesis",
    ))?;
    let apple_app_attest = if p.apple_app_id.is_none()
        && p.apple_cd_hashes.is_empty()
        && assurance == Assurance::ProducerSigned
    {
        None
    } else {
        #[cfg(feature = "apple-verifier")]
        {
            let app_id = p
                .apple_app_id
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or(PoolError::Invalid("Apple trust requires apple_app_id"))?;
            if p.apple_cd_hashes.is_empty() {
                return Err(PoolError::Invalid("Apple trust requires apple_cd_hashes"));
            }
            Some(hellas_client::AppleAppAttestTrust::new(
                app_id,
                p.apple_cd_hashes
                    .iter()
                    .map(|v| fixed("apple_cd_hashes", v))
                    .collect::<Result<_>>()?,
                std::sync::Arc::new(crate::FilesystemAssertionCounterStore::new(
                    p.journal_root.join("apple-counters"),
                )),
            ))
        }
        #[cfg(not(feature = "apple-verifier"))]
        {
            return Err(PoolError::Invalid(
                "Apple trust requires the SDK apple-verifier feature",
            ));
        }
    };
    Ok(Some(hellas_client::ProviderTrustAnchor {
        expected_genesis,
        required_assurance: assurance,
        apple_app_attest,
    }))
}

fn fixed<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|source| PoolError::Hex { field, source })?;
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
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
    work_config: PathBuf,
    journal_root: PathBuf,
    provider: EndpointId,
    #[serde(default)]
    provider_addrs: Vec<SocketAddr>,
    bond: String,
    payment_coins: Vec<String>,
    omission_bond: u64,
    provider_genesis: Option<ContentId>,
    apple_app_id: Option<String>,
    #[serde(default)]
    apple_cd_hashes: Vec<String>,
}
