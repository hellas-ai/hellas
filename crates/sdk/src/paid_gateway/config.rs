use super::{PaidWorkOptions, PoolError, Result};
use crate::trust_policy::TrustPolicyStore;
use crate::work_config::load_work_config;
use hellas_kernel::{CoinId, EdgeId, Funding, List, MAX_PARTY_INPUTS};
use hellas_rpc::Assurance;
use hellas_work::model::grant::records::grant_transport;
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
/// must be absolute; existing assertion counters stay beside each channel journal.
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
    if !file.trust_store.is_absolute() {
        return Err(PoolError::Invalid("trust_store must be absolute"));
    }
    let trust_store = TrustPolicyStore::new(file.trust_store);
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
            let config = load_work_config(&p.work_config)?;
            let provider_trust = trust(&p, assurance, &config, &trust_store)?;
            let provider_addrs = if p.provider_addrs.is_empty() {
                match &p.offer {
                    Some(signed) => signed
                        .offer()
                        .addresses
                        .iter()
                        .map(|a| {
                            a.parse()
                                .map_err(|_| PoolError::Invalid("paid offer address"))
                        })
                        .collect::<Result<_>>()?,
                    None => vec![],
                }
            } else {
                p.provider_addrs
            };
            Ok(PaidWorkOptions {
                config,
                journal_root: p.journal_root,
                provider: p.provider,
                provider_addrs,
                provider_trust,
                bond: EdgeId::from_bytes(fixed("bond", &p.bond)?),
                payment_funding: Funding::new(
                    crate::work_config::coin_list(&coins)
                        .ok_or(PoolError::Invalid("payment_coins must name 1 to 4 coins"))?,
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
    config: &crate::work_config::WorkConfig,
    store: &TrustPolicyStore,
) -> Result<hellas_client::ProviderTrustAnchor> {
    let trust = store.resolve_environment(
        &p.trust_policy,
        assurance,
        config.work_policy.allowed_environment(),
        std::sync::Arc::new(crate::FilesystemAssertionCounterStore::new(
            p.journal_root.join("apple-counters"),
        )),
    )?;
    if let Some(signed) = &p.offer {
        signed
            .check()
            .map_err(|_| PoolError::Invalid("paid offer signature or bond is invalid"))?;
        let offer = signed.offer();
        if offer.proposal.network() != config.chain.network
            || offer.proposal.bond_edge().to_bytes() != fixed::<32>("bond", &p.bond)?
            || grant_transport(&offer.provider)
                .map_err(|_| PoolError::Invalid("paid offer transport"))?
                != *p.provider.as_bytes()
        {
            return Err(PoolError::Invalid(
                "paid offer differs from the configured network, bond or provider",
            ));
        }
        trust.verify_enrollment(&offer.provider).map_err(|_| {
            PoolError::Invalid("paid offer enrollment does not satisfy the provider trust policy")
        })?;
    }
    Ok(trust)
}

fn fixed<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N]> {
    hellas_auth::hex::parse(value).map_err(|source| PoolError::Hex { field, source })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
    trust_store: PathBuf,
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
    trust_policy: String,
    offer: Option<Box<hellas_work::model::offer::SignedPaidOffer>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{PaidFixture, enrollment, signer};
    use hellas_work::model::offer::{PaidOffer, SignedPaidOffer};

    #[test]
    fn imported_offer_requires_independent_approval_and_checks_network_bond_transport_and_assurance()
     {
        let fixture = PaidFixture::new();
        let peer = iroh::SecretKey::from_bytes(&[4; 32]).public();
        let provider = enrollment(peer).0;
        let signed = SignedPaidOffer::sign(
            PaidOffer {
                provider: provider.clone(),
                proposal: fixture.proposal.clone(),
                addresses: vec![],
            },
            &signer(2),
        )
        .unwrap();
        let value = serde_json::json!({
            "work_config": "/config/work.json", "journal_root": "/state/client", "provider": peer,
            "bond": hex::encode(fixture.proposal.bond_edge().to_bytes()), "payment_coins": [hex::encode([1; 32])],
            "omission_bond": 601, "offer": signed, "trust_policy": "provider",
        });
        let entry: ProviderFile = serde_json::from_value(value.clone()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store = TrustPolicyStore::new(directory.path());
        assert!(trust(&entry, Assurance::ProducerSigned, &fixture.config, &store).is_err());
        let mut policy = crate::trust_policy::TrustPolicy {
            provider_genesis: hellas_rpc::ContentId::from_bytes([0; 32]),
            assurance: Assurance::ProducerSigned,
            environments: vec![fixture.config.work_policy.allowed_environment()],
            apple: None,
        };
        store
            .approve("provider", 0, policy.clone(), "independent pin".into())
            .unwrap();
        assert!(trust(&entry, Assurance::ProducerSigned, &fixture.config, &store).is_err());
        policy.provider_genesis = provider.content_id();
        store
            .approve("provider", 1, policy, "reviewed provider pin".into())
            .unwrap();
        assert_eq!(
            trust(&entry, Assurance::ProducerSigned, &fixture.config, &store)
                .unwrap()
                .expected_genesis,
            provider.content_id()
        );
        assert!(trust(&entry, Assurance::AppleAppAttest, &fixture.config, &store).is_err());
        let mut other_network = fixture.config.clone();
        other_network.chain.network = hellas_kernel::NetworkId::new("other-network").unwrap();
        assert!(trust(&entry, Assurance::ProducerSigned, &other_network, &store).is_err());
        for (field, replacement) in [
            ("bond", serde_json::json!(hex::encode([7; 32]))),
            (
                "provider",
                serde_json::json!(iroh::SecretKey::from_bytes(&[8; 32]).public()),
            ),
        ] {
            let mut altered = value.clone();
            altered[field] = replacement;
            let entry = serde_json::from_value(altered).unwrap();
            assert!(
                trust(&entry, Assurance::ProducerSigned, &fixture.config, &store).is_err(),
                "{field}"
            );
        }
        let mut no_pin = value;
        no_pin.as_object_mut().unwrap().remove("trust_policy");
        assert!(serde_json::from_value::<ProviderFile>(no_pin).is_err());
    }
}
