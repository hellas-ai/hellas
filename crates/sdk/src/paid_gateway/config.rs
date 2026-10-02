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
            let config = load_work_config(&p.work_config)?;
            let provider_trust = trust(&p, assurance, &config)?;
            let provider_addrs = if p.provider_addrs.is_empty() {
                match &p.provider_genesis {
                    EnrollmentSource::Offer(signed) => signed
                        .offer()
                        .addresses
                        .iter()
                        .map(|a| {
                            a.parse()
                                .map_err(|_| PoolError::Invalid("paid offer address"))
                        })
                        .collect::<Result<_>>()?,
                    EnrollmentSource::Pin(_) => vec![],
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
    config: &crate::work_config::WorkConfig,
) -> Result<hellas_client::ProviderTrustAnchor> {
    let expected_genesis = match &p.provider_genesis {
        EnrollmentSource::Pin(pin) => *pin,
        EnrollmentSource::Offer(signed) => {
            signed
                .check()
                .map_err(|_| PoolError::Invalid("paid offer signature or bond is invalid"))?;
            let offer = signed.offer();
            if offer.proposal.network() != config.chain.network
                || offer.proposal.bond_edge().to_bytes() != fixed::<32>("bond", &p.bond)?
                || offer
                    .provider
                    .grant_transport()
                    .map_err(|_| PoolError::Invalid("paid offer transport"))?
                    != *p.provider.as_bytes()
            {
                return Err(PoolError::Invalid(
                    "paid offer differs from the configured network, bond or provider",
                ));
            }
            offer.provider.content_id()
        }
    };
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
    let trust = hellas_client::ProviderTrustAnchor {
        expected_genesis,
        required_assurance: assurance,
        apple_app_attest,
    };
    if let EnrollmentSource::Offer(signed) = &p.provider_genesis {
        trust
            .verify_enrollment(&signed.offer().provider)
            .map_err(|_| {
                PoolError::Invalid(
                    "paid offer enrollment does not satisfy the provider trust policy",
                )
            })?;
    }
    Ok(trust)
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
    provider_genesis: EnrollmentSource,
    apple_app_id: Option<String>,
    #[serde(default)]
    apple_cd_hashes: Vec<String>,
}

/// The field is mandatory: either an independently obtained pin or the signed
/// enrollment-bearing offer exported by provider provisioning.
#[derive(Deserialize)]
#[serde(untagged)]
enum EnrollmentSource {
    Pin(ContentId),
    Offer(Box<hellas_rpc::protocol::work_offer::SignedPaidOffer>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{PaidFixture, enrollment, signer};
    use hellas_rpc::protocol::work_offer::{PaidOffer, SignedPaidOffer};

    #[test]
    fn imported_offer_derives_the_pin_and_checks_network_bond_transport_and_assurance() {
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
            "omission_bond": 601, "provider_genesis": signed,
        });
        let entry: ProviderFile = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            trust(&entry, Assurance::ProducerSigned, &fixture.config)
                .unwrap()
                .expected_genesis,
            provider.content_id()
        );
        assert!(trust(&entry, Assurance::AppleAppAttest, &fixture.config).is_err());
        let mut other_network = fixture.config.clone();
        other_network.chain.network = hellas_kernel::NetworkId::new("other-network").unwrap();
        assert!(trust(&entry, Assurance::ProducerSigned, &other_network).is_err());
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
                trust(&entry, Assurance::ProducerSigned, &fixture.config).is_err(),
                "{field}"
            );
        }
        let mut no_pin = value;
        no_pin.as_object_mut().unwrap().remove("provider_genesis");
        assert!(serde_json::from_value::<ProviderFile>(no_pin).is_err());
    }
}
