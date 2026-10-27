//! Provider bond provisioning.
//!
//! Provisioning checks that the bond and staked coins are unreserved, then
//! arms a finalized history floor and journals the signed offer. It reopens the
//! journal to verify durability before returning. Unanswered offers reserve their
//! staked coins as soon as revision one is signed.

use hellas_work::model::grant::records::check_grant_provider;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod error;
pub use error::ProvisionError;
type Result<T, E = ProvisionError> = std::result::Result<T, E>;
use hellas_chain::WorkBlocks;
use hellas_chain::domain::MAX_EDGE_LIFETIME_BLOCKS;
use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, NetworkId,
    Parties, PartyKeys, Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkStakeBondTerms,
};
use hellas_work::model::bundle::WorkChannelSetupBundleV2;
use hellas_work::model::setup::ProviderChannelPolicy;
use hellas_work::work_close::FinalizedBlocks;
use hellas_work::work_store::{Role, SetupScan, SetupStore};
use hellas_work::work_store::{SetupRecord, SetupState};

/// Checked inputs selected by the provider under its standing policy.
pub struct ProvisionOptions {
    /// Chain and journal identity.
    pub network: NetworkId,
    pub journal_root: PathBuf,
    pub policy: ProviderChannelPolicy,
    pub omission_bond: u64,
    pub payment_funding: Funding,
    pub peer: [u8; 32],
    /// The key this provider stakes and signs the bond with, read from
    /// the identity the operator already has and never made here.
    pub settlement_key: Secp256k1Signer,
    pub provider: hellas_rpc::ProviderEnrollmentBundle,
    pub addresses: Vec<String>,
    /// Principal authorized by the finalized funding delegation.
    pub client_principal: hellas_auth::authority::PrincipalId,
    /// The node key named by that delegation.
    pub client_node: Key,
    /// Whether returned stake remains delegated to this provider node.
    pub redelegate_payout: bool,
    /// The coins this provider stakes.
    pub stake_coins: Vec<CoinId>,
    /// Height the bond expires at, which is also the admission horizon of
    /// the channel it insures.
    pub bond_timeout: u64,
    /// What the bond's timeout returns to the staking provider.
    pub timeout_payout: u64,
    /// The largest job price this bond covers.
    pub max_job_price: u64,
}

/// Sign and journal an offer under an existing provider identity.
pub async fn provision_offer(
    options: ProvisionOptions,
    node: &hellas_chain::node::FullNode,
    authority: &hellas_work::node::NodeCoordinator,
    held: &[SetupState],
    write_started: &std::sync::atomic::AtomicBool,
) -> Result<Provisioned> {
    authority.check_provider(&options.provider).await?;
    let candidate = BondCandidate::plan(&options, authority.owner().await?)?;
    let offer = Offer::plan(&options, candidate, held)?;
    let view = tokio::time::timeout(std::time::Duration::from_secs(30), node.wait_ready())
        .await
        .map_err(|_| ProvisionError::NoFinalizedBlock)??;
    let floor = floor_of(&WorkBlocks::new(view.client()))
        .await?
        .ok_or(ProvisionError::NoFinalizedBlock)?;
    offer.journal(floor, write_started).await
}

/// One offer as the disk holds it, read back after it was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provisioned {
    /// The bond this journal is keyed to, which is what discovery names
    /// it by.
    pub bond_edge: EdgeId,
    /// The floor its history starts above, as retained.
    pub floor: SetupScan,
    pub offer: hellas_work::model::offer::SignedPaidOffer,
}

/// Deterministic bond inputs, checked before a signature is journaled.
struct BondCandidate {
    network: NetworkId,
    journal_root: PathBuf,
    bond_edge: EdgeId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    settlement_key: Secp256k1Signer,
}

impl BondCandidate {
    fn plan(
        options: &ProvisionOptions,
        owner: hellas_auth::authority::PrincipalId,
    ) -> Result<Self> {
        let network = options.network;
        let journal_root = options.journal_root.clone();
        // Maker is the provider and taker is the client, which is what
        // makes this signature the maker's: `propose_bond` refuses a bond
        // whose staking party this key is not.
        let provider = options.settlement_key.party_key();
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(
                PartyKeys::new(
                    Key::from_bytes(*owner.as_bytes()),
                    provider,
                    options.redelegate_payout.then_some(provider),
                ),
                PartyKeys::new(
                    Key::from_bytes(*options.client_principal.as_bytes()),
                    options.client_node,
                    Some(options.client_node),
                ),
            ),
            timeout: BlockHeight::new(options.bond_timeout),
            timeout_outputs: List::take(
                [Payout::delegated(
                    Key::from_bytes(*owner.as_bytes()),
                    options.redelegate_payout.then_some(provider),
                    options.timeout_payout,
                ); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: options.max_job_price,
        };
        let bond_funding = Funding::new(
            staked(&options.stake_coins)?,
            List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
        );
        let bond_edge = Tx::edge_id_of(&bond_funding, &Terms::work_stake_bond(bond_terms.clone()));
        Ok(Self {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            settlement_key: options.settlement_key.clone(),
        })
    }
}

/// One offer, decided before anything is dialled or written.
struct Offer {
    candidate: BondCandidate,
    policy: ProviderChannelPolicy,
    omission_bond: u64,
    payment_funding: Funding,
    peer: [u8; 32],
    provider: hellas_rpc::ProviderEnrollmentBundle,
    addresses: Vec<String>,
}

impl Offer {
    /// Reads the operator's answers, and refuses everything refusable
    /// without a chain.
    fn plan(
        options: &ProvisionOptions,
        candidate: BondCandidate,
        held: &[SetupState],
    ) -> Result<Self> {
        check_grant_provider(&options.provider)
            .map_err(|_| hellas_work::model::offer::PaidOfferError::Provider)?;
        if options.provider.genesis.statement.producer_public_key
            != hellas_auth::PublicKey::Secp256k1(options.settlement_key.party_key().to_bytes())
        {
            return Err(hellas_work::model::offer::PaidOfferError::Provider.into());
        }
        if options.addresses.len() > 16
            || options
                .addresses
                .iter()
                .any(|a| a.len() > 512 || a.parse::<std::net::SocketAddr>().is_err())
            || options.provider.canonical_bytes().len() > 32 * 1024
        {
            return Err(hellas_work::model::offer::PaidOfferError::Malformed.into());
        }
        refuse_offer_collisions(candidate.bond_edge, &candidate.bond_funding, held)?;
        Ok(Self {
            candidate,
            policy: options.policy.clone(),
            omission_bond: options.omission_bond,
            payment_funding: options.payment_funding.clone(),
            peer: options.peer,
            provider: options.provider.clone(),
            addresses: options.addresses.clone(),
        })
    }

    /// Journals revision 1, and returns only once a fresh open of the
    /// journal replays it.
    async fn journal(
        self,
        floor: SetupScan,
        write_started: &std::sync::atomic::AtomicBool,
    ) -> Result<Provisioned> {
        let timeout = self.candidate.bond_terms.timeout.get();
        if timeout <= floor.height {
            return Err(ProvisionError::ExpiredBond {
                timeout,
                height: floor.height,
            });
        }
        if timeout - floor.height > MAX_EDGE_LIFETIME_BLOCKS {
            return Err(ProvisionError::BondLifetime);
        }
        let Self {
            candidate,
            policy,
            omission_bond,
            payment_funding,
            peer,
            provider,
            addresses,
        } = self;
        let BondCandidate {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            settlement_key,
        } = candidate;
        let terms = Terms::work_stake_bond(bond_terms.clone());
        let auth = hellas_kernel::PartyAuth::signer(hellas_kernel::Auth::native(
            settlement_key.sign(Tx::open_hash(network, &bond_funding, &terms)),
        ));
        let proposal =
            WorkChannelSetupBundleV2::propose_bond(network, bond_funding, bond_terms, auth)
                .map_err(hellas_work::model::offer::PaidOfferError::from)?;
        let offer = hellas_work::model::offer::SignedPaidOffer::sign(
            hellas_work::model::offer::PaidOffer {
                provider,
                proposal,
                policy,
                omission_bond,
                payment_funding,
                addresses,
            },
            &settlement_key,
        )?;
        // A failed open, append or replay can leave a committed reservation.
        // Preflight reads and signatures above this boundary cannot do so.
        write_started.store(true, std::sync::atomic::Ordering::Release);
        {
            let mut store = open_provider_journal(&journal_root, network, bond_edge).await?;
            store
                .commit(
                    SetupRecord::Offer {
                        peer,
                        floor: Some(floor),
                        offer: Box::new(offer),
                    },
                    &Secp256k1Verifier::new(),
                )
                .await?;
        }

        // Reopen with the same replay and signature checks used at startup.
        let reopened = open_provider_journal(&journal_root, network, bond_edge).await?;
        let state = reopened.state();
        let (Some(1), Some(floor)) = (state.revision(), state.scan_armed()) else {
            return Err(ProvisionError::JournalReplay {
                root: journal_root,
                revision: state.revision(),
                floor: state.scan_armed().map(|scan| scan.height),
            });
        };
        let offer = state
            .offer()
            .map(|(_, offer)| offer.clone())
            .ok_or(ProvisionError::MissingProposal(bond_edge))?;
        Ok(Provisioned {
            bond_edge,
            floor,
            offer,
        })
    }
}

async fn open_provider_journal(
    root: &Path,
    network: NetworkId,
    bond_edge: EdgeId,
) -> Result<SetupStore> {
    SetupStore::open(
        root,
        network,
        bond_edge,
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .await
    .map_err(|source| ProvisionError::Journal {
        root: root.into(),
        source,
    })
}

/// Reservations include every journaled proposal, before either Open is posted.
fn refuse_offer_collisions(bond: EdgeId, funding: &Funding, held: &[SetupState]) -> Result<()> {
    let candidate_coins = funding_coins(funding);
    for state in held {
        let Some(bundle) = state.bundle() else {
            continue;
        };
        if bundle.bond_edge() == bond {
            return Err(ProvisionError::BondCollision(bond));
        }
        let reserved = funding_coins(bundle.bond_funding());
        if let Some(coin) = candidate_coins.intersection(&reserved).next() {
            return Err(ProvisionError::ReservedCoin {
                coin: *coin,
                bond: bundle.bond_edge(),
            });
        }
    }
    Ok(())
}

/// Every input one bond funding consumes, irrespective of party position.
fn funding_coins(funding: &Funding) -> BTreeSet<CoinId> {
    funding
        .maker()
        .iter()
        .chain(funding.taker().iter())
        .copied()
        .collect()
}

/// Returns the finalized tip and its payload, or `None` before the first block.
/// Both values must come from the same block to start a contiguous history.
async fn floor_of<B>(blocks: &B) -> Result<Option<SetupScan>>
where
    B: FinalizedBlocks + ?Sized,
{
    let Some(height) = blocks.latest_height().await? else {
        return Ok(None);
    };
    let Some(block) = blocks.block_at(height).await? else {
        return Ok(None);
    };
    Ok(Some(SetupScan {
        height: block.height,
        payload: block.payload,
    }))
}

/// Reads the coins one provider stakes.
fn staked(ids: &[CoinId]) -> Result<List<CoinId, MAX_PARTY_INPUTS>> {
    if ids.is_empty() || ids.len() > MAX_PARTY_INPUTS {
        return Err(ProvisionError::StakeCount(ids.len()));
    }
    let mut seen = BTreeSet::new();
    for coin in ids {
        if !seen.insert(*coin) {
            return Err(ProvisionError::DuplicateCoin(*coin));
        }
    }
    crate::work_config::coin_list(ids).ok_or(ProvisionError::StakeCount(ids.len()))
}

#[cfg(test)]
mod tests;
