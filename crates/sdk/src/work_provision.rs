//! Provider bond provisioning.
//!
//! Preview derives the bond without reading the chain or writing a journal.
//! Provisioning checks that the route, bond and staked coins are unreserved, then
//! arms a finalized history floor and journals the signed offer. It reopens the
//! journal to verify durability before returning. Unanswered offers reserve their
//! staked coins as soon as revision one is signed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod error;
pub use error::ProvisionError;
type Result<T, E = ProvisionError> = std::result::Result<T, E>;
use hellas_chain::client::VerifiedRemoteLightClient;
use hellas_chain::domain::MAX_EDGE_LIFETIME_BLOCKS;
use hellas_chain::{ConsensusInfo, ConsensusVerifier, WorkBlocks};
use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, Funding, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, NetworkId,
    Parties, Payout, Secp256k1Signer, Secp256k1Verifier, Terms, Tx, WorkStakeBondTerms,
};
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_work::work_close::FinalizedBlocks;
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint};
use hellas_work::work_store::{Role, SetupScan, SetupStore, discover_setups};
use tracing::{info, warn};

use crate::work_config::{WorkConfig, WorkRoute};

/// What an operator asks for when they make one offer.
pub struct ProvisionOptions {
    /// Chain, journal, route and execution-policy configuration.
    pub work_config: WorkConfig,
    /// The key this provider stakes and signs the bond with, read from
    /// the identity the operator already has and never made here.
    pub settlement_key: Secp256k1Signer,
    /// The client this bond names as taker.
    pub client: Key,
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

/// Compute the bond before the operator adds its bilateral route.
pub fn preview_bond(options: &ProvisionOptions) -> Result<EdgeId> {
    Ok(BondCandidate::plan(options)?.bond_edge)
}

/// Sign and journal an offer under an existing provider identity.
pub async fn provision_offer(options: ProvisionOptions) -> Result<Provisioned> {
    let candidate = BondCandidate::plan(&options)?;
    let offer = Offer::plan(&options, options.work_config.provider_policy(), candidate)?;
    offer.journal(finalized_floor(&options.work_config).await?)
}

/// One offer as the disk holds it, read back after it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provisioned {
    /// The bond this journal is keyed to, which is what discovery names
    /// it by.
    pub bond_edge: EdgeId,
    /// The floor its history starts above, as retained.
    pub floor: SetupScan,
}

/// Deterministic inputs shared by bond preview and provisioning.
struct BondCandidate {
    network: NetworkId,
    journal_root: PathBuf,
    bond_edge: EdgeId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    settlement_key: Secp256k1Signer,
}

impl BondCandidate {
    fn plan(options: &ProvisionOptions) -> Result<Self> {
        let network = options.work_config.chain.network;
        let journal_root = options.work_config.journal_root.clone();
        // Maker is the provider and taker is the client, which is what
        // makes this signature the maker's: `propose_bond` refuses a bond
        // whose staking party this key is not.
        let provider = options.settlement_key.party_key();
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(provider, options.client),
            timeout: BlockHeight::new(options.bond_timeout),
            timeout_outputs: List::take(
                [Payout::new(provider, options.timeout_payout); MAX_EDGE_OUTPUTS],
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
    admission: PaymentAdmission,
}

impl Offer {
    /// Reads the operator's answers, and refuses everything refusable
    /// without a chain.
    fn plan(
        options: &ProvisionOptions,
        policy: ProviderChannelPolicy,
        candidate: BondCandidate,
    ) -> Result<Self> {
        let route = route_for_candidate(
            &options.work_config,
            candidate.bond_edge,
            &candidate.bond_terms,
        )?;
        refuse_offer_collisions(&options.work_config, route, &candidate.bond_funding)?;
        Ok(Self {
            candidate,
            admission: PaymentAdmission::Admits(Box::new(policy)),
        })
    }

    /// Journals revision 1, and returns only once a fresh open of the
    /// journal replays it.
    fn journal(self, floor: SetupScan) -> Result<Provisioned> {
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
            admission,
        } = self;
        let BondCandidate {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            settlement_key,
        } = candidate;
        {
            let store = open_provider_journal(&journal_root, network, bond_edge)?;
            let mut endpoint = SetupEndpoint::new(store, settlement_key, admission);
            // Preserve the journal's immutable history floor on retry.
            if let Some(held) = endpoint.state().scan_armed() {
                info!(
                    height = held.height,
                    "this journal already holds its history floor, and a floor does not move",
                );
            } else {
                endpoint.arm_scan(floor)?;
            }
            endpoint.propose_bond(network, bond_funding, bond_terms)?;
        }

        // Reopen with the same replay and signature checks used at startup.
        let reopened = open_provider_journal(&journal_root, network, bond_edge)?;
        let state = reopened.state();
        let (Some(1), Some(floor)) = (state.revision(), state.scan_armed()) else {
            return Err(ProvisionError::JournalReplay {
                root: journal_root,
                revision: state.revision(),
                floor: state.scan_armed().map(|scan| scan.height),
            });
        };
        Ok(Provisioned { bond_edge, floor })
    }
}

fn open_provider_journal(root: &Path, network: NetworkId, bond_edge: EdgeId) -> Result<SetupStore> {
    SetupStore::open(
        root,
        network,
        bond_edge,
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .map_err(|source| ProvisionError::Journal {
        root: root.into(),
        source,
    })
}

/// Finds the candidate bond's route and checks its client before signing.
fn route_for_candidate<'config>(
    config: &'config WorkConfig,
    bond_edge: EdgeId,
    bond_terms: &WorkStakeBondTerms,
) -> Result<&'config WorkRoute> {
    let route = config
        .routes
        .iter()
        .find(|route| route.bond == bond_edge)
        .ok_or(ProvisionError::MissingRoute(bond_edge))?;
    check_client(route, bond_edge, bond_terms.parties.taker())?;
    Ok(route)
}

/// Checks route, bond and coin reservations before opening the candidate journal.
/// Unidentified or unreadable existing journals prevent provisioning.
fn refuse_offer_collisions(
    config: &WorkConfig,
    candidate: &WorkRoute,
    candidate_funding: &Funding,
) -> Result<()> {
    let root = &config.journal_root;
    let network = config.chain.network;
    let found = discover_setups(root, network).map_err(|source| ProvisionError::Journal {
        root: root.clone(),
        source,
    })?;
    if let Some(unnamed) = found.unidentified.into_iter().next() {
        return Err(ProvisionError::Unidentified {
            path: unnamed.path,
            source: unnamed.reason,
        });
    }

    let candidate_coins = funding_coins(candidate_funding);
    for held in found
        .setups
        .iter()
        .filter(|setup| setup.role == Role::Provider)
    {
        if held.bond_edge == candidate.bond {
            return Err(ProvisionError::BondCollision(candidate.bond));
        }
        let route = config
            .routes
            .iter()
            .find(|route| route.bond == held.bond_edge)
            .ok_or(ProvisionError::MissingRoute(held.bond_edge))?;
        let store = open_provider_journal(root, network, held.bond_edge)?;
        let bundle = store
            .state()
            .bundle()
            .ok_or(ProvisionError::MissingProposal(held.bond_edge))?;
        check_client(route, held.bond_edge, bundle.bond_terms().parties.taker())?;
        if route.peer == candidate.peer {
            return Err(ProvisionError::PeerCollision {
                peer: candidate.peer,
                bond: held.bond_edge,
            });
        }
        // Revision-one funding is reserved even before an executable Open exists.
        let reserved = funding_coins(bundle.bond_funding());
        if let Some(coin) = candidate_coins.intersection(&reserved).next() {
            return Err(ProvisionError::ReservedCoin {
                coin: *coin,
                bond: held.bond_edge,
            });
        }
    }
    Ok(())
}

fn check_client(route: &WorkRoute, bond: EdgeId, actual: Key) -> Result<()> {
    if route.client != actual {
        return Err(ProvisionError::WrongClient {
            bond,
            expected: route.client,
            actual,
        });
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

/// Reads one finalized block from the first configured validator that
/// answers, as the floor this setup's history starts above.
async fn finalized_floor(config: &WorkConfig) -> Result<SetupScan> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })?;
    for url in &config.validators {
        let client = match VerifiedRemoteLightClient::connect(url.clone(), verifier.clone()).await {
            Ok(client) => client,
            Err(error) => {
                warn!(validator = %url, %error, "a configured validator did not answer");
                continue;
            }
        };
        match floor_of(&WorkBlocks::new(client)).await {
            Ok(Some(floor)) => {
                info!(validator = %url, height = floor.height, "the history floor was read here");
                return Ok(floor);
            }
            Ok(None) => warn!(validator = %url, "a configured validator has finalized nothing"),
            Err(error) => warn!(validator = %url, %error, "a configured validator did not answer"),
        }
    }
    Err(ProvisionError::NoFinalizedBlock)
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
    let slots = std::array::from_fn(|i| {
        ids.get(i)
            .copied()
            .unwrap_or(CoinId::from_bytes([0; CoinId::LENGTH]))
    });
    Ok(List::take(slots, ids.len()))
}

#[cfg(test)]
mod tests;
