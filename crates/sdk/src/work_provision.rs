//! Making the offers a fresh provider has nothing to serve without.
//!
//! `WorkRunner::discover` answers `WorkSetup` from the setup journals it
//! finds under the configured work root, and finding is the whole of what
//! it does. A correctly configured provider with no journal therefore
//! refuses every client that dials it, and the paid path is unreachable
//! from a clean install. This is the operator's step that writes them.
//!
//! # The order is the journal's, and none of its rules are here
//!
//! Three library calls. [`SetupStore`] is opened as the provider's half
//! of one bond, the immutable history floor is armed, and
//! [`SetupEndpoint::propose_bond`] signs the stake and journals it before
//! there is anything to export.
//!
//! Arming is first because it has to be: the setup state refuses
//! "recording revision 1 before arming its scan floor", so the floor is
//! not a preparation this command chose to do early but the step every
//! later one is refused before. The floor is a finalized height and the
//! payload digest at it, and the setup's own history must name that
//! digest as the parent of its first block. So it is read from a
//! validator rather than written down by an operator: a floor naming a
//! block this chain does not have is a setup whose history can never be
//! contiguous, and nothing later would say so out loud.
//!
//! # Exit means durable
//!
//! [`SetupStore::commit`] fsyncs a revision before it returns, and this
//! command still reopens the journal and replays it before printing
//! anything. That reopen is the one `WorkRunner::discover` will do, run
//! early: an operator told the offer exists has been told about the disk,
//! and about a file whose exclusive lock is already free for the runner
//! to take.
//!
//! # One recourse backs one route
//!
//! A provider offer reserves a route, a bond, and every coin funding that
//! bond. A second offer is safe only when all three are disjoint from every
//! provider offer already under the root. Existing peers come from the
//! durable route table, while existing coins come from the bond funding in
//! each retained setup bundle. Revision one is enough: it holds the funding
//! before a client has answered, while [`SetupState::funding_coins`] is still
//! empty because there is no executable Open yet.
//!
//! Discovery, route agreement, and funding comparison all happen while the
//! candidate is only a value. The candidate journal is not opened until
//! afterwards, so every collision is refused before a floor is written or a
//! bond signature is made.
//!
//! # What the operator chooses, and what is built
//!
//! Every number in the bond is the operator's and this command invents
//! none of them. Two parts of the shape are not choices: a stake bond is
//! funded by its maker alone, so the taker's side of the funding is
//! empty, and its timeout pays the staking party and nobody else, so
//! there is one payout and it names the provider's own key. A second
//! payout to that same party would only raise the close cost the payout
//! has to clear. The kernel checks the rest when the Open reaches it —
//! that the payout total is the edge's close value, that the price cap
//! covers a job, that the timeout is ahead of the block including it —
//! and re-spelling any of that here would be a second answer to a
//! question consensus already answers.
//!
//! [`SetupState::funding_coins`]: hellas_work::work_store::SetupState::funding_coins

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
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
type CliResult<T> = anyhow::Result<T>;

/// What an operator asks for when they make one offer.
pub struct ProvisionOptions {
    /// The loaded paid-work configuration, not the path it came from. It
    /// carries the network the bond is bound to, the root the journal is
    /// written under, the validators the floor is read from, and the
    /// artifact the provider's policy rests on.
    pub work_config: WorkConfig,
    /// The key this provider stakes and signs the bond with, read from
    /// the identity the operator already has and never made here.
    pub settlement_key: Secp256k1Signer,
    /// The client this bond names as taker, hex-encoded.
    pub client: String,
    /// The coins this provider stakes, hex-encoded.
    pub stake_coins: Vec<String>,
    /// Height the bond expires at, which is also the admission horizon of
    /// the channel it insures.
    pub bond_timeout: u64,
    /// What the bond's timeout returns to the staking provider.
    pub timeout_payout: u64,
    /// The largest job price this bond covers.
    pub max_job_price: u64,
    /// Print the deterministic bond edge and stop before any external read or write.
    pub print_bond_only: bool,
}

/// Makes one offer, and says where it is.
///
/// # Errors
///
/// A configuration with no matching bilateral route, a route, bond, or funding coin already reserved by another offer,
/// a key or coin id that is not one, no configured validator with a finalized
/// block to read a floor from, and whatever the setup journal says about the
/// revision it refused or could not make durable.
pub async fn run_provision(options: ProvisionOptions) -> CliResult<()> {
    // The candidate is the one source of the bond edge for both preview and
    // provisioning.  Keep this before evidence, routing, validators and the
    // journal: the preview exists so an operator can put this value into the
    // route table those later steps require.
    let candidate = BondCandidate::plan(&options)?;
    if options.print_bond_only {
        println!("bond_edge: {}", hex::encode(candidate.bond_edge.to_bytes()));
        return Ok(());
    }
    let offer = Offer::plan(&options, options.work_config.provider_policy(), candidate)?;
    // Dialled after every refusal that can be made without a chain, and
    // before the journal exists: a floor is the first thing written into
    // it, so a run that cannot read one leaves no half-made offer behind.
    let made = offer.journal(finalized_floor(&options.work_config).await?)?;

    println!(
        "offer journaled: bond {} under {}",
        hex::encode(made.bond_edge.to_bytes()),
        options.work_config.journal_root.display(),
    );
    // The floor read back out of the journal rather than the one just
    // dialled, because those differ on a retry and the durable one is the
    // one this setup's history will be measured against.
    println!(
        "history floor: finalized height {} with payload {}",
        made.floor.height,
        hex::encode(made.floor.payload),
    );
    Ok(())
}

/// Compute the bond before the operator adds its bilateral route.
pub fn preview_bond(options: &ProvisionOptions) -> CliResult<EdgeId> {
    Ok(BondCandidate::plan(options)?.bond_edge)
}

/// Sign and journal an offer under an existing provider identity.
pub async fn provision_offer(options: ProvisionOptions) -> CliResult<Provisioned> {
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

/// The deterministic bond inputs, built without evidence, routing, a chain,
/// or a journal.
///
/// Preview and real provisioning both pass through this value. In particular,
/// the real path does not recompute the edge after printing it, so a preview
/// cannot drift from the offer later signed.
struct BondCandidate {
    network: NetworkId,
    journal_root: PathBuf,
    bond_edge: EdgeId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    settlement_key: Secp256k1Signer,
}

impl BondCandidate {
    fn plan(options: &ProvisionOptions) -> CliResult<Self> {
        let network = options.work_config.chain.network;
        let journal_root = options.work_config.journal_root.clone();
        // Maker is the provider and taker is the client, which is what
        // makes this signature the maker's: `propose_bond` refuses a bond
        // whose staking party this key is not.
        let provider = options.settlement_key.party_key();
        let bond_terms = WorkStakeBondTerms {
            parties: Parties::new(
                provider,
                Key::from_bytes(fixed::<{ Key::LENGTH }>("--client", &options.client)?),
            ),
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
    network: NetworkId,
    journal_root: PathBuf,
    bond_edge: EdgeId,
    bond_funding: Funding,
    bond_terms: WorkStakeBondTerms,
    admission: PaymentAdmission,
    settlement_key: Secp256k1Signer,
}

impl Offer {
    /// Reads the operator's answers, and refuses everything refusable
    /// without a chain.
    fn plan(
        options: &ProvisionOptions,
        policy: ProviderChannelPolicy,
        candidate: BondCandidate,
    ) -> CliResult<Self> {
        let admission = PaymentAdmission::Admits(Box::new(policy));
        let BondCandidate {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            settlement_key,
        } = candidate;
        let route = route_for_candidate(&options.work_config, bond_edge, &bond_terms)?;
        refuse_offer_collisions(&options.work_config, route, &bond_funding)?;
        Ok(Self {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            admission,
            settlement_key,
        })
    }

    /// Journals revision 1, and returns only once a fresh open of the
    /// journal replays it.
    fn journal(self, floor: SetupScan) -> CliResult<Provisioned> {
        let timeout = self.bond_terms.timeout.get();
        anyhow::ensure!(
            timeout > floor.height,
            "bond timeout must be after finalized height {}",
            floor.height
        );
        anyhow::ensure!(
            timeout - floor.height <= MAX_EDGE_LIFETIME_BLOCKS,
            "bond timeout exceeds the chain maximum lifetime"
        );
        let Self {
            network,
            journal_root,
            bond_edge,
            bond_funding,
            bond_terms,
            admission,
            settlement_key,
        } = self;
        {
            let store = open_provider_journal(&journal_root, network, bond_edge)?;
            let mut endpoint = SetupEndpoint::new(store, settlement_key, admission);
            // The floor is immutable and the store writes exactly one arm
            // of it, so a run that arms and then fails keeps the height
            // its successor starts from rather than moving it.
            if let Some(held) = endpoint.state().scan_armed() {
                info!(
                    height = held.height,
                    "this journal already holds its history floor, and a floor does not move",
                );
            } else {
                endpoint
                    .arm_scan(floor)
                    .context("failed to make this setup's immutable history floor durable")?;
            }
            endpoint
                .propose_bond(network, bond_funding, bond_terms)
                .context("failed to sign and journal the bond proposal")?;
        }

        // The journal is closed above, so this is a second process's view
        // of it: the same replay and the same signature checks the runner
        // runs, before an operator is told there is anything to run them
        // on.
        let reopened = open_provider_journal(&journal_root, network, bond_edge)?;
        let state = reopened.state();
        let (Some(1), Some(floor)) = (state.revision(), state.scan_armed()) else {
            bail!(
                "the journal under {} replays as revision {:?} over floor {:?}, not the armed \
                 proposal that was just written",
                journal_root.display(),
                state.revision(),
                state.scan_armed().map(|scan| scan.height),
            );
        };
        Ok(Provisioned { bond_edge, floor })
    }
}

fn open_provider_journal(
    root: &Path,
    network: NetworkId,
    bond_edge: EdgeId,
) -> CliResult<SetupStore> {
    SetupStore::open(
        root,
        network,
        bond_edge,
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .with_context(|| {
        format!(
            "failed to open the provider setup journal for bond {} under {}",
            hex::encode(bond_edge.to_bytes()),
            root.display(),
        )
    })
}

/// Returns the configured bilateral route the candidate would occupy.
///
/// The bond is derived from the exact funding and terms first. Matching by
/// that canonical value means a route cannot be selected by insertion order,
/// and checking the client here refuses a journal the next startup would
/// reject before the provider signs it.
fn route_for_candidate<'config>(
    config: &'config WorkConfig,
    bond_edge: EdgeId,
    bond_terms: &WorkStakeBondTerms,
) -> CliResult<&'config WorkRoute> {
    let Some(route) = config.routes.iter().find(|route| route.bond == bond_edge) else {
        bail!(
            "bond {} has no bilateral route in this work configuration; an offer is signed only \
             after its peer, bond, and client are named together",
            hex::encode(bond_edge.to_bytes()),
        );
    };
    let client = bond_terms.parties.taker();
    if route.client != client {
        bail!(
            "route for peer {:#} expects client {}, but candidate bond {} names {} as its taker",
            route.peer,
            hex::encode(route.client.to_bytes()),
            hex::encode(bond_edge.to_bytes()),
            hex::encode(client.to_bytes()),
        );
    }
    Ok(route)
}

/// Refuses every collision before the candidate journal is opened.
///
/// An existing bond is named by discovery, its peer is named by the durable
/// route table, and its funding is named by the retained bundle. Failure to
/// recover any one of those facts is a refusal: absence of evidence is not
/// evidence that the candidate is disjoint.
fn refuse_offer_collisions(
    config: &WorkConfig,
    candidate: &WorkRoute,
    candidate_funding: &Funding,
) -> CliResult<()> {
    let root = &config.journal_root;
    let network = config.chain.network;
    let found = discover_setups(root, network).with_context(|| {
        format!(
            "failed to enumerate the work journals under {}",
            root.display(),
        )
    })?;
    for unnamed in &found.unidentified {
        warn!(
            path = %unnamed.path.display(),
            reason = %unnamed.reason,
            "a setup journal under the work root could not be named",
        );
    }
    if let Some(unnamed) = found.unidentified.first() {
        bail!(
            "setup journal {} cannot be identified, so a new offer cannot be proved disjoint: {}",
            unnamed.path.display(),
            unnamed.reason,
        );
    }

    let candidate_coins = funding_coins(candidate_funding);
    for held in found
        .setups
        .iter()
        .filter(|setup| setup.role == Role::Provider)
    {
        if held.bond_edge == candidate.bond {
            bail!(
                "candidate bond {} collides with a provider offer already under {}",
                hex::encode(candidate.bond.to_bytes()),
                root.display(),
            );
        }
        let Some(route) = config
            .routes
            .iter()
            .find(|route| route.bond == held.bond_edge)
        else {
            bail!(
                "provider offer over bond {} under {} has no configured route, so the candidate \
                 route cannot be proved disjoint",
                hex::encode(held.bond_edge.to_bytes()),
                root.display(),
            );
        };
        let store = open_provider_journal(root, network, held.bond_edge)?;
        let Some(bundle) = store.state().bundle() else {
            bail!(
                "provider offer over bond {} was discovered without a retained revision",
                hex::encode(held.bond_edge.to_bytes()),
            );
        };
        let held_client = bundle.bond_terms().parties.taker();
        if route.client != held_client {
            bail!(
                "route for peer {:#} expects client {}, but provider offer over bond {} names {} \
                 as its taker",
                route.peer,
                hex::encode(route.client.to_bytes()),
                hex::encode(held.bond_edge.to_bytes()),
                hex::encode(held_client.to_bytes()),
            );
        }
        if route.peer == candidate.peer {
            bail!(
                "candidate route peer {:#} collides with the provider offer over bond {}",
                candidate.peer,
                hex::encode(held.bond_edge.to_bytes()),
            );
        }
        // The retained revision's own staked funding, not the executable
        // Opens: the provider signed these coins when it made the offer, so
        // they are promised from that moment, while `funding_coins` answers
        // from Opens that do not exist until the client countersigns. Read
        // from there, every offer no client has answered would look like it
        // reserved nothing.
        let reserved = funding_coins(bundle.bond_funding());
        if let Some(coin) = candidate_coins.intersection(&reserved).next() {
            bail!(
                "candidate stake coin {} is already reserved by provider offer over bond {}",
                hex::encode(coin.to_bytes()),
                hex::encode(held.bond_edge.to_bytes()),
            );
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

/// Reads one finalized block from the first configured validator that
/// answers, as the floor this setup's history starts above.
async fn finalized_floor(config: &WorkConfig) -> CliResult<SetupScan> {
    let verifier = ConsensusVerifier::new(&ConsensusInfo {
        validators: config.validators.clone(),
        threshold_identity: config.chain.threshold_identity.clone(),
        network_id: config.chain.network.as_str().to_owned(),
    })
    .context("the configured threshold identity is not usable")?;
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
    bail!("no configured validator answered with a finalized block to floor this offer at")
}

/// Returns the finalized tip as a scan floor, or `None` before anything
/// is finalized.
///
/// The height and the payload come from one block rather than from two
/// reads, because the setup's first history block must name that exact
/// payload as its parent.
async fn floor_of<B>(blocks: &B) -> CliResult<Option<SetupScan>>
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
fn staked(ids: &[String]) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes(fixed::<{ CoinId::LENGTH }>("--stake-coin", id)?);
    }
    // The zip above stops at the shorter side, so a list the array cannot
    // hold is refused here rather than silently staking the first four of
    // it.
    List::new(slots, ids.len()).with_context(|| {
        format!(
            "--stake-coin names {} coins, and one party funds an open with at most \
             {MAX_PARTY_INPUTS}",
            ids.len(),
        )
    })
}

/// Reads exactly `N` bytes of hex, or says which flag was not that.
fn fixed<const N: usize>(flag: &str, value: &str) -> CliResult<[u8; N]> {
    let bytes =
        hex::decode(value).with_context(|| format!("{flag} {value:?} is not hex-encoded bytes"))?;
    let Ok(fixed) = <[u8; N]>::try_from(bytes.as_slice()) else {
        bail!(
            "{flag} {value:?} is {} bytes, and {N} are wanted",
            bytes.len()
        );
    };
    Ok(fixed)
}

#[cfg(test)]
mod tests;
