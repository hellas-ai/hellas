use hellas_authority::model::grant::records::check_grant_provider;
use std::path::{Path, PathBuf};

type Result<T, E = ProvisionError> = std::result::Result<T, E>;
use hellas_chain::WorkBlocks;
use hellas_chain::domain::MAX_EDGE_LIFETIME_BLOCKS;
use hellas_channel::model::bundle::WorkChannelSetupBundleV2;
use hellas_channel::model::setup::ProviderChannelPolicy;
use hellas_channel::work_close::FinalizedBlocks;
use hellas_channel::work_store::{Role, SetupScan, SetupStore};
use hellas_channel::work_store::{SetupRecord, SetupState};
use hellas_kernel::{
    BlockHeight, Funding, List, MAX_EDGE_OUTPUTS, Parties, PartyKeys, Payout, Terms, Tx,
    WorkStakeBondTerms,
};

use super::*;
use hellas_chain::LightClient as _;
use hellas_channel::model::offer::{SignedPaidOffer, request_digest};
use hellas_kernel::{CoinId, Key, MAX_PARTY_INPUTS};
use hellas_rpc::pb::work::{
    OfferGranted, OfferRefusalCode, OfferRefused, PaymentEdgeValues, Quote, RequestOfferRequest,
    RequestOfferResponse, request_offer_response::Outcome,
};
use std::collections::BTreeSet;

pub(super) struct OfferAllocator {
    pub needs_restart: std::sync::atomic::AtomicBool,
    pub config: WorkRunnerConfig,
    pub node: FullNode,
    pub authority: hellas_authority::node::NodeCoordinator,
    pub provider: hellas_rpc::ProviderEnrollmentBundle,
    pub addresses: Vec<String>,
    pub registry: Arc<tokio::sync::Mutex<BTreeMap<EdgeId, SetupService>>>,
    pub adopt: tokio::sync::mpsc::Sender<SetupClock>,
    pub mount: MountedSetup,
}

type OfferCall = (
    RequestOfferRequest,
    TransportContext,
    oneshot::Sender<Result<RequestOfferResponse, WireStatus>>,
);

pub(super) struct AutomaticOffers {
    calls: tokio::sync::mpsc::Sender<OfferCall>,
    worker: Mutex<Option<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)>>,
    registry: Arc<tokio::sync::Mutex<BTreeMap<EdgeId, SetupService>>>,
}

impl std::fmt::Debug for AutomaticOffers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutomaticOffers").finish_non_exhaustive()
    }
}

impl AutomaticOffers {
    pub fn spawn(allocator: OfferAllocator) -> Self {
        let (calls, mut pending) = tokio::sync::mpsc::channel::<OfferCall>(16);
        let (stop, mut stopped) = oneshot::channel();
        let registry = allocator.registry.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    call = pending.recv() => match call {
                        Some((request, context, reply)) => {
                            // Once accepted, finish durable allocation even if the
                            // RPC caller disconnects. Only this worker allocates.
                            let result = Box::pin(allocator.request(request, context, &allocator.mount)).await;
                            let _ = reply.send(result);
                        }
                        None => break,
                    },
                }
            }
        });
        Self {
            calls,
            worker: Mutex::new(Some((stop, task))),
            registry,
        }
    }

    pub async fn request(
        &self,
        request: RequestOfferRequest,
        context: TransportContext,
    ) -> Result<RequestOfferResponse, WireStatus> {
        let (reply, answer) = oneshot::channel();
        self.calls
            .try_send((request, context, reply))
            .map_err(unavailable)?;
        answer.await.map_err(unavailable)?
    }

    pub async fn shutdown(&self) -> Result<(), MountError> {
        let worker = self.worker.lock().map_err(|_| MountError::Poisoned)?.take();
        if let Some((stop, task)) = worker {
            let _ = stop.send(());
            task.await.map_err(MountError::OfferWorker)?;
        }
        self.registry.lock().await.clear();
        Ok(())
    }
}

fn invalid() -> WireStatus {
    WireStatus::new(
        hellas_wire::WireCode::InvalidArgument,
        "invalid offer request",
    )
}
fn unavailable(error: impl std::fmt::Display) -> WireStatus {
    WireStatus::new(hellas_wire::WireCode::Unavailable, error.to_string())
}
fn refused(code: OfferRefusalCode, required: u64) -> RequestOfferResponse {
    RequestOfferResponse {
        outcome: Some(Outcome::Refused(OfferRefused {
            code: code as i32,
            required,
        })),
    }
}
fn granted(offer: &SignedPaidOffer) -> Result<RequestOfferResponse, WireStatus> {
    Ok(RequestOfferResponse {
        outcome: Some(Outcome::Granted(OfferGranted {
            offer: offer.encode().map_err(unavailable)?,
        })),
    })
}

fn quote(
    policy: &ProviderChannelPolicy,
    omission_bond: u64,
) -> Result<RequestOfferResponse, WireStatus> {
    let values = policy.expected_payment_values;
    let required = values
        .value()
        .checked_add(values.reserve())
        .ok_or_else(invalid)?;
    let fees = values.close_fees();
    let bytes = hellas_rpc::protocol::value::encode_bounded(
        &policy,
        hellas_authority::model::grant::records::MAX_OFFER_BYTES,
    )
    .map_err(unavailable)?;
    Ok(RequestOfferResponse {
        outcome: Some(Outcome::Quote(Quote {
            provider_channel_policy: bytes,
            required: Some(PaymentEdgeValues {
                value: values.value(),
                reserve: values.reserve(),
                base_fee: fees.base(),
                slot_fee: fees.slot(),
                proof_fee: fees.proof(),
                lifetime_fee: fees.lifetime(),
            }),
            omission_bond,
            funding_value: required,
        })),
    })
}

impl OfferAllocator {
    pub async fn request(
        &self,
        request: RequestOfferRequest,
        context: TransportContext,
        mount: &MountedSetup,
    ) -> Result<RequestOfferResponse, WireStatus> {
        if self
            .needs_restart
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(unavailable("offer allocation requires journal recovery"));
        }
        let peer = context.vouched_peer().ok_or_else(invalid)?.0;
        let exporter = context.open_exporter.ok_or_else(invalid)?;
        let principal: [u8; 33] = request
            .client_principal
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let key: [u8; 33] = request
            .client_key
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        let signature: [u8; 64] = request
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| invalid())?;
        if request.funding_coins.len() > MAX_PARTY_INPUTS
            || request.funding_coins.iter().any(|c| c.len() != 32)
        {
            return Err(invalid());
        }
        let coins = request
            .funding_coins
            .iter()
            .map(|c| CoinId::from_bytes(c.as_slice().try_into().expect("checked coin")))
            .collect::<Vec<_>>();
        if coins.iter().collect::<BTreeSet<_>>().len() != coins.len() {
            return Err(invalid());
        }
        hellas_auth::signature::verify_digest_signature(
            &hellas_auth::PublicKey::Secp256k1(key),
            &hellas_auth::Signature::Secp256k1(signature),
            request_digest(
                self.config.network,
                self.provider.content_id(),
                &request,
                &exporter,
            ),
        )
        .map_err(|_| invalid())?;

        // Serialize policy selection, reservation and adoption. A runner tick can
        // advance a journal while this lock prevents a second allocation.
        let mut registry = self.registry.lock().await;
        let current = self.authority.paid_policy().await.map_err(unavailable)?;
        let Some(current) = current else {
            return Ok(refused(OfferRefusalCode::NoPolicy, 0));
        };
        current.policy.check().map_err(unavailable)?;
        if current.policy.offers.bond_lifetime_blocks
            > hellas_chain::domain::MAX_EDGE_LIFETIME_BLOCKS
        {
            return Err(unavailable("offer lifetime exceeds chain maximum"));
        }
        let policy = current.provider_policy(self.config.network);
        let values = policy.expected_payment_values;
        // The node's consensus fee schedule is fixed. Reject terms that could
        // quote a capacity the finalized Open cannot produce.
        if values.close_fees() != hellas_chain::domain::KERNEL_FEES || values.reserve() != 0 {
            return Err(unavailable("paid policy differs from chain fees"));
        }
        let required = values
            .value()
            .checked_add(values.reserve())
            .ok_or_else(invalid)?;
        if coins.is_empty() && registry.is_empty() {
            return quote(&policy, current.policy.offers.omission_bond);
        }
        let view = self.node.view().map_err(unavailable)?;
        let chain = view.client();
        let tip = chain
            .get_latest_block()
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("no finalized state"))?;
        let mut held = Vec::with_capacity(registry.len());
        let mut open = 0;
        let mut reserved = BTreeSet::new();
        for service in registry.values() {
            let state = service.state().await.map_err(unavailable)?;
            let bundle = state
                .bundle()
                .ok_or_else(|| unavailable("offer journal has no proposal"))?;
            let snapshot = chain
                .work_channel_snapshot(WorkChannelQuery {
                    bond_edge: bundle.bond_edge(),
                    payment_edge: bundle.payment_edge(),
                    funding: state.funding_coins(),
                })
                .await
                .map_err(unavailable)?
                .ok_or_else(|| unavailable("finalized offer snapshot unavailable"))?;
            let released = matches!(
                state.end(),
                Some(
                    hellas_channel::work_store::SetupEnd::Complete
                        | hellas_channel::work_store::SetupEnd::Aborted(
                            hellas_channel::work_store::SetupAbort::BondReclaimed
                        )
                )
            );
            let live = snapshot.bond().is_some()
                || snapshot.payment().is_some()
                || (!released && snapshot.block().height < bundle.bond_terms().timeout.get());
            if live {
                open += 1;
                reserved.extend(bundle.bond_funding().maker().iter().copied());
                let taker = bundle.bond_terms().parties.taker();
                if taker.owner().to_bytes() == principal || taker.signer().to_bytes() == key {
                    if taker.owner().to_bytes() != principal || taker.signer().to_bytes() != key {
                        return Err(invalid());
                    }
                    // A settled payment cannot be resumed. Its still-live bond
                    // continues to occupy this client's stake allowance, so
                    // refuse before a quote could trigger another owner spend.
                    if state
                        .origin()
                        .is_some_and(|origin| snapshot.block().height >= origin.height)
                        && snapshot.payment().is_none()
                    {
                        return Ok(refused(OfferRefusalCode::NoStakeAvailable, 0));
                    }
                    // Payment has already consumed its funding on resume. Returning
                    // the original offer neither allocates stake nor changes its peer.
                    let (_, offer) = state
                        .offer()
                        .ok_or_else(|| unavailable("missing retained offer"))?;
                    if coins.is_empty() {
                        return quote(&offer.offer().policy, offer.offer().omission_bond);
                    }
                    return granted(offer);
                }
                held.push(state);
            }
        }
        if coins.is_empty() {
            return quote(&policy, current.policy.offers.omission_bond);
        }
        let owned = chain
            .get_coins_by_owner(Key::from_bytes(principal).into())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("client ownership unavailable"))?;
        let delegated = chain
            .get_coins_by_delegate(Key::from_bytes(key).into())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("client delegation unavailable"))?;
        if owned.snapshot.payload != delegated.snapshot.payload
            || owned.snapshot.state_root != delegated.snapshot.state_root
        {
            return Err(unavailable(
                "client funding snapshot advanced; retry offer request",
            ));
        }
        let mut total = 0_u64;
        for coin in &coins {
            let id: hellas_chain::domain::ObjectId = coin.to_bytes().into();
            let value = owned
                .coins
                .iter()
                .find(|(held, _)| *held == id)
                .map(|(_, value)| *value);
            if value.is_none()
                || !delegated
                    .coins
                    .iter()
                    .any(|(held, delegated_value)| *held == id && Some(*delegated_value) == value)
            {
                return Ok(refused(OfferRefusalCode::NeedsFunding, required));
            }
            total = total
                .checked_add(value.ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
        }
        if total != required {
            return Ok(refused(OfferRefusalCode::NeedsFunding, required));
        }
        if open >= current.policy.offers.max_open_offers {
            return Ok(refused(OfferRefusalCode::OfferLimit, 0));
        }
        let owner = self.authority.owner().await.map_err(unavailable)?;
        let listing = chain
            .get_coins_by_delegate(self.config.settlement_key.party_key().into())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("delegated stake unavailable"))?;
        let owned_stake = chain
            .get_coins_by_owner(Key::from_bytes(*owner.as_bytes()).into())
            .await
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("stake ownership unavailable"))?;
        if owned_stake.snapshot.payload != listing.snapshot.payload
            || owned_stake.snapshot.state_root != listing.snapshot.state_root
        {
            return Err(unavailable("stake snapshot advanced; retry offer request"));
        }
        let mut available = Vec::new();
        for (id, value) in listing.coins {
            let coin_id = CoinId::from_bytes(id.0);
            if !reserved.contains(&coin_id)
                && value > 0
                && value <= current.policy.offers.max_stake_per_client
                && owned_stake
                    .coins
                    .iter()
                    .any(|(held, owned_value)| *held == id && *owned_value == value)
            {
                available.push((coin_id, value));
            }
        }
        // A positive stake insures the protocol's price cap; omission collateral
        // belongs to the payment edge. One eligible coin is the fewest possible.
        available.sort_by_key(|(id, value)| (*value, *id));
        let Some((stake, stake_value)) = available.first().copied() else {
            return Ok(refused(OfferRefusalCode::NoStakeAvailable, 0));
        };
        let timeout = tip
            .height
            .checked_add(current.policy.offers.bond_lifetime_blocks)
            .ok_or_else(invalid)?;
        let adoption = self.adopt.try_reserve().map_err(unavailable)?;
        let provisioned = provision_offer(
            ProvisionOptions {
                network: self.config.network,
                journal_root: self.config.journal_root.clone(),
                policy,
                omission_bond: current.policy.offers.omission_bond,
                peer,
                payment_funding: hellas_kernel::Funding::new(
                    crate::work_config::coin_list(&coins).ok_or_else(invalid)?,
                    hellas_kernel::List::empty(CoinId::from_bytes([0; 32])),
                ),
                settlement_key: self.config.settlement_key.clone(),
                provider: self.provider.clone(),
                addresses: self.addresses.clone(),
                client_principal: hellas_auth::authority::PrincipalId::from_public_key(
                    hellas_auth::PublicKey::P256(principal),
                )
                .map_err(|_| invalid())?,
                client_node: Key::from_bytes(key),
                redelegate_payout: current.policy.offers.redelegate_payout,
                stake_coins: vec![stake],
                bond_timeout: timeout,
                timeout_payout: stake_value,
                max_job_price: current.policy.payment_policy.fixed_price,
            },
            &self.node,
            &self.authority,
            &held,
            &self.needs_restart,
        )
        .await
        .map_err(unavailable)?;
        let store = SetupStore::open(
            &self.config.journal_root,
            self.config.network,
            provisioned.bond_edge,
            Role::Provider,
            &Secp256k1Verifier::new(),
        )
        .await
        .map_err(unavailable)?;
        let clock = WorkRunner::adopt_setup(&self.config, store, mount).map_err(unavailable)?;
        let Driven::Setup { service, .. } = &clock.driven else {
            unreachable!()
        };
        registry.insert(provisioned.bond_edge, service.clone());
        adoption.send(clock);
        if self.adopt.is_closed() {
            return Err(unavailable("paid observer stopped"));
        }
        self.needs_restart
            .store(false, std::sync::atomic::Ordering::Release);
        granted(&provisioned.offer)
    }
}

/// Checked inputs selected by the provider under its standing policy.
struct ProvisionOptions {
    /// Chain and journal identity.
    network: NetworkId,
    journal_root: PathBuf,
    policy: ProviderChannelPolicy,
    omission_bond: u64,
    payment_funding: Funding,
    peer: [u8; 32],
    /// The key this provider stakes and signs the bond with, read from
    /// the identity the operator already has and never made here.
    settlement_key: Secp256k1Signer,
    provider: hellas_rpc::ProviderEnrollmentBundle,
    addresses: Vec<String>,
    /// Principal authorized by the finalized funding delegation.
    client_principal: hellas_auth::authority::PrincipalId,
    /// The node key named by that delegation.
    client_node: Key,
    /// Whether returned stake remains delegated to this provider node.
    redelegate_payout: bool,
    /// The coins this provider stakes.
    stake_coins: Vec<CoinId>,
    /// Height the bond expires at, which is also the admission horizon of
    /// the channel it insures.
    bond_timeout: u64,
    /// What the bond's timeout returns to the staking provider.
    timeout_payout: u64,
    /// The largest job price this bond covers.
    max_job_price: u64,
}

/// Sign and journal an offer under an existing provider identity.
async fn provision_offer(
    options: ProvisionOptions,
    node: &hellas_chain::node::FullNode,
    authority: &hellas_authority::node::NodeCoordinator,
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
struct Provisioned {
    /// The bond this journal is keyed to, which is what discovery names
    /// it by.
    bond_edge: EdgeId,
    /// The floor its history starts above, as retained.
    floor: SetupScan,
    offer: hellas_channel::model::offer::SignedPaidOffer,
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
            .map_err(|_| hellas_channel::model::offer::PaidOfferError::Provider)?;
        if options.provider.genesis.statement.producer_public_key
            != hellas_auth::PublicKey::Secp256k1(options.settlement_key.party_key().to_bytes())
        {
            return Err(hellas_channel::model::offer::PaidOfferError::Provider.into());
        }
        if options.addresses.len() > 16
            || options
                .addresses
                .iter()
                .any(|a| a.len() > 512 || a.parse::<std::net::SocketAddr>().is_err())
            || options.provider.canonical_bytes().len() > 32 * 1024
        {
            return Err(hellas_channel::model::offer::PaidOfferError::Malformed.into());
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
                .map_err(hellas_channel::model::offer::PaidOfferError::from)?;
        let offer = hellas_channel::model::offer::SignedPaidOffer::sign(
            hellas_channel::model::offer::PaidOffer {
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

#[derive(Debug, thiserror::Error)]
enum ProvisionError {
    #[error(transparent)]
    Store(#[from] hellas_channel::work_store::WorkStoreError),
    #[error(transparent)]
    Authority(#[from] hellas_authority::work_store::grant::NodeStoreError),
    #[error(transparent)]
    Offer(#[from] hellas_channel::model::offer::PaidOfferError),
    #[error("bond timeout {timeout} must be after finalized height {height}")]
    ExpiredBond { timeout: u64, height: u64 },
    #[error("bond timeout exceeds the chain maximum lifetime")]
    BondLifetime,
    #[error("stake requires between 1 and at most 4 coins, found {0}")]
    StakeCount(usize),
    #[error("duplicate stake coin {}", hex::encode(.0.to_bytes()))]
    DuplicateCoin(CoinId),
    #[error("provider offer over bond {} has no retained revision", hex::encode(.0.to_bytes()))]
    MissingProposal(EdgeId),
    #[error("candidate bond {} collides with an existing provider offer", hex::encode(.0.to_bytes()))]
    BondCollision(EdgeId),
    #[error("candidate stake coin {} is reserved by bond {}", hex::encode(coin.to_bytes()), hex::encode(bond.to_bytes()))]
    ReservedCoin { coin: CoinId, bond: EdgeId },
    #[error("journal under {} replays as revision {revision:?} over floor {floor:?}, not the armed proposal", root.display())]
    JournalReplay {
        root: PathBuf,
        revision: Option<u8>,
        floor: Option<u64>,
    },
    #[error("work journal under {}: {source}", root.display())]
    Journal {
        root: PathBuf,
        source: hellas_channel::work_store::WorkStoreError,
    },
    #[error("the local node is not ready with a finalized block to floor this offer at")]
    NoFinalizedBlock,
    #[error(transparent)]
    Setup(#[from] hellas_channel::work_handshake::SetupExchangeError),
    #[error(transparent)]
    Query(#[from] hellas_chain::QueryError),
    #[error(transparent)]
    Config(#[from] crate::work_config::WorkConfigError),
    #[error(transparent)]
    BlockSource(#[from] hellas_channel::work_close::BlockSourceError),
}

#[cfg(test)]
mod tests;
