use super::*;
use hellas_chain::LightClient as _;
use hellas_kernel::{CoinId, Key, MAX_PARTY_INPUTS};
use hellas_rpc::pb::work::{
    OfferGranted, OfferRefusalCode, OfferRefused, PaymentEdgeValues, Quote, RequestOfferRequest,
    RequestOfferResponse, request_offer_response::Outcome,
};
use hellas_work::model::offer::{SignedPaidOffer, request_digest};
use std::collections::BTreeSet;

pub(super) struct OfferAllocator {
    pub config: WorkRunnerConfig,
    pub node: FullNode,
    pub authority: hellas_work::node::NodeCoordinator,
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
        hellas_work::model::grant::records::MAX_OFFER_BYTES,
    )
    .map_err(unavailable)?;
    return Ok(RequestOfferResponse {
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
            omission_bond: omission_bond,
            funding_value: required,
        })),
    });
}

impl OfferAllocator {
    pub async fn request(
        &self,
        request: RequestOfferRequest,
        context: TransportContext,
        mount: &MountedSetup,
    ) -> Result<RequestOfferResponse, WireStatus> {
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
            let live = snapshot.bond().is_some()
                || snapshot.payment().is_some()
                || (state.end() != Some(hellas_work::work_store::SetupEnd::Complete)
                    && snapshot.block().height < bundle.bond_terms().timeout.get());
            if live {
                open += 1;
                reserved.extend(bundle.bond_funding().maker().iter().copied());
                let taker = bundle.bond_terms().parties.taker();
                if taker.owner().to_bytes() == principal || taker.signer().to_bytes() == key {
                    if taker.owner().to_bytes() != principal || taker.signer().to_bytes() != key {
                        return Err(invalid());
                    }
                    // Payment has already consumed its funding on resume. Returning
                    // the original offer neither allocates stake nor changes its peer.
                    let (_, offer) = state
                        .offer()
                        .ok_or_else(|| unavailable("missing retained offer"))?;
                    if coins.is_empty() {
                        return quote(&offer.offer().policy, offer.offer().omission_bond);
                    }
                    if snapshot.block().height >= bundle.bond_terms().timeout.get() {
                        return Ok(refused(OfferRefusalCode::OfferLimit, 0));
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
        let provisioned = crate::work_provision::provision_offer(
            crate::work_provision::ProvisionOptions {
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
        granted(&provisioned.offer)
    }
}
