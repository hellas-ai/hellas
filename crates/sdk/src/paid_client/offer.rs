use super::*;
use hellas_rpc::pb::work::{Quote, RequestOfferRequest, request_offer_response::Outcome};
use hellas_wire::{Metadata, StreamTransport};
use hellas_work::model::offer::{SignedPaidOffer, request_digest};
use iroh::{EndpointAddr, TransportAddr};

#[derive(Clone, Debug)]
pub struct PaidQuote {
    pub policy: ProviderChannelPolicy,
    pub omission_bond: u64,
    pub funding_value: u64,
}

struct OfferConnection {
    transport: hellas_wire::iroh::IrohTransport,
    provider: hellas_rpc::ProviderEnrollmentBundle,
}

impl OfferConnection {
    async fn open(args: &PaidWorkOptions, endpoint: &Endpoint) -> Result<Self> {
        let address = EndpointAddr::from_parts(
            args.provider,
            args.provider_addrs.iter().copied().map(TransportAddr::Ip),
        );
        let connection = endpoint
            .connect(
                address,
                hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes(),
            )
            .await
            .map_err(|source| PaidClientError::Connect {
                provider: args.provider,
                source,
            })?;
        let transport = hellas_wire::iroh::IrohTransport::new(connection);
        let (provider, _) = hellas_client::confidential_open_selected::<
            hellas_rpc::services::work_setup::Open,
        >(&transport, args.assurance, args.apple_trust.as_ref())
        .await?;
        if hellas_work::model::grant::records::grant_transport(&provider)
            .map_err(|_| PaidClientError::ProviderIdentityChanged)?
            != *args.provider.as_bytes()
        {
            return Err(PaidClientError::ProviderIdentityChanged);
        }
        Ok(Self {
            transport,
            provider,
        })
    }

    async fn request(
        &self,
        args: &PaidWorkOptions,
        signer: &Secp256k1Signer,
        owner: hellas_auth::authority::PrincipalId,
        funding: Option<&Funding>,
    ) -> Result<Outcome> {
        let mut request = RequestOfferRequest {
            client_principal: owner.as_bytes().to_vec(),
            client_key: signer.party_key().to_bytes().to_vec(),
            funding_coins: funding
                .map(|funding| {
                    funding
                        .maker()
                        .iter()
                        .map(|coin| coin.to_bytes().to_vec())
                        .collect()
                })
                .unwrap_or_default(),
            signature: vec![],
        };
        let exporter = self
            .transport
            .context()
            .open_exporter
            .ok_or(PaidClientError::MissingState("offer exporter"))?;
        let digest = request_digest(
            args.config.chain.network,
            self.provider.content_id(),
            &request,
            &exporter,
        );
        request.signature = signer
            .sign(hellas_kernel::PayloadHash::from_bytes(*digest.as_bytes()))
            .as_bytes()
            .to_vec();
        let timeout = args.timeout.min(hellas_chain::node::RECOVERY_TIMEOUT);
        let response = tokio::time::timeout(timeout, async {
            loop {
                let response = hellas_rpc::call::unary::<
                    _,
                    hellas_rpc::services::work_setup::RequestOffer,
                >(&self.transport, request.clone(), Metadata::new())
                .await;
                match response {
                    // A block may advance between the provider's coherent proof
                    // reads. Retrying this signed request reuses its retained offer.
                    Err(status) if status.code() == hellas_wire::WireCode::Unavailable => {
                        tokio::time::sleep(args.config.poll).await;
                    }
                    response => {
                        return response.map_err(|status| {
                            hellas_client::ClientError::wire("offer request failed", status)
                        });
                    }
                }
            }
        })
        .await
        .map_err(|_| PaidClientError::Timeout {
            stage: "offer availability",
        })??;
        response
            .outcome
            .ok_or(PaidClientError::MissingState("offer response"))
    }
}

fn check_quote(
    args: &PaidWorkOptions,
    quote: Quote,
    provider: &hellas_rpc::ProviderEnrollmentBundle,
) -> Result<PaidQuote> {
    let policy: ProviderChannelPolicy = hellas_rpc::protocol::value::decode_canonical_bounded(
        &quote.provider_channel_policy,
        hellas_work::model::grant::records::MAX_OFFER_BYTES,
    )
    .map_err(|_| PaidClientError::InputMismatch("quote encoding"))?;
    check_policy(args, &policy, quote.omission_bond)?;
    let trust = hellas_client::selected_provider_trust(
        provider,
        args.assurance,
        args.apple_trust.as_ref(),
    )?;
    if trust.apple_app_attest.is_some() {
        trust.verify_environment(policy.work_policy.allowed_environment())?;
    }
    let required = quote
        .required
        .ok_or(PaidClientError::MissingState("quoted edge values"))?;
    let values = policy.expected_payment_values;
    let fees = values.close_fees();
    if required.value != values.value()
        || required.reserve != values.reserve()
        || (
            required.base_fee,
            required.slot_fee,
            required.proof_fee,
            required.lifetime_fee,
        ) != (fees.base(), fees.slot(), fees.proof(), fees.lifetime())
        || values.value().checked_add(values.reserve()) != Some(quote.funding_value)
        || fees != hellas_chain::domain::KERNEL_FEES
        || values.reserve() != 0
    {
        return Err(PaidClientError::InputMismatch("quoted funding"));
    }
    Ok(PaidQuote {
        policy,
        omission_bond: quote.omission_bond,
        funding_value: quote.funding_value,
    })
}

pub(super) fn check_policy(
    args: &PaidWorkOptions,
    policy: &ProviderChannelPolicy,
    omission_bond: u64,
) -> Result<()> {
    if policy.network != args.config.chain.network
        || policy.payment_policy.fixed_price != args.expected_price
    {
        return Err(PaidClientError::InputMismatch("quoted network or price"));
    }
    policy.work_policy.check()?;
    policy.payment_policy.check()?;
    let settlement =
        hellas_kernel::work_payment_settlement(policy.expected_payment_values, omission_bond)
            .ok_or(hellas_work::model::setup::WorkSetupError::Unsettleable)?;
    hellas_work::model::setup::check_collateral(omission_bond, settlement.capacity())?;
    Ok(())
}

pub async fn request_paid_quote(
    args: &PaidWorkOptions,
    endpoint: &Endpoint,
    signer: &Secp256k1Signer,
    owner: hellas_auth::authority::PrincipalId,
) -> Result<PaidQuote> {
    args.validate()?;
    let connection = OfferConnection::open(args, endpoint).await?;
    match connection.request(args, signer, owner, None).await? {
        Outcome::Quote(quote) => check_quote(args, quote, &connection.provider),
        Outcome::Refused(refused) => Err(PaidClientError::OfferRefused(refused.code)),
        _ => Err(PaidClientError::InputMismatch("expected quote")),
    }
}

pub(super) async fn obtain_offer(
    args: &PaidWorkOptions,
    endpoint: &Endpoint,
    signer: &Secp256k1Signer,
    owner: &crate::client_owner::ClientOwner,
    chain: &RemoteLightClient,
) -> Result<SignedPaidOffer> {
    let principal = owner.principal();
    let connection = OfferConnection::open(args, endpoint).await?;
    let quote = match connection.request(args, signer, principal, None).await? {
        Outcome::Quote(quote) => check_quote(args, quote, &connection.provider)?,
        Outcome::Refused(refused) => return Err(PaidClientError::OfferRefused(refused.code)),
        _ => return Err(PaidClientError::InputMismatch("expected quote")),
    };
    let quoted_provider = connection.provider.clone();
    drop(connection);
    let funding = owner
        .fund(
            chain,
            args.config.chain.network,
            args.provider,
            quote.funding_value,
            args.config.poll,
            args.timeout.min(hellas_chain::node::RECOVERY_TIMEOUT),
        )
        .await?;
    let connection = OfferConnection::open(args, endpoint).await?;
    if connection.provider != quoted_provider {
        return Err(PaidClientError::ProviderIdentityChanged);
    }
    let offer = match connection
        .request(args, signer, principal, Some(&funding))
        .await?
    {
        Outcome::Granted(granted) => SignedPaidOffer::decode(&granted.offer)?,
        Outcome::Refused(refused) => return Err(PaidClientError::OfferRefused(refused.code)),
        _ => return Err(PaidClientError::InputMismatch("expected funded offer")),
    };
    if offer.offer().payment_funding != funding
        || offer.offer().provider != connection.provider
        || offer.offer().policy != quote.policy
        || offer.offer().omission_bond != quote.omission_bond
    {
        return Err(PaidClientError::InputMismatch("offer differs from quote"));
    }
    Ok(offer)
}

pub(crate) async fn retained_offer<
    C: hellas_chain::LightClient + hellas_chain::work_view::FinalizedWorkView,
>(
    args: &PaidWorkOptions,
    chain: &WorkBlocks<C>,
) -> Result<Option<(SetupStore, SignedPaidOffer)>> {
    let found =
        hellas_work::work_store::discover_setups(&args.journal_root, args.config.chain.network)
            .await?;
    if !found.unidentified.is_empty() {
        return Err(PaidClientError::MissingState("unidentified client journal"));
    }
    let mut retained = None;
    for setup in found
        .setups
        .into_iter()
        .filter(|setup| setup.role == Role::Client)
    {
        let store = SetupStore::open(
            &args.journal_root,
            args.config.chain.network,
            setup.bond_edge,
            Role::Client,
            &Secp256k1Verifier::new(),
        )
        .await?;
        let floor = store
            .state()
            .origin()
            .map_or(0, |origin| origin.height)
            .max(store.state().scan_cursor().map_or(0, |scan| scan.height))
            .max(store.state().scan_armed().map_or(0, |scan| scan.height));
        let chain = chain.clone().with_min_height(floor);
        let Some((_, offer)) = store.state().offer() else {
            return Err(PaidClientError::MissingState("client offer"));
        };
        if hellas_work::model::grant::records::grant_transport(&offer.offer().provider)
            .map_err(|_| PaidClientError::ProviderIdentityChanged)?
            != *args.provider.as_bytes()
        {
            continue;
        }
        if matches!(
            store.state().end(),
            Some(
                hellas_work::work_store::SetupEnd::Aborted(_)
                    | hellas_work::work_store::SetupEnd::Faulted(_)
            )
        ) {
            continue;
        }
        if store.state().end() != Some(hellas_work::work_store::SetupEnd::Complete) {
            let snapshot = chain
                .work_channel_snapshot(WorkChannelQuery {
                    bond_edge: setup.bond_edge,
                    payment_edge: store.state().payment_edge(),
                    funding: store.state().funding_coins(),
                })
                .await?
                .ok_or(PaidClientError::MissingState("finalized incomplete setup"))?;
            if snapshot.block().height >= offer.offer().proposal.bond_terms().timeout.get()
                && snapshot.payment().is_none()
            {
                continue;
            }
        }
        if let Some(payment) = store.state().payment_edge()
            && store.state().end() == Some(hellas_work::work_store::SetupEnd::Complete)
        {
            let snapshot = chain
                .work_channel_snapshot(WorkChannelQuery {
                    bond_edge: setup.bond_edge,
                    payment_edge: Some(payment),
                    funding: Default::default(),
                })
                .await?
                .ok_or(PaidClientError::MissingState("finalized client channel"))?;
            if snapshot.payment().is_none() {
                continue;
            }
        }
        if retained.is_some() {
            return Err(PaidClientError::AmbiguousRecovery);
        }
        let offer = offer.clone();
        retained = Some((store, offer));
    }
    Ok(retained)
}
