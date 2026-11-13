use super::*;
use hellas_channel::model::offer::{SignedPaidOffer, request_digest};
use hellas_private::StoreLocation;
use hellas_rpc::pb::work::{Quote, RequestOfferRequest, request_offer_response::Outcome};
use hellas_wire::{Metadata, StreamTransport};
use iroh::{EndpointAddr, TransportAddr};

#[derive(Clone, Debug)]
pub struct PaidQuote {
    pub policy: ProviderChannelPolicy,
    pub omission_bond: u64,
    pub funding_value: u64,
}

struct OfferConnection {
    transport: hellas_wire::iroh::IrohTransport,
}

impl OfferConnection {
    /// Dials the addressed node and refuses any enrollment other than the
    /// addressed one before a request is signed or disclosed.
    async fn open(args: &PaidWorkOptions, endpoint: &Endpoint) -> Result<Self> {
        let trust = args.trust()?;
        let address = EndpointAddr::from_parts(
            args.provider.node,
            args.provider_addrs.iter().copied().map(TransportAddr::Ip),
        );
        let connection = endpoint
            .connect(
                address,
                hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes(),
            )
            .await
            .map_err(|source| PaidClientError::Connect {
                provider: args.provider.node,
                source,
            })?;
        let transport = hellas_wire::iroh::IrohTransport::new(connection);
        hellas_client::confidential_open::<hellas_rpc::services::work_setup::Open>(
            &transport, &trust,
        )
        .await?;
        Ok(Self { transport })
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
            args.config.network(),
            args.provider.enrollment,
            &request,
            &exporter,
        );
        request.signature = signer
            .sign(hellas_kernel::PayloadHash::from_bytes(*digest.as_bytes()))
            .as_bytes()
            .to_vec();
        retry_offer(
            super::read_timeout(args.timeout),
            hellas_channel::work::SETUP_POLL,
            || {
                hellas_rpc::call::unary::<_, hellas_rpc::services::work_setup::RequestOffer>(
                    &self.transport,
                    request.clone(),
                    Metadata::new(),
                )
            },
        )
        .await
    }
}

async fn retry_offer<F, R>(timeout: Duration, poll: Duration, mut request: F) -> Result<Outcome>
where
    F: FnMut() -> R,
    R: Future<Output = Result<hellas_rpc::pb::work::RequestOfferResponse, hellas_wire::WireStatus>>,
{
    let mut unavailable = None;
    let response = tokio::time::timeout(timeout, async {
        loop {
            let response = request().await;
            match response {
                // A block may advance between the provider's coherent proof
                // reads. Retrying this signed request reuses its retained offer.
                Err(status) if status.code() == hellas_wire::WireCode::Unavailable => {
                    tracing::debug!(%status, "provider offer temporarily unavailable");
                    unavailable = Some(status);
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "inventory class C: unavailable offer proof retry"
                    )]
                    tokio::time::sleep(poll).await;
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
    .map_err(|_| {
        if let Some(source) = unavailable {
            PaidClientError::OfferUnavailable { source }
        } else {
            PaidClientError::Timeout {
                stage: "offer availability",
            }
        }
    })??;
    response
        .outcome
        .ok_or(PaidClientError::MissingState("offer response"))
}

fn check_quote(args: &PaidWorkOptions, quote: Quote) -> Result<PaidQuote> {
    let policy: ProviderChannelPolicy = hellas_rpc::protocol::value::decode_canonical_bounded(
        &quote.provider_channel_policy,
        hellas_authority::model::grant::records::MAX_OFFER_BYTES,
    )
    .map_err(|_| PaidClientError::InputMismatch("quote encoding"))?;
    check_policy(args, &policy, quote.omission_bond)?;
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
    if policy.network != args.config.network() {
        return Err(PaidClientError::InputMismatch("quoted network"));
    }
    if policy.payment_policy.fixed_price > args.expected_price {
        return Err(PaidClientError::PriceAbove {
            quoted: policy.payment_policy.fixed_price,
            maximum: args.expected_price,
        });
    }
    policy.invocation_policy.validate()?;
    policy.payment_policy.check()?;
    let settlement =
        hellas_kernel::work_payment_settlement(policy.expected_payment_values, omission_bond)
            .ok_or(hellas_channel::model::setup::WorkSetupError::Unsettleable)?;
    hellas_channel::model::setup::check_collateral(omission_bond, settlement.capacity())?;
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
        Outcome::Quote(quote) => check_quote(args, quote),
        Outcome::Refused(refused) => Err(PaidClientError::OfferRefused(refused.code)),
        _ => Err(PaidClientError::InputMismatch("expected quote")),
    }
}

pub(super) async fn fund_offer(
    args: &PaidWorkOptions,
    endpoint: &Endpoint,
    signer: &Secp256k1Signer,
    owner: &crate::client_owner::ClientOwner,
    chain: &RemoteLightClient,
    quote: PaidQuote,
    controls: crate::client_owner::FundingControls<'_>,
) -> Result<SignedPaidOffer> {
    let principal = owner.principal();
    let funding = owner
        .fund_with_approval(chain, args.provider.node, quote.funding_value, controls)
        .await?;
    let connection = OfferConnection::open(args, endpoint).await?;
    // A verified funding coin can be visible to this client's validators
    // before the provider's finalized view reaches it, so a funding refusal
    // asks again at each new block. The exact signed request is reused; this
    // cannot create another funding signature or a work proposal.
    let needs_funding = hellas_rpc::pb::work::OfferRefusalCode::NeedsFunding as i32;
    let deadline = tokio::time::Instant::now() + super::read_timeout(args.timeout);
    let mut blocks = chain.finalized_blocks().await?;
    let offer = loop {
        match connection
            .request(args, signer, principal, Some(&funding))
            .await?
        {
            Outcome::Granted(granted) => break SignedPaidOffer::decode(&granted.offer)?,
            Outcome::Refused(refused) if refused.code == needs_funding => {
                tokio::time::timeout_at(deadline, blocks.next())
                    .await
                    .map_err(|_| PaidClientError::OfferRefused(needs_funding))??;
            }
            Outcome::Refused(refused) => return Err(PaidClientError::OfferRefused(refused.code)),
            _ => return Err(PaidClientError::InputMismatch("expected funded offer")),
        }
    };
    if offer.offer().payment_funding != funding {
        return Err(PaidClientError::InputMismatch("approved payment funding"));
    }
    if offer.offer().provider.content_id() != args.provider.enrollment {
        return Err(PaidClientError::InputMismatch(
            "approved provider enrollment",
        ));
    }
    if offer.offer().policy != quote.policy {
        return Err(PaidClientError::InputMismatch("quoted policy"));
    }
    if offer.offer().omission_bond != quote.omission_bond {
        return Err(PaidClientError::InputMismatch("quoted omission bond"));
    }
    Ok(offer)
}

/// The certified height one retained setup journal already relies on.
///
/// A source below this height cannot answer the journal's own reads, so
/// source selection has to meet the same floor before it is asked.
fn journal_floor(store: &SetupStore) -> u64 {
    store.state().observed_height().unwrap_or(0)
}

/// One retained client setup addressed to the requested provider, opened
/// from its own journal.
struct RetainedSetup {
    store: SetupStore,
    offer: SignedPaidOffer,
}

/// Open setup journals retained through source selection, so the floor and
/// selected offer come from the same discovery and journal locks.
pub(crate) struct RetainedSetups {
    setups: Vec<RetainedSetup>,
    provider: hellas_client::ProviderAddress,
}

impl RetainedSetups {
    pub(crate) async fn discover(
        journal_root: &StoreLocation,
        network: hellas_kernel::NetworkId,
        provider: hellas_client::ProviderAddress,
    ) -> Result<Self> {
        let found = hellas_channel::work_store::discover_setups(journal_root, network).await?;
        if !found.unidentified.is_empty() {
            return Err(PaidClientError::MissingState("unidentified client journal"));
        }
        let mut retained = Vec::new();
        for setup in found
            .setups
            .into_iter()
            .filter(|setup| setup.role == Role::Client)
        {
            let store = SetupStore::open(
                journal_root,
                network,
                setup.bond_edge,
                Role::Client,
                &Secp256k1Verifier::new(),
            )
            .await?;
            let Some((_, offer)) = store.state().offer() else {
                return Err(PaidClientError::MissingState("client offer"));
            };
            if hellas_authority::model::grant::records::grant_transport(&offer.offer().provider)
                .map_err(|_| PaidClientError::ProviderIdentityChanged)?
                != *provider.node.as_bytes()
            {
                continue;
            }
            if matches!(
                store.state().end(),
                Some(
                    hellas_channel::work_store::SetupEnd::Aborted(_)
                        | hellas_channel::work_store::SetupEnd::Faulted(_)
                )
            ) {
                continue;
            }
            let offer = offer.clone();
            retained.push(RetainedSetup { store, offer });
        }
        Ok(Self {
            setups: retained,
            provider,
        })
    }

    pub(crate) fn floor(&self) -> u64 {
        self.setups
            .iter()
            .map(|entry| journal_floor(&entry.store))
            .max()
            .unwrap_or(0)
    }

    pub(crate) async fn select<
        C: hellas_chain::LightClient + hellas_chain::work_view::FinalizedWorkView,
    >(
        self,
        chain: &WorkBlocks<C>,
    ) -> Result<Option<(SetupStore, SignedPaidOffer)>> {
        let provider = self.provider;
        let mut retained = None;
        for RetainedSetup { store, offer } in self.setups {
            let chain = chain.clone().with_min_height(journal_floor(&store));
            if store.state().end() != Some(hellas_channel::work_store::SetupEnd::Complete) {
                let snapshot = chain
                    .work_channel_snapshot(WorkChannelQuery {
                        bond_edge: store.state().bond_edge(),
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
                && store.state().end() == Some(hellas_channel::work_store::SetupEnd::Complete)
            {
                let snapshot = chain
                    .work_channel_snapshot(WorkChannelQuery {
                        bond_edge: store.state().bond_edge(),
                        payment_edge: Some(payment),
                        funding: Default::default(),
                    })
                    .await?
                    .ok_or(PaidClientError::MissingState("finalized client channel"))?;
                if snapshot.payment().is_none() {
                    continue;
                }
            }
            if offer.offer().provider.content_id() != provider.enrollment {
                return Err(PaidClientError::RetainedEnrollment(provider));
            }
            if retained.is_some() {
                return Err(PaidClientError::AmbiguousRecovery);
            }
            retained = Some((store, offer));
        }
        Ok(retained)
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use hellas_rpc::pb::work::{OfferRefusalCode, OfferRefused, RequestOfferResponse};
    use hellas_wire::{WireCode, WireStatus};

    #[tokio::test(start_paused = true)]
    async fn unavailable_deadline_preserves_the_last_provider_cause() {
        let mut calls = 0;
        let error = retry_offer(Duration::from_secs(3), Duration::from_secs(1), || {
            calls += 1;
            std::future::ready(Err(WireStatus::new(
                WireCode::Unavailable,
                if calls == 1 {
                    "initializing"
                } else {
                    "chain node is catching up"
                },
            )))
        })
        .await
        .unwrap_err();
        assert!(calls >= 2);
        let PaidClientError::OfferUnavailable { source } = error else {
            panic!("{error}")
        };
        assert_eq!(source.code(), WireCode::Unavailable);
        assert!(source.to_string().contains("chain node is catching up"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_funding_refusal_ends_the_unavailable_retry() {
        let mut calls = 0;
        let outcome = retry_offer(Duration::from_secs(3), Duration::from_secs(1), || {
            calls += 1;
            std::future::ready(if calls == 1 {
                Err(WireStatus::new(WireCode::Unavailable, "initializing"))
            } else {
                Ok(RequestOfferResponse {
                    outcome: Some(Outcome::Refused(OfferRefused {
                        code: OfferRefusalCode::NeedsFunding as i32,
                        required: 401,
                    })),
                })
            })
        })
        .await
        .unwrap();
        assert_eq!(calls, 2);
        assert!(
            matches!(outcome, Outcome::Refused(refused) if refused.code == OfferRefusalCode::NeedsFunding as i32)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_returns_a_response_when_the_provider_becomes_available() {
        let mut calls = 0;
        let response = retry_offer(Duration::from_secs(3), Duration::from_secs(1), || {
            calls += 1;
            std::future::ready(if calls == 1 {
                Err(WireStatus::new(WireCode::Unavailable, "initializing"))
            } else {
                Ok(RequestOfferResponse {
                    outcome: Some(Outcome::Refused(OfferRefused {
                        code: OfferRefusalCode::NoStakeAvailable as i32,
                        required: 0,
                    })),
                })
            })
        })
        .await
        .unwrap();
        assert_eq!(calls, 2);
        assert!(
            matches!(response, Outcome::Refused(refused) if refused.code == OfferRefusalCode::NoStakeAvailable as i32)
        );
    }
}
