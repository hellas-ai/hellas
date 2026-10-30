//! Associate archived signed funding intents with durable channel setups.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredFundingChannel {
    pub reservation: [u8; 16],
    pub network: hellas_kernel::NetworkId,
    pub channel: hellas_auth::Digest,
    pub bond_edge: EdgeId,
    pub payment_edge: EdgeId,
    pub funding_value: u64,
}

/// Finish a previously signed funding intent by reservation identity. This
/// cannot obtain a quote, allocate an intent, or request an owner signature.
pub async fn recover_funding_intent(
    args: &PaidWorkOptions,
    owner: &ClientOwner,
    reservation: [u8; 16],
    approval: Option<&dyn FundingApproval>,
) -> Result<Funding> {
    args.validate()?;
    args.config.clone().validate()?;
    let timeout = read_timeout(args.timeout);
    let chain = crate::client_chain::connect(&args.config, timeout).await?;
    owner
        .recover_funding_intent(
            &chain,
            args.config.chain.network,
            args.provider.node,
            reservation,
            crate::client_owner::FundingControls {
                poll: args.config.poll,
                timeout,
                approval,
            },
        )
        .await
        .map_err(Into::into)
}

/// Metadata-only recovery, including closed historical channels. The exact
/// funding coin must occur in both the signed owner intent and signed offer.
/// No quote, provider connection, signature, or transaction is created here.
/// Call only when no session owns the setup journals. This association alone
/// does not authorize release of any money; verified settlement is separate.
pub fn recover_funding_channels(
    args: &PaidWorkOptions,
    owner: &ClientOwner,
) -> impl std::future::Future<Output = Result<Vec<RecoveredFundingChannel>>> {
    Box::pin(recover_funding_channels_inner(args, owner))
}

async fn recover_funding_channels_inner(
    args: &PaidWorkOptions,
    owner: &ClientOwner,
) -> Result<Vec<RecoveredFundingChannel>> {
    let intents = owner.funding_intents().await?;
    if intents.is_empty() {
        return Ok(Vec::new());
    }
    let network = args.config.chain.network;
    let found = hellas_channel::work_store::discover_setups(&args.journal_root, network).await?;
    if !found.unidentified.is_empty() {
        return Err(PaidClientError::MissingState("unidentified funding setup"));
    }
    let verifier = Secp256k1Verifier::new();
    let mut recovered = Vec::new();
    let mut used = std::collections::BTreeSet::new();
    for setup in found.setups.into_iter().filter(|s| s.role == Role::Client) {
        let store = SetupStore::open(
            &args.journal_root,
            network,
            setup.bond_edge,
            Role::Client,
            &verifier,
        )
        .await?;
        let Some((_, signed)) = store.state().offer() else {
            continue;
        };
        signed.check()?;
        if hellas_client::ProviderAddress::of(&signed.offer().provider)? != args.provider {
            continue;
        }
        args.trust()?.verify_enrollment(&signed.offer().provider)?;
        let matches: Vec<_> = intents
            .iter()
            .filter(|i| {
                i.network == network
                    && i.provider == args.provider.node
                    && i.funding == signed.offer().payment_funding
            })
            .collect();
        if matches.is_empty() {
            continue;
        }
        if matches.len() != 1 {
            return Err(PaidClientError::AmbiguousRecovery);
        }
        let intent = matches[0];
        let values = signed.offer().policy.expected_payment_values;
        if values.value().checked_add(values.reserve()) != Some(intent.amount) {
            return Err(PaidClientError::InputMismatch("archived funding amount"));
        }
        // Incomplete setups remain reserved until they produce a channel.
        let Some(descriptor) = store.state().close_descriptor() else {
            continue;
        };
        if store.state().origin().is_none() {
            continue;
        }
        let channel = descriptor.channel();
        let client = channel.payment_terms().parties().maker();
        if client.owner().to_bytes() != *owner.principal().as_bytes()
            || client.signer() != owner.delegate()
            || client.payout_delegate() != Some(owner.delegate())
            || descriptor.bond_edge() != setup.bond_edge
        {
            return Err(PaidClientError::InputMismatch(
                "archived funding client identity",
            ));
        }
        if !used.insert(intent.reservation) {
            return Err(PaidClientError::AmbiguousRecovery);
        }
        recovered.push(RecoveredFundingChannel {
            reservation: intent.reservation,
            network,
            channel: channel.id(),
            bond_edge: setup.bond_edge,
            payment_edge: channel.payment_edge(),
            funding_value: intent.amount,
        });
    }
    Ok(recovered)
}
