//! Recover exact client returns from certified close transactions. This path
//! has no funding, provider connection, or transaction submission capability.
use super::*;
use hellas_auth::{Digest, authority::PrincipalId};
use hellas_channel::work_close::{FinalizedWork, catch_up};
use hellas_channel::work_store::ChannelStore;
use hellas_kernel::{Key, NetworkId, Tx};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedChannelSettlement {
    pub network: NetworkId,
    pub channel: Digest,
    pub bond_edge: EdgeId,
    pub payment_edge: EdgeId,
    pub height: u64,
    pub payload: [u8; 32],
    pub funding_value: u64,
    pub client_returned: u64,
    pub provider_payout: u64,
}

/// Recover a specific channel's settlement from its signed journals and a
/// freshly verified finalized block. Returns `None` for a channel that has not
/// closed. Missing or pruned evidence is an error, never a zero-spend result.
/// Stop/drop any session owning this channel before calling this function.
pub fn finalized_channel_settlement(
    args: &PaidWorkOptions,
    bond: EdgeId,
    owner: PrincipalId,
    delegate: Key,
) -> impl std::future::Future<Output = Result<Option<FinalizedChannelSettlement>>> {
    Box::pin(finalized_channel_settlement_inner(
        args, bond, owner, delegate,
    ))
}

async fn finalized_channel_settlement_inner(
    args: &PaidWorkOptions,
    bond: EdgeId,
    owner: PrincipalId,
    delegate: Key,
) -> Result<Option<FinalizedChannelSettlement>> {
    args.validate()?;
    args.config.clone().validate()?;
    let found =
        hellas_channel::work_store::discover_setups(&args.journal_root, args.config.chain.network)
            .await?;
    if !found.unidentified.is_empty()
        || !found
            .setups
            .iter()
            .any(|s| s.role == Role::Client && s.bond_edge == bond)
    {
        return Err(PaidClientError::MissingState("settlement setup journal"));
    }
    let verifier = Secp256k1Verifier::new();
    let setup = SetupStore::open(
        &args.journal_root,
        args.config.chain.network,
        bond,
        Role::Client,
        &verifier,
    )
    .await?;
    let (_, signed) = setup
        .state()
        .offer()
        .ok_or(PaidClientError::MissingState("settlement signed offer"))?;
    signed.check()?;
    args.trust()?.verify_enrollment(&signed.offer().provider)?;
    if hellas_client::ProviderAddress::of(&signed.offer().provider)? != args.provider {
        return Err(PaidClientError::RetainedEnrollment(args.provider));
    }
    let descriptor = setup
        .state()
        .close_descriptor()
        .ok_or(PaidClientError::MissingState(
            "settlement channel descriptor",
        ))?;
    let channel = descriptor.channel().clone();
    let client = channel.payment_terms().parties().maker();
    if client.owner().to_bytes() != *owner.as_bytes()
        || client.signer() != delegate
        || client.payout_delegate() != Some(delegate)
        || descriptor.bond_edge() != bond
    {
        return Err(PaidClientError::InputMismatch("settlement client identity"));
    }
    let values = signed.offer().policy.expected_payment_values;
    let funding_value = values
        .value()
        .checked_add(values.reserve())
        .ok_or(PaidClientError::InputMismatch("settlement funding value"))?;
    let origin = setup
        .state()
        .origin()
        .ok_or(PaidClientError::MissingState("settlement channel origin"))?;
    let mut journal = ChannelStore::open(
        &args.journal_root,
        channel.clone(),
        descriptor.expected_settlement()?,
        Role::Client,
        origin,
        hellas_store::ContentStore::new(),
        &verifier,
    )
    .await?;
    let timeout = super::read_timeout(args.timeout);
    let remote = crate::client_chain::connect(&args.config, timeout).await?;
    let chain = WorkBlocks::new(remote)
        .with_read_retry(args.config.poll, timeout)
        .with_min_height(journal.state().cursor().0);
    // Observing finalized blocks can expire jobs and record closure, but cannot
    // approve, sign, submit, or pay for any work.
    if journal.state().close_settled().is_none() {
        catch_up(&chain, &mut journal, &verifier).await?;
    }
    let Some(settled) = journal.state().close_settled() else {
        return Ok(None);
    };
    let block = chain
        .block_at(settled.height)
        .await?
        .ok_or(PaidClientError::MissingState("finalized settlement block"))?;
    let (client_returned, provider_payout) = close_payouts(
        &block,
        &channel,
        settled.height,
        settled.payload,
        settled.provider_payout,
    )?;
    Ok(Some(FinalizedChannelSettlement {
        network: args.config.chain.network,
        channel: channel.id(),
        bond_edge: bond,
        payment_edge: channel.payment_edge(),
        height: block.height,
        payload: block.payload,
        funding_value,
        client_returned,
        provider_payout,
    }))
}

fn close_payouts(
    block: &FinalizedWork,
    channel: &hellas_channel::model::work::PaidChannel,
    height: u64,
    payload: [u8; 32],
    expected_provider: u64,
) -> Result<(u64, u64)> {
    if block.height != height || block.payload != payload {
        return Err(PaidClientError::InputMismatch("settlement finalized block"));
    }
    let mut closes = block.txs.iter().filter_map(|tx| match tx {
        Tx::Close { input, outputs, .. } if *input == channel.payment_edge() => Some(outputs),
        _ => None,
    });
    let outputs = closes.next().ok_or(PaidClientError::MissingState(
        "settlement close transaction",
    ))?;
    if closes.next().is_some() {
        return Err(PaidClientError::InputMismatch("duplicate settlement close"));
    }
    let parties = channel.payment_terms().parties();
    let mut returned = 0u64;
    let mut paid = 0u64;
    for payout in outputs.as_slice() {
        let total = if payout.owner() == parties.maker().owner()
            && payout.delegate() == parties.maker().payout_delegate()
        {
            &mut returned
        } else if payout.owner() == parties.taker().owner()
            && payout.delegate() == parties.taker().payout_delegate()
        {
            &mut paid
        } else {
            return Err(PaidClientError::InputMismatch("settlement payout identity"));
        };
        *total = total
            .checked_add(payout.value())
            .ok_or(PaidClientError::InputMismatch("settlement payout overflow"))?;
    }
    if paid != expected_provider {
        return Err(PaidClientError::InputMismatch("settlement provider payout"));
    }
    Ok((returned, paid))
}
