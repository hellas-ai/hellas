//! Settle retained funding and recover exact certified returns without funding
//! or connecting to a provider. Evidence recovery alone never submits a transaction.
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

/// A retained client channel identified from its signed setup journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedSettlementChannel {
    pub bond: EdgeId,
    pub price: u64,
    pub assurance: hellas_rpc::Assurance,
}

/// Enumerate exact retained channels without contacting a provider or reading
/// live object proofs. Unidentified, incomplete or mismatched journals fail
/// closed so an existing obligation is never silently ignored.
pub async fn retained_settlement_channels(
    root: &std::path::Path,
    network: NetworkId,
    provider: hellas_client::ProviderAddress,
    owner: PrincipalId,
    delegate: Key,
) -> Result<Vec<RetainedSettlementChannel>> {
    let found = hellas_channel::work_store::discover_setups(root, network).await?;
    if !found.unidentified.is_empty() {
        return Err(PaidClientError::MissingState("unidentified client journal"));
    }
    let verifier = Secp256k1Verifier::new();
    let mut channels = Vec::new();
    for entry in found.setups.into_iter().filter(|s| s.role == Role::Client) {
        let setup =
            SetupStore::open_existing(root, network, entry.bond_edge, Role::Client, &verifier)
                .await?;
        let (_, signed) = setup
            .state()
            .offer()
            .ok_or(PaidClientError::MissingState("settlement signed offer"))?;
        signed.check()?;
        let actual = hellas_client::ProviderAddress::of(&signed.offer().provider)?;
        if actual.node != provider.node {
            continue;
        }
        if actual != provider {
            return Err(PaidClientError::RetainedEnrollment(provider));
        }
        if matches!(
            setup.state().end(),
            Some(hellas_channel::work_store::SetupEnd::Aborted(_))
        ) {
            continue;
        }
        checked_descriptor(&setup, entry.bond_edge, owner, delegate)?;
        let assurance = match signed.offer().provider.genesis.statement.root_kind {
            hellas_rpc::RootKind::SecureEnclave => hellas_rpc::Assurance::AppleAppAttest,
            _ => hellas_rpc::Assurance::ProducerSigned,
        };
        channels.push(RetainedSettlementChannel {
            bond: entry.bond_edge,
            price: signed.offer().policy.payment_policy.fixed_price,
            assurance,
        });
    }
    Ok(channels)
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
    let mut recovery = open_settlement(args, bond, owner, delegate).await?;
    let verifier = Secp256k1Verifier::new();
    // Observing finalized blocks can expire jobs and record closure, but cannot
    // approve, sign, submit, or pay for any work.
    if recovery.journal.state().close_settled().is_none() {
        catch_up(&recovery.chain, &mut recovery.journal, &verifier).await?;
    }
    settlement_receipt(&recovery).await
}

/// Close exactly this retained funded channel using its signed journal and
/// verified finalized blocks. This requires no live object snapshot, provider
/// connection, owner funding authority, or new purchase. Callers bound its
/// lifetime; cancellation preserves the close intent for the next attempt.
pub async fn settle_channel(
    args: &PaidWorkOptions,
    bond: EdgeId,
    owner: PrincipalId,
    signer: &Secp256k1Signer,
) -> Result<FinalizedChannelSettlement> {
    let recovery = open_settlement(args, bond, owner, signer.party_key()).await?;
    let mut endpoint = ClientEndpoint::recover(recovery.journal, signer.clone())?;
    loop {
        endpoint
            .advance_close(&recovery.chain, &recovery.chain)
            .await?;
        if endpoint.state().close_settled().is_some() {
            break;
        }
        if !endpoint.state().is_closing() {
            endpoint.prepare_close().await?;
        }
        tokio::time::sleep(args.config.poll).await;
    }
    // The finalized receipt is verified through the same recovery reader used
    // after a crash. No requested or merely enqueued close releases funding.
    let channel = endpoint.state().channel();
    let settled = endpoint
        .state()
        .close_settled()
        .expect("loop observed finality");
    receipt(
        &recovery.chain,
        channel,
        recovery.bond,
        recovery.funding_value,
        settled,
    )
    .await
}

struct SettlementRecovery {
    journal: ChannelStore,
    chain: WorkBlocks<RemoteLightClient>,
    bond: EdgeId,
    funding_value: u64,
}

fn checked_descriptor(
    setup: &SetupStore,
    bond: EdgeId,
    owner: PrincipalId,
    delegate: Key,
) -> Result<&hellas_channel::model::setup::CloseDescriptor> {
    let descriptor = setup
        .state()
        .close_descriptor()
        .ok_or(PaidClientError::MissingState(
            "settlement channel descriptor",
        ))?;
    let client = descriptor.channel().payment_terms().parties().maker();
    if client.owner().to_bytes() != *owner.as_bytes()
        || client.signer() != delegate
        || client.payout_delegate() != Some(delegate)
        || descriptor.bond_edge() != bond
    {
        return Err(PaidClientError::InputMismatch("settlement client identity"));
    }
    if setup.state().origin().is_none() {
        return Err(PaidClientError::MissingState("settlement channel origin"));
    }
    Ok(descriptor)
}

async fn open_settlement(
    args: &PaidWorkOptions,
    bond: EdgeId,
    owner: PrincipalId,
    delegate: Key,
) -> Result<SettlementRecovery> {
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
    let setup = SetupStore::open_existing(
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
    let descriptor = checked_descriptor(&setup, bond, owner, delegate)?;
    let channel = descriptor.channel().clone();
    let values = signed.offer().policy.expected_payment_values;
    let funding_value = values
        .value()
        .checked_add(values.reserve())
        .ok_or(PaidClientError::InputMismatch("settlement funding value"))?;
    let origin = setup
        .state()
        .origin()
        .ok_or(PaidClientError::MissingState("settlement channel origin"))?;
    let journal = ChannelStore::open_existing(
        &args.journal_root,
        channel.clone(),
        descriptor.expected_settlement()?,
        Role::Client,
        origin,
        hellas_store::ContentStore::new(),
        &verifier,
    )
    .await?;
    if !journal.state().origin_observed() {
        return Err(PaidClientError::MissingState(
            "settlement origin observation",
        ));
    }
    let timeout = super::read_timeout(args.timeout);
    let remote = crate::client_chain::connect(&args.config, timeout).await?;
    let chain = WorkBlocks::new(remote)
        .with_read_retry(args.config.poll, timeout)
        .with_min_height(journal.state().cursor().0);
    Ok(SettlementRecovery {
        journal,
        chain,
        bond,
        funding_value,
    })
}

async fn settlement_receipt(
    recovery: &SettlementRecovery,
) -> Result<Option<FinalizedChannelSettlement>> {
    let Some(settled) = recovery.journal.state().close_settled() else {
        return Ok(None);
    };
    receipt(
        &recovery.chain,
        recovery.journal.state().channel(),
        recovery.bond,
        recovery.funding_value,
        settled,
    )
    .await
    .map(Some)
}

async fn receipt(
    chain: &WorkBlocks<RemoteLightClient>,
    channel: &hellas_channel::model::work::PaidChannel,
    bond: EdgeId,
    funding_value: u64,
    settled: hellas_channel::work_store::CloseSettlement,
) -> Result<FinalizedChannelSettlement> {
    let block = chain
        .block_at(settled.height)
        .await?
        .ok_or(PaidClientError::MissingState("finalized settlement block"))?;
    let (client_returned, provider_payout) = close_payouts(
        &block,
        channel,
        settled.height,
        settled.payload,
        settled.provider_payout,
    )?;
    Ok(FinalizedChannelSettlement {
        network: channel.network(),
        channel: channel.id(),
        bond_edge: bond,
        payment_edge: channel.payment_edge(),
        height: block.height,
        payload: block.payload,
        funding_value,
        client_returned,
        provider_payout,
    })
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
