//! Settle retained funding and recover exact certified returns without funding
//! or connecting to a provider. Evidence recovery alone never submits a transaction.
use super::*;
use hellas_auth::{Digest, authority::PrincipalId};
use hellas_channel::work::ClientChannel;
use hellas_channel::work_store::ChannelStore;
use hellas_kernel::{Key, NetworkId};
use hellas_private::StoreLocation;

/// The certified read of one client channel a close step decides from.
pub(super) async fn channel_read(
    chain: &WorkBlocks<RemoteLightClient>,
    channel: &hellas_channel::model::work::PaidChannel,
) -> Result<hellas_chain::WorkChannelSnapshot> {
    Ok(chain
        .work_channel_snapshot(WorkChannelQuery {
            bond_edge: channel.payment_terms().bond_edge,
            payment_edge: Some(channel.payment_edge()),
            funding: Default::default(),
        })
        .await?
        .ok_or(PaidClientError::MissingState(
            "no certified channel state is available",
        ))?
        .into_inner())
}

/// Drives one client close to finality.
///
/// The loop is shared by the live session and offline settlement because the
/// two failures it must survive are the same: a start that was not included
/// before its window closed must be replaced, and a source or sink that
/// refuses one attempt must not end the wait. `advance_close` applies each
/// read, resubmits the retained start and, once a contest is answered or its
/// window has shut, offers the adjudicated close; `prepare_close` returns the
/// retained start while it can still land and signs a replacement once it
/// cannot, and a fresh start is handed to the chain as soon as it is signed:
/// its inclusion window is counted in blocks from the read it was signed at.
/// A source that fails is replaced by the next configured validator.
/// [`POLL`](hellas_channel::work::POLL) is the only pacing: this loop has no
/// deadline. Returns the source that observed the close.
pub(super) async fn settle_close<C>(
    client: &mut C,
    config: &WorkConfig,
    timeout: std::time::Duration,
) -> Result<WorkBlocks<RemoteLightClient>>
where
    C: ClientChannel + Send,
{
    let mut source_config = config.clone();
    let mut chain = None;
    loop {
        if chain.is_none() {
            let floor = client.client().await?.state().cursor().0;
            match crate::client_chain::connect_at(&source_config, timeout, floor).await {
                Ok(remote) => chain = Some(WorkBlocks::new(remote).with_min_height(floor)),
                Err(error) => {
                    tracing::debug!(%error, "paid settlement is waiting for a chain source");
                    source_config.chain.rotate_validators();
                }
            }
        }
        if let Some(source) = chain.as_ref() {
            match close_step(client, source).await {
                Ok(true) => return Ok(chain.expect("the source that settled")),
                Ok(false) => {}
                Err(
                    PaidClientError::Query(_)
                    | PaidClientError::CatchUp(hellas_channel::work_close::CatchUpError::Source(_)),
                ) => {
                    chain = None;
                    source_config.chain.rotate_validators();
                }
                Err(error) => return Err(error),
            }
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "inventory class B: certified close; rollout 3"
        )]
        tokio::time::sleep(hellas_channel::work::POLL).await;
    }
}

/// One read, one close step, and a start signed and sent if none is live.
/// Returns whether the close is settled.
async fn close_step<C>(client: &mut C, chain: &WorkBlocks<RemoteLightClient>) -> Result<bool>
where
    C: ClientChannel + Send,
{
    use hellas_channel::work_close::TxSink as _;
    let channel = client.client().await?.state().channel().clone();
    let snapshot = channel_read(chain, &channel).await?;
    let mut endpoint = client.client().await?;
    endpoint
        .advance_close(&snapshot.observed_channel(), chain)
        .await?;
    if endpoint.state().close_settled().is_some() {
        return Ok(true);
    }
    if !endpoint.state().is_closing() {
        let start = endpoint.prepare_close().await?;
        drop(endpoint);
        chain
            .submit(hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start),
            ))
            .await
            .map_err(hellas_channel::work_close::CatchUpError::from)?;
    }
    Ok(false)
}

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
    root: &StoreLocation,
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
        let setup = setup.into_state().await;
        let (_, signed) = setup
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
            setup.end(),
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

/// Recover a specific channel's settlement from its signed journals, one
/// certified read of the channel, and its two payout coins. Returns `None`
/// for a channel that has not closed. A payout coin already spent is an
/// error, never a zero-spend result.
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
    // Observing the channel can expire jobs and record closure, but cannot
    // approve, sign, submit, or pay for any work.
    let result = async {
        if recovery.journal.state().close_settled().is_none() {
            let channel = recovery.journal.state().channel().clone();
            let snapshot = channel_read(&recovery.chain, &channel).await?;
            hellas_channel::work_close::observe(
                &mut recovery.journal,
                &snapshot.observed_channel(),
                &verifier,
            )
            .await?;
        }
        settlement_receipt(&recovery).await
    }
    .await;
    let closed = recovery.journal.close().await;
    let value = result?;
    closed?;
    Ok(value)
}

/// Close exactly this retained funded channel using its signed journal and
/// certified reads of the channel. This requires no provider connection,
/// owner funding authority, or new purchase. Callers bound its
/// lifetime; cancellation preserves the close intent for the next attempt.
pub async fn settle_channel(
    args: &PaidWorkOptions,
    bond: EdgeId,
    owner: PrincipalId,
    signer: &Secp256k1Signer,
) -> Result<FinalizedChannelSettlement> {
    let recovery = open_settlement(args, bond, owner, signer.party_key()).await?;
    let mut endpoint = ClientEndpoint::recover(recovery.journal, signer.clone())?;
    let result = async {
        let chain = settle_close(
            &mut endpoint,
            &args.config,
            super::read_timeout(args.timeout),
        )
        .await?;
        // The receipt is read the same way after a crash. No requested or
        // merely enqueued close releases funding.
        let channel = endpoint.state().channel();
        let settled = endpoint
            .state()
            .close_settled()
            .expect("loop observed the close");
        receipt(
            &chain,
            channel,
            recovery.bond,
            recovery.funding_value,
            settled,
        )
        .await
    }
    .await;
    let closed = endpoint.close().await;
    let value = result?;
    closed?;
    Ok(value)
}

struct SettlementRecovery {
    journal: ChannelStore,
    chain: WorkBlocks<RemoteLightClient>,
    bond: EdgeId,
    funding_value: u64,
}

fn checked_descriptor(
    setup: &hellas_channel::work_store::SetupState,
    bond: EdgeId,
    owner: PrincipalId,
    delegate: Key,
) -> Result<&hellas_channel::model::setup::CloseDescriptor> {
    let descriptor = setup
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
    if setup.origin().is_none() {
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
    let found =
        hellas_channel::work_store::discover_setups(&args.journal_root(), args.config.network())
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
        &args.journal_root(),
        args.config.network(),
        bond,
        Role::Client,
        &verifier,
    )
    .await?;
    let setup = setup.into_state().await;
    let (_, signed) = setup
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
        .origin()
        .ok_or(PaidClientError::MissingState("settlement channel origin"))?;
    let mut journal = ChannelStore::open_existing(
        &args.journal_root(),
        channel.clone(),
        descriptor.expected_settlement()?,
        Role::Client,
        origin,
        args.content.clone(),
        &verifier,
    )
    .await?;
    let chain = async {
        let timeout = super::read_timeout(args.timeout);
        let remote =
            crate::client_chain::connect_at(&args.config, timeout, journal.state().cursor().0)
                .await?;
        Ok(WorkBlocks::new(remote).with_min_height(journal.state().cursor().0))
    }
    .await;
    let chain = match chain {
        Ok(chain) => chain,
        Err(error) => {
            // The read failure is the cause; a close failure is secondary.
            let _ = journal.close().await;
            return Err(error);
        }
    };
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
    let (client_returned, provider_payout) = close_payouts(chain, channel).await?;
    Ok(FinalizedChannelSettlement {
        network: channel.network(),
        channel: channel.id(),
        bond_edge: bond,
        payment_edge: channel.payment_edge(),
        height: settled.height,
        payload: settled.payload,
        funding_value,
        client_returned,
        provider_payout,
    })
}

/// What a closed payment edge paid each party, read from the two coins its
/// close issues at fixed ids: the provider's at index 0 and the client's at
/// index 1, whatever route closed it.
///
/// A coin already spent leaves nothing to read, and that is an error rather
/// than a zero.
pub(super) async fn close_payouts(
    chain: &WorkBlocks<RemoteLightClient>,
    channel: &hellas_channel::model::work::PaidChannel,
) -> Result<(u64, u64)> {
    use hellas_chain::LightClient as _;
    let ids = payout_coin_ids(channel);
    let read = chain
        .client()
        .get_objects(ids.map(hellas_chain::domain::ObjectKey::Coin).to_vec())
        .await?
        .ok_or(PaidClientError::MissingState(
            "no certified state for the payouts",
        ))?;
    let value = |id| {
        read.coin(id)?
            .map(|coin| coin.value)
            .ok_or(PaidClientError::MissingState(
                "settlement payout already spent",
            ))
    };
    Ok((value(ids[1])?, value(ids[0])?))
}

/// The two coins every close of `channel`'s payment edge issues: the
/// provider's at index 0, the client's at index 1. A payout's id is fixed
/// by the edge, its index and its owner, never by its value or delegate.
fn payout_coin_ids(
    channel: &hellas_channel::model::work::PaidChannel,
) -> [hellas_kernel::CoinId; 2] {
    let parties = channel.payment_terms().parties();
    let edge = channel.payment_edge();
    [
        parties.taker().payout(0, false).id(edge, 0),
        parties.maker().payout(0, false).id(edge, 1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_channel::test_support::channel::{
        HORIZON, OMISSION_BOND, STAKE, bond_edge, bond_terms_for, channel_policy, payment_edge,
        payment_terms_for, signer,
    };
    use hellas_kernel::{BlockHeight, List, MAX_EDGE_OUTPUTS, Parties, PartyKeys, Payout, Tx};

    /// The receipt reads the coins a close issued by id, without the close
    /// itself. That holds only if those ids are the ones the kernel derives
    /// for the close's outputs, whatever they pay and to whichever delegate.
    #[test]
    fn payout_coin_ids_are_the_ones_any_close_issues() {
        let owner = signer(0x31).party_key();
        let delegate = signer(0x32).party_key();
        let provider = signer(0x33).party_key();
        let parties = Parties::new(
            PartyKeys::sole(provider),
            PartyKeys::new(owner, delegate, Some(delegate)),
        );
        let terms = payment_terms_for(
            bond_edge(),
            bond_terms_for(
                parties,
                BlockHeight::new(HORIZON),
                Payout::new(provider, STAKE),
                40,
            ),
            hellas_channel::model::work::private_policy_commitment(
                hellas_channel::test_support::channel::network(),
                &hellas_channel::test_support::channel::SALT,
                &channel_policy(),
            ),
            8,
            OMISSION_BOND,
        );
        let channel = hellas_channel::model::work::PaidChannel::new(
            hellas_channel::test_support::channel::network(),
            payment_edge(),
            terms,
            &hellas_channel::test_support::channel::SALT,
            channel_policy(),
        )
        .unwrap();
        let parties = channel.payment_terms().parties();
        for (paid, returned, owner_signed) in [
            (40, 60, [false, false]),
            (0, 100, [true, true]),
            (75, 25, [true, false]),
        ] {
            let mut outputs = [parties.taker().payout(paid, owner_signed[1]); MAX_EDGE_OUTPUTS];
            outputs[1] = parties.maker().payout(returned, owner_signed[0]);
            let issued = Tx::close_output_ids(channel.payment_edge(), &List::take(outputs, 2));
            assert_eq!(issued.as_slice(), payout_coin_ids(&channel).as_slice());
        }
    }
}
