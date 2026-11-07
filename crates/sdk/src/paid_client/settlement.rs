//! Settle retained funding and recover exact certified returns without funding
//! or connecting to a provider. Evidence recovery alone never submits a transaction.
use super::*;
use hellas_auth::{Digest, authority::PrincipalId};
use hellas_channel::work::ClientChannel;
use hellas_channel::work_close::{FinalizedBlocks, FinalizedWork, TxSink, catch_up};
use hellas_channel::work_store::ChannelStore;
use hellas_kernel::{Key, NetworkId, Tx};
use hellas_private::StoreLocation;

/// Drives one client close to finality.
///
/// The loop is shared by the live session and offline settlement because the
/// two failures it must survive are the same: a start that was not included
/// before its window closed must be replaced, and a source or sink that
/// refuses one attempt must not end the wait. `advance_close` resubmits the
/// retained start and, once a contest exists, offers the answer and the
/// adjudicated close; `prepare_close` returns the retained start while it can
/// still land and signs a replacement once it cannot. `poll` is the only
/// pacing: this loop has no deadline.
pub(super) async fn settle_close<C, S, T>(
    client: &mut C,
    source: &S,
    sink: &T,
    poll: std::time::Duration,
) -> Result<u64>
where
    C: ClientChannel + Send,
    S: FinalizedBlocks + ?Sized,
    T: TxSink + ?Sized,
{
    loop {
        {
            let mut endpoint = client.client().await?;
            endpoint.advance_close(source, sink).await?;
            if let Some(settled) = endpoint.state().close_settled() {
                return Ok(settled.provider_payout);
            }
            if !endpoint.state().is_closing() {
                endpoint.prepare_close().await?;
            }
        }
        tokio::time::sleep(poll).await;
    }
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
    let result = async {
        if recovery.journal.state().close_settled().is_none() {
            catch_up(&recovery.chain, &mut recovery.journal, &verifier).await?;
        }
        settlement_receipt(&recovery).await
    }
    .await;
    recovery.journal.close().await;
    result
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
    let result = async {
        settle_close(
            &mut endpoint,
            &recovery.chain,
            &recovery.chain,
            args.config.poll,
        )
        .await?;
        // The finalized receipt is verified through the same recovery reader used
        // after a crash. No requested or merely enqueued close releases funding.
        let channel = endpoint.state().channel();
        let settled = endpoint
            .state()
            .close_settled()
            .expect("loop observed finality");
        let pending = endpoint
            .state()
            .close_history()
            .map(|history| history.pending);
        receipt(
            &recovery.chain,
            channel,
            recovery.bond,
            recovery.funding_value,
            settled,
            pending,
        )
        .await
    }
    .await;
    endpoint.close().await;
    result
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
    args.config.clone().validate()?;
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
        hellas_store::ContentStore::new(),
        &verifier,
    )
    .await?;
    let chain = async {
        if !journal.state().origin_observed() {
            return Err(PaidClientError::MissingState(
                "settlement origin observation",
            ));
        }
        let timeout = super::read_timeout(args.timeout);
        let remote =
            crate::client_chain::connect_at(&args.config, timeout, journal.state().cursor().0)
                .await?;
        Ok(WorkBlocks::new(remote)
            .with_read_retry(args.config.poll, timeout)
            .with_min_height(journal.state().cursor().0))
    }
    .await;
    let chain = match chain {
        Ok(chain) => chain,
        Err(error) => {
            journal.close().await;
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
        recovery
            .journal
            .state()
            .close_history()
            .map(|history| history.pending),
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
    pending: Option<hellas_kernel::PendingPaymentClose>,
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
        pending,
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

/// Replays the settlement block's contest moves through the kernel's own
/// transitions, on top of the retained contest record.
///
/// The observer stops advancing
/// [`CloseHistory`](hellas_channel::work_store::CloseHistory) once a channel
/// settles, so a start or response ordered before the close in the settling
/// block never reaches the retained record. Applying the same transitions the
/// kernel applied reproduces the record the close was checked against,
/// including an owner action that a later freeze inherits.
fn block_pending(
    block: &FinalizedWork,
    channel: &hellas_channel::model::work::PaidChannel,
    retained: Option<hellas_kernel::PendingPaymentClose>,
) -> Result<Option<hellas_kernel::PendingPaymentClose>> {
    let mut pending = retained;
    for tx in &block.txs {
        match tx {
            Tx::Move {
                action: hellas_kernel::Move::StartPaymentClose(start),
            } if start.payment_edge() == channel.payment_edge() => {
                pending = Some(
                    hellas_kernel::PendingPaymentClose::from_accepted_start(
                        channel.network(),
                        block.height,
                        start,
                    )
                    .ok_or(PaidClientError::InputMismatch("settlement close start"))?,
                );
            }
            Tx::Move {
                action: hellas_kernel::Move::RespondPaymentClose(response),
            } if response.payment_edge() == channel.payment_edge() => {
                if let Some(record) = pending {
                    pending = Some(record.with_accepted_response(response));
                }
            }
            Tx::Close { input, .. } if *input == channel.payment_edge() => break,
            _ => {}
        }
    }
    Ok(pending)
}

fn close_payouts(
    block: &FinalizedWork,
    channel: &hellas_channel::model::work::PaidChannel,
    height: u64,
    payload: [u8; 32],
    expected_provider: u64,
    retained: Option<hellas_kernel::PendingPaymentClose>,
) -> Result<(u64, u64)> {
    if block.height != height || block.payload != payload {
        return Err(PaidClientError::InputMismatch("settlement finalized block"));
    }
    let pending = block_pending(block, channel, retained)?;
    let mut closes = block.txs.iter().filter_map(|tx| match tx {
        Tx::Close {
            input,
            proof,
            outputs,
        } if *input == channel.payment_edge() => Some((proof, outputs)),
        _ => None,
    });
    let (proof, outputs) = closes.next().ok_or(PaidClientError::MissingState(
        "settlement close transaction",
    ))?;
    if closes.next().is_some() {
        return Err(PaidClientError::InputMismatch("duplicate settlement close"));
    }
    // The close's own witness decides which destinations may appear; the
    // kernel's `PartyKeys::is_destination` checks owner and delegate together,
    // so an owner-signed exit is accepted undelegated while any other
    // delegate change is still refused.
    let owner_signed = proof
        .payment_close_owner_signed(pending.as_ref())
        .ok_or(PaidClientError::InputMismatch("settlement payment proof"))?;
    let parties = channel.payment_terms().parties();
    let mut returned = 0u64;
    let mut paid = 0u64;
    for payout in outputs.as_slice() {
        let total = if parties.maker().is_destination(*payout, owner_signed[0]) {
            &mut returned
        } else if parties.taker().is_destination(*payout, owner_signed[1]) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_channel::test_support::channel::{
        CURSOR, Checked, HORIZON, OMISSION_BOND, PRICE, STAKE, bond_edge, bond_terms_for,
        channel_policy, checked_job, payload_at, payment_edge, payment_terms_for, signer,
    };
    use hellas_channel::work::admit_payment;
    use hellas_channel::work_close::BlockSourceError;
    use hellas_kernel::{
        BlockHeight, List, MAX_EDGE_OUTPUTS, MIN_OMIT_RESPONSE_BLOCKS, Move, Parties, PartyAuth,
        PartyKeys, Payout, Proof, Sig,
    };
    use hellas_rpc::services::work::WorkClientImpl;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    // ── Finding 7: an expired start is replaced ───────────────────────

    /// The fixture's one job, paid, so the client's book holds no open job
    /// and it may sign a close.
    async fn paid_job() -> Checked {
        let mut fixture = checked_job().await;
        let (transport, server) = hellas_channel::test_support::transport::transport_pair();
        let serving =
            hellas_channel::test_support::channel::serve_work(server, fixture.service.clone());
        let id = fixture.id;
        let paid = admit_payment(&WorkClientImpl::new(transport), &mut fixture.client, id).await;
        serving.abort();
        paid.expect("the fixture job is paid");
        fixture
    }

    /// A finalized history the test writes: every tip query adds one empty
    /// block, and every accepted submission rides in the next block. The
    /// first close start is never admitted, which is the partition this
    /// regression is about.
    struct SimChain {
        state: Mutex<SimState>,
    }

    struct SimState {
        height: u64,
        blocks: BTreeMap<u64, FinalizedWork>,
        pending: Vec<Tx>,
        first_start: Option<hellas_kernel::PaymentCloseStart>,
        starts: Vec<hellas_kernel::PaymentCloseStart>,
    }

    impl SimChain {
        fn new(height: u64) -> Self {
            Self {
                state: Mutex::new(SimState {
                    height,
                    blocks: BTreeMap::new(),
                    pending: Vec::new(),
                    first_start: None,
                    starts: Vec::new(),
                }),
            }
        }

        fn starts(&self) -> Vec<hellas_kernel::PaymentCloseStart> {
            self.state.lock().unwrap().starts.clone()
        }
    }

    impl FinalizedBlocks for SimChain {
        async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
            let mut state = self.state.lock().unwrap();
            state.height += 1;
            let height = state.height;
            let txs = std::mem::take(&mut state.pending);
            state.blocks.insert(
                height,
                FinalizedWork {
                    height,
                    parent: payload_at(height - 1),
                    payload: payload_at(height),
                    txs,
                },
            );
            Ok(Some(height))
        }

        async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
            Ok(self.state.lock().unwrap().blocks.get(&height).cloned())
        }
    }

    impl TxSink for SimChain {
        async fn submit(&self, tx: Tx) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
            let mut state = self.state.lock().unwrap();
            if let Tx::Move {
                action: Move::StartPaymentClose(start),
            } = &tx
            {
                let start = start.clone();
                match &state.first_start {
                    None => {
                        state.first_start = Some(start.clone());
                        state.starts.push(start);
                        return Ok(hellas_rpc::SubmitTxOutcome::ValidationRejected);
                    }
                    Some(first) if *first == start => {
                        return Ok(hellas_rpc::SubmitTxOutcome::ValidationRejected);
                    }
                    Some(_) => state.starts.push(start),
                }
            }
            state.pending.push(tx);
            Ok(hellas_rpc::SubmitTxOutcome::Enqueued)
        }
    }

    #[tokio::test]
    async fn an_expired_close_start_is_replaced_and_settlement_completes() {
        let fixture = paid_job().await;
        let mut client = fixture.client;
        let sim = SimChain::new(CURSOR);
        let provider_payout = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            settle_close(&mut client, &sim, &sim, std::time::Duration::from_millis(1)),
        )
        .await
        .expect("settlement completes once the replacement lands")
        .unwrap();
        assert_eq!(provider_payout, PRICE);
        let starts = sim.starts();
        assert_eq!(
            starts.len(),
            2,
            "the expired start is replaced exactly once"
        );
        assert_ne!(starts[0], starts[1]);
        assert_eq!(
            client
                .state()
                .close_settled()
                .map(|settled| settled.provider_payout),
            Some(PRICE)
        );
    }

    // ── Finding 9: an owner exit pays undelegated ─────────────────────

    /// A delegated client channel, and the parties its close must pay.
    fn delegated_channel() -> (
        hellas_channel::model::work::PaidChannel,
        Parties,
        hellas_kernel::Key,
        hellas_kernel::Key,
    ) {
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
            MIN_OMIT_RESPONSE_BLOCKS,
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
        (channel, parties, owner, provider)
    }

    fn close_block(
        channel: &hellas_channel::model::work::PaidChannel,
        proof: Proof,
        outputs: [Payout; MAX_EDGE_OUTPUTS],
    ) -> FinalizedWork {
        FinalizedWork {
            height: 7,
            parent: [0; 32],
            payload: [1; 32],
            txs: vec![Tx::close(
                channel.payment_edge(),
                proof,
                List::take(outputs, 2),
            )],
        }
    }

    #[test]
    fn payment_receipts_require_a_payment_proof_and_its_contest() {
        let (channel, parties, _, _) = delegated_channel();
        let mut outputs = [parties.taker().payout(40, false); MAX_EDGE_OUTPUTS];
        outputs[1] = parties.maker().payout(60, false);
        for proof in [
            Proof::mutual(
                PartyAuth::signer(Sig::default()),
                PartyAuth::signer(Sig::default()),
            ),
            Proof::timeout(
                hellas_kernel::Terms::work_payment(channel.payment_terms().clone()),
                None,
            ),
            Proof::adjudicated(hellas_kernel::PaymentContestCommitment::from_bytes([0; 32])),
        ] {
            let block = close_block(&channel, proof, outputs);
            assert!(matches!(
                close_payouts(&block, &channel, 7, [1; 32], 40, None),
                Err(PaidClientError::InputMismatch("settlement payment proof"))
            ));
        }
    }

    #[test]
    fn an_owner_signed_close_pays_undelegated_and_a_wrong_delegate_is_refused() {
        let (channel, parties, owner, provider) = delegated_channel();
        let provider_payout = parties.taker().payout(40, false);
        let client_payout = parties.maker().payout(60, true);
        assert_eq!(client_payout, Payout::new(owner, 60));
        assert_eq!(provider_payout, Payout::new(provider, 40));

        // The owner signs the maker side; the provider signs its own.
        let proof = Proof::freeze(
            40,
            (7, 7),
            PartyAuth::owner(Sig::default()),
            PartyAuth::signer(Sig::default()),
        );
        let mut outputs = [provider_payout; MAX_EDGE_OUTPUTS];
        outputs[1] = client_payout;
        let block = close_block(&channel, proof, outputs);
        assert_eq!(
            close_payouts(&block, &channel, 7, [1; 32], 40, None).unwrap(),
            (60, 40)
        );

        // The same owner-signed close carrying the committed delegate is not
        // an owner exit and is refused.
        let mut outputs = [provider_payout; MAX_EDGE_OUTPUTS];
        outputs[1] = parties.maker().payout(60, false);
        let block = close_block(
            &channel,
            Proof::freeze(
                40,
                (7, 7),
                PartyAuth::owner(Sig::default()),
                PartyAuth::signer(Sig::default()),
            ),
            outputs,
        );
        assert!(matches!(
            close_payouts(&block, &channel, 7, [1; 32], 40, None),
            Err(PaidClientError::InputMismatch("settlement payout identity"))
        ));
    }

    /// A block that settles the channel in the same transaction sequence as
    /// the owner's start: the observer never advances the retained close
    /// history past it, so only the block itself records the owner action a
    /// delegate-signed freeze inherits.
    #[test]
    fn a_same_block_owner_start_pays_undelegated_through_the_freeze() {
        let (channel, parties, _, _) = delegated_channel();
        let start = || {
            Tx::move_action(Move::StartPaymentClose(
                hellas_kernel::PaymentCloseStart::new(
                    channel.payment_edge(),
                    hellas_kernel::Terms::work_payment(channel.payment_terms().clone()),
                    hellas_kernel::Party::Maker,
                    (7, 7),
                    None,
                    PartyAuth::owner(Sig::default()),
                ),
            ))
        };
        let proof = Proof::freeze(
            40,
            (7, 7),
            PartyAuth::signer(Sig::default()),
            PartyAuth::signer(Sig::default()),
        );
        let provider_payout = parties.taker().payout(40, false);
        let mut outputs = [provider_payout; MAX_EDGE_OUTPUTS];
        outputs[1] = parties.maker().payout(60, true);
        let block = |txs: Vec<Tx>| FinalizedWork {
            height: 7,
            parent: [0; 32],
            payload: [1; 32],
            txs,
        };

        // The owner start and the delegate-signed freeze settle together.
        let tx = Tx::close(
            channel.payment_edge(),
            proof.clone(),
            List::take(outputs, 2),
        );
        assert_eq!(
            close_payouts(&block(vec![start(), tx]), &channel, 7, [1; 32], 40, None).unwrap(),
            (60, 40)
        );

        // Without the start in the block the inherited owner action is gone,
        // and the same close cannot pay the owner's bare destination.
        let tx = Tx::close(
            channel.payment_edge(),
            proof.clone(),
            List::take(outputs, 2),
        );
        assert!(matches!(
            close_payouts(&block(vec![tx]), &channel, 7, [1; 32], 40, None),
            Err(PaidClientError::InputMismatch("settlement payout identity"))
        ));

        // The start does not license the committed delegate either.
        outputs[1] = parties.maker().payout(60, false);
        let tx = Tx::close(channel.payment_edge(), proof, List::take(outputs, 2));
        assert!(matches!(
            close_payouts(&block(vec![start(), tx]), &channel, 7, [1; 32], 40, None),
            Err(PaidClientError::InputMismatch("settlement payout identity"))
        ));
    }
}
