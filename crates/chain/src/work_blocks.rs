//! Handing finalized blocks to a paid endpoint's watcher.
//!
//! # Why an adapter and not a blanket impl
//!
//! The watcher's block source is `hellas_work::work_close::FinalizedBlocks`
//! and a light client is `crate::LightClient`. Both are foreign to each
//! other, so nothing can implement the first for every one of the
//! second; [`WorkBlocks`] is the one type that owns that pairing. It
//! adds no policy — every decision it could make is made by
//! [`FinalizedBlockView::decode`] above it or by the journal below it.
//!
//! # What crosses
//!
//! One block, checked. `decode` is what turns a bag of bytes beside a
//! finalization certificate into a block: it hashes the bytes against
//! the payload the certificate names, decodes them with the validator's
//! own codec, and checks the height and state root. Only then are the
//! transactions in it facts.
//!
//! They cross in consensus order, and the non-kernel ones are dropped
//! rather than reordered. That is not a projection the watcher has to
//! trust: a transfer or a merge cannot open a contest or close an edge,
//! so the relative order of everything that *can* is exactly the
//! validator's.
//!
//! # And one way back
//!
//! The same pairing carries a transaction *out*. An endpoint that could
//! read blocks and not submit would sign a start it had no way to hand
//! to anyone, so the sink is here rather than in a second adapter — one
//! light client, one channel, one direction each way.
//!
//! # And the state behind the blocks
//!
//! A setup driver needs a third thing: one coherent read of the two
//! edges, the bond's lease, and the liveness of the coins its retained
//! Opens spend. That is [`FinalizedWorkView`], and it is on the same
//! light client, so it is on the same adapter rather than a second one
//! a caller could pair with a different chain. What crosses is
//! [`FinalizedSetup`], which is `hellas_rpc`'s owned shape of the same
//! answer; the coherence it carries is the snapshot's, and
//! `WorkChannelSnapshot::finalized_setup` is what refuses to produce
//! one from a snapshot that asked about other coins.

use hellas_kernel::{Terms, Tx};
use hellas_work::work::WorkService;
use hellas_work::work_close::{
    BlockSourceError, CatchUpError, CloseError, CloseProgress, FinalizedBlocks, FinalizedWork,
    TxSink,
};
use hellas_work::work_open::{FinalizedSetup, SetupQuery, SetupView};

use crate::SubmitTxOutcome;
use crate::block_view::FinalizedBlockView;
use crate::domain::{Digest, Transaction};
use crate::light_client::{FinalizedBlockQuery, LightClient, QueryError};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};

/// One light client, as a paid endpoint's block source.
#[derive(Clone, Debug)]
pub struct WorkBlocks<C>(C);

/// What one production clock step did for a mounted paid channel.
#[derive(Debug)]
pub struct PaidWorkClockAdvance {
    /// The verified snapshot already read for settlement, reusable by admission.
    pub snapshot: Option<WorkChannelSnapshot>,
    /// The journaled start-or-response drive that ran first.
    pub close: CloseProgress,
    /// Submission outcome for a due adjudicated payment close.
    pub adjudication: Option<SubmitTxOutcome>,
    /// Submission outcome for a due completed-bond timeout.
    pub bond_timeout: Option<SubmitTxOutcome>,
}

/// Why one production clock step could not finish.
#[derive(Debug, thiserror::Error)]
pub enum PaidWorkClockError {
    /// The journaled close drive failed.
    #[error("the journaled close drive failed: {0}")]
    CloseDrive(#[source] CatchUpError),
    /// The coherent finalized channel read failed.
    #[error("the coherent finalized channel read failed: {0}")]
    Snapshot(#[source] QueryError),
    /// The endpoint could not derive the close consensus permits.
    #[error("the mounted endpoint could not derive its close: {0}")]
    Decision(#[source] CloseError),
    /// The connected transaction sink failed.
    #[error("the connected transaction sink failed: {0}")]
    Submission(#[source] BlockSourceError),
    /// The retained work-bond shape had no deterministic timeout payout.
    #[error("the mounted channel's embedded bond terms have no timeout payout")]
    TimeoutUnavailable,
}

impl PaidWorkClockError {
    /// Returns whether the connected chain should be replaced before retry.
    #[must_use]
    pub const fn source_failed(&self) -> bool {
        matches!(
            self,
            Self::CloseDrive(CatchUpError::Source(_)) | Self::Snapshot(_) | Self::Submission(_)
        )
    }
}

impl<C: LightClient> WorkBlocks<C> {
    /// Reads finalized blocks for a watcher through `client`.
    pub const fn new(client: C) -> Self {
        Self(client)
    }
}

/// Advances one mounted paid channel on the production clock.
///
/// The journaled close drive runs first. The endpoint is then borrowed
/// synchronously only long enough to copy the two edge ids and embedded
/// bond terms. One coherent finalized snapshot from `source` decides both
/// permissionless submissions: the payment close through
/// [`WorkService::adjudicated_close`], and the bond timeout when that same
/// read still contains the bond at or beyond its committed horizon.
///
/// `NoContest`, `OtherContest`, and `ResponseWindowOpen` are clock states,
/// not failures. They leave adjudication absent from the returned advance
/// and are reconsidered from a fresh snapshot on the next tick.
///
/// # Errors
///
/// Returns the failed journal drive, snapshot, decision, or submission.
/// A retained work-bond shape without a timeout payout is also refused.
pub async fn advance_paid_work_clock<S>(
    service: &WorkService,
    source: &S,
) -> Result<PaidWorkClockAdvance, PaidWorkClockError>
where
    S: FinalizedBlocks + FinalizedWorkView + TxSink + Sync,
{
    let close = service
        .advance_close(source, source)
        .await
        .map_err(PaidWorkClockError::CloseDrive)?;
    let (query, bond_terms) = service
        .with_state(|state| {
            let channel = state.channel();
            let payment_terms = channel.payment_terms();
            (
                WorkChannelQuery {
                    bond_edge: payment_terms.bond_edge,
                    payment_edge: channel.payment_edge(),
                    funding: Default::default(),
                },
                Terms::work_stake_bond(payment_terms.bond_terms.clone()),
            )
        })
        .map_err(|error| PaidWorkClockError::Decision(CloseError::Endpoint(error)))?;
    let bond_edge = query.bond_edge;
    let Some(snapshot) = source
        .work_channel_snapshot(query)
        .await
        .map_err(PaidWorkClockError::Snapshot)?
    else {
        return Ok(PaidWorkClockAdvance {
            snapshot: None,
            close,
            adjudication: None,
            bond_timeout: None,
        });
    };

    let adjudication = match service.adjudicated_close(&snapshot.observed_channel()) {
        Ok(tx) => Some(
            source
                .submit(tx)
                .await
                .map_err(PaidWorkClockError::Submission)?,
        ),
        Err(
            CloseError::NoContest
            | CloseError::OtherContest
            | CloseError::ResponseWindowOpen { .. },
        ) => None,
        Err(error) => return Err(PaidWorkClockError::Decision(error)),
    };

    let bond_timeout =
        if snapshot.bond().is_some() && snapshot.block().height >= bond_terms.timeout().get() {
            let tx = Tx::timeout_close(bond_edge, &bond_terms)
                .ok_or(PaidWorkClockError::TimeoutUnavailable)?;
            Some(
                source
                    .submit(tx)
                    .await
                    .map_err(PaidWorkClockError::Submission)?,
            )
        } else {
            None
        };

    Ok(PaidWorkClockAdvance {
        snapshot: Some(snapshot),
        close,
        adjudication,
        bond_timeout,
    })
}

/// Returns a payload digest as the 32 bytes a journal records.
///
/// Copied field by field rather than by a fallible conversion because
/// the two widths are the same width: a Sha256 digest is 32 bytes, and
/// this is only ever called on one. There is no shorter-digest case to
/// report, so there is no error here to swallow.
fn bytes(digest: &Digest) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let source: &[u8] = digest;
    for (slot, byte) in out.iter_mut().zip(source) {
        *slot = *byte;
    }
    out
}

impl<C: LightClient + FinalizedWorkView> SetupView for WorkBlocks<C> {
    async fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        let funding = query.funding;
        let Some(snapshot) = self
            .0
            .work_channel_snapshot(WorkChannelQuery {
                bond_edge: query.bond_edge,
                payment_edge: query.payment_edge,
                funding: funding.clone(),
            })
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        // The snapshot answers for the coins its own query named, and
        // the query above is the one built from `funding`. A `None`
        // here is a light client that answered a different question —
        // reported as a source failure, because a decision taken on it
        // would read another transaction's survivors as this one's.
        snapshot.finalized_setup(&funding).map(Some).ok_or_else(|| {
            BlockSourceError::new(
                "the work channel snapshot answers for other funding coins than were asked for",
            )
        })
    }
}

impl<C: LightClient + FinalizedWorkView> FinalizedWorkView for WorkBlocks<C> {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        self.0.work_channel_snapshot(query).await
    }
}

impl<C: LightClient> TxSink for WorkBlocks<C> {
    async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
        self.0
            .submit_tx(Transaction::Kernel(tx))
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))
    }
}

impl<C: LightClient> FinalizedBlocks for WorkBlocks<C> {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self
            .0
            .get_latest_block()
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))?
            .map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        let Some(finalized) = self
            .0
            .get_finalized_block(FinalizedBlockQuery::Height(height))
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        let view = FinalizedBlockView::decode(&finalized)
            .map_err(|error| BlockSourceError::new(error.to_string()))?;
        // The height a caller asked for, against the height the block
        // itself carries. `decode` has already tied the block to its own
        // snapshot; this is what ties that snapshot to the question.
        if view.height() != height {
            return Err(BlockSourceError::new(format!(
                "asked for finalized block {height} and was given {}",
                view.height(),
            )));
        }
        Ok(Some(FinalizedWork {
            height,
            parent: bytes(&view.parent()),
            payload: bytes(&view.payload()),
            txs: view
                .txs()
                .iter()
                .filter_map(|tx| match tx {
                    Transaction::Kernel(kernel) => Some(kernel.clone()),
                    _ => None,
                })
                .collect(),
        }))
    }
}

/// The setup driver against a real chain.
///
/// Everything below the driver is the node's own: a QMDB database, the
/// kernel executing into it, an owner index, a follower indexer holding
/// real finalization certificates, and a mempool the light client
/// submits into. What the tests substitute for is consensus itself —
/// [`Chain::seal`] plays the proposer, taking whatever the driver
/// submitted and putting it in the next block. Nothing else is stood in
/// for: the transactions are the bundle's own, the blocks are decoded
/// and checked by [`FinalizedBlockView`], and the objects the decision
/// reads come out of the database those transactions wrote.
#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_runtime::{Handle, Supervisor as _};
    use hellas_kernel::{
        BlockHash, BlockHeight, CoinId, Context as KernelContext, EdgeId, EdgeValues, Fees,
        Funding, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Move, Parties, Party, Payout,
        PendingSlot, Secp256k1Signer, Secp256k1Verifier, Terms as KernelTerms, Tx as KernelTx,
        WorkPaymentTerms, WorkStakeBondTerms,
    };
    use hellas_rpc::call::WithTrailer;
    use hellas_rpc::pb::work::{ExchangeSetupRequest, exchange_setup_response::Outcome};
    use hellas_rpc::protocol::work::{
        PaidChannelPolicyV1, PaidExecutionPolicyV1, private_policy_commitment,
    };
    use hellas_rpc::protocol::work_setup::{
        ProviderChannelPolicy, WorkChannelConfig, WorkChannelDescriptor,
    };
    use hellas_rpc::protocol::{ContentId, Digest as ProtocolDigest};
    use hellas_rpc::services::work_setup::WorkSetupHandler;
    use hellas_wire::TransportContext;
    use hellas_work::work_close::{BlockSourceError, adjudicated_close, close_start};
    use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
    use hellas_work::work_open::{SetupAdvance, SetupProgress, SetupStep, advance_setup};
    use hellas_work::work_store::{
        Role, SetupAbort, SetupEnd, SetupOrigin, SetupRecord, SetupScan, SetupStateError,
        SetupStore, WorkStoreError,
    };

    use crate::HellasBlock;
    use crate::app::Mempool;
    use crate::config::Config;
    use crate::domain::{KERNEL_FEES, SettlementKey, TEST_NETWORK, genesis_object_id};
    use crate::execution::store::{UtxoDatabase, utxo_db_config};
    use crate::execution::test_support::{
        consensus_fixture, finalization, index_block, index_genesis, run_qmdb,
    };
    use crate::execution::{ChainVerifier, execute_all};
    use crate::indexer::spawn_follower_indexer;
    use crate::light_client::ConsensusInfo;
    use crate::owner_index::{ApplyOutcome, OwnerIndex};
    use crate::rpc::LocalLightClient;
    use commonware_cryptography::Digestible as _;

    /// What the client funds its payment channel with.
    const FUNDING: u64 = 100;
    /// What the provider stakes on the bond.
    const STAKE: u64 = 12;
    /// One over half the funding, so the bond exceeds the capacity it
    /// leaves behind at zero fees.
    const OMISSION_BOND: u64 = 51;
    const HORIZON: u64 = 500;
    const SALT: [u8; 32] = [0x5a; 32];
    /// The window the provider measured its response probability over,
    /// and the one the terms admit.
    const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS + 4;

    fn signer(byte: u8) -> Secp256k1Signer {
        match Secp256k1Signer::from_secret_scalar([byte; 32]) {
            Ok(signer) => signer,
            Err(error) => panic!("a fixed scalar is a key: {error:?}"),
        }
    }

    fn provider() -> Secp256k1Signer {
        signer(0x22)
    }

    fn client() -> Secp256k1Signer {
        signer(0x21)
    }

    fn one_coin(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
        let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
        slots[0] = id;
        List::take(slots, 1)
    }

    fn no_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
        List::take(
            [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS],
            0,
        )
    }

    /// The genesis coin allocated to the client, and the one allocated
    /// to the provider. Allocation order fixes the two ids.
    fn client_coin() -> CoinId {
        CoinId::from_bytes(genesis_object_id(0).into())
    }

    fn provider_coin() -> CoinId {
        CoinId::from_bytes(genesis_object_id(1).into())
    }

    fn bond_terms() -> WorkStakeBondTerms {
        WorkStakeBondTerms {
            parties: Parties::new(provider().party_key(), client().party_key()),
            timeout: BlockHeight::new(HORIZON),
            timeout_outputs: List::take(
                [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
                1,
            ),
            max_job_price: 4,
        }
    }

    fn bond_funding() -> Funding {
        Funding::new(one_coin(provider_coin()), no_coins())
    }

    fn bond_edge() -> EdgeId {
        KernelTx::edge_id_of(&bond_funding(), &KernelTerms::work_stake_bond(bond_terms()))
    }

    fn channel_policy() -> PaidChannelPolicyV1 {
        PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        }
    }

    fn execution_policy() -> PaidExecutionPolicyV1 {
        PaidExecutionPolicyV1 {
            allowed_environment: ContentId::from_bytes([0x31; 32]),
            generation_policy_digest: ProtocolDigest::from_bytes([0x32; 32]),
            identity_source_digest: ProtocolDigest::from_bytes([0x33; 32]),
            max_prompt_tokens: 512,
            max_new_tokens: 128,
            max_stop_token_ids: 4,
            max_spool_bytes: 1_048_576,
            max_encoded_result_frame: 262_144,
            max_encoded_quote_response: 1_048_576,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
            fixed_price: 10,
        }
    }

    /// The edge the provider requires the client to fund: the whole
    /// allocation, no reserve, and the chain's zero fees.
    fn expected_values() -> EdgeValues {
        EdgeValues::new(FUNDING, 0, Fees::new(0, 0, 0, 0))
    }

    fn provider_policy() -> ProviderChannelPolicy {
        ProviderChannelPolicy {
            network: TEST_NETWORK,
            policy_salt: SALT,
            channel_policy: channel_policy(),
            execution_policy: execution_policy().into(),
            expected_payment_values: expected_values(),
            min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        }
    }

    fn payment_terms() -> WorkPaymentTerms {
        WorkPaymentTerms {
            bond_edge: bond_edge(),
            bond_terms: bond_terms(),
            private_policy_commitment: private_policy_commitment(
                TEST_NETWORK,
                &SALT,
                &channel_policy(),
            ),
            omit_response_blocks: WINDOW,
            start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
            omission_bond: OMISSION_BOND,
        }
    }

    fn payment_edge_of(funding: &Funding) -> EdgeId {
        KernelTx::edge_id_of(funding, &KernelTerms::work_payment(payment_terms()))
    }

    /// A sink that will not take a transaction.
    ///
    /// Stands in for the moment between the journal write and the
    /// broadcast: the endpoint has committed that it is about to send,
    /// and the send does not happen.
    struct RefusingSink;

    impl TxSink for RefusingSink {
        async fn submit(
            &self,
            _tx: hellas_kernel::Tx,
        ) -> Result<SubmitTxOutcome, BlockSourceError> {
            Err(BlockSourceError::new("the sink refuses"))
        }
    }

    /// One node: a database, the kernel over it, an owner index, an
    /// indexer of finalized blocks, and a mempool.
    struct Chain {
        database: UtxoDatabase<commonware_runtime::tokio::Context>,
        index: OwnerIndex,
        indexer: crate::indexer::ChainIndexer,
        mempool: Mempool,
        fixture: crate::execution::test_support::ConsensusFixture,
        allocations: Vec<(SettlementKey, u64)>,
        head: HellasBlock,
        height: u64,
        /// How many mempool entries earlier blocks already carried.
        /// Nothing else drains this mempool, so everything past it is
        /// what the driver submitted since.
        sealed: usize,
        _indexer_task: Handle<()>,
    }

    impl Chain {
        async fn start(runtime: commonware_runtime::tokio::Context, name: &str) -> Self {
            let indexer_context = runtime.child("chain_indexer");
            let config = utxo_db_config(&runtime, name, 1024, 8);
            let database = <UtxoDatabase<_> as DatabaseSet<_>>::init(runtime, config).await;
            let allocations = vec![
                (SettlementKey::from(client().party_key()), FUNDING),
                (SettlementKey::from(provider().party_key()), STAKE),
            ];
            let genesis = index_genesis();
            let fixture = consensus_fixture(97);
            let (indexer, task) = spawn_follower_indexer(
                indexer_context,
                name,
                Config {
                    mailbox_size: 32,
                    replay_buffer: 32,
                    write_buffer: 32,
                    page_cache_size: 1024,
                    page_cache_count: 8,
                    ..Config::default()
                },
                fixture.verifier.clone(),
                genesis.clone(),
            )
            .await
            .expect("chain indexer");
            let index = OwnerIndex::new(TEST_NETWORK, &genesis, allocations.clone());
            Self {
                database,
                index,
                indexer,
                mempool: Mempool::default(),
                fixture,
                allocations,
                head: genesis,
                height: 0,
                sealed: 0,
                _indexer_task: task,
            }
        }

        fn light_client(&self) -> LocalLightClient {
            LocalLightClient::new(
                self.database.clone(),
                self.index.clone(),
                self.mempool.clone(),
                self.indexer.clone(),
                ConsensusInfo {
                    validators: Vec::new(),
                    threshold_identity: Vec::new(),
                    network_id: TEST_NETWORK.as_str().to_string(),
                },
            )
        }

        /// Puts everything submitted since the last block into the next
        /// one, executes it, finalizes it, and indexes it.
        async fn seal(&mut self) -> HellasBlock {
            let pending = self.mempool.test_transactions().await;
            let fresh = pending[self.sealed..].to_vec();
            self.sealed = pending.len();
            self.height += 1;

            let batches = self.database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    TEST_NETWORK,
                    BlockHeight::new(self.height),
                    BlockHash::from_bytes([0; BlockHash::LENGTH]),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &fresh,
                &self.allocations,
                batches,
            )
            .await
            .expect("the block executes");
            let merkleized = batches.merkleize().await.expect("state merkleizes");
            let root = merkleized.root();
            self.database.finalize(merkleized).await;

            let block = index_block(&self.head, root, fresh);
            self.indexer
                .ingest_finalized(block.clone(), finalization(&self.fixture, &block))
                .await
                .expect("finalized ingest");
            assert_eq!(
                self.index.apply_finalized(&block),
                Ok(ApplyOutcome::Applied)
            );
            self.head = block.clone();
            block
        }
    }

    /// Runs the three-revision handshake between two journals and
    /// returns the client's endpoint, once both hold revision 3.
    ///
    /// The provider's half is a [`SetupService`], asked through its own
    /// handler. The framing between the two is `hellas-rpc`'s and its
    /// own suite runs it over a real multiplexed transport; what is
    /// under test here is everything that happens to the artifact
    /// afterwards.
    async fn shake_hands(
        provider_root: &std::path::Path,
        client_root: &std::path::Path,
        payment_funding: Funding,
        scan: SetupScan,
    ) {
        let mut proposer = SetupEndpoint::new(
            open_store(provider_root, Role::Provider),
            provider(),
            PaymentAdmission::Admits(Box::new(provider_policy())),
        );
        proposer.arm_scan(scan).expect("the provider arms its scan");
        if let Err(error) = proposer.propose_bond(TEST_NETWORK, bond_funding(), bond_terms()) {
            panic!("the provider proposes its bond: {error}");
        }
        let service = SetupService::new(proposer);
        let mut caller = SetupEndpoint::new(
            open_store(client_root, Role::Client),
            client(),
            PaymentAdmission::Proposes(Box::new(provider_policy())),
        );

        let proposal = exchange(&service, Vec::new()).await;
        if let Err(error) = caller.import(&proposal) {
            panic!("the client imports the bond proposal: {error}");
        }
        caller.arm_scan(scan).expect("the client arms its scan");
        if let Err(error) = caller.propose_payment(payment_funding, payment_terms()) {
            panic!("the client proposes its payment: {error}");
        }
        let offered = caller
            .state()
            .bundle_bytes()
            .map(<[u8]>::to_vec)
            .expect("the client holds revision 2");
        let countersigned = exchange(&service, offered).await;
        if let Err(error) = caller.import(&countersigned) {
            panic!("the client imports the countersigned payment: {error}");
        }
        assert_eq!(caller.state().revision(), Some(3));
        // Both journals let go of their files, so everything below reads
        // what actually reached the disk.
        drop(service);
        drop(caller);
    }

    /// Offers one revision to the provider's service and returns the
    /// revision it answers with.
    async fn exchange(service: &SetupService, bundle: Vec<u8>) -> Vec<u8> {
        let answered = WorkSetupHandler::exchange_setup(
            service,
            ExchangeSetupRequest { bundle },
            TransportContext::default(),
        )
        .await
        .expect("the setup handler answers");
        let response: WithTrailer<_> = answered.into();
        match response.response.outcome {
            Some(Outcome::Advanced(advanced)) => advanced.bundle,
            other => panic!("expected an advanced revision, got {other:?}"),
        }
    }

    fn open_store(root: &std::path::Path, role: Role) -> SetupStore {
        match SetupStore::open(
            root,
            TEST_NETWORK,
            bond_edge(),
            role,
            &Secp256k1Verifier::new(),
        ) {
            Ok(store) => store,
            Err(error) => panic!("the setup journal opens: {error}"),
        }
    }

    fn scan_at(block: &HellasBlock) -> SetupScan {
        SetupScan {
            height: commonware_consensus::Heightable::height(block).get(),
            payload: block.digest().into(),
        }
    }

    /// A handshake, two Opens, two finalized blocks, and two journals
    /// that agree on where the channel began.
    ///
    /// The whole slice, end to end. What it establishes, in order:
    ///
    /// - the driver submits the bond only after journaling that it is
    ///   about to, proved by a sink that refuses — the marker is on the
    ///   disk and no bond exists;
    /// - a resubmission after that failure is the *retained* bytes, and
    ///   it opens exactly one bond;
    /// - the payment follows the bond and takes its lease;
    /// - completion is recorded against the real block that carried the
    ///   payment Open, parent and all, on both journals;
    /// - and the same finalized read the driver decided from makes the
    ///   channel `check_ready` admits work over.
    #[test]
    fn two_journals_open_one_channel_and_record_where_it_began() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let payment_edge = payment_edge_of(&payment_funding);
            let mut chain = Chain::start(runtime, "work_setup_e2e").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let verifier = Secp256k1Verifier::new();

            // The finalized block is the observation floor durably armed
            // before either executable Open can leave the handshake.
            let floor = chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                scan_at(&floor),
            )
            .await;
            let mut provider_store = open_store(provider_root.path(), Role::Provider);

            // The client, at the same state, has nothing to do. Both
            // submissions are the provider's, and the client's journal
            // says so rather than trying to make one.
            let mut client_store = open_store(client_root.path(), Role::Client);
            assert_eq!(
                step(&blocks, &blocks, &mut client_store).await,
                SetupProgress::AwaitingCounterparty,
            );
            assert!(chain.mempool.test_transactions().await.is_empty());
            drop(client_store);

            // The sink refuses. The marker must already be durable, and
            // it must be durable *on the disk* rather than in the state
            // this process is holding.
            let refused = advance_setup(
                &blocks,
                &blocks,
                &RefusingSink,
                &mut provider_store,
                &verifier,
            )
            .await;
            assert!(
                refused.is_err(),
                "a sink that refuses is an error, got {refused:?}",
            );
            drop(provider_store);
            let mut provider_store = open_store(provider_root.path(), Role::Provider);
            assert!(
                provider_store.state().bond_submitted(),
                "the bond submission was journaled before it was broadcast",
            );
            assert!(chain.mempool.test_transactions().await.is_empty());

            // The retry submits the retained bytes. Nothing was signed
            // again: the journal holds one bundle and the transaction
            // comes out of it.
            assert_eq!(
                step(&blocks, &blocks, &mut provider_store).await,
                SetupProgress::Submitted {
                    step: SetupStep::Bond,
                    outcome: SubmitTxOutcome::Enqueued,
                },
            );
            let bond_block = chain.seal().await;
            assert_eq!(bond_block.txs().len(), 1, "one bond open, not two");

            assert_eq!(
                step(&blocks, &blocks, &mut provider_store).await,
                SetupProgress::Submitted {
                    step: SetupStep::Payment,
                    outcome: SubmitTxOutcome::Enqueued,
                },
            );
            let origin_block = chain.seal().await;
            // Both edges are live and the bond is leased to this payment
            // channel, so the driver records where that happened.
            let SetupProgress::Complete(origin) = step(&blocks, &blocks, &mut provider_store).await
            else {
                panic!("the provider completes its setup");
            };
            assert_eq!(
                origin,
                SetupOrigin {
                    payment_edge,
                    height: commonware_consensus::Heightable::height(&origin_block).get(),
                    payload: origin_block.digest().into(),
                    parent: bond_block.digest().into(),
                },
                "the origin is the block that carried the payment open, and its parent",
            );

            // The client's own journal, driven by the same function,
            // reaches the same origin. It submits nothing: every step
            // above was the provider's.
            let mut client_store = open_store(client_root.path(), Role::Client);
            assert_eq!(
                step(&blocks, &blocks, &mut client_store).await,
                SetupProgress::Complete(origin),
            );

            // And both of them still say so after a crash.
            drop(provider_store);
            drop(client_store);
            assert_eq!(
                open_store(provider_root.path(), Role::Provider)
                    .state()
                    .origin(),
                Some(origin),
            );
            assert_eq!(
                open_store(client_root.path(), Role::Client)
                    .state()
                    .origin(),
                Some(origin),
            );

            // The same coherent read the decision was made from, handed
            // to the readiness gate. This is what an endpoint mounting
            // the paid service needs, and it is the first time a chain
            // read has been able to produce one.
            let snapshot = blocks
                .work_channel_snapshot(WorkChannelQuery {
                    bond_edge: bond_edge(),
                    payment_edge,
                    funding: BTreeSet::new(),
                })
                .await
                .expect("a channel snapshot")
                .expect("finalized state is available");
            let payment = snapshot.payment().expect("the payment edge is live");
            assert_eq!(
                payment.values(),
                expected_values(),
                "the funded edge is the one the provider's policy expected",
            );
            let recovered = open_store(provider_root.path(), Role::Provider);
            let armed = recovered
                .state()
                .close_descriptor()
                .expect("the crash-recovered journal mounts close-only state");
            let funded = armed
                .funded_settlement(payment)
                .expect("recovery settles from the coherent funded edge");
            assert_eq!(funded.capacity(), FUNDING - OMISSION_BOND);
            drop(recovered);
            let descriptor = match WorkChannelDescriptor::open(WorkChannelConfig {
                network: TEST_NETWORK,
                payment_edge,
                payment_terms: payment_terms(),
                policy_salt: SALT,
                channel_policy: channel_policy(),
                execution_policy: execution_policy().into(),
                expected_payment_values: expected_values(),
            }) {
                Ok(descriptor) => descriptor,
                Err(error) => panic!("the configured channel opens: {error}"),
            };
            let ready = match descriptor.check_ready(&snapshot.observed_channel()) {
                Ok(ready) => ready,
                Err(error) => panic!("the opened channel is ready: {error}"),
            };
            assert_eq!(ready.finalized_height(), snapshot.block().height);
            assert_eq!(ready.settlement().capacity(), FUNDING - OMISSION_BOND);
        });
    }

    /// Revision 3 is a portable authorization, not merely a getter: after
    /// the exporting provider crashes, the counterparty can land both Opens
    /// and permissionlessly retire the leased bond, and the provider still
    /// mounts the surviving payment edge from journal history alone.
    #[test]
    fn round4_exported_authorization_recovers() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let mut chain = Chain::start(runtime, "work_setup_journal_recovery").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let floor = chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                scan_at(&floor),
            )
            .await;

            // Crash after the real handshake export. The only values kept
            // outside the dead process are the portable Opens the peer got.
            let (bond_open, payment_open) = {
                let recovered = open_store(provider_root.path(), Role::Provider);
                (
                    recovered.state().bond_open().expect("portable bond Open"),
                    recovered
                        .state()
                        .payment_open()
                        .expect("portable payment Open"),
                )
            };
            chain
                .mempool
                .test_submit(Transaction::Kernel(bond_open))
                .await;
            chain
                .mempool
                .test_submit(Transaction::Kernel(payment_open))
                .await;
            chain.seal().await;

            let payment_edge = payment_edge_of(&Funding::new(one_coin(client_coin()), no_coins()));
            let descriptor = provider_policy()
                .admit(payment_edge, payment_terms())
                .expect("the exported policy admitted this channel");
            let start = close_start(
                descriptor.channel(),
                Party::Maker,
                chain.height,
                None,
                &client(),
            )
            .expect("the counterparty builds a real close Start");
            chain
                .mempool
                .test_submit(Transaction::Kernel(KernelTx::move_action(
                    Move::StartPaymentClose(start),
                )))
                .await;
            chain.seal().await;

            let snapshot = blocks
                .work_channel_snapshot(WorkChannelQuery {
                    bond_edge: bond_edge(),
                    payment_edge,
                    funding: BTreeSet::new(),
                })
                .await
                .expect("the contest snapshot reads")
                .expect("finalized contest state exists");
            let PendingSlot::Present(pending) = snapshot.pending() else {
                panic!("the real Start created a pending close");
            };
            while chain.height < pending.response_deadline() {
                chain.seal().await;
            }
            let close = adjudicated_close(
                descriptor.channel(),
                descriptor
                    .close_descriptor()
                    .expected_settlement()
                    .expect("settlement"),
                &pending,
            )
            .expect("the finalized contest determines its close");
            chain.mempool.test_submit(Transaction::Kernel(close)).await;
            let close_block = chain.seal().await;
            assert!(
                close_block.txs().iter().any(|tx| {
                    matches!(tx, Transaction::Kernel(KernelTx::Close { input, .. }) if *input == payment_edge)
                }),
                "the real finalized history contains the adjudicated payment Close",
            );

            let mut restarted = open_store(provider_root.path(), Role::Provider);
            let mounted = step(&blocks, &blocks, &mut restarted).await;
            assert!(
                matches!(mounted, SetupProgress::CloseOnly { settled: true, .. }),
                "journal-only recovery mounts CloseOnly: {mounted:?}",
            );
        });
    }

    #[test]
    fn round6_submitted_open_delays_end() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let mut chain = Chain::start(runtime, "work_setup_open_obligation").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let floor = chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                scan_at(&floor),
            )
            .await;

            let verifier = Secp256k1Verifier::new();
            let bond_open = {
                let mut provider_store = open_store(provider_root.path(), Role::Provider);
                let retained = provider_store.state().bond_open().expect("retained Open");
                let refused = advance_setup(
                    &blocks,
                    &blocks,
                    &RefusingSink,
                    &mut provider_store,
                    &verifier,
                )
                .await;
                assert!(refused.is_err(), "the marker survives the failed broadcast");
                retained
            };

            let mut restarted = open_store(provider_root.path(), Role::Provider);
            let blocked = restarted.commit(
                SetupRecord::Ended {
                    outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
                },
                &verifier,
            );
            assert!(matches!(
                blocked,
                Err(WorkStoreError::Setup(
                    SetupStateError::SubmittedOpenUnresolved
                ))
            ));
            drop(restarted);

            chain
                .mempool
                .test_submit(Transaction::Kernel(bond_open))
                .await;
            chain.seal().await;

            let mut restarted = open_store(provider_root.path(), Role::Provider);
            advance_setup(&blocks, &blocks, &blocks, &mut restarted, &verifier)
                .await
                .expect("the finalized Open is applied before the next setup decision");
            assert!(
                !restarted.state().bond_submitted(),
                "the finalized Open discharges the journal obligation",
            );
            assert!(
                restarted.state().payment_submitted(),
                "after catching up, the driver immediately submits the payment Open",
            );
            assert!(matches!(
                restarted.commit(
                    SetupRecord::Ended {
                        outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
                    },
                    &verifier,
                ),
                Err(WorkStoreError::Setup(
                    SetupStateError::SubmittedOpenUnresolved
                ))
            ));
        });
    }

    /// The provider does not stake on a channel the client cannot fund.
    ///
    /// One thing moves from the test above: the coin the client names as
    /// its payment funding is one nobody ever minted. Every signature is
    /// the same, both Opens are executable, and the bond is still
    /// perfectly submittable — and the preflight refuses it, because the
    /// coins are read at the same block the edges are.
    #[test]
    fn a_stake_is_not_locked_for_a_payment_that_cannot_be_funded() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let payment_funding = Funding::new(
                one_coin(CoinId::from_bytes(genesis_object_id(9).into())),
                no_coins(),
            );
            let mut chain = Chain::start(runtime, "work_setup_unfunded").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let floor = chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                scan_at(&floor),
            )
            .await;

            let mut provider_store = open_store(provider_root.path(), Role::Provider);
            assert_eq!(
                step(&blocks, &blocks, &mut provider_store).await,
                SetupProgress::Aborted(SetupAbort::PaymentFundingSpent),
            );
            assert!(
                !provider_store.state().bond_submitted(),
                "no stake was locked",
            );
            assert!(
                chain.mempool.test_transactions().await.is_empty(),
                "and nothing was broadcast",
            );
            drop(provider_store);
            assert_eq!(
                open_store(provider_root.path(), Role::Provider)
                    .state()
                    .end(),
                Some(SetupEnd::Aborted(SetupAbort::PaymentFundingSpent)),
            );
        });
    }

    /// A bond already on chain over a channel that cannot be funded is
    /// reported, not resolved.
    ///
    /// The same unfundable channel as above, except that the bond Open
    /// reaches consensus anyway — the retained bytes are executable and
    /// anyone holding them can send them. `decide` answers `TimeoutBond`
    /// and the driver hands that answer back untouched: the setup
    /// journal has no record for a Timeout submission, and this driver
    /// broadcasts nothing it cannot write down first. Nothing else in
    /// the workspace sends one either, so the assertion below that the
    /// mempool is empty is also the whole story of the provider's stake.
    #[test]
    fn an_unusable_live_bond_is_reported_and_not_timed_out() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let payment_funding = Funding::new(
                one_coin(CoinId::from_bytes(genesis_object_id(9).into())),
                no_coins(),
            );
            let mut chain = Chain::start(runtime, "work_setup_stranded").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let floor = chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                scan_at(&floor),
            )
            .await;

            // The bond, posted by something that is not this driver.
            let mut provider_store = open_store(provider_root.path(), Role::Provider);
            let bond_open = provider_store
                .state()
                .bond_open()
                .expect("the completed handshake is an executable bond open");
            chain
                .mempool
                .test_submit(Transaction::Kernel(bond_open))
                .await;
            let bond_block = chain.seal().await;
            assert_eq!(bond_block.txs().len(), 1);

            assert_eq!(
                step(&blocks, &blocks, &mut provider_store).await,
                SetupProgress::BondTimeoutSubmitted {
                    outcome: SubmitTxOutcome::Enqueued,
                },
            );
            assert_eq!(
                chain.mempool.test_transactions().await.len(),
                2,
                "the driver records and submits the deterministic Timeout",
            );
            assert_eq!(
                provider_store.state().end(),
                None,
                "and it recorded no ending it could not act on",
            );
        });
    }

    /// One step of the driver against the real sink, panicking on the
    /// errors these tests do not expect.
    ///
    /// The channel a mounting step hands back is dropped here, which
    /// releases its journal: these tests assert about what the setup
    /// recorded, and `a_completed_setup_hands_back_the_channel_it_mounted`
    /// asserts about what was handed back.
    async fn step<C>(
        view: &WorkBlocks<C>,
        blocks: &WorkBlocks<C>,
        store: &mut SetupStore,
    ) -> SetupProgress
    where
        C: LightClient + FinalizedWorkView,
    {
        loop {
            match advance_setup(view, blocks, view, store, &Secp256k1Verifier::new()).await {
                Ok(SetupAdvance {
                    progress: SetupProgress::HistoryAdvanced { .. },
                    ..
                }) => continue,
                Ok(advance) => return advance.progress,
                Err(error) => panic!("the driver takes a step: {error}"),
            }
        }
    }
}
