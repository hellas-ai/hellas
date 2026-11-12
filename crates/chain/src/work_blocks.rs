//! One light client, as a paid endpoint's chain.
//!
//! A paid endpoint needs two things from a chain and no more: one
//! coherent, proof-checked read of its channels' objects at a certified
//! block ([`FinalizedWorkView`]), and somewhere to hand a transaction
//! ([`TxSink`]). [`WorkBlocks`] is the one type that pairs them over a
//! light client, so the read and the submission cannot be pointed at two
//! different chains, and it refuses any read older than what the
//! journal it serves already holds.

use hellas_channel::work::WorkService;
use hellas_channel::work_close::{
    BlockSourceError, CatchUpError, CloseError, CloseProgress, TxSink, due_bond_timeout,
};
use hellas_kernel::Tx;

use crate::SubmitTxOutcome;
use crate::domain::Transaction;
use crate::light_client::{LightClient, QueryError};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery, WorkChannelSnapshot};

/// One light client, as a paid endpoint's chain.
///
/// The client must authenticate each read on the same pinned consensus
/// chain: a remote client with an independently authenticated consensus
/// verifier, or a validating node's own. This adapter does not turn an
/// unverified remote connection into trusted evidence.
#[derive(Clone, Debug)]
pub struct WorkBlocks<C> {
    client: C,
    min_height: u64,
}

/// What one production clock step did for a mounted paid channel.
#[derive(Debug)]
pub struct PaidWorkClockAdvance {
    /// The shared start, response, and final adjudication drive.
    pub close: CloseProgress,
    /// Submission outcome for a due completed-bond timeout.
    pub bond_timeout: Option<SubmitTxOutcome>,
}

/// Why one production clock step could not finish.
#[derive(Debug, thiserror::Error)]
pub enum PaidWorkClockError {
    /// The journaled close drive failed.
    #[error("the journaled close drive failed: {0}")]
    CloseDrive(#[source] CatchUpError),
    /// The endpoint could not derive the close consensus permits.
    #[error("the mounted endpoint could not derive its close: {0}")]
    Decision(#[source] CloseError),
    /// The connected transaction sink failed.
    #[error("the connected transaction sink failed: {0}")]
    Submission(#[source] BlockSourceError),
}

impl PaidWorkClockError {
    /// Returns whether the connected chain should be replaced before retry.
    #[must_use]
    pub const fn source_failed(&self) -> bool {
        matches!(
            self,
            Self::CloseDrive(CatchUpError::Source(_)) | Self::Submission(_)
        )
    }
}

impl<C: LightClient> WorkBlocks<C> {
    /// Reads and submits for a paid endpoint through `client`.
    pub const fn new(client: C) -> Self {
        Self {
            client,
            min_height: 0,
        }
    }

    /// A persisted journal must never interpret absence at an earlier root.
    #[must_use]
    pub fn with_min_height(mut self, height: u64) -> Self {
        self.min_height = self.min_height.max(height);
        self
    }

    /// Returns the light client this adapter reads and submits through.
    pub const fn client(&self) -> &C {
        &self.client
    }
}

impl From<QueryError> for BlockSourceError {
    fn from(error: QueryError) -> Self {
        Self::new(error.to_string())
    }
}

/// Advances one mounted paid channel on the production clock, from one
/// certified read of it.
///
/// The journaled close drive runs first: it applies the read and serves
/// the contest, adjudication or retained start it shows. The bond then
/// comes back by its Timeout once the payment edge is closed or the bond
/// horizon has passed.
///
/// # Errors
///
/// Returns the failed journal drive, decision, or submission, including
/// [`CloseError::BondTimeoutUnavailable`] for a bond with no timeout payout.
pub async fn advance_paid_work_clock<T>(
    service: &WorkService,
    snapshot: &WorkChannelSnapshot,
    sink: &T,
) -> Result<PaidWorkClockAdvance, PaidWorkClockError>
where
    T: TxSink + ?Sized + Sync,
{
    let close = service
        .advance_close(&snapshot.observed_channel(), sink)
        .await
        .map_err(PaidWorkClockError::CloseDrive)?;
    let tx = service
        .with_state(|state| due_bond_timeout(state, &snapshot.observed_channel()))
        .await
        .map_err(|error| PaidWorkClockError::Decision(CloseError::Endpoint(error)))?
        .map_err(PaidWorkClockError::Decision)?;
    let bond_timeout = match tx {
        Some(tx) => Some(
            sink.submit(tx)
                .await
                .map_err(PaidWorkClockError::Submission)?,
        ),
        None => None,
    };
    Ok(PaidWorkClockAdvance {
        close,
        bond_timeout,
    })
}

impl<C: LightClient + FinalizedWorkView> FinalizedWorkView for WorkBlocks<C> {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<crate::light_client::Verified<WorkChannelSnapshot>>, QueryError> {
        let snapshot = self.client.work_channel_snapshot(query).await?;
        if snapshot.as_ref().map_or(0, |value| value.block().height) < self.min_height {
            return Err(QueryError::StateUnavailable(format!(
                "chain is behind persisted journal height {}",
                self.min_height
            )));
        }
        Ok(snapshot)
    }
}

impl<C: LightClient> TxSink for WorkBlocks<C> {
    async fn submit(&self, tx: Tx) -> Result<SubmitTxOutcome, BlockSourceError> {
        self.client
            .submit_tx(Transaction::Kernel(tx))
            .await
            .map_err(|error| BlockSourceError::new(error.to_string()))
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

    use commonware_consensus::{
        CertifiableBlock as _,
        simplex::types::Context,
        types::{Epoch, Height, Round, View},
    };
    use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
    use commonware_runtime::{Handle, Supervisor as _};
    use hellas_kernel::{
        BlockHash, BlockHeight, CoinId, Context as KernelContext, EdgeId, EdgeValues, Fees,
        Funding, List, MAX_PARTY_INPUTS, Move, Parties, Party, Payout, PendingSlot,
        Secp256k1Signer, Secp256k1Verifier, Terms as KernelTerms, Tx as KernelTx, WorkPaymentTerms,
        WorkStakeBondTerms,
    };

    use hellas_channel::model::setup::{
        ProviderChannelPolicy, WorkChannelConfig, WorkChannelDescriptor,
    };
    use hellas_channel::model::work::{PaidChannelPolicyV1, private_policy_commitment};
    use hellas_channel::test_support::channel::work_policy;
    use hellas_channel::work_close::{BlockSourceError, adjudicated_close, close_start};
    use hellas_channel::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
    use hellas_channel::work_open::{
        FinalizedSetup, SetupProgress, SetupStep, advance_setup, setup_query,
    };
    use hellas_channel::work_store::{
        Role, SetupAbort, SetupEnd, SetupFault, SetupOrigin, SetupRecord, SetupStateError,
        SetupStore, WorkStoreError,
    };

    use crate::HellasBlock;
    use crate::app::Mempool;
    use crate::config::Config;
    use crate::domain::{KERNEL_FEES, SettlementKey, TEST_NETWORK, genesis_object_id};
    use crate::execution::store::{UtxoDatabase, utxo_db_config};
    use crate::execution::test_support::{
        consensus_fixture, finality_envelope, index_genesis, run_qmdb,
    };
    use crate::execution::{ChainVerifier, execute_all};
    use crate::indexer::fixtures::spawn_archive;
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

    fn client_coin() -> CoinId {
        CoinId::from_bytes(genesis_object_id(0).0)
    }

    fn provider_coin() -> CoinId {
        CoinId::from_bytes(genesis_object_id(1).0)
    }

    fn bond_terms() -> WorkStakeBondTerms {
        hellas_channel::test_support::channel::bond_terms_for(
            Parties::new(
                hellas_kernel::PartyKeys::sole(provider().party_key()),
                hellas_kernel::PartyKeys::sole(client().party_key()),
            ),
            BlockHeight::new(HORIZON),
            Payout::new(provider().party_key(), STAKE),
            4,
        )
    }

    fn bond_funding() -> Funding {
        Funding::new(one_coin(provider_coin()), no_coins())
    }

    fn bond_edge() -> EdgeId {
        KernelTx::edge_id_of(&bond_funding(), &KernelTerms::work_stake_bond(bond_terms()))
    }

    fn channel_policy() -> PaidChannelPolicyV1 {
        hellas_channel::test_support::channel::credit_policy(40, 40)
    }

    /// The edge the provider requires the client to fund: the whole
    /// allocation, no reserve, and the chain's zero fees.
    fn expected_values() -> EdgeValues {
        EdgeValues::new(FUNDING, 0, Fees::new(0, 0, 0, 0))
    }

    fn provider_policy() -> ProviderChannelPolicy {
        ProviderChannelPolicy {
            payment_policy: payment_policy(),
            network: TEST_NETWORK,
            policy_salt: SALT,
            channel_policy: channel_policy(),
            invocation_policy: work_policy(),
            expected_payment_values: expected_values(),
        }
    }

    fn payment_terms() -> WorkPaymentTerms {
        hellas_channel::test_support::channel::payment_terms_for(
            bond_edge(),
            bond_terms(),
            private_policy_commitment(TEST_NETWORK, &SALT, &channel_policy()),
            hellas_kernel::MAX_START_VALIDITY_BLOCKS,
            OMISSION_BOND,
        )
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
        indexer: crate::indexer::fixtures::ArchiveSource,
        mempool: Mempool,
        fixture: crate::execution::test_support::ConsensusFixture,
        allocations: Vec<(SettlementKey, u64)>,
        head: HellasBlock,
        height: u64,
        /// How many mempool entries earlier blocks already carried.
        /// Nothing else drains this mempool, so everything past it is
        /// what the driver submitted since.
        sealed: usize,
        indexer_task: Handle<()>,
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
            let (indexer, task) = spawn_archive(
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
                indexer_task: task,
            }
        }

        async fn shutdown(self) {
            self.indexer_task.abort();
            let _ = self.indexer_task.await;
        }

        fn light_client(&self) -> LocalLightClient {
            LocalLightClient::new(
                self.database.clone(),
                self.index.clone(),
                self.mempool.clone(),
                self.indexer.archive.clone(),
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
            let mut fresh = Vec::new();
            fresh.extend_from_slice(&pending[self.sealed..]);
            self.sealed = pending.len();
            self.height += 1;

            let batches = self.database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    TEST_NETWORK,
                    BlockHeight::new(self.height),
                    self.height * 1_000,
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
            let block = HellasBlock::new(
                Context {
                    round: Round::new(Epoch::zero(), View::new(self.height)),
                    leader: self.fixture.leaders[0].clone(),
                    parent: (self.head.context().round.view(), self.head.digest()),
                },
                self.head.digest(),
                Height::new(self.height),
                self.height * 1_000,
                root,
                crate::execution::store::sync_target(&merkleized),
                fresh,
            );
            self.indexer
                .publish_proof(block.clone(), &finality_envelope(&self.fixture, &block))
                .await
                .expect("finalized ingest");
            self.database.finalize(merkleized).await;
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
        content: (
            &hellas_store::content::DiskStore,
            &hellas_store::content::DiskStore,
        ),
    ) {
        let mut proposer = SetupEndpoint::new(
            open_store(provider_root, Role::Provider, content.0).await,
            provider(),
            PaymentAdmission::Admits(Box::new(provider_policy())),
        );
        if let Err(error) = proposer
            .propose_bond(TEST_NETWORK, bond_funding(), bond_terms())
            .await
        {
            panic!("the provider proposes its bond: {error}");
        }
        let service = SetupService::new(proposer);
        let mut caller = SetupEndpoint::new(
            open_store(client_root, Role::Client, content.1).await,
            client(),
            PaymentAdmission::Proposes(Box::new(provider_policy())),
        );

        hellas_channel::test_support::channel::finish_setup(
            &service,
            &mut caller,
            bond_edge(),
            payment_funding,
            payment_terms(),
        )
        .await;
        assert_eq!(caller.state().revision(), Some(3));
        // Both journals let go of their files, so everything below reads
        // what actually reached the disk.
        drop(service);
        drop(caller);
    }

    async fn content(root: &std::path::Path) -> hellas_store::content::DiskStore {
        let content = hellas_channel::test_support::channel::content_store(root).await;
        content.finish_recovery().await.unwrap();
        content
    }

    async fn open_store(
        root: &std::path::Path,
        role: Role,
        content: &hellas_store::content::DiskStore,
    ) -> SetupStore {
        let mut store = hellas_channel::test_support::channel::open_setup_store(
            root,
            TEST_NETWORK,
            bond_edge(),
            role,
        )
        .await;
        store.set_content_store(content.clone());
        store
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
            let provider_content = content(provider_root.path()).await;
            let client_content = content(client_root.path()).await;
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let payment_edge = payment_edge_of(&payment_funding);
            let mut chain = Chain::start(runtime, "work_setup_e2e").await;
            let blocks = WorkBlocks::new(chain.light_client());
            let verifier = Secp256k1Verifier::new();

            chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                (&provider_content, &client_content),
            )
            .await;
            let mut provider_store =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;

            // The client, at the same state, has nothing to do. Both
            // submissions are the provider's, and the client's journal
            // says so rather than trying to make one.
            let mut client_store =
                open_store(client_root.path(), Role::Client, &client_content).await;
            assert_eq!(
                step(&blocks, &mut client_store).await,
                SetupProgress::AwaitingCounterparty,
            );
            assert!(chain.mempool.test_transactions().await.is_empty());
            drop(client_store);

            // The sink refuses. The marker must already be durable, and
            // it must be durable *on the disk* rather than in the state
            // this process is holding.
            let read = read(&blocks, &provider_store).await;
            let refused = advance_setup(&read, &RefusingSink, &mut provider_store, &verifier).await;
            assert!(
                refused.is_err(),
                "a sink that refuses is an error, got {refused:?}",
            );
            drop(provider_store);
            let mut provider_store =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
            assert!(
                provider_store.state().bond_submitted(),
                "the bond submission was journaled before it was broadcast",
            );
            assert!(chain.mempool.test_transactions().await.is_empty());

            // The retry submits the retained bytes. Nothing was signed
            // again: the journal holds one bundle and the transaction
            // comes out of it.
            assert_eq!(
                step(&blocks, &mut provider_store).await,
                SetupProgress::Submitted {
                    step: SetupStep::Bond,
                    outcome: SubmitTxOutcome::Enqueued,
                },
            );
            let bond_block = chain.seal().await;
            assert_eq!(bond_block.txs().len(), 1, "one bond open, not two");

            assert_eq!(
                step(&blocks, &mut provider_store).await,
                SetupProgress::Submitted {
                    step: SetupStep::Payment,
                    outcome: SubmitTxOutcome::Enqueued,
                },
            );
            let origin_block = chain.seal().await;
            // Both edges are live and the bond is leased to this payment
            // channel, so the driver records the read that first showed it.
            let SetupProgress::Complete(origin) = step(&blocks, &mut provider_store).await else {
                panic!("the provider completes its setup");
            };
            assert_eq!(
                origin,
                SetupOrigin {
                    payment_edge,
                    height: commonware_consensus::Heightable::height(&origin_block).get(),
                    payload: origin_block.digest().into(),
                },
                "the origin is the first certified read that shows the payment edge",
            );
            let _ = bond_block;

            // The client's own journal, driven by the same function and
            // reading at the same block, records the same first sighting.
            // It submits nothing: every step above was the provider's.
            let mut client_store =
                open_store(client_root.path(), Role::Client, &client_content).await;
            assert_eq!(
                step(&blocks, &mut client_store).await,
                SetupProgress::Complete(origin),
            );

            // And both of them still say so after a crash.
            drop(provider_store);
            drop(client_store);
            assert_eq!(
                open_store(provider_root.path(), Role::Provider, &provider_content)
                    .await
                    .state()
                    .origin(),
                Some(origin),
            );
            assert_eq!(
                open_store(client_root.path(), Role::Client, &client_content)
                    .await
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
                    payment_edge: Some(payment_edge),
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
            let recovered =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
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
                payment_policy: payment_policy(),
                network: TEST_NETWORK,
                payment_edge,
                payment_terms: payment_terms(),
                policy_salt: SALT,
                channel_policy: channel_policy(),
                invocation_policy: work_policy(),
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
            chain.shutdown().await;
        });
    }

    /// Revision 3 is a portable authorization, not merely a getter: after
    /// the exporting provider crashes, the counterparty can land both Opens
    /// and run a whole contest to its close. The restarted provider never
    /// saw the payment edge, and its read shows a bond still leased to a
    /// payment edge that is gone. Nothing it reads now says what that
    /// channel paid, so the setup stops for manual reconciliation rather
    /// than guess; the stake stays reclaimable by the bond's Timeout.
    #[test]
    fn round4_exported_authorization_recovers() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let provider_content = content(provider_root.path()).await;
            let client_content = content(client_root.path()).await;
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let mut chain = Chain::start(runtime, "work_setup_journal_recovery").await;
            let blocks = WorkBlocks::new(chain.light_client());
            chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                (&provider_content, &client_content),
            )
            .await;

            // Crash after the real handshake export. The only values kept
            // outside the dead process are the portable Opens the peer got.
            let (bond_open, payment_open) = {
                let recovered =
                    open_store(provider_root.path(), Role::Provider, &provider_content).await;
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
                    payment_edge: Some(payment_edge),
                    funding: BTreeSet::new(),
                })
                .await
                .expect("the contest snapshot reads")
                .expect("finalized contest state exists");
            let PendingSlot::Present(pending) = snapshot.pending() else {
                panic!("the real Start created a pending close");
            };
            while chain.height * 1_000 < pending.response_deadline_ms() {
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

            let mut restarted =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
            assert_eq!(
                step(&blocks, &mut restarted).await,
                SetupProgress::Faulted(SetupFault::UnexplainedState),
                "a channel that opened and closed unwatched is reconciled by hand",
            );
            chain.shutdown().await;
        });
    }

    #[test]
    fn round6_submitted_open_delays_end() {
        run_qmdb(|runtime| async move {
            let provider_root = tempfile::tempdir().expect("a temp dir");
            let client_root = tempfile::tempdir().expect("a temp dir");
            let provider_content = content(provider_root.path()).await;
            let client_content = content(client_root.path()).await;
            let payment_funding = Funding::new(one_coin(client_coin()), no_coins());
            let mut chain = Chain::start(runtime, "work_setup_open_obligation").await;
            let blocks = WorkBlocks::new(chain.light_client());
            chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                (&provider_content, &client_content),
            )
            .await;

            let verifier = Secp256k1Verifier::new();
            let bond_open = {
                let mut provider_store =
                    open_store(provider_root.path(), Role::Provider, &provider_content).await;
                let retained = provider_store.state().bond_open().expect("retained Open");
                let read = read(&blocks, &provider_store).await;
                let refused =
                    advance_setup(&read, &RefusingSink, &mut provider_store, &verifier).await;
                assert!(refused.is_err(), "the marker survives the failed broadcast");
                retained
            };

            let mut restarted =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
            let blocked = restarted.commit(
                SetupRecord::Ended {
                    outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
                },
                &verifier,
            );
            assert!(matches!(
                blocked.await,
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

            let mut restarted =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
            let current = read(&blocks, &restarted).await;
            advance_setup(&current, &blocks, &mut restarted, &verifier)
                .await
                .expect("the read showing the Open is recorded before the next setup decision");
            assert!(
                !restarted.state().bond_submitted(),
                "the finalized Open discharges the journal obligation",
            );
            assert!(
                restarted.state().payment_submitted(),
                "on the same read, the driver submits the payment Open",
            );
            assert!(matches!(
                restarted
                    .commit(
                        SetupRecord::Ended {
                            outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
                        },
                        &verifier,
                    )
                    .await,
                Err(WorkStoreError::Setup(
                    SetupStateError::SubmittedOpenUnresolved
                ))
            ));
            chain.shutdown().await;
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
            let provider_content = content(provider_root.path()).await;
            let client_content = content(client_root.path()).await;
            let payment_funding = Funding::new(
                one_coin(CoinId::from_bytes(genesis_object_id(9).into())),
                no_coins(),
            );
            let mut chain = Chain::start(runtime, "work_setup_unfunded").await;
            let blocks = WorkBlocks::new(chain.light_client());
            chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                (&provider_content, &client_content),
            )
            .await;

            let mut provider_store =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
            assert_eq!(
                step(&blocks, &mut provider_store).await,
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
                open_store(provider_root.path(), Role::Provider, &provider_content)
                    .await
                    .state()
                    .end(),
                Some(SetupEnd::Aborted(SetupAbort::PaymentFundingSpent)),
            );
            chain.shutdown().await;
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
            let provider_content = content(provider_root.path()).await;
            let client_content = content(client_root.path()).await;
            let payment_funding = Funding::new(
                one_coin(CoinId::from_bytes(genesis_object_id(9).into())),
                no_coins(),
            );
            let mut chain = Chain::start(runtime, "work_setup_stranded").await;
            let blocks = WorkBlocks::new(chain.light_client());
            chain.seal().await;
            shake_hands(
                provider_root.path(),
                client_root.path(),
                payment_funding,
                (&provider_content, &client_content),
            )
            .await;

            // The bond, posted by something that is not this driver.
            let mut provider_store =
                open_store(provider_root.path(), Role::Provider, &provider_content).await;
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
                step(&blocks, &mut provider_store).await,
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
            chain.shutdown().await;
        });
    }

    /// One step of the driver against the real sink, panicking on the
    /// errors these tests do not expect.
    ///
    /// The channel a mounting step hands back is dropped here, which
    /// releases its journal: these tests assert about what the setup
    /// recorded, and `a_completed_setup_hands_back_the_channel_it_mounted`
    /// asserts about what was handed back.
    async fn step<C>(blocks: &WorkBlocks<C>, store: &mut SetupStore) -> SetupProgress
    where
        C: LightClient + FinalizedWorkView,
    {
        let current = read(blocks, store).await;
        match advance_setup(&current, blocks, store, &Secp256k1Verifier::new()).await {
            Ok(advance) => advance.progress,
            Err(error) => panic!("the driver takes a step: {error}"),
        }
    }

    /// One certified read of what this setup journal asks now.
    async fn read<C>(blocks: &WorkBlocks<C>, store: &SetupStore) -> FinalizedSetup
    where
        C: LightClient + FinalizedWorkView,
    {
        let query = setup_query(store.state()).expect("the handshake names a payment edge");
        blocks
            .work_channel_snapshot(WorkChannelQuery {
                bond_edge: query.bond_edge,
                payment_edge: query.payment_edge,
                funding: query.funding.clone(),
            })
            .await
            .expect("the setup state reads")
            .expect("certified state exists")
            .finalized_setup(&query)
            .expect("the read answers the setup's query")
    }

    fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
        hellas_channel::model::work::JobPaymentPolicyV2 {
            fixed_price: 10,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        }
    }
}
