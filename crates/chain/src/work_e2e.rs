//! The black-box question: against a real chain, does the provider's
//! finalized balance go up by the job price, and for the right reason?
//!
//! # What is real here
//!
//! - **The committee.** Six validator identities, a real threshold deal
//!   over them, and a real BLS finalization certificate over every
//!   block, verified by [`ConsensusVerifier`] inside each node's own
//!   follower indexer. A forged certificate does not get in.
//! - **Six nodes.** Each has its own QMDB database, its own kernel
//!   execution, its own owner index, its own indexer and its own
//!   mempool. Every block is executed independently by all six and
//!   [`Devnet::seal`] refuses to finalize one unless all six agree on
//!   the state root. The provider reads and submits at node 0; the
//!   client reads and submits at node 1, so neither party's evidence
//!   comes from the other's view.
//! - **Genesis.** A real [`Genesis`] document, validated, its network id
//!   read back through [`crate::domain::network_id`], and its two
//!   allocations parsed by the shipped
//!   [`crate::config::parse_genesis_settlement_key`] — which is what
//!   makes funding a secp256k1 settlement key a real event here rather
//!   than an assumption.
//! - **The channel.** Both Opens are the handshake's own signed bytes,
//!   submitted by the setup driver through a light client and finalized
//!   in real blocks. Nothing about the edges is fabricated.
//! - **The job.** A real [`ProviderEndpoint`] behind a real
//!   [`WorkService`], reached by a real [`ClientEndpoint`] over a real
//!   multiplexed transport, with both journals on disk.
//! - **The close.** The runner's production clock entry
//!   ([`advance_paid_work_clock`]) drives the start and response, submits
//!   the adjudicated close from one coherent finalized read, and returns
//!   the completed bond at its horizon from that same read.
//!
//! # What is simulated, exactly
//!
//! 1. **The proposer.** No simplex engine runs. [`Devnet::seal`] plays
//!    the leader: it drains every node's mempool, executes the result on
//!    all six, and certifies the block with the six real schemes. So
//!    ordering, view changes, leader rotation and gossip are *not*
//!    exercised — and neither is the fan-in a real proposer gets, since
//!    `seal` reads all six mempools directly. There is no library edge
//!    that spawns a validator into a caller's runtime:
//!    `crate::validator::run` (crates/chain/src/validator.rs:884) is
//!    private, reads a TOML path, binds sockets and owns its own tokio
//!    runtime, so six of them cannot share one test process.
//! 2. **The model.** [`FixtureExecutor`] is not `hellas-executor`; this
//!    repository has no model weights to run. Both sides invoke the same
//!    `FixtureExecutor`, which is what "the same executor
//!    implementation" means here, and the reproduction seam is the real
//!    [`Reproducer`] trait with the real derivation around it.
//! 3. **The provider's prompt lookup.** A shipped provider resolves the
//!    accepted bundle from its artifact store; here the provider's
//!    backend is handed the prompt at construction. The *client's* side
//!    is not stubbed: it derives its question from the journal-held
//!    bundle through [`hellas_client::work::reproduce::plan`].
//! 4. **The timer.** The test advances the production paid-work clock
//!    entry at explicit proposer turns rather than waiting on `serve`'s
//!    wall-clock interval. Every provider-clock transaction still comes
//!    from that entry; only when a tick occurs is controlled here.
//! 5. **Transports.** No ALPN advertisement, no peer discovery and no
//!    gateway. Both endpoints are constructed directly and the paid
//!    exchange runs over a mux pair on in-memory pipes — real framing
//!    and real method routing, no network.
//!
//! Nothing else is stood in for. In particular no balance, no payout, no
//! certificate and no edge value below is written by this file. The final
//! coin values that prove settlement are read from a node's finalized QMDB;
//! whole-owner assertions also refuse unless the owner-index projection
//! names exactly the same fixture coins and values as those QMDB reads.
//!
//! # What the §1 fan-out gap costs this test
//!
//! `serve`'s clock reads and submits through the first validator that
//! answers (`crates/cli/src/commands/serve/node.rs:773-778`), and §1's
//! concurrent fan-out to all six does not exist. This harness has the
//! same shape by construction: each party is pinned to one node. So what
//! is proved is that the money is right *when one honest validator
//! answers a party*. It is not proved that a party censored at its one
//! validator still gets paid, because there is no second submission path
//! for it to fall back to — in this test or in the tree. The one thing
//! the six nodes do buy is that no party's *evidence* is the other's:
//! the provider's balance is read at node 0 and confirmed at node 1, and
//! every block is executed six times before it is finalized.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::{Handle, Supervisor as _};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::reproduce::{
    ReproduceFault, Reproduced, Reproducer, plan as reproduction_plan,
};
use hellas_client::work::{CheckedResult, CollectOutcome, collect_checked_result};
use hellas_kernel::{
    BlockHash, BlockHeight, CoinId, Context as KernelContext, EdgeId, EdgeValues, Fees, Funding,
    List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, MIN_OMIT_RESPONSE_BLOCKS, Move, Parties, Party,
    Payout, PendingSlot, Secp256k1Signer, Secp256k1Verifier, Terms as KernelTerms, Tx as KernelTx,
    WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{ExchangeSetupRequest, exchange_setup_response::Outcome};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, PreparedPaidInputV1,
    SourceRef, TextArtifact, TextExecution, TextExecutionId, TextPolicy, TokenIds, completed_text,
};
use hellas_rpc::protocol::work::{
    JobDeadlines, PaidChannelPolicyV1, PaidExecutionPolicyV1, generation_policy_digest,
    identity_source_digest, private_policy_commitment,
};
use hellas_rpc::protocol::work_setup::{
    ProviderChannelPolicy, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor,
};
use hellas_rpc::services::work::WorkServer;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProducerSigningKey, ProgramManifest, PublicKey as RpcPublicKey,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport as _, TransportContext};
use hellas_work::work::{
    BackendFault, ClientEndpoint, CloseEndpoint, JobProposal, PaidWorkBackend, PaymentError,
    PreparedEvaluateInput, RunOutcome, WorkService, propose_work, run_accepted_work,
};
use hellas_work::work_close::{CloseProgress, TxSink, close_start};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{SetupAdvance, SetupProgress, SetupStep, advance_setup};
use hellas_work::work_store::{Role, SetupOrigin, SetupScan, SetupStore};
use tokio::sync::mpsc;

use crate::HellasBlock;
use crate::app::Mempool;
use crate::config::{Genesis, GenesisEntry, GenesisValidator, ValidatorConfig};
use crate::domain::{
    KERNEL_FEES, Object, SettlementKey, TEST_NETWORK, coin_object_id, genesis_object_id,
};
use crate::execution::store::{UtxoDatabase, utxo_db_config};
use crate::execution::test_support::{
    ConsensusFixture, consensus_fixture_of, finalization, index_block, index_genesis, run_qmdb,
};
use crate::execution::{ChainVerifier, execute_all};
use crate::genesis::GENESIS_SCHEMA_VERSION;
use crate::indexer::spawn_follower_indexer;
use crate::light_client::{ConsensusInfo, LightClient};
use crate::owner_index::{ApplyOutcome, OwnerIndex};
use crate::rpc::LocalLightClient;
use crate::work_blocks::{PaidWorkClockAdvance, WorkBlocks, advance_paid_work_clock};
use crate::work_view::{FinalizedWorkView, WorkChannelQuery};

// ── The money, and the two numbers it is made of ──────────────────────

/// The whole of the client's genesis allocation, and the whole of what
/// it funds the payment edge with.
const CLIENT_FUNDING: u64 = 100;
/// The whole of the provider's genesis allocation, and the whole of
/// what it stakes on the bond. Deliberately not equal to [`PRICE`]:
/// returned principal and earnings must be two distinguishable numbers.
const PROVIDER_STAKE: u64 = 12;
/// What a proved understatement forfeits.
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 51;
/// The sole job's price, fixed by the execution policy both parties
/// signed.
const PRICE: u64 = 10;
/// The bond's timeout, and so the channel's admission horizon.
const HORIZON: u64 = 64;
/// The shipped devnet document's committee size.
const VALIDATORS: u64 = 6;
/// The response window the terms commit and the measurements claim.
const WINDOW: u64 = MIN_OMIT_RESPONSE_BLOCKS + 4;
const SALT: [u8; 32] = [0x5a; 32];
const CREDIT_LIMIT: u64 = 40;
/// Which node the provider reads and submits at.
const PROVIDER_NODE: usize = 0;
/// Which node the client reads and submits at. Not the provider's.
const CLIENT_NODE: usize = 1;

// ── Identities ────────────────────────────────────────────────────────

fn signer(byte: u8) -> Secp256k1Signer {
    match Secp256k1Signer::from_secret_scalar([byte; 32]) {
        Ok(signer) => signer,
        Err(error) => panic!("a fixed scalar is a key: {error:?}"),
    }
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

fn client_key() -> SettlementKey {
    SettlementKey::from(client().party_key())
}

fn provider_key() -> SettlementKey {
    SettlementKey::from(provider().party_key())
}

// ── Genesis, as a document ────────────────────────────────────────────

/// The genesis document this network is defined by.
///
/// Six validators, and two allocations addressed by secp256k1
/// settlement keys — the case `parse_genesis_settlement_key` was widened
/// for. Nothing here bypasses that parser.
fn genesis_document(fixture: &ConsensusFixture) -> Genesis {
    Genesis {
        schema_version: GENESIS_SCHEMA_VERSION,
        network_id: TEST_NETWORK.as_str().to_string(),
        validators: fixture
            .leaders
            .iter()
            .enumerate()
            .map(|(index, key)| GenesisValidator {
                public_key: hex::encode(key.encode()),
                label: format!("validator-{index}"),
            })
            .collect(),
        allocations: vec![
            GenesisEntry {
                address: client_key().to_string(),
                balance: CLIENT_FUNDING,
            },
            GenesisEntry {
                address: provider_key().to_string(),
                balance: PROVIDER_STAKE,
            },
        ],
    }
}

/// The allocations that document funds, derived the way a validator
/// derives them.
fn genesis_allocations(genesis: Genesis) -> Vec<(SettlementKey, u64)> {
    let config = ValidatorConfig {
        private_key: String::new(),
        threshold_share: String::new(),
        threshold_polynomial: String::new(),
        listen_port: 0,
        metrics_port: None,
        light_client_bind: None,
        relay_urls: Vec::new(),
        genesis,
        peers: Vec::new(),
    };
    match config.genesis_allocations() {
        Ok(allocations) => allocations,
        Err(error) => panic!("the genesis document funds both parties: {error}"),
    }
}

/// The genesis coin one allocation minted, named by its position in the
/// sorted allocation list — which is the index
/// `maybe_seed_genesis` writes it under.
fn genesis_coin(allocations: &[(SettlementKey, u64)], owner: SettlementKey) -> CoinId {
    let Some(index) = allocations.iter().position(|(key, _)| *key == owner) else {
        panic!("genesis funds this owner");
    };
    let Ok(index) = u16::try_from(index) else {
        panic!("two allocations fit in a u16");
    };
    CoinId::from_bytes(genesis_object_id(index).into())
}

// ── The channel both parties sign ─────────────────────────────────────

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

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), PROVIDER_STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: CREDIT_LIMIT,
    }
}

fn bond_funding(allocations: &[(SettlementKey, u64)]) -> Funding {
    Funding::new(
        one_coin(genesis_coin(allocations, provider_key())),
        no_coins(),
    )
}

fn payment_funding(allocations: &[(SettlementKey, u64)]) -> Funding {
    Funding::new(
        one_coin(genesis_coin(allocations, client_key())),
        no_coins(),
    )
}

fn bond_edge(allocations: &[(SettlementKey, u64)]) -> EdgeId {
    KernelTx::edge_id_of(
        &bond_funding(allocations),
        &KernelTerms::work_stake_bond(bond_terms()),
    )
}

fn payment_edge(allocations: &[(SettlementKey, u64)]) -> EdgeId {
    KernelTx::edge_id_of(
        &payment_funding(allocations),
        &KernelTerms::work_payment(payment_terms(allocations)),
    )
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: CREDIT_LIMIT,
        delivery_credit_limit: CREDIT_LIMIT,
    }
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(&text_policy().canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the generation policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(&identity_artifact().canonical_bytes())
        {
            Ok(digest) => digest,
            Err(error) => panic!("the identity artifact hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
        fixed_price: PRICE,
    }
}

fn payment_terms(allocations: &[(SettlementKey, u64)]) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(allocations),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(
            TEST_NETWORK,
            &SALT,
            &channel_policy(),
        ),
        omit_response_blocks: WINDOW,
        start_validity_blocks: 64,
        omission_bond: OMISSION_BOND,
    }
}

/// What the provider requires the client's edge to be worth: the whole
/// allocation, no reserve, and this chain's zero fees.
fn expected_values() -> EdgeValues {
    EdgeValues::new(CLIENT_FUNDING, 0, Fees::new(0, 0, 0, 0))
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

fn descriptor(allocations: &[(SettlementKey, u64)]) -> WorkChannelDescriptor {
    match WorkChannelDescriptor::open(WorkChannelConfig {
        network: TEST_NETWORK,
        payment_edge: payment_edge(allocations),
        payment_terms: payment_terms(allocations),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy().into(),
        expected_payment_values: expected_values(),
    }) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the configured channel opens: {error}"),
    }
}

// ── One node, and six of them ─────────────────────────────────────────

/// One validator's own state: its database, its kernel's output, its
/// owner index, its finalized-block indexer, and its mempool.
struct Node {
    database: UtxoDatabase<commonware_runtime::tokio::Context>,
    index: OwnerIndex,
    indexer: crate::indexer::ChainIndexer,
    mempool: Mempool,
    task: Handle<()>,
}

/// One runtime label per node. Static because `Supervisor::child` takes
/// a `&'static str`, and six of them is the shipped committee.
const NODE_LABELS: [&str; 6] = [
    "validator_0",
    "validator_1",
    "validator_2",
    "validator_3",
    "validator_4",
    "validator_5",
];

/// Six nodes on one genesis, and the proposer they do not have.
struct Devnet {
    nodes: Vec<Node>,
    fixture: ConsensusFixture,
    allocations: Vec<(SettlementKey, u64)>,
    consensus_info: ConsensusInfo,
    head: HellasBlock,
    height: u64,
    /// Every transaction already in finalized history, by digest.
    ///
    /// A count would not do. A mempool snapshot lists its response
    /// residents in front of its general ones, so the moment a contest
    /// answer arrives a positional cursor re-proposes transactions that
    /// are already on chain — which the kernel then refuses. This is the
    /// proposer's own rule, spelled here because there is no proposer.
    included: BTreeSet<crate::domain::Digest>,
}

impl Devnet {
    async fn start(runtime: commonware_runtime::tokio::Context, name: &str) -> Self {
        let fixture = consensus_fixture_of(101, VALIDATORS);
        let document = genesis_document(&fixture);
        // The document is the network's identity, so the id everything
        // below signs under is read back out of it rather than assumed.
        let network = match crate::domain::network_id(&document) {
            Ok(network) => network,
            Err(error) => panic!("the genesis document names its network: {error}"),
        };
        assert_eq!(
            network, TEST_NETWORK,
            "every signature below is bound to the id the document declares",
        );
        let allocations = genesis_allocations(document);
        assert_eq!(
            allocations.len(),
            2,
            "genesis funds exactly the two parties",
        );
        let consensus_info = ConsensusInfo {
            validators: fixture
                .leaders
                .iter()
                .map(|key| hex::encode(key.encode()))
                .collect(),
            threshold_identity: fixture.assembler.identity().encode().to_vec(),
            network_id: TEST_NETWORK.as_str().to_string(),
        };
        assert_eq!(consensus_info.validators.len(), VALIDATORS as usize);

        let genesis = index_genesis();
        let mut nodes = Vec::new();
        for (ordinal, label) in NODE_LABELS.iter().enumerate().take(VALIDATORS as usize) {
            let partition = format!("{name}_{ordinal}");
            let node_context = runtime.child(label);
            let config = utxo_db_config(&node_context, &partition, 1024, 8);
            let database =
                <UtxoDatabase<_> as DatabaseSet<_>>::init(node_context.child("db"), config).await;
            let (indexer, task) = spawn_follower_indexer(
                node_context.child("indexer"),
                &partition,
                crate::config::Config {
                    mailbox_size: 32,
                    replay_buffer: 32,
                    write_buffer: 32,
                    page_cache_size: 1024,
                    page_cache_count: 8,
                    ..crate::config::Config::default()
                },
                fixture.verifier.clone(),
                genesis.clone(),
            )
            .await
            .expect("a follower indexer");
            nodes.push(Node {
                database,
                index: OwnerIndex::new(TEST_NETWORK, &genesis, allocations.clone()),
                indexer,
                mempool: Mempool::default(),
                task,
            });
        }

        Self {
            nodes,
            fixture,
            allocations,
            consensus_info,
            head: genesis,
            height: 0,
            included: BTreeSet::new(),
        }
    }

    fn light_client(&self, node: usize) -> LocalLightClient {
        LocalLightClient::new(
            self.nodes[node].database.clone(),
            self.nodes[node].index.clone(),
            self.nodes[node].mempool.clone(),
            self.nodes[node].indexer.clone(),
            self.consensus_info.clone(),
        )
    }

    fn blocks(&self, node: usize) -> WorkBlocks<LocalLightClient> {
        WorkBlocks::new(self.light_client(node))
    }

    /// Plays the proposer: everything every node's mempool has taken
    /// since the last block goes into the next one, and all six execute
    /// it.
    ///
    /// This is the simulated part, and it is simulated in exactly one
    /// direction: the *ordering* is this function's, and the *execution*
    /// is each node's own kernel. A block whose six state roots disagree
    /// is refused here rather than finalized, so nothing below can rest
    /// on one node's private opinion of the state.
    async fn seal(&mut self) -> HellasBlock {
        let mut fresh = Vec::new();
        let mut proposed = BTreeSet::new();
        for node in &self.nodes {
            for transaction in node.mempool.test_transactions().await {
                let digest =
                    <commonware_cryptography::Sha256 as commonware_cryptography::Hasher>::hash(
                        &commonware_codec::Encode::encode(&transaction),
                    );
                if self.included.contains(&digest) || !proposed.insert(digest) {
                    continue;
                }
                fresh.push(transaction);
            }
        }
        self.included.extend(proposed);
        self.height += 1;

        let mut root = None;
        for node in &self.nodes {
            let batches = node.database.new_batches().await;
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
            let node_root = merkleized.root();
            match root {
                None => root = Some(node_root),
                Some(agreed) => assert_eq!(
                    node_root, agreed,
                    "every validator's own execution reaches the same state root",
                ),
            }
            node.database.finalize(merkleized).await;
        }
        let Some(root) = root else {
            panic!("a devnet has at least one node");
        };

        let block = index_block(&self.head, root, fresh);
        let certificate = finalization(&self.fixture, &block);
        for node in &self.nodes {
            node.indexer
                .ingest_finalized(block.clone(), certificate.clone())
                .await
                .expect("a certified block is ingested");
            assert_eq!(
                node.index.apply_finalized(&block),
                Ok(ApplyOutcome::Applied),
            );
        }
        self.head = block.clone();
        block
    }

    async fn seal_through(&mut self, height: u64) {
        while self.height < height {
            self.seal().await;
        }
    }

    /// Every coin this fixture can mint for one owner at the finalized
    /// tip, read from that node's executed QMDB state.
    ///
    /// QMDB has no full-object iterator, so the fixed transaction graph's
    /// complete coin-id set is probed directly. Projected ids are added to
    /// that set so an index-only extra is also caught, and the projection
    /// must then equal the coins and values actually read from QMDB.
    async fn coins(&self, node: usize, owner: SettlementKey) -> Vec<(CoinId, u64)> {
        let Some(held) = self
            .light_client(node)
            .get_coins_by_owner(owner)
            .await
            .expect("the owner index answers")
        else {
            panic!("the owner index has a finalized cursor");
        };
        let projected_root = held.snapshot.state_root;
        let mut projected = held
            .coins
            .into_iter()
            .map(|(id, value)| (CoinId::from_bytes(id.into()), value))
            .collect::<Vec<_>>();
        projected.sort_by_key(|(id, value)| (*value, *id));

        let (earnings, refund) = payment_close_coins(&self.allocations);
        let mut ids = BTreeSet::from([
            genesis_coin(&self.allocations, client_key()),
            genesis_coin(&self.allocations, provider_key()),
            earnings,
            refund,
        ]);
        ids.extend(
            KernelTx::close_output_ids(bond_edge(&self.allocations), &bond_terms().timeout_outputs)
                .iter()
                .copied(),
        );
        ids.extend(projected.iter().map(|(id, _)| *id));

        let reader = self.nodes[node].database.read().await;
        assert_eq!(
            reader.root(),
            projected_root,
            "the owner projection and executed reads name the same finalized state",
        );
        let mut executed = Vec::new();
        for id in ids {
            match reader
                .get(&coin_object_id(id))
                .await
                .expect("the finalized QMDB answers a coin read")
            {
                Some(Object::Coin(coin)) if coin.owner == owner => {
                    executed.push((id, coin.value));
                }
                Some(Object::Coin(_)) | None => {}
                Some(object) => panic!(
                    "fixture coin id {id:?} resolved to a {} in finalized QMDB",
                    object.kind(),
                ),
            }
        }
        executed.sort_by_key(|(id, value)| (*value, *id));
        assert_eq!(
            projected, executed,
            "the owner-index projection agrees with the executed coin state",
        );
        executed
    }

    async fn value_of(&self, node: usize, owner: SettlementKey, coin: CoinId) -> Option<u64> {
        self.coins(node, owner)
            .await
            .into_iter()
            .find(|(id, _)| *id == coin)
            .map(|(_, value)| value)
    }

    async fn snapshot(
        &self,
        node: usize,
        allocations: &[(SettlementKey, u64)],
    ) -> crate::work_view::WorkChannelSnapshot {
        self.light_client(node)
            .work_channel_snapshot(WorkChannelQuery {
                bond_edge: bond_edge(allocations),
                payment_edge: payment_edge(allocations),
                funding: BTreeSet::new(),
            })
            .await
            .expect("a channel snapshot reads")
            .expect("finalized channel state exists")
    }

    /// Stops every follower indexer before the commonware runtime that
    /// owns it is dropped.
    async fn shutdown(self) {
        for node in self.nodes {
            node.task.abort();
            let _ = node.task.await;
        }
    }
}

// ── The handshake, and the setup drive ────────────────────────────────

fn open_setup(root: &std::path::Path, bond: EdgeId, role: Role) -> SetupStore {
    match SetupStore::open(root, TEST_NETWORK, bond, role, &Secp256k1Verifier::new()) {
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

/// The provider's live setup service after a real three-revision
/// handshake.
///
/// Only the provider's half stays alive, because only the provider's
/// half is a runner's: the client's endpoint is dropped so its journal
/// reaches the disk, and everything asserted about the client below is
/// read back out of those files by a fresh `SetupStore::open`.
struct Handshake {
    provider: SetupService,
}

/// Runs the handshake and leaves the provider's half alive, exactly as
/// the runner holds it: behind the [`SetupService`] that answered.
async fn shake_hands(
    provider_root: &std::path::Path,
    client_root: &std::path::Path,
    allocations: &[(SettlementKey, u64)],
    scan: SetupScan,
) -> Handshake {
    let bond = bond_edge(allocations);
    let mut proposer = SetupEndpoint::new(
        open_setup(provider_root, bond, Role::Provider),
        provider(),
        PaymentAdmission::Admits(Box::new(provider_policy())),
    );
    proposer.arm_scan(scan).expect("the provider arms its scan");
    if let Err(error) = proposer.propose_bond(TEST_NETWORK, bond_funding(allocations), bond_terms())
    {
        panic!("the provider proposes its bond: {error}");
    }
    let service = SetupService::new(proposer);

    let mut caller = SetupEndpoint::new(
        open_setup(client_root, bond, Role::Client),
        client(),
        PaymentAdmission::Proposes(Box::new(provider_policy())),
    );
    let proposal = exchange(&service, Vec::new()).await;
    if let Err(error) = caller.import(&proposal) {
        panic!("the client imports the bond proposal: {error}");
    }
    caller.arm_scan(scan).expect("the client arms its scan");
    if let Err(error) =
        caller.propose_payment(payment_funding(allocations), payment_terms(allocations))
    {
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
    assert_eq!(
        caller.state().revision(),
        Some(3),
        "both halves hold the fully countersigned setup",
    );
    drop(caller);
    Handshake { provider: service }
}

/// One step of the provider's setup, driven the way `serve`'s clock
/// drives it: through the same [`SetupService`] that answered the
/// handshake, over one source that is both view, blocks and sink.
async fn provider_step(
    service: &SetupService,
    source: &WorkBlocks<LocalLightClient>,
) -> SetupAdvance {
    loop {
        match service.advance_setup(source, source, source).await {
            Ok(SetupAdvance {
                progress: SetupProgress::HistoryAdvanced { .. },
                ..
            }) => continue,
            Ok(advance) => return advance,
            Err(error) => panic!("the provider's setup takes a step: {error}"),
        }
    }
}

/// The same, for the client's own journal, which submits nothing.
async fn client_step(
    store: &mut SetupStore,
    source: &WorkBlocks<LocalLightClient>,
) -> SetupAdvance {
    loop {
        match advance_setup(source, source, source, store, &Secp256k1Verifier::new()).await {
            Ok(SetupAdvance {
                progress: SetupProgress::HistoryAdvanced { .. },
                ..
            }) => continue,
            Ok(advance) => return advance,
            Err(error) => panic!("the client's setup takes a step: {error}"),
        }
    }
}

// ── The one executor, invoked twice ───────────────────────────────────

/// The prompt this fixture's job runs on.
const PROMPT: [u32; 4] = [9, 8, 7, 6];

/// The deterministic implementation both parties run.
///
/// Not `hellas-executor`: there are no model weights in this
/// repository. What it stands in for is the *model*; the two invocations
/// of it below are real and separate, and the one that matters — the
/// client's — reaches it through the real [`Reproducer`] seam with the
/// real bundle derivation in front.
struct FixtureExecutor;

impl FixtureExecutor {
    /// One deterministic continuation of a prompt.
    fn run(prompt: &[u32], max_new_tokens: u32) -> Vec<u32> {
        let limit = core::cmp::min(prompt.len(), max_new_tokens as usize + 1);
        let mut out = Vec::with_capacity(limit + 1);
        out.push(101);
        for token in &prompt[..limit.saturating_sub(1)] {
            out.push(token.wrapping_mul(7).wrapping_add(59));
        }
        out
    }
}

/// The provider's backend: the shared executor, plus the signed
/// transcript a provider produces around it, and a call counter.
struct ProviderBackend {
    calls: Arc<AtomicUsize>,
    /// The prompt a shipped provider would resolve from its artifact
    /// store. Handed over here; see the module note.
    prompt: Vec<u32>,
}

impl PaidWorkBackend for ProviderBackend {
    fn evaluate(
        &self,
        input: PreparedEvaluateInput,
    ) -> impl core::future::Future<Output = Result<Vec<OutputEventEnvelope>, BackendFault>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = FixtureExecutor::run(&self.prompt, execution_policy().max_new_tokens);
        let prompt = self.prompt.clone();
        async move { Ok(transcript_for(input.evaluate_request(), &prompt, &answer)) }
    }
}

/// The client's re-execution: the same executor, reached through the
/// real seam, on the question the *journal-held bundle* derives.
struct ClientReexecution {
    calls: Arc<AtomicUsize>,
}

impl Reproducer for ClientReexecution {
    async fn reproduce(&self, bundle: &PreparedPaidInputV1) -> Result<Reproduced, ReproduceFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let plan = reproduction_plan(bundle)?;
        assert_eq!(
            plan.prompt_token_ids,
            PROMPT.to_vec(),
            "the client's question comes out of the bundle both parties signed",
        );
        Ok(Reproduced {
            output_token_ids: FixtureExecutor::run(&plan.prompt_token_ids, plan.max_new_tokens),
            stop_reason: EvaluateStopReason::STOP_TOKEN,
            matched_stop_token_id: Some(1),
        })
    }
}

fn transcript_for(
    request: &EvaluateRequest,
    prompt: &[u32],
    answer: &[u32],
) -> Vec<OutputEventEnvelope> {
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: prompt.len() as u64,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the usage sums: {error}"),
    };
    let text_artifact = completed_text(
        TextExecutionId::from_digest(request.text_execution),
        prompt,
        answer,
    )
    .artifact
    .output_id()
    .digest();
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact,
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the transcript finishes: {error}"),
    }
}

// ── The job's prepared inputs ─────────────────────────────────────────

const CAUSAL_LM_ENVIRONMENT_ID: ContentId = ContentId::from_bytes([0x16; 32]);

fn manifest() -> ProgramManifest {
    let application = Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR)
        .expect("the causal-LM application identity is valid");
    ProgramManifest::new(application, CAUSAL_LM_ENVIRONMENT_ID)
}

fn prompt_tokens() -> TokenIds {
    TokenIds::from(PROMPT.to_vec())
}

fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(BoundTermId::from_digest(manifest().content_id().digest()))
}

fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

fn evaluate_request() -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: RpcPublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [0x9e; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn prepared_input() -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 30,
        terminal: 40,
        payment: 50,
    }
}

// ── Transport ─────────────────────────────────────────────────────────

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let _ = self.out.send(bytes);
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
    }
}

fn session() -> TransportContext {
    TransportContext {
        open_exporter: Some([0x5e; 32]),
        ..TransportContext::default()
    }
}

fn transport_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let caller = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
        },
        session(),
    );
    let answerer = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        session(),
    );
    (caller, answerer)
}

fn serve(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

// ── The whole opened channel, both halves ─────────────────────────────

/// Everything the two parties hold once consensus has opened their
/// channel: the mounted provider service, the client's endpoint, the
/// readiness decision, and where the channel began.
struct Opened {
    service: WorkService,
    client: ClientEndpoint,
    ready: ReadyChannel,
    origin: SetupOrigin,
}

/// Steps 1 and 2: a real chain, a real genesis, and a real channel
/// opened through it.
async fn open_channel(
    devnet: &mut Devnet,
    provider_root: &std::path::Path,
    client_root: &std::path::Path,
) -> Opened {
    let allocations = devnet.allocations.clone();
    let provider_blocks = devnet.blocks(PROVIDER_NODE);
    let client_blocks = devnet.blocks(CLIENT_NODE);

    // The genesis coins exist only once a block has executed.
    let floor = devnet.seal().await;
    assert_eq!(
        devnet
            .value_of(
                PROVIDER_NODE,
                client_key(),
                genesis_coin(&allocations, client_key())
            )
            .await,
        Some(CLIENT_FUNDING),
        "genesis funded the client's secp256k1 settlement key",
    );
    assert_eq!(
        devnet
            .value_of(
                CLIENT_NODE,
                provider_key(),
                genesis_coin(&allocations, provider_key())
            )
            .await,
        Some(PROVIDER_STAKE),
        "genesis funded the provider's secp256k1 settlement key",
    );

    let handshake = shake_hands(provider_root, client_root, &allocations, scan_at(&floor)).await;

    // The bond, submitted by the driver and finalized by consensus.
    assert_eq!(
        provider_step(&handshake.provider, &provider_blocks)
            .await
            .progress,
        SetupProgress::Submitted {
            step: SetupStep::Bond,
            outcome: crate::SubmitTxOutcome::Enqueued,
        },
    );
    let bond_block = devnet.seal().await;
    assert_eq!(bond_block.txs().len(), 1, "one bond Open, finalized");

    // Then the payment, which takes the bond's lease.
    assert_eq!(
        provider_step(&handshake.provider, &provider_blocks)
            .await
            .progress,
        SetupProgress::Submitted {
            step: SetupStep::Payment,
            outcome: crate::SubmitTxOutcome::Enqueued,
        },
    );
    let origin_block = devnet.seal().await;
    assert_eq!(origin_block.txs().len(), 1, "one payment Open, finalized");

    let advance = provider_step(&handshake.provider, &provider_blocks).await;
    let SetupProgress::Complete(origin) = advance.progress else {
        panic!("the provider completes its setup: {:?}", advance.progress);
    };
    assert_eq!(
        origin,
        SetupOrigin {
            payment_edge: payment_edge(&allocations),
            height: commonware_consensus::Heightable::height(&origin_block).get(),
            payload: origin_block.digest().into(),
            parent: bond_block.digest().into(),
        },
    );
    let Some(provider_store) = advance.mounted else {
        panic!("a completed setup hands back the channel it mounted");
    };

    // The client reaches the same origin from its own journal, reading a
    // different validator. The journal is reopened from the disk, so
    // nothing this process held in memory carries the client's half.
    let mut client_setup = open_setup(client_root, bond_edge(&allocations), Role::Client);
    let client_advance = client_step(&mut client_setup, &client_blocks).await;
    assert_eq!(client_advance.progress, SetupProgress::Complete(origin));
    let Some(client_store) = client_advance.mounted else {
        panic!("the client's completed setup hands back its channel");
    };

    // One coherent finalized read, and the readiness decision made from
    // it. Both parties take their own.
    let provider_snapshot = devnet.snapshot(PROVIDER_NODE, &allocations).await;
    let client_snapshot = devnet.snapshot(CLIENT_NODE, &allocations).await;
    let payment = provider_snapshot
        .payment()
        .expect("the payment edge is live");
    assert_eq!(
        payment.values(),
        expected_values(),
        "the funded edge is worth what the admitted policy required",
    );
    assert_eq!(
        devnet
            .snapshot(CLIENT_NODE, &allocations)
            .await
            .payment()
            .map(|edge| edge.values()),
        Some(expected_values()),
        "and the client's own validator says the same",
    );

    let ready = match descriptor(&allocations).check_ready(&provider_snapshot.observed_channel()) {
        Ok(ready) => ready,
        Err(error) => panic!("the opened channel is ready: {error}"),
    };
    let client_ready =
        match descriptor(&allocations).check_ready(&client_snapshot.observed_channel()) {
            Ok(ready) => ready,
            Err(error) => panic!("the client's read is ready too: {error}"),
        };
    assert_eq!(
        ready.settlement().capacity(),
        CLIENT_FUNDING - OMISSION_BOND,
    );

    // The mount, in the runner's own order: close-only first, then a
    // readiness decision admits work.
    let close = match CloseEndpoint::new(provider_store, provider()) {
        Ok(close) => close,
        Err(error) => panic!("the mounted channel is this node's to close: {error}"),
    };
    let service = WorkService::close_only(close);
    if let Err(error) = service.admit_new_work(ready.clone()) {
        panic!("the ready channel admits work: {error}");
    }
    let client_endpoint = match ClientEndpoint::new(client_ready, client_store, client()) {
        Ok(endpoint) => endpoint,
        Err(error) => panic!("the client endpoint binds: {error}"),
    };

    Opened {
        service,
        client: client_endpoint,
        ready,
        origin,
    }
}

/// Step 3: one paid job, with both invocation counts asserted.
///
/// Returns the price the provider acknowledged crediting.
async fn run_one_paid_job(devnet: &Devnet, opened: &mut Opened) -> u64 {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let client_calls = Arc::new(AtomicUsize::new(0));
    let backend = ProviderBackend {
        calls: Arc::clone(&provider_calls),
        prompt: PROMPT.to_vec(),
    };
    let engine = ClientReexecution {
        calls: Arc::clone(&client_calls),
    };
    let proposal = JobProposal {
        prepared_input: prepared_input().into(),
        deadlines: deadlines(),
    };

    let (transport, server) = transport_pair();
    let serving = serve(server, opened.service.clone());
    let work_id = propose_work(transport, &mut opened.client, &proposal)
        .await
        .expect("the provider accepts the proposed job");
    serving.abort();

    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        0,
        "acceptance runs no backend",
    );

    let outcome = run_accepted_work(&opened.service, &opened.ready, &backend, work_id).await;
    assert!(
        matches!(outcome, Ok(RunOutcome::Completed { .. })),
        "the accepted job completes: {outcome:?}",
    );
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        1,
        "the provider invoked its backend exactly once",
    );

    // Nothing is payable yet. `collect_checked_result` is the only step
    // that both takes the answer and checks it, and this is the journal
    // refusing to price a job it has not been through.
    //
    // What this does *not* separate is delivery from the check: proving
    // that a delivered-but-refuted answer cannot be paid for needs a
    // second verdict on the same job, and that is
    // `crates/client/tests/work.rs`'s. Here the two are one call, and
    // the assertion is that the payment comes after it.
    let too_early = opened.client.pay(work_id);
    assert!(
        matches!(too_early, Err(PaymentError::NotPayable { .. })),
        "a job the client has not collected and checked is not payable: {too_early:?}",
    );

    let (transport, server) = transport_pair();
    let serving = serve(server, opened.service.clone());
    let collected = collect_checked_result(
        transport,
        &mut opened.client,
        &opened.ready,
        &devnet.blocks(CLIENT_NODE),
        &engine,
        work_id,
    )
    .await;
    serving.abort();
    let Ok(CollectOutcome::Checked(CheckedResult { result, transcript })) = collected else {
        panic!("the delivered answer reproduces: {collected:?}");
    };
    assert_eq!(result.work_id, work_id);
    assert!(!transcript.is_empty());
    assert_eq!(
        client_calls.load(Ordering::SeqCst),
        1,
        "the client re-executed exactly once",
    );

    // The payment is signed only now: `collect_checked_result` is what
    // reaches the matched phase, and `pay` refuses any other one.
    let (transport, server) = transport_pair();
    let serving = serve(server, opened.service.clone());
    let credited = pay_for_result(transport, &mut opened.client, work_id).await;
    serving.abort();
    let Ok(credited) = credited else {
        panic!("the checked answer is paid for: {credited:?}");
    };
    assert_eq!(credited, PRICE, "one job, at its authorized price");
    assert_eq!(
        opened
            .service
            .with_state(|state| state.max_executable_certificate())
            .expect("the endpoint is reachable"),
        PRICE,
        "the provider holds a certificate for exactly the job price",
    );
    // Still one, after a delivery and a payment: the answer came out of
    // the provider's spool, not out of a second run.
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);
    assert_eq!(client_calls.load(Ordering::SeqCst), 1);
    credited
}

/// One tick through the same per-channel entry `serve` puts on its timer.
async fn provider_clock(devnet: &Devnet, service: &WorkService) -> PaidWorkClockAdvance {
    let blocks = devnet.blocks(PROVIDER_NODE);
    advance_paid_work_clock(service, &blocks)
        .await
        .expect("the provider's production clock advances")
}

/// Drives the provider's close until the contest it opened is on chain.
async fn drive_close_onto_chain(devnet: &mut Devnet, service: &WorkService) {
    let advance = provider_clock(devnet, service).await;
    assert!(
        matches!(advance.close, CloseProgress::Submitted { .. }),
        "the production clock submits a start: {advance:?}",
    );
    assert_eq!(advance.adjudication, None, "no contest is finalized yet");
    assert_eq!(advance.bond_timeout, None, "the bond horizon is ahead");
    devnet.seal().await;

    let advance = provider_clock(devnet, service).await;
    let CloseProgress::Opened { .. } = advance.close else {
        panic!("the start opened a contest: {advance:?}");
    };
    assert_eq!(
        advance.adjudication, None,
        "an unresponded contest below its deadline is not final",
    );
    assert_eq!(advance.bond_timeout, None, "the bond horizon is ahead");
}

/// Lets the production clock submit a due adjudication and finalizes it.
async fn settle_on_the_clock(devnet: &mut Devnet, service: &WorkService) -> HellasBlock {
    let allocations = devnet.allocations.clone();
    assert_eq!(
        provider_clock(devnet, service).await.adjudication,
        Some(crate::SubmitTxOutcome::Enqueued),
        "the production clock submits the due adjudicated close",
    );
    let block = devnet.seal().await;
    assert!(
        block.txs().iter().any(|tx| matches!(
            tx,
            crate::domain::Transaction::Kernel(KernelTx::Close { input, .. })
                if *input == payment_edge(&allocations)
        )),
        "the adjudicated payment close is in finalized history",
    );
    block
}

/// Lets the production clock return the completed bond at its horizon.
async fn return_the_stake(devnet: &mut Devnet, service: &WorkService) -> CoinId {
    let allocations = devnet.allocations.clone();
    devnet.seal_through(HORIZON).await;
    assert_eq!(
        provider_clock(devnet, service).await.bond_timeout,
        Some(crate::SubmitTxOutcome::Enqueued),
        "the production clock submits the completed bond's timeout",
    );
    let block = devnet.seal().await;
    assert!(
        block.txs().iter().any(|tx| matches!(
            tx,
            crate::domain::Transaction::Kernel(KernelTx::Close { input, .. })
                if *input == bond_edge(&allocations)
        )),
        "the bond timeout is in finalized history",
    );
    let outputs =
        KernelTx::close_output_ids(bond_edge(&allocations), &bond_terms().timeout_outputs);
    assert_eq!(outputs.len(), 1, "the bond has one timeout payout");
    outputs.as_slice()[0]
}

/// The two payout coins an adjudicated payment close mints: the
/// provider's, then the client's.
///
/// A payout coin's id is `(edge, position, owner)` and deliberately not
/// its value (`crates/kernel/src/tx/payout.rs:66`), so naming a coin
/// this way says *which* payout it is and asserts nothing about how much
/// it is worth. That is why every amount below is a separate assertion
/// against what the finalized QMDB stores. The order — provider first,
/// client second — is `split_payouts`' own
/// (`crates/kernel/src/work.rs:266-278`).
fn payment_close_coins(allocations: &[(SettlementKey, u64)]) -> (CoinId, CoinId) {
    let edge = payment_edge(allocations);
    (
        Payout::new(provider().party_key(), 0).id(edge, 0),
        Payout::new(client().party_key(), 0).id(edge, 1),
    )
}

// ── Steps 1–4: the money claim ────────────────────────────────────────

/// The whole of §0, measured: the provider's finalized **earnings** rise
/// by exactly the job price, and its returned stake principal is a
/// different coin from a different close, asserted separately.
///
/// The settlement numbers are read back out of a validator's finalized
/// QMDB, with its owner-index projection required to agree, never computed
/// by this test and asserted against itself:
///
/// - the provider earns `10` — the certificate amount, and the price the
///   client's own authorization fixed;
/// - the provider's returned principal is `12` — its stake, back from
///   the bond's timeout, and **not** earnings;
/// - the client goes from `100` to `90`, a fall of exactly `10`.
///
/// `12 != 10` on purpose. A test whose stake and price were the same
/// number could pass on principal alone.
#[test]
fn one_paid_job_earns_the_price_and_returns_the_stake_separately() {
    run_qmdb(|runtime| async move {
        let provider_root = tempfile::tempdir().expect("a temp dir");
        let client_root = tempfile::tempdir().expect("a temp dir");
        let mut devnet = Devnet::start(runtime, "work_e2e_paid").await;
        let allocations = devnet.allocations.clone();

        let mut opened = open_channel(&mut devnet, provider_root.path(), client_root.path()).await;
        assert_eq!(opened.origin.payment_edge, payment_edge(&allocations));

        // The provider's stake is locked and its genesis coin is gone,
        // so nothing it holds now can be mistaken for earnings later.
        assert_eq!(
            devnet.coins(PROVIDER_NODE, provider_key()).await,
            Vec::new(),
            "the provider holds no coin at all while its stake is bonded",
        );

        let credited = run_one_paid_job(&devnet, &mut opened).await;
        assert_eq!(credited, PRICE);

        // Nothing has moved on chain yet: an admitted certificate is not
        // a payout.
        assert_eq!(
            devnet.coins(PROVIDER_NODE, provider_key()).await,
            Vec::new(),
            "an off-chain certificate pays nobody",
        );

        // Settle. The provider opens its own close at the certificate it
        // holds; there is nothing for anyone to answer.
        opened
            .service
            .prepare_close()
            .expect("the provider prepares the close its certificate spends");
        drive_close_onto_chain(&mut devnet, &opened.service).await;
        let deadline = match devnet.snapshot(PROVIDER_NODE, &allocations).await.pending() {
            PendingSlot::Present(pending) => {
                assert_eq!(
                    pending.final_cumulative(),
                    PRICE,
                    "the contest consensus holds settles at the certificate the client signed",
                );
                pending.response_deadline()
            }
            other => panic!("the start opened a contest on chain: {other:?}"),
        };
        devnet.seal_through(deadline).await;
        settle_on_the_clock(&mut devnet, &opened.service).await;

        // The provider's own journal, caught up past its close, agrees
        // about what it was paid.
        let advance = provider_clock(&devnet, &opened.service).await;
        assert_eq!(
            advance.close,
            CloseProgress::Settled {
                provider_payout: PRICE
            },
        );
        assert_eq!(advance.adjudication, None, "the payment edge is gone");
        assert_eq!(advance.bond_timeout, None, "the bond horizon is ahead");

        // ── The money ─────────────────────────────────────────────────
        //
        // Earnings first, named by the exact coin the adjudicated close
        // minted for the provider — so this is the payout of *this*
        // close, not a total.
        let (earnings_coin, refund_coin) = payment_close_coins(&allocations);
        assert_eq!(
            devnet
                .value_of(PROVIDER_NODE, provider_key(), earnings_coin)
                .await,
            Some(PRICE),
            "EARNINGS: the payment close paid the provider exactly the job price",
        );
        assert_eq!(
            devnet
                .value_of(CLIENT_NODE, provider_key(), earnings_coin)
                .await,
            Some(PRICE),
            "and a second validator's finalized QMDB says the same",
        );
        assert_eq!(
            devnet.coins(PROVIDER_NODE, provider_key()).await,
            vec![(earnings_coin, PRICE)],
            "EARNINGS ARE THE WHOLE OF WHAT THE PROVIDER HOLDS: \
             no principal has come back yet, so this number cannot be one",
        );

        // The client's side of the same close.
        assert_eq!(
            devnet
                .value_of(CLIENT_NODE, client_key(), refund_coin)
                .await,
            Some(CLIENT_FUNDING - PRICE),
            "the client got back its funding less exactly the job price",
        );
        assert_eq!(
            devnet.coins(CLIENT_NODE, client_key()).await,
            vec![(refund_coin, CLIENT_FUNDING - PRICE)],
            "and holds nothing else: 100 in, 90 out, a fall of exactly 10",
        );

        // Returned principal, separately: a different coin, from a
        // different edge, minted by a different close.
        let principal_coin = return_the_stake(&mut devnet, &opened.service).await;
        assert_ne!(
            principal_coin, earnings_coin,
            "principal and earnings are different coins",
        );
        assert_eq!(
            devnet
                .value_of(PROVIDER_NODE, provider_key(), principal_coin)
                .await,
            Some(PROVIDER_STAKE),
            "RETURNED PRINCIPAL: the bond timeout returned the stake, 12, unchanged",
        );
        assert_eq!(
            devnet
                .value_of(PROVIDER_NODE, provider_key(), earnings_coin)
                .await,
            Some(PRICE),
            "and the earnings coin is still exactly the price, 10, unchanged by it",
        );

        // The whole provider balance, decomposed. 22 = 10 earned + 12
        // returned, and the two halves are named.
        let mut held = devnet.coins(PROVIDER_NODE, provider_key()).await;
        held.sort_by_key(|(_, value)| *value);
        assert_eq!(
            held,
            vec![(earnings_coin, PRICE), (principal_coin, PROVIDER_STAKE)]
        );
        assert_eq!(
            held.iter().map(|(_, value)| value).sum::<u64>(),
            PRICE + PROVIDER_STAKE,
        );

        drop(opened);
        devnet.shutdown().await;
    });
}

// ── Step 5: the contest path ──────────────────────────────────────────

/// A client that opens an understated close is answered by the runner's
/// own close drive before the deadline, and the adjudicated close pays
/// the certificate — plus the omission bond the understatement forfeits
/// — rather than the claim.
///
/// The numbers: the client opens at `0`, having signed a certificate for
/// `10`. The provider is paid `10 + 4 = 14`; the client gets `100 - 14 =
/// 86`. The understated claim of `0` pays the provider nothing and is
/// what the response overrides.
#[test]
fn an_understated_close_is_answered_and_pays_the_certificate() {
    run_qmdb(|runtime| async move {
        let provider_root = tempfile::tempdir().expect("a temp dir");
        let client_root = tempfile::tempdir().expect("a temp dir");
        let mut devnet = Devnet::start(runtime, "work_e2e_contest").await;
        let allocations = devnet.allocations.clone();

        let mut opened = open_channel(&mut devnet, provider_root.path(), client_root.path()).await;
        assert_eq!(run_one_paid_job(&devnet, &mut opened).await, PRICE);

        // The client opens a close claiming the provider earned nothing.
        // Its own signature, on the real start builder, at the height
        // its own validator reports.
        let start = close_start(
            opened.ready.channel(),
            Party::Maker,
            devnet.height,
            None,
            &client(),
        )
        .expect("the client signs an understated start");
        assert!(
            start.certificate().is_none(),
            "the claim under test is that the provider earned nothing",
        );
        let client_blocks = devnet.blocks(CLIENT_NODE);
        assert_eq!(
            client_blocks
                .submit(KernelTx::move_action(Move::StartPaymentClose(start)))
                .await
                .expect("the client's validator takes the start"),
            crate::SubmitTxOutcome::Enqueued,
        );
        devnet.seal().await;

        let opened_at = devnet.height;
        let deadline = match devnet.snapshot(PROVIDER_NODE, &allocations).await.pending() {
            PendingSlot::Present(pending) => {
                assert_eq!(
                    pending.final_cumulative(),
                    0,
                    "the understated claim is on chain"
                );
                pending.response_deadline()
            }
            other => panic!("the client's start opened a contest: {other:?}"),
        };
        assert!(
            deadline > opened_at,
            "the window is open when the drive runs"
        );

        // The runner's close drive, on its cadence, over the provider's
        // own validator. This is the whole of the provider's answer.
        let advance = provider_clock(&devnet, &opened.service).await;
        let CloseProgress::Opened { .. } = advance.close else {
            panic!("the drive saw the contest: {advance:?}");
        };
        assert_eq!(
            advance.adjudication, None,
            "the response is not consensus evidence before it lands",
        );
        assert_eq!(advance.bond_timeout, None, "the bond horizon is ahead");
        let answer_block = devnet.seal().await;
        assert!(
            answer_block.txs().iter().any(|tx| matches!(
                tx,
                crate::domain::Transaction::Kernel(KernelTx::Move {
                    action: Move::RespondPaymentClose(_)
                })
            )),
            "the response is in finalized history",
        );
        assert!(
            devnet.height < deadline,
            "and it landed at {} — before the deadline at {deadline}",
            devnet.height,
        );

        let settled = match devnet.snapshot(PROVIDER_NODE, &allocations).await.pending() {
            PendingSlot::Present(pending) => pending,
            other => panic!("the answered contest is still pending: {other:?}"),
        };
        assert!(settled.responded(), "consensus recorded the answer");
        assert_eq!(
            settled.final_cumulative(),
            PRICE,
            "the contest now settles at the certificate, not the claim",
        );

        settle_on_the_clock(&mut devnet, &opened.service).await;

        // The adjudicated payouts: the certificate plus the forfeited
        // omission bond, and the client's remainder.
        let paid = PRICE + OMISSION_BOND;
        let (earnings_coin, refund_coin) = payment_close_coins(&allocations);
        assert_eq!(
            devnet
                .value_of(PROVIDER_NODE, provider_key(), earnings_coin)
                .await,
            Some(paid),
            "the adjudicated close paid the certificate amount plus the bond: 10 + 4",
        );
        assert_eq!(
            devnet.coins(PROVIDER_NODE, provider_key()).await,
            vec![(earnings_coin, paid)],
            "and that is the whole of what the provider holds: no principal is in it",
        );
        assert_eq!(
            devnet
                .value_of(CLIENT_NODE, client_key(), refund_coin)
                .await,
            Some(CLIENT_FUNDING - paid),
            "the client kept 86 of its 100, having tried to keep 100",
        );

        // And the principal, separately, as above.
        let principal_coin = return_the_stake(&mut devnet, &opened.service).await;
        assert_eq!(
            devnet
                .value_of(PROVIDER_NODE, provider_key(), principal_coin)
                .await,
            Some(PROVIDER_STAKE),
            "RETURNED PRINCIPAL: still 12, still not earnings",
        );

        drop(opened);
        devnet.shutdown().await;
    });
}
