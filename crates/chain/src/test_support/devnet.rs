//! Six independently executing validators on one genesis document.
//!
//! Only block ordering is a fixture: [`Devnet::seal`] plays the proposer,
//! and every validator executes each block with its own kernel against its
//! own QMDB. Each validator serves the light-client protocol over
//! WebSocket and certified history over iroh ChainSync, so a test can run
//! full nodes against it or a remote light client with no node at all.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use commonware_codec::Encode as _;
use commonware_consensus::{
    Block as _, CertifiableBlock as _,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::Digestible as _;
use commonware_glue::stateful::db::{DatabaseSet, Merkleized as _, Unmerkleized as _};
use commonware_runtime::{Handle, Supervisor as _};
use commonware_storage::{mmr::Location, qmdb::sync::Target};
use commonware_utils::non_empty_range;
use hellas_kernel::{Auth, BlockHash, BlockHeight, CoinId, Context as KernelContext, PayloadHash};

use crate::HellasBlock;
use crate::app::Mempool;
use crate::config::{Genesis, GenesisEntry, GenesisValidator};
use crate::consensus::ConsensusVerifier;
use crate::domain::{
    Coin, Digest, KERNEL_FEES, Object, SettlementKey, TEST_NETWORK, Transaction, coin_object_id,
    genesis_object_id,
};
use crate::execution::store::{UtxoDatabase, utxo_db_config};
use crate::execution::test_support::{ConsensusFixture, finalization, reshape_authorized};
use crate::execution::{ChainVerifier, execute_all};
use crate::genesis::GENESIS_SCHEMA_VERSION;
use crate::indexer::spawn_archive;
use crate::light_client::{ConsensusInfo, LightClient as _};
use crate::owner_index::{ApplyOutcome, OwnerIndex};
use crate::rpc::LocalLightClient;

/// Runs `test` on a commonware tokio runtime whose storage lives in a
/// fresh temporary directory; the devnet's databases are opened there.
pub fn run<F, Fut, T>(test: F) -> T
where
    F: FnOnce(Runtime) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    crate::execution::test_support::run_qmdb(test)
}

/// The shipped devnet document's committee size.
pub const VALIDATORS: usize = 6;

/// The runtime handed to [`Devnet::start`]; [`run`] provides one.
pub type Runtime = commonware_runtime::tokio::Context;

// ── Genesis owners ────────────────────────────────────────────────────

/// The curve a genesis owner signs with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerKind {
    /// A secp256k1 owner, signing natively.
    Native,
    /// A P-256 software passkey, signing WebAuthn assertions.
    Passkey,
}

/// One genesis allocation and the fixed scalar that owns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisOwner {
    pub kind: OwnerKind,
    /// Every byte of the owner's 32-byte secret scalar.
    pub seed: u8,
    pub balance: u64,
}

impl GenesisOwner {
    /// The settlement key genesis funds.
    pub fn key(&self) -> SettlementKey {
        match self.kind {
            OwnerKind::Native => native_signer(self.seed).party_key().into(),
            OwnerKind::Passkey => passkey(self.seed).party_key().into(),
        }
    }

    /// This owner's authorization of one kernel payload.
    pub fn authorize(&self, hash: PayloadHash) -> Auth {
        match self.kind {
            OwnerKind::Native => Auth::native(native_signer(self.seed).sign(hash)),
            OwnerKind::Passkey => Auth::webauthn(match passkey(self.seed).sign(hash) {
                Ok(assertion) => assertion,
                Err(error) => panic!("a software passkey signs: {error:?}"),
            }),
        }
    }

    /// The 32-byte secret scalar, as the CLI's file-backed signers read it.
    pub fn scalar(&self) -> [u8; 32] {
        [self.seed; 32]
    }
}

fn native_signer(seed: u8) -> hellas_kernel::Secp256k1Signer {
    match hellas_kernel::Secp256k1Signer::from_secret_scalar([seed; 32]) {
        Ok(signer) => signer,
        Err(error) => panic!("a fixed scalar is a secp256k1 key: {error:?}"),
    }
}

fn passkey(seed: u8) -> hellas_kernel::SoftPasskey {
    match hellas_kernel::SoftPasskey::from_secret_scalar([seed; 32]) {
        Ok(passkey) => passkey,
        Err(error) => panic!("a fixed scalar is a P-256 key: {error:?}"),
    }
}

/// The genesis coin one allocation minted, named by its position in the
/// sorted allocation list — which is the index `maybe_seed_genesis`
/// writes it under.
pub fn genesis_coin(allocations: &[(SettlementKey, u64)], owner: SettlementKey) -> CoinId {
    let Some(index) = allocations.iter().position(|(key, _)| *key == owner) else {
        panic!("genesis funds this owner");
    };
    let Ok(index) = u16::try_from(index) else {
        panic!("a fixture's allocations fit in a u16");
    };
    CoinId::from_bytes(genesis_object_id(index).into())
}

/// The owner's reshape of its whole genesis coin into one coin of the same
/// value delegated to `node`, and the id of that coin.
pub fn delegate_allocation(
    allocations: &[(SettlementKey, u64)],
    owner: &GenesisOwner,
    node: SettlementKey,
) -> (Transaction, CoinId) {
    let key = owner.key();
    let (tx, ids) = reshape_authorized(
        &[coin_object_id(genesis_coin(allocations, key))],
        &[(key, Some(node), owner.balance)],
        |hash| owner.authorize(hash),
    );
    (tx, CoinId::from_bytes(ids[0].0))
}

// ── The network ───────────────────────────────────────────────────────

/// What [`Devnet::start`] builds.
pub struct DevnetConfig<'a> {
    /// Prefixes every storage partition, so devnets sharing one runtime
    /// keep separate databases.
    pub name: &'a str,
    pub owners: Vec<GenesisOwner>,
    /// How many full nodes to start; full node `i` submits through
    /// validator `i` and syncs from it.
    pub full_nodes: usize,
}

/// One validator's own state: its database, its kernel's output, its
/// owner index, its finalized-block indexer, and its mempool.
struct Validator {
    database: UtxoDatabase<Runtime>,
    index: OwnerIndex,
    indexer: crate::indexer::ChainIndexer,
    mempool: Mempool,
    task: Handle<()>,
    light_client_url: String,
    chain_sync: iroh::EndpointAddr,
}

/// One runtime label per validator. Static because `Supervisor::child`
/// takes a `&'static str`.
const VALIDATOR_LABELS: [&str; VALIDATORS] = [
    "validator_0",
    "validator_1",
    "validator_2",
    "validator_3",
    "validator_4",
    "validator_5",
];

/// Six validators on one genesis, and the proposer they do not have.
pub struct Devnet {
    validators: Vec<Validator>,
    fixture: ConsensusFixture,
    document: Genesis,
    consensus_info: ConsensusInfo,
    genesis_payload: Digest,
    owners: Vec<GenesisOwner>,
    allocations: Vec<(SettlementKey, u64)>,
    full_nodes: Vec<crate::node::FullNode>,
    rpc: tokio::task::JoinSet<()>,
    activity: Vec<tokio::sync::broadcast::Sender<crate::ConsensusActivity>>,
    storage: tempfile::TempDir,
    head: HellasBlock,
    height: u64,
    /// Every transaction already in finalized history, by digest.
    ///
    /// A count would not do. A mempool snapshot lists its response
    /// residents in front of its general ones, so the moment a contest
    /// answer arrives a positional cursor re-proposes transactions that
    /// are already on chain — which the kernel then refuses. This is the
    /// proposer's own rule, spelled here because there is no proposer.
    included: BTreeSet<Digest>,
}

impl Devnet {
    pub fn start(
        runtime: Runtime,
        config: DevnetConfig<'_>,
    ) -> impl std::future::Future<Output = Self> + '_ {
        // Construct the network startup future outside the caller's poll frame.
        Box::pin(async move {
            let DevnetConfig {
                name,
                owners,
                full_nodes: full_node_count,
            } = config;
            assert!(
                full_node_count <= VALIDATORS,
                "each full node has its own validator"
            );
            // Full nodes use live peer discovery; each devnet needs its own committee
            // so concurrent tests cannot accept one another's certified blocks.
            let seed = rand::random();
            let unbound =
                crate::execution::test_support::consensus_fixture_of(seed, VALIDATORS as u64);
            let document = genesis_document(&unbound, &owners);
            // The document is the network's identity, so the id everything
            // below signs under is read back out of it rather than assumed.
            let network = match crate::domain::network_id(&document) {
                Ok(network) => network,
                Err(error) => panic!("the genesis document names its network: {error}"),
            };
            assert_eq!(
                network, TEST_NETWORK,
                "every signature a test makes is bound to the id the document declares",
            );
            // Derived the way a validator derives them, sorted by key.
            let allocations = match crate::config::genesis_allocations(&document) {
                Ok(allocations) => allocations,
                Err(error) => panic!("the genesis document funds every owner: {error}"),
            };
            assert_eq!(
                allocations.len(),
                owners.len(),
                "genesis funds exactly the configured owners",
            );
            let fixture = crate::execution::test_support::consensus_fixture_in(
                seed,
                VALIDATORS as u64,
                network,
                crate::genesis_digest(&document),
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

            let (root, target) = crate::execution::store::empty_state(
                runtime.child("genesis"),
                &format!("{name}-genesis"),
                1024,
                8,
            )
            .await;
            let genesis = HellasBlock::genesis(
                fixture.leaders.iter().min().unwrap().clone(),
                root,
                target,
                crate::genesis_digest(&document),
            );

            let storage = tempfile::tempdir().unwrap();
            for owner in &owners {
                std::fs::write(owner_file(storage.path(), owner), owner.scalar()).unwrap();
            }

            let mut validators = Vec::new();
            let mut rpc = tokio::task::JoinSet::new();
            let mut activity = Vec::new();
            for (ordinal, label) in VALIDATOR_LABELS.iter().enumerate() {
                let partition = format!("{name}_{ordinal}");
                let context = runtime.child(label);
                let config = utxo_db_config(&context, &partition, 1024, 8);
                let database =
                    <UtxoDatabase<_> as DatabaseSet<_>>::init(context.child("db"), config).await;
                let (indexer, task) = spawn_archive(
                    context.child("indexer"),
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
                let index = OwnerIndex::new(TEST_NETWORK, &genesis, allocations.clone());
                let mempool = Mempool::default();
                let (events, _) = tokio::sync::broadcast::channel(128);
                activity.push(events.clone());

                use hellas_wire::ServiceMarker as _;
                let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                    .alpns(vec![
                        hellas_rpc::services::chain_sync::ChainSync::ALPN
                            .as_bytes()
                            .to_vec(),
                        hellas_rpc::services::node::Node::ALPN.as_bytes().to_vec(),
                    ])
                    .bind()
                    .await
                    .unwrap();
                let chain_sync = endpoint.addr();
                rpc.spawn(crate::node::transport::serve_validator_endpoint(
                    indexer.clone(),
                    events.clone(),
                    endpoint,
                    database.clone(),
                    fixture.verifier.clone(),
                ));

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let light_client_url = format!("ws://{}", listener.local_addr().unwrap());
                let service = crate::LightClientRpc::with_state(
                    LocalLightClient::new(
                        database.clone(),
                        index.clone(),
                        mempool.clone(),
                        indexer.clone(),
                        consensus_info.clone(),
                    ),
                    events,
                    crate::LightClientRpcState::default(),
                );
                rpc.spawn(serve_light_client(listener, service));

                validators.push(Validator {
                    database,
                    index,
                    indexer,
                    mempool,
                    task,
                    light_client_url,
                    chain_sync,
                });
            }

            let mut devnet = Self {
                validators,
                fixture,
                document,
                consensus_info,
                genesis_payload: genesis.digest(),
                owners,
                allocations,
                full_nodes: Vec::new(),
                rpc,
                activity,
                storage,
                head: genesis,
                height: 0,
                included: BTreeSet::new(),
            };
            for ordinal in 0..full_node_count {
                let mut config = devnet.full_node_config(
                    devnet.storage.path().join(format!("full-node-{ordinal}")),
                    ordinal,
                );
                config
                    .peers
                    .extend(devnet.full_nodes.iter().map(|node| node.endpoint_addr()));
                let node = crate::node::FullNode::start(config).await.unwrap();
                devnet.full_nodes.push(node);
            }
            devnet
        })
    }

    /// The genesis document every validator started from.
    pub fn genesis(&self) -> &Genesis {
        &self.document
    }

    /// The network every signature on this chain is bound to.
    pub fn network(&self) -> hellas_kernel::NetworkId {
        TEST_NETWORK
    }

    /// The digest of the genesis block, which full nodes pin.
    pub fn genesis_payload(&self) -> Digest {
        self.genesis_payload
    }

    /// The committee and threshold identity this chain finalizes under.
    pub fn consensus_info(&self) -> &ConsensusInfo {
        &self.consensus_info
    }

    /// A verifier built from the genesis document's committee, as a
    /// client with no node provisions one.
    pub fn consensus_verifier(&self) -> ConsensusVerifier {
        match ConsensusVerifier::new(&self.consensus_info, crate::genesis_digest(&self.document)) {
            Ok(verifier) => verifier,
            Err(error) => panic!("the genesis committee verifies: {error}"),
        }
    }

    /// The genesis owners, as configured.
    pub fn owners(&self) -> &[GenesisOwner] {
        &self.owners
    }

    /// Genesis allocations in the order the chain minted them.
    pub fn allocations(&self) -> &[(SettlementKey, u64)] {
        &self.allocations
    }

    /// The file holding `owner`'s secret scalar: 32 raw bytes, which is a
    /// software passkey file for a [`OwnerKind::Passkey`] owner.
    pub fn owner_key_file(&self, owner: &GenesisOwner) -> PathBuf {
        assert!(
            self.owners.contains(owner),
            "a genesis owner of this devnet"
        );
        owner_file(self.storage.path(), owner)
    }

    /// Validator `validator`'s light-client WebSocket URL.
    pub fn light_client_url(&self, validator: usize) -> &str {
        &self.validators[validator].light_client_url
    }

    /// Every validator's light-client WebSocket URL, in committee order.
    pub fn light_client_urls(&self) -> Vec<String> {
        self.validators
            .iter()
            .map(|validator| validator.light_client_url.clone())
            .collect()
    }

    /// The light client validator `validator` serves at its URL, read in
    /// process.
    pub fn validator_light_client(&self, validator: usize) -> LocalLightClient {
        let validator = &self.validators[validator];
        LocalLightClient::new(
            validator.database.clone(),
            validator.index.clone(),
            validator.mempool.clone(),
            validator.indexer.clone(),
            self.consensus_info.clone(),
        )
    }

    /// A full-node configuration that submits through `validator` and
    /// syncs from it. The caller owns the node it starts.
    pub fn full_node_config(&self, storage_dir: PathBuf, validator: usize) -> crate::node::Config {
        let validator = &self.validators[validator];
        crate::node::Config {
            genesis: self.document.clone(),
            threshold_identity: self.consensus_info.threshold_identity.clone(),
            genesis_payload: self.genesis_payload,
            storage_dir,
            validators: vec![validator.light_client_url.clone()],
            peers: vec![validator.chain_sync.clone()],
            archive_blocks: None,
        }
    }

    /// The `node`th full node this devnet started.
    pub fn full_node(&self, node: usize) -> &crate::node::FullNode {
        &self.full_nodes[node]
    }

    /// The `node`th full node's view of the finalized tip.
    pub fn light_client(&self, node: usize) -> LocalLightClient {
        self.full_nodes[node]
            .view()
            .expect("the full node has executed the finalized tip")
            .client()
    }

    /// The height of the last sealed block.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Plays the proposer: everything every validator's mempool has taken
    /// since the last block goes into the next one, and all six execute
    /// it.
    ///
    /// This is the simulated part, and it is simulated in exactly one
    /// direction: the *ordering* is this function's, and the *execution*
    /// is each validator's own kernel. A block whose six state roots
    /// disagree is refused here rather than finalized, so nothing a test
    /// asserts can rest on one validator's private opinion of the state.
    /// Returns once every full node this devnet started has executed it.
    pub async fn seal(&mut self) -> HellasBlock {
        let mut fresh = Vec::new();
        let mut proposed = BTreeSet::new();
        for validator in &self.validators {
            for transaction in validator.mempool.test_transactions().await {
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
        let mut owner_root = None;
        let mut target = None;
        for validator in &self.validators {
            let batches = validator.database.new_batches().await;
            let batches = execute_all(
                KernelContext::with_fees(
                    TEST_NETWORK,
                    BlockHeight::new(self.height),
                    BlockHash::from_bytes(self.head.digest().0),
                    KERNEL_FEES,
                ),
                &ChainVerifier::new(),
                &fresh,
                &self.allocations,
                batches,
            )
            .await
            .expect("the block executes");
            let owners = crate::execution::owner_tree::root(&batches).await.unwrap();
            if let Some(expected) = owner_root {
                assert_eq!(owners, expected);
            }
            owner_root = Some(owners);
            let merkleized = batches.merkleize().await.expect("state merkleizes");
            let bounds = merkleized.bounds();
            let validator_target = Target {
                root: merkleized.root(),
                range: non_empty_range!(bounds.inactivity_floor, Location::new(bounds.total_size)),
            };
            if let Some(expected) = &target {
                assert_eq!(&validator_target, expected);
            }
            target = Some(validator_target);
            let validator_root = merkleized.root();
            match root {
                None => root = Some(validator_root),
                Some(agreed) => assert_eq!(
                    validator_root, agreed,
                    "every validator's own execution reaches the same state root",
                ),
            }
            validator.database.finalize(merkleized).await;
        }
        let Some(root) = root else {
            panic!("a devnet has at least one validator");
        };

        let block = HellasBlock::new(
            Context {
                round: Round::new(Epoch::zero(), View::new(self.height)),
                leader: self.fixture.leaders[0].clone(),
                parent: (self.head.context().round.view(), self.head.digest()),
            },
            self.head.digest(),
            Height::new(self.height),
            self.height,
            root,
            target.unwrap(),
            fresh,
        )
        .with_owner_root(owner_root.unwrap());
        let certificate = finalization(&self.fixture, &block);
        for validator in &self.validators {
            validator
                .indexer
                .ingest_finalized(block.clone(), certificate.clone())
                .await
                .expect("a certified block is ingested");
            assert_eq!(
                validator.index.apply_finalized(&block),
                Ok(ApplyOutcome::Applied),
            );
        }
        self.head = block.clone();
        for events in &self.activity {
            let _ = events.send(crate::ConsensusActivity::Finalization {
                proposal: crate::ProposalInfo {
                    epoch: 0,
                    view: self.height,
                    parent_view: self.height - 1,
                    parent_payload: block.parent(),
                    payload: block.digest(),
                },
                signers: vec![],
                certificate: certificate.encode().to_vec(),
            });
        }
        for node in &self.full_nodes {
            let mut progress = node.finalized();
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                while *progress.borrow_and_update() < self.height {
                    progress.changed().await.unwrap();
                }
                node.wait_ready().await.unwrap();
            })
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "full node at {:?} did not reach {}: {error}; {:?}",
                    *node.finalized().borrow(),
                    self.height,
                    node.peer_registry()
                )
            });
            assert_eq!(
                node.view()
                    .unwrap()
                    .client()
                    .get_state_root()
                    .await
                    .unwrap(),
                Some(root)
            );
        }
        block
    }

    pub async fn seal_through(&mut self, height: u64) {
        while self.height < height {
            self.seal().await;
        }
    }

    /// The coins among `candidates` that `owner` holds at the finalized
    /// tip, read from validator `node`'s executed QMDB state.
    ///
    /// QMDB has no full-object iterator, so the caller names the complete
    /// coin-id set its transaction graph can mint. Full node `node`'s
    /// owner-index projection is added to that set so an index-only extra
    /// is also caught, and the projection must then equal the coins and
    /// values actually read from QMDB.
    pub async fn coins(
        &self,
        node: usize,
        owner: SettlementKey,
        candidates: impl IntoIterator<Item = CoinId>,
    ) -> Vec<(CoinId, Coin)> {
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

        let mut ids = candidates.into_iter().collect::<BTreeSet<_>>();
        ids.extend(projected.iter().map(|(id, _)| *id));

        let reader = self.validators[node].database.read().await;
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
                Some(Object::Coin(coin)) if coin.owner == owner => executed.push((id, coin)),
                Some(Object::Coin(_)) | None => {}
                Some(object) => panic!(
                    "fixture coin id {id:?} resolved to a {} in finalized QMDB",
                    object.kind(),
                ),
            }
        }
        executed.sort_by_key(|(id, coin)| (coin.value, *id));
        assert_eq!(
            projected,
            executed
                .iter()
                .map(|(id, coin)| (*id, coin.value))
                .collect::<Vec<_>>(),
            "the owner-index projection agrees with the executed coin state",
        );
        executed
    }

    /// Stops every full node and server, then every follower indexer
    /// before the commonware runtime that owns it is dropped.
    pub async fn shutdown(mut self) {
        for node in self.full_nodes {
            node.shutdown().await.unwrap();
        }
        self.rpc.shutdown().await;
        for validator in self.validators {
            validator.task.abort();
            let _ = validator.task.await;
        }
    }
}

/// The genesis document this network is defined by: the six validators
/// and one allocation per owner. Nothing here bypasses the genesis key
/// parser.
fn genesis_document(fixture: &ConsensusFixture, owners: &[GenesisOwner]) -> Genesis {
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
        allocations: owners
            .iter()
            .map(|owner| GenesisEntry {
                address: owner.key().to_string(),
                balance: owner.balance,
            })
            .collect(),
    }
}

fn owner_file(storage: &Path, owner: &GenesisOwner) -> PathBuf {
    storage.join(format!("owner-{:02x}.key", owner.seed))
}

/// Serves one validator's light-client protocol on `listener`, without the
/// shipped server's per-address admission limits: every client in a test
/// connects from the same loopback address.
async fn serve_light_client(
    listener: tokio::net::TcpListener,
    service: crate::LightClientRpc<LocalLightClient>,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                let service = service.clone();
                connections.spawn(async move {
                    let ws = tokio_tungstenite::accept_async_with_config(
                        stream,
                        Some(hellas_wire::ws::websocket_config()),
                    )
                    .await
                    .unwrap();
                    let transport = hellas_wire::ws::accept_upgraded(ws, None).unwrap();
                    let _ = crate::server::serve_light_client_transport(transport, service).await;
                });
            },
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RemoteLightClient;
    use crate::light_client::FinalizedBlockQuery;

    /// A client with no node of its own reads each validator over its
    /// light-client URL, checks every answer against the committee the
    /// genesis document names, and gets the block a full node that
    /// executed the chain itself holds. A verifier for another committee
    /// refuses the same answers, so the agreement is the verifier's and
    /// not merely the wire's.
    #[test]
    fn a_remote_light_client_verifies_the_block_a_full_node_finalized() {
        run(|runtime| async move {
            let owner = GenesisOwner {
                kind: OwnerKind::Passkey,
                seed: 0x41,
                balance: 7,
            };
            let mut devnet = Devnet::start(
                runtime,
                DevnetConfig {
                    name: "devnet_remote",
                    owners: vec![owner],
                    full_nodes: 1,
                },
            )
            .await;
            assert_eq!(devnet.light_client_urls().len(), VALIDATORS);

            // The owner's key file is a software passkey for the funded key.
            let scalar: [u8; 32] = std::fs::read(devnet.owner_key_file(&owner))
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                SettlementKey::from(
                    hellas_kernel::SoftPasskey::from_secret_scalar(scalar)
                        .unwrap()
                        .party_key()
                ),
                owner.key(),
            );

            // A non-empty block, submitted by a client with no node.
            devnet.seal().await;
            let node_key = SettlementKey::from(native_signer(0x42).party_key());
            let (tx, delegated) = delegate_allocation(devnet.allocations(), &owner, node_key);
            let submitter = RemoteLightClient::connect(devnet.light_client_url(3))
                .await
                .unwrap();
            assert_eq!(
                submitter.submit_tx(tx).await.unwrap(),
                crate::SubmitTxOutcome::Enqueued,
            );
            let block = devnet.seal().await;
            assert_eq!(block.txs().len(), 1, "the submitted reshape is finalized");

            let full_node = devnet.light_client(0);
            let latest = full_node.get_latest_block().await.unwrap().unwrap();
            assert_eq!(latest.height, 2);
            assert_eq!(latest.payload, block.digest());
            let finalized = full_node
                .get_finalized_block(FinalizedBlockQuery::Height(2))
                .await
                .unwrap()
                .unwrap();
            for url in devnet.light_client_urls() {
                let remote = RemoteLightClient::connect(url.clone())
                    .await
                    .unwrap()
                    .with_consensus_verifier(devnet.consensus_verifier());
                assert_eq!(
                    remote.get_latest_block().await.unwrap().as_ref(),
                    Some(&latest),
                    "{url}",
                );
                assert_eq!(
                    remote
                        .get_finalized_block(FinalizedBlockQuery::Height(2))
                        .await
                        .unwrap()
                        .as_ref(),
                    Some(&finalized),
                    "{url}",
                );
                let held = remote
                    .get_coins_by_owner(owner.key())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    held.coins,
                    vec![(coin_object_id(delegated), owner.balance)],
                    "{url}",
                );

                let stranger = crate::execution::test_support::consensus_fixture_in(
                    rand::random(),
                    VALIDATORS as u64,
                    TEST_NETWORK,
                    crate::genesis_digest(devnet.genesis()),
                );
                let refused = RemoteLightClient::connect(url.clone())
                    .await
                    .unwrap()
                    .with_consensus_verifier(stranger.verifier);
                assert!(
                    refused.get_latest_block().await.is_err(),
                    "another committee's verifier refuses {url}",
                );
            }
            devnet.shutdown().await;
        });
    }
}
