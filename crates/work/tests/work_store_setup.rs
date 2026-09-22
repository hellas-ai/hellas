//! The setup journal, and the one decision that recovers a handshake.
//!
//! Every crash here is a real one: the store is dropped, its file is
//! left exactly as it was, and a new store is opened over it. What is
//! asserted is what the second process may do — never what the first
//! one meant to do.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hellas_kernel::{
    Auth, BlockHeight, CoinId, Decode as _, Edge, EdgeId, EdgeValues, Fees, Funding, Key,
    LeaseSlots, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, Move, NetworkId, Parties, Party,
    PaymentCloseStart, Payout, Proof, RegistryChunk, RegistryNamespace, RegistryRecordTag,
    Secp256k1Signer, Secp256k1Verifier, Sig, Terms, TermsHash, Tx, WorkPaymentTerms,
    WorkStakeBondTerms,
};
use hellas_rpc::pb::work::{ExchangeSetupRequest, exchange_setup_response::Outcome};
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, private_policy_commitment,
};
use hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_work::work_close::{BlockSourceError, FinalizedBlocks, FinalizedWork, TxSink};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{
    FinalizedSetup, SetupDriveError, SetupProgress, SetupQuery, SetupStep, SetupView, advance_setup,
};
use hellas_work::work_store::journal::{Journal, JournalError, JournalId, JournalKind};
use hellas_work::work_store::setup::setup_key;
use hellas_work::work_store::{
    DiscoveredSetup, ObservedSetup, Role, SetupAbort, SetupDecision, SetupDiscoveryError, SetupEnd,
    SetupFault, SetupHistoryBatch, SetupHistoryBlock, SetupRecord, SetupScan, SetupState,
    SetupStateError, SetupStore, WorkStoreError, discover_setups,
};

#[path = "support/basic.rs"]
mod basic;
use basic::{network, temp};

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const STAKE: u64 = 64;
const BOND_COIN: u8 = 0xa1;
const PAYMENT_COIN: u8 = 0xb1;
const SALT: [u8; 32] = [0x5a; 32];

fn other_network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-other") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn provider() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x22; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn client() -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([0x21; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn coin(id: u8) -> CoinId {
    CoinId::from_bytes([id; CoinId::LENGTH])
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    coins(&[])
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn bond_funding() -> Funding {
    Funding::new(coins(&[BOND_COIN]), empty_coins())
}

/// A second bond, over a coin the first one does not stake.
///
/// Two bonds is what a journal root holds: one file each, and nothing
/// outside the files says which bond either of them is about.
fn other_bond_funding() -> Funding {
    Funding::new(coins(&[BOND_COIN + 1]), empty_coins())
}

fn payment_funding() -> Funding {
    Funding::new(coins(&[PAYMENT_COIN]), empty_coins())
}

fn payment_terms(bond_edge: EdgeId) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge,
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
        // Over half of the dearest edge these fixtures meet (4,096), so the
        // bond exceeds the capacity it leaves on every one of them.
        omission_bond: 2_049,
    }
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
        generation_policy_digest: Digest::from_bytes([0x32; 32]),
        identity_source_digest: Digest::from_bytes([0x33; 32]),
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

fn provider_policy() -> ProviderChannelPolicy {
    ProviderChannelPolicy {
        network: network(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy(),
        expected_payment_values: EdgeValues::new(3_000, 200, Fees::ZERO),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    }
}

fn proposed() -> WorkChannelSetupBundleV1 {
    proposed_over(bond_funding())
}

fn proposed_over(funding: Funding) -> WorkChannelSetupBundleV1 {
    let hash = Tx::open_hash(network(), &funding, &Terms::work_stake_bond(bond_terms()));
    match WorkChannelSetupBundleV1::propose_bond(
        network(),
        funding,
        bond_terms(),
        Auth::native(provider().sign(hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    }
}

fn countersigned(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let bond_hash = bundle.bond_open_hash();
    let terms = payment_terms(bundle.bond_edge());
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(terms.clone()),
    );
    match bundle.countersign_bond_and_propose_payment(
        Auth::native(client().sign(bond_hash)),
        payment_funding(),
        terms,
        Auth::native(client().sign(payment_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}

fn completed(bundle: WorkChannelSetupBundleV1) -> WorkChannelSetupBundleV1 {
    let Some(hash) = bundle.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match bundle.countersign_payment(Auth::native(provider().sign(hash))) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

fn bundle_record(bundle: &WorkChannelSetupBundleV1) -> SetupRecord {
    SetupRecord::Bundle {
        bundle: bundle.encode(),
    }
}

fn scan() -> SetupScan {
    SetupScan {
        height: 7,
        payload: [0x47; 32],
    }
}

fn scan_record() -> SetupRecord {
    let scan = scan();
    SetupRecord::ScanArmed {
        height: scan.height,
        payload: scan.payload,
    }
}

fn armed_record(bundle: &WorkChannelSetupBundleV1) -> SetupRecord {
    let payment_edge = bundle
        .payment_edge()
        .expect("an armed revision has a payment edge");
    let terms = bundle
        .payment_terms()
        .expect("an armed revision has payment terms")
        .clone();
    let descriptor = provider_policy()
        .describe_close(payment_edge, terms)
        .expect("the fixture close descriptor opens");
    SetupRecord::ArmedBundle {
        bundle: bundle.encode(),
        close_descriptor: Box::new(descriptor),
    }
}

fn bond_edge() -> EdgeId {
    proposed().bond_edge()
}

fn payment_edge() -> EdgeId {
    let Some(edge) = countersigned(proposed()).payment_edge() else {
        panic!("a proposed payment derives its edge");
    };
    edge
}

/// The client's close Start on the payment edge, as it appears when it
/// is ordered after the Open in the very block that carried it.
fn same_block_contest() -> Tx {
    Tx::move_action(Move::StartPaymentClose(PaymentCloseStart::new(
        payment_edge(),
        Terms::work_payment(payment_terms(bond_edge())),
        Party::Maker,
        (scan().height + 2, scan().height + 9),
        None,
        Sig::from_bytes([0_u8; Sig::LENGTH]),
    )))
}

/// The file name a setup journal for one bond takes under a root.
fn journal_name(bond_edge: EdgeId) -> String {
    let key = setup_key(network(), bond_edge);
    let mut name = String::from("setup-");
    for byte in key.into_bytes() {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".0000000000000000.journal");
    name
}

fn store(root: &std::path::Path, role: Role) -> SetupStore {
    match SetupStore::open(
        root,
        network(),
        bond_edge(),
        role,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    }
}

/// A provider store that has durably retained the complete handshake.
fn completed_store(root: &std::path::Path) -> SetupStore {
    let mut store = store(root, Role::Provider);
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());
    for record in [
        scan_record(),
        bundle_record(&one),
        bundle_record(&two),
        armed_record(&three),
    ] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the fixture revision commits: {error}");
        }
    }
    store
}

/// A provider store recovered mid-handshake, holding revision 2.
///
/// The client's countersigned bond and proposed payment are journaled and
/// this endpoint has not countersigned the payment yet — so the payment
/// Open is not executable, and `funding_coins` names the bond's coin
/// alone.
fn revision_two_store(root: &std::path::Path) -> SetupStore {
    let mut store = store(root, Role::Provider);
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    for record in [scan_record(), bundle_record(&one), bundle_record(&two)] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the fixture revision commits: {error}");
        }
    }
    store
}

/// A client store that has durably retained the complete handshake.
///
/// The client arms its descriptor at revision 2 — after it has signed
/// the payment Open and before the provider countersigns it — which is
/// what makes revision 3 an import rather than a second arming.
fn client_completed_store(root: &std::path::Path) -> SetupStore {
    let mut store = store(root, Role::Client);
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());
    for record in [
        bundle_record(&one),
        scan_record(),
        armed_record(&two),
        bundle_record(&three),
    ] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the fixture revision commits: {error}");
        }
    }
    store
}

// ── Observed objects, written out ─────────────────────────────────────

const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_BOND_LEASE: u8 = 31;
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

fn edge(terms: TermsHash, maker: Key, taker: Key, allowed: u8) -> Edge {
    // 60 of capacity once the 2,049 bond is taken out.
    valued_edge(2_109, terms, maker, taker, allowed)
}

fn valued_edge(value: u64, terms: TermsHash, maker: Key, taker: Key, allowed: u8) -> Edge {
    let mut out = vec![FORMAT_VERSION, TAG_EDGE];
    out.extend_from_slice(&value.to_be_bytes()); // value
    out.extend_from_slice(&0_u64.to_be_bytes()); // reserve
    out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
    for _ in 0..4 {
        out.extend_from_slice(&0_u64.to_be_bytes());
    }
    out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
    out.extend_from_slice(&HORIZON.to_be_bytes());
    out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
    out.extend_from_slice(&maker.to_bytes());
    out.extend_from_slice(&taker.to_bytes());
    out.extend_from_slice(terms.as_bytes());
    out.push(allowed);
    match Edge::decode_exact(&out) {
        Ok(edge) => edge,
        Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
    }
}

fn bond_object() -> Edge {
    edge(
        Terms::work_stake_bond(bond_terms()).hash(),
        provider().party_key(),
        client().party_key(),
        WORK_STAKE_CLOSES,
    )
}

fn payment_object() -> Edge {
    edge(
        Terms::work_payment(payment_terms(bond_edge())).hash(),
        client().party_key(),
        provider().party_key(),
        WORK_PAYMENT_CLOSES,
    )
}

/// The payment edge as the client actually funded it: above the value
/// the provider's configuration expected.
///
/// Reachable, and not a fixture convenience. An edge's id is a hash over
/// the funding coins and the terms, never over what those coins are
/// worth, so the client that names them decides the edge's value — and
/// `provider_policy` merely expects 3,200.
fn overfunded_payment_object() -> Edge {
    valued_edge(
        4_096,
        Terms::work_payment(payment_terms(bond_edge())).hash(),
        client().party_key(),
        provider().party_key(),
        WORK_PAYMENT_CLOSES,
    )
}

/// The canonical bytes of one bond lease, written out field by field.
fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE];
    value.push(2); // body version
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(
        Terms::work_payment(payment_terms(bond_edge()))
            .hash()
            .as_bytes(),
    );
    value.extend_from_slice(&payment_terms(bond_edge()).private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());
    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    assert!(slots.iter().all(Option::is_some), "the lease splits");
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

fn faulty_lease() -> LeaseSlots {
    let Some(chunk) = RegistryChunk::split(
        RegistryNamespace::BondLease,
        RegistryRecordTag::BondLease,
        &[0xff; 8],
        0,
    ) else {
        panic!("a short value splits into one chunk");
    };
    hellas_kernel::parse_bond_lease([Some(chunk), Some(chunk)], bond_edge())
}

fn all_live() -> BTreeSet<CoinId> {
    [BOND_COIN, PAYMENT_COIN]
        .into_iter()
        .map(|id| CoinId::from_bytes([id; CoinId::LENGTH]))
        .collect()
}

fn without(coin: u8) -> BTreeSet<CoinId> {
    let mut live = all_live();
    live.remove(&CoinId::from_bytes([coin; CoinId::LENGTH]));
    live
}

struct Observed {
    height: u64,
    bond: Option<Edge>,
    payment: Option<Edge>,
    lease: LeaseSlots,
    live: BTreeSet<CoinId>,
}

impl Observed {
    /// Neither edge exists, every coin is live, and the height is well
    /// inside the horizon: the state the first submission is decided
    /// from.
    fn before_anything() -> Self {
        Self {
            height: 10,
            bond: None,
            payment: None,
            lease: LeaseSlots::Absent,
            live: all_live(),
        }
    }

    fn decide(&self, state: &SetupState) -> SetupDecision {
        state.decide(&ObservedSetup {
            height: self.height,
            bond: self.bond.as_ref(),
            payment: self.payment.as_ref(),
            lease: self.lease,
            live_funding: &self.live,
        })
    }
}

/// One coherent finalized read of a channel whose bond is gone and
/// whose payment edge is still live.
///
/// The state a permissionless bond Timeout leaves behind, and the state
/// a close-only mount has to settle against. It counts its reads,
/// because "the mount consults it" is half of what these tests are
/// about.
struct SurvivingPayment {
    payment: Edge,
    height: u64,
    reads: std::sync::atomic::AtomicUsize,
}

impl SurvivingPayment {
    fn at(height: u64, payment: Edge) -> Self {
        Self {
            payment,
            height,
            reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SetupView for SurvivingPayment {
    async fn finalized_setup(
        &self,
        _query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Some(FinalizedSetup {
            height: self.height,
            bond: None,
            payment: Some(self.payment),
            lease: LeaseSlots::Absent,
            live_funding: BTreeSet::new(),
        }))
    }
}

/// One coherent finalized read of a channel whose bond, payment edge,
/// and lease are all live: the state a completed setup is decided from,
/// and the state its mount settles against.
///
/// It counts its reads for [`SurvivingPayment`]'s reason. A mount that
/// never consults the edge settled against something else.
struct LiveChannel {
    payment: Edge,
    height: u64,
    reads: std::sync::atomic::AtomicUsize,
}

impl LiveChannel {
    fn at(height: u64, payment: Edge) -> Self {
        Self {
            payment,
            height,
            reads: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn reads(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SetupView for LiveChannel {
    async fn finalized_setup(
        &self,
        _query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Some(FinalizedSetup {
            height: self.height,
            bond: Some(bond_object()),
            payment: Some(self.payment),
            lease: lease_over(bond_edge(), payment_edge()),
            live_funding: all_live(),
        }))
    }
}

/// Close-only recovery decides *what* to mount from journaled history
/// and *what it settles* from one coherent read of the surviving edge.
/// It hands nothing to consensus on either count.
struct NoSink;

impl TxSink for NoSink {
    async fn submit(&self, _tx: Tx) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        panic!("mounting a close-only channel submits nothing");
    }
}

/// A finalized history a test writes down.
struct Blocks {
    blocks: Vec<FinalizedWork>,
}

impl FinalizedBlocks for Blocks {
    async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
        Ok(self.blocks.last().map(|block| block.height))
    }

    async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
        Ok(self
            .blocks
            .iter()
            .find(|block| block.height == height)
            .cloned())
    }
}

// ── The journal ───────────────────────────────────────────────────────

/// A revision is durable before its signature is exported, and a crash
/// between the two re-exports the same artifact rather than a new one.
#[test]
fn a_retained_revision_is_re_exported_byte_for_byte() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let two = countersigned(proposed());

    // The client's process: retain revision 1, then retain revision 2 —
    // which carries its own two signatures — and crash before exporting
    // it.
    {
        let mut client_store = store(dir.path(), Role::Client);
        if let Err(error) = client_store.commit(bundle_record(&proposed()), &verifier) {
            panic!("revision 1 commits: {error}");
        }
        if let Err(error) = client_store.commit(scan_record(), &verifier) {
            panic!("the scan arm commits: {error}");
        }
        if let Err(error) = client_store.commit(armed_record(&two), &verifier) {
            panic!("revision 2 commits: {error}");
        }
    }

    let recovered = store(dir.path(), Role::Client);
    assert_eq!(recovered.state().revision(), Some(2));
    assert_eq!(
        recovered.state().bundle_bytes(),
        Some(two.encode().as_slice())
    );
    assert_eq!(recovered.len(), 3);
}

#[test]
fn applying_an_exportable_bundle_without_scan_arming_is_refused() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut provider_store = store(dir.path(), Role::Provider);
    let error = provider_store
        .commit(bundle_record(&proposed()), &verifier)
        .expect_err("revision 1 cannot become exportable before ScanArmed");
    assert!(matches!(
        error,
        WorkStoreError::Setup(SetupStateError::WrongStage { .. })
    ));
    assert!(provider_store.state().bundle_bytes().is_none());
}

#[test]
fn a_second_distinct_scan_arm_is_refused() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut provider_store = store(dir.path(), Role::Provider);
    provider_store
        .commit(scan_record(), &verifier)
        .expect("the first arm commits");
    let error = provider_store
        .commit(
            SetupRecord::ScanArmed {
                height: scan().height + 1,
                payload: [0x99; 32],
            },
            &verifier,
        )
        .expect_err("a distinct scan floor cannot replace the held one");
    assert!(matches!(
        error,
        WorkStoreError::Setup(SetupStateError::WrongStage { .. })
    ));
    assert_eq!(provider_store.state().scan_armed(), Some(scan()));
}

/// The three revisions go in order, and nothing else does.
#[test]
fn revisions_extend_and_never_rewind() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    // Revision 2 without revision 1 is not a conversation this endpoint
    // took part in.
    let mut skipping = store(dir.path(), Role::Provider);
    let error = skipping
        .commit(bundle_record(&two), &verifier)
        .expect_err("a first record must be revision 1");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );
    assert!(skipping.is_empty(), "a refused record writes nothing");
    drop(skipping);

    let mut ordered = store(dir.path(), Role::Provider);
    for record in [
        scan_record(),
        bundle_record(&one),
        bundle_record(&two),
        armed_record(&three),
    ] {
        if let Err(error) = ordered.commit(record, &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    assert_eq!(ordered.state().revision(), Some(3));

    // A replayed stale revision.
    let error = ordered
        .commit(bundle_record(&two), &verifier)
        .expect_err("revision 2 does not follow revision 3");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert_eq!(ordered.state().revision(), Some(3));
    assert_eq!(ordered.len(), 4);
}

/// A revision whose signatures do not check never reaches the file —
/// and could not be read back out of one.
#[test]
fn an_unverified_revision_is_not_journaled() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();

    // The client signs the bond where the provider must: the same
    // bytes, the wrong party.
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(client().sign(hash)),
    ) else {
        panic!("the bundle assembles");
    };

    let mut journal = store(dir.path(), Role::Provider);
    let error = journal
        .commit(bundle_record(&forged), &verifier)
        .expect_err("the provider did not sign this");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert!(journal.is_empty());
}

/// The bundle decoder is exact, so bytes with anything after a whole
/// revision are not a revision.
#[test]
fn a_noncanonical_revision_is_refused() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut bytes = proposed().encode();
    bytes.push(0);
    let mut journal = store(dir.path(), Role::Provider);
    let error = journal
        .commit(SetupRecord::Bundle { bundle: bytes }, &verifier)
        .expect_err("a trailing byte is not canonical");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
}

/// The journal is keyed to one network and one bond. Reopening it as
/// another channel's fails closed rather than replaying as empty.
#[test]
fn a_journal_belongs_to_one_network_and_one_bond() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));

    for (label, network, bond) in [
        ("another network", other_network(), bond_edge()),
        (
            "another bond",
            network(),
            EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
        ),
    ] {
        // A different key is a different file name, so this is a fresh
        // empty journal rather than this one misread — which is the
        // point: no state crosses over.
        let Ok(other) = SetupStore::open(dir.path(), network, bond, Role::Provider, &verifier)
        else {
            panic!("a fresh journal opens");
        };
        assert!(
            other.state().revision().is_none(),
            "{label} shares no state with this channel"
        );
    }

    // And this channel's own file, moved to where another channel's
    // journal would be found. The name is not the binding: the header
    // inside is, and it does not describe that channel.
    let elsewhere = EdgeId::from_bytes([0x99; EdgeId::LENGTH]);
    let theirs = journal_path(dir.path(), network(), elsewhere);
    if let Err(error) = std::fs::copy(journal_path(dir.path(), network(), bond_edge()), &theirs) {
        panic!("the copy succeeds: {error}");
    }
    let error = SetupStore::open(dir.path(), network(), elsewhere, Role::Provider, &verifier)
        .expect_err("this file is not that channel's journal");
    assert!(
        matches!(
            error,
            WorkStoreError::Journal(JournalError::HeaderMismatch { .. })
        ),
        "unexpected error: {error}"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Two processes over one journal: the second fails before it can act.
#[test]
fn a_second_holder_is_refused() {
    let dir = temp();
    let held = store(dir.path(), Role::Provider);
    let verifier = Secp256k1Verifier::new();
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    )
    .expect_err("the journal is already held");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Locked { .. })),
        "unexpected error: {error}"
    );
    drop(held);
    assert!(
        SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &verifier
        )
        .is_ok(),
        "the lock is released with the store"
    );
}

/// A frame interrupted mid-write is the state before it; a frame that
/// is whole and does not verify is not a state at all.
#[test]
fn a_torn_tail_recovers_and_a_corrupt_frame_does_not() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };

    // Interrupted inside the last frame: the caller was never told the
    // write happened, so the state is the one before it.
    for cut in [1_usize, 8, 64] {
        let truncated = whole.len().saturating_sub(cut);
        if let Err(error) = std::fs::write(&path, &whole[..truncated]) {
            panic!("the truncated journal writes: {error}");
        }
        let recovered = match SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("a torn tail recovers: {error}"),
        };
        assert_eq!(
            recovered.state().revision(),
            Some(2),
            "the interrupted third revision is not state"
        );
    }

    // A byte changed inside a frame that is all there — the last one,
    // or one with two more written after it. Both are long enough to
    // have been complete appends, so both are records this endpoint may
    // have been told it had written, and neither is read back as an
    // earlier state.
    for (label, at) in [
        ("the last frame", whole.len().saturating_sub(64)),
        ("a frame with two after it", header_len() + 8),
    ] {
        let mut corrupt = whole.clone();
        if let Some(byte) = corrupt.get_mut(at) {
            *byte ^= 0xff;
        }
        if let Err(error) = std::fs::write(&path, &corrupt) {
            panic!("case {label}: the corrupt journal writes: {error}");
        }
        let error = SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &verifier,
        )
        .expect_err("a whole frame that does not verify is refused");
        assert!(
            matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
            "case {label}: unexpected error: {error}"
        );
    }
}

/// The file one setup journal is kept in, derived the way the store
/// derives it rather than by looking for whatever is in the directory.
fn journal_path(root: &std::path::Path, network: NetworkId, bond: EdgeId) -> std::path::PathBuf {
    root.join(format!(
        "setup-{}.0000000000000000.journal",
        hex(&setup_key(network, bond).into_bytes())
    ))
}

// ── What a root holds ─────────────────────────────────────────────────

/// A restarted node opens every journal under its root, and the file
/// alone tells it which bond and which side each one is.
///
/// The two values asserted are `SetupStore::open`'s two keys, and
/// neither is anywhere but in the journals: the second process below is
/// given the root, the network and nothing else. So the reopened
/// revisions are what proves the recovery — a wrong bond edge names a
/// file that is not there and replays as empty, and a wrong role is a
/// header the journal refuses.
#[test]
fn a_restart_finds_every_journal_its_root_holds() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let staked = proposed();
    let funded = proposed_over(other_bond_funding());
    assert_ne!(staked.bond_edge(), funded.bond_edge());

    // One bond this node stakes as the provider, one it funds as the
    // client, both under the one root.
    {
        let mut provider_store = store(dir.path(), Role::Provider);
        for record in [scan_record(), bundle_record(&staked)] {
            if let Err(error) = provider_store.commit(record, &verifier) {
                panic!("the provider's revision commits: {error}");
            }
        }
        let mut client_store = match SetupStore::open(
            dir.path(),
            network(),
            funded.bond_edge(),
            Role::Client,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("the client's journal opens: {error}"),
        };
        if let Err(error) = client_store.commit(bundle_record(&funded), &verifier) {
            panic!("the client's revision commits: {error}");
        }
    }

    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("the root enumerates: {error}"),
    };

    assert!(
        found.unidentified.is_empty(),
        "every journal under the root is one this node wrote",
    );
    assert_eq!(found.setups.len(), 2);
    for (bundle, role) in [(&staked, Role::Provider), (&funded, Role::Client)] {
        let expected = DiscoveredSetup {
            bond_edge: bundle.bond_edge(),
            role,
        };
        assert!(
            found.setups.contains(&expected),
            "discovery did not recover {expected:?} from {:?}",
            found.setups,
        );
        let reopened = match SetupStore::open(
            dir.path(),
            network(),
            expected.bond_edge,
            expected.role,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("the discovered journal reopens: {error}"),
        };
        assert_eq!(reopened.role(), role);
        assert_eq!(
            reopened.state().bundle_bytes(),
            Some(bundle.encode().as_slice()),
            "the reopened journal is the one that bond's revision was written to",
        );
    }
}

/// A root holding no journals owns none, which is an answer and not a
/// failure — and so is a root the node has not created yet.
#[test]
fn a_root_holding_no_journals_yields_none() {
    let dir = temp();
    // A channel journal beside them is the other store's, and is not a
    // setup this discovery has anything to say about.
    if let Err(error) = std::fs::write(
        dir.path().join(format!(
            "channel-{}.0000000000000000.journal",
            "00".repeat(32)
        )),
        b"not this module's file",
    ) {
        panic!("the fixture file is written: {error}");
    }

    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("an empty root is not a failure: {error}"),
    };
    assert!(found.setups.is_empty());
    assert!(found.unidentified.is_empty());

    let unopened = dir.path().join("never-opened");
    let found = match discover_setups(&unopened, network()) {
        Ok(found) => found,
        Err(error) => panic!("a root that does not exist yet owns nothing: {error}"),
    };
    assert!(found.setups.is_empty());
    assert!(found.unidentified.is_empty());
}

/// A setup journal that cannot be named is reported by name, and the
/// journal beside it is still opened.
///
/// Skipping it silently is the failure this guards: a file this node
/// cannot open may be a channel it still owes a close, and nobody would
/// ever be told it was there.
#[test]
fn a_journal_that_cannot_be_identified_is_reported_by_name() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let armed = proposed_over(other_bond_funding());

    // A handshake that armed its immutable history floor and crashed
    // before its first revision: the file is this endpoint's, and the
    // bond it is keyed to is nowhere inside it.
    {
        let mut store = match SetupStore::open(
            dir.path(),
            network(),
            armed.bond_edge(),
            Role::Provider,
            &verifier,
        ) {
            Ok(store) => store,
            Err(error) => panic!("the armed journal opens: {error}"),
        };
        if let Err(error) = store.commit(scan_record(), &verifier) {
            panic!("the scan arm commits: {error}");
        }
    }
    // And a file wearing a setup journal's name that is not one.
    let counterfeit = dir.path().join(format!(
        "setup-{}.0000000000000000.journal",
        "ab".repeat(32)
    ));
    if let Err(error) = std::fs::write(&counterfeit, b"not a journal at all") {
        panic!("the fixture file is written: {error}");
    }
    // And one complete journal beside them.
    {
        let mut store = store(dir.path(), Role::Provider);
        for record in [scan_record(), bundle_record(&proposed())] {
            if let Err(error) = store.commit(record, &verifier) {
                panic!("the revision commits: {error}");
            }
        }
    }

    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("one unreadable journal does not stop the root: {error}"),
    };

    assert_eq!(
        found.setups,
        vec![DiscoveredSetup {
            bond_edge: bond_edge(),
            role: Role::Provider,
        }],
        "the journal beside the two unnameable ones is still opened",
    );
    let named: BTreeSet<_> = found
        .unidentified
        .iter()
        .map(|setup| setup.path.clone())
        .collect();
    assert_eq!(
        named,
        BTreeSet::from([
            counterfeit.clone(),
            dir.path().join(journal_name(armed.bond_edge())),
        ]),
        "both unnameable files are named",
    );
    for setup in &found.unidentified {
        if setup.path == counterfeit {
            assert!(
                matches!(setup.reason, SetupDiscoveryError::Journal(_)),
                "unexpected reason: {}",
                setup.reason,
            );
        } else {
            assert!(
                matches!(setup.reason, SetupDiscoveryError::NoRevision),
                "unexpected reason: {}",
                setup.reason,
            );
        }
    }
}

/// A journal whose only revision is another bond's is refused, not
/// believed.
///
/// The key is what ties a revision to the file it was found in:
/// `setup_key(network, bond_edge)` is the file's name and its header,
/// and a discovery that read the bond out of the records without
/// checking it would hand back an edge this journal was never opened
/// under — and the store would then open a second, empty file for it.
#[test]
fn a_revision_that_is_not_this_journals_bond_is_refused() {
    let dir = temp();
    let key = setup_key(network(), bond_edge());
    {
        let (mut journal, _) = match Journal::open(
            dir.path().join(journal_name(bond_edge())),
            JournalId {
                kind: JournalKind::Setup,
                role: Role::Provider,
                key: key.into_bytes(),
                generation: 0,
            },
        ) {
            Ok(opened) => opened,
            Err(error) => panic!("the fixture journal opens: {error}"),
        };
        if let Err(error) =
            journal.append(&bundle_record(&proposed_over(other_bond_funding())).encode())
        {
            panic!("the foreign revision appends: {error}");
        }
    }

    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("the root enumerates: {error}"),
    };

    assert!(found.setups.is_empty());
    let [unidentified] = found.unidentified.as_slice() else {
        panic!("one journal, one refusal: {:?}", found.unidentified);
    };
    assert_eq!(
        unidentified.path,
        dir.path().join(journal_name(bond_edge()))
    );
    assert!(
        matches!(unidentified.reason, SetupDiscoveryError::WrongKey),
        "unexpected reason: {}",
        unidentified.reason,
    );
}

// ── The recovery decision ─────────────────────────────────────────────

/// The first submission and every resubmission are the same decision,
/// and the payment-funding preflight is a premise of it.
#[test]
fn locking_stake_requires_every_payment_input_to_be_live() {
    let dir = temp();
    let held = completed_store(dir.path());
    let state = held.state();

    let ready = Observed::before_anything();
    assert_eq!(ready.decide(state), SetupDecision::SubmitBond);

    // MUTATION of exactly one input: a coin funding the client's
    // already-signed payment Open is spent. The provider does not lock
    // its stake, and its own funding is untouched.
    let spent_payment = Observed {
        live: without(PAYMENT_COIN),
        ..Observed::before_anything()
    };
    assert_eq!(
        spent_payment.decide(state),
        SetupDecision::Abort(SetupAbort::PaymentFundingSpent)
    );

    // The same read after the bond was already broadcast and included:
    // the decision is about the chain, not about the attempt.
    let after_broadcast = Observed {
        bond: Some(bond_object()),
        ..Observed::before_anything()
    };
    assert_eq!(after_broadcast.decide(state), SetupDecision::SubmitPayment);
}

/// Every branch of the recovery machine, each differing from the
/// submit-bond case in exactly one fact.
#[test]
fn the_recovery_decision_covers_every_finalized_shape() {
    let dir = temp();
    let held = completed_store(dir.path());
    let state = held.state();
    let bond = bond_object();
    let payment = payment_object();
    let ours = lease_over(bond_edge(), payment_edge());
    let elsewhere = lease_over(bond_edge(), EdgeId::from_bytes([0x77; EdgeId::LENGTH]));

    let cases: Vec<(&str, Observed, SetupDecision)> = vec![
        (
            "both edges and this channel's lease",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: ours,
                ..Observed::before_anything()
            },
            SetupDecision::Complete,
        ),
        (
            "a live pair leased to another channel",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: elsewhere,
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeasedElsewhere),
        ),
        (
            "a live pair with an unreadable lease",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                lease: faulty_lease(),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeaseMalformed),
        ),
        (
            "a live pair with no lease at all",
            Observed {
                bond: Some(bond),
                payment: Some(payment),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::UnexplainedState),
        ),
        (
            "a payment edge whose bond is gone",
            Observed {
                payment: Some(payment),
                ..Observed::before_anything()
            },
            SetupDecision::CloseOnly,
        ),
        (
            "a live unleased bond",
            Observed {
                bond: Some(bond),
                ..Observed::before_anything()
            },
            SetupDecision::SubmitPayment,
        ),
        (
            "a live unleased bond whose capacity funding is gone",
            Observed {
                bond: Some(bond),
                live: without(PAYMENT_COIN),
                ..Observed::before_anything()
            },
            SetupDecision::TimeoutBond,
        ),
        (
            "a live unleased bond at the horizon",
            Observed {
                bond: Some(bond),
                height: HORIZON,
                ..Observed::before_anything()
            },
            SetupDecision::TimeoutBond,
        ),
        (
            "a live bond leased to another channel",
            Observed {
                bond: Some(bond),
                lease: elsewhere,
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::LeasedElsewhere),
        ),
        (
            "nothing on chain, and the stake input spent",
            Observed {
                live: without(BOND_COIN),
                ..Observed::before_anything()
            },
            SetupDecision::Fault(SetupFault::BondFundingSpent),
        ),
        (
            "nothing on chain, past the bond open's own timeout",
            Observed {
                height: HORIZON,
                ..Observed::before_anything()
            },
            SetupDecision::Abort(SetupAbort::BondOpenExpired),
        ),
        (
            "nothing on chain, one block inside it",
            Observed {
                height: HORIZON - 1,
                ..Observed::before_anything()
            },
            SetupDecision::SubmitBond,
        ),
    ];

    for (label, observed, expected) in cases {
        assert_eq!(observed.decide(state), expected, "case: {label}");
    }
}

#[test]
fn round7_payment_live_without_bond_mounts_close() {
    let dir = temp();
    let held = completed_store(dir.path());
    let observed = Observed {
        payment: Some(payment_object()),
        ..Observed::before_anything()
    };
    assert_eq!(observed.decide(held.state()), SetupDecision::CloseOnly);
}

/// A client holds no countersigned payment Open. It never decides to
/// submit or to time anything out, whatever the chain looks like.
#[test]
fn a_client_never_submits_the_providers_transactions() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut client_store = store(dir.path(), Role::Client);
    let one = proposed();
    let two = countersigned(one.clone());
    for record in [bundle_record(&one), scan_record(), armed_record(&two)] {
        if let Err(error) = client_store.commit(record, &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    let state = client_store.state();

    assert_eq!(
        Observed::before_anything().decide(state),
        SetupDecision::AwaitingCounterparty
    );
    assert_eq!(
        Observed {
            bond: Some(bond_object()),
            ..Observed::before_anything()
        }
        .decide(state),
        SetupDecision::AwaitingCounterparty
    );
    // What it can still see is that the channel is finished.
    assert_eq!(
        Observed {
            bond: Some(bond_object()),
            payment: Some(payment_object()),
            lease: lease_over(bond_edge(), payment_edge()),
            ..Observed::before_anything()
        }
        .decide(state),
        SetupDecision::Complete
    );
}

/// Revision 1 alone says nothing about the chain: there is no payment
/// edge to look for yet.
#[test]
fn a_proposal_alone_decides_nothing() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(scan_record(), &verifier) {
        panic!("the scan arm commits: {error}");
    }
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier) {
        panic!("revision 1 commits: {error}");
    }
    assert_eq!(
        Observed::before_anything().decide(journal.state()),
        SetupDecision::AwaitingCounterparty
    );
}

/// The broadcast journal precedes the broadcast, and a step that has no
/// executable transaction behind it is not recorded.
#[test]
fn submission_markers_follow_the_transactions_they_are_about() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(scan_record(), &verifier) {
        panic!("the scan arm commits: {error}");
    }
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier) {
        panic!("revision 1 commits: {error}");
    }

    // No countersigned bond exists yet, so there is nothing to have
    // broadcast.
    let error = journal
        .commit(SetupRecord::BondSubmitted, &verifier)
        .expect_err("revision 1 holds no executable transaction");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );

    let two = countersigned(proposed());
    let three = completed(two.clone());
    for record in [bundle_record(&two), armed_record(&three)] {
        if let Err(error) = journal.commit(record, &verifier) {
            panic!("the revision commits: {error}");
        }
    }

    // The payment is not broadcast before the bond it needs.
    let error = journal
        .commit(SetupRecord::PaymentSubmitted, &verifier)
        .expect_err("the bond goes first");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );

    for record in [SetupRecord::BondSubmitted, SetupRecord::PaymentSubmitted] {
        if let Err(error) = journal.commit(record, &verifier) {
            panic!("the marker commits: {error}");
        }
    }
    assert!(journal.state().bond_submitted());
    assert!(journal.state().payment_submitted());

    // A marker already held is not written twice.
    let before = journal.len();
    if let Err(error) = journal.commit(SetupRecord::BondSubmitted, &verifier) {
        panic!("an idempotent marker commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // A client cannot record having broadcast what it does not hold.
    let other = temp();
    let mut client_store = store(other.path(), Role::Client);
    for record in [
        bundle_record(&proposed()),
        scan_record(),
        armed_record(&two),
        bundle_record(&three),
    ] {
        if let Err(error) = client_store.commit(record, &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    let error = client_store
        .commit(SetupRecord::BondSubmitted, &verifier)
        .expect_err("a client does not broadcast the bond");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongRole { .. })
        ),
        "unexpected error: {error}"
    );
}

/// Completion carries the watcher's starting cursor, and setup ends
/// once.
#[test]
fn completion_records_the_channels_origin_and_is_terminal() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    // The payment edge is the retained bundle's, never a supplied one.
    let error = journal
        .commit(
            SetupRecord::Complete {
                payment_edge: EdgeId::from_bytes([0x66; EdgeId::LENGTH]),
                origin_height: 44,
                origin_payload: [0x01; 32],
                origin_parent: [0x02; 32],
            },
            &verifier,
        )
        .expect_err("another edge is not this channel's");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongPaymentEdge { .. })
        ),
        "unexpected error: {error}"
    );

    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
        origin_parent: [0x02; 32],
    };
    if let Err(error) = journal.commit(complete.clone(), &verifier) {
        panic!("completion commits: {error}");
    }
    let Some(origin) = journal.state().origin() else {
        panic!("completion records an origin");
    };
    assert_eq!(origin.height, 44);
    assert_eq!(origin.parent, [0x02; 32]);
    assert_eq!(journal.state().end(), Some(SetupEnd::Complete));

    // Recording it again is the same fact.
    let before = journal.len();
    if let Err(error) = journal.commit(complete, &verifier) {
        panic!("an idempotent completion commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // Ending an ended setup is not.
    let error = journal
        .commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::BondOpenExpired),
            },
            &verifier,
        )
        .expect_err("setup ended already");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Ended(_))),
        "unexpected error: {error}"
    );

    // And a completed setup decides completion, whatever it is shown.
    assert_eq!(
        Observed::before_anything().decide(journal.state()),
        SetupDecision::Complete
    );
}

/// An ended setup stays ended across a restart, and never resubmits.
#[test]
fn an_aborted_setup_does_not_come_back() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    {
        let mut journal = completed_store(dir.path());
        if let Err(error) = journal.commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::BondOpenExpired),
            },
            &verifier,
        ) {
            panic!("the abort commits: {error}");
        }
    }
    let recovered = store(dir.path(), Role::Provider);
    assert_eq!(
        recovered.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondOpenExpired))
    );
    assert_eq!(
        Observed::before_anything().decide(recovered.state()),
        SetupDecision::Abort(SetupAbort::BondOpenExpired),
        "a state that stopped is not resubmitted because the coins are live"
    );
}

/// A crash before the bond is broadcast, with a payment input spent in
/// the meantime: recovery aborts, and the provider's funding is never
/// named by a transaction it would send.
#[test]
fn a_crash_before_broadcast_recovers_into_the_preflight() {
    let dir = temp();
    drop(completed_store(dir.path()));

    let recovered = store(dir.path(), Role::Provider);
    let observed = Observed {
        live: without(PAYMENT_COIN),
        ..Observed::before_anything()
    };
    assert_eq!(
        observed.decide(recovered.state()),
        SetupDecision::Abort(SetupAbort::PaymentFundingSpent)
    );
    assert!(
        !recovered.state().bond_submitted(),
        "nothing was broadcast, so nothing spent the stake input"
    );
}

/// The coins the caller must read liveness for are the ones the
/// retained transactions actually spend.
#[test]
fn the_funding_coins_come_from_the_retained_transactions() {
    let dir = temp();
    let journal = completed_store(dir.path());
    assert_eq!(journal.state().funding_coins(), all_live());
    assert_eq!(journal.state().horizon(), Some(HORIZON));
    assert_eq!(journal.state().payment_edge(), Some(payment_edge()));
    assert_eq!(journal.state().bond_edge(), bond_edge());
}

/// The record codec is exact: an unknown tag, a short body, and a
/// trailing byte are all refused.
#[test]
fn the_record_codec_is_exact() {
    let scan_arm = scan_record();
    let scan_bytes = scan_arm.encode();
    assert_eq!(SetupRecord::decode(&scan_bytes), Ok(scan_arm));

    let armed = armed_record(&countersigned(proposed()));
    let armed_bytes = armed.encode();
    assert_eq!(SetupRecord::decode(&armed_bytes), Ok(armed));
    assert_eq!(
        SetupRecord::decode(&armed_bytes[..armed_bytes.len() - 1]),
        Err(SetupStateError::Malformed),
    );

    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
        origin_parent: [0x02; 32],
    };
    let bytes = complete.encode();
    // tag || edge || height || payload || parent
    assert_eq!(bytes.len(), 1 + 32 + 8 + 32 + 32);
    assert_eq!(SetupRecord::decode(&bytes), Ok(complete));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SetupRecord::decode(&trailing),
        Err(SetupStateError::Malformed)
    );
    assert_eq!(
        SetupRecord::decode(&bytes[..bytes.len() - 1]),
        Err(SetupStateError::Malformed)
    );
    assert_eq!(SetupRecord::decode(&[9]), Err(SetupStateError::Malformed));
    assert_eq!(SetupRecord::decode(&[]), Err(SetupStateError::Malformed));

    // The fields are in the order the encoder writes them: swapping the
    // two 32-byte block digests is a different record, and only a
    // reader that agrees with the layout can see it.
    let Ok(SetupRecord::Complete {
        origin_payload,
        origin_parent,
        ..
    }) = SetupRecord::decode(&bytes)
    else {
        panic!("the record decodes");
    };
    assert_eq!(origin_payload, [0x01; 32]);
    assert_eq!(origin_parent, [0x02; 32]);

    let history = SetupRecord::SetupHistoryBatch(SetupHistoryBatch {
        blocks: vec![SetupHistoryBlock {
            height: scan().height + 1,
            parent: scan().payload,
            payload: [0x48; 32],
            txs: vec![
                completed(countersigned(proposed()))
                    .payment_open()
                    .expect("an executable payment Open"),
            ],
        }],
    });
    assert_eq!(SetupRecord::decode(&history.encode()), Ok(history));
}

#[test]
fn setup_history_replay_checks_first_and_internal_links_atomically() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());
    let before = journal.len();
    let error = journal
        .commit(
            SetupRecord::SetupHistoryBatch(SetupHistoryBatch {
                blocks: vec![
                    SetupHistoryBlock {
                        height: scan().height + 1,
                        parent: [0xff; 32],
                        payload: [0x48; 32],
                        txs: Vec::new(),
                    },
                    SetupHistoryBlock {
                        height: scan().height + 2,
                        parent: [0xee; 32],
                        payload: [0x49; 32],
                        txs: Vec::new(),
                    },
                ],
            }),
            &verifier,
        )
        .expect_err("a batch not extending ScanArmed is refused as one transition");
    assert!(matches!(
        error,
        WorkStoreError::Setup(SetupStateError::Malformed)
    ));
    assert_eq!(journal.len(), before);
    assert_eq!(journal.state().history_cursor(), Some(scan()));
}

/// Every signature-bearing setup export leaves enough state to recover the
/// portable Open and, once payment is funded, mount close-only settlement
/// without operator configuration.
#[test]
fn round4_exported_authorization_recovers() {
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    // Crash after provider revision 1 export.
    let provider_one = temp();
    {
        let mut journal = store(provider_one.path(), Role::Provider);
        for record in [scan_record(), bundle_record(&one)] {
            if let Err(error) = journal.commit(record, &verifier) {
                panic!("provider revision 1 arms before export: {error}");
            }
        }
    }
    let recovered_one = store(provider_one.path(), Role::Provider);
    assert_eq!(recovered_one.state().scan_armed(), Some(scan()));
    assert_eq!(
        recovered_one.state().bundle_bytes(),
        Some(one.encode().as_slice())
    );
    drop(recovered_one);

    // Crash after client revision 2 export. The countersigned bond is a
    // portable executable Open, and the same record retains the close
    // descriptor before those bytes can leave.
    let client_two = temp();
    {
        let mut journal = store(client_two.path(), Role::Client);
        for record in [bundle_record(&one), scan_record(), armed_record(&two)] {
            if let Err(error) = journal.commit(record, &verifier) {
                panic!("client revision 2 arms before export: {error}");
            }
        }
    }
    let recovered_two = store(client_two.path(), Role::Client);
    assert!(recovered_two.state().bond_open().is_some());
    assert!(recovered_two.state().close_descriptor().is_some());
    drop(recovered_two);

    // Crash after provider revision 3 export. A counterparty may now submit
    // either executable Open; recovery still derives the funded settlement
    // from the observed edge rather than from the lost configuration.
    let provider_three = temp();
    {
        let mut journal = store(provider_three.path(), Role::Provider);
        for record in [
            scan_record(),
            bundle_record(&one),
            bundle_record(&two),
            armed_record(&three),
        ] {
            if let Err(error) = journal.commit(record, &verifier) {
                panic!("provider revision 3 arms before export: {error}");
            }
        }
    }
    let recovered_three = store(provider_three.path(), Role::Provider);
    assert!(recovered_three.state().bond_open().is_some());
    assert!(recovered_three.state().payment_open().is_some());
    let descriptor = recovered_three
        .state()
        .close_descriptor()
        .expect("revision 3 retained its close descriptor");
    let settlement = descriptor
        .funded_settlement(&payment_object())
        .expect("funded recovery derives settlement from the edge");
    assert_eq!(settlement.capacity(), 60);
}

/// A marker-before-broadcast crash cannot be turned into an early terminal
/// setup record: the portable Open may still finalize after the snapshot that
/// suggested abort or fault.
#[test]
fn round6_submitted_open_delays_end() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());
    if let Err(error) = journal.commit(SetupRecord::BondSubmitted, &verifier) {
        panic!("the bond submission arms its unresolved Open: {error}");
    }
    for outcome in [
        SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
        SetupEnd::Faulted(SetupFault::BondFundingSpent),
    ] {
        let error = journal
            .commit(SetupRecord::Ended { outcome }, &verifier)
            .expect_err("an in-flight Open prevents setup end");
        assert!(
            matches!(
                error,
                WorkStoreError::Setup(SetupStateError::SubmittedOpenUnresolved)
            ),
            "unexpected error: {error}",
        );
        assert_eq!(journal.state().end(), None);
    }

    let bond_open = journal
        .state()
        .bond_open()
        .expect("the retained submitted Open");
    if let Err(error) = journal.commit(
        SetupRecord::SetupHistoryBatch(SetupHistoryBatch {
            blocks: vec![
                SetupHistoryBlock {
                    height: scan().height + 1,
                    parent: scan().payload,
                    payload: [0x48; 32],
                    txs: Vec::new(),
                },
                SetupHistoryBlock {
                    height: scan().height + 2,
                    parent: [0x48; 32],
                    payload: [0x49; 32],
                    txs: vec![bond_open],
                },
            ],
        }),
        &verifier,
    ) {
        panic!("contiguous history finalizes the retained Open: {error}");
    }
    assert!(
        !journal.state().bond_submitted(),
        "the finalized Open discharges its submission obligation",
    );
    if let Err(error) = journal.commit(
        SetupRecord::Ended {
            outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
        },
        &verifier,
    ) {
        panic!("history resolution permits the end: {error}");
    }
    drop(journal);
    assert_eq!(
        store(dir.path(), Role::Provider).state().end(),
        Some(SetupEnd::Aborted(SetupAbort::PaymentFundingSpent)),
    );
}

/// A provider's own finalized bond Timeout ends the setup cleanly, not
/// in the fault the spent stake would otherwise be read as.
///
/// The provider submits the bond and then the deterministic Timeout.
/// While that Timeout is only submitted, the absent bond over a spent
/// stake is its own reclaim in flight and no fault is decided. Once
/// contiguous history holds the bond Open and the Close that spent it,
/// the same read is a clean reclaim — the stake came back — and the end
/// is `Abort(BondReclaimed)`, which a genuinely unexplained spend
/// (`the_recovery_decision_covers_every_finalized_shape`) still is not.
#[test]
fn a_finalized_bond_timeout_reclaims_the_stake_cleanly() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());
    for record in [
        SetupRecord::BondSubmitted,
        SetupRecord::BondTimeoutSubmitted,
    ] {
        if let Err(error) = journal.commit(record, &verifier) {
            panic!("the provider arms and times out its bond: {error}");
        }
    }

    let spent_stake = || Observed {
        live: without(BOND_COIN),
        ..Observed::before_anything()
    };

    // The Timeout is submitted but its Close is not yet in history: this
    // endpoint's own reclaim is in flight, so it waits rather than
    // journaling a theft it caused.
    assert_eq!(
        spent_stake().decide(journal.state()),
        SetupDecision::AwaitingCounterparty,
        "a submitted timeout waits for its finalized close",
    );

    // History finalizes the bond Open and the deterministic Timeout Close
    // that consumed it.
    let bond_open = journal.state().bond_open().expect("the retained bond Open");
    let bond_close = Tx::timeout_close(bond_edge(), &Terms::work_stake_bond(bond_terms()))
        .expect("the bond has a deterministic timeout close");
    if let Err(error) = journal.commit(
        SetupRecord::SetupHistoryBatch(SetupHistoryBatch {
            blocks: vec![
                SetupHistoryBlock {
                    height: scan().height + 1,
                    parent: scan().payload,
                    payload: [0x51; 32],
                    txs: vec![bond_open],
                },
                SetupHistoryBlock {
                    height: scan().height + 2,
                    parent: [0x51; 32],
                    payload: [0x52; 32],
                    txs: vec![bond_close],
                },
            ],
        }),
        &verifier,
    ) {
        panic!("history finalizes the bond and its timeout close: {error}");
    }

    // The absent bond over spent stake is now explained by this
    // endpoint's own finalized reclaim.
    assert_eq!(
        spent_stake().decide(journal.state()),
        SetupDecision::Abort(SetupAbort::BondReclaimed),
        "the finalized timeout close ends the setup cleanly",
    );

    // And that clean end journals where a fault could not have.
    if let Err(error) = journal.commit(
        SetupRecord::Ended {
            outcome: SetupEnd::Aborted(SetupAbort::BondReclaimed),
        },
        &verifier,
    ) {
        panic!("the reclaim end journals: {error}");
    }
    drop(journal);
    assert_eq!(
        store(dir.path(), Role::Provider).state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondReclaimed)),
    );
}

#[tokio::test]
async fn setup_completes_without_waiting_for_a_quiet_chain() {
    struct AdvancingBlocks {
        history: Blocks,
        reads: AtomicUsize,
    }
    impl FinalizedBlocks for AdvancingBlocks {
        async fn latest_height(&self) -> Result<Option<u64>, BlockSourceError> {
            let offset = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(Some(scan().height + offset as u64))
        }

        async fn block_at(&self, height: u64) -> Result<Option<FinalizedWork>, BlockSourceError> {
            self.history.block_at(height).await
        }
    }

    let dir = temp();
    let mut journal = completed_store(dir.path());
    let payment_open = completed(countersigned(proposed()))
        .payment_open()
        .expect("the signed payment Open");
    let blocks = AdvancingBlocks {
        history: Blocks {
            blocks: vec![
                FinalizedWork {
                    height: scan().height + 1,
                    parent: scan().payload,
                    payload: [0xa1; 32],
                    txs: vec![payment_open],
                },
                FinalizedWork {
                    height: scan().height + 2,
                    parent: [0xa1; 32],
                    payload: [0xa2; 32],
                    txs: vec![],
                },
            ],
        },
        reads: AtomicUsize::new(0),
    };
    let view = LiveChannel::at(scan().height + 1, payment_object());
    let advance = advance_setup(
        &view,
        &blocks,
        &NoSink,
        &mut journal,
        &Secp256k1Verifier::new(),
    )
    .await
    .expect("a moving tip does not postpone the setup decision");
    assert!(matches!(advance.progress, SetupProgress::Complete(_)));
    assert!(advance.mounted.is_some());
    assert!(blocks.reads.load(Ordering::SeqCst) > 1);
}

/// A completed setup hands back the channel it mounted, opened at the
/// origin it recorded and settled against the edge it read.
///
/// The completion is where a caller would otherwise start re-deriving:
/// it would take the origin, reach into `close_descriptor()`, pick a
/// settlement, open a store, and replay history — four decisions the
/// library already made. Two of them are visible here. The client funded
/// 4,096 where the provider's configuration expected 1,200, and a close
/// built on the expectation is one consensus refuses; and the contest
/// ordered after the Open in the origin block is one only a replay of
/// that block sees, because the mount's cursor already sits on it.
#[tokio::test]
async fn a_completed_setup_hands_back_the_channel_it_mounted() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    let bundle = completed(countersigned(proposed()));
    let payment_open = bundle.payment_open().expect("the executable payment Open");
    let origin_payload = [0xa1; 32];
    let blocks = Blocks {
        blocks: vec![FinalizedWork {
            height: scan().height + 1,
            parent: scan().payload,
            payload: origin_payload,
            txs: vec![payment_open, same_block_contest()],
        }],
    };
    let view = LiveChannel::at(scan().height + 1, overfunded_payment_object());

    let advance = match advance_setup(&view, &blocks, &NoSink, &mut journal, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("a live leased pair completes: {error}"),
    };
    let SetupProgress::Complete(origin) = advance.progress else {
        panic!("a live leased pair completes: {:?}", advance.progress);
    };
    assert_eq!(
        origin.height,
        scan().height + 1,
        "the origin is the block the payment Open landed in",
    );
    assert_eq!(journal.state().end(), Some(SetupEnd::Complete));

    let mounted = advance
        .mounted
        .expect("completion hands back the channel it opened");
    assert_eq!(
        mounted.state().cursor(),
        (origin.height, origin_payload),
        "the channel was opened at the origin the completion recorded",
    );
    assert_eq!(
        mounted.state().settlement().adjudicated_total(),
        4_096,
        "the mount settled against the edge the coherent read found",
    );
    assert_eq!(mounted.state().settlement().capacity(), 2_047);
    assert!(
        mounted.state().close_opened().is_some(),
        "and the origin block's own contest is journaled on the channel handed back",
    );
    let expected = journal
        .state()
        .close_descriptor()
        .expect("the armed close descriptor")
        .expected_settlement()
        .expect("the configured expectation settles");
    assert_eq!(
        expected.adjudicated_total(),
        3_200,
        "and the expectation a re-deriving caller would have reached is another number",
    );
}

/// A restart over a completed setup hands the channel back too, and it
/// is the same channel.
///
/// A completed setup is terminal: the only branch a restarted process
/// reaches it by is the journal shortcut, which decides nothing and
/// records nothing. If that branch handed back only the origin, every
/// restart would be the one place a caller had to mount for itself —
/// and it would settle against the configured expectation, because the
/// funded value is the one thing the setup journal does not hold.
#[tokio::test]
async fn a_restart_over_a_completed_setup_hands_back_the_same_channel() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    let bundle = completed(countersigned(proposed()));
    let payment_open = bundle.payment_open().expect("the executable payment Open");
    let origin_payload = [0xa2; 32];
    let blocks = Blocks {
        blocks: vec![FinalizedWork {
            height: scan().height + 1,
            parent: scan().payload,
            payload: origin_payload,
            txs: vec![payment_open, same_block_contest()],
        }],
    };
    let view = LiveChannel::at(scan().height + 1, overfunded_payment_object());

    let (origin, records) = loop {
        match advance_setup(&view, &blocks, &NoSink, &mut journal, &verifier).await {
            Ok(advance) => match advance.progress {
                SetupProgress::HistoryAdvanced { .. } => continue,
                SetupProgress::Complete(origin) => {
                    let mounted = advance.mounted.expect("completion hands its channel back");
                    break (origin, mounted.len());
                }
                other => panic!("the setup completes: {other:?}"),
            },
            Err(error) => panic!("the setup completes: {error}"),
        }
    };
    // The mounted channel's journal is exclusive for as long as it
    // lives, so the restart below is a restart of both files.
    drop(journal);

    let mut restarted = store(dir.path(), Role::Provider);
    assert_eq!(restarted.state().end(), Some(SetupEnd::Complete));
    let before = view.reads();
    let advance = match advance_setup(&view, &blocks, &NoSink, &mut restarted, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("the restart answers from the journal: {error}"),
    };
    assert_eq!(
        advance.progress,
        SetupProgress::Complete(origin),
        "the restart reaches the completion by the journal, not by a second scan",
    );
    let mounted = advance
        .mounted
        .expect("the restart hands the channel back as well");
    assert_eq!(
        view.reads(),
        before + 1,
        "and it read the surviving edge to settle it",
    );
    assert_eq!(mounted.state().cursor(), (origin.height, origin_payload));
    assert_eq!(
        mounted.state().settlement().adjudicated_total(),
        4_096,
        "the restart settled at the funded edge, not at the configuration",
    );
    assert!(
        mounted.state().close_opened().is_some(),
        "the contest the first mount replayed is still on the channel it hands back",
    );
    assert_eq!(
        mounted.len(),
        records,
        "and it reopened the first mount's journal rather than writing a second one",
    );
}

/// A setup is driven while its own `WorkSetup` ALPN is answered from the
/// same journal, and the caller still mounts by receiving.
///
/// The journal is exclusive — the assertion below is that a second
/// `SetupStore::open` on this root is refused — so "drive it and serve
/// it" is not two stores, it is one store borrowed twice. A step that
/// held that borrow across its finalized read would be a provider that
/// stops answering the handshake for as long as the chain is slow; the
/// view here is stopped for the whole of the exchange, and the exchange
/// is answered with the retained revision anyway.
///
/// What comes back is unchanged: `SetupAdvance::mounted` carries the
/// channel this step opened, so a driver reachable from the service
/// mounts by receiving exactly as a caller holding the store did.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_is_driven_while_its_alpn_is_served_from_the_same_journal() {
    let dir = temp();
    let journal = completed_store(dir.path());

    // Why this has to go through the service at all: the journal is
    // held, and a runner cannot open a second one to drive from.
    match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Err(WorkStoreError::Journal(JournalError::Locked { .. })) => {}
        other => panic!("a second store over one root is refused: {other:?}"),
    }

    let three = completed(countersigned(proposed()));
    let payment_open = three.payment_open().expect("the executable payment Open");
    let origin_payload = [0xa3; 32];
    let service = SetupService::new(SetupEndpoint::new(
        journal,
        provider(),
        PaymentAdmission::Admits(Box::new(provider_policy())),
    ));
    let blocks = Arc::new(Blocks {
        blocks: vec![FinalizedWork {
            height: scan().height + 1,
            parent: scan().payload,
            payload: origin_payload,
            txs: vec![payment_open, same_block_contest()],
        }],
    });
    let released = Arc::new(AtomicBool::new(false));
    let view = Arc::new(HeldChannel {
        inner: LiveChannel::at(scan().height + 1, overfunded_payment_object()),
        reached: AtomicUsize::new(0),
        released: Arc::clone(&released),
    });

    // The completing step, stopped at its finalized read.
    let driving = tokio::spawn({
        let service = service.clone();
        let view = Arc::clone(&view);
        let blocks = Arc::clone(&blocks);
        async move {
            service
                .advance_setup(view.as_ref(), blocks.as_ref(), &NoSink)
                .await
        }
    });
    let waited = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while view.reached.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(waited.is_ok(), "the driver reached the finalized read");

    // The ALPN, answered from the same journal while that read waits.
    let answering = tokio::spawn({
        let service = service.clone();
        async move { exchange(&service, Vec::new()).await }
    });
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), answering).await;
    let Ok(Ok(offered)) = answered else {
        panic!("the WorkSetup ALPN does not queue behind the drive: {answered:?}");
    };
    assert_eq!(
        offered,
        three.encode(),
        "and it was answered with the revision the journal holds",
    );
    assert!(
        !driving.is_finished(),
        "the drive was still stopped at its finalized read while that was answered",
    );

    released.store(true, Ordering::SeqCst);
    let Ok(Ok(advance)) = driving.await else {
        panic!("the released drive completes the setup");
    };
    let SetupProgress::Complete(origin) = advance.progress else {
        panic!(
            "the released drive completes the setup: {:?}",
            advance.progress
        );
    };
    assert_eq!(origin.height, scan().height + 1);
    let mounted = advance
        .mounted
        .expect("the driven completion hands back the channel it opened");
    assert_eq!(
        mounted.state().cursor(),
        (origin.height, origin_payload),
        "the channel was opened at the origin the completion recorded",
    );
    assert_eq!(
        mounted.state().settlement().adjudicated_total(),
        4_096,
        "and settled against the edge the coherent read found",
    );
    assert!(
        mounted.state().close_opened().is_some(),
        "the origin block's own contest is journaled on the channel handed back",
    );

    // One driver: a second step while the first is live is refused
    // rather than admitted to the drive.
    let held = service.drive().expect("the setup has a driver to take");
    assert!(
        matches!(service.drive(), Err(SetupDriveError::Busy)),
        "a second driver of one setup is turned away",
    );
    drop(held);
    assert!(service.drive().is_ok(), "and the slot comes back");
}

/// A view that stops the driver where a real chain would, and counts
/// that it got there.
struct HeldChannel {
    inner: LiveChannel,
    reached: AtomicUsize,
    released: Arc<AtomicBool>,
}

impl SetupView for HeldChannel {
    async fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        self.reached.fetch_add(1, Ordering::SeqCst);
        while !self.released.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        self.inner.finalized_setup(query).await
    }
}

/// Offers one revision to a setup service through its own handler, and
/// returns the revision it answers with.
async fn exchange(service: &SetupService, bundle: Vec<u8>) -> Vec<u8> {
    let answered = WorkSetupHandler::exchange_setup(
        service,
        ExchangeSetupRequest { bundle },
        hellas_wire::TransportContext::default(),
    )
    .await
    .expect("the setup handler answers");
    let response: hellas_rpc::call::WithTrailer<_> = answered.into();
    match response.response.outcome {
        Some(Outcome::Advanced(advanced)) => advanced.bundle,
        other => panic!("expected an advanced revision, got {other:?}"),
    }
}

/// A step decides from the revision it asked the chain about, not from
/// the one the ALPN journaled while it was waiting.
///
/// The provider is recovered at revision 2, where the payment Open is
/// not yet executable and `funding_coins` therefore names the bond's
/// coin alone. The step asks the chain that question and stops there.
/// The ALPN — answered from the same journal, which is the whole reason
/// the borrow is short — countersigns the payment and journals revision
/// 3, and now the payment Open is executable and its funding coin is
/// part of the question.
///
/// Every coin is live on chain throughout. The revision-2 answer says
/// nothing about the payment coin because it was never asked, and a
/// coin that was not asked about is not a coin that was spent: deciding
/// from that answer at revision 3 aborts the setup with
/// `PaymentFundingSpent`, or times the bond out, and both are
/// permanent. So the assertion is the negative one — no end is
/// journaled — and the positive one that this step reaches the
/// submission a state it actually observed supports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_setup_decides_from_the_revision_it_asked_the_chain_about() {
    let dir = temp();
    let journal = revision_two_store(dir.path());
    let three = completed(countersigned(proposed()));
    let service = SetupService::new(SetupEndpoint::new(
        journal,
        provider(),
        PaymentAdmission::Admits(Box::new(provider_policy())),
    ));
    // Nothing of this setup is on chain yet, so there is no history to
    // catch up on and the step goes straight to its finalized read.
    let blocks = Arc::new(Blocks { blocks: Vec::new() });
    let released = Arc::new(AtomicBool::new(false));
    let view = Arc::new(HeldFunding::holding(Arc::clone(&released)));
    let sink = Arc::new(Mempool::default());

    let driving = tokio::spawn({
        let service = service.clone();
        let view = Arc::clone(&view);
        let blocks = Arc::clone(&blocks);
        let sink = Arc::clone(&sink);
        async move {
            service
                .advance_setup(view.as_ref(), blocks.as_ref(), sink.as_ref())
                .await
        }
    });
    let waited = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while view.asked().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(waited.is_ok(), "the driver reached its revision-2 read");

    // Revision 3, journaled through the ALPN while that read waits.
    let answering = tokio::spawn({
        let service = service.clone();
        async move { exchange(&service, Vec::new()).await }
    });
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), answering).await;
    let Ok(Ok(offered)) = answered else {
        panic!("the WorkSetup ALPN does not queue behind the drive: {answered:?}");
    };
    assert_eq!(
        offered,
        three.encode(),
        "the ALPN countersigned the payment and journaled revision 3",
    );
    assert!(
        !driving.is_finished(),
        "and it did that while the drive was still stopped at its revision-2 read",
    );

    released.store(true, Ordering::SeqCst);
    let Ok(Ok(advance)) = driving.await else {
        panic!("the released drive takes a step");
    };
    match advance.progress {
        SetupProgress::Submitted {
            step: SetupStep::Bond,
            ..
        } => {}
        SetupProgress::Aborted(abort) => {
            panic!("the step ended the setup from a state it never observed: {abort:?}");
        }
        SetupProgress::TimeoutBond | SetupProgress::BondTimeoutSubmitted { .. } => {
            panic!("the step took the stake back from a state it never observed");
        }
        other => panic!("the step submits the bond it can now fund: {other:?}"),
    }

    let asked = view.asked();
    assert_eq!(
        asked.len(),
        2,
        "the revision-2 answer was discarded and the read taken again",
    );
    assert!(
        !asked[0].funding.contains(&coin(PAYMENT_COIN)),
        "the first read asked only about the executable bond's funding",
    );
    assert!(
        asked[1].funding.contains(&coin(PAYMENT_COIN)),
        "and the second asked about the funding revision 3 made executable",
    );
    assert_eq!(
        sink.submitted().len(),
        1,
        "one bond Open was handed to consensus",
    );

    drop(service);
    let recovered = store(dir.path(), Role::Provider);
    assert_eq!(recovered.state().revision(), Some(3));
    assert!(
        recovered.state().end().is_none(),
        "and the journal records no end at all: {:?}",
        recovered.state().end(),
    );
}

/// A finalized read that answers exactly the query it was asked, and
/// stops the driver on the first one.
///
/// Every coin the query names is live, and nothing is spent for the
/// whole of this test — so a `live_funding` short of a setup's funding
/// can only be an answer to a query that did not ask about it.
struct HeldFunding {
    asked: std::sync::Mutex<Vec<SetupQuery>>,
    released: Arc<AtomicBool>,
}

impl HeldFunding {
    fn holding(released: Arc<AtomicBool>) -> Self {
        Self {
            asked: std::sync::Mutex::new(Vec::new()),
            released,
        }
    }

    fn asked(&self) -> Vec<SetupQuery> {
        match self.asked.lock() {
            Ok(asked) => asked.clone(),
            Err(error) => panic!("the fixture view is not poisoned: {error}"),
        }
    }
}

impl SetupView for HeldFunding {
    async fn finalized_setup(
        &self,
        query: SetupQuery,
    ) -> Result<Option<FinalizedSetup>, BlockSourceError> {
        let first = match self.asked.lock() {
            Ok(mut asked) => {
                asked.push(query.clone());
                asked.len() == 1
            }
            Err(error) => panic!("the fixture view is not poisoned: {error}"),
        };
        if first {
            while !self.released.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        }
        Ok(Some(FinalizedSetup {
            height: 10,
            bond: None,
            payment: None,
            lease: LeaseSlots::Absent,
            live_funding: query.funding,
        }))
    }
}

/// A sink that keeps what it was handed.
#[derive(Default)]
struct Mempool {
    submitted: std::sync::Mutex<Vec<Tx>>,
}

impl Mempool {
    fn submitted(&self) -> Vec<Tx> {
        match self.submitted.lock() {
            Ok(submitted) => submitted.clone(),
            Err(error) => panic!("the fixture sink is not poisoned: {error}"),
        }
    }
}

impl TxSink for Mempool {
    async fn submit(&self, tx: Tx) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        match self.submitted.lock() {
            Ok(mut submitted) => submitted.push(tx),
            Err(error) => panic!("the fixture sink is not poisoned: {error}"),
        }
        Ok(hellas_rpc::SubmitTxOutcome::Enqueued)
    }
}

/// A close ordered after the payment Open in the origin block itself is
/// seen when the channel is mounted, not lost with the block that opened
/// it.
///
/// The origin block carries the payment Open and, after it, a client's
/// `StartPaymentClose` on that very edge. A later block times the bond
/// out, which is what puts this setup on the close-only recovery path.
/// The mount opens with its cursor already on the origin block, so a
/// same-block contest is exactly the one an inclusive-observe would drop
/// — and the assertion is that the channel the caller is handed holds
/// it, without the caller having replayed anything itself.
#[tokio::test]
async fn a_mount_replays_a_same_block_contest() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    let bundle = completed(countersigned(proposed()));
    let payment_open = bundle.payment_open().expect("the executable payment Open");
    let bond_close = Tx::timeout_close(bond_edge(), &Terms::work_stake_bond(bond_terms()))
        .expect("the bond has a deterministic timeout close");

    let origin_payload = [0x71; 32];
    let blocks = Blocks {
        blocks: vec![
            FinalizedWork {
                height: scan().height + 1,
                parent: scan().payload,
                payload: origin_payload,
                txs: vec![payment_open, same_block_contest()],
            },
            FinalizedWork {
                height: scan().height + 2,
                parent: origin_payload,
                payload: [0x72; 32],
                txs: vec![bond_close],
            },
        ],
    };

    let view = SurvivingPayment::at(scan().height + 2, payment_object());
    let advance = match advance_setup(&view, &blocks, &NoSink, &mut journal, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("a bond-timed-out payment mounts close-only: {error}"),
    };
    let SetupProgress::CloseOnly { origin, settled } = advance.progress else {
        panic!(
            "a bond-timed-out payment mounts close-only: {:?}",
            advance.progress
        );
    };
    assert!(!settled, "the payment edge is contested, not closed");
    assert_eq!(
        origin.height,
        scan().height + 1,
        "the origin is the payment Open block"
    );

    // The channel handed back holds the contest: the Start ordered after
    // the Open in the origin block was replayed, not dropped with the
    // block the cursor already sat on. Nothing here re-derived it.
    let mounted = advance
        .mounted
        .expect("a close-only mount hands back the channel it opened");
    assert!(
        mounted.state().close_opened().is_some(),
        "the same-block contest is journaled on the mounted channel",
    );
}

/// A client's contiguous history crosses the bond Timeout that anyone
/// could have sent, and its cursor keeps moving.
///
/// A leased bond may be permissionlessly timed out at its horizon while
/// the payment edge survives, so every client will eventually fetch a
/// block carrying that Close. A batch is applied whole, and a client may
/// not record bond Close evidence — so a batch that carried it would be
/// refused, and refused again on every retry, with the cursor stuck
/// below the block it landed in for good. The Close is left out and the
/// header is not.
#[tokio::test]
async fn a_client_history_crosses_a_permissionless_bond_timeout() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = client_completed_store(dir.path());

    let bundle = completed(countersigned(proposed()));
    let payment_open = bundle.payment_open().expect("the executable payment Open");
    let bond_close = Tx::timeout_close(bond_edge(), &Terms::work_stake_bond(bond_terms()))
        .expect("the bond has a deterministic timeout close");

    let origin_payload = [0x81; 32];
    let timeout_payload = [0x82; 32];
    let blocks = Blocks {
        blocks: vec![
            FinalizedWork {
                height: scan().height + 1,
                parent: scan().payload,
                payload: origin_payload,
                txs: vec![payment_open],
            },
            FinalizedWork {
                height: scan().height + 2,
                parent: origin_payload,
                payload: timeout_payload,
                txs: vec![bond_close],
            },
        ],
    };
    let view = SurvivingPayment::at(scan().height + 2, payment_object());

    let advance = advance_setup(&view, &blocks, &NoSink, &mut journal, &verifier).await;
    assert_eq!(
        journal.state().history_cursor().map(|scan| scan.height),
        Some(scan().height + 2),
        "the cursor moved past the block the bond died in",
    );
    let crossed = journal
        .state()
        .history()
        .iter()
        .find(|block| block.height == scan().height + 2)
        .expect("that block's header is retained");
    assert_eq!(
        crossed.parent, origin_payload,
        "the header is what keeps the history one chain",
    );
    assert!(
        crossed.txs.is_empty(),
        "and a client records no bond Close evidence: {:?}",
        crossed.txs,
    );

    // The client is not stuck: the surviving payment edge mounts, and
    // its origin is the block its own Open landed in.
    match advance {
        Ok(advance) => match advance.progress {
            SetupProgress::CloseOnly { origin, settled } => {
                assert!(!settled, "the payment edge outlived the bond");
                assert_eq!(origin.height, scan().height + 1);
                assert!(
                    advance.mounted.is_some(),
                    "and the client is handed the channel it mounted",
                );
            }
            other => panic!("the client mounts the surviving payment edge: {other:?}"),
        },
        Err(error) => panic!("the client mounts the surviving payment edge: {error}"),
    }
}

/// A payment edge that outlived its bond settles at what it holds, not
/// at what the provider's configuration expected it to hold.
///
/// An edge's id is a hash over its funding coins and its terms, never
/// over what those coins are worth, so the client that names them
/// decides the value and an overfunded edge is this same channel. The
/// mount therefore has to read the edge, and it has to read it before it
/// fixes the number every close it builds must distribute: 4,096 is what
/// consensus will make an adjudicated close hand out, and 1,200 — the
/// configured expectation — is a close consensus refuses.
#[tokio::test]
async fn an_overfunded_close_only_channel_settles_at_the_edge_it_holds() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path());

    let bundle = completed(countersigned(proposed()));
    let payment_open = bundle.payment_open().expect("the executable payment Open");
    let bond_close = Tx::timeout_close(bond_edge(), &Terms::work_stake_bond(bond_terms()))
        .expect("the bond has a deterministic timeout close");

    let origin_payload = [0x91; 32];
    let blocks = Blocks {
        blocks: vec![
            FinalizedWork {
                height: scan().height + 1,
                parent: scan().payload,
                payload: origin_payload,
                txs: vec![payment_open],
            },
            FinalizedWork {
                height: scan().height + 2,
                parent: origin_payload,
                payload: [0x92; 32],
                txs: vec![bond_close],
            },
        ],
    };
    let view = SurvivingPayment::at(scan().height + 2, overfunded_payment_object());

    // The first mount, on the journal-only route: it still reads.
    let advance = match advance_setup(&view, &blocks, &NoSink, &mut journal, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("a bond-timed-out payment mounts close-only: {error}"),
    };
    let SetupProgress::CloseOnly { origin, settled } = advance.progress else {
        panic!(
            "a bond-timed-out payment mounts close-only: {:?}",
            advance.progress
        );
    };
    assert!(journal.state().close_only_recovery());
    assert!(!settled, "the payment edge outlived the bond");
    assert_eq!(
        view.reads(),
        1,
        "the mount settled against a coherent read of the edge",
    );

    // And what it settled against is the number consensus will make an
    // adjudicated close hand out, on the channel the caller was handed
    // rather than on one the caller built for itself.
    let mounted = advance
        .mounted
        .expect("a close-only mount hands back the channel it opened");
    assert_eq!(mounted.state().settlement().adjudicated_total(), 4_096);
    assert_eq!(mounted.state().settlement().capacity(), 2_047);
    // The channel journal is held for as long as that store lives, so
    // the restart below is a restart of both files.
    drop(mounted);

    // The restart: the same journal reopened over its own files takes
    // the same step to the same answer.
    drop(journal);
    let mut restarted = store(dir.path(), Role::Provider);
    match advance_setup(&view, &blocks, &NoSink, &mut restarted, &verifier).await {
        Ok(advance) => match advance.progress {
            SetupProgress::CloseOnly {
                origin: again,
                settled,
            } => {
                assert!(!settled);
                assert_eq!(again, origin, "the restart mounts the same channel");
                let mounted = advance
                    .mounted
                    .expect("the restart is handed the channel too");
                assert_eq!(
                    mounted.state().settlement().adjudicated_total(),
                    4_096,
                    "and it settles at the funded edge, not at the configuration",
                );
            }
            other => panic!("the restart mounts close-only: {other:?}"),
        },
        Err(error) => panic!("the restart mounts close-only: {error}"),
    }
    assert_eq!(view.reads(), 2, "and it read the edge again to do it");

    // And what both mounts settled against is what an adjudicated close
    // has to distribute. The expectation is not: a close built on it
    // would hand out 1,200 from an edge holding 4,096, and consensus
    // takes a close whose outputs sum to exactly what the edge
    // distributes or none at all.
    let descriptor = restarted
        .state()
        .close_descriptor()
        .expect("the armed close descriptor");
    let funded = descriptor
        .funded_settlement(&overfunded_payment_object())
        .expect("the surviving edge settles");
    let expected = descriptor
        .expected_settlement()
        .expect("the configured expectation settles");
    assert_eq!(funded.adjudicated_total(), 4_096);
    assert_eq!(funded.capacity(), 2_047);
    assert_eq!(
        expected.adjudicated_total(),
        3_200,
        "the expectation is a different close from the one this edge can pay",
    );
}

/// Every ending this handshake can reach survives the journal, under
/// the code it has always had.
///
/// All eight are reachable — `decide` returns each of them from the
/// chain state it observes — so none of this is a test of dead surface.
/// The codes are pinned rather than only round-tripped, because a
/// round-trip is a conversation between an encoder and a decoder that
/// renumber together, and it is the *disk* that has to agree: a store
/// that reads yesterday's `Ended` as a different ending resumes a
/// handshake that ended for another reason.
#[test]
fn every_setup_ending_round_trips_under_its_own_code() {
    // The tag `4` and the seven codes, written out here rather than
    // read from the module that assigns them.
    let endings: [(SetupEnd, u8); 8] = [
        (SetupEnd::Complete, 0),
        (SetupEnd::Aborted(SetupAbort::BondOpenExpired), 1),
        (SetupEnd::Aborted(SetupAbort::PaymentFundingSpent), 2),
        (SetupEnd::Faulted(SetupFault::BondFundingSpent), 3),
        (SetupEnd::Faulted(SetupFault::LeaseMalformed), 4),
        (SetupEnd::Faulted(SetupFault::LeasedElsewhere), 5),
        (SetupEnd::Faulted(SetupFault::UnexplainedState), 6),
        (SetupEnd::Aborted(SetupAbort::BondReclaimed), 7),
    ];
    for (outcome, code) in endings {
        let bytes = SetupRecord::Ended { outcome }.encode();
        assert_eq!(bytes, [4, code], "the bytes of {outcome:?}");
        assert_eq!(
            SetupRecord::decode(&bytes),
            Ok(SetupRecord::Ended { outcome }),
            "{outcome:?} reads back as itself"
        );
    }
    // Eight codes, and nothing beyond them is an ending.
    assert_eq!(
        SetupRecord::decode(&[4, 8]),
        Err(SetupStateError::Malformed)
    );
}

/// A frame is bound to its journal and to its position in it.
///
/// Not by the reader's care: by the digest. A frame copied to another
/// position, or lifted from another channel's journal, is not a record
/// this journal ever wrote, and replay never replays it.
///
/// What replay *does* with it depends on what is after it, and that is
/// the journal's crash rule rather than a second opinion about binding:
/// a frame nothing follows is indistinguishable from an interrupted
/// append, so it is dropped; a frame with records after it cannot be
/// one, so the file is refused.
#[test]
fn a_frame_cannot_be_moved_duplicated_or_lifted() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };

    // The undamaged file first. A store that reported a tear whatever
    // it read would satisfy every assertion below, and an operator who
    // is told this after a clean shutdown stops believing it.
    match SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    ) {
        Ok(clean) => assert!(!clean.recovered_torn_tail(), "nothing was interrupted"),
        Err(error) => panic!("the clean journal opens: {error}"),
    }

    // The last frame, appended a second time. Its digest is the one for
    // the position it came from.
    let Ok(revision_three) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    let two = completed_store_bytes();
    let last = revision_three
        .len()
        .checked_sub(two)
        .expect("the third frame is a suffix");
    let mut duplicated = whole.clone();
    duplicated.extend_from_slice(&revision_three[last..]);
    if let Err(error) = std::fs::write(&path, &duplicated) {
        panic!("the duplicated journal writes: {error}");
    }
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &verifier,
    )
    .expect_err("a frame at another position does not verify at it");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
        "a whole copied frame is not a tear: {error}"
    );

    // The same frames, under another channel's header.
    let elsewhere = EdgeId::from_bytes([0x88; EdgeId::LENGTH]);
    {
        // Create the other journal so its header exists, then graft
        // this one's frames onto it.
        let _ = store_for(dir.path(), elsewhere);
    }
    let theirs = journal_path(dir.path(), network(), elsewhere);
    let Ok(header) = std::fs::read(&theirs) else {
        panic!("the fresh journal reads");
    };
    let mut grafted = header;
    grafted.extend_from_slice(&whole[header_len()..]);
    if let Err(error) = std::fs::write(&theirs, &grafted) {
        panic!("the grafted journal writes: {error}");
    }
    let error = SetupStore::open(dir.path(), network(), elsewhere, Role::Provider, &verifier)
        .expect_err("those frames were written for another journal");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Corrupt { .. })),
        "unexpected error: {error}"
    );
}

/// How many bytes the third revision's frame occupies, measured rather
/// than assumed.
fn completed_store_bytes() -> usize {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider);
    let one = proposed();
    let two = countersigned(one.clone());
    for record in [scan_record(), bundle_record(&one), bundle_record(&two)] {
        if let Err(error) = journal.commit(record, &verifier) {
            panic!("the revision commits: {error}");
        }
    }
    drop(journal);
    let Ok(short) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    let mut journal = store(dir.path(), Role::Provider);
    if let Err(error) = journal.commit(armed_record(&completed(two)), &verifier) {
        panic!("the revision commits: {error}");
    }
    drop(journal);
    let Ok(long) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    long.len() - short.len()
}

/// The fixed header, measured the same way.
fn header_len() -> usize {
    let dir = temp();
    drop(store(dir.path(), Role::Provider));
    let Ok(bytes) = std::fs::read(journal_path(dir.path(), network(), bond_edge())) else {
        panic!("the journal reads");
    };
    bytes.len()
}

fn store_for(root: &std::path::Path, bond: EdgeId) -> SetupStore {
    match SetupStore::open(
        root,
        network(),
        bond,
        Role::Provider,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("a fresh journal opens: {error}"),
    }
}

/// After a torn tail is truncated, the next append lands where the next
/// frame's digest says it does.
#[test]
fn a_recovered_journal_can_be_written_again() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()));
    let path = journal_path(dir.path(), network(), bond_edge());
    let Ok(whole) = std::fs::read(&path) else {
        panic!("the journal reads");
    };
    if let Err(error) = std::fs::write(&path, &whole[..whole.len() - 30]) {
        panic!("the truncated journal writes: {error}");
    }

    {
        let mut recovered = store(dir.path(), Role::Provider);
        assert_eq!(recovered.state().revision(), Some(2));
        // The interrupted revision, retried.
        if let Err(error) = recovered.commit(
            armed_record(&completed(countersigned(proposed()))),
            &verifier,
        ) {
            panic!("the retried revision commits: {error}");
        }
    }

    let reopened = store(dir.path(), Role::Provider);
    assert_eq!(reopened.state().revision(), Some(3));
    assert_eq!(reopened.len(), 4);
}

/// Signatures are checked when the journal is read back, not only when
/// it is written.
///
/// Committed under a verifier that accepts anything, then reopened
/// under the real one: what was journaled is refused, rather than being
/// trusted because it is already on the disk.
#[test]
fn replay_checks_the_signatures_again() {
    let dir = temp();
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        Auth::native(client().sign(hash)),
    ) else {
        panic!("the bundle assembles");
    };
    {
        let Ok(mut credulous) = SetupStore::open(
            dir.path(),
            network(),
            bond_edge(),
            Role::Provider,
            &AcceptAll,
        ) else {
            panic!("the journal opens");
        };
        if let Err(error) = credulous.commit(scan_record(), &AcceptAll) {
            panic!("the scan arm commits: {error}");
        }
        if let Err(error) = credulous.commit(bundle_record(&forged), &AcceptAll) {
            panic!("a credulous verifier accepts it: {error}");
        }
    }
    let error = SetupStore::open(
        dir.path(),
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .expect_err("the provider never signed that");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
}

/// A verifier that accepts everything, so a test can write a journal
/// the real verifier will refuse.
struct AcceptAll;

impl hellas_kernel::SigVerifier for AcceptAll {
    fn verify_sig(
        &self,
        _sig: hellas_kernel::Sig,
        _key: Key,
        _hash: hellas_kernel::PayloadHash,
    ) -> bool {
        true
    }
}

// ── Rotation ──────────────────────────────────────────────────────────

/// A handshake still waiting on both its Opens.
///
/// The two unresolved-submission flags, the timeout marker, and one
/// history block that resolves nothing: the fields a settled fixture
/// cannot hold at the same time as its own resolutions.
fn in_flight_store(root: &std::path::Path) -> SetupStore {
    let verifier = Secp256k1Verifier::new();
    let mut store = completed_store(root);
    for record in [
        SetupRecord::BondSubmitted,
        SetupRecord::PaymentSubmitted,
        SetupRecord::BondTimeoutSubmitted,
        SetupRecord::SetupHistoryBatch(SetupHistoryBatch {
            blocks: vec![SetupHistoryBlock {
                height: scan().height + 1,
                parent: scan().payload,
                payload: [0x48; 32],
                txs: Vec::new(),
            }],
        }),
    ] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the in-flight fixture commits: {error}");
        }
    }
    store
}

/// A handshake whose history has finalized and closed both edges.
///
/// The other half of the state space: both finalization flags, both
/// close flags, the origin the payment Open fixes, and an end.
fn settled_store(root: &std::path::Path) -> SetupStore {
    let verifier = Secp256k1Verifier::new();
    let mut store = completed_store(root);
    let three = completed(countersigned(proposed()));
    let (Some(bond_open), Some(payment_open)) = (three.bond_open(), three.payment_open()) else {
        panic!("an executable revision holds both Opens");
    };
    // A work-payment edge commits no timeout payout, so the two closes
    // are built the same way rather than one of each: what the journal
    // reads off a close is its input edge, and nothing else.
    let bond = Terms::work_stake_bond(bond_terms());
    let Some(outputs) = bond.timeout_outputs().cloned() else {
        panic!("a bond commits its timeout payout");
    };
    let close_of = |edge: EdgeId| Tx::close(edge, Proof::timeout(bond.clone()), outputs.clone());
    let blocks = vec![
        SetupHistoryBlock {
            height: scan().height + 1,
            parent: scan().payload,
            payload: [0x48; 32],
            txs: vec![bond_open],
        },
        SetupHistoryBlock {
            height: scan().height + 2,
            parent: [0x48; 32],
            payload: [0x49; 32],
            txs: vec![payment_open],
        },
        SetupHistoryBlock {
            height: scan().height + 3,
            parent: [0x49; 32],
            payload: [0x4a; 32],
            txs: vec![close_of(bond_edge()), close_of(payment_edge())],
        },
    ];
    for record in [
        SetupRecord::SetupHistoryBatch(SetupHistoryBatch { blocks }),
        SetupRecord::Ended {
            outcome: SetupEnd::Aborted(SetupAbort::BondReclaimed),
        },
    ] {
        if let Err(error) = store.commit(record, &verifier) {
            panic!("the settled fixture commits: {error}");
        }
    }
    store
}

/// One named fixture: what to call it, and how to build it.
type Fixture = (&'static str, fn(&std::path::Path) -> SetupStore);

/// Every fixture a rotation is asserted over, named.
const FIXTURES: [Fixture; 2] = [("in flight", in_flight_store), ("settled", settled_store)];

/// The one journal file under a root, and the name it wears.
fn only_journal(root: &std::path::Path) -> std::path::PathBuf {
    let Ok(entries) = std::fs::read_dir(root) else {
        panic!("the root reads");
    };
    let mut found: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".journal"))
        .collect();
    found.sort();
    let [path] = found.as_slice() else {
        panic!("one installed generation, not {found:?}");
    };
    path.clone()
}

fn read(path: &std::path::Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("{} reads: {error}", path.display()),
    }
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    if let Err(error) = std::fs::write(path, bytes) {
        panic!("{} writes: {error}", path.display());
    }
}

/// What a checkpoint replays to is exactly what the frames it replaced
/// replayed to.
///
/// The comparison is of the whole [`SetupState`], not of the fields this
/// test happens to think of: a field added to that struct and left out
/// of the checkpoint fails to compile, and a field added and *encoded
/// wrongly* fails here, as long as the two fixtures above reach a value
/// for it that is not the one `SetupState::new` starts at. Both fixtures
/// are asserted to reach such a value below, so a new field is covered
/// the moment either fixture moves it.
#[test]
fn a_checkpoint_replays_to_what_the_frames_replayed_to() {
    for (label, fixture) in FIXTURES {
        let control = temp();
        let expected = fixture(control.path()).state().clone();

        let rotated = temp();
        {
            let mut store = fixture(rotated.path());
            if let Err(error) = store.rotate() {
                panic!("{label}: the rotation completes: {error}");
            }
            assert_eq!(
                store.len(),
                1,
                "{label}: a fresh successor holds its checkpoint and nothing else",
            );
        }
        let reopened = store(rotated.path(), Role::Provider);
        assert_eq!(
            reopened.state(),
            &expected,
            "{label}: the checkpoint is the state, not a summary of it",
        );
        assert!(
            !reopened.recovered_torn_tail(),
            "{label}: a rotation is not a tear",
        );
    }

    // What the two fixtures between them exercise. Asserted rather than
    // assumed, because a round trip over a state that is all defaults is
    // a round trip that proves nothing.
    let in_flight = temp();
    let in_flight = in_flight_store(in_flight.path());
    let in_flight = in_flight.state();
    assert!(in_flight.bond_submitted());
    assert!(in_flight.payment_submitted());
    assert_eq!(in_flight.revision(), Some(3));
    assert!(in_flight.close_descriptor().is_some());
    assert!(in_flight.scan_armed().is_some());
    assert_eq!(in_flight.history().len(), 1);
    assert_ne!(in_flight.history_cursor(), in_flight.scan_armed());
    assert_eq!(in_flight.end(), None);

    let settled = temp();
    let settled = settled_store(settled.path());
    let settled = settled.state();
    assert_eq!(settled.history().len(), 3);
    assert!(settled.origin().is_some());
    assert!(settled.close_only_recovery());
    assert!(!settled.submitted_open_unresolved());
    assert_eq!(
        settled.end(),
        Some(SetupEnd::Aborted(SetupAbort::BondReclaimed)),
    );
}

/// A crash at any point of the install reopens the same handshake.
///
/// The successor's bytes are the store's own, taken from a real
/// rotation; the four directories below are the four shapes the
/// documented order passes through. What each one must yield is the
/// state the predecessor had — which is what the checkpoint says, and
/// what the predecessor's frames say, because a rotation moves bytes and
/// not facts.
#[test]
fn a_rotation_crashing_at_any_step_reopens_the_same_setup() {
    for (label, fixture) in FIXTURES {
        let source = temp();
        let expected = fixture(source.path()).state().clone();
        let predecessor_name = only_journal(source.path());
        let predecessor = read(&predecessor_name);
        let Some(predecessor_name) = predecessor_name.file_name().map(std::ffi::OsStr::to_owned)
        else {
            panic!("{label}: the predecessor has a name");
        };

        let installed = temp();
        {
            let mut store = fixture(installed.path());
            if let Err(error) = store.rotate() {
                panic!("{label}: the rotation completes: {error}");
            }
        }
        let successor_name = only_journal(installed.path());
        let successor = read(&successor_name);
        let Some(successor_name) = successor_name.file_name().map(std::ffi::OsStr::to_owned) else {
            panic!("{label}: the successor has a name");
        };
        let mut candidate_name = successor_name.clone();
        candidate_name.push(".candidate");

        for step in [
            "the candidate was still being written",
            "the candidate is whole and unrenamed",
            "the rename happened and the predecessor is still there",
            "the predecessor is unlinked",
        ] {
            let dir = temp();
            match step {
                "the candidate was still being written" => {
                    write(&dir.path().join(&predecessor_name), &predecessor);
                    write(
                        &dir.path().join(&candidate_name),
                        &successor[..successor.len() / 2],
                    );
                }
                "the candidate is whole and unrenamed" => {
                    write(&dir.path().join(&predecessor_name), &predecessor);
                    write(&dir.path().join(&candidate_name), &successor);
                }
                "the rename happened and the predecessor is still there" => {
                    write(&dir.path().join(&predecessor_name), &predecessor);
                    write(&dir.path().join(&successor_name), &successor);
                }
                _ => write(&dir.path().join(&successor_name), &successor),
            }

            let reopened = store(dir.path(), Role::Provider);
            assert_eq!(
                reopened.state(),
                &expected,
                "{label}, {step}: the same handshake reopens",
            );
        }
    }
}

/// An uninstalled candidate is not read, even when it says something.
///
/// The candidate here is a real checkpoint of a real earlier state, and
/// the predecessor beside it has moved on since. A recovery that read
/// the candidate would answer with the older handshake and lose two
/// journaled submissions; a recovery that ignores it answers with the
/// file the writer was actually told about.
#[test]
fn an_uninstalled_candidate_is_never_read() {
    let verifier = Secp256k1Verifier::new();

    let earlier = temp();
    {
        let mut earlier_store = completed_store(earlier.path());
        if let Err(error) = earlier_store.rotate() {
            panic!("the rotation completes: {error}");
        }
    }
    let stale = read(&only_journal(earlier.path()));
    let Some(candidate_name) = only_journal(earlier.path())
        .file_name()
        .map(std::ffi::OsStr::to_owned)
    else {
        panic!("the successor has a name");
    };
    let mut candidate_name = candidate_name;
    candidate_name.push(".candidate");

    let dir = temp();
    let expected = {
        let mut later = completed_store(dir.path());
        for record in [SetupRecord::BondSubmitted, SetupRecord::PaymentSubmitted] {
            if let Err(error) = later.commit(record, &verifier) {
                panic!("the later submission commits: {error}");
            }
        }
        later.state().clone()
    };
    write(&dir.path().join(&candidate_name), &stale);

    let reopened = store(dir.path(), Role::Provider);
    assert_eq!(
        reopened.state(),
        &expected,
        "the predecessor is what recovery reads",
    );
    assert!(
        reopened.state().bond_submitted() && reopened.state().payment_submitted(),
        "the two submissions the stale candidate does not know about",
    );
}

/// A rotated journal is still a journal a restart can name.
///
/// Discovery reads the bond edge out of the first revision the file
/// retained — and after a rotation that revision is in the checkpoint,
/// not in a frame. A discovery that read only the frames would report
/// every long-lived setup as holding no revision, and a setup a node
/// cannot name is a close it stops answering.
#[test]
fn a_rotated_setup_is_still_discovered() {
    let dir = temp();
    {
        let mut store = settled_store(dir.path());
        if let Err(error) = store.rotate() {
            panic!("the rotation completes: {error}");
        }
    }
    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("the root enumerates: {error}"),
    };
    assert!(
        found.unidentified.is_empty(),
        "nothing is unnameable: {:?}",
        found.unidentified,
    );
    assert_eq!(
        found.setups.as_slice(),
        &[DiscoveredSetup {
            bond_edge: bond_edge(),
            role: Role::Provider,
        }],
        "one journal, one setup, whichever generation it is on",
    );
}

/// A retired generation is not a second journal.
///
/// The crash between the rename and the unlink leaves two installed
/// files for one setup. Discovery must offer the newest and not both:
/// mounting the retired one would be a node running the same close duty
/// twice, from a file it has already replaced.
#[test]
fn a_predecessor_left_by_a_crash_is_not_discovered_twice() {
    let source = temp();
    let predecessor_path = {
        let store = settled_store(source.path());
        drop(store);
        only_journal(source.path())
    };
    let predecessor = read(&predecessor_path);
    let Some(predecessor_name) = predecessor_path.file_name().map(std::ffi::OsStr::to_owned) else {
        panic!("the predecessor has a name");
    };

    let dir = temp();
    {
        let mut store = settled_store(dir.path());
        if let Err(error) = store.rotate() {
            panic!("the rotation completes: {error}");
        }
    }
    write(&dir.path().join(&predecessor_name), &predecessor);

    let found = match discover_setups(dir.path(), network()) {
        Ok(found) => found,
        Err(error) => panic!("the root enumerates: {error}"),
    };
    assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
    assert_eq!(found.setups.len(), 1, "one setup, not one per generation");
}
