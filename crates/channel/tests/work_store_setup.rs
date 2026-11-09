//! The setup journal, and the one decision that recovers a handshake.
//!
//! Every crash here is a real one: the store is dropped, its file is
//! left exactly as it was, and a new store is opened over it. What is
//! asserted is what the second process may do — never what the first
//! one meant to do.

use hellas_channel::test_support::channel::{client, network, provider};
use hellas_private::StoreLocation;
use hellas_rpc::protocol::invocation::InvocationPolicy;

use std::collections::BTreeSet;

use hellas_channel::model::bundle::WorkChannelSetupBundleV2;
use hellas_channel::model::setup::ProviderChannelPolicy;
use hellas_channel::model::work::{PaidChannelPolicyV1, private_policy_commitment};
use hellas_channel::work_close::{BlockSourceError, TxSink};
use hellas_channel::work_open::{
    FinalizedSetup, SetupProgress, SetupStep, advance_setup, setup_query,
};
use hellas_channel::work_store::journal::{Journal, JournalError, JournalId, JournalKind};
use hellas_channel::work_store::setup::setup_key;
use hellas_channel::work_store::{
    DiscoveredSetup, ObservedSetup, Role, SetupAbort, SetupDecision, SetupDiscoveryError, SetupEnd,
    SetupFault, SetupRecord, SetupState, SetupStateError, SetupStore, WorkStoreError,
    discover_setups,
};
use hellas_kernel::{
    Auth, BlockHeight, CoinId, Decode as _, Edge, EdgeId, EdgeValues, Fees, Funding, Key,
    LeaseSlots, List, MAX_PARTY_INPUTS, Move, NetworkId, Parties, Party, PartyAuth, PartyKeys,
    PaymentCloseStart, Payout, PendingSlot, RegistryChunk, RegistryNamespace, RegistryRecordTag,
    Secp256k1Verifier, Sig, Terms, TermsHash, Tx, WorkPaymentTerms, WorkStakeBondTerms,
};

mod support;
use support::temp;

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

fn coins(ids: &[u8]) -> List<CoinId, MAX_PARTY_INPUTS> {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, id) in slots.iter_mut().zip(ids) {
        *slot = CoinId::from_bytes([*id; CoinId::LENGTH]);
    }
    List::take(slots, ids.len())
}

fn empty_coins() -> List<CoinId, MAX_PARTY_INPUTS> {
    coins(&[])
}

fn bond_terms() -> WorkStakeBondTerms {
    hellas_channel::test_support::channel::bond_terms_for(
        Parties::new(
            PartyKeys::sole(provider().party_key()),
            PartyKeys::sole(client().party_key()),
        ),
        BlockHeight::new(HORIZON),
        Payout::new(provider().party_key(), STAKE),
        40,
    )
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
    hellas_channel::test_support::channel::payment_terms_for(
        bond_edge,
        bond_terms(),
        private_policy_commitment(network(), &SALT, &channel_policy()),
        hellas_kernel::MAX_START_VALIDITY_BLOCKS,
        2_049,
    )
}

fn channel_policy() -> PaidChannelPolicyV1 {
    hellas_channel::test_support::channel::credit_policy(40, 40)
}

fn work_policy() -> InvocationPolicy {
    hellas_channel::test_support::channel::work_policy()
}

fn provider_policy() -> ProviderChannelPolicy {
    ProviderChannelPolicy {
        payment_policy: payment_policy(),
        network: network(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        invocation_policy: work_policy(),
        expected_payment_values: EdgeValues::new(3_000, 200, Fees::ZERO),
    }
}

fn proposed() -> WorkChannelSetupBundleV2 {
    proposed_over(bond_funding())
}

fn proposed_over(funding: Funding) -> WorkChannelSetupBundleV2 {
    let hash = Tx::open_hash(network(), &funding, &Terms::work_stake_bond(bond_terms()));
    match WorkChannelSetupBundleV2::propose_bond(
        network(),
        funding,
        bond_terms(),
        hellas_kernel::PartyAuth::signer(Auth::native(provider().sign(hash))),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    }
}

fn countersigned(bundle: WorkChannelSetupBundleV2) -> WorkChannelSetupBundleV2 {
    let bond_hash = bundle.bond_open_hash();
    let terms = payment_terms(bundle.bond_edge());
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(terms.clone()),
    );
    match bundle.countersign_bond_and_propose_payment(
        hellas_kernel::PartyAuth::signer(Auth::native(client().sign(bond_hash))),
        payment_funding(),
        terms,
        hellas_kernel::PartyAuth::signer(Auth::native(client().sign(payment_hash))),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}

fn completed(bundle: WorkChannelSetupBundleV2) -> WorkChannelSetupBundleV2 {
    let Some(hash) = bundle.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match bundle.countersign_payment(hellas_kernel::PartyAuth::owner(Auth::native(
        provider().sign(hash),
    ))) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

fn bundle_record(bundle: &WorkChannelSetupBundleV2) -> SetupRecord {
    SetupRecord::Bundle {
        bundle: bundle.encode(),
    }
}

/// A height every fixture read is taken above.
const FLOOR: u64 = 7;

fn armed_record(bundle: &WorkChannelSetupBundleV2) -> SetupRecord {
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
        (FLOOR + 2, FLOOR + 9),
        None,
        PartyAuth::signer(Sig::from_bytes([0_u8; Sig::LENGTH])),
    )))
}

/// The file name a setup journal for one bond takes under a root.
fn journal_name(bond_edge: EdgeId) -> std::path::PathBuf {
    journal_path(std::path::Path::new(""), network(), bond_edge)
}

async fn store(root: &std::path::Path, role: Role) -> SetupStore {
    let location = StoreLocation::for_test(root);
    match SetupStore::open(
        &location,
        network(),
        bond_edge(),
        role,
        &Secp256k1Verifier::new(),
    )
    .await
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    }
}

/// A provider store that has durably retained the complete handshake.
async fn completed_store(root: &std::path::Path) -> SetupStore {
    let location = StoreLocation::for_test(root);
    completed_store_at(&location).await
}

async fn completed_store_at(location: &StoreLocation) -> SetupStore {
    let verifier = Secp256k1Verifier::new();
    let mut store = SetupStore::open(location, network(), bond_edge(), Role::Provider, &verifier)
        .await
        .unwrap();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());
    for record in [
        bundle_record(&one),
        bundle_record(&two),
        armed_record(&three),
    ] {
        if let Err(error) = store.commit(record, &verifier).await {
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
    // Each party: owner, signer, and an absent payout delegate.
    for party in [maker, taker] {
        out.extend_from_slice(&party.to_bytes());
        out.extend_from_slice(&party.to_bytes());
        out.push(0);
    }
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

/// One coherent certified read for the setup this journal holds,
/// answering exactly the question the journal asks.
fn read(
    state: &SetupState,
    height: u64,
    bond: Option<Edge>,
    payment: Option<Edge>,
    lease: LeaseSlots,
    live_funding: BTreeSet<CoinId>,
) -> FinalizedSetup {
    FinalizedSetup {
        query: setup_query(state).expect("the setup names its payment edge"),
        height,
        payload: [height as u8; 32],
        certified_at_ms: hellas_channel::test_support::channel::now_ms(),
        bond,
        payment,
        lease,
        pending: PendingSlot::Absent,
        live_funding,
    }
}

/// A live, leased channel: the state a completed setup is decided from.
fn live_channel(state: &SetupState, height: u64, payment: Edge) -> FinalizedSetup {
    read(
        state,
        height,
        Some(bond_object()),
        Some(payment),
        lease_over(bond_edge(), payment_edge()),
        all_live(),
    )
}

/// A channel whose bond is gone and whose payment edge is still live.
fn surviving_payment(state: &SetupState, height: u64, payment: Edge) -> FinalizedSetup {
    read(
        state,
        height,
        None,
        Some(payment),
        LeaseSlots::Absent,
        BTreeSet::new(),
    )
}

/// Mounting submits nothing.
struct NoSink;

impl TxSink for NoSink {
    async fn submit(&self, _tx: Tx) -> Result<hellas_rpc::SubmitTxOutcome, BlockSourceError> {
        panic!("mounting a channel submits nothing");
    }
}

/// What a certified read at `height` showing the bond, the payment edge,
/// or both live teaches this journal.
fn seen(state: &SetupState, height: u64, bond: bool, payment: bool) -> SetupRecord {
    let (bond_edge, payment_edge) = (bond_object(), payment_object());
    let live = all_live();
    SetupRecord::Observed(
        state
            .observe(&ObservedSetup {
                height,
                bond: bond.then_some(&bond_edge),
                payment: payment.then_some(&payment_edge),
                lease: if payment {
                    lease_over(self::bond_edge(), self::payment_edge())
                } else {
                    LeaseSlots::Absent
                },
                live_funding: &live,
            })
            .expect("the read teaches the journal something"),
    )
}

// ── The journal ───────────────────────────────────────────────────────

/// A revision is durable before its signature is exported, and a crash
/// between the two re-exports the same artifact rather than a new one.
#[tokio::test]
async fn a_retained_revision_is_re_exported_byte_for_byte() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let two = countersigned(proposed());

    // The client's process: retain revision 1, then retain revision 2 —
    // which carries its own two signatures — and crash before exporting
    // it.
    {
        let mut client_store = store(dir.path(), Role::Client).await;
        if let Err(error) = client_store
            .commit(bundle_record(&proposed()), &verifier)
            .await
        {
            panic!("revision 1 commits: {error}");
        }
        if let Err(error) = client_store.commit(armed_record(&two), &verifier).await {
            panic!("revision 2 commits: {error}");
        }
    }

    let recovered = store(dir.path(), Role::Client).await;
    assert_eq!(recovered.state().revision(), Some(2));
    assert_eq!(
        recovered.state().bundle_bytes(),
        Some(two.encode().as_slice())
    );
    assert_eq!(recovered.len(), 2);
}

/// The three revisions go in order, and nothing else does.
#[tokio::test]
async fn revisions_extend_and_never_rewind() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    // Revision 2 without revision 1 is not a conversation this endpoint
    // took part in.
    let mut skipping = store(dir.path(), Role::Provider).await;
    let error = skipping
        .commit(bundle_record(&two), &verifier)
        .await
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

    let mut ordered = store(dir.path(), Role::Provider).await;
    for record in [
        bundle_record(&one),
        bundle_record(&two),
        armed_record(&three),
    ] {
        if let Err(error) = ordered.commit(record, &verifier).await {
            panic!("the revision commits: {error}");
        }
    }
    assert_eq!(ordered.state().revision(), Some(3));

    // A replayed stale revision.
    let error = ordered
        .commit(bundle_record(&two), &verifier)
        .await
        .expect_err("revision 2 does not follow revision 3");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert_eq!(ordered.state().revision(), Some(3));
    assert_eq!(ordered.len(), 3);
}

/// A revision whose signatures do not check never reaches the file —
/// and could not be read back out of one.
#[tokio::test]
async fn an_unverified_revision_is_not_journaled() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();

    // The client signs the bond where the provider must: the same
    // bytes, the wrong party.
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV2::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        hellas_kernel::PartyAuth::signer(Auth::native(client().sign(hash))),
    ) else {
        panic!("the bundle assembles");
    };

    let mut journal = store(dir.path(), Role::Provider).await;
    let error = journal
        .commit(bundle_record(&forged), &verifier)
        .await
        .expect_err("the provider did not sign this");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
    assert!(journal.is_empty());
}

/// The bundle decoder is exact, so bytes with anything after a whole
/// revision are not a revision.
#[tokio::test]
async fn a_noncanonical_revision_is_refused() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut bytes = proposed().encode();
    bytes.push(0);
    let mut journal = store(dir.path(), Role::Provider).await;
    let error = journal
        .commit(SetupRecord::Bundle { bundle: bytes }, &verifier)
        .await
        .expect_err("a trailing byte is not canonical");
    assert!(
        matches!(error, WorkStoreError::Setup(SetupStateError::Bundle(_))),
        "unexpected error: {error}"
    );
}

/// The journal is keyed to one network and one bond. Reopening it as
/// another channel's fails closed rather than replaying as empty.
#[tokio::test]
async fn a_journal_belongs_to_one_network_and_one_bond() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    drop(completed_store(dir.path()).await);

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
        let location = StoreLocation::for_test(dir.path());
        let Ok(other) = SetupStore::open(&location, network, bond, Role::Provider, &verifier).await
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
    let location = StoreLocation::for_test(dir.path());
    let error = SetupStore::open(&location, network(), elsewhere, Role::Provider, &verifier)
        .await
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
#[tokio::test]
async fn a_second_holder_is_refused() {
    let dir = temp();
    let held = store(dir.path(), Role::Provider).await;
    let verifier = Secp256k1Verifier::new();
    let location = StoreLocation::for_test(dir.path());
    let error = SetupStore::open(&location, network(), bond_edge(), Role::Provider, &verifier)
        .await
        .expect_err("the journal is already held");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Locked { .. })),
        "unexpected error: {error}"
    );
    drop(held);
    assert!(
        SetupStore::open(&location, network(), bond_edge(), Role::Provider, &verifier)
            .await
            .is_ok(),
        "the lock is released with the store"
    );
}

/// The file one setup journal is kept in, derived the way the store
/// derives it rather than by looking for whatever is in the directory.
fn journal_path(root: &std::path::Path, network: NetworkId, bond: EdgeId) -> std::path::PathBuf {
    let location = StoreLocation::for_test(root);
    Journal::path(&location, &setup_stem(network, bond))
}

fn setup_stem(network: NetworkId, bond: EdgeId) -> String {
    format!("setup-{}", hex(&setup_key(network, bond).into_bytes()))
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
#[tokio::test]
async fn a_restart_finds_every_journal_its_root_holds() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let staked = proposed();
    let funded = proposed_over(other_bond_funding());
    assert_ne!(staked.bond_edge(), funded.bond_edge());

    // One bond this node stakes as the provider, one it funds as the
    // client, both under the one root.
    {
        let mut provider_store = store(dir.path(), Role::Provider).await;
        for record in [bundle_record(&staked)] {
            if let Err(error) = provider_store.commit(record, &verifier).await {
                panic!("the provider's revision commits: {error}");
            }
        }
        let location = StoreLocation::for_test(dir.path());
        let mut client_store = match SetupStore::open(
            &location,
            network(),
            funded.bond_edge(),
            Role::Client,
            &verifier,
        )
        .await
        {
            Ok(store) => store,
            Err(error) => panic!("the client's journal opens: {error}"),
        };
        if let Err(error) = client_store.commit(bundle_record(&funded), &verifier).await {
            panic!("the client's revision commits: {error}");
        }
    }

    let location = StoreLocation::for_test(dir.path());
    let found = match discover_setups(&location, network()).await {
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
        let location = StoreLocation::for_test(dir.path());
        let reopened = match SetupStore::open(
            &location,
            network(),
            expected.bond_edge,
            expected.role,
            &verifier,
        )
        .await
        {
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
#[tokio::test]
async fn a_root_holding_no_journals_yields_none() {
    let dir = temp();
    // A channel journal beside them is the other store's, and is not a
    // setup this discovery has anything to say about.
    let location = StoreLocation::for_test(dir.path());
    drop(
        Journal::open_latest(
            &location,
            &format!("channel-{}", "00".repeat(32)),
            JournalId {
                kind: JournalKind::Channel,
                role: Role::Provider,
                key: [0; 32],
            },
        )
        .await
        .unwrap(),
    );

    let found = match discover_setups(&location, network()).await {
        Ok(found) => found,
        Err(error) => panic!("an empty root is not a failure: {error}"),
    };
    assert!(found.setups.is_empty());
    assert!(found.unidentified.is_empty());

    let unopened = dir.path().join("never-opened");
    let other_location = StoreLocation::for_test(&unopened);
    let found = match discover_setups(&other_location, network()).await {
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
#[tokio::test]
async fn a_journal_that_cannot_be_identified_is_reported_by_name() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let armed = proposed_over(other_bond_funding());

    // A handshake that recorded a read and crashed before its first
    // revision: the file is this endpoint's, and the bond it is keyed to
    // is nowhere inside it.
    {
        let location = StoreLocation::for_test(dir.path());
        let mut store = match SetupStore::open(
            &location,
            network(),
            armed.bond_edge(),
            Role::Provider,
            &verifier,
        )
        .await
        {
            Ok(store) => store,
            Err(error) => panic!("the armed journal opens: {error}"),
        };
        let read = seen(store.state(), FLOOR + 1, true, false);
        store
            .commit(read, &verifier)
            .await
            .expect("a read without a revision commits");
    }
    // And a file wearing a setup journal's name that is not one.
    let location = StoreLocation::for_test(dir.path());
    let counterfeit = Journal::path(&location, &format!("setup-{}", "ab".repeat(32)));
    std::fs::write(&counterfeit, b"not a journal at all").unwrap();
    // And one complete journal beside them.
    {
        let mut store = store(dir.path(), Role::Provider).await;
        for record in [bundle_record(&proposed())] {
            if let Err(error) = store.commit(record, &verifier).await {
                panic!("the revision commits: {error}");
            }
        }
    }

    let found = match discover_setups(&location, network()).await {
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
                matches!(
                    setup.reason,
                    SetupDiscoveryError::Journal(JournalError::NotAJournal { .. })
                ),
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
#[tokio::test]
async fn a_revision_that_is_not_this_journals_bond_is_refused() {
    let dir = temp();
    let key = setup_key(network(), bond_edge());
    {
        let location = StoreLocation::for_test(dir.path());
        let (mut journal, _) = match Journal::open_latest(
            &location,
            &setup_stem(network(), bond_edge()),
            JournalId {
                kind: JournalKind::Setup,
                role: Role::Provider,
                key: key.into_bytes(),
            },
        )
        .await
        {
            Ok(opened) => opened,
            Err(error) => panic!("the fixture journal opens: {error}"),
        };
        if let Err(error) = journal
            .append(
                &bundle_record(&proposed_over(other_bond_funding()))
                    .encode()
                    .unwrap(),
            )
            .await
        {
            panic!("the foreign revision appends: {error}");
        }
    }

    let location = StoreLocation::for_test(dir.path());
    let found = match discover_setups(&location, network()).await {
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
#[tokio::test]
async fn locking_stake_requires_every_payment_input_to_be_live() {
    let dir = temp();
    let held = completed_store(dir.path()).await;
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
#[tokio::test]
async fn the_recovery_decision_covers_every_finalized_shape() {
    let dir = temp();
    let held = completed_store(dir.path()).await;
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

#[tokio::test]
async fn round7_payment_live_without_bond_mounts_close() {
    let dir = temp();
    let held = completed_store(dir.path()).await;
    let observed = Observed {
        payment: Some(payment_object()),
        ..Observed::before_anything()
    };
    assert_eq!(observed.decide(held.state()), SetupDecision::CloseOnly);
}

/// A client holds no countersigned payment Open. It never decides to
/// submit or to time anything out, whatever the chain looks like.
#[tokio::test]
async fn a_client_never_submits_the_providers_transactions() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut client_store = store(dir.path(), Role::Client).await;
    let one = proposed();
    let two = countersigned(one.clone());
    for record in [bundle_record(&one), armed_record(&two)] {
        if let Err(error) = client_store.commit(record, &verifier).await {
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
#[tokio::test]
async fn a_proposal_alone_decides_nothing() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider).await;
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier).await {
        panic!("revision 1 commits: {error}");
    }
    assert_eq!(
        Observed::before_anything().decide(journal.state()),
        SetupDecision::AwaitingCounterparty
    );
}

/// The broadcast journal precedes the broadcast, and a step that has no
/// executable transaction behind it is not recorded.
#[tokio::test]
async fn submission_markers_follow_the_transactions_they_are_about() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = store(dir.path(), Role::Provider).await;
    if let Err(error) = journal.commit(bundle_record(&proposed()), &verifier).await {
        panic!("revision 1 commits: {error}");
    }

    // No countersigned bond exists yet, so there is nothing to have
    // broadcast.
    let error = journal
        .commit(SetupRecord::BondSubmitted, &verifier)
        .await
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
        if let Err(error) = journal.commit(record, &verifier).await {
            panic!("the revision commits: {error}");
        }
    }

    // The payment is not broadcast before the bond it needs.
    let error = journal
        .commit(SetupRecord::PaymentSubmitted, &verifier)
        .await
        .expect_err("the bond goes first");
    assert!(
        matches!(
            error,
            WorkStoreError::Setup(SetupStateError::WrongStage { .. })
        ),
        "unexpected error: {error}"
    );

    for record in [SetupRecord::BondSubmitted, SetupRecord::PaymentSubmitted] {
        if let Err(error) = journal.commit(record, &verifier).await {
            panic!("the marker commits: {error}");
        }
    }
    assert!(journal.state().bond_submitted());
    assert!(journal.state().payment_submitted());

    // A marker already held is not written twice.
    let before = journal.len();
    if let Err(error) = journal.commit(SetupRecord::BondSubmitted, &verifier).await {
        panic!("an idempotent marker commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // A client cannot record having broadcast what it does not hold.
    let other = temp();
    let mut client_store = store(other.path(), Role::Client).await;
    for record in [
        bundle_record(&proposed()),
        armed_record(&two),
        bundle_record(&three),
    ] {
        if let Err(error) = client_store.commit(record, &verifier).await {
            panic!("the revision commits: {error}");
        }
    }
    let error = client_store
        .commit(SetupRecord::BondSubmitted, &verifier)
        .await
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
#[tokio::test]
async fn completion_records_the_channels_origin_and_is_terminal() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;

    // The payment edge is the retained bundle's, never a supplied one.
    let error = journal
        .commit(
            SetupRecord::Complete {
                payment_edge: EdgeId::from_bytes([0x66; EdgeId::LENGTH]),
                origin_height: 44,
                origin_payload: [0x01; 32],
            },
            &verifier,
        )
        .await
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
    };
    if let Err(error) = journal.commit(complete.clone(), &verifier).await {
        panic!("completion commits: {error}");
    }
    let Some(origin) = journal.state().origin() else {
        panic!("completion records an origin");
    };
    assert_eq!(origin.height, 44);
    assert_eq!(journal.state().end(), Some(SetupEnd::Complete));

    // Recording it again is the same fact.
    let before = journal.len();
    if let Err(error) = journal.commit(complete, &verifier).await {
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
        .await
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

/// A retried completion is the retry it is only when it names the same
/// origin. One naming another block is a caller whose finalized read
/// disagrees with the journal's — refused as the end it follows, not
/// absorbed as a duplicate.
#[tokio::test]
async fn a_different_completion_after_the_end_is_not_a_retry() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
    };
    if let Err(error) = journal.commit(complete.clone(), &verifier).await {
        panic!("completion commits: {error}");
    }

    // The same record again is the retry: nothing is appended.
    let before = journal.len();
    if let Err(error) = journal.commit(complete, &verifier).await {
        panic!("an idempotent completion commits: {error}");
    }
    assert_eq!(journal.len(), before);

    // Each field independently changes the completed origin.
    for (payment_edge, origin_height, origin_payload) in [
        (EdgeId::from_bytes([0x55; 32]), 44, [0x01; 32]),
        (payment_edge(), 45, [0x01; 32]),
        (payment_edge(), 44, [0x03; 32]),
    ] {
        let error = journal
            .commit(
                SetupRecord::Complete {
                    payment_edge,
                    origin_height,
                    origin_payload,
                },
                &verifier,
            )
            .await
            .expect_err("a different origin is not the completion already recorded");
        assert!(
            matches!(
                error,
                WorkStoreError::Setup(SetupStateError::Ended(SetupEnd::Complete))
            ),
            "unexpected error: {error}"
        );
        assert_eq!(journal.len(), before, "nothing was written for it");
    }
    let origin = journal
        .state()
        .origin()
        .expect("the recorded origin stands");
    assert_eq!(origin.payment_edge, payment_edge());
    assert_eq!(origin.height, 44);
    assert_eq!(origin.payload, [0x01; 32]);
}

/// An ended setup stays ended across a restart, and never resubmits.
#[tokio::test]
async fn an_aborted_setup_does_not_come_back() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    {
        let mut journal = completed_store(dir.path()).await;
        if let Err(error) = journal
            .commit(
                SetupRecord::Ended {
                    outcome: SetupEnd::Aborted(SetupAbort::BondOpenExpired),
                },
                &verifier,
            )
            .await
        {
            panic!("the abort commits: {error}");
        }
    }
    let recovered = store(dir.path(), Role::Provider).await;
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
#[tokio::test]
async fn a_crash_before_broadcast_recovers_into_the_preflight() {
    let dir = temp();
    drop(completed_store(dir.path()).await);

    let recovered = store(dir.path(), Role::Provider).await;
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
#[tokio::test]
async fn the_funding_coins_come_from_the_retained_transactions() {
    let dir = temp();
    let journal = completed_store(dir.path()).await;
    assert_eq!(journal.state().funding_coins(), all_live());
    assert_eq!(journal.state().horizon(), Some(HORIZON));
    assert_eq!(journal.state().payment_edge(), Some(payment_edge()));
    assert_eq!(journal.state().bond_edge(), bond_edge());
}

/// The record codec is exact: an unknown tag, a short body, and a
/// trailing byte are all refused.
#[tokio::test]
async fn the_record_codec_is_exact() {
    let armed = armed_record(&countersigned(proposed()));
    let armed_bytes = armed.encode().unwrap();
    assert_eq!(SetupRecord::decode(&armed_bytes), Ok(armed));
    assert_eq!(
        SetupRecord::decode(&armed_bytes[..armed_bytes.len() - 1]),
        Err(SetupStateError::Malformed),
    );

    let complete = SetupRecord::Complete {
        payment_edge: payment_edge(),
        origin_height: 44,
        origin_payload: [0x01; 32],
    };
    let bytes = complete.encode().unwrap();
    // tag || edge || height || payload
    assert_eq!(bytes.len(), 1 + 32 + 8 + 32);
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

    let dir = temp();
    let fixture = completed_store(dir.path()).await;
    let history = seen(fixture.state(), FLOOR + 1, true, true);
    assert_eq!(SetupRecord::decode(&history.encode().unwrap()), Ok(history));
}

/// Every signature-bearing setup export leaves enough state to recover the
/// portable Open and, once payment is funded, mount close-only settlement
/// without operator configuration.
#[tokio::test]
async fn round4_exported_authorization_recovers() {
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let two = countersigned(one.clone());
    let three = completed(two.clone());

    // Crash after provider revision 1 export.
    let provider_one = temp();
    {
        let mut journal = store(provider_one.path(), Role::Provider).await;
        for record in [bundle_record(&one)] {
            if let Err(error) = journal.commit(record, &verifier).await {
                panic!("provider revision 1 arms before export: {error}");
            }
        }
    }
    let recovered_one = store(provider_one.path(), Role::Provider).await;
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
        let mut journal = store(client_two.path(), Role::Client).await;
        for record in [bundle_record(&one), armed_record(&two)] {
            if let Err(error) = journal.commit(record, &verifier).await {
                panic!("client revision 2 arms before export: {error}");
            }
        }
    }
    let recovered_two = store(client_two.path(), Role::Client).await;
    assert!(recovered_two.state().bond_open().is_some());
    assert!(recovered_two.state().close_descriptor().is_some());
    drop(recovered_two);

    // Crash after provider revision 3 export. A counterparty may now submit
    // either executable Open; recovery still derives the funded settlement
    // from the observed edge rather than from the lost configuration.
    let provider_three = temp();
    {
        let mut journal = store(provider_three.path(), Role::Provider).await;
        for record in [
            bundle_record(&one),
            bundle_record(&two),
            armed_record(&three),
        ] {
            if let Err(error) = journal.commit(record, &verifier).await {
                panic!("provider revision 3 arms before export: {error}");
            }
        }
    }
    let recovered_three = store(provider_three.path(), Role::Provider).await;
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
#[tokio::test]
async fn round6_submitted_open_delays_end() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    if let Err(error) = journal.commit(SetupRecord::BondSubmitted, &verifier).await {
        panic!("the bond submission arms its unresolved Open: {error}");
    }
    for outcome in [
        SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
        SetupEnd::Faulted(SetupFault::BondFundingSpent),
    ] {
        let error = journal
            .commit(SetupRecord::Ended { outcome }, &verifier)
            .await
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

    let read = seen(journal.state(), FLOOR + 2, true, false);
    if let Err(error) = journal.commit(read, &verifier).await {
        panic!("a read showing the bond resolves the retained Open: {error}");
    }
    assert!(
        !journal.state().bond_submitted(),
        "the finalized Open discharges its submission obligation",
    );
    if let Err(error) = journal
        .commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::PaymentFundingSpent),
            },
            &verifier,
        )
        .await
    {
        panic!("history resolution permits the end: {error}");
    }
    drop(journal);
    assert_eq!(
        store(dir.path(), Role::Provider).await.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::PaymentFundingSpent)),
    );
}

/// A provider's own finalized bond Timeout ends the setup cleanly, not
/// in the fault the spent stake would otherwise be read as.
///
/// The provider submits the bond and then the deterministic Timeout.
/// While no read has shown the bond, the absent bond over a spent stake
/// is its own reclaim in flight and no fault is decided. Once a read has
/// shown the bond live, its absence is a closed bond — and a bond's only
/// exit is the Timeout that pays the stake back — so the end is
/// `Abort(BondReclaimed)`, which a genuinely unexplained spend
/// (`the_recovery_decision_covers_every_finalized_shape`) still is not.
#[tokio::test]
async fn a_finalized_bond_timeout_reclaims_the_stake_cleanly() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    for record in [
        SetupRecord::BondSubmitted,
        SetupRecord::BondTimeoutSubmitted,
    ] {
        if let Err(error) = journal.commit(record, &verifier).await {
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

    // A read shows the bond live.
    let read = seen(journal.state(), FLOOR + 1, true, false);
    if let Err(error) = journal.commit(read, &verifier).await {
        panic!("a read showing the bond journals: {error}");
    }

    // The absent bond over spent stake is now a closed bond.
    assert_eq!(
        spent_stake().decide(journal.state()),
        SetupDecision::Abort(SetupAbort::BondReclaimed),
        "the finalized timeout close ends the setup cleanly",
    );

    // And that clean end journals where a fault could not have.
    if let Err(error) = journal
        .commit(
            SetupRecord::Ended {
                outcome: SetupEnd::Aborted(SetupAbort::BondReclaimed),
            },
            &verifier,
        )
        .await
    {
        panic!("the reclaim end journals: {error}");
    }
    drop(journal);
    assert_eq!(
        store(dir.path(), Role::Provider).await.state().end(),
        Some(SetupEnd::Aborted(SetupAbort::BondReclaimed)),
    );
}

/// The client's contest that landed with, or before, the first read this
/// provider took of the payment edge: it is the pending-close slot of that
/// same read.
fn contest_pending() -> PendingSlot {
    let Tx::Move {
        action: Move::StartPaymentClose(start),
    } = same_block_contest()
    else {
        panic!("the fixture contest is a start");
    };
    PendingSlot::Present(
        hellas_kernel::PendingPaymentClose::from_accepted_start(
            network(),
            FLOOR + 1,
            hellas_channel::test_support::channel::now_ms(),
            &start,
        )
        .expect("the fixture contest opens"),
    )
}

#[tokio::test]
async fn provider_setup_preserves_power_durability_when_mounting_the_channel() {
    let dir = temp();
    let location =
        StoreLocation::for_test(dir.path()).with_durability(hellas_private::Durability::Power);
    let mut setup = completed_store_at(&location).await;
    let content = hellas_channel::test_support::channel::content_store(dir.path()).await;
    setup.set_content_store(content);
    let read = live_channel(setup.state(), FLOOR + 1, payment_object());
    let advance = advance_setup(&read, &NoSink, &mut setup, &Secp256k1Verifier::new())
        .await
        .unwrap();
    assert!(matches!(advance.progress, SetupProgress::Complete(_)));
    let mut channel = advance.mounted.expect("provider setup mounts its channel");
    assert_eq!(
        channel.synchronous_for_test().await,
        2,
        "channel journal is FULL"
    );
}

/// A completed setup hands back the channel it mounted, starting at the
/// first read that showed the payment edge live and leased, settled
/// against the edge it read — and a contest already open at that read is
/// on the channel handed back.
///
/// The client funded 4,096 where the provider's configuration expected
/// 1,200, and a close built on the expectation is one consensus refuses.
#[tokio::test]
async fn a_completed_setup_hands_back_the_channel_it_mounted() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    let content = hellas_channel::test_support::channel::content_store(dir.path()).await;
    journal.set_content_store(content.clone());

    let mut read = live_channel(journal.state(), FLOOR + 1, overfunded_payment_object());
    read.pending = contest_pending();
    let advance = match advance_setup(&read, &NoSink, &mut journal, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("a live leased pair completes: {error}"),
    };
    let SetupProgress::Complete(origin) = advance.progress else {
        panic!("a live leased pair completes: {:?}", advance.progress);
    };
    assert_eq!(
        (origin.height, origin.payload),
        (read.height, read.payload),
        "the origin is this endpoint's first sighting of the payment edge",
    );
    assert_eq!(journal.state().end(), Some(SetupEnd::Complete));
    assert_eq!(journal.state().observed_height(), Some(read.height));

    let mounted = advance
        .mounted
        .expect("completion hands back the channel it opened");
    assert_eq!(mounted.state().cursor(), (origin.height, origin.payload));
    assert_eq!(mounted.state().certified_at_ms(), read.certified_at_ms);
    assert_eq!(mounted.state().settlement().adjudicated_total(), 4_096);
    assert_eq!(mounted.state().settlement().capacity(), 2_047);
    assert!(
        mounted.state().close_opened().is_some(),
        "the contest open at the first sighting is journaled on the channel",
    );
    let expected = journal
        .state()
        .close_descriptor()
        .expect("the armed close descriptor")
        .expected_settlement()
        .expect("the configured expectation settles");
    assert_eq!(expected.adjudicated_total(), 3_200);
}

/// A restart over a completed setup hands the same channel back, settled
/// against a fresh read of the edge.
#[tokio::test]
async fn a_restart_over_a_completed_setup_hands_back_the_same_channel() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    let content = hellas_channel::test_support::channel::content_store(dir.path()).await;
    journal.set_content_store(content.clone());

    let mut read = live_channel(journal.state(), FLOOR + 1, overfunded_payment_object());
    read.pending = contest_pending();
    let advance = advance_setup(&read, &NoSink, &mut journal, &verifier)
        .await
        .expect("the setup completes");
    let SetupProgress::Complete(origin) = advance.progress else {
        panic!("the setup completes: {:?}", advance.progress);
    };
    let records = advance
        .mounted
        .expect("completion hands its channel back")
        .len();
    drop(journal);

    let mut restarted = store(dir.path(), Role::Provider).await;
    restarted.set_content_store(content.clone());
    assert_eq!(restarted.state().end(), Some(SetupEnd::Complete));
    let advance = advance_setup(&read, &NoSink, &mut restarted, &verifier)
        .await
        .expect("the restart answers from the journal");
    assert_eq!(advance.progress, SetupProgress::Complete(origin));
    let mounted = advance
        .mounted
        .expect("the restart hands the channel back as well");
    assert_eq!(mounted.state().cursor(), (origin.height, origin.payload));
    assert_eq!(mounted.state().settlement().adjudicated_total(), 4_096);
    assert!(mounted.state().close_opened().is_some());
    assert_eq!(
        mounted.len(),
        records,
        "the same read again writes nothing to the channel journal",
    );
}

/// A read answers the question it was asked, and a step refuses one that
/// is not the journal's question now.
///
/// A revision the handshake commits while a read is in flight makes the
/// payment Open executable, and its funding coins would read as absent —
/// spent — in an answer that never asked about them. That answer decides
/// nothing; so does one older than a read the journal already recorded.
#[tokio::test]
async fn a_step_refuses_a_read_of_another_question_or_an_older_state() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let one = proposed();
    let mut journal = store(dir.path(), Role::Provider).await;
    journal
        .commit(bundle_record(&one), &verifier)
        .await
        .expect("revision 1 commits");
    // The read is taken while revision 1 is all the journal holds...
    let early = FinalizedSetup {
        query: setup_query(journal.state()).expect("revision 1 names its bond"),
        height: FLOOR + 1,
        payload: [0x48; 32],
        certified_at_ms: hellas_channel::test_support::channel::now_ms(),
        bond: None,
        payment: None,
        lease: LeaseSlots::Absent,
        pending: PendingSlot::Absent,
        live_funding: without(PAYMENT_COIN),
    };
    // ...and revisions 2 and 3 land before it is answered.
    for record in [
        bundle_record(&countersigned(one.clone())),
        armed_record(&completed(countersigned(one))),
    ] {
        journal
            .commit(record, &verifier)
            .await
            .expect("revision commits");
    }
    let sink = Mempool::default();
    let advance = advance_setup(&early, &sink, &mut journal, &verifier)
        .await
        .expect("the step answers");
    assert_eq!(advance.progress, SetupProgress::AwaitingFinalizedState);
    assert!(sink.submitted().is_empty());
    assert_eq!(journal.state().end(), None);

    // A read of the journal's own question decides.
    let current = read(
        journal.state(),
        FLOOR + 2,
        Some(bond_object()),
        None,
        LeaseSlots::Absent,
        all_live(),
    );
    let advance = advance_setup(&current, &sink, &mut journal, &verifier)
        .await
        .expect("the step answers");
    assert!(matches!(
        advance.progress,
        SetupProgress::Submitted {
            step: SetupStep::Payment,
            ..
        }
    ));
    // An older state than one already recorded decides nothing.
    let older = read(
        journal.state(),
        FLOOR + 1,
        None,
        None,
        LeaseSlots::Absent,
        without(BOND_COIN),
    );
    let advance = advance_setup(&older, &sink, &mut journal, &verifier)
        .await
        .expect("the step answers");
    assert_eq!(advance.progress, SetupProgress::AwaitingFinalizedState);
    assert_eq!(journal.state().end(), None);
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

/// A payment edge that outlived its bond mounts close-only and settles at
/// what it holds, not at what the configuration expected it to hold.
#[tokio::test]
async fn an_overfunded_close_only_channel_settles_at_the_edge_it_holds() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut journal = completed_store(dir.path()).await;
    let content = hellas_channel::test_support::channel::content_store(dir.path()).await;
    journal.set_content_store(content.clone());

    let read = surviving_payment(journal.state(), FLOOR + 2, overfunded_payment_object());
    let advance = match advance_setup(&read, &NoSink, &mut journal, &verifier).await {
        Ok(advance) => advance,
        Err(error) => panic!("a bond-timed-out payment mounts close-only: {error}"),
    };
    let SetupProgress::CloseOnly { origin, settled } = advance.progress else {
        panic!(
            "a bond-timed-out payment mounts close-only: {:?}",
            advance.progress
        );
    };
    assert!(!settled, "the payment edge outlived the bond");
    assert_eq!(origin.height, FLOOR + 2);
    let mounted = advance
        .mounted
        .expect("a close-only mount hands back the channel it opened");
    assert_eq!(mounted.state().settlement().adjudicated_total(), 4_096);
    assert_eq!(mounted.state().settlement().capacity(), 2_047);
    drop(mounted);
    drop(journal);

    // The restart reaches the recorded origin and settles again from the read.
    let mut restarted = store(dir.path(), Role::Provider).await;
    restarted.set_content_store(content.clone());
    let advance = advance_setup(&read, &NoSink, &mut restarted, &verifier)
        .await
        .expect("the restart mounts");
    assert_eq!(advance.progress, SetupProgress::Complete(origin));
    let mounted = advance
        .mounted
        .expect("the restart is handed the channel too");
    assert_eq!(mounted.state().settlement().adjudicated_total(), 4_096);
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
        let bytes = SetupRecord::Ended { outcome }.encode().unwrap();
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

/// Signatures are checked when the journal is read back, not only when
/// it is written.
///
/// Committed under a verifier that accepts anything, then reopened
/// under the real one: what was journaled is refused, rather than being
/// trusted because it is already on the disk.
#[tokio::test]
async fn replay_checks_the_signatures_again() {
    let dir = temp();
    let hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(bond_terms()),
    );
    let Ok(forged) = WorkChannelSetupBundleV2::propose_bond(
        network(),
        bond_funding(),
        bond_terms(),
        hellas_kernel::PartyAuth::signer(Auth::native(client().sign(hash))),
    ) else {
        panic!("the bundle assembles");
    };
    {
        let location = StoreLocation::for_test(dir.path());
        let Ok(mut credulous) = SetupStore::open(
            &location,
            network(),
            bond_edge(),
            Role::Provider,
            &AcceptAll,
        )
        .await
        else {
            panic!("the journal opens");
        };
        if let Err(error) = credulous.commit(bundle_record(&forged), &AcceptAll).await {
            panic!("a credulous verifier accepts it: {error}");
        }
    }
    let location = StoreLocation::for_test(dir.path());
    let error = SetupStore::open(
        &location,
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .await
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
async fn in_flight_store(root: &std::path::Path) -> SetupStore {
    let verifier = Secp256k1Verifier::new();
    let mut store = completed_store(root).await;
    for record in [
        SetupRecord::BondSubmitted,
        SetupRecord::PaymentSubmitted,
        SetupRecord::BondTimeoutSubmitted,
    ] {
        if let Err(error) = store.commit(record, &verifier).await {
            panic!("the in-flight fixture commits: {error}");
        }
    }
    store
}

/// A handshake whose history has finalized and closed both edges.
///
/// The other half of the state space: both finalization flags, both
/// close flags, the origin the payment Open fixes, and an end.
async fn settled_store(root: &std::path::Path) -> SetupStore {
    let verifier = Secp256k1Verifier::new();
    let mut store = completed_store(root).await;
    let seen_live = seen(store.state(), FLOOR + 3, true, true);
    for record in [
        seen_live,
        SetupRecord::Ended {
            outcome: SetupEnd::Aborted(SetupAbort::BondReclaimed),
        },
    ] {
        if let Err(error) = store.commit(record, &verifier).await {
            panic!("the settled fixture commits: {error}");
        }
    }
    store
}

/// Exercise both unresolved and settled obligations during rotation.
const FIXTURES: [(&str, bool); 2] = [("in flight", false), ("settled", true)];

async fn fixture(root: &std::path::Path, settled: bool) -> SetupStore {
    if settled {
        settled_store(root).await
    } else {
        in_flight_store(root).await
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
#[tokio::test]
async fn a_checkpoint_replays_to_what_the_frames_replayed_to() {
    for (label, settled) in FIXTURES {
        let control = temp();
        let expected = fixture(control.path(), settled).await.state().clone();

        let rotated = temp();
        {
            let mut store = fixture(rotated.path(), settled).await;
            if let Err(error) = store.rotate().await {
                panic!("{label}: the rotation completes: {error}");
            }
            assert_eq!(
                store.len(),
                0,
                "{label}: a fresh generation holds its checkpoint and nothing else",
            );
        }
        let reopened = store(rotated.path(), Role::Provider).await;
        assert_eq!(
            reopened.state(),
            &expected,
            "{label}: the checkpoint is the state, not a summary of it",
        );
    }

    // What the two fixtures between them exercise. Asserted rather than
    // assumed, because a round trip over a state that is all defaults is
    // a round trip that proves nothing.
    let in_flight = temp();
    let in_flight = in_flight_store(in_flight.path()).await;
    let in_flight = in_flight.state();
    assert!(in_flight.bond_submitted());
    assert!(in_flight.payment_submitted());
    assert_eq!(in_flight.revision(), Some(3));
    assert!(in_flight.close_descriptor().is_some());
    assert_eq!(in_flight.end(), None);

    let settled = temp();
    let settled = settled_store(settled.path()).await;
    let settled = settled.state();
    assert_eq!(settled.observed_height(), Some(FLOOR + 3));
    assert!(!settled.submitted_open_unresolved());
    assert_eq!(
        settled.end(),
        Some(SetupEnd::Aborted(SetupAbort::BondReclaimed)),
    );
}

/// A rotated journal is still a journal a restart can name.
///
/// Discovery reads the bond edge out of the first revision the file
/// retained — and after a rotation that revision is in the checkpoint,
/// not in a frame. A discovery that read only the frames would report
/// every long-lived setup as holding no revision, and a setup a node
/// cannot name is a close it stops answering.
#[tokio::test]
async fn a_rotated_setup_is_still_discovered() {
    let dir = temp();
    {
        let mut store = settled_store(dir.path()).await;
        if let Err(error) = store.rotate().await {
            panic!("the rotation completes: {error}");
        }
    }
    let location = StoreLocation::for_test(dir.path());
    let found = match discover_setups(&location, network()).await {
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

fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
    hellas_channel::model::work::JobPaymentPolicyV2 {
        fixed_price: 10,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}

/// A spend nothing this journal saw explains is a fault on the first read
/// that shows it: an edge that opened and closed while unwatched leaves
/// no state to tell it from a theft, and recovering it is an operator's.
#[tokio::test]
async fn an_unexplained_spend_faults_on_the_read_that_shows_it() {
    let directory = temp();
    let mut journal = completed_store(directory.path()).await;
    let verifier = Secp256k1Verifier::new();
    let spent = read(
        journal.state(),
        FLOOR + 1,
        None,
        None,
        LeaseSlots::Absent,
        without(BOND_COIN),
    );
    let advance = advance_setup(&spent, &NoSink, &mut journal, &verifier)
        .await
        .unwrap();
    assert_eq!(
        advance.progress,
        SetupProgress::Faulted(SetupFault::BondFundingSpent)
    );
}

#[tokio::test]
async fn existing_only_setup_never_creates_a_missing_journal() {
    let dir = temp();
    let location = StoreLocation::for_test(dir.path());
    let error = SetupStore::open_existing(
        &location,
        network(),
        bond_edge(),
        Role::Provider,
        &Secp256k1Verifier::new(),
    )
    .await
    .expect_err("missing setup cannot be recreated for recovery");
    assert!(matches!(error, WorkStoreError::Journal(_)));
    assert!(!journal_path(dir.path(), network(), bond_edge()).exists());
}
