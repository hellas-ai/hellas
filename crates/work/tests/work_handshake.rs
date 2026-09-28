//! The two-Open handshake over a real transport: two endpoints that
//! have never met, two journals on two directories, and the three
//! revisions that turn them into one channel.
//!
//! Nothing here calls a handler as a function. Every exchange is framed,
//! routed by method id, decoded and answered over a multiplexed
//! transport, because a wire-shaped mistake is invisible to a direct
//! call. Every crash is a real one: the journal is dropped and reopened
//! over its own files.
//!
//! Each mutation test states what it breaks. A rule with no test that
//! fails when the rule is deleted is not a rule.

use bytes::Bytes;
use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, EdgeValues, Fees, Funding, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, NetworkId, Parties, Payout, Secp256k1Signer, Secp256k1Verifier,
    SigVerifier as _, Terms, Tx, WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::pb::work::{
    ExchangeSetupRequest, ExchangeSetupResponse, SetupAdvanced, WorkRefusalCode, WorkRefused,
    exchange_setup_response::Outcome,
};
use hellas_rpc::protocol::work::{
    PaidChannelPolicyV1, PaidExecutionPolicyV1, private_policy_commitment,
};
use hellas_rpc::protocol::work_bundle::WorkChannelSetupBundleV1;
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_rpc::protocol::{ContentId, Digest};
use hellas_rpc::services::work_setup::{WorkSetup, WorkSetupClientImpl, WorkSetupServer};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, ServiceMarker, StreamTransport};
use hellas_work::work_handshake::{
    PaymentAdmission, SetupEndpoint, SetupExchangeError, SetupService, apply_setup_exchange,
    prepare_setup_exchange, send_setup_exchange,
};
use hellas_work::work_store::{Role, SetupScan, SetupStore};
use prost::Message as _;
use tokio::sync::mpsc;

async fn exchange_setup<T>(
    transport: T,
    endpoint: &mut SetupEndpoint,
) -> Result<(), SetupExchangeError>
where
    T: StreamTransport + Sync,
    T::Error: std::error::Error + Send + Sync + 'static,
    T::Stream: 'static,
{
    let request = prepare_setup_exchange(endpoint);
    let response = send_setup_exchange(transport, request).await?;
    apply_setup_exchange(endpoint, response)
}

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const STAKE: u64 = 64;
const SALT: [u8; 32] = [0x5a; 32];
/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
const OMISSION_BOND: u64 = 601;
const PAYMENT_VALUE: u64 = 1_000;
const PAYMENT_RESERVE: u64 = 200;
/// The window the provider measured its own response probability over,
/// and the one the fixture's terms admit.
///
/// Above the kernel's floor by enough that a test can propose a
/// *shorter* window and still be proposing terms the kernel itself
/// would accept — so what refuses it is the provider's measurement and
/// not a consensus rule standing in front of it.
const WINDOW: u64 = hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS + 4;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

fn provider() -> Secp256k1Signer {
    signer(0x22)
}

fn client() -> Secp256k1Signer {
    signer(0x21)
}

/// A third key with no role in these terms.
fn stranger() -> Secp256k1Signer {
    signer(0x23)
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
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

/// The provider's stake funding: its own coins, none of the client's.
fn bond_funding() -> Funding {
    Funding::new(coins(&[0xa1]), empty_coins())
}

/// The client's capacity funding: its own coins, none of the
/// provider's, and disjoint from the stake.
fn payment_funding() -> Funding {
    Funding::new(coins(&[0xb1]), empty_coins())
}

fn payment_terms(bond_edge: EdgeId) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge,
        bond_terms: bond_terms(),
        // The provider's own commitment, because the provider's
        // admission policy opens it against its own salt and credit
        // policy before it will countersign.
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: WINDOW,
        start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS,
        omission_bond: OMISSION_BOND,
    }
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 40,
        delivery_credit_limit: 40,
    }
}

fn other_channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 39,
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

/// What this provider will countersign a payment over.
fn provider_policy() -> ProviderChannelPolicy {
    ProviderChannelPolicy {
        network: network(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        execution_policy: execution_policy().into(),
        expected_payment_values: EdgeValues::new(
            PAYMENT_VALUE,
            PAYMENT_RESERVE,
            Fees::new(0, 0, 0, 0),
        ),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    }
}

fn admits() -> PaymentAdmission {
    PaymentAdmission::Admits(Box::new(provider_policy()))
}

fn proposes() -> PaymentAdmission {
    PaymentAdmission::Proposes(Box::new(provider_policy()))
}

fn scan() -> SetupScan {
    SetupScan {
        height: 7,
        payload: [0x47; 32],
    }
}

fn arm(endpoint: &mut SetupEndpoint) {
    if let Err(error) = endpoint.arm_scan(scan()) {
        panic!("the fixture arms its immutable history floor: {error}");
    }
}

fn bond_edge() -> EdgeId {
    Tx::edge_id_of(&bond_funding(), &Terms::work_stake_bond(bond_terms()))
}

/// Opens one endpoint's setup journal under its own directory.
fn endpoint(
    root: &std::path::Path,
    role: Role,
    signer: Secp256k1Signer,
    admission: PaymentAdmission,
) -> SetupEndpoint {
    let store = match SetupStore::open(
        root,
        network(),
        bond_edge(),
        role,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the fixture journal opens: {error}"),
    };
    SetupEndpoint::new(store, signer, admission)
}

/// A provider endpoint that has already signed and journaled its bond
/// proposal, which is the state an operator's configuration leaves it
/// in.
fn proposing_provider(root: &std::path::Path) -> SetupEndpoint {
    let mut endpoint = endpoint(root, Role::Provider, provider(), admits());
    arm(&mut endpoint);
    if let Err(error) = endpoint.propose_bond(network(), bond_funding(), bond_terms()) {
        panic!("the fixture provider proposes its bond: {error}");
    }
    endpoint
}

#[test]
fn no_export_path_can_return_unjournaled_revision_bytes() {
    let root = tempfile::tempdir().expect("a temp dir");
    let mut provider_endpoint = endpoint(root.path(), Role::Provider, provider(), admits());
    let error = provider_endpoint
        .propose_bond(network(), bond_funding(), bond_terms())
        .expect_err("the export path cannot sign past a missing ScanArmed");
    assert!(matches!(error, SetupExchangeError::Store(_)));
    assert!(
        provider_endpoint.state().bundle_bytes().is_none(),
        "no bytes exist for a caller to export when the durable guard refuses",
    );
    drop(provider_endpoint);
    assert!(
        reopen(root.path(), Role::Provider)
            .state()
            .bundle_bytes()
            .is_none(),
        "the refusal is also the recovered state",
    );
}

// ── An in-memory pipe pair, so the wire is a real wire ────────────────

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

fn transport_pair() -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let dialer = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
        },
        hellas_wire::TransportContext::default(),
    );
    let listener = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
        },
        hellas_wire::TransportContext::default(),
    );
    (dialer, listener)
}

/// Serves one setup endpoint over one transport until the caller stops
/// it.
fn serve(transport: MuxTransport, service: SetupService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkSetupServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

/// Stops the server and lets go of the journal's exclusive lock.
///
/// Every assertion about what a provider durably holds is made over a
/// journal reopened from its own files, which is only possible once the
/// process that held it is gone — so the check and the crash are the
/// same step, and no test can read a value that only ever lived in
/// memory.
async fn stop(serving: tokio::task::JoinHandle<()>, service: SetupService) {
    serving.abort();
    let _ = serving.await;
    drop(service);
}

/// Reopens one setup journal over its own files.
fn reopen(root: &std::path::Path, role: Role) -> SetupStore {
    match SetupStore::open(
        root,
        network(),
        bond_edge(),
        role,
        &Secp256k1Verifier::new(),
    ) {
        Ok(store) => store,
        Err(error) => panic!("the journal reopens: {error}"),
    }
}

// ── Reading answers ───────────────────────────────────────────────────

fn refusal_code(response: &ExchangeSetupResponse) -> WorkRefusalCode {
    match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(_) => panic!("a refusal names a defined code, got {}", refused.code),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn advanced_bundle(response: &ExchangeSetupResponse) -> Vec<u8> {
    match response.outcome.as_ref() {
        Some(Outcome::Advanced(advanced)) => advanced.bundle.clone(),
        other => panic!("expected an advanced revision, got {other:?}"),
    }
}

// ── The whole handshake, over a real transport ────────────────────────

/// Two endpoints that have never met complete the handshake, and what
/// comes out of it is two executable transactions.
#[tokio::test]
async fn two_endpoints_that_have_never_met_open_a_channel() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let client_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());

    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    // The client holds nothing and asks for the provider's proposal.
    assert_eq!(caller.state().revision(), None);
    if let Err(error) = exchange_setup(dialer.clone(), &mut caller).await {
        panic!("the first exchange completes: {error}");
    }
    arm(&mut caller);
    assert_eq!(
        caller.state().revision(),
        Some(1),
        "the client now holds the provider's bond proposal",
    );

    // The client fixes both of its own choices, durably, before either
    // signature can leave.
    if let Err(error) = caller.propose_payment(payment_funding(), payment_terms(bond_edge())) {
        panic!("the client proposes its payment: {error}");
    }
    assert_eq!(caller.state().revision(), Some(2));

    // The second exchange carries it, and comes back countersigned.
    if let Err(error) = exchange_setup(dialer, &mut caller).await {
        panic!("the second exchange completes: {error}");
    }
    assert_eq!(
        caller.state().revision(),
        Some(3),
        "the client holds the completed handshake",
    );
    stop(serving, service).await;

    // Both endpoints hold the same artifact, byte for byte.
    let provider = reopen(provider_root.path(), Role::Provider);
    let provider_bytes = provider
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("the provider holds the completed handshake");
    assert_eq!(
        caller.state().bundle_bytes(),
        Some(provider_bytes.as_slice()),
        "the two journals hold the same revision 3",
    );

    // And what it holds is two transactions the kernel can execute.
    let bundle = match WorkChannelSetupBundleV1::decode(&provider_bytes) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the completed handshake decodes: {error}"),
    };
    assert_eq!(bundle.check(&Secp256k1Verifier::new()), Ok(()));
    assert!(bundle.bond_open().is_some(), "the bond open is executable");
    assert!(
        bundle.payment_open().is_some(),
        "the payment open is executable",
    );
    assert_eq!(bundle.bond_edge(), bond_edge());
}

/// Terms the provider's own configuration refuses are terms it does not
/// countersign — and it writes nothing when it refuses them.
///
/// Each of the four fields revision 2 leaves to the client, moved on its
/// own with the other three at the fixture's admitted values.
///
/// What each case checks is the same two facts — the refusal is
/// `Declined`, and the provider's reopened journal is still at revision
/// 2. The second is the load-bearing one: revision 3 *is* the
/// provider's countersignature, so a journal that stops at 2 is a
/// provider that did not make one. The offered revision itself is
/// retained, which is the order `advance` has always had — the client's
/// bytes are journaled, and only the provider's own signature is
/// withheld.
#[tokio::test]
async fn a_provider_does_not_countersign_terms_its_own_policy_refuses() {
    let base = payment_terms(bond_edge());
    let refused: [(&str, WorkPaymentTerms); 3] = [
        (
            "a credit policy that is not this provider's",
            WorkPaymentTerms {
                private_policy_commitment: private_policy_commitment(
                    network(),
                    &SALT,
                    &other_channel_policy(),
                ),
                ..base.clone()
            },
        ),
        (
            "an omission bond that does not exceed the capacity it insures",
            WorkPaymentTerms {
                omission_bond: 1,
                ..base.clone()
            },
        ),
        (
            "a Start span below this profile's fixed span",
            WorkPaymentTerms {
                start_validity_blocks: hellas_kernel::MAX_START_VALIDITY_BLOCKS - 1,
                ..base.clone()
            },
        ),
    ];

    for (what, terms) in refused {
        let provider_root = tempfile::tempdir().expect("a temp dir");
        let client_root = tempfile::tempdir().expect("a temp dir");
        let service = SetupService::new(proposing_provider(provider_root.path()));
        let mut proposing_policy = provider_policy();
        if terms.private_policy_commitment != base.private_policy_commitment {
            proposing_policy.channel_policy = other_channel_policy();
        }
        let mut caller = endpoint(
            client_root.path(),
            Role::Client,
            client(),
            PaymentAdmission::Proposes(Box::new(proposing_policy)),
        );
        let (dialer, listener) = transport_pair();
        let serving = serve(listener, service.clone());

        if let Err(error) = exchange_setup(dialer.clone(), &mut caller).await {
            panic!("the first exchange completes: {error}");
        }
        arm(&mut caller);
        if let Err(error) = caller.propose_payment(payment_funding(), terms) {
            panic!("the client is free to propose {what}: {error}");
        }
        assert_eq!(caller.state().revision(), Some(2));

        match exchange_setup(dialer, &mut caller).await {
            Err(SetupExchangeError::Refused { refusal, reason }) => {
                assert_eq!(
                    refusal,
                    hellas_work::work::WorkRefusal::Declined,
                    "{what}: refused as {refusal} — {reason}",
                );
            }
            other => panic!("{what} is countersigned rather than refused: {other:?}"),
        }
        stop(serving, service).await;

        assert_eq!(
            reopen(provider_root.path(), Role::Provider)
                .state()
                .revision(),
            Some(2),
            "{what}: the provider countersigned terms it was configured to refuse",
        );
        assert_eq!(
            caller.state().revision(),
            Some(2),
            "{what}: the client's own revision is untouched by the refusal",
        );
    }

    // The same four fields at the values this provider admits complete
    // the handshake, which is what says the refusals above were the
    // mutations and not the fixture.
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let client_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());
    complete(&dialer, &mut caller).await;
    assert_eq!(caller.state().revision(), Some(3));
    stop(serving, service).await;
}

/// An endpoint that proposes payment terms does not countersign them,
/// whoever asks and however good the terms are.
///
/// The terms offered here are the ones the provider admits in the test
/// above, so what refuses them is the admission and not the economics.
#[tokio::test]
async fn a_proposing_endpoint_declines_to_countersign_admissible_terms() {
    let root = tempfile::tempdir().expect("a temp dir");
    let mut proposer = endpoint(root.path(), Role::Provider, provider(), proposes());
    arm(&mut proposer);
    if let Err(error) = proposer.propose_bond(network(), bond_funding(), bond_terms()) {
        panic!("the fixture provider proposes its bond: {error}");
    }
    let service = SetupService::new(proposer);

    let client_root = tempfile::tempdir().expect("a temp dir");
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    if let Err(error) = exchange_setup(dialer.clone(), &mut caller).await {
        panic!("the first exchange completes: {error}");
    }
    arm(&mut caller);
    if let Err(error) = caller.propose_payment(payment_funding(), payment_terms(bond_edge())) {
        panic!("the client proposes its payment: {error}");
    }
    match exchange_setup(dialer, &mut caller).await {
        Err(SetupExchangeError::Refused { refusal, .. }) => {
            assert_eq!(refusal, hellas_work::work::WorkRefusal::Declined);
        }
        other => panic!("a proposing endpoint countersigned: {other:?}"),
    }
    stop(serving, service).await;
    assert_eq!(
        reopen(root.path(), Role::Provider).state().revision(),
        Some(2),
        "the offered revision is retained; the countersignature that would be revision 3 is not",
    );
}

/// The provider's countersignature is over *this* payment open, and
/// over nothing else it could be confused with.
///
/// The negative half is the point. A signature that verified over the
/// bond hash as well would be one this test could not tell from a
/// signature over the right hash, and `check` — which is the only other
/// thing that looks at it — reads the same field.
#[tokio::test]
async fn the_answer_is_signed_over_this_payment_open_and_no_other_hash() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let client_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    complete(&dialer, &mut caller).await;
    stop(serving, service).await;

    let bytes = caller
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("a completed handshake");
    let bundle = match WorkChannelSetupBundleV1::decode(&bytes) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the completed handshake decodes: {error}"),
    };
    let Some(payment_hash) = bundle.payment_open_hash() else {
        panic!("a completed handshake has a payment open hash");
    };
    let Some(hellas_kernel::Tx::Open { taker_auth, .. }) = bundle.payment_open() else {
        panic!("a completed handshake has an executable payment open");
    };
    // Maker is the client on the payment leg, so the provider's
    // countersignature is the taker's.
    let verifier = Secp256k1Verifier::new();
    assert!(
        verifier.verify_auth(&taker_auth, provider().party_key(), payment_hash),
        "the provider signed the payment open",
    );
    assert!(
        !verifier.verify_auth(&taker_auth, provider().party_key(), bundle.bond_open_hash()),
        "the same signature does not also verify over the bond open",
    );
    assert!(
        !verifier.verify_auth(&taker_auth, client().party_key(), payment_hash),
        "and it is not the client's signature",
    );
}

// ── Reply after durable ───────────────────────────────────────────────

/// Every revision is on the disk before the signature it carries
/// leaves, on both sides.
///
/// Proved by killing both endpoints and reopening their journals from
/// their own files: what a reopened journal holds is exactly what the
/// peer was handed. Move the provider's `commit` after the return in
/// `SetupEndpoint::advance` and this fails with the reopened provider
/// journal at revision 2 while the client holds revision 3 — a
/// countersignature the provider has no record of making.
#[tokio::test]
async fn every_revision_is_durable_before_its_signature_leaves() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let client_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    complete(&dialer, &mut caller).await;
    let delivered = caller
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("a completed handshake");
    stop(serving, service).await;
    drop(dialer);
    drop(caller);

    // Both processes die and come back over their own files.
    let recovered_provider = reopen(provider_root.path(), Role::Provider);
    let recovered_client = reopen(client_root.path(), Role::Client);
    assert_eq!(
        recovered_provider.state().revision(),
        Some(3),
        "the provider's disk holds the countersignature it exported",
    );
    assert_eq!(
        recovered_provider.state().bundle_bytes(),
        Some(delivered.as_slice()),
        "and holds exactly the bytes the client was handed",
    );
    assert_eq!(
        recovered_client.state().revision(),
        Some(3),
        "the client's disk holds the answer it acted on",
    );
    assert_eq!(
        recovered_client.state().bundle_bytes(),
        Some(delivered.as_slice()),
    );
}

/// A replayed revision is answered with the same bytes and writes
/// nothing.
///
/// The journal is what makes this true: it recognises the revision it
/// already holds and refuses to append it twice. Delete
/// `Applied::Redundant` for a bundle the state already equals and this
/// fails on the record count, having written a second copy of the
/// completed handshake.
#[tokio::test]
async fn a_replay_is_answered_the_same_and_writes_nothing() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let client_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut caller = endpoint(client_root.path(), Role::Client, client(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    complete(&dialer, &mut caller).await;
    let first = caller
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("a completed handshake");

    // The client, having lost the answer, asks again with revision 3.
    let response = match WorkSetupClientImpl::new(dialer)
        .exchange_setup(ExchangeSetupRequest {
            bundle: first.clone(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the replay completes: {status}"),
    };
    stop(serving, service).await;

    assert_eq!(
        advanced_bundle(&response),
        first,
        "the replay is answered with the same bytes",
    );
    let provider = reopen(provider_root.path(), Role::Provider);
    assert_eq!(
        provider.len(),
        4,
        "the journal holds one record per revision and nothing for the replay",
    );
    assert_eq!(provider.state().bundle_bytes(), Some(first.as_slice()));
}

// ── What the exchange refuses ─────────────────────────────────────────

/// A provider that has proposed no bond has nothing to offer, and says
/// so as the one refusal a caller may retry unchanged.
#[tokio::test]
async fn a_provider_with_no_proposal_is_not_ready() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(endpoint(
        provider_root.path(),
        Role::Provider,
        provider(),
        admits(),
    ));
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service);

    let response = match WorkSetupClientImpl::new(dialer)
        .exchange_setup(ExchangeSetupRequest { bundle: Vec::new() })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    serving.abort();
    assert_eq!(refusal_code(&response), WorkRefusalCode::NotReady);
}

/// A stranger cannot make the provider countersign anything.
///
/// This is the whole of why the exchange needs no connection binding:
/// the authority is in the artifact, not in who is holding it. The
/// stranger's revision 2 is well formed, extends the provider's own
/// revision 1, and is signed with a real secp256k1 key — and the
/// provider refuses it, because the key is not the one its bond terms
/// name as taker.
///
/// Delete the client-signature check in `WorkChannelSetupBundleV1::check`
/// and this fails: the provider countersigns a payment channel funded
/// by coins the client never agreed to lock.
#[tokio::test]
async fn a_stranger_cannot_make_the_provider_countersign() {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let stranger_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let mut interloper = endpoint(stranger_root.path(), Role::Client, stranger(), proposes());
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    // The stranger legitimately learns revision 1 — it is a public
    // proposal, and it will be a public transaction.
    if let Err(error) = exchange_setup(dialer.clone(), &mut interloper).await {
        panic!("the proposal is public: {error}");
    }
    arm(&mut interloper);
    assert_eq!(interloper.state().revision(), Some(1));

    // And cannot journal a revision 2 over it, because its own store
    // runs the same check the provider's will.
    let refused = interloper.propose_payment(payment_funding(), payment_terms(bond_edge()));
    let Err(SetupExchangeError::Store(error)) = refused else {
        panic!("a stranger's revision 2 is refused, got {refused:?}");
    };
    assert!(
        error.to_string().contains("client"),
        "the refusal names the party that did not sign, got {error}",
    );

    // Nor can it get one past the provider by building the bytes by
    // hand and putting them on the wire.
    let forged = forged_revision_two();
    let response = match WorkSetupClientImpl::new(dialer)
        .exchange_setup(ExchangeSetupRequest { bundle: forged })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    stop(serving, service).await;
    assert_eq!(refusal_code(&response), WorkRefusalCode::Invalid);

    let provider = reopen(provider_root.path(), Role::Provider);
    assert_eq!(
        provider.state().revision(),
        Some(1),
        "the provider's journal is where it was",
    );
}

/// A revision over another bond is refused, and the journal is left
/// where it was.
///
/// Delete the `bond_edge` comparison in `SetupState::apply_bundle` and
/// this fails: the provider countersigns a payment over bond terms it
/// never proposed, having replaced its own revision 1 with the
/// caller's. Note what does *not* catch this — `check_extends` compares
/// the revision number first, and a well-formed revision 2 passes that;
/// its prefix comparison then never runs, because the journal has
/// already been told this is the same handshake.
#[tokio::test]
async fn a_revision_over_another_bond_is_refused() {
    let response = refused_by_a_proposing_provider(rewritten_revision_two()).await;
    assert_eq!(refusal_code(&response.0), WorkRefusalCode::Invalid);
    assert!(
        response.1.contains("bond edge"),
        "the refusal names the field that disagreed, got {}",
        response.1,
    );
}

/// A revision that skips the one this endpoint is waiting for is
/// refused.
///
/// The scenario is a provider that has lost its journal and been
/// reconfigured back to its own proposal, and a client that answers
/// with the completed handshake it still holds. It is the same bond,
/// the same network, and every signature in it is real — and it is
/// still not something this endpoint may adopt, because a revision 3 it
/// never produced is a countersignature it has no record of making.
///
/// Delete `check_extends` in `SetupState::apply_bundle` and this fails:
/// the provider adopts the completed handshake and answers with it,
/// having signed nothing.
#[tokio::test]
async fn a_revision_that_skips_the_expected_one_is_refused() {
    let response = refused_by_a_proposing_provider(complete_revision_three()).await;
    assert_eq!(refusal_code(&response.0), WorkRefusalCode::Invalid);
    assert!(
        response.1.contains("revision 3, not the expected 2"),
        "the refusal names the revision it wanted, got {}",
        response.1,
    );
}

/// Offers `bundle` to a provider holding only its own proposal, and
/// returns the answer once the journal has been checked for damage.
async fn refused_by_a_proposing_provider(bundle: Vec<u8>) -> (ExchangeSetupResponse, String) {
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let service = SetupService::new(proposing_provider(provider_root.path()));
    let (dialer, listener) = transport_pair();
    let serving = serve(listener, service.clone());

    let response = match WorkSetupClientImpl::new(dialer)
        .exchange_setup(ExchangeSetupRequest { bundle })
        .await
    {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    };
    stop(serving, service).await;

    let provider = reopen(provider_root.path(), Role::Provider);
    assert_eq!(
        provider.state().revision(),
        Some(1),
        "the provider still holds only its own proposal",
    );
    assert_eq!(
        provider.len(),
        2,
        "and wrote nothing for the revision it refused",
    );
    let reason = match response.outcome.as_ref() {
        Some(Outcome::Refused(refused)) => refused.reason.clone(),
        other => panic!("expected a refusal, got {other:?}"),
    };
    (response, reason)
}

// ── The wire shapes ───────────────────────────────────────────────────

/// The field numbers this exchange occupies, pinned.
///
/// A round trip cannot see a tag that moved in the encoder and the
/// decoder together; two peers built from different revisions of the
/// proto can. Every byte below is written out by hand rather than
/// produced by the same prost that is being checked.
#[test]
fn the_wire_field_numbers_are_pinned() {
    assert_eq!(
        ExchangeSetupRequest {
            bundle: vec![0xab, 0xcd],
        }
        .encode_to_vec(),
        // field 1, length-delimited: (1 << 3) | 2 == 0x0a
        vec![0x0a, 0x02, 0xab, 0xcd],
    );
    assert_eq!(
        SetupAdvanced {
            bundle: vec![0xab, 0xcd],
        }
        .encode_to_vec(),
        vec![0x0a, 0x02, 0xab, 0xcd],
    );
    assert_eq!(
        ExchangeSetupResponse {
            outcome: Some(Outcome::Advanced(SetupAdvanced { bundle: vec![0x01] })),
        }
        .encode_to_vec(),
        // outcome field 1 wrapping a SetupAdvanced whose field 1 is one
        // byte long.
        vec![0x0a, 0x03, 0x0a, 0x01, 0x01],
    );
    assert_eq!(
        ExchangeSetupResponse {
            outcome: Some(Outcome::Refused(WorkRefused {
                code: WorkRefusalCode::NotReady as i32,
                reason: String::new(),
            })),
        }
        .encode_to_vec(),
        // outcome field 2 wrapping a WorkRefused whose field 1 is the
        // varint 1 and whose empty field 2 is not written.
        vec![0x12, 0x02, 0x08, 0x01],
    );
}

/// The service and method this exchange is dialed on.
///
/// The numeric ids are pinned beside every other service's in
/// `hellas_rpc::pb`; what is pinned here is the name a peer resolves
/// and the ALPN a listener binds, which no id assertion covers.
#[test]
fn the_service_is_reachable_by_its_own_name() {
    assert_eq!(
        <WorkSetup as ServiceMarker>::NAME,
        "hellas.work.v1.WorkSetup",
    );
    assert_eq!(
        <WorkSetup as ServiceMarker>::ALPN,
        "/hellas.work.v1.WorkSetup/2.0",
    );
}

// ── Helpers that build what an honest endpoint would not ──────────────

/// Runs the whole handshake against a served provider.
async fn complete(dialer: &MuxTransport, caller: &mut SetupEndpoint) {
    if let Err(error) = exchange_setup(dialer.clone(), caller).await {
        panic!("the first exchange completes: {error}");
    }
    arm(caller);
    if let Err(error) = caller.propose_payment(payment_funding(), payment_terms(bond_edge())) {
        panic!("the client proposes its payment: {error}");
    }
    if let Err(error) = exchange_setup(dialer.clone(), caller).await {
        panic!("the second exchange completes: {error}");
    }
}

/// Revision 2 over the provider's real proposal, signed by a key the
/// bond terms do not name.
fn forged_revision_two() -> Vec<u8> {
    revision_two_signed_by(&stranger(), bond_terms()).encode()
}

/// Revision 2 over a *different* bond proposal, which is what a caller
/// that had rewritten the provider's own would send.
fn rewritten_revision_two() -> Vec<u8> {
    let mut terms = bond_terms();
    terms.max_job_price = 40_000;
    revision_two_signed_by(&client(), terms).encode()
}

/// The completed handshake over this provider's own bond, built without
/// the provider taking part.
///
/// Both parties' real keys, because the point is not a forgery: it is a
/// revision that is valid everywhere except in the order this endpoint
/// reached it.
fn complete_revision_three() -> Vec<u8> {
    let two = revision_two_signed_by(&client(), bond_terms());
    let Some(hash) = two.payment_open_hash() else {
        panic!("a proposed payment has an open hash");
    };
    match two.countersign_payment(hellas_kernel::Auth::native(provider().sign(hash))) {
        Ok(bundle) => bundle.encode(),
        Err(error) => panic!("the fixture payment countersigns: {error}"),
    }
}

fn revision_two_signed_by(
    caller: &Secp256k1Signer,
    terms: WorkStakeBondTerms,
) -> WorkChannelSetupBundleV1 {
    let bond_hash = Tx::open_hash(
        network(),
        &bond_funding(),
        &Terms::work_stake_bond(terms.clone()),
    );
    let bundle = match WorkChannelSetupBundleV1::propose_bond(
        network(),
        bond_funding(),
        terms.clone(),
        hellas_kernel::Auth::native(provider().sign(bond_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture bond proposes: {error}"),
    };
    let payment = WorkPaymentTerms {
        bond_edge: bundle.bond_edge(),
        bond_terms: terms,
        ..payment_terms(bundle.bond_edge())
    };
    let payment_hash = Tx::open_hash(
        network(),
        &payment_funding(),
        &Terms::work_payment(payment.clone()),
    );
    match bundle.countersign_bond_and_propose_payment(
        hellas_kernel::Auth::native(caller.sign(bond_hash)),
        payment_funding(),
        payment,
        hellas_kernel::Auth::native(caller.sign(payment_hash)),
    ) {
        Ok(bundle) => bundle,
        Err(error) => panic!("the fixture payment proposes: {error}"),
    }
}
