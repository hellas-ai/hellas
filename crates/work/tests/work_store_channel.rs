//! One channel's durable ledger: what survives a crash, what a restart
//! may still do, and what it may never do twice.
//!
//! Every crash here is a real one: the store is dropped, its files are
//! left exactly as they were, and a new store is opened over them. The
//! assertions are about the second process — never about what the first
//! one intended.

use hellas_work::test_support::paid::{
    client, identity_artifact, manifest, network, payload_at, prompt_tokens, provider,
    text_execution, text_policy, transcript_for as transcript_of,
};

use hellas_auth::Digest;
use hellas_auth::PublicKey;
use hellas_kernel::{
    BlockHeight, EarnedCertificate, EdgeId, EdgeValues, Encode as _, Fees, List, MAX_EDGE_OUTPUTS,
    Parties, Party, PartyAuth, PartyKeys, PayloadHash, Payout, Secp256k1Verifier, Sig, TermsHash,
    WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::protocol::artifacts::InputAddressed as _;
use hellas_rpc::{Assurance, Evaluate, EvaluateRequest, OutputEventEnvelope};
use hellas_work::model::prepared_input::PreparedPaidInputV1;
use hellas_work::model::work::{
    PaidChannel, PaidChannelPolicyV1, PaidJobAuthorizationV2, PaidJobResultV1, PaidWorkError,
    PaymentBindingV1, PrivateRecord as _, decode_transcript, encode_transcript, next_payment,
    payment_binding_digest, prepared_input_digest, private_policy_commitment, result_digest,
    terminal_result, work_id,
};
use hellas_work::work_store::channel::funding::{Clock, FinalizedHeight};
use hellas_work::work_store::journal::{Journal, JournalError, JournalId, JournalKind};
use hellas_work::work_store::{
    ChannelRecord, ChannelStateError, ChannelStore, JobPhase, JobState, Role, SetupOrigin,
    TerminalOutcome, WorkStoreError,
};

mod support;
use support::temp;

// ── Fixture ───────────────────────────────────────────────────────────

const HORIZON: u64 = 500;
const PRICE: u64 = 10;
/// Two jobs' worth of credit, and not three: a limit that is a multiple
/// of the price cannot tell "at the limit" from "one job short of it".
const COMPUTE_LIMIT: u64 = 25;
const DELIVERY_LIMIT: u64 = 25;
const OMISSION_BOND: u64 = 4;
const PAYMENT_VALUE: u64 = 1_000;
const SALT: [u8; 32] = [0x5a; 32];

fn channel_policy() -> PaidChannelPolicyV1 {
    limits(COMPUTE_LIMIT, DELIVERY_LIMIT)
}

const fn limits(compute: u64, delivery: u64) -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: compute,
        delivery_credit_limit: delivery,
    }
}

fn bond_terms() -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(
            PartyKeys::sole(provider().party_key()),
            PartyKeys::sole(client().party_key()),
        ),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

fn terms_for(policy: PaidChannelPolicyV1) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0xb0; 32]),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &policy),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn channel_on(payment_edge: EdgeId) -> PaidChannel {
    channel_with(payment_edge, channel_policy())
}

/// A channel whose credit policy is the one it commits to, so a test
/// can move one limit without moving the other.
fn channel_with(payment_edge: EdgeId, policy: PaidChannelPolicyV1) -> PaidChannel {
    match PaidChannel::new(network(), payment_edge, terms_for(policy), &SALT, policy) {
        Ok(channel) => channel,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

fn channel() -> PaidChannel {
    channel_on(EdgeId::from_bytes([0xe1; 32]))
}

fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) =
        work_payment_settlement(EdgeValues::new(PAYMENT_VALUE, 0, Fees::ZERO), OMISSION_BOND)
    else {
        panic!("a funded edge prices both exits");
    };
    settlement
}

async fn open(root: &std::path::Path, role: Role) -> ChannelStore {
    open_on(root, channel(), role).await
}

async fn open_on(root: &std::path::Path, channel: PaidChannel, role: Role) -> ChannelStore {
    let origin = origin_of(&channel);
    match ChannelStore::open(
        root,
        channel,
        settlement(),
        role,
        origin,
        &Secp256k1Verifier::new(),
    )
    .await
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    }
}

/// Where a fixture channel was opened: the block before the one a
/// client records its receipt at, so a fixture cursor record is the
/// contiguous next block and nothing has to be skipped to reach it.
fn origin_of(channel: &PaidChannel) -> SetupOrigin {
    SetupOrigin {
        payment_edge: channel.payment_edge(),
        height: RECEIPT_HEIGHT - 1,
        payload: payload_at(RECEIPT_HEIGHT - 1),
        parent: payload_at(RECEIPT_HEIGHT - 2),
    }
}

fn payload(digest: Digest) -> PayloadHash {
    PayloadHash::from_bytes(digest.into_bytes())
}

// ── The prepared inputs a job executes from ───────────────────────────

/// One job's request. The nonce moves with the proposal nonce, so two
/// jobs on one channel are two different prepared bundles.
fn evaluate_request(nonce: u64) -> EvaluateRequest {
    let mut bytes = [0x77; 32];
    bytes[..8].copy_from_slice(&nonce.to_be_bytes());
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: bytes,
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle(nonce: u64) -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(nonce),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn bundle_bytes(nonce: u64) -> Vec<u8> {
    match bundle(nonce).encode() {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture bundle encodes: {error}"),
    }
}

fn spool(transcript: &[OutputEventEnvelope]) -> Vec<u8> {
    match encode_transcript(transcript) {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture transcript encodes: {error}"),
    }
}

/// Everything one job's records are built from, at one ledger position.
struct Job {
    authorization: PaidJobAuthorizationV2,
    work_id: Digest,
    result: PaidJobResultV1,
    transcript: Vec<OutputEventEnvelope>,
    binding: PaymentBindingV1,
    certificate: EarnedCertificate,
}

fn job_at(channel: &PaidChannel, nonce: u64, credited: u64) -> Job {
    let authorization = authorization_for(channel, nonce);
    let work_id = work_id(channel, &authorization);
    // The result is derived from a real transcript rather than made up:
    // the store rebuilds it from the stored events, so a hand-written
    // pair of digests is not a result any journal here would take.
    let transcript = transcript_of(&evaluate_request(nonce), &[101, 102, 103]);
    let result = match terminal_result(channel, &authorization, &transcript) {
        Ok(result) => result,
        Err(error) => panic!("the fixture transcript is a terminal: {error}"),
    };
    let (certificate, binding) =
        match next_payment(channel, &authorization, &result, credited, settlement()) {
            Ok(payment) => payment,
            Err(error) => panic!("the fixture payment builds: {error}"),
        };
    Job {
        authorization,
        work_id,
        result,
        transcript,
        binding,
        certificate,
    }
}

fn authorization_for(channel: &PaidChannel, nonce: u64) -> PaidJobAuthorizationV2 {
    let terms = channel.payment_terms();
    PaidJobAuthorizationV2 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        work_policy_digest: Digest::from_bytes([0x31; 32]),
        payment_policy_digest: Digest::from_bytes([0xec; 32]),
        prepared_input_digest: match prepared_input_digest(channel, &bundle(nonce)) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture bundle hashes: {error}"),
        },
        proposal_nonce: nonce,
        acceptance_deadline: 160,
        request_commitment: Evaluate::commit_request(&evaluate_request(nonce)),
        environment_commitment: manifest().content_id(),
        price: PRICE,
        terminal_deadline: 200,
        payment_deadline: 300,
    }
}

impl Job {
    fn proposed(&self) -> ChannelRecord {
        ChannelRecord::JobProposed {
            authorization: self.authorization,
            client_signature: client().sign(payload(self.work_id)),
            prepared_input: bundle_bytes(self.authorization.proposal_nonce),
        }
    }

    fn accepted(&self) -> ChannelRecord {
        ChannelRecord::JobAccepted {
            work_id: self.work_id,
            provider_signature: provider().sign(payload(self.work_id)),
        }
    }

    fn result_record(&self, channel: &PaidChannel) -> ChannelRecord {
        ChannelRecord::JobResult {
            work_id: self.work_id,
            result: self.result,
            provider_signature: provider().sign(payload(result_digest(channel, &self.result))),
            transcript: spool(&self.transcript),
        }
    }

    fn paid(&self, channel: &PaidChannel) -> ChannelRecord {
        ChannelRecord::JobTerminated {
            work_id: self.work_id,
            outcome: TerminalOutcome::Certified {
                certificate: self.certificate,
                binding: Box::new(self.binding),
                binding_signature: client()
                    .sign(payload(payment_binding_digest(channel, &self.binding))),
                certificate_signature: client().sign(self.certificate.digest(channel.network())),
            },
        }
    }
}

/// The provider's whole sequence for one job, in order.
async fn provider_sequence(channel: &PaidChannel, job: &Job) -> Vec<ChannelRecord> {
    vec![
        job.proposed(),
        job.accepted(),
        ChannelRecord::JobRunning {
            work_id: job.work_id,
        },
        job.result_record(channel),
        ChannelRecord::PlaintextReleased {
            work_id: job.work_id,
        },
        job.paid(channel),
    ]
}

/// The client's whole sequence for the same job.
///
/// It opens with a cursor because a client records a receipt against a
/// finalized height: the terminal deadline is what a late delivery is
/// late against, and a journal with no processed block cannot say.
async fn client_sequence(channel: &PaidChannel, job: &Job) -> Vec<ChannelRecord> {
    vec![
        cursor_at(RECEIPT_HEIGHT),
        job.proposed(),
        job.accepted(),
        job.result_record(channel),
        ChannelRecord::ResultMatched {
            work_id: job.work_id,
        },
        job.paid(channel),
    ]
}

/// A finalized height inside every fixture job's terminal deadline.
const RECEIPT_HEIGHT: u64 = 150;

fn cursor_at(height: u64) -> ChannelRecord {
    ChannelRecord::CursorAdvanced {
        height,
        parent: payload_at(height.saturating_sub(1)),
        payload: payload_at(height),
    }
}

/// Moves one store's cursor to `height`, one block at a time.
async fn advance(store: &mut ChannelStore, height: u64) {
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= height {
        commit_all(store, &[cursor_at(next)]).await;
        next += 1;
    }
}

async fn commit_all(store: &mut ChannelStore, records: &[ChannelRecord]) {
    let verifier = Secp256k1Verifier::new();
    for record in records {
        if let Err(error) = store.commit(record.clone(), &verifier).await {
            panic!("the fixture record commits: {error}");
        }
    }
}

async fn open_metadata(root: &std::path::Path) -> ChannelStore {
    ChannelStore::open_metadata_only(
        root,
        channel(),
        settlement(),
        Role::Provider,
        origin_of(&channel()),
        &Secp256k1Verifier::new(),
    )
    .await
    .expect("metadata provider journal opens")
}

fn assert_payloads_absent(root: &std::path::Path, needles: &[&[u8]]) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_payloads_absent(&path, needles);
        } else {
            let bytes = std::fs::read(&path).unwrap();
            for needle in needles {
                assert!(!needle.is_empty());
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == *needle),
                    "customer payload reached {}",
                    path.display()
                );
            }
        }
    }
}

#[tokio::test]
async fn metadata_journal_never_writes_payloads_at_any_commit_or_rotation() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let sequence = provider_sequence(&channel, &job).await;
    let input = bundle_bytes(1);
    let output = spool(&job.transcript);
    let payloads = [&input[..], &output[..], job.transcript[0].payload()];
    for boundary in 1..=sequence.len() {
        let root = temp();
        let mut store = open_metadata(root.path()).await;
        for record in &sequence[..boundary] {
            store
                .commit(record.clone(), &Secp256k1Verifier::new())
                .await
                .unwrap();
            assert_payloads_absent(root.path(), &payloads);
        }
        if let Some(active) = store.state().job_by_id(job.work_id) {
            assert_eq!(active.prepared_input(), input);
            if active.result().is_some() {
                assert_eq!(active.transcript(), output);
            }
        }
        store.rotate().await.unwrap();
        assert_payloads_absent(root.path(), &payloads);
        drop(store);
        let reopened = open_metadata(root.path()).await;
        if let Some(active) = reopened.state().job_by_id(job.work_id) {
            assert!(active.prepared_input().is_empty());
            assert!(active.transcript().is_empty());
            assert_eq!(active.authorization(), &job.authorization);
        } else {
            assert_eq!(reopened.state().ledger().credited_cumulative(), PRICE);
        }
    }
}

#[tokio::test]
async fn metadata_journal_can_credit_an_already_delivered_result_after_restart() {
    let root = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open_metadata(root.path()).await;
    commit_all(&mut store, &provider_sequence(&channel, &job).await[..5]).await;
    drop(store);
    let mut recovered = open_metadata(root.path()).await;
    recovered
        .commit(job.paid(&channel), &Secp256k1Verifier::new())
        .await
        .unwrap();
    assert_eq!(recovered.state().ledger().credited_cumulative(), PRICE);
    recovered.rotate().await.unwrap();
    drop(recovered);
    assert_eq!(
        open_metadata(root.path())
            .await
            .state()
            .ledger()
            .credited_cumulative(),
        PRICE
    );
}

#[tokio::test]
async fn metadata_replay_does_not_weaken_live_payload_validation() {
    let root = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open_metadata(root.path()).await;
    let mut proposal = job.proposed();
    if let ChannelRecord::JobProposed { prepared_input, .. } = &mut proposal {
        prepared_input.clear();
    }
    assert!(
        store
            .commit(proposal, &Secp256k1Verifier::new())
            .await
            .is_err()
    );
    assert!(store.is_empty());
    commit_all(&mut store, &provider_sequence(&channel, &job).await[..3]).await;
    let mut result = job.result_record(&channel);
    if let ChannelRecord::JobResult { transcript, .. } = &mut result {
        transcript.clear();
    }
    let records = store.len();
    assert!(
        store
            .commit(result, &Secp256k1Verifier::new())
            .await
            .is_err()
    );
    assert_eq!(store.len(), records);
}

#[tokio::test]
async fn journal_retention_mode_cannot_change_when_reopened() {
    for metadata in [false, true] {
        let root = temp();
        let store = if metadata {
            open_metadata(root.path()).await
        } else {
            open(root.path(), Role::Provider).await
        };
        drop(store);
        let reopened = if metadata {
            ChannelStore::open(
                root.path(),
                channel(),
                settlement(),
                Role::Provider,
                origin_of(&channel()),
                &Secp256k1Verifier::new(),
            )
            .await
        } else {
            ChannelStore::open_metadata_only(
                root.path(),
                channel(),
                settlement(),
                Role::Provider,
                origin_of(&channel()),
                &Secp256k1Verifier::new(),
            )
            .await
        };
        assert!(
            reopened.is_err(),
            "retention mode is part of journal identity"
        );
    }
}

// ── The happy path ────────────────────────────────────────────────────

/// One paid job credits its certificate and rests at a certified
/// terminal, and the channel's one job is closed for good.
#[tokio::test]
async fn one_paid_job_moves_every_ledger_once() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider).await;

    commit_all(&mut store, &provider_sequence(&channel, &job).await).await;

    let state = store.state();
    assert!(state.jobs().next().is_none(), "a paid job is closed");
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    assert!(
        matches!(
            state.terminals().next().map(|terminal| &terminal.outcome),
            Some(TerminalOutcome::Certified { .. })
        ),
        "the one job rests at a certified terminal",
    );
    assert_eq!(state.max_executable_certificate(), PRICE);
}

/// The same sequence on the client, whose one certificate credits the
/// same cumulative it signed.
#[tokio::test]
async fn the_client_credits_the_same_payment_it_signed() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Client).await;

    commit_all(&mut store, &client_sequence(&channel, &job).await).await;

    let state = store.state();
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    assert!(state.jobs().next().is_none());
    assert!(
        matches!(
            state.terminals().next().map(|terminal| &terminal.outcome),
            Some(TerminalOutcome::Certified { .. })
        ),
        "the one job rests at a certified terminal",
    );
}

/// The sole authorization a channel ever admits carries nonce 1.
///
/// The nonce is a fixed marker rather than a high-water mark — the
/// permanent terminal is what stops a second job — but fixed means
/// fixed: an otherwise perfectly valid first proposal whose nonce is 2,
/// correctly signed over its own `work_id`, is refused. Without this
/// check two endpoints could open the same channel's one job under two
/// different `work_id`s and disagree forever about which one it was.
#[tokio::test]
async fn proposal_nonces_advance_monotonically() {
    let dir = temp();
    let channel = channel();
    let mut store = open(dir.path(), Role::Provider).await;

    // Any positive starting nonce is legal and establishes the high-water
    // mark.
    let other = job_at(&channel, 2, 0);
    commit_all(&mut store, &[other.proposed()]).await;
    assert_eq!(store.state().proposal_nonce_high_water(), 2);

    // A lower nonce cannot be reused for another job.
    let job = job_at(&channel, 1, 0);
    let error = store
        .commit(job.proposed(), &Secp256k1Verifier::new())
        .await
        .expect_err("the proposal nonce does not move backwards");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "proposal_nonce"
            })
        ),
        "unexpected error: {error}",
    );
    assert_eq!(
        store.state().jobs().len(),
        1,
        "the first proposal remains open"
    );
}

// ── A result is its transcript's own ──────────────────────────────────

/// A result must be the one its stored transcript produces.
///
/// Two mutations of the same pairing, each varying exactly one side of
/// it. Neither touches a signature: the second is signed correctly over
/// the result it carries, which is the whole point — a provider that
/// signs a result its own events do not summarise is refused by the
/// rebuild and not by a signature check.
#[tokio::test]
async fn a_result_must_be_the_transcript_it_is_stored_beside() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider).await;
    commit_all(
        &mut store,
        &[
            job.proposed(),
            job.accepted(),
            ChannelRecord::JobRunning {
                work_id: job.work_id,
            },
        ],
    )
    .await;

    // MUTATION: the same signed result, spooled beside a transcript of
    // a different answer to the same request.
    let other_answer = transcript_of(&evaluate_request(1), &[201, 202, 203]);
    let error = store
        .commit(
            ChannelRecord::JobResult {
                work_id: job.work_id,
                result: job.result,
                provider_signature: provider().sign(payload(result_digest(&channel, &job.result))),
                transcript: spool(&other_answer),
            },
            &verifier,
        )
        .await
        .expect_err("a result is not another answer's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "result against its transcript"
            })
        ),
        "unexpected error: {error}"
    );

    // MUTATION: the same transcript, beside a result whose answer digest
    // is one byte other — and correctly signed over that other result.
    let mut altered = job.result;
    let mut digest = altered.canonical_output_digest.into_bytes();
    digest[0] ^= 1;
    altered.canonical_output_digest = Digest::from_bytes(digest);
    let error = store
        .commit(
            ChannelRecord::JobResult {
                work_id: job.work_id,
                result: altered,
                provider_signature: provider().sign(payload(result_digest(&channel, &altered))),
                transcript: spool(&job.transcript),
            },
            &verifier,
        )
        .await
        .expect_err("a transcript is not another result's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "result against its transcript"
            })
        ),
        "unexpected error: {error}"
    );

    // The control: the pair that belongs together is taken, and the
    // stored bytes are the ones offered.
    if let Err(error) = store.commit(job.result_record(&channel), &verifier).await {
        panic!("a result and its own transcript record: {error}");
    }
    let Some(open) = store.state().jobs().next() else {
        panic!("the job is open");
    };
    assert_eq!(open.phase(), JobPhase::Ready);
    assert_eq!(open.transcript(), spool(&job.transcript));
}

/// A restart finds the exact transcript the result was derived from.
///
/// This is what a spool is for: the process that computed the answer is
/// gone, and the one that comes back can still hand over the bytes it
/// was paid to produce — and can still show they rebuild the result it
/// signed.
#[tokio::test]
async fn a_restart_finds_the_transcript_the_result_was_derived_from() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &provider_sequence(&channel, &job).await[..4]).await;
    }

    let recovered = open(dir.path(), Role::Provider).await;
    let Some(open) = recovered.state().jobs().next() else {
        panic!("the job is still open");
    };
    assert_eq!(open.phase(), JobPhase::Ready);
    assert_eq!(open.transcript(), spool(&job.transcript));

    // And the bytes that came back are the answer, not merely bytes:
    // decoded and rebuilt here, independently of the store that read
    // them, they are the result the provider signed.
    let Ok(events) = decode_transcript(open.transcript(), 1 << 20) else {
        panic!("the recovered spool decodes");
    };
    assert_eq!(events, job.transcript);
    assert_eq!(
        terminal_result(&channel, &job.authorization, &events),
        Ok(job.result)
    );
}

// ── A receipt has a height, and a verdict is a step ───────────────────

/// A client records a receipt at the terminal deadline and not after it.
///
/// One block either side of the deadline the job was signed under, with
/// the cursor as the only thing varied.
#[tokio::test]
async fn the_terminal_deadline_is_the_last_height_a_receipt_may_be_recorded_at() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let deadline = job.authorization.terminal_deadline;
    for (height, timely) in [(deadline, true), (deadline + 1, false)] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Client).await;
        commit_all(&mut store, &[job.proposed(), job.accepted()]).await;
        advance(&mut store, height).await;
        let recorded = store
            .commit(job.result_record(&channel), &Secp256k1Verifier::new())
            .await;
        if timely {
            if let Err(error) = recorded {
                panic!("a receipt at {height} is timely: {error}");
            }
            continue;
        }
        let Err(error) = recorded else {
            panic!("a receipt at {height} is late");
        };
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::ReceiptLate {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "unexpected error: {error}"
        );
    }
}

/// Acceptance and dispatch consume the cursor held after their phase
/// boundary. The same cursor state `PaymentLate` reads is therefore part of
/// the durable apply, while an idempotent already-committed co-signature is
/// returned without a second deadline decision.
#[tokio::test]
async fn round3_transition_consumes_post_boundary_cursor() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let verifier = Secp256k1Verifier::new();

    for (height, timely) in [
        (job.authorization.acceptance_deadline, true),
        (job.authorization.acceptance_deadline + 1, false),
    ] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider).await;
        advance(&mut store, height).await;
        commit_all(&mut store, &[job.proposed()]).await;
        let accepted = store.commit(job.accepted(), &verifier).await;
        if timely {
            if let Err(error) = accepted {
                panic!("acceptance at its deadline is durable: {error}");
            }
            // Once committed, the same signature is idempotent even after
            // the deadline: the endpoint does not re-decide an escaped
            // authorization.
            advance(&mut store, height + 1).await;
            if let Err(error) = store.commit(job.accepted(), &verifier).await {
                panic!("a retained co-signature is not re-decided: {error}");
            }
        } else {
            assert!(matches!(
                accepted,
                Err(WorkStoreError::Channel(ChannelStateError::AcceptanceLate {
                    now,
                    deadline,
                })) if now == FinalizedHeight(height).diagnostic()
                    && deadline == FinalizedHeight(job.authorization.acceptance_deadline).diagnostic()
            ));
        }
    }

    for (height, timely) in [
        (job.authorization.terminal_deadline, true),
        (job.authorization.terminal_deadline + 1, false),
    ] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &[job.proposed(), job.accepted()]).await;
        advance(&mut store, height).await;
        let running = store
            .commit(
                ChannelRecord::JobRunning {
                    work_id: job.work_id,
                },
                &verifier,
            )
            .await;
        if timely {
            if let Err(error) = running {
                panic!("dispatch at the terminal deadline is durable: {error}");
            }
        } else {
            assert!(matches!(
                running,
                Err(WorkStoreError::Channel(ChannelStateError::DispatchLate {
                    now,
                    deadline,
                })) if now == FinalizedHeight(height).diagnostic()
                    && deadline == FinalizedHeight(job.authorization.terminal_deadline).diagnostic()
            ));
        }
    }
}

/// A client signs a payment at the payment deadline and not after it.
///
/// One block either side of the deadline the job was signed under, with
/// the cursor as the only thing varied. Past it the provider may end
/// this job as expired and charge its price to this client's loss
/// ledger, and a certificate signed then is money the provider can
/// still close on: the same job, paid for and charged for.
#[tokio::test]
async fn the_payment_deadline_is_the_last_height_a_payment_may_be_signed_at() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let deadline = job.authorization.payment_deadline;
    for (height, timely) in [(deadline, true), (deadline + 1, false)] {
        let dir = temp();
        let mut store = open(dir.path(), Role::Client).await;
        let sequence = client_sequence(&channel, &job).await;
        commit_all(&mut store, &sequence[..5]).await;
        assert_eq!(
            store.state().jobs().next().map(JobState::phase),
            Some(JobPhase::Matched),
        );
        advance(&mut store, height).await;

        let paid = store
            .commit(job.paid(&channel), &Secp256k1Verifier::new())
            .await;
        if timely {
            if let Err(error) = paid {
                panic!("a payment at {height} is timely: {error}");
            }
            assert_eq!(store.state().ledger().credited_cumulative(), PRICE);
            continue;
        }
        let Err(error) = paid else {
            panic!("a payment at {height} is late");
        };
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::PaymentLate {
                    height: found,
                    deadline: owed,
                }) if found == height && owed == deadline
            ),
            "unexpected error: {error}"
        );
        assert_eq!(
            store.state().ledger().credited_cumulative(),
            0,
            "a refused payment credits nothing",
        );
    }
}

/// A store's clock starts at the block that opened the channel.
///
/// There is no "before the first block" state to reach, and that is
/// what makes every deadline rule below mean something: a journal whose
/// cursor could be absent would be a journal on which a receipt three
/// hundred blocks late reads as timely.
#[tokio::test]
async fn a_store_opens_anchored_at_the_channels_origin() {
    let dir = temp();
    let store = open(dir.path(), Role::Client).await;
    assert_eq!(
        store.state().cursor(),
        (RECEIPT_HEIGHT - 1, payload_at(RECEIPT_HEIGHT - 1))
    );

    // And the origin is this channel's. One opened at another edge's
    // origin would be reading a height that is not about it.
    let error = ChannelStore::open(
        dir.path().join("elsewhere").as_path(),
        channel(),
        settlement(),
        Role::Client,
        SetupOrigin {
            payment_edge: EdgeId::from_bytes([0x5e; 32]),
            height: RECEIPT_HEIGHT - 1,
            payload: payload_at(RECEIPT_HEIGHT - 1),
            parent: payload_at(RECEIPT_HEIGHT - 2),
        },
        &Secp256k1Verifier::new(),
    )
    .await
    .expect_err("that origin is another channel's");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "setup origin payment_edge"
            })
        ),
        "unexpected error: {error}"
    );
}

/// A verdict is the client's step, and it needs a result to be about.
///
/// This is what keeps [`ChannelRecord::ResultMatched`] worth its tag.
/// Without the phase rule below, a client could record a verdict about
/// an answer that had not arrived, and the payment gate that reads it
/// would be gating on nothing.
#[tokio::test]
async fn a_verdict_belongs_to_a_client_holding_a_result() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    // MUTATION: the provider's journal, which has no oracle.
    let mut provider_store = open(dir.path(), Role::Provider).await;
    commit_all(
        &mut provider_store,
        &provider_sequence(&channel, &job).await[..4],
    )
    .await;
    let error = provider_store
        .commit(
            ChannelRecord::ResultMatched {
                work_id: job.work_id,
            },
            &verifier,
        )
        .await
        .expect_err("a provider does not check its own answer");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongRole {
                step: "recording a reproduction match",
                expected: "client"
            })
        ),
        "unexpected error: {error}"
    );

    // MUTATION: a client's journal, one step before the result.
    let other = temp();
    let mut store = open(other.path(), Role::Client).await;
    let sequence = client_sequence(&channel, &job).await;
    commit_all(&mut store, &sequence[..3]).await;
    assert_eq!(
        store.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted)
    );
    let error = store
        .commit(
            ChannelRecord::ResultMatched {
                work_id: job.work_id,
            },
            &verifier,
        )
        .await
        .expect_err("there is nothing yet to have checked");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase {
                step: "recording a reproduction match",
                phase: "accepted"
            })
        ),
        "unexpected error: {error}"
    );

    // The control: with the result recorded, the same step is taken —
    // and taken again is redundant rather than a second verdict.
    commit_all(&mut store, &sequence[3..5]).await;
    let before = store.len();
    if let Err(error) = store
        .commit(
            ChannelRecord::ResultMatched {
                work_id: job.work_id,
            },
            &verifier,
        )
        .await
    {
        panic!("a repeated verdict is the same verdict: {error}");
    }
    assert_eq!(store.len(), before, "and it is not written twice");
    assert_eq!(
        store.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Matched)
    );
}

/// An authenticated result is payable without mandatory reproduction.
///
/// The optional matched marker remains valid, but does not gate ordinary
/// settlement: the provider's result signature and transcript binding
/// are the evidence the payment names.
#[tokio::test]
async fn an_authenticated_result_is_payable_without_reproduction() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Client).await;
    let sequence = client_sequence(&channel, &job).await;
    commit_all(&mut store, &sequence[..4]).await;
    assert_eq!(
        store.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Ready)
    );

    // The ordinary path pays directly from Ready.
    if let Err(error) = store.commit(job.paid(&channel), &verifier).await {
        panic!("an authenticated result is paid for: {error}");
    }
    assert_eq!(store.state().ledger().credited_cumulative(), PRICE);
}

/// Two jobs share one channel, may advance in a different order than
/// they were proposed, and retain both terminals across restart.
#[tokio::test]
async fn concurrent_jobs_pay_once_each_and_survive_restart() {
    let dir = temp();
    let channel = channel();
    let first = job_at(&channel, 1, 0);
    let second = job_at(&channel, 2, PRICE);
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider).await;

    // Both reservations exist together. Follow-on records deliberately
    // arrive in the reverse proposal order.
    for record in [
        first.proposed(),
        second.proposed(),
        second.accepted(),
        first.accepted(),
        ChannelRecord::JobRunning {
            work_id: second.work_id,
        },
        ChannelRecord::JobRunning {
            work_id: first.work_id,
        },
        second.result_record(&channel),
        first.result_record(&channel),
        ChannelRecord::PlaintextReleased {
            work_id: second.work_id,
        },
        ChannelRecord::PlaintextReleased {
            work_id: first.work_id,
        },
    ] {
        store
            .commit(record, &verifier)
            .await
            .expect("the interleaving is valid");
    }
    assert_eq!(store.state().jobs().len(), 2);
    assert_eq!(store.state().proposal_nonce_high_water(), 2);

    store
        .commit(first.paid(&channel), &verifier)
        .await
        .expect("the first cumulative pays");
    store
        .commit(second.paid(&channel), &verifier)
        .await
        .expect("the next cumulative pays");
    assert_eq!(store.state().ledger().credited_cumulative(), 2 * PRICE);
    assert_eq!(store.state().jobs().len(), 0);
    assert_eq!(store.state().terminals().len(), 2);
    assert_eq!(
        store.state().last_payment().map(|payment| payment.work_id),
        Some(second.work_id),
    );

    drop(store);
    let reopened = open(dir.path(), Role::Provider).await;
    assert_eq!(reopened.state().ledger().credited_cumulative(), 2 * PRICE);
    assert_eq!(reopened.state().terminals().len(), 2);
    assert!(reopened.state().terminal_by_id(first.work_id).is_some());
    assert!(reopened.state().terminal_by_id(second.work_id).is_some());
    assert_eq!(
        reopened
            .state()
            .payment(second.work_id)
            .map(|payment| payment.certificate.earned_cumulative()),
        Some(2 * PRICE),
    );
}

// ── The defect this phase exists to prevent ───────────────────────────

/// Re-sending the retained certificate after a crash is not a second
/// payment.
#[tokio::test]
async fn re_sending_a_retained_payment_is_idempotent() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Client).await;
        commit_all(&mut store, &client_sequence(&channel, &job).await).await;
    }

    let mut recovered = open(dir.path(), Role::Client).await;
    let Some(retained) = recovered.state().last_payment() else {
        panic!("the payment is retained for re-sending");
    };
    assert_eq!(retained.certificate, job.certificate);
    assert_eq!(retained.binding, job.binding);
    // The job it paid for, kept beside the bytes: the payment closed
    // that job, so nothing else on this state can still name it.
    assert_eq!(retained.work_id, job.work_id);

    let before = recovered.len();
    if let Err(error) = recovered
        .commit(job.paid(&channel), &Secp256k1Verifier::new())
        .await
    {
        panic!("re-sending the retained payment: {error}");
    }
    assert_eq!(recovered.len(), before, "nothing is written twice");
    assert_eq!(recovered.state().ledger().credited_cumulative(), PRICE);
}

// ── Crash points ──────────────────────────────────────────────────────

/// A crash after every write boundary, and what the next process holds.
///
/// The prefix is committed, the store is dropped without ceremony, and
/// a new one is opened over the same files. What is asserted is the
/// exact state — not that recovery "works".
#[tokio::test]
async fn every_provider_write_boundary_recovers_to_one_state() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let sequence = provider_sequence(&channel, &job).await;

    let expected: Vec<(Option<JobPhase>, u64)> = vec![
        // phase, credited
        (Some(JobPhase::HalfSigned), 0),
        (Some(JobPhase::Accepted), 0),
        (Some(JobPhase::Running), 0),
        (Some(JobPhase::Ready), 0),
        (Some(JobPhase::Delivered), 0),
        (None, PRICE),
    ];

    for (index, (phase, credited)) in expected.into_iter().enumerate() {
        let dir = temp();
        {
            let mut store = open(dir.path(), Role::Provider).await;
            commit_all(&mut store, &sequence[..=index]).await;
        }
        let recovered = open(dir.path(), Role::Provider).await;
        let state = recovered.state();
        assert_eq!(
            state
                .jobs()
                .next()
                .map(hellas_work::work_store::JobState::phase),
            phase,
            "phase after {} records",
            index + 1
        );
        assert_eq!(
            state.ledger().credited_cumulative(),
            credited,
            "credited after {} records",
            index + 1
        );
        assert_eq!(recovered.len(), index as u64 + 1);
    }
}

/// A half-signed job survives a restart with the exact bytes the peer
/// may already have.
#[tokio::test]
async fn a_half_signed_job_keeps_its_bytes() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &[job.proposed()]).await;
    }

    let mut recovered = open(dir.path(), Role::Provider).await;
    let Some(open_job) = recovered.state().jobs().next() else {
        panic!("the half-signed job survives");
    };
    assert_eq!(open_job.phase(), JobPhase::HalfSigned);
    assert_eq!(*open_job.authorization(), job.authorization);
    assert_eq!(
        open_job.client_signature(),
        client().sign(payload(job.work_id)),
        "the client's exact signature is retained"
    );
    assert!(open_job.provider_signature().is_none());

    // The peer re-sends what it sent before the crash: the same
    // proposal, not a second one.
    let before = recovered.len();
    if let Err(error) = recovered
        .commit(job.proposed(), &Secp256k1Verifier::new())
        .await
    {
        panic!("an exact replay commits: {error}");
    }
    assert_eq!(recovered.len(), before);

    // The same nonce with different bytes is not a replay.
    let mut different = job.authorization;
    different.terminal_deadline = 201;
    let error = recovered
        .commit(
            ChannelRecord::JobProposed {
                authorization: different,
                client_signature: client().sign(payload(work_id(&channel, &different))),
                prepared_input: bundle_bytes(different.proposal_nonce),
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .expect_err("a second job while one is open");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "proposal_nonce"
            })
        ),
        "unexpected error: {error}"
    );
}

/// A crash between the running marker and the result is never resolved
/// by running it again, and never by accepting a result now.
#[tokio::test]
async fn an_interrupted_invocation_stays_indeterminate() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let verifier = Secp256k1Verifier::new();
    {
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(
            &mut store,
            &[
                job.proposed(),
                job.accepted(),
                ChannelRecord::JobRunning {
                    work_id: job.work_id,
                },
            ],
        )
        .await;
    }

    let mut recovered = open(dir.path(), Role::Provider).await;
    assert!(recovered.state().is_indeterminate());
    let error = recovered
        .commit(job.result_record(&channel), &verifier)
        .await
        .expect_err("this process did not make that invocation");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Indeterminate)
        ),
        "unexpected error: {error}"
    );

    // The only way out is an explicit ending, and it rests the one job
    // at a permanent indeterminate terminal. The compute this provider
    // may have spent is the provider's own to bear.
    if let Err(error) = recovered
        .commit(
            ChannelRecord::JobTerminated {
                work_id: job.work_id,
                outcome: TerminalOutcome::Indeterminate,
            },
            &verifier,
        )
        .await
    {
        panic!("the ending commits: {error}");
    }
    assert!(!recovered.state().is_indeterminate());
    assert!(
        matches!(
            recovered.state().terminals().next().map(|t| &t.outcome),
            Some(TerminalOutcome::Indeterminate)
        ),
        "the job rests at an indeterminate terminal",
    );
}

// ── Credit ────────────────────────────────────────────────────────────

/// The one job's price is checked against the compute limit before the
/// provider co-signs, one unit either side.
///
/// There is no accumulation across jobs — the channel admits one job for
/// life — so the whole of the check is the one job's price against the
/// limit.
#[tokio::test]
async fn compute_credit_bounds_what_may_be_co_signed() {
    let verifier = Secp256k1Verifier::new();

    // A channel whose compute limit is one unit below the one job's price.
    let dir = temp();
    let channel = channel_with(EdgeId::from_bytes([0xe5; 32]), limits(PRICE - 1, 1_000));
    let mut store = open_on(dir.path(), channel.clone(), Role::Provider).await;
    let job = job_at(&channel, 1, 0);
    let error = store
        .commit(job.proposed(), &verifier)
        .await
        .expect_err("the one job's price is over the compute limit");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::OverCredit {
                ledger: "compute",
                used: 0,
                reserved: 0,
                price,
                limit,
            }) if price == PRICE && limit == PRICE - 1
        ),
        "unexpected error: {error}"
    );

    // The control: a limit that exactly fits the one job co-signs it.
    let roomy = channel_with(EdgeId::from_bytes([0xe6; 32]), limits(PRICE, 1_000));
    let other = temp();
    let mut store = open_on(other.path(), roomy.clone(), Role::Provider).await;
    let job = job_at(&roomy, 1, 0);
    if let Err(error) = store.commit(job.proposed(), &verifier).await {
        panic!("a job within the compute limit co-signs: {error}");
    }
}

/// The one job's price is checked against the delivery limit before the
/// plaintext leaves, one unit either side.
#[tokio::test]
async fn delivery_credit_bounds_what_may_be_released() {
    let verifier = Secp256k1Verifier::new();

    // A channel with compute room but a delivery limit one unit below the
    // one job's price.
    let dir = temp();
    let channel = channel_with(EdgeId::from_bytes([0xe3; 32]), limits(1_000, PRICE - 1));
    let mut store = open_on(dir.path(), channel.clone(), Role::Provider).await;
    let job = job_at(&channel, 1, 0);
    commit_all(&mut store, &provider_sequence(&channel, &job).await[..4]).await;
    let error = store
        .commit(
            ChannelRecord::PlaintextReleased {
                work_id: job.work_id,
            },
            &verifier,
        )
        .await
        .expect_err("the one job's price is over the delivery limit");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::OverCredit {
                ledger: "delivery",
                used: 0,
                reserved: 0,
                price,
                limit,
            }) if price == PRICE && limit == PRICE - 1
        ),
        "unexpected error: {error}"
    );
    assert!(
        store.state().jobs().next().map(JobState::phase) == Some(JobPhase::Ready),
        "nothing was released, so the job is still ready",
    );

    // The control: a limit that exactly fits releases the plaintext.
    let roomy = channel_with(EdgeId::from_bytes([0xe4; 32]), limits(1_000, PRICE));
    let other = temp();
    let mut store = open_on(other.path(), roomy.clone(), Role::Provider).await;
    let job = job_at(&roomy, 1, 0);
    commit_all(&mut store, &provider_sequence(&roomy, &job).await[..5]).await;
    assert_eq!(
        store.state().jobs().next().map(JobState::phase),
        Some(JobPhase::Delivered),
    );
}

// ── What the store refuses ────────────────────────────────────────────

/// Every signature is checked against the party the channel names, over
/// that record's own digest.
#[tokio::test]
async fn a_signature_from_the_wrong_party_is_not_evidence() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    let cases: Vec<(&str, Vec<ChannelRecord>, ChannelRecord)> = vec![
        (
            "the provider signing as the client",
            Vec::new(),
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: provider().sign(payload(job.work_id)),
                prepared_input: bundle_bytes(job.authorization.proposal_nonce),
            },
        ),
        (
            "the client signing as the provider",
            vec![job.proposed()],
            ChannelRecord::JobAccepted {
                work_id: job.work_id,
                provider_signature: client().sign(payload(job.work_id)),
            },
        ),
        (
            "a result signed over another digest",
            vec![
                job.proposed(),
                job.accepted(),
                ChannelRecord::JobRunning {
                    work_id: job.work_id,
                },
            ],
            ChannelRecord::JobResult {
                work_id: job.work_id,
                result: job.result,
                provider_signature: provider().sign(payload(job.work_id)),
                transcript: spool(&job.transcript),
            },
        ),
        (
            "a binding signed over another digest",
            provider_sequence(&channel, &job).await[..5].to_vec(),
            ChannelRecord::JobTerminated {
                work_id: job.work_id,
                outcome: TerminalOutcome::Certified {
                    certificate: job.certificate,
                    binding: Box::new(job.binding),
                    binding_signature: client().sign(payload(job.work_id)),
                    certificate_signature: client().sign(job.certificate.digest(network())),
                },
            },
        ),
        (
            "a certificate the client did not sign",
            provider_sequence(&channel, &job).await[..5].to_vec(),
            ChannelRecord::JobTerminated {
                work_id: job.work_id,
                outcome: TerminalOutcome::Certified {
                    certificate: job.certificate,
                    binding: Box::new(job.binding),
                    binding_signature: client()
                        .sign(payload(payment_binding_digest(&channel, &job.binding))),
                    certificate_signature: provider().sign(job.certificate.digest(network())),
                },
            },
        ),
    ];

    for (label, prefix, record) in cases {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &prefix).await;
        let before = store.len();
        let error = store
            .commit(record, &verifier)
            .await
            .expect_err("this signature is not the party's");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::BadSignature { .. })
            ),
            "case {label}: unexpected error: {error}"
        );
        assert_eq!(store.len(), before, "case {label}: nothing is written");
    }
    drop(dir);
}

/// A payment is the one this ledger position admits, or it is not
/// journaled at all.
///
/// Each case moves exactly one field of the honest payment and re-signs
/// whatever the move invalidated, so what refuses it is the arithmetic
/// and not a stale signature. The refusals name the field, which is
/// what makes this six checks rather than one that six inputs happen to
/// trip.
#[tokio::test]
async fn a_payment_must_be_the_one_this_position_admits() {
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);
    let elsewhere = Digest::from_bytes([0x5e; 32]);
    let other_edge = EdgeId::from_bytes([0x77; 32]);
    let other_terms = TermsHash::from_bytes([0x88; 32]);

    let bindings: Vec<(&str, &str, PaymentBindingV1)> = vec![
        (
            "a work id this journal never opened",
            "binding work_id",
            PaymentBindingV1 {
                work_id: elsewhere,
                ..job.binding
            },
        ),
        (
            "a result this provider never signed",
            "binding result_digest",
            PaymentBindingV1 {
                result_digest: elsewhere,
                ..job.binding
            },
        ),
        (
            "a binding that names some other certificate",
            "binding certificate_digest",
            PaymentBindingV1 {
                certificate_digest: PayloadHash::from_bytes([0x5e; 32]),
                ..job.binding
            },
        ),
    ];
    for (label, field, binding) in bindings {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &provider_sequence(&channel, &job).await[..5]).await;
        let error = store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Certified {
                        certificate: job.certificate,
                        binding: Box::new(binding),
                        binding_signature: client()
                            .sign(payload(payment_binding_digest(&channel, &binding))),
                        certificate_signature: client().sign(job.certificate.digest(network())),
                    },
                },
                &verifier,
            )
            .await
            .expect_err("this is not the payment the position admits");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Mismatch {
                    field: found
                })) if found == field
            ),
            "case {label}: unexpected error: {error}"
        );
    }

    let certificates: Vec<(&str, &str, EarnedCertificate)> = vec![
        (
            "an amount this ledger did not arrive at",
            "certificate earned_cumulative",
            EarnedCertificate::new(
                channel.payment_edge(),
                channel.payment_terms_hash(),
                PRICE + 1,
            ),
        ),
        (
            "another edge",
            "certificate payment_edge",
            EarnedCertificate::new(other_edge, channel.payment_terms_hash(), PRICE),
        ),
        (
            "another terms body",
            "certificate payment_terms_hash",
            EarnedCertificate::new(channel.payment_edge(), other_terms, PRICE),
        ),
    ];
    for (label, field, certificate) in certificates {
        let dir = temp();
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &provider_sequence(&channel, &job).await[..5]).await;
        // The binding is left as the one this position expects, so the
        // check in front of the certificate passes and what refuses each
        // case is the certificate's own field. It is also the case that
        // check cannot see: an offered certificate that is not the one
        // the binding names.
        let error = store
            .commit(
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Certified {
                        certificate,
                        binding: Box::new(job.binding),
                        binding_signature: client()
                            .sign(payload(payment_binding_digest(&channel, &job.binding))),
                        certificate_signature: client().sign(certificate.digest(network())),
                    },
                },
                &verifier,
            )
            .await
            .expect_err("this is not the payment the position admits");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::Record(PaidWorkError::Mismatch {
                    field: found
                })) if found == field
            ),
            "case {label}: unexpected error: {error}"
        );
    }
}

/// A record for another channel is not this channel's, whatever it is
/// signed with.
#[tokio::test]
async fn a_record_for_another_channel_is_refused() {
    let dir = temp();
    let other = channel_on(EdgeId::from_bytes([0xe9; 32]));
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider).await;

    let elsewhere = job_at(&other, 1, 0);
    let error = store
        .commit(elsewhere.proposed(), &verifier)
        .await
        .expect_err("that authorization names another channel");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongChannel { .. })
        ),
        "unexpected error: {error}"
    );
}

/// Role-scoped steps belong to one role.
#[tokio::test]
async fn role_scoped_steps_belong_to_one_role() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel, 1, 0);

    let mut client_store = open(dir.path(), Role::Client).await;
    commit_all(&mut client_store, &[job.proposed(), job.accepted()]).await;
    for record in [
        ChannelRecord::JobRunning {
            work_id: job.work_id,
        },
        ChannelRecord::PlaintextReleased {
            work_id: job.work_id,
        },
    ] {
        let error = client_store
            .commit(record, &verifier)
            .await
            .expect_err("that is a provider's step");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::WrongRole { .. })
            ),
            "unexpected error: {error}"
        );
    }
}

/// The finalized cursor moves to the next block, or it does not move.
///
/// Two rules, varied one at a time against the same held block. A
/// height that is not the next one is a block this endpoint never read;
/// a parent that is not the held payload is a block from a history it
/// never read. Either would let a watcher report progress it has not
/// made, and every deadline in this crate is measured against that
/// progress.
#[tokio::test]
async fn the_cursor_only_moves_to_the_contiguous_next_block() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider).await;
    let anchor = RECEIPT_HEIGHT - 1;
    commit_all(&mut store, &[cursor_at(anchor + 1)]).await;
    assert_eq!(store.state().cursor(), (anchor + 1, payload_at(anchor + 1)));

    // Every height but the next one, with the parent left correct. The
    // repeated height carries a different payload, so it is a second
    // block at the held height rather than the retry answered below.
    for height in [anchor + 1, anchor, 0, anchor + 3, anchor + 20] {
        let error = store
            .commit(
                ChannelRecord::CursorAdvanced {
                    height,
                    parent: payload_at(anchor + 1),
                    payload: [0x99; 32],
                },
                &verifier,
            )
            .await
            .expect_err("only the next height moves the cursor");
        assert!(
            matches!(
                error,
                WorkStoreError::Channel(ChannelStateError::CursorNotNext {
                    held,
                    actual,
                }) if held == anchor + 1 && actual == height
            ),
            "unexpected error at {height}: {error}"
        );
    }

    // The next height, and the only thing varied is the parent.
    let error = store
        .commit(
            ChannelRecord::CursorAdvanced {
                height: anchor + 2,
                parent: payload_at(anchor),
                payload: payload_at(anchor + 2),
            },
            &verifier,
        )
        .await
        .expect_err("a block from another history does not extend this one");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::CursorNotContiguous { height })
                if height == anchor + 2
        ),
        "unexpected error: {error}"
    );

    // The same two fields, correct: the cursor moves by exactly one.
    commit_all(&mut store, &[cursor_at(anchor + 2)]).await;
    assert_eq!(store.state().cursor(), (anchor + 2, payload_at(anchor + 2)));

    // The same block again is the same fact.
    let before = store.len();
    commit_all(&mut store, &[cursor_at(anchor + 2)]).await;
    assert_eq!(store.len(), before);
}

/// Two processes over one channel: the second fails before it can act.
#[tokio::test]
async fn a_second_process_cannot_hold_the_same_channel() {
    let dir = temp();
    let held = open(dir.path(), Role::Provider).await;
    let error = ChannelStore::open(
        dir.path(),
        channel(),
        settlement(),
        Role::Provider,
        origin_of(&channel()),
        &Secp256k1Verifier::new(),
    )
    .await
    .expect_err("the journal is already held");
    assert!(
        matches!(error, WorkStoreError::Journal(JournalError::Locked { .. })),
        "unexpected error: {error}"
    );
    drop(held);
    let _ = open(dir.path(), Role::Provider).await;
}

/// The stem of the one channel journal under a root.
fn channel_stem(root: &std::path::Path) -> String {
    Journal::stems(root)
        .unwrap()
        .into_iter()
        .find(|stem| stem.starts_with("channel-"))
        .expect("the channel journal exists")
}

// ── The record codec ──────────────────────────────────────────────────

/// The codec is exact, and its field order is pinned by bytes rather
/// than by a round trip.
#[test]
fn the_record_codec_is_exact_and_ordered() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);

    let cursor = ChannelRecord::CursorAdvanced {
        height: 0x0102_0304_0506_0708,
        parent: [0xaa; 32],
        payload: [0xab; 32],
    };
    let bytes = cursor.encode();
    // tag || height || parent || payload — the height first and
    // big-endian, and the two digests in that order. A round trip would
    // pass with them transposed; these bytes do not.
    let mut expected = vec![0_u8];
    expected.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    expected.extend_from_slice(&[0xaa; 32]);
    expected.extend_from_slice(&[0xab; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(cursor));

    let start = hellas_kernel::PaymentCloseStart::new(
        channel.payment_edge(),
        hellas_kernel::Terms::work_payment(channel.payment_terms().clone()),
        hellas_kernel::Party::Taker,
        (11, 18),
        None,
        PartyAuth::signer(provider().sign(payload(job.work_id))),
    );
    let prepared = ChannelRecord::ClosePrepared {
        start: Box::new(start.clone()),
    };
    let bytes = prepared.encode();
    // tag || the kernel's own encoding of the start, and nothing else:
    // the journal holds the bytes consensus will read, not a second
    // spelling of them.
    let mut expected = vec![8_u8];
    let mut body = vec![0_u8; start.encoded_size()];
    let written = start.write_to(&mut body);
    body.truncate(written);
    expected.extend_from_slice(&body);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(prepared));

    // tag || contest id || opener || response deadline || claimed. The
    // opener is one byte after the digest, and the two big-endian `u64`s
    // follow it; a round trip would pass with any of them exchanged, and
    // these bytes would not.
    let opened = ChannelRecord::CloseOpened {
        start_id: hellas_kernel::StartId::from_bytes([0xcd; 32]),
        opener: Party::Maker,
        response_deadline: 0x3132_3334_3536_3738,
        claimed: 0x4142_4344_4546_4748,
    };
    let bytes = opened.encode();
    let mut expected = vec![9_u8];
    expected.extend_from_slice(&[0xcd; 32]);
    expected.push(0);
    expected.extend_from_slice(&0x3132_3334_3536_3738_u64.to_be_bytes());
    expected.extend_from_slice(&0x4142_4344_4546_4748_u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(opened));

    let opened = ChannelRecord::CloseOpened {
        start_id: hellas_kernel::StartId::from_bytes([0xcd; 32]),
        opener: Party::Taker,
        response_deadline: 0,
        claimed: 0,
    };
    let bytes = opened.encode();
    let mut expected = vec![9_u8];
    expected.extend_from_slice(&[0xcd; 32]);
    expected.push(1);
    expected.extend_from_slice(&0_u64.to_be_bytes());
    expected.extend_from_slice(&0_u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(opened));

    // And nothing else is a party.
    let mut unknown = bytes;
    unknown[33] = 2;
    assert_eq!(
        ChannelRecord::decode(&unknown),
        Err(ChannelStateError::Malformed)
    );

    // tag || contest id || response digest. Two digests, and only their
    // order tells them apart: a round trip would pass with them
    // transposed, and a journal written that way would refuse the very
    // answer it holds.
    let responded = ChannelRecord::CloseResponded {
        start_id: hellas_kernel::StartId::from_bytes([0xcd; 32]),
        response_digest: PayloadHash::from_bytes([0xce; 32]),
    };
    let bytes = responded.encode();
    let mut expected = vec![11_u8];
    expected.extend_from_slice(&[0xcd; 32]);
    expected.extend_from_slice(&[0xce; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(responded));

    // And it is exactly that long: a byte short and a byte over are both
    // malformed, so a truncated tail cannot read as an answer.
    assert_eq!(
        ChannelRecord::decode(&bytes[..bytes.len() - 1]),
        Err(ChannelStateError::Malformed)
    );
    let mut over = bytes;
    over.push(0);
    assert_eq!(
        ChannelRecord::decode(&over),
        Err(ChannelStateError::Malformed)
    );

    let settled = ChannelRecord::CloseSettled {
        height: 0x1112_1314_1516_1718,
        payload: [0xef; 32],
        provider_payout: 0x2122_2324_2526_2728,
    };
    let bytes = settled.encode();
    // tag || height || payload || provider payout. Two big-endian
    // `u64`s around one digest: a round trip would pass with them
    // exchanged, and these bytes would not.
    let mut expected = vec![10_u8];
    expected.extend_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
    expected.extend_from_slice(&[0xef; 32]);
    expected.extend_from_slice(&0x2122_2324_2526_2728_u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(settled));

    // The nested bodies are their own canonical encodings, in the order
    // the record names them.
    let proposed = job.proposed();
    let bytes = proposed.encode();
    let mut expected = vec![1_u8];
    expected.extend_from_slice(&job.authorization.encode());
    expected.extend_from_slice(client().sign(payload(job.work_id)).as_bytes());
    expected.extend_from_slice(&bundle_bytes(1));
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(proposed));

    // The result record: body, then signature, then the transcript as
    // the whole of the rest.
    let recorded = job.result_record(&channel);
    let bytes = recorded.encode();
    let mut expected = vec![4_u8];
    expected.extend_from_slice(job.work_id.as_bytes());
    expected.extend_from_slice(&job.result.encode());
    expected.extend_from_slice(
        provider()
            .sign(payload(result_digest(&channel, &job.result)))
            .as_bytes(),
    );
    expected.extend_from_slice(&spool(&job.transcript));
    assert_eq!(bytes, expected);
    assert_eq!(ChannelRecord::decode(&bytes), Ok(recorded));

    // Marker records carry the work ID, so reordered messages cannot be
    // applied to whichever job happens to be current.
    for record in [
        ChannelRecord::JobRunning {
            work_id: job.work_id,
        },
        ChannelRecord::PlaintextReleased {
            work_id: job.work_id,
        },
        ChannelRecord::ResultMatched {
            work_id: job.work_id,
        },
    ] {
        let bytes = record.encode();
        assert_eq!(bytes.len(), 1 + Digest::LEN);
        assert_eq!(&bytes[1..], job.work_id.as_bytes());
        assert_eq!(ChannelRecord::decode(&bytes), Ok(record));
    }
    assert!(ChannelRecord::decode(&[3]).is_err());

    // The terminated record: the terminal tag, then the outcome
    // discriminant, then — for a certified outcome — the certificate,
    // binding, and two client signatures.
    let paid = job.paid(&channel);
    let bytes = paid.encode();
    let mut expected = vec![7_u8];
    expected.extend_from_slice(job.work_id.as_bytes());
    expected.push(0_u8);
    let mut certificate = vec![0_u8; job.certificate.encoded_size()];
    let written = job.certificate.write_to(&mut certificate);
    certificate.truncate(written);
    expected.extend_from_slice(&certificate);
    expected.extend_from_slice(&job.binding.encode());
    expected.extend_from_slice(
        client()
            .sign(payload(payment_binding_digest(&channel, &job.binding)))
            .as_bytes(),
    );
    expected.extend_from_slice(client().sign(job.certificate.digest(network())).as_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(
        bytes.len(),
        2 + Digest::LEN
            + EarnedCertificate::ENCODED_SIZE
            + PaymentBindingV1::ENCODED_SIZE
            + 2 * Sig::LENGTH
    );
    assert_eq!(ChannelRecord::decode(&bytes), Ok(paid));

    // Swapping the two client signatures is a different record, and a
    // reader that agreed with the layout only by round-tripping could
    // not see it.
    let swapped = ChannelRecord::JobTerminated {
        work_id: job.work_id,
        outcome: TerminalOutcome::Certified {
            certificate: job.certificate,
            binding: Box::new(job.binding),
            binding_signature: client().sign(job.certificate.digest(network())),
            certificate_signature: client()
                .sign(payload(payment_binding_digest(&channel, &job.binding))),
        },
    };
    assert_ne!(swapped.encode(), bytes);

    // The other terminal outcomes: each is the terminal tag, its own
    // discriminant, and its fixed fields, and each round-trips.
    for (discriminant, outcome) in [
        (
            1_u8,
            TerminalOutcome::Refuted {
                result_digest: Digest::from_bytes([0x51; 32]),
                reproduction_digest: Digest::from_bytes([0x52; 32]),
            },
        ),
        (
            2_u8,
            TerminalOutcome::Expired {
                deadline: 0x0102_0304_0506_0708,
                height: 0x1112_1314_1516_1718,
                payload: [0x53; 32],
            },
        ),
        (3_u8, TerminalOutcome::Failed { code: 0x2122_2324 }),
        (4_u8, TerminalOutcome::Indeterminate),
    ] {
        let record = ChannelRecord::JobTerminated {
            work_id: job.work_id,
            outcome,
        };
        let bytes = record.encode();
        assert_eq!(bytes.first(), Some(&7_u8), "the terminal tag");
        assert_eq!(
            bytes.get(1 + Digest::LEN),
            Some(&discriminant),
            "the outcome discriminant"
        );
        assert_eq!(ChannelRecord::decode(&bytes), Ok(record));
    }

    // Exactness.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ChannelRecord::decode(&trailing),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&bytes[..bytes.len() - 1]),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&[12]),
        Err(ChannelStateError::Malformed)
    );
    assert_eq!(
        ChannelRecord::decode(&[]),
        Err(ChannelStateError::Malformed)
    );
}

/// Signatures are checked when the journal is read back, not only when
/// it is written.
#[tokio::test]
async fn replay_checks_the_signatures_again() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let forged = ChannelRecord::JobProposed {
        authorization: job.authorization,
        client_signature: provider().sign(payload(job.work_id)),
        prepared_input: bundle_bytes(job.authorization.proposal_nonce),
    };
    {
        let Ok(mut credulous) = ChannelStore::open(
            dir.path(),
            channel.clone(),
            settlement(),
            Role::Provider,
            origin_of(&channel),
            &AcceptAll,
        )
        .await
        else {
            panic!("the store opens");
        };
        if let Err(error) = credulous.commit(forged, &AcceptAll).await {
            panic!("a credulous verifier accepts it: {error}");
        }
    }
    let error = ChannelStore::open(
        dir.path(),
        channel.clone(),
        settlement(),
        Role::Provider,
        origin_of(&channel),
        &Secp256k1Verifier::new(),
    )
    .await
    .expect_err("the client never signed that");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::BadSignature { .. })
        ),
        "unexpected error: {error}"
    );
}

/// A verifier that accepts everything, so a test can write a journal
/// the real verifier will refuse.
struct AcceptAll;

impl hellas_kernel::SigVerifier for AcceptAll {
    fn verify_sig(&self, _sig: Sig, _key: hellas_kernel::Key, _hash: PayloadHash) -> bool {
        true
    }
}

/// A provider records a result only for an invocation it marked.
///
/// The marker is what makes the indeterminate case detectable at all: a
/// result accepted without one is a result whose invocation left no
/// trace, and after a crash there would be nothing to be indeterminate
/// about.
#[tokio::test]
async fn a_result_needs_the_marker_that_says_the_backend_was_called() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider).await;
    commit_all(&mut store, &[job.proposed(), job.accepted()]).await;

    let error = store
        .commit(job.result_record(&channel), &Secp256k1Verifier::new())
        .await
        .expect_err("nothing marked this job as invoked");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::WrongPhase { .. })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        store
            .state()
            .jobs()
            .next()
            .map(hellas_work::work_store::JobState::phase),
        Some(JobPhase::Accepted)
    );
}

/// The inputs a job executes from survive the crash, and are the ones
/// the authorization commits to.
///
/// The quote that carried them is transient. Without them a provider
/// that restarted after accepting could not execute the job it
/// accepted; with the wrong ones it would execute a job nobody signed.
#[tokio::test]
async fn the_retained_dispatch_input_is_the_one_the_authorization_commits_to() {
    let dir = temp();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    {
        let mut store = open(dir.path(), Role::Provider).await;
        commit_all(&mut store, &[job.proposed(), job.accepted()]).await;
    }

    let recovered = open(dir.path(), Role::Provider).await;
    let Some(open_job) = recovered.state().jobs().next() else {
        panic!("the accepted job survives");
    };
    assert_eq!(open_job.prepared_input(), bundle_bytes(1).as_slice());
    // And they are a bundle, not opaque bytes that happen to be stored.
    if let Err(error) = PreparedPaidInputV1::decode(open_job.prepared_input(), 1 << 20) {
        panic!("the retained inputs are a bundle: {error}");
    }

    // MUTATION of exactly one thing: another job's bundle, under this
    // job's authorization and this job's real client signature.
    let other = temp();
    let mut fresh = open(other.path(), Role::Provider).await;
    let error = fresh
        .commit(
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: client().sign(payload(job.work_id)),
                prepared_input: bundle_bytes(2),
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .expect_err("those are not the inputs the authorization names");
    assert!(
        matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
        "unexpected error: {error}"
    );
    assert!(fresh.state().jobs().next().is_none());

    // And bytes that are not a bundle at all.
    let error = fresh
        .commit(
            ChannelRecord::JobProposed {
                authorization: job.authorization,
                client_signature: client().sign(payload(job.work_id)),
                prepared_input: vec![0xff; 8],
            },
            &Secp256k1Verifier::new(),
        )
        .await
        .expect_err("that is not a prepared bundle");
    assert!(
        matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
        "unexpected error: {error}"
    );
}

/// Inputs swapped on the disk fault the journal rather than becoming a
/// job to execute.
///
/// The other half of the property above, and the one that matters to a
/// dispatch: an accepted job is executed from bytes nobody re-verifies
/// at dispatch time, so what makes them the right bytes is that opening
/// the file re-runs the same digest check that admitted them. A store
/// that only checked on commit would hand a restarted provider a job
/// its client never signed, and ask for no new signature to do it.
#[tokio::test]
async fn inputs_swapped_on_the_disk_are_not_a_job_to_execute() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);

    // Two journals written the same way, behind the store's back
    // because no store would take the second: the same authorization,
    // the same real client signature, and the same real co-signature
    // over the same work id. Only the bundle differs.
    for (bundle_nonce, readable) in [(1_u64, true), (2, false)] {
        let dir = temp();
        {
            // One store, opened and dropped, so the journal exists with
            // the name and header its key fixes.
            drop(open(dir.path(), Role::Provider).await);
        }
        let stem = channel_stem(dir.path());
        {
            let id = JournalId {
                kind: JournalKind::Channel,
                role: Role::Provider,
                key: channel_key_bytes(&stem),
            };
            let (mut journal, _) = match Journal::open_existing(dir.path(), &stem, id).await {
                Ok(opened) => opened,
                Err(error) => panic!("the journal opens: {error}"),
            };
            for record in [
                ChannelRecord::JobProposed {
                    authorization: job.authorization,
                    client_signature: client().sign(payload(job.work_id)),
                    prepared_input: bundle_bytes(bundle_nonce),
                },
                ChannelRecord::JobAccepted {
                    work_id: job.work_id,
                    provider_signature: provider().sign(payload(job.work_id)),
                },
            ] {
                if let Err(error) = journal.append(&record.encode()).await {
                    panic!("the record appends: {error}");
                }
            }
        }

        let opened = ChannelStore::open(
            dir.path(),
            channel.clone(),
            settlement(),
            Role::Provider,
            origin_of(&channel),
            &Secp256k1Verifier::new(),
        )
        .await;
        if readable {
            match opened {
                Ok(store) => assert!(store.state().jobs().next().is_some(), "the job replays"),
                Err(error) => panic!("the journal this route wrote reopens: {error}"),
            }
            continue;
        }
        let Err(error) = opened else {
            panic!("those are not the inputs the authorization names");
        };
        assert!(
            matches!(error, WorkStoreError::Channel(ChannelStateError::Record(_))),
            "unexpected error: {error}"
        );
    }
}

/// The 32-byte key a channel journal's own stem carries.
///
/// Read from the name rather than derived a second time: a second
/// derivation could be wrong in the same way twice.
fn channel_key_bytes(stem: &str) -> [u8; 32] {
    let hex = stem.strip_prefix("channel-").unwrap();
    let mut key = [0_u8; 32];
    assert_eq!(hex.len(), 2 * key.len(), "the name carries a 32-byte key");
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let Ok(text) = std::str::from_utf8(pair) else {
            panic!("hex is ascii");
        };
        match u8::from_str_radix(text, 16) {
            Ok(value) => *byte = value,
            Err(error) => panic!("the name is hex: {error}"),
        }
    }
    key
}

// ── The close cutoff ──────────────────────────────────────────────────

/// A retained close start admits no further work.
///
/// A close is built from what is held when it is signed, and it can only
/// be signed once the one job has reached a certified terminal — so a
/// second proposal is refused because the channel's one job is over, the
/// same permanent fact that also makes the close possible. The closing
/// guard is the same refusal read from the other side.
#[tokio::test]
async fn a_retained_close_start_admits_no_further_work() {
    let dir = temp();
    let channel = channel();
    let verifier = Secp256k1Verifier::new();
    let mut store = open(dir.path(), Role::Provider).await;
    commit_all(&mut store, &[cursor_at(RECEIPT_HEIGHT)]).await;

    // One paid job, which is the only way this journal comes to hold a
    // certificate at all.
    let paid = job_at(&channel, 1, 0);
    commit_all(&mut store, &provider_sequence(&channel, &paid).await).await;
    assert_eq!(store.state().max_executable_certificate(), PRICE);

    let Ok(start) = hellas_work::work_close::close_start(
        &channel,
        hellas_kernel::Party::Taker,
        RECEIPT_HEIGHT,
        store.state().executable_certificate(),
        &provider(),
    ) else {
        panic!("a channel with a certificate builds a close start");
    };
    commit_all(
        &mut store,
        &[ChannelRecord::ClosePrepared {
            start: Box::new(start),
        }],
    )
    .await;
    assert!(store.state().is_closing());

    // A later job would otherwise be valid, but the retained close is the
    // admission cutoff.
    let next = job_at(&channel, 2, PRICE);
    let error = store
        .commit(next.proposed(), &verifier)
        .await
        .expect_err("a job after the one job is refused");
    assert!(
        matches!(
            error,
            WorkStoreError::Channel(ChannelStateError::Closing {
                step: "proposing a job"
            })
        ),
        "unexpected error: {error}"
    );
    assert_eq!(
        store.state().max_executable_certificate(),
        PRICE,
        "and it moves nothing",
    );
    assert!(store.state().jobs().next().is_none());
}

/// Each `JobTerminal` variant is permanent: once the channel's one job
/// has reached it, a late reply to that job is refused and a second
/// proposal cannot open another.
///
/// The channel admits one job for its whole life. The five outcomes are
/// the five ways that life can end, and none of them reopens it —
/// [`ChannelStateError::Terminated`] is what both a late co-signature and
/// a fresh proposal meet.
#[tokio::test]
async fn each_job_terminal_rejects_a_late_reply_and_a_second_proposal() {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let result_digest = result_digest(&channel, &job.result);
    let reproduction_digest = Digest::from_bytes([0xab; 32]);

    let variants: Vec<(&str, Role, Vec<ChannelRecord>)> = vec![
        (
            "certified",
            Role::Provider,
            provider_sequence(&channel, &job).await,
        ),
        (
            "refuted",
            Role::Client,
            vec![
                cursor_at(RECEIPT_HEIGHT),
                job.proposed(),
                job.accepted(),
                job.result_record(&channel),
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Refuted {
                        result_digest,
                        reproduction_digest,
                    },
                },
            ],
        ),
        (
            "expired",
            Role::Provider,
            vec![
                job.proposed(),
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Expired {
                        deadline: job.authorization.payment_deadline,
                        height: RECEIPT_HEIGHT - 1,
                        payload: payload_at(RECEIPT_HEIGHT - 1),
                    },
                },
            ],
        ),
        (
            "failed",
            Role::Provider,
            vec![
                job.proposed(),
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Failed { code: 1 },
                },
            ],
        ),
        (
            "indeterminate",
            Role::Provider,
            vec![
                job.proposed(),
                ChannelRecord::JobTerminated {
                    work_id: job.work_id,
                    outcome: TerminalOutcome::Indeterminate,
                },
            ],
        ),
    ];

    for (name, role, records) in variants {
        let dir = temp();
        let mut store = open(dir.path(), role).await;
        let verifier = Secp256k1Verifier::new();
        for record in records {
            if let Err(error) = store.commit(record, &verifier).await {
                panic!("{name}: reaching the terminal records: {error}");
            }
        }
        assert!(
            store.state().jobs().next().is_none(),
            "{name}: the one job is over"
        );
        assert!(
            store.state().terminals().next().is_some(),
            "{name}: and its terminal is on the disk",
        );

        // A late reply to the finished job: a co-signature that arrives
        // now is answering a job that is over.
        let late = store.commit(job.accepted(), &verifier).await;
        assert!(
            matches!(
                late,
                Err(WorkStoreError::Channel(
                    ChannelStateError::Terminated { .. }
                )),
            ),
            "{name}: a late reply is refused as terminated: {late:?}",
        );

        // And a second proposal has nothing to open.
        let second = store.commit(job.proposed(), &verifier).await;
        assert!(
            matches!(
                second,
                Err(WorkStoreError::Channel(
                    ChannelStateError::Terminated { .. }
                )),
            ),
            "{name}: a second proposal is refused as terminated: {second:?}",
        );
    }
}

/// The deleted counterparty-loss ledger leaves no reachable caller: a
/// whole job's life opens one channel journal and no second file.
///
/// The identity-wide loss ledger was a second journal per counterparty.
/// It is gone — the provider bears an unpaid job itself — so nothing here
/// opens a `counterparty-*` journal, on any path a job can take. A file
/// that appeared would be a caller that outlived the deletion.
#[tokio::test]
async fn a_whole_job_opens_no_counterparty_loss_file() {
    let dir = temp();
    let channel = channel();
    let mut store = open(dir.path(), Role::Provider).await;
    let job = job_at(&channel, 1, 0);
    commit_all(&mut store, &provider_sequence(&channel, &job).await).await;
    assert!(
        matches!(
            store
                .state()
                .terminals()
                .next()
                .map(|terminal| &terminal.outcome),
            Some(TerminalOutcome::Certified { .. })
        ),
        "the job reached a certified terminal",
    );

    let names = Journal::stems(dir.path()).expect("the journal directory reads");
    assert!(
        names.iter().any(|name| name.starts_with("channel-")),
        "the one channel journal exists: {names:?}",
    );
    assert!(
        !names.iter().any(|name| name.starts_with("counterparty")),
        "and no counterparty-loss journal was ever opened: {names:?}",
    );
}

/// One contest admits one answer, and it is the answer the contest and
/// the certificate derive.
///
/// The record is written before the answer leaves the process, so the
/// journal cannot check that it was sent — which is exactly why it must
/// check that it is the right one. An arbitrary digest taken on trust
/// would be the worst of both: this contest would read as answered while
/// the answer that actually spends the certificate was still unsent, and
/// the journal would then refuse *that* answer as a disagreement.
///
/// The rest is what a written answer has to survive. The same answer
/// again is the retry it is and costs no write; a different one to the
/// same contest is this endpoint contradicting what it may already have
/// sent. And an answer to a contest nothing is owed on — none open, one
/// this endpoint opened itself, one already at its own high-water, or a
/// client's journal, which has nothing to spend — is not a step this
/// state can take at all.
#[tokio::test]
async fn one_contest_admits_one_answer() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open(dir.path(), Role::Provider).await;
    let start_id = hellas_kernel::StartId::from_bytes([0x7c; 32]);
    let arbitrary = ChannelRecord::CloseResponded {
        start_id,
        response_digest: PayloadHash::from_bytes([0x7d; 32]),
    };

    // There is nothing to answer yet.
    let early = store.commit(arbitrary.clone(), &verifier).await;
    assert!(
        matches!(
            early,
            Err(WorkStoreError::Channel(
                ChannelStateError::WrongPhase { .. }
            ))
        ),
        "an answer names a contest this journal has read: {early:?}",
    );

    commit_all(&mut store, &provider_sequence(&channel, &job).await).await;
    commit_all(
        &mut store,
        &[ChannelRecord::CloseOpened {
            start_id,
            opener: Party::Maker,
            response_deadline: RECEIPT_HEIGHT + 16,
            claimed: 0,
        }],
    )
    .await;

    // A digest this contest and this certificate do not derive is not
    // this endpoint's answer, whatever wrote it down.
    let invented = store.commit(arbitrary, &verifier).await;
    assert!(
        matches!(
            invented,
            Err(WorkStoreError::Channel(ChannelStateError::WrongChannel {
                field: "close response digest"
            }))
        ),
        "an invented answer is refused: {invented:?}",
    );
    assert_eq!(
        store.state().close_responded(),
        None,
        "and left nothing behind to suppress the real one",
    );

    // The one answer those two derive.
    let answer = ChannelRecord::CloseResponded {
        start_id,
        response_digest: hellas_work::work_close::response_body_digest(
            &channel,
            start_id,
            &job.certificate,
        ),
    };
    commit_all(&mut store, std::slice::from_ref(&answer)).await;
    assert_eq!(
        store.state().close_responded().map(|held| held.start_id),
        Some(start_id),
    );

    // The retry writes nothing.
    let before = store.len();
    commit_all(&mut store, &[answer]).await;
    assert_eq!(store.len(), before, "the same answer is not written twice");

    // A second, different answer to that same contest is not a retry.
    let disagreement = store
        .commit(
            ChannelRecord::CloseResponded {
                start_id,
                response_digest: PayloadHash::from_bytes([0x7e; 32]),
            },
            &verifier,
        )
        .await;
    assert!(
        matches!(
            disagreement,
            Err(WorkStoreError::Channel(ChannelStateError::Conflict { .. }))
        ),
        "one window, one answer: {disagreement:?}",
    );

    // Nor is an answer to some other contest.
    let elsewhere = store
        .commit(
            ChannelRecord::CloseResponded {
                start_id: hellas_kernel::StartId::from_bytes([0x7f; 32]),
                response_digest: PayloadHash::from_bytes([0x7d; 32]),
            },
            &verifier,
        )
        .await;
    assert!(
        matches!(
            elsewhere,
            Err(WorkStoreError::Channel(ChannelStateError::Conflict { .. }))
        ),
        "the answer this journal holds is the answer to its own contest: {elsewhere:?}",
    );

    // A contest this provider opened itself is not one it answers, and
    // neither is one already at its own high-water. Both are frozen the
    // moment they are journaled, so neither becomes answerable later.
    for (opener, claimed, what) in [
        (Party::Taker, 0, "a contest this endpoint opened"),
        (
            Party::Maker,
            PRICE,
            "a contest at this endpoint's high-water",
        ),
    ] {
        let unowed = temp();
        let mut store = open(unowed.path(), Role::Provider).await;
        commit_all(&mut store, &provider_sequence(&channel, &job).await).await;
        commit_all(
            &mut store,
            &[ChannelRecord::CloseOpened {
                start_id,
                opener,
                response_deadline: RECEIPT_HEIGHT + 16,
                claimed,
            }],
        )
        .await;
        let refused = store
            .commit(
                ChannelRecord::CloseResponded {
                    start_id,
                    response_digest: hellas_work::work_close::response_body_digest(
                        &channel,
                        start_id,
                        &job.certificate,
                    ),
                },
                &verifier,
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(WorkStoreError::Channel(
                    ChannelStateError::WrongPhase { .. }
                ))
            ),
            "{what} is owed no answer: {refused:?}",
        );
    }

    // And a client has nothing to answer with.
    let other = temp();
    let mut client_store = open(other.path(), Role::Client).await;
    commit_all(
        &mut client_store,
        &[ChannelRecord::CloseOpened {
            start_id,
            opener: Party::Maker,
            response_deadline: RECEIPT_HEIGHT + 16,
            claimed: 0,
        }],
    )
    .await;
    let wrong_role = client_store
        .commit(
            ChannelRecord::CloseResponded {
                start_id,
                response_digest: PayloadHash::from_bytes([0x7d; 32]),
            },
            &verifier,
        )
        .await;
    assert!(
        matches!(
            wrong_role,
            Err(WorkStoreError::Channel(ChannelStateError::WrongRole { .. }))
        ),
        "only the certificate's beneficiary answers: {wrong_role:?}",
    );
}

// ── Rotation ──────────────────────────────────────────────────────────

/// A provider holding a delivered job that has not been paid for.
///
/// The half of the state a settled channel cannot hold: an open job,
/// with its authorization, its inputs, both signatures, its signed
/// result and the transcript that result was rebuilt from.
async fn delivered_store(root: &std::path::Path) -> ChannelStore {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = open_on(root, channel.clone(), Role::Provider).await;
    advance(&mut store, RECEIPT_HEIGHT).await;
    commit_all(
        &mut store,
        &[
            job.proposed(),
            job.accepted(),
            ChannelRecord::JobRunning {
                work_id: job.work_id,
            },
            job.result_record(&channel),
            ChannelRecord::PlaintextReleased {
                work_id: job.work_id,
            },
        ],
    )
    .await;
    store
}

/// A provider whose one job is paid for and whose edge has closed.
///
/// The other half: a certified terminal, the ledger that terminal
/// credited, the retained close start, the contest, the answer fixed for
/// it, and the settlement that ended it.
async fn closed_store(root: &std::path::Path) -> ChannelStore {
    let channel = channel();
    let job = job_at(&channel, 1, 0);
    let mut store = delivered_store(root).await;
    commit_all(&mut store, &[job.paid(&channel)]).await;

    let start = hellas_kernel::PaymentCloseStart::new(
        channel.payment_edge(),
        hellas_kernel::Terms::work_payment(channel.payment_terms().clone()),
        Party::Taker,
        (RECEIPT_HEIGHT + 1, RECEIPT_HEIGHT + 8),
        Some((
            job.certificate,
            PartyAuth::owner(client().sign(job.certificate.digest(channel.network()))),
        )),
        // This reducer fixture retains a synthetic action signature; both parties are sole owners.
        PartyAuth::owner(provider().sign(payload(job.work_id))),
    );
    let start_id = hellas_kernel::StartId::from_bytes([0x7c; 32]);
    commit_all(
        &mut store,
        &[
            ChannelRecord::ClosePrepared {
                start: Box::new(start),
            },
            ChannelRecord::CloseOpened {
                start_id,
                opener: Party::Maker,
                response_deadline: RECEIPT_HEIGHT + 16,
                claimed: 0,
            },
            ChannelRecord::CloseResponded {
                start_id,
                response_digest: hellas_work::work_close::response_body_digest(
                    &channel,
                    start_id,
                    &job.certificate,
                ),
            },
            ChannelRecord::CloseSettled {
                height: RECEIPT_HEIGHT + 20,
                payload: payload_at(RECEIPT_HEIGHT + 20),
                provider_payout: PRICE,
            },
        ],
    )
    .await;
    store
}

/// Exercise both delivered and closed obligations during rotation.
const FIXTURES: [(&str, bool); 2] = [("delivered", false), ("closed", true)];

async fn fixture(root: &std::path::Path, closed: bool) -> ChannelStore {
    if closed {
        closed_store(root).await
    } else {
        delivered_store(root).await
    }
}

/// Reply uncertainty is independent of the retained signature. Rotation must
/// preserve both a pending exchange and a refused, still half-signed job.
#[tokio::test]
async fn proposal_ordering_survives_checkpoint_rotation() {
    let dir = temp();
    let verifier = Secp256k1Verifier::new();
    let job = job_at(&channel(), 1, 0);
    let mut store = open(dir.path(), Role::Client).await;
    store.commit(job.proposed(), &verifier).await.unwrap();
    for pending in [true, false, true] {
        store
            .commit(
                ChannelRecord::ProposalExchange {
                    work_id: job.work_id,
                    pending,
                },
                &verifier,
            )
            .await
            .unwrap();
        let expected = store.state().clone();
        store.rotate().await.unwrap();
        drop(store);
        store = open(dir.path(), Role::Client).await;
        assert_eq!(store.state(), &expected);
        assert_eq!(
            store.state().job_book().pending_proposal(),
            pending.then_some(job.work_id)
        );
        assert_eq!(
            store.state().job_by_id(job.work_id).unwrap().phase(),
            JobPhase::HalfSigned
        );
        let another = job_at(&channel(), 2, 0);
        if pending {
            assert!(store.commit(another.proposed(), &verifier).await.is_err());
            assert_eq!(store.state().proposal_nonce_high_water(), 1);
        }
    }
}

/// A valid journal frame cannot make an accepted, nonexistent, or provider job
/// the client's pending proposal. Reopening revalidates the checkpoint itself.
#[tokio::test]
async fn invalid_pending_proposals_are_rejected_at_checkpoint_replay() {
    let verifier = Secp256k1Verifier::new();
    for (role, accepted, unknown) in [
        (Role::Client, true, false),
        (Role::Client, false, true),
        (Role::Provider, false, false),
    ] {
        let dir = temp();
        let channel = channel();
        let job = job_at(&channel, 1, 0);
        let mut store = open(dir.path(), role).await;
        store.commit(job.proposed(), &verifier).await.unwrap();
        if accepted {
            store.commit(job.accepted(), &verifier).await.unwrap();
        }
        let mut bytes = store.state().checkpoint();
        let suffix = if store.state().job_book().pending_proposal().is_some() {
            33
        } else {
            1
        };
        bytes.truncate(bytes.len() - suffix);
        bytes.push(1);
        bytes.extend_from_slice(if unknown {
            &[0xff; 32]
        } else {
            job.work_id.as_bytes()
        });
        drop(store);
        let stem = channel_stem(dir.path());
        let (id, _) = Journal::inspect(dir.path(), &stem).await.unwrap();
        let (mut journal, _) = Journal::open_existing(dir.path(), &stem, id).await.unwrap();
        journal.rotate(&bytes).await.unwrap();
        drop(journal);
        assert!(matches!(
            ChannelStore::open(
                dir.path(),
                channel.clone(),
                settlement(),
                role,
                origin_of(&channel),
                &verifier
            )
            .await,
            Err(WorkStoreError::Channel(_))
        ));
    }
}

/// What a checkpoint replays to is exactly what the frames it replaced
/// replayed to.
///
/// The comparison is of the whole [`Channel`], not of the fields
/// this test happens to think of: a field added to that struct and left
/// out of the checkpoint fails to compile, and a field added and encoded
/// wrongly fails here, as long as one of the two fixtures reaches a
/// value for it that is not the one a fresh store starts at. What each
/// fixture reaches is asserted below rather than assumed.
#[tokio::test]
async fn a_checkpoint_replays_to_what_the_frames_replayed_to() {
    for (label, closed) in FIXTURES {
        let control = temp();
        let expected = fixture(control.path(), closed).await.state().clone();

        let rotated = temp();
        {
            let mut store = fixture(rotated.path(), closed).await;
            if let Err(error) = store.rotate().await {
                panic!("{label}: the rotation completes: {error}");
            }
            assert_eq!(
                store.len(),
                0,
                "{label}: a fresh generation holds its checkpoint and nothing else",
            );
        }
        let reopened = open(rotated.path(), Role::Provider).await;
        assert_eq!(
            reopened.state(),
            &expected,
            "{label}: the checkpoint is the state, not a summary of it",
        );
    }

    let delivered = temp();
    let delivered = delivered_store(delivered.path()).await;
    let delivered = delivered.state();
    let Some(job) = delivered.jobs().next() else {
        panic!("the delivered fixture holds its job");
    };
    assert_eq!(job.phase(), JobPhase::Delivered);
    assert!(job.provider_signature().is_some());
    assert!(job.result().is_some());
    assert!(!job.transcript().is_empty());
    assert!(!job.prepared_input().is_empty());
    assert_eq!(delivered.cursor().0, RECEIPT_HEIGHT);
    assert_eq!(delivered.terminals().next(), None);

    let closed = temp();
    let closed = closed_store(closed.path()).await;
    let closed = closed.state();
    assert!(closed.jobs().next().is_none());
    assert!(closed.terminals().next().is_some());
    assert_eq!(closed.ledger().credited_cumulative(), PRICE);
    assert!(closed.close_prepared().is_some());
    assert!(closed.close_opened().is_some());
    assert!(closed.close_responded().is_some());
    assert!(closed.close_settled().is_some());
    assert!(closed.last_payment().is_some());
}

/// A duty outlives the file it is written in, however many times that
/// file has to be replaced.
///
/// This is the case the whole slice is for. The channel is closed and
/// paid; what is left is a provider reading blocks, which consensus does
/// not bound and a file does. It advances the cursor far enough to cross
/// the soft limit twice, and what is asserted afterwards is that the
/// certificate, the terminal and the answer are still there — and that
/// the bytes on the disk are bounded by one generation rather than by
/// the number of blocks read.
#[tokio::test]
async fn a_duty_survives_repeated_rotation() {
    use hellas_work::work_store::journal::{MAX_ACTIVE_FRAMES, MAX_ACTIVE_JOURNAL_BYTES};

    let dir = temp();
    let expected = {
        let mut store = closed_store(dir.path()).await;
        let before = store.state().clone();
        let start = store.state().cursor().0;
        // Two soft limits' worth of blocks, and a few more, so the
        // second rotation is not the last record written.
        advance(&mut store, start + 2 * MAX_ACTIVE_FRAMES + 32).await;
        assert_eq!(
            store.state().cursor().0,
            start + 2 * MAX_ACTIVE_FRAMES + 32,
            "every block was read",
        );
        assert_eq!(
            store.state().terminals().next(),
            before.terminals().next(),
            "rotation moves bytes and not facts",
        );
        store.state().clone()
    };

    let bytes: u64 = hellas_work::test_support::all_files(dir.path())
        .iter()
        .map(|path| std::fs::metadata(path).unwrap().len())
        .sum();
    assert!(
        bytes < MAX_ACTIVE_JOURNAL_BYTES,
        "the live generation is bounded, not the block count: {bytes} bytes",
    );

    let reopened = open(dir.path(), Role::Provider).await;
    assert_eq!(reopened.state(), &expected);
    assert!(
        reopened.state().last_payment().is_some(),
        "the certificate a close still has to carry",
    );
    assert!(
        reopened.state().close_responded().is_some(),
        "and the one answer this endpoint fixed",
    );
}
