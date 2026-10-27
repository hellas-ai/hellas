//! Paid setup, work and settlement across six independently executing
//! validators and two full nodes. Only block ordering and the model backend
//! are fixtures. Providers and clients read their own executed QMDB, fetch
//! certified history over the network, and submit to validator mempools.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use commonware_cryptography::Digestible as _;
use hellas_auth::{ProducerSigningKey, PublicKey as RpcPublicKey};
use hellas_client::work::payment::pay_for_result;
use hellas_client::work::reproduce::{
    ReproduceFault, Reproduced, Reproducer, plan as reproduction_plan,
};
use hellas_client::work::{CheckedResult, CollectOutcome, collect_checked_result};
use hellas_kernel::{
    BlockHeight, CoinId, EdgeId, EdgeValues, Fees, Funding, List, MAX_EDGE_OUTPUTS,
    MAX_PARTY_INPUTS, MIN_OMIT_RESPONSE_BLOCKS, Move, Parties, Party, PartyKeys, Payout,
    PendingSlot, Secp256k1Signer, Secp256k1Verifier, Terms as KernelTerms, Tx as KernelTx,
    WorkPaymentTerms, WorkStakeBondTerms,
};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::pb::work::{ExchangeSetupRequest, exchange_setup_response::Outcome};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, SourceRef,
    TextArtifact, TextExecution, TextExecutionId, TextPolicy, TokenIds, completed_text,
};
use hellas_rpc::services::work::WorkServer;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProgramManifest,
};
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use hellas_wire::{DefaultClock, Dispatcher, StreamTransport as _, TransportContext};
use hellas_work::model::prepared_input::PreparedPaidInputV1;
use hellas_work::model::setup::{
    ProviderChannelPolicy, ReadyChannel, WorkChannelConfig, WorkChannelDescriptor,
};
use hellas_work::model::work::{
    EvaluatePolicyV2, JobDeadlines, PaidChannelPolicyV1, generation_policy_digest,
    identity_source_digest, private_policy_commitment,
};
use hellas_work::work::{
    BackendFault, ClientEndpoint, CloseEndpoint, JobProposal, PaymentError, RunOutcome,
    WorkBackend, WorkService, propose_work, run_accepted_work,
};
use hellas_work::work_close::{CloseProgress, TxSink, close_start};
use hellas_work::work_handshake::{PaymentAdmission, SetupEndpoint, SetupService};
use hellas_work::work_open::{SetupAdvance, SetupProgress, SetupStep, advance_setup};
use hellas_work::work_store::{Role, SetupOrigin, SetupScan, SetupStore};
use tokio::sync::mpsc;

use crate::HellasBlock;
use crate::domain::{SettlementKey, TEST_NETWORK};
use crate::rpc::LocalLightClient;
use crate::test_support::devnet::{
    Devnet, DevnetConfig, GenesisOwner, OwnerKind, delegate_allocation, genesis_coin,
    run as run_qmdb,
};
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

/// The two genesis allocations, as the chain minted them, and how the
/// parties hold them.
#[derive(Clone)]
struct Allocations {
    coins: Vec<(SettlementKey, u64)>,
    owners: OwnerKind,
    locked: bool,
    owner_exit: bool,
}
impl std::ops::Deref for Allocations {
    type Target = [(SettlementKey, u64)];
    fn deref(&self) -> &Self::Target {
        &self.coins
    }
}
impl Allocations {
    fn client_owner(&self) -> GenesisOwner {
        GenesisOwner {
            kind: self.owners,
            secret_scalar: [0x31; 32],
            balance: CLIENT_FUNDING,
        }
    }
    fn provider_owner(&self) -> GenesisOwner {
        GenesisOwner {
            kind: self.owners,
            secret_scalar: [0x32; 32],
            balance: PROVIDER_STAKE,
        }
    }
    fn client_key(&self) -> SettlementKey {
        self.client_owner().key()
    }
    fn provider_key(&self) -> SettlementKey {
        self.provider_owner().key()
    }
}

/// One party's whole genesis allocation, reshaped into a coin delegated
/// to its node key.
fn delegated_funding(
    allocations: &Allocations,
    is_client: bool,
) -> (crate::domain::Transaction, CoinId) {
    let (owner, node) = if is_client {
        (allocations.client_owner(), client())
    } else {
        (allocations.provider_owner(), provider())
    };
    delegate_allocation(allocations, &owner, node.party_key().into())
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

fn bond_terms(allocations: &Allocations) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(
            PartyKeys::new(
                allocations.provider_key().into_kernel(),
                provider().party_key(),
                (!allocations.locked).then_some(provider().party_key()),
            ),
            PartyKeys::new(
                allocations.client_key().into_kernel(),
                client().party_key(),
                (!allocations.locked).then_some(client().party_key()),
            ),
        ),
        timeout: BlockHeight::new(HORIZON),
        timeout_outputs: List::take(
            [Payout::delegated(
                allocations.provider_key().into_kernel(),
                (!allocations.locked).then_some(provider().party_key()),
                PROVIDER_STAKE,
            ); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: CREDIT_LIMIT,
    }
}

fn bond_funding(allocations: &Allocations) -> Funding {
    Funding::new(
        one_coin(delegated_funding(allocations, false).1),
        no_coins(),
    )
}

fn payment_funding(allocations: &Allocations) -> Funding {
    Funding::new(one_coin(delegated_funding(allocations, true).1), no_coins())
}

fn bond_edge(allocations: &Allocations) -> EdgeId {
    KernelTx::edge_id_of(
        &bond_funding(allocations),
        &KernelTerms::work_stake_bond(bond_terms(allocations)),
    )
}

fn payment_edge(allocations: &Allocations) -> EdgeId {
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

fn work_policy() -> EvaluatePolicyV2 {
    EvaluatePolicyV2 {
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
        max_encoded_prepared_input: 1_048_576,
    }
}

fn payment_terms(allocations: &Allocations) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(allocations),
        bond_terms: bond_terms(allocations),
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
        payment_policy: payment_policy(),
        network: TEST_NETWORK,
        policy_salt: SALT,
        channel_policy: channel_policy(),
        work_policy: work_policy().into(),
        expected_payment_values: expected_values(),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    }
}

fn descriptor(allocations: &Allocations) -> WorkChannelDescriptor {
    match WorkChannelDescriptor::open(WorkChannelConfig {
        payment_policy: payment_policy(),
        network: TEST_NETWORK,
        payment_edge: payment_edge(allocations),
        payment_terms: payment_terms(allocations),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        work_policy: work_policy().into(),
        expected_payment_values: expected_values(),
    }) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the configured channel opens: {error}"),
    }
}

// ── The chain both parties read ───────────────────────────────────────

/// The six-validator devnet with both parties' allocations, and the
/// paid-work reads this file asserts through.
struct WorkDevnet {
    devnet: Devnet,
    allocations: Allocations,
}

impl std::ops::Deref for WorkDevnet {
    type Target = Devnet;
    fn deref(&self) -> &Devnet {
        &self.devnet
    }
}

impl std::ops::DerefMut for WorkDevnet {
    fn deref_mut(&mut self) -> &mut Devnet {
        &mut self.devnet
    }
}

impl WorkDevnet {
    async fn start(
        runtime: commonware_runtime::tokio::Context,
        name: &str,
        owners: OwnerKind,
        locked: bool,
        owner_exit: bool,
    ) -> Self {
        let mut allocations = Allocations {
            coins: Vec::new(),
            owners,
            locked,
            owner_exit,
        };
        let devnet = Devnet::start(
            runtime,
            DevnetConfig {
                name,
                owners: vec![allocations.client_owner(), allocations.provider_owner()],
                full_nodes: 2,
            },
        )
        .await;
        allocations.coins = devnet.allocations().to_vec();
        Self {
            devnet,
            allocations,
        }
    }

    fn blocks(&self, node: usize) -> WorkBlocks<LocalLightClient> {
        WorkBlocks::new(self.light_client(node))
    }

    /// Every coin this fixture's transaction graph can mint for one
    /// owner at the finalized tip, each checked for the delegation its
    /// payout committed.
    async fn coins(&self, node: usize, owner: SettlementKey) -> Vec<(CoinId, u64)> {
        let allocations = &self.allocations;
        let (earnings, refund) = payment_close_coins(allocations);
        let mut ids = BTreeSet::from([
            genesis_coin(allocations, allocations.client_key()),
            genesis_coin(allocations, allocations.provider_key()),
            earnings,
            refund,
        ]);
        ids.extend(
            KernelTx::close_output_ids(
                bond_edge(allocations),
                &bond_terms(allocations).timeout_outputs,
            )
            .iter()
            .copied(),
        );
        let funding_coin = delegated_funding(allocations, owner == allocations.client_key()).1;
        self.devnet
            .coins(node, owner, ids)
            .await
            .into_iter()
            .map(|(id, coin)| {
                let undelegated = id == genesis_coin(allocations, owner)
                    || (allocations.locked && id != funding_coin)
                    || (allocations.owner_exit && id == refund);
                let expected_delegate = if undelegated {
                    None
                } else if owner == allocations.client_key() {
                    Some(SettlementKey::from(client().party_key()))
                } else {
                    Some(SettlementKey::from(provider().party_key()))
                };
                assert_eq!(
                    coin.delegate, expected_delegate,
                    "executed payout retains its committed node delegation"
                );
                (id, coin.value)
            })
            .collect()
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
        allocations: &Allocations,
    ) -> crate::work_view::WorkChannelSnapshot {
        self.light_client(node)
            .work_channel_snapshot(WorkChannelQuery {
                bond_edge: bond_edge(allocations),
                payment_edge: Some(payment_edge(allocations)),
                funding: BTreeSet::new(),
            })
            .await
            .expect("a channel snapshot reads")
            .expect("finalized channel state exists")
    }

    async fn shutdown(self) {
        self.devnet.shutdown().await;
    }
}

// ── The handshake, and the setup drive ────────────────────────────────

async fn open_setup(root: &std::path::Path, bond: EdgeId, role: Role) -> SetupStore {
    match SetupStore::open(root, TEST_NETWORK, bond, role, &Secp256k1Verifier::new()).await {
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
async fn exchange(service: &SetupService, bond: EdgeId, bundle: Vec<u8>) -> Vec<u8> {
    let answered = WorkSetupHandler::exchange_setup(
        service,
        ExchangeSetupRequest {
            bond_edge: bond.as_bytes().to_vec(),
            bundle,
        },
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
    allocations: &Allocations,
    scan: SetupScan,
) -> Handshake {
    let bond = bond_edge(allocations);
    let mut proposer = SetupEndpoint::new(
        open_setup(provider_root, bond, Role::Provider).await,
        provider(),
        PaymentAdmission::Admits(Box::new(provider_policy())),
    );
    proposer
        .arm_scan(scan)
        .await
        .expect("the provider arms its scan");
    if let Err(error) = proposer
        .propose_bond(
            TEST_NETWORK,
            bond_funding(allocations),
            bond_terms(allocations),
        )
        .await
    {
        panic!("the provider proposes its bond: {error}");
    }
    let service = SetupService::new(proposer);

    let mut caller = SetupEndpoint::new(
        open_setup(client_root, bond, Role::Client).await,
        client(),
        PaymentAdmission::Proposes(Box::new(provider_policy())),
    );
    let proposal = exchange(&service, bond_edge(allocations), Vec::new()).await;
    if let Err(error) = caller.import(&proposal).await {
        panic!("the client imports the bond proposal: {error}");
    }
    caller
        .arm_scan(scan)
        .await
        .expect("the client arms its scan");
    if let Err(error) = caller
        .propose_payment(payment_funding(allocations), payment_terms(allocations))
        .await
    {
        panic!("the client proposes its payment: {error}");
    }
    let offered = caller
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("the client holds revision 2");
    let countersigned = exchange(&service, bond_edge(allocations), offered).await;
    if let Err(error) = caller.import(&countersigned).await {
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

impl WorkBackend for ProviderBackend {
    fn try_admit(
        &self,
        domain: hellas_work::work::admission::CapacityDomain,
    ) -> Result<hellas_work::work::admission::WorkPermit, BackendFault> {
        Err(hellas_work::work::admission::AdmissionError::Unsupported(domain).into())
    }

    async fn execute(
        &self,
        prepared: hellas_work::work::PreparedWorkInput,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, BackendFault> {
        let hellas_work::work::PreparedWorkInput::Evaluate(input) = prepared else {
            return Err(hellas_work::work::admission::AdmissionError::Unsupported(
                hellas_work::work::admission::CapacityDomain::Fetch,
            )
            .into());
        };
        let input = *input;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = FixtureExecutor::run(&self.prompt, work_policy().max_new_tokens);
        let prompt = self.prompt.clone();
        Ok(transcript_for(input.evaluate_request(), &prompt, &answer))
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
    devnet: &mut WorkDevnet,
    provider_root: &std::path::Path,
    client_root: &std::path::Path,
) -> Opened {
    let allocations = devnet.allocations.clone();
    // Full-node views are unavailable until the first certified block executes.
    devnet.seal().await;
    let provider_blocks = devnet.blocks(PROVIDER_NODE);
    let client_blocks = devnet.blocks(CLIENT_NODE);
    assert_eq!(
        devnet
            .value_of(
                PROVIDER_NODE,
                allocations.client_key(),
                genesis_coin(&allocations, allocations.client_key())
            )
            .await,
        Some(CLIENT_FUNDING),
        "genesis funded the client owner",
    );
    assert_eq!(
        devnet
            .value_of(
                CLIENT_NODE,
                allocations.provider_key(),
                genesis_coin(&allocations, allocations.provider_key())
            )
            .await,
        Some(PROVIDER_STAKE),
        "genesis funded the provider owner",
    );

    for is_client in [false, true] {
        let crate::domain::Transaction::Kernel(tx) = delegated_funding(&allocations, is_client).0;
        assert_eq!(
            devnet.blocks(CLIENT_NODE).submit(tx).await.unwrap(),
            crate::SubmitTxOutcome::Enqueued
        );
    }
    let floor = devnet.seal().await;
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
    let mut client_setup = open_setup(client_root, bond_edge(&allocations), Role::Client).await;
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
    if let Err(error) = service.admit_new_work(ready.clone()).await {
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
async fn run_one_paid_job(devnet: &WorkDevnet, opened: &mut Opened) -> u64 {
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
    let too_early = opened.client.pay(work_id).await;
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
            .await
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
async fn provider_clock(devnet: &WorkDevnet, service: &WorkService) -> PaidWorkClockAdvance {
    let blocks = devnet.blocks(PROVIDER_NODE);
    advance_paid_work_clock(service, &blocks)
        .await
        .expect("the provider's production clock advances")
}

/// Drives the provider's close until the contest it opened is on chain.
async fn drive_close_onto_chain(devnet: &mut WorkDevnet, service: &WorkService) {
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
async fn settle_on_the_clock(devnet: &mut WorkDevnet, service: &WorkService) -> HellasBlock {
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
async fn return_the_stake(devnet: &mut WorkDevnet, service: &WorkService) -> CoinId {
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
    let outputs = KernelTx::close_output_ids(
        bond_edge(&allocations),
        &bond_terms(&allocations).timeout_outputs,
    );
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
fn payment_close_coins(allocations: &Allocations) -> (CoinId, CoinId) {
    let edge = payment_edge(allocations);
    (
        Payout::delegated(
            allocations.provider_key().into_kernel(),
            (!allocations.locked).then_some(provider().party_key()),
            0,
        )
        .id(edge, 0),
        Payout::delegated(
            allocations.client_key().into_kernel(),
            (!allocations.locked).then_some(client().party_key()),
            0,
        )
        .id(edge, 1),
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
    for owners in [OwnerKind::Native, OwnerKind::Passkey] {
        for locked in [false, true] {
            eprintln!("paid lifecycle owners={owners:?}, locked={locked}");
            run_qmdb(move |runtime| async move {
                let provider_root = tempfile::tempdir().expect("a temp dir");
                let client_root = tempfile::tempdir().expect("a temp dir");
                let mut devnet =
                    WorkDevnet::start(runtime, "work_e2e_paid", owners, locked, false).await;
                let allocations = devnet.allocations.clone();

                let mut opened =
                    open_channel(&mut devnet, provider_root.path(), client_root.path()).await;
                assert_eq!(opened.origin.payment_edge, payment_edge(&allocations));

                // The provider's stake is locked and its genesis coin is gone,
                // so nothing it holds now can be mistaken for earnings later.
                assert_eq!(
                    devnet
                        .coins(PROVIDER_NODE, allocations.provider_key())
                        .await,
                    Vec::new(),
                    "the provider holds no coin at all while its stake is bonded",
                );

                let credited = run_one_paid_job(&devnet, &mut opened).await;
                assert_eq!(credited, PRICE);

                // Nothing has moved on chain yet: an admitted certificate is not
                // a payout.
                assert_eq!(
                    devnet
                        .coins(PROVIDER_NODE, allocations.provider_key())
                        .await,
                    Vec::new(),
                    "an off-chain certificate pays nobody",
                );

                // Settle. The provider opens its own close at the certificate it
                // holds; there is nothing for anyone to answer.
                opened
                    .service
                    .prepare_close()
                    .await
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
                        .value_of(PROVIDER_NODE, allocations.provider_key(), earnings_coin)
                        .await,
                    Some(PRICE),
                    "EARNINGS: the payment close paid the provider exactly the job price",
                );
                assert_eq!(
                    devnet
                        .value_of(CLIENT_NODE, allocations.provider_key(), earnings_coin)
                        .await,
                    Some(PRICE),
                    "and a second validator's finalized QMDB says the same",
                );
                assert_eq!(
                    devnet
                        .coins(PROVIDER_NODE, allocations.provider_key())
                        .await,
                    vec![(earnings_coin, PRICE)],
                    "EARNINGS ARE THE WHOLE OF WHAT THE PROVIDER HOLDS: \
             no principal has come back yet, so this number cannot be one",
                );

                // The client's side of the same close.
                assert_eq!(
                    devnet
                        .value_of(CLIENT_NODE, allocations.client_key(), refund_coin)
                        .await,
                    Some(CLIENT_FUNDING - PRICE),
                    "the client got back its funding less exactly the job price",
                );
                assert_eq!(
                    devnet.coins(CLIENT_NODE, allocations.client_key()).await,
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
                        .value_of(PROVIDER_NODE, allocations.provider_key(), principal_coin)
                        .await,
                    Some(PROVIDER_STAKE),
                    "RETURNED PRINCIPAL: the bond timeout returned the stake, 12, unchanged",
                );
                assert_eq!(
                    devnet
                        .value_of(PROVIDER_NODE, allocations.provider_key(), earnings_coin)
                        .await,
                    Some(PRICE),
                    "and the earnings coin is still exactly the price, 10, unchanged by it",
                );

                // The whole provider balance, decomposed. 22 = 10 earned + 12
                // returned, and the two halves are named.
                let mut held = devnet
                    .coins(PROVIDER_NODE, allocations.provider_key())
                    .await;
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
    }
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
    for owners in [OwnerKind::Native, OwnerKind::Passkey] {
        for owner_exit in [false, true] {
            eprintln!("contested lifecycle owners={owners:?}, owner_exit={owner_exit}");
            run_qmdb(move |runtime| async move {
                let provider_root = tempfile::tempdir().expect("a temp dir");
                let client_root = tempfile::tempdir().expect("a temp dir");
                let mut devnet =
                    WorkDevnet::start(runtime, "work_e2e_contest", owners, false, owner_exit).await;
                let allocations = devnet.allocations.clone();

                let mut opened =
                    open_channel(&mut devnet, provider_root.path(), client_root.path()).await;
                assert_eq!(run_one_paid_job(&devnet, &mut opened).await, PRICE);

                // The client opens a close claiming the provider earned nothing.
                // Its own signature, on the real start builder, at the height
                // its own validator reports.
                let start = close_start(
                    opened.ready.channel(),
                    Party::Maker,
                    devnet.height(),
                    None,
                    &client(),
                )
                .expect("the client signs an understated start");
                let start = if allocations.owner_exit {
                    let hash =
                        hellas_work::work_close::start_body_digest(opened.ready.channel(), &start);
                    hellas_kernel::PaymentCloseStart::new(
                        start.payment_edge(),
                        start.terms().clone(),
                        start.opener_role(),
                        (start.valid_from_height(), start.valid_through_height()),
                        start.certificate().cloned(),
                        hellas_kernel::PartyAuth::new(
                            hellas_kernel::Authority::Owner,
                            allocations.client_owner().authorize(hash),
                        ),
                    )
                } else {
                    start
                };
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

                let opened_at = devnet.height();
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
                    devnet.height() < deadline,
                    "and it landed at {} — before the deadline at {deadline}",
                    devnet.height(),
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
                        .value_of(PROVIDER_NODE, allocations.provider_key(), earnings_coin)
                        .await,
                    Some(paid),
                    "the adjudicated close paid the certificate amount plus the bond: 10 + 4",
                );
                assert_eq!(
                    devnet
                        .coins(PROVIDER_NODE, allocations.provider_key())
                        .await,
                    vec![(earnings_coin, paid)],
                    "and that is the whole of what the provider holds: no principal is in it",
                );
                assert_eq!(
                    devnet
                        .value_of(CLIENT_NODE, allocations.client_key(), refund_coin)
                        .await,
                    Some(CLIENT_FUNDING - paid),
                    "the client kept 86 of its 100, having tried to keep 100",
                );

                // And the principal, separately, as above.
                let principal_coin = return_the_stake(&mut devnet, &opened.service).await;
                assert_eq!(
                    devnet
                        .value_of(PROVIDER_NODE, allocations.provider_key(), principal_coin)
                        .await,
                    Some(PROVIDER_STAKE),
                    "RETURNED PRINCIPAL: still 12, still not earnings",
                );

                drop(opened);
                devnet.shutdown().await;
            });
        }
    }
}

fn payment_policy() -> hellas_work::model::work::JobPaymentPolicyV2 {
    hellas_work::model::work::JobPaymentPolicyV2 {
        fixed_price: PRICE,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}
