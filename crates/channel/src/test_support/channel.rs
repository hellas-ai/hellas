//! Shared funded-channel and signed invocation fixtures for paid-work tests.

use super::transport::transport_pair;
use crate::model::setup::ObservedChannel;
use crate::model::work::{PaidJobAuthorizationV2, signing_hash, work_id};
use crate::work::{
    BackendFault, ClientEndpoint, ProviderEndpoint, RunOutcome, WorkBackend, WorkService,
    fetch_result_stream, run_accepted_work,
};
use hellas_kernel::PendingSlot;
use hellas_rpc::services::work::WorkServer;
use hellas_wire::mux::MuxTransport;
use hellas_wire::{Dispatcher, StreamTransport};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crate::model::setup::{
    ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use crate::model::work::{JobDeadlines, PaidChannelPolicyV1, private_policy_commitment};
use crate::work_store::{ChannelRecord, ChannelStore, Role, SetupOrigin};
use hellas_auth::{Digest, ProducerSigningKey, PublicKey};
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, PartyKeys, Payout, Secp256k1Signer, Secp256k1Verifier,
    Terms, TermsHash, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::protocol::invocation::{
    self, Admission, Artifact, InvocationInput, InvocationPolicy, InvocationRequest, Limits,
    PreparedInvocation, compute, output,
};
use hellas_rpc::{Assurance, ContentId, JsonBytes, OutputEventEnvelope, ProgramManifest};

pub const HORIZON: u64 = 500;
pub const PRICE: u64 = 10;
pub const CREDIT_LIMIT: u64 = 40;

/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
pub const OMISSION_BOND: u64 = 601;
pub const PAYMENT_VALUE: u64 = 1_000;
pub const PAYMENT_RESERVE: u64 = 200;
pub const STAKE: u64 = 64;
pub const SALT: [u8; 32] = [0x5a; 32];

/// The finalized block both endpoints have processed through.
pub const CURSOR: u64 = 10;

/// The prompt this fixture's bundle carries, in tokens.
pub const PROMPT_TOKENS: u64 = 4;

/// A frame bound no legal delivery here comes close to.
pub const WIDE_FRAME: u32 = 262_144;

const FORMAT_VERSION: u8 = 1;
const TAG_BLOCK_HEIGHT: u8 = 1;
const TAG_FEES: u8 = 2;
const TAG_PARTIES: u8 = 3;
const TAG_EDGE: u8 = 5;
const TAG_BOND_LEASE: u8 = 31;

/// `Freeze | Adjudicated`: close-kind tags 3 and 4.
const WORK_PAYMENT_CLOSES: u8 = 0b0001_1000;

/// `Timeout` alone: close-kind tag 1.
const WORK_STAKE_CLOSES: u8 = 0b0000_0010;

pub fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-test") else {
        panic!("a short ascii id is a legal network id");
    };
    network
}

pub fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

pub fn client() -> Secp256k1Signer {
    signer(0x21)
}

pub fn provider() -> Secp256k1Signer {
    signer(0x22)
}

pub fn bond_edge() -> EdgeId {
    EdgeId::from_bytes([0x11; EdgeId::LENGTH])
}

pub fn payment_edge() -> EdgeId {
    EdgeId::from_bytes([0x22; EdgeId::LENGTH])
}

/// Distinct digests link synthetic blocks into a contiguous chain.
pub fn payload_at(height: u64) -> [u8; 32] {
    let mut payload = [0xc0; 32];
    for (slot, byte) in payload.iter_mut().zip(height.to_be_bytes()) {
        *slot = byte;
    }
    payload
}

/// Advance through empty finalized blocks using the production watcher.
pub async fn advance(store: &mut crate::work_store::ChannelStore, height: u64) {
    let mut next = store.state().cursor().0.saturating_add(1);
    while next <= height {
        let block = crate::work_close::FinalizedWork {
            height: next,
            parent: payload_at(next.saturating_sub(1)),
            payload: payload_at(next),
            txs: Vec::new(),
        };
        if let Err(error) =
            crate::work_close::observe(store, &block, &hellas_kernel::Secp256k1Verifier::new())
                .await
        {
            panic!("the fixture block applies: {error}");
        }
        next = next.saturating_add(1);
    }
}

pub fn channel_policy() -> PaidChannelPolicyV1 {
    credit_policy(CREDIT_LIMIT, CREDIT_LIMIT)
}

pub fn bond_terms() -> WorkStakeBondTerms {
    bond_terms_for(
        Parties::new(
            PartyKeys::sole(provider().party_key()),
            PartyKeys::sole(client().party_key()),
        ),
        BlockHeight::new(HORIZON),
        Payout::new(provider().party_key(), STAKE),
        40,
    )
}

pub fn payment_terms() -> WorkPaymentTerms {
    payment_terms_for(
        bond_edge(),
        bond_terms(),
        private_policy_commitment(network(), &SALT, &channel_policy()),
        hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        8,
        OMISSION_BOND,
    )
}

pub fn payment_values() -> EdgeValues {
    EdgeValues::new(PAYMENT_VALUE, PAYMENT_RESERVE, Fees::new(0, 0, 0, 0))
}

pub fn origin() -> SetupOrigin {
    SetupOrigin {
        payment_edge: payment_edge(),
        height: 0,
        payload: payload_at(0),
        parent: [0_u8; 32],
    }
}

pub fn settlement() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(payment_values(), OMISSION_BOND) else {
        panic!("a funded edge prices both exits");
    };
    settlement
}

pub fn payment_policy() -> crate::model::work::JobPaymentPolicyV2 {
    crate::model::work::JobPaymentPolicyV2 {
        fixed_price: PRICE,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}

pub fn environment() -> compute::Environment {
    compute::Environment {
        sources: vec![],
        assets: vec![],
    }
}
pub fn manifest() -> ProgramManifest {
    environment().manifest().unwrap()
}
pub fn plan() -> compute::Plan {
    compute::Plan {
        calls: vec![compute::Call {
            entry: "answer".into(),
            args: vec![],
            bind: vec![compute::Bind::Name("answer".into())],
        }],
        step: None,
        outputs: vec![compute::Declared {
            slot: "answer".into(),
            kind: compute::OutputKind::Buffer { max_bytes: 4096 },
        }],
    }
}
pub fn invocation_request(nonce: u8) -> InvocationRequest {
    bundle(nonce).request
}
pub fn bundle(nonce: u8) -> PreparedInvocation {
    let input = InvocationInput {
        artifacts: vec![],
        parameters: JsonBytes(plan().canonical_bytes().unwrap()),
    };
    PreparedInvocation::new(
        InvocationRequest {
            execution_environment: manifest().content_id(),
            input: input.content_id().unwrap(),
            runner_public_key: PublicKey::Secp256k1(provider().party_key().to_bytes()),
            nonce: [nonce; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        },
        &manifest(),
        input,
        work_policy().canonical_bytes().unwrap(),
    )
    .unwrap()
}

pub const fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 50,
        terminal: 100,
        payment: 200,
    }
}

pub fn bond_object() -> Edge {
    EdgeBytes {
        value: STAKE,
        reserve: 0,
        maker: provider().party_key(),
        taker: client().party_key(),
        terms: Terms::work_stake_bond(bond_terms()).hash(),
        allowed: WORK_STAKE_CLOSES,
    }
    .build()
}

pub fn payment_object() -> Edge {
    EdgeBytes {
        value: PAYMENT_VALUE,
        reserve: PAYMENT_RESERVE,
        maker: client().party_key(),
        taker: provider().party_key(),
        terms: payment_terms_hash(payment_terms()),
        allowed: WORK_PAYMENT_CLOSES,
    }
    .build()
}

pub fn lease_over(bond: EdgeId, payment: EdgeId) -> LeaseSlots {
    use hellas_kernel::{RegistryChunk, RegistryNamespace, RegistryRecordTag};

    let mut value = vec![FORMAT_VERSION, TAG_BOND_LEASE, 2];
    value.extend_from_slice(&bond.to_bytes());
    value.extend_from_slice(&payment.to_bytes());
    value.extend_from_slice(payment_terms_hash(payment_terms()).as_bytes());
    value.extend_from_slice(&payment_terms().private_policy_commitment);
    value.extend_from_slice(&HORIZON.to_be_bytes());
    let slots = [0, 1].map(|index| {
        RegistryChunk::split(
            RegistryNamespace::BondLease,
            RegistryRecordTag::BondLease,
            &value,
            index,
        )
    });
    let parsed = hellas_kernel::parse_bond_lease(slots, bond);
    assert!(
        matches!(parsed, hellas_kernel::LeaseSlots::Present(_)),
        "the hand-written lease is readable, got {parsed:?}",
    );
    parsed
}

pub fn bundle_bytes(nonce: u8) -> Vec<u8> {
    match bundle(nonce).canonical_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("the fixture bundle encodes: {error}"),
    }
}

/// A fixture client resolves its locally held objects before exercising the
/// provider's upload and reference-only acceptance methods. Requests produced
/// by ClientEndpoint already name a reference; hand-authored fixture requests
/// still carry their local body here, before any provider call.
pub fn fixture_uploads(
    channel: &crate::model::work::PaidChannel,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    Vec<hellas_rpc::pb::work::UploadContentRequest>,
) {
    use crate::model::work::{PaidJobAuthorizationV2, PrivateRecord as _};
    use hellas_rpc::protocol::content_upload::decode_reference;
    let wire = request.clone();
    let Ok(_) = PaidJobAuthorizationV2::decode(&request.authorization) else {
        return (wire, Vec::new());
    };
    let bytes = if let Some(reference) = decode_reference(&request.prepared_input) {
        let Some(bytes) = (0..=u8::MAX).map(bundle_bytes).find(|bytes| {
            ContentId::hash(bytes) == reference.id() && bytes.len() as u64 == reference.bytes()
        }) else {
            return (wire, Vec::new());
        };
        bytes
    } else {
        request.prepared_input.clone()
    };
    input_uploads(channel, &wire, &bytes)
}

pub fn input_uploads(
    channel: &crate::model::work::PaidChannel,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
    bytes: &[u8],
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    Vec<hellas_rpc::pb::work::UploadContentRequest>,
) {
    use crate::model::work::{PaidJobAuthorizationV2, PrivateRecord as _, signing_hash, work_id};
    use hellas_rpc::protocol::content_upload::{
        CONTENT_CHUNK_BYTES, chunk_digest, encode_reference,
    };
    let mut wire = request.clone();
    let Ok(a) = PaidJobAuthorizationV2::decode(&request.authorization) else {
        return (wire, Vec::new());
    };
    let reference = hellas_rpc::ContentRef::new(ContentId::hash(bytes), bytes.len() as u64);
    wire.prepared_input = encode_reference(reference);
    let id = work_id(channel, &a);
    let program_manifest =
        PreparedInvocation::from_canonical_bytes(bytes, crate::content::MAX_CONTENT_BYTES)
            .ok()
            .map(|input| input.manifest().unwrap().canonical_bytes())
            .unwrap_or_default();
    let program_root =
        PreparedInvocation::from_canonical_bytes(bytes, crate::content::MAX_CONTENT_BYTES)
            .ok()
            .map(|input| program_root(&input))
            .unwrap_or_default();
    let uploads = bytes
        .chunks(CONTENT_CHUNK_BYTES)
        .enumerate()
        .map(|(index, bytes)| {
            let offset = (index * CONTENT_CHUNK_BYTES) as u64;
            let sig = client().sign(signing_hash(chunk_digest(
                a.channel_id,
                id,
                reference,
                offset,
                bytes,
                &[7; 32],
            )));
            hellas_rpc::pb::work::UploadContentRequest {
                program_root: program_root.clone(),
                program_manifest: program_manifest.clone(),
                route: wire.route.clone(),
                authorization: wire.authorization.clone(),
                client_signature: wire.client_signature.clone(),
                content_id: reference.id().as_bytes().to_vec(),
                total_bytes: reference.bytes(),
                offset,
                chunk: bytes.to_vec(),
                chunk_signature: sig.as_bytes().to_vec(),
            }
        })
        .collect();
    (wire, uploads)
}
pub async fn accept_uploaded(
    endpoint: &mut crate::work::ProviderEndpoint,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> hellas_rpc::pb::work::AcceptWorkResponse {
    let (wire, uploads) = fixture_uploads(endpoint.state().channel(), request);
    for upload in uploads {
        if let Some(refusal) = super::upload_failure(endpoint.upload_content(
            &upload,
            &hellas_wire::TransportContext {
                open_exporter: Some([7; 32]),
                ..Default::default()
            },
        )) {
            return refusal;
        }
    }
    endpoint.accept(&wire).await
}

pub async fn accept_uploaded_service(
    service: &crate::work::WorkService,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> hellas_rpc::pb::work::AcceptWorkResponse {
    let Ok(channel) = service.with_state(|state| state.channel().clone()).await else {
        return service.accept(request).await;
    };
    let (wire, uploads) = fixture_uploads(&channel, request);
    for upload in uploads {
        if let Some(refusal) = super::upload_failure(
            service
                .upload(
                    &upload,
                    &hellas_wire::TransportContext {
                        open_exporter: Some([7; 32]),
                        ..Default::default()
                    },
                )
                .await,
        ) {
            return refusal;
        }
    }
    service.accept(&wire).await
}

pub async fn commit(store: &mut ChannelStore, record: ChannelRecord) {
    if let ChannelRecord::JobProposed {
        authorization,
        prepared_input,
        ..
    } = &record
        && store.state().role() == Role::Provider
        && let Ok(input) = PreparedInvocation::from_canonical_bytes(
            prepared_input,
            crate::content::MAX_CONTENT_BYTES,
        )
    {
        let root = program_root(&input);
        if !root.is_empty() {
            let policy =
                InvocationPolicy::from_canonical_bytes(input.application_policy.as_bytes())
                    .unwrap();
            let objects = crate::job::content_closure(
                &policy,
                &input.manifest().unwrap(),
                &root,
                authorization.input_content,
            )
            .unwrap();
            let work = work_id(store.state().channel(), authorization);
            store
                .uploads
                .declare_closure(
                    work,
                    &objects,
                    authorization.acceptance_deadline,
                    authorization.retention,
                    policy.limits.max_upload_bytes,
                )
                .unwrap();
            store
                .uploads
                .stage_complete(
                    work,
                    hellas_rpc::ContentRef::for_bytes(&root),
                    authorization.acceptance_deadline,
                    authorization.retention,
                    policy.limits.max_upload_bytes,
                    &root,
                )
                .unwrap();
        }
    }
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()).await {
        panic!("the fixture record commits: {error}");
    }
}

pub fn transcript_for(request: &InvocationRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    transcript_chunks(
        request,
        &[answer],
        &provider_producer(),
        PROMPT_TOKENS,
        Digest::from_bytes([0x77; 32]),
    )
}

pub async fn store_at(
    root: &std::path::Path,
    ready: &ReadyChannel,
    role: Role,
    height: u64,
) -> ChannelStore {
    let mut store = match ChannelStore::open(
        root,
        ready.channel().clone(),
        settlement(),
        role,
        origin(),
        hellas_store::ContentStore::new(),
        &Secp256k1Verifier::new(),
    )
    .await
    {
        Ok(store) => store,
        Err(error) => panic!("the fixture store opens: {error}"),
    };
    advance(&mut store, height).await;
    store
}

pub fn work_policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![Admission::Compute {
            evaluator: compute::EVALUATOR.into(),
        }],
        limits: Limits {
            max_upload_bytes: 1 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 128,
            execution_timeout_ms: 60_000,
        },
    }
}

/// The same scalar as the provider's channel party key.
pub fn provider_producer() -> ProducerSigningKey {
    match ProducerSigningKey::from_secret_bytes([0x22; 32]) {
        Ok(key) => key,
        Err(error) => panic!("a fixed scalar is a producer key: {error}"),
    }
}

/// Construct wire fixtures independently of the production edge encoder.
struct EdgeBytes {
    value: u64,
    reserve: u64,
    maker: Key,
    taker: Key,
    terms: TermsHash,
    allowed: u8,
}

impl EdgeBytes {
    fn build(&self) -> Edge {
        let mut out = vec![FORMAT_VERSION, TAG_EDGE];
        out.extend_from_slice(&self.value.to_be_bytes());
        out.extend_from_slice(&self.reserve.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_FEES]);
        for _ in 0..4 {
            out.extend_from_slice(&0_u64.to_be_bytes());
        }
        out.extend_from_slice(&[FORMAT_VERSION, TAG_BLOCK_HEIGHT]);
        out.extend_from_slice(&HORIZON.to_be_bytes());
        out.extend_from_slice(&[FORMAT_VERSION, TAG_PARTIES]);
        // Each party: owner, signer, and an absent payout delegate.
        for party in [self.maker, self.taker] {
            out.extend_from_slice(&party.to_bytes());
            out.extend_from_slice(&party.to_bytes());
            out.push(0);
        }
        out.extend_from_slice(self.terms.as_bytes());
        out.push(self.allowed);
        match Edge::decode_exact(&out) {
            Ok(edge) => edge,
            Err(error) => panic!("the hand-written edge is canonical: {error:?}"),
        }
    }
}

pub fn descriptor() -> WorkChannelDescriptor {
    descriptor_with(work_policy())
}

pub fn descriptor_with(policy: InvocationPolicy) -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        payment_policy: payment_policy(),
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        invocation_policy: policy,
        expected_payment_values: payment_values(),
    };
    match WorkChannelDescriptor::open(config) {
        Ok(descriptor) => descriptor,
        Err(error) => panic!("the fixture channel opens: {error}"),
    }
}

pub async fn accept_uploaded_client(
    service: &crate::work::WorkService,
    client: &crate::work::ClientEndpoint,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
) -> hellas_rpc::pb::work::AcceptWorkResponse {
    use crate::model::work::{PaidJobAuthorizationV2, PrivateRecord as _, work_id};
    let Ok(a) = PaidJobAuthorizationV2::decode(&request.authorization) else {
        return service.accept(request).await;
    };
    let id = work_id(client.state().channel(), &a);
    let Some(job) = client.state().job_by_id(id) else {
        return service.accept(request).await;
    };
    let (wire, uploads) = input_uploads(client.state().channel(), request, job.prepared_input());
    for upload in uploads {
        if let Some(refusal) = super::upload_failure(
            service
                .upload(
                    &upload,
                    &hellas_wire::TransportContext {
                        open_exporter: Some([7; 32]),
                        ..Default::default()
                    },
                )
                .await,
        ) {
            return refusal;
        }
    }
    service.accept(&wire).await
}

pub const NONCE: u8 = 1;

pub fn ready() -> ReadyChannel {
    ready_of(&descriptor(), CURSOR)
}

// ── The prepared inputs a job executes from ───────────────────────────

pub fn authorization() -> PaidJobAuthorizationV2 {
    match crate::job::propose(
        ready().channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(NONCE),
        u64::from(NONCE),
        deadlines(),
    ) {
        Ok(authorization) => authorization,
        Err(error) => panic!("the fixture authorization builds: {error}"),
    }
}

/// Puts one accepted job on both journals, and returns its `work_id`.
///
/// The acceptance exchange has its own file; these tests are about what
/// happens after both signatures exist.
pub async fn accept(stores: &mut [&mut ChannelStore]) -> Digest {
    let authorization = authorization();
    let ready = ready();
    let id = work_id(ready.channel(), &authorization);
    let Ok(prepared_input) = bundle(NONCE).canonical_bytes() else {
        panic!("the fixture bundle encodes");
    };
    for store in stores {
        commit(
            store,
            ChannelRecord::JobProposed {
                authorization,
                client_signature: client().sign(signing_hash(id)),
                prepared_input: prepared_input.clone(),
            },
        )
        .await;
        commit(
            store,
            ChannelRecord::JobAccepted {
                work_id: id,
                provider_signature: provider().sign(signing_hash(id)),
            },
        )
        .await;
    }
    id
}

// ── Transcripts and the backend that produces them ────────────────────

pub const ANSWER: [u32; 5] = [101, 102, 103, 104, 105];

/// A backend that counts its calls and signs the fixture answer.
pub struct AnsweringBackend {
    pub calls: Arc<AtomicUsize>,
    transcript: fn(&InvocationRequest, &[u32]) -> Vec<OutputEventEnvelope>,
}

impl AnsweringBackend {
    pub fn with_transcript(
        transcript: fn(&InvocationRequest, &[u32]) -> Vec<OutputEventEnvelope>,
    ) -> Self {
        Self {
            transcript,
            ..Self::new()
        }
    }

    pub fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            transcript: transcript_for,
        }
    }
}

impl WorkBackend for AnsweringBackend {
    fn try_admit(
        &self,
        domain: crate::work::admission::CapacityDomain,
    ) -> Result<crate::work::admission::WorkPermit, BackendFault> {
        Err(crate::work::admission::AdmissionError::Unsupported(domain).into())
    }

    async fn execute(
        &self,
        prepared: crate::work::Admitted<PreparedInvocation>,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let produced = (self.transcript)(&prepared.invocation().request, &ANSWER);
        Ok(produced)
    }
}

/// Runs one accepted job to a signed, durable result.
pub async fn run_to_result(service: &WorkService, ready: &ReadyChannel, id: Digest) {
    let backend = AnsweringBackend::new();
    let outcome = run_accepted_work(service, ready, &backend, id).await;
    assert!(
        matches!(outcome, Ok(RunOutcome::Completed { .. })),
        "the fixture job completes: {outcome:?}",
    );
}

// ── Transport plumbing ────────────────────────────────────────────────

/// Stops one serving task and waits for it to be gone.
///
/// Awaited rather than merely cancelled: the task holds a handle to the
/// provider's endpoint, and a test that reopens that journal from its
/// files needs the process to have actually let go of it.
pub async fn stop(serving: tokio::task::JoinHandle<()>) {
    serving.abort();
    let _ = serving.await;
}

pub fn serve_work(transport: MuxTransport, service: WorkService) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = WorkServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

// ── Canonical chain objects, spelled out ──────────────────────────────

// ── The state this phase begins from ──────────────────────────────────

/// One job, accepted, computed, delivered and independently checked.
///
/// Everything before the payment, driven exactly as the earlier phases
/// drive it, because a payment for a job that reached this state any
/// other way would be a payment for something these tests invented.
pub struct Checked {
    pub client_root: tempfile::TempDir,
    pub provider_root: tempfile::TempDir,
    pub ready: ReadyChannel,
    pub service: WorkService,
    pub client: ClientEndpoint,
    pub id: Digest,
}

pub async fn checked_job() -> Checked {
    let client_root = tempfile::tempdir().expect("a temp dir");
    let provider_root = tempfile::tempdir().expect("a temp dir");
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;

    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);
    let Ok(mut client) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    run_to_result(&service, &ready, id).await;

    let (transport, server) = transport_pair();
    let serving = serve_work(server, service.clone());
    let delivered = fetch_result_stream(transport, &mut client, &ready, id, |_| Ok(())).await;
    stop(serving).await;
    if let Err(error) = delivered {
        panic!("the fixture delivery completes: {error}");
    }
    // The client journals authenticated verification before signing payment.
    if let Err(error) = client.verified(id).await {
        panic!("the fixture verification records: {error}");
    }
    Checked {
        client_root,
        provider_root,
        ready,
        service,
        client,
        id,
    }
}

pub const fn credit_policy(compute: u64, delivery: u64) -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: compute,
        delivery_credit_limit: delivery,
    }
}

pub fn bond_terms_for(
    parties: Parties,
    timeout: BlockHeight,
    payout: Payout,
    max_job_price: u64,
) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties,
        timeout,
        timeout_outputs: List::take([payout; MAX_EDGE_OUTPUTS], 1),
        max_job_price,
    }
}

pub fn payment_terms_for(
    bond_edge: EdgeId,
    bond_terms: WorkStakeBondTerms,
    private_policy_commitment: [u8; 32],
    omit_response_blocks: u64,
    start_validity_blocks: u64,
    omission_bond: u64,
) -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge,
        bond_terms,
        private_policy_commitment,
        omit_response_blocks,
        start_validity_blocks,
        omission_bond,
    }
}

impl Default for AnsweringBackend {
    fn default() -> Self {
        Self::new()
    }
}

pub fn serve_setup(
    transport: MuxTransport,
    service: crate::work_handshake::SetupService,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let server = hellas_rpc::services::work_setup::WorkSetupServer(service);
        while let Ok(Some(inbound)) = transport.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&server, inbound).await;
        }
    })
}

pub async fn exchange_setup(
    service: &crate::work_handshake::SetupService,
    bond: EdgeId,
    bundle: Vec<u8>,
) -> Vec<u8> {
    use hellas_rpc::pb::work::{ExchangeSetupRequest, exchange_setup_response::Outcome};
    use hellas_rpc::services::work_setup::WorkSetupHandler;
    let answered = WorkSetupHandler::exchange_setup(
        service,
        ExchangeSetupRequest {
            bond_edge: bond.as_bytes().to_vec(),
            bundle,
        },
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

pub fn transcript_chunks(
    request: &InvocationRequest,
    chunks: &[&[u32]],
    key: &ProducerSigningKey,
    input_units: u64,
    text_artifact: Digest,
) -> Vec<OutputEventEnvelope> {
    let _ = (input_units, text_artifact);
    let answer: Vec<u8> = chunks
        .iter()
        .flat_map(|chunk| chunk.iter().flat_map(|v| v.to_le_bytes()))
        .collect();
    output::InvocationOutput {
        outcome: output::Outcome::Succeeded,
        artifacts: vec![Artifact::new("answer", "catena.bytes.v1", answer)],
        metadata: JsonBytes(
            hellas_rpc::protocol::value::canonical_dag_cbor(&compute::RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    }
    .sign(request, key, 1024)
    .unwrap()
}

pub fn ready_of(descriptor: &WorkChannelDescriptor, height: u64) -> ReadyChannel {
    let bond = bond_object();
    let payment = payment_object();
    let observed = ObservedChannel {
        height,
        bond: Some(&bond),
        payment: Some(&payment),
        lease: lease_over(bond_edge(), payment_edge()),
        pending: PendingSlot::Absent,
    };
    match descriptor.check_ready(&observed) {
        Ok(ready) => ready,
        Err(error) => panic!("the fixture channel is ready: {error}"),
    }
}

pub async fn open_setup_store(
    root: &std::path::Path,
    network: NetworkId,
    bond: EdgeId,
    role: Role,
) -> crate::work_store::SetupStore {
    crate::work_store::SetupStore::open(root, network, bond, role, &Secp256k1Verifier::new())
        .await
        .expect("the setup journal opens")
}

/// Drive the same three signed revisions while each caller keeps its own terms and scan.
pub async fn finish_setup(
    service: &crate::work_handshake::SetupService,
    caller: &mut crate::work_handshake::SetupEndpoint,
    bond: EdgeId,
    scan: crate::work_store::SetupScan,
    funding: hellas_kernel::Funding,
    terms: WorkPaymentTerms,
) {
    let proposal = exchange_setup(service, bond, Vec::new()).await;
    caller
        .import(&proposal)
        .await
        .expect("the client imports the bond proposal");
    caller
        .arm_scan(scan)
        .await
        .expect("the client arms its scan");
    caller
        .propose_payment(funding, terms)
        .await
        .expect("the client proposes its payment");
    let offered = caller
        .state()
        .bundle_bytes()
        .map(<[u8]>::to_vec)
        .expect("the client holds revision 2");
    let countersigned = exchange_setup(service, bond, offered).await;
    caller
        .import(&countersigned)
        .await
        .expect("the client imports the countersigned payment");
}

/// A Fetch invocation on the same financial channel, with ephemeral content.
pub fn fetch_policy() -> InvocationPolicy {
    use invocation::fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy};
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: hellas_rpc::FetchContract::http().unwrap(),
                route: FetchRoutePolicy::open_fetch(false, vec!["example.com".into()]),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 1 << 20,
                    max_encoded_result_frame: 262144,
                    max_encoded_prepared_input: 1 << 20,
                },
            },
        }],
        limits: work_policy().limits,
    }
}
pub fn fetch_bundle(nonce: u8) -> PreparedInvocation {
    let contract = hellas_rpc::FetchContract::http().unwrap();
    let body = serde_json::to_vec(&hellas_rpc::http_fetch::HttpFetchRequest {
        url: "https://example.com/private-input".into(),
        method: "GET".into(),
        headers: vec![],
        body_base64: String::new(),
        tls: hellas_rpc::http_fetch::HttpTls {
            roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
            spki_sha256: vec![],
        },
        credential: None,
        max_response_bytes: 128,
    })
    .unwrap();
    let caller = ProducerSigningKey::from_secret_bytes([0x21; 32]).unwrap();
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        "http",
        "fetch",
        &body,
        contract.manifest_id(),
        Assurance::ProducerSigned,
        &caller,
        hellas_rpc::Retention::Ephemeral,
    )
    .unwrap();
    invocation::fetch::prepare(
        &events,
        &contract,
        provider_producer().public_key(),
        fetch_policy().canonical_bytes().unwrap(),
        [nonce; 32],
    )
    .unwrap()
}
pub fn fetch_transcript(input: &PreparedInvocation) -> Vec<OutputEventEnvelope> {
    use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, StopReason};
    let events = [
        OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
            status: 200,
            headers: vec![],
        })),
        OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body {
            base64: "cHJpdmF0ZS1yZXN1bHQ=".into(),
        })),
    ]
    .iter()
    .map(|e| hellas_rpc::fetch::encode_fetch_event_payload(e).unwrap())
    .collect::<Vec<_>>();
    let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
        stop_reason: StopReason::EndOfText,
        usage: None,
    })
    .unwrap();
    invocation::fetch::output(&events, &terminal)
        .unwrap()
        .sign(&input.request, &provider_producer(), 1024)
        .unwrap()
}

pub fn program_root(input: &PreparedInvocation) -> Vec<u8> {
    if input.request.execution_environment == manifest().content_id() {
        environment().canonical_bytes().unwrap()
    } else {
        Vec::new()
    }
}
pub fn program_content() -> crate::content::InvocationContent {
    let mut content = crate::content::EphemeralContent::default();
    content.insert(environment().canonical_bytes().unwrap());
    crate::content::InvocationContent::Ephemeral(content)
}
