//! Shared funded-channel and signed Evaluate fixtures for paid-work tests.

use crate::model::prepared_input::PreparedPaidInputV1;
use crate::model::setup::{
    ReadyChannel, WorkChannelConfig, WorkChannelDescriptor, payment_terms_hash,
};
use crate::model::work::{
    EvaluatePolicyV2, JobDeadlines, PaidChannelPolicyV1, generation_policy_digest,
    identity_source_digest, private_policy_commitment,
};
use crate::work_store::{ChannelRecord, ChannelStore, Role, SetupOrigin};
use hellas_auth::{Digest, ProducerSigningKey, PublicKey};
use hellas_kernel::{
    BlockHeight, Decode as _, Edge, EdgeId, EdgeValues, Fees, Key, LeaseSlots, List,
    MAX_EDGE_OUTPUTS, NetworkId, Parties, PartyKeys, Payout, Secp256k1Signer, Secp256k1Verifier,
    Terms, TermsHash, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::evaluate::{
    EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
    input_commitment,
};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical as _, InputAddressed as _, OutputAddressed as _, SourceRef,
    TextArtifact, TextExecution, TextPolicy, TokenIds,
};
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, EvaluateRequest,
    OutputEventEnvelope, ProgramManifest,
};

pub const HORIZON: u64 = 500;
pub const PRICE: u64 = 10;
const CREDIT_LIMIT: u64 = 40;

/// One over half the funding, so the bond exceeds the capacity it
/// leaves behind at zero fees.
pub const OMISSION_BOND: u64 = 601;
pub const PAYMENT_VALUE: u64 = 1_000;
pub const PAYMENT_RESERVE: u64 = 200;
const STAKE: u64 = 64;
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
    PaidChannelPolicyV1 {
        compute_credit_limit: CREDIT_LIMIT,
        delivery_credit_limit: CREDIT_LIMIT,
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
            [Payout::new(provider().party_key(), STAKE); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price: 40,
    }
}

pub fn payment_terms() -> WorkPaymentTerms {
    WorkPaymentTerms {
        bond_edge: bond_edge(),
        bond_terms: bond_terms(),
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        start_validity_blocks: 8,
        omission_bond: OMISSION_BOND,
    }
}

fn payment_values() -> EdgeValues {
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

pub fn manifest() -> ProgramManifest {
    ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR).unwrap(),
        ContentId::from_bytes([0x16; 32]),
    )
}

pub fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
}

pub fn text_policy() -> TextPolicy {
    TextPolicy::from_u32_stop_tokens(64, [2, 1])
}

pub fn identity_artifact() -> TextArtifact {
    TextArtifact::identity(BoundTermId::from_digest(manifest().content_id().digest()))
}

pub fn text_execution() -> TextExecution {
    TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    )
}

pub fn evaluate_request(nonce: u8) -> EvaluateRequest {
    EvaluateRequest {
        text_execution: text_execution().input_id().digest(),
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [nonce; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

pub fn bundle(nonce: u8) -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(nonce),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
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
    match bundle(nonce).encode() {
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
    if let Err(error) = store.commit(record, &Secp256k1Verifier::new()).await {
        panic!("the fixture record commits: {error}");
    }
}

pub fn transcript_for(request: &EvaluateRequest, answer: &[u32]) -> Vec<OutputEventEnvelope> {
    let key = provider_producer();
    let mut builder =
        EvaluateOutputTranscriptBuilder::new(input_commitment(request), request.assurance, &key);
    if let Err(error) = builder.push_token_delta(answer.to_vec()) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: PROMPT_TOKENS,
        output_units: answer.len() as u64,
    };
    let billable_units = match usage.billable_units() {
        Ok(units) => units,
        Err(error) => panic!("the fixture usage sums: {error}"),
    };
    match builder.finish(EvaluateTerminal {
        final_position: answer.len() as u64,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
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

pub fn work_policy() -> EvaluatePolicyV2 {
    EvaluatePolicyV2 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: match generation_policy_digest(&text_policy().canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture policy hashes: {error}"),
        },
        identity_source_digest: match identity_source_digest(&identity_artifact().canonical_bytes())
        {
            Ok(digest) => digest,
            Err(error) => panic!("the fixture identity hashes: {error}"),
        },
        max_prompt_tokens: 512,
        max_new_tokens: 128,
        max_stop_token_ids: 4,
        max_spool_bytes: 1_048_576,
        max_encoded_result_frame: WIDE_FRAME,
        max_encoded_prepared_input: 1_048_576,
        max_upload_bytes: 1_048_576,
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

pub fn descriptor_with(
    policy: impl Into<crate::model::profile::WorkPolicy>,
) -> WorkChannelDescriptor {
    let config = WorkChannelConfig {
        payment_policy: payment_policy(),
        network: network(),
        payment_edge: payment_edge(),
        payment_terms: payment_terms(),
        policy_salt: SALT,
        channel_policy: channel_policy(),
        work_policy: policy.into(),
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
