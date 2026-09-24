//! Independent vectors and mutation proofs for the paid-work records.
//!
//! Authored outside the implementation module on purpose. Every
//! canonical encoding here is pinned as a hex string decoded field by
//! field, because a round-trip test cannot see a field order that moved
//! in the encoder and the decoder together, and every digest is pinned
//! as a hex string, because a digest recomputed by the same code it is
//! being compared against is not a vector.
//!
//! Each mutation test states what it breaks. A rule with no test that
//! fails when the rule is deleted is not a rule.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, EarnedCertificate, EdgeId, EdgeValues, Fees, List, NetworkId, Parties, Payout,
    Secp256k1Signer, Secp256k1Verifier, SigVerifier, TermsHash, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::evaluate::{EvaluateStopReason, EvaluateTerminal, EvaluateUsage};
use hellas_rpc::protocol::artifacts::{
    BoundTermId, Canonical, InputAddressed, OutputAddressed, PreparedPaidInputV1, SourceRef,
    TextArtifact, TextExecution, TextExecutionId, TextPolicy, TextState, TokenIds, completed_text,
};
use hellas_rpc::protocol::work::{
    CreditLedger, PaidChannel, PaidChannelPolicyV1, PaidExecutionPolicyV1, PaidJobAuthorizationV1,
    PaidJobResultV1, PaidWorkError, PaymentBindingV1, PrivateRecord, canonical_output_digest,
    check_authorization, check_execution_policy, check_prepared_input, check_result,
    decode_transcript, encode_transcript, execution_policy_digest, generation_policy_digest,
    identity_source_digest, next_payment, payment_binding_digest, prepared_input_digest,
    private_policy_commitment, result_digest, work_id,
};
use hellas_rpc::{
    Application, Assurance, CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR, ContentId, Digest, Evaluate,
    EvaluateRequest, EventCommitment, ProgramManifest, PublicKey, RequestCommitment,
};

// ── Fixtures ──────────────────────────────────────────────────────────

const NETWORK: &str = "hellas-devnet-1";
const OTHER_NETWORK: &str = "hellas-devnet-22";
/// The channel's certificate capacity, from the kernel's own settlement
/// arithmetic over an edge that locks a million and reserves nothing.
fn capacity() -> WorkPaymentSettlement {
    let Some(settlement) = work_payment_settlement(
        EdgeValues::new(1_000_000 + payment_terms().omission_bond, 0, Fees::ZERO),
        payment_terms().omission_bond,
    ) else {
        panic!("a funded edge prices both exits");
    };
    assert_eq!(settlement.capacity(), 1_000_000);
    settlement
}
const SALT: [u8; 32] = [0x5a; 32];

fn evaluate_request_bytes_of() -> Vec<u8> {
    hellas_rpc::protocol::schemes::evaluate::evaluate_request_bytes(&evaluate_request())
}

/// Assembles bundle bytes from six arbitrary bodies, so a test can build
/// a spelling the constructor would never produce.
fn assemble(bodies: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for body in bodies {
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
    }
    bytes
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The three fallible digests over variable-length bodies, unwrapped.
///
/// Every fixture body here is a few hundred bytes, so the only error
/// these can return — a body too long for its `u32` length prefix — is
/// noise at each of their sixteen call sites.
fn input_digest(channel: &PaidChannel, bundle: &PreparedPaidInputV1) -> Digest {
    prepared_input_digest(channel, bundle).expect("a representable bundle")
}

fn policy_digest_of(policy: &TextPolicy) -> Digest {
    generation_policy_digest(&policy.canonical_bytes()).expect("a representable policy body")
}

fn identity_digest_of(artifact: &TextArtifact) -> Digest {
    identity_source_digest(&artifact.canonical_bytes()).expect("a representable artifact body")
}

fn network() -> NetworkId {
    NetworkId::new(NETWORK).expect("legal network id")
}

fn client() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([3; 32]).expect("legal scalar")
}

fn provider() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([4; 32]).expect("legal scalar")
}

fn payment_terms() -> WorkPaymentTerms {
    let bond = WorkStakeBondTerms {
        // Bond maker is the provider, taker is the client; the payment
        // edge mirrors that, which is where `PaidChannel` reads its keys.
        parties: Parties::new(provider().party_key(), client().party_key()),
        timeout: BlockHeight::new(5_000),
        timeout_outputs: List::take(
            [
                Payout::new(provider().party_key(), 900),
                Payout::default(),
                Payout::default(),
                Payout::default(),
            ],
            1,
        ),
        max_job_price: 500,
    };
    WorkPaymentTerms {
        bond_edge: EdgeId::from_bytes([0xb0; 32]),
        bond_terms: bond,
        private_policy_commitment: private_policy_commitment(network(), &SALT, &channel_policy()),
        omit_response_blocks: 32,
        start_validity_blocks: 16,
        omission_bond: 100,
    }
}

fn channel() -> PaidChannel {
    PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        payment_terms(),
        &SALT,
        channel_policy(),
    )
    .expect("terms that commit to this credit policy")
}

/// A channel on another network, or another payment edge.
///
/// The credit commitment binds the network, so terms minted for one
/// network do not open on another: a foreign channel is built from
/// foreign terms, which is what a foreign channel is.
fn channel_on(network: NetworkId, payment_edge: EdgeId) -> PaidChannel {
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network, &SALT, &channel_policy()),
        ..payment_terms()
    };
    PaidChannel::new(network, payment_edge, terms, &SALT, channel_policy())
        .expect("terms that commit to this credit policy")
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 700,
        delivery_credit_limit: 800,
    }
}

fn manifest() -> ProgramManifest {
    ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR).unwrap(),
        ContentId::from_bytes([0x16; 32]),
    )
}

fn prompt_tokens() -> TokenIds {
    TokenIds::from([9, 8, 7, 6])
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
        runner_public_key: PublicKey::Secp256k1(client().party_key().to_bytes()),
        execution_environment: manifest().content_id(),
        nonce: [0x77; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    }
}

fn bundle() -> PreparedPaidInputV1 {
    PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    )
}

fn execution_policy() -> PaidExecutionPolicyV1 {
    PaidExecutionPolicyV1 {
        allowed_environment: manifest().content_id(),
        generation_policy_digest: policy_digest_of(&text_policy()),
        identity_source_digest: identity_digest_of(&identity_artifact()),
        max_prompt_tokens: 8,
        max_new_tokens: 64,
        max_stop_token_ids: 4,
        max_spool_bytes: 65_536,
        max_encoded_result_frame: 262_144,
        max_encoded_quote_response: 1_048_576,
        dispatch_margin_blocks: 20,
        delivery_margin_blocks: 10,
        oracle_grace_blocks: 30,
        fixed_price: 250,
    }
}

fn authorization() -> PaidJobAuthorizationV1 {
    let channel = channel();
    let terms = payment_terms();
    PaidJobAuthorizationV1 {
        channel_id: channel.id(),
        bond_edge: terms.bond_edge,
        bond_terms_hash: terms.bond_terms_hash(),
        payment_edge: channel.payment_edge(),
        payment_terms_hash: channel.payment_terms_hash(),
        execution_policy_digest: execution_policy_digest(&channel, &execution_policy()),
        prepared_input_digest: input_digest(&channel, &bundle()),
        proposal_nonce: 0x0102_0304_0506_0708,
        acceptance_deadline: 1_000,
        request_commitment: Evaluate::commit_request(&evaluate_request()),
        environment_commitment: manifest().content_id(),
        price: 250,
        terminal_deadline: 1_050,
        payment_deadline: 1_100,
    }
}

fn job_result(work_id: Digest) -> PaidJobResultV1 {
    PaidJobResultV1 {
        work_id,
        terminal_transcript_commitment: EventCommitment::from_digest(Digest::from_bytes(
            [0x31; 32],
        )),
        canonical_output_digest: Digest::from_bytes([0x32; 32]),
    }
}

// ── Golden encodings ──────────────────────────────────────────────────

/// Every fixed body's exact bytes, decoded field by field.
///
/// The sizes are the second assertion: the plan fixes them, and a body
/// that silently grew a field would still round-trip.
#[test]
fn golden_record_encodings_are_pinned() {
    assert_eq!(PaidChannelPolicyV1::BODY_SIZE, 16);
    assert_eq!(PaidChannelPolicyV1::ENCODED_SIZE, 18);
    assert_eq!(PaidExecutionPolicyV1::BODY_SIZE, 154);
    assert_eq!(PaidExecutionPolicyV1::ENCODED_SIZE, 156);
    assert_eq!(PaidJobAuthorizationV1::BODY_SIZE, 328);
    assert_eq!(PaidJobAuthorizationV1::ENCODED_SIZE, 330);
    assert_eq!(PaidJobResultV1::BODY_SIZE, 96);
    assert_eq!(PaidJobResultV1::ENCODED_SIZE, 98);
    assert_eq!(PaymentBindingV1::BODY_SIZE, 96);
    assert_eq!(PaymentBindingV1::ENCODED_SIZE, 98);

    assert_eq!(
        hex(&channel_policy().encode()),
        concat!(
            "01",
            "00",               // format version 1, tag 0 = PAID_CHANNEL_POLICY
            "00000000000002bc", // compute_credit_limit = 700
            "0000000000000320", // delivery_credit_limit = 800
        )
    );

    assert_eq!(
        hex(&job_result(Digest::from_bytes([0x30; 32])).encode()),
        concat!(
            "01",
            "03", // format version 1, tag 3 = PAID_JOB_RESULT
            "3030303030303030303030303030303030303030303030303030303030303030", // work_id
            "3131313131313131313131313131313131313131313131313131313131313131", // transcript
            "3232323232323232323232323232323232323232323232323232323232323232", // output digest
        )
    );

    // The one new canonical encoding in this profile, hand-decoded. Its
    // three fields are all 32 bytes, so a round trip agrees with any
    // permutation of them and only these bytes do not: `a1` is the job,
    // `a2` the result, `d0` the certificate, in that order.
    let binding = PaymentBindingV1 {
        work_id: Digest::from_bytes([0xa1; 32]),
        result_digest: Digest::from_bytes([0xa2; 32]),
        certificate_digest: hellas_kernel::PayloadHash::from_bytes([0xd0; 32]),
    };
    assert_eq!(
        hex(&binding.encode()),
        concat!(
            "01",
            "04", // format version 1, tag 4 = PAYMENT_BINDING
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", // work_id
            "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2", // result_digest
            "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", // certificate
        )
    );
    assert_eq!(PaymentBindingV1::decode(&binding.encode()), Ok(binding));

    let policy = PaidExecutionPolicyV1 {
        allowed_environment: ContentId::from_bytes([0x40; 32]),
        generation_policy_digest: Digest::from_bytes([0x41; 32]),
        identity_source_digest: Digest::from_bytes([0x42; 32]),
        max_prompt_tokens: 1,
        max_new_tokens: 2,
        max_stop_token_ids: 3,
        max_spool_bytes: 5,
        max_encoded_result_frame: 6,
        max_encoded_quote_response: 7,
        dispatch_margin_blocks: 8,
        delivery_margin_blocks: 9,
        oracle_grace_blocks: 10,
        fixed_price: 11,
    };
    assert_eq!(
        hex(&policy.encode()),
        concat!(
            "01",
            "01", // format version 1, tag 1 = PAID_EXECUTION_POLICY
            "4040404040404040404040404040404040404040404040404040404040404040", // environment
            "4141414141414141414141414141414141414141414141414141414141414141", // generation
            "4242424242424242424242424242424242424242424242424242424242424242", // identity
            "00000001", // max_prompt_tokens
            "00000002", // max_new_tokens
            "0003", // max_stop_token_ids
            "0000000000000005", // max_spool_bytes
            "00000006", // max_encoded_result_frame
            "00000007", // max_encoded_quote_response
            "0000000000000008", // dispatch_margin_blocks
            "0000000000000009", // delivery_margin_blocks
            "000000000000000a", // oracle_grace_blocks
            "000000000000000b", // fixed_price
        )
    );

    let authorization = PaidJobAuthorizationV1 {
        channel_id: Digest::from_bytes([0x50; 32]),
        bond_edge: EdgeId::from_bytes([0x51; 32]),
        bond_terms_hash: TermsHash::from_bytes([0x52; 32]),
        payment_edge: EdgeId::from_bytes([0x53; 32]),
        payment_terms_hash: TermsHash::from_bytes([0x54; 32]),
        execution_policy_digest: Digest::from_bytes([0x55; 32]),
        prepared_input_digest: Digest::from_bytes([0x56; 32]),
        proposal_nonce: 1,
        acceptance_deadline: 2,
        request_commitment: RequestCommitment::from_digest(Digest::from_bytes([0x57; 32])),
        environment_commitment: ContentId::from_bytes([0x58; 32]),
        price: 3,
        terminal_deadline: 4,
        payment_deadline: 5,
    };
    assert_eq!(
        hex(&authorization.encode()),
        concat!(
            "01",
            "02", // format version 1, tag 2 = PAID_JOB_AUTHORIZATION
            "5050505050505050505050505050505050505050505050505050505050505050", // channel_id
            "5151515151515151515151515151515151515151515151515151515151515151", // bond_edge
            "5252525252525252525252525252525252525252525252525252525252525252", // bond_terms
            "5353535353535353535353535353535353535353535353535353535353535353", // payment_edge
            "5454545454545454545454545454545454545454545454545454545454545454", // payment_terms
            "5555555555555555555555555555555555555555555555555555555555555555", // policy digest
            "5656565656565656565656565656565656565656565656565656565656565656", // prepared input
            "0000000000000001", // proposal_nonce
            "0000000000000002", // acceptance_deadline
            "5757575757575757575757575757575757575757575757575757575757575757", // request
            "5858585858585858585858585858585858585858585858585858585858585858", // environment
            "0000000000000003", // price
            "0000000000000004", // terminal_deadline
            "0000000000000005", // payment_deadline
        )
    );
}

/// Maximum-value bodies still encode to their fixed width.
#[test]
fn maximum_value_bodies_stay_fixed_width() {
    let mut authorization = authorization();
    authorization.proposal_nonce = u64::MAX;
    authorization.acceptance_deadline = u64::MAX;
    authorization.price = u64::MAX;
    authorization.terminal_deadline = u64::MAX;
    authorization.payment_deadline = u64::MAX;
    let bytes = authorization.encode();
    assert_eq!(bytes.len(), PaidJobAuthorizationV1::ENCODED_SIZE);
    assert_eq!(PaidJobAuthorizationV1::decode(&bytes), Ok(authorization));
    // The five `u64`s, all `ff`, at the offsets the layout puts them.
    assert_eq!(hex(&bytes[226..242]), "ffffffffffffffffffffffffffffffff");
    assert_eq!(
        hex(&bytes[306..330]),
        "ffffffffffffffffffffffffffffffffffffffffffffffff"
    );
}

/// Wrong tag, wrong version, truncation, and a trailing byte all reject.
#[test]
fn envelope_and_length_mutations_reject() {
    let bytes = job_result(Digest::from_bytes([0x30; 32])).encode();
    assert!(PaidJobResultV1::decode(&bytes).is_ok());

    // MUTATION: a result body presented under the binding tag.
    let mut wrong_tag = bytes.clone();
    wrong_tag[1] = 4;
    assert_eq!(
        PaidJobResultV1::decode(&wrong_tag),
        Err(PaidWorkError::WrongRecordTag {
            expected: 3,
            actual: 4
        })
    );

    // MUTATION: a tag this record does not own (5 is the fetch profile's
    // policy tag).
    let mut unknown_tag = bytes.clone();
    unknown_tag[1] = 5;
    assert_eq!(
        PaidJobResultV1::decode(&unknown_tag),
        Err(PaidWorkError::WrongRecordTag {
            expected: 3,
            actual: 5
        })
    );

    // MUTATION: a future format version.
    let mut wrong_version = bytes.clone();
    wrong_version[0] = 2;
    assert_eq!(
        PaidJobResultV1::decode(&wrong_version),
        Err(PaidWorkError::UnknownFormatVersion { actual: 2 })
    );

    // MUTATION: one byte short.
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        PaidJobResultV1::decode(truncated),
        Err(PaidWorkError::RecordLength {
            expected: 98,
            actual: 97
        })
    );

    // MUTATION: one byte long.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PaidJobResultV1::decode(&trailing),
        Err(PaidWorkError::RecordLength {
            expected: 98,
            actual: 99
        })
    );
}

/// A paid-work body must not decode as another paid-work record.
///
/// Two rules do this between them, and which one fires depends on the
/// pair. Four of the five records have lengths no other record shares,
/// so a body offered as one of those never reaches the tag rule: the
/// length refuses it first, whether or not the tag byte was changed with
/// it. The fifth pair — a result and a payment binding, both three
/// digests — is the same width, and there the envelope tag is the whole
/// of what separates them.
///
/// Which means a result body whose tag byte is *rewritten* does decode
/// as a binding, and that is asserted below rather than glossed. What
/// stops it mattering is not the codec: the two are signed by different
/// parties under different domains, and the ledger checks every field of
/// a binding against the job it is offered for. A relabelled result
/// carries a transcript commitment where a result digest belongs, which
/// is not the digest of anything.
#[test]
fn a_body_cannot_be_reinterpreted_under_another_record() {
    let sizes = [
        ("channel policy", PaidChannelPolicyV1::ENCODED_SIZE),
        ("execution policy", PaidExecutionPolicyV1::ENCODED_SIZE),
        ("authorization", PaidJobAuthorizationV1::ENCODED_SIZE),
        ("result", PaidJobResultV1::ENCODED_SIZE),
        ("payment binding", PaymentBindingV1::ENCODED_SIZE),
    ];
    let collisions: Vec<(&str, &str)> = sizes
        .iter()
        .enumerate()
        .flat_map(|(index, (name, size))| {
            sizes
                .iter()
                .skip(index + 1)
                .filter(move |(_, other)| other == size)
                .map(move |(other, _)| (*name, *other))
        })
        .collect();
    assert_eq!(
        collisions,
        vec![("result", "payment binding")],
        "the set of same-width pairs is exactly the one the tag rule covers",
    );

    // The pair the length cannot separate: relabelled, and refused by
    // the tag it now carries.
    let result = job_result(Digest::from_bytes([0x30; 32])).encode();
    let mut relabelled = result.clone();
    relabelled[1] = 4;
    assert!(PaymentBindingV1::decode(&relabelled).is_ok());
    assert_eq!(
        PaymentBindingV1::decode(&result),
        Err(PaidWorkError::WrongRecordTag {
            expected: 4,
            actual: 3
        })
    );

    let policy = execution_policy().encode();
    assert_eq!(
        PaidJobAuthorizationV1::decode(&policy),
        Err(PaidWorkError::RecordLength {
            expected: 330,
            actual: 156
        })
    );

    // The tag relabelled too, which changes nothing: the length is read
    // before the envelope is.
    let mut disguised = policy.clone();
    disguised[1] = 2;
    assert_eq!(
        PaidJobAuthorizationV1::decode(&disguised),
        Err(PaidWorkError::RecordLength {
            expected: 330,
            actual: 156
        })
    );
}

// ── Golden digests ────────────────────────────────────────────────────

/// Pinned digests over two legal network ids of different lengths.
///
/// The encoded network carries a one-byte length prefix, so a raw or
/// padded spelling of the same id is a different preimage. Both vectors
/// are pinned; if the prefix were dropped, both would move.
#[test]
fn golden_digests_bind_the_encoded_network() {
    let channel = channel();
    assert_eq!(
        hex(channel.id().as_bytes()),
        "3fb8c6063009d6fa39e41884fcbc325ce0886f34e5ca0ff9f7893fcb9f29cb66"
    );
    assert_eq!(
        hex(&work_id(&channel, &authorization()).into_bytes()),
        "7ebf09a0d7c77b8747d53b56cbd981b7cad754ec3c4a913f16cfe8f6545c0ee4"
    );

    let other = channel_on(
        NetworkId::new(OTHER_NETWORK).expect("legal network id"),
        EdgeId::from_bytes([0xe1; 32]),
    );
    assert_ne!(channel.id(), other.id());
    // Rebuilt by hand rather than by the module that is being pinned:
    // the domain, the one-byte length prefix, and the four commitments,
    // hashed through the crate's other entry point.
    let mut preimage = b"hellas.work.channel.v2".to_vec();
    preimage.push(OTHER_NETWORK.len() as u8);
    preimage.extend_from_slice(OTHER_NETWORK.as_bytes());
    preimage.extend_from_slice(other.payment_edge().as_bytes());
    preimage.extend_from_slice(other.payment_terms_hash().as_bytes());
    preimage.extend_from_slice(other.payment_terms().bond_edge.as_bytes());
    preimage.extend_from_slice(other.payment_terms().bond_terms_hash().as_bytes());
    assert_eq!(Digest::hash(&preimage), other.id());
    assert_eq!(
        hex(other.id().as_bytes()),
        "2242df9d621b8156cec0a1903919d46739dd79665df31e04e5bb5499174e5191"
    );
}

/// The same body in another channel is another digest, and every check
/// that names the channel refuses it.
#[test]
fn records_do_not_cross_channels() {
    let here = channel();
    let sibling = channel_on(network(), EdgeId::from_bytes([0xe2; 32]));
    let elsewhere = channel_on(
        NetworkId::new(OTHER_NETWORK).expect("legal network id"),
        here.payment_edge(),
    );
    let authorization = authorization();
    let result = job_result(work_id(&here, &authorization));
    let (_, binding) =
        next_payment(&here, &authorization, &result, 0, capacity()).expect("a legal payment");

    assert_ne!(here.id(), sibling.id());
    for (label, other) in [("sibling", &sibling), ("elsewhere", &elsewhere)] {
        assert_ne!(
            work_id(&here, &authorization),
            work_id(other, &authorization),
            "{label} shares this channel's work_id"
        );
        assert_ne!(
            result_digest(&here, &result),
            result_digest(other, &result),
            "{label} shares this channel's result digest"
        );
        assert_ne!(
            payment_binding_digest(&here, &binding),
            payment_binding_digest(other, &binding),
            "{label} shares this channel's payment binding digest"
        );
        assert_ne!(
            execution_policy_digest(&here, &execution_policy()),
            execution_policy_digest(other, &execution_policy()),
            "{label} shares this channel's policy digest"
        );
        assert_ne!(
            input_digest(&here, &bundle()),
            input_digest(other, &bundle()),
            "{label} shares this channel's prepared input digest"
        );
        // MUTATION: replay this channel's authorization on another one.
        assert_eq!(
            check_authorization(other, &authorization, &execution_policy(), 900),
            Err(PaidWorkError::Mismatch {
                field: "channel_id"
            }),
            "{label} accepted a foreign authorization"
        );
    }
}

// ── Prepared input bundle ─────────────────────────────────────────────

/// The bundle encodes as six big-endian lengths and six bodies, and its
/// digest is reproducible from the same six component bodies with no
/// cache in the process.
#[test]
fn prepared_input_is_reproducible_from_its_components() {
    let bundle = bundle();
    let encoded = bundle.encode().expect("a representable bundle");

    let expected = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &prompt_tokens().canonical_bytes(),
        &text_policy().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    assert_eq!(encoded, expected);

    let decoded = PreparedPaidInputV1::decode(&encoded, 1_048_576).expect("legal bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(
        decoded
            .parts()
            .expect("the canonical bodies parse")
            .manifest
            .canonical_bytes(),
        manifest().canonical_bytes(),
    );
    assert_eq!(
        input_digest(&channel(), &decoded),
        input_digest(&channel(), &bundle)
    );
}

/// Reordering, relabelling, or padding the bundle rejects rather than
/// producing a second acceptable spelling of the same job.
#[test]
fn prepared_input_mutations_reject() {
    let encoded = bundle().encode().expect("a representable bundle");
    let budget = 1_048_576;
    assert!(PreparedPaidInputV1::decode(&encoded, budget).is_ok());

    // MUTATION: swap the prompt-token and policy segments. They decode
    // as each other's schema, so the bundle has no second spelling.
    let swapped = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &text_policy().canonical_bytes(),
        &prompt_tokens().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    assert_ne!(swapped, encoded);
    let err = PreparedPaidInputV1::decode(&swapped, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("swapped components must not parse");
    assert!(
        err.to_string().contains("expected array length 2, got 3"),
        "{err}"
    );

    // MUTATION: the first declared length one byte short. Every later
    // segment then starts one byte early, so the next length is read out
    // of a body and refused before anything is allocated for it.
    let mut short_length = encoded.clone();
    let first_len = u32::from_be_bytes([
        short_length[0],
        short_length[1],
        short_length[2],
        short_length[3],
    ]);
    short_length[..4].copy_from_slice(&(first_len - 1).to_be_bytes());
    let err = PreparedPaidInputV1::decode(&short_length, budget)
        .expect_err("a shortened length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: the last declared length one byte short, which leaves a
    // well-formed prefix and one byte over.
    let mut short_last = encoded.clone();
    let last_prefix = encoded.len() - identity_artifact().canonical_bytes().len() - 4;
    let last_len = u32::from_be_bytes([
        short_last[last_prefix],
        short_last[last_prefix + 1],
        short_last[last_prefix + 2],
        short_last[last_prefix + 3],
    ]);
    short_last[last_prefix..last_prefix + 4].copy_from_slice(&(last_len - 1).to_be_bytes());
    let err = PreparedPaidInputV1::decode(&short_last, budget)
        .expect_err("a shortened final length must not decode");
    assert!(
        err.to_string()
            .contains("trailing bytes after prepared input"),
        "{err}"
    );

    // MUTATION: one appended byte.
    let mut trailing = encoded.clone();
    trailing.push(0);
    let err = PreparedPaidInputV1::decode(&trailing, budget)
        .expect_err("a trailing byte must not decode");
    assert!(
        err.to_string()
            .contains("trailing bytes after prepared input"),
        "{err}"
    );

    // MUTATION: a noncanonical nested body — the last token id re-spelled
    // with a wider integer header.
    let mut widened = prompt_tokens().canonical_bytes();
    let position = widened
        .iter()
        .rposition(|byte| *byte == 6)
        .expect("last token id");
    widened.splice(position..=position, [0x18, 6]);
    let noncanonical = assemble(&[
        &evaluate_request_bytes_of(),
        &manifest().canonical_bytes(),
        &text_execution().canonical_bytes(),
        &widened,
        &text_policy().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    let err = PreparedPaidInputV1::decode(&noncanonical, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("a noncanonical token body must not parse");
    assert!(err.to_string().contains("non-canonical"), "{err}");

    // MUTATION: the carried manifest must be parsed too; hashing arbitrary
    // bytes would let a paid-input graph commit to an invalid application.
    let mut noncanonical_manifest = manifest().canonical_bytes();
    noncanonical_manifest.push(0);
    let noncanonical = assemble(&[
        &evaluate_request_bytes_of(),
        &noncanonical_manifest,
        &text_execution().canonical_bytes(),
        &prompt_tokens().canonical_bytes(),
        &text_policy().canonical_bytes(),
        &identity_artifact().canonical_bytes(),
    ]);
    let err = PreparedPaidInputV1::decode(&noncanonical, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("a noncanonical manifest body must not parse");
    assert!(err.to_string().contains("trailing bytes"), "{err}");
}

/// A declared length is never trusted: not against the input, not
/// against the budget, and not in aggregate.
#[test]
fn prepared_input_lengths_are_bounded_before_allocation() {
    let encoded = bundle().encode().expect("a representable bundle");

    // MUTATION: u32::MAX in the first length.
    let mut huge = encoded.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let err = PreparedPaidInputV1::decode(&huge, 1_048_576)
        .expect_err("a u32::MAX length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: six lengths that are individually legal and jointly
    // beyond the budget.
    let budget = encoded.len() - 1;
    let err = PreparedPaidInputV1::decode(&encoded, budget)
        .expect_err("a bundle over its budget must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // The exact budget is legal; one byte less is not.
    assert!(PreparedPaidInputV1::decode(&encoded, encoded.len()).is_ok());
}

// ── Streaming hash equivalence ────────────────────────────────────────

/// Every `XFH` preimage hashes the same however it is written, and the
/// single-chunk hasher genuinely cannot take its place.
#[test]
fn streaming_hash_matches_one_shot_under_every_segmentation() {
    let mut preimage = b"hellas.work.prepared-input.v1".to_vec();
    preimage.extend_from_slice(&[0xab; 20_000]);
    let expected = Digest::hash(&preimage);

    for split in [1, 8_191, 8_192, 8_193, 65_536, preimage.len()] {
        let split = split.min(preimage.len());
        let mut hasher = hellas_xet::XetFileHasher::new();
        hasher.update(&preimage[..split]);
        hasher.update(&preimage[split..]);
        assert_eq!(hasher.finalize(), expected, "split at {split}");
    }

    // MUTATION: hash the same preimage with the single-chunk hasher. It
    // asserts rather than truncating, which is exactly why the variable
    // preimages do not use it.
    let panicked = std::panic::catch_unwind(|| {
        let mut hasher = hellas_xet::SingleChunkHasher::new();
        hasher.update(&preimage);
        hasher.finalize()
    });
    assert!(panicked.is_err());
}

/// A legal bundle can be far larger than the single-chunk limit, and its
/// digest is computed anyway.
///
/// This is the test that makes the choice of hasher load-bearing: a
/// prompt of a few thousand tokens puts the prepared-input preimage past
/// [`hellas_xet::MIN_CHUNK_SIZE`], where the single-chunk hasher asserts.
#[test]
fn a_bundle_over_the_single_chunk_limit_still_hashes() {
    let long_prompt = TokenIds::from_u32s(0..4_000);
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        long_prompt.output_id(),
        text_policy().output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let large = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &long_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    assert!(
        large.encode().expect("a representable bundle").len() > hellas_xet::MIN_CHUNK_SIZE,
        "the fixture must exceed the single-chunk limit to be a test of it",
    );
    let digest = input_digest(&channel(), &large);
    assert_ne!(digest, input_digest(&channel(), &bundle()));

    // The same bundle over a channel-sized budget still decodes, and its
    // digest survives the round trip.
    let encoded = large.encode().expect("a representable bundle");
    let decoded = PreparedPaidInputV1::decode(&encoded, 1_048_576).expect("legal bundle");
    assert_eq!(input_digest(&channel(), &decoded), digest);
}

/// Every fixed-record preimage is measured, not assumed, to be under the
/// single-chunk limit.
///
/// The widest is `longest domain || network || channel || widest record`.
/// Both maxima are taken over the whole set rather than named, so the
/// record and the domain that happen to be widest today are asserted to
/// be the widest rather than assumed to stay so.
#[test]
fn widest_fixed_preimage_is_measured() {
    let longest_network =
        NetworkId::new(&"n".repeat(hellas_kernel::MAX_NETWORK_ID_LENGTH)).expect("legal id");
    let encoded_network = 1 + hellas_kernel::MAX_NETWORK_ID_LENGTH;
    for size in [
        PaidChannelPolicyV1::ENCODED_SIZE,
        PaidExecutionPolicyV1::ENCODED_SIZE,
        PaidJobResultV1::ENCODED_SIZE,
        PaymentBindingV1::ENCODED_SIZE,
    ] {
        assert!(
            size <= PaidJobAuthorizationV1::ENCODED_SIZE,
            "{size} is wider than the record the bound is taken over"
        );
    }
    for domain in [
        "hellas.work.channel.v2",
        "hellas.work.generation-policy.v1",
        "hellas.work.identity-source.v1",
        "hellas.work.execution-policy.v1",
        "hellas.work.prepared-input.v1",
        "hellas.work.paid-job-authorize.v1",
        "hellas.work.paid-job-result.v1",
        "hellas.work.payment-binding.v1",
        "hellas.work.evaluate-output.v2",
    ] {
        assert!(
            domain.len() <= "hellas.work.paid-channel-policy.v1".len(),
            "{domain} is longer than the domain the bound is taken over"
        );
    }
    let widest = "hellas.work.paid-channel-policy.v1".len()
        + encoded_network
        + 32
        + PaidJobAuthorizationV1::ENCODED_SIZE;
    assert_eq!(widest, 34 + 64 + 32 + 330);
    assert_eq!(widest, 460);
    assert!(widest < hellas_xet::MIN_CHUNK_SIZE);

    // The one shape that is not record-shaped is bounded too: the
    // channel id, which is derived before a channel id exists and so
    // carries no channel field.
    assert_eq!(
        "hellas.work.channel.v2".len() + encoded_network + 4 * 32,
        214
    );

    // The widest preimage is also a preimage that must hash rather than
    // panic, so it is actually hashed here.
    let channel = channel_on(longest_network, EdgeId::from_bytes([0xe1; 32]));
    let _ = work_id(&channel, &authorization());
}

// ── Authorization ─────────────────────────────────────────────────────

/// The happy path: both parties check the same authorization against
/// their own terms and sign the same digest.
#[test]
fn both_parties_sign_one_authorization_digest() {
    let channel = channel();
    let authorization = authorization();
    let work_id = check_authorization(&channel, &authorization, &execution_policy(), 900)
        .expect("a legal authorization");
    check_prepared_input(&channel, &authorization, &execution_policy(), &bundle())
        .expect("a legal bundle");

    let payload = hellas_kernel::PayloadHash::from_bytes(work_id.into_bytes());
    let client_sig = client().sign(payload);
    let provider_sig = provider().sign(payload);
    let verifier = Secp256k1Verifier;
    assert!(verifier.verify_sig(client_sig, channel.client_key(), payload));
    assert!(verifier.verify_sig(provider_sig, channel.provider_key(), payload));

    // MUTATION: the client changes the price after the provider signs.
    let mut repriced = authorization;
    repriced.price = 249;
    let moved = work_id_payload(&channel, &repriced);
    assert!(!verifier.verify_sig(provider_sig, channel.provider_key(), moved));
}

fn work_id_payload(
    channel: &PaidChannel,
    authorization: &PaidJobAuthorizationV1,
) -> hellas_kernel::PayloadHash {
    hellas_kernel::PayloadHash::from_bytes(work_id(channel, authorization).into_bytes())
}

/// Every authorization field moves the signed digest.
///
/// A field that did not would be a field either party could change after
/// the other signed.
#[test]
fn every_authorization_field_moves_the_work_id() {
    let channel = channel();
    let base = authorization();
    let signed = work_id(&channel, &base);

    let mutations: Vec<(&str, PaidJobAuthorizationV1)> = vec![
        ("channel_id", {
            let mut m = base;
            m.channel_id = Digest::from_bytes([0; 32]);
            m
        }),
        ("bond_edge", {
            let mut m = base;
            m.bond_edge = EdgeId::from_bytes([0; 32]);
            m
        }),
        ("bond_terms_hash", {
            let mut m = base;
            m.bond_terms_hash = TermsHash::from_bytes([0; 32]);
            m
        }),
        ("payment_edge", {
            let mut m = base;
            m.payment_edge = EdgeId::from_bytes([0; 32]);
            m
        }),
        ("payment_terms_hash", {
            let mut m = base;
            m.payment_terms_hash = TermsHash::from_bytes([0; 32]);
            m
        }),
        ("execution_policy_digest", {
            let mut m = base;
            m.execution_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("prepared_input_digest", {
            let mut m = base;
            m.prepared_input_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("proposal_nonce", {
            let mut m = base;
            m.proposal_nonce ^= 1;
            m
        }),
        ("acceptance_deadline", {
            let mut m = base;
            m.acceptance_deadline += 1;
            m
        }),
        ("request_commitment", {
            let mut m = base;
            m.request_commitment = RequestCommitment::from_digest(Digest::from_bytes([0; 32]));
            m
        }),
        ("environment_commitment", {
            let mut m = base;
            m.environment_commitment = ContentId::from_bytes([0; 32]);
            m
        }),
        ("price", {
            let mut m = base;
            m.price += 1;
            m
        }),
        ("terminal_deadline", {
            let mut m = base;
            m.terminal_deadline += 1;
            m
        }),
        ("payment_deadline", {
            let mut m = base;
            m.payment_deadline += 1;
            m
        }),
    ];
    assert_eq!(mutations.len(), 14, "every field must be mutated");
    for (field, mutated) in mutations {
        assert_ne!(
            work_id(&channel, &mutated),
            signed,
            "{field} left the digest alone"
        );
    }
}

/// The authorization's own rules: price bounds, deadline ordering, and
/// the acceptance window.
#[test]
fn authorization_rules_reject_their_violations() {
    let channel = channel();
    let policy = execution_policy();
    let base = authorization();
    assert!(check_authorization(&channel, &base, &policy, 900).is_ok());

    // MUTATION: a free job.
    let mut zero_price = base;
    zero_price.price = 0;
    let mut zero_policy = policy;
    zero_policy.fixed_price = 0;
    zero_price.execution_policy_digest = execution_policy_digest(&channel, &zero_policy);
    assert_eq!(
        check_authorization(&channel, &zero_price, &zero_policy, 900),
        Err(PaidWorkError::PolicyZero {
            field: "fixed_price"
        })
    );

    // MUTATION: a price the bond does not cover.
    let mut over_bond = base;
    over_bond.price = 501;
    let mut over_policy = policy;
    over_policy.fixed_price = 501;
    over_bond.execution_policy_digest = execution_policy_digest(&channel, &over_policy);
    assert_eq!(
        check_authorization(&channel, &over_bond, &over_policy, 900),
        Err(PaidWorkError::PriceOutOfRange {
            price: 501,
            max_job_price: 500
        })
    );

    // MUTATION: a price that disagrees with the signed policy.
    let mut mispriced = base;
    mispriced.price = 249;
    assert_eq!(
        check_authorization(&channel, &mispriced, &policy, 900),
        Err(PaidWorkError::Mismatch { field: "price" })
    );

    // MUTATION: signing after the acceptance window closed.
    assert_eq!(
        check_authorization(&channel, &base, &policy, 1_001),
        Err(PaidWorkError::AcceptanceExpired {
            height: 1_001,
            deadline: 1_000
        })
    );

    // MUTATION: a payment deadline past the channel's admission horizon.
    let mut late = base;
    late.payment_deadline = 5_000;
    assert_eq!(
        check_authorization(&channel, &late, &policy, 900),
        Err(PaidWorkError::DeadlineOrder {
            acceptance: 1_000,
            terminal: 1_050,
            payment: 5_000,
            horizon: 5_000
        })
    );

    // MUTATION: terminal and payment deadlines out of order.
    let mut inverted = base;
    inverted.terminal_deadline = 1_100;
    inverted.payment_deadline = 1_050;
    assert!(matches!(
        check_authorization(&channel, &inverted, &policy, 900),
        Err(PaidWorkError::DeadlineOrder { .. })
    ));
}

/// Every execution-policy field is inside the digest the authorization
/// pins, so a locally re-decoded policy that differs anywhere fails the
/// comparison.
#[test]
fn every_execution_policy_field_moves_its_digest() {
    let channel = channel();
    let base = execution_policy();
    let pinned = execution_policy_digest(&channel, &base);
    let authorization = authorization();

    let mutations: Vec<(&str, PaidExecutionPolicyV1)> = vec![
        ("allowed_environment", {
            let mut m = base;
            m.allowed_environment = ContentId::from_bytes([0; 32]);
            m
        }),
        ("generation_policy_digest", {
            let mut m = base;
            m.generation_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("identity_source_digest", {
            let mut m = base;
            m.identity_source_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("max_prompt_tokens", {
            let mut m = base;
            m.max_prompt_tokens += 1;
            m
        }),
        ("max_new_tokens", {
            let mut m = base;
            m.max_new_tokens += 1;
            m
        }),
        ("max_stop_token_ids", {
            let mut m = base;
            m.max_stop_token_ids += 1;
            m
        }),
        ("max_spool_bytes", {
            let mut m = base;
            m.max_spool_bytes += 1;
            m
        }),
        ("max_encoded_result_frame", {
            let mut m = base;
            m.max_encoded_result_frame += 1;
            m
        }),
        ("max_encoded_quote_response", {
            let mut m = base;
            m.max_encoded_quote_response += 1;
            m
        }),
        ("dispatch_margin_blocks", {
            let mut m = base;
            m.dispatch_margin_blocks += 1;
            m
        }),
        ("delivery_margin_blocks", {
            let mut m = base;
            m.delivery_margin_blocks += 1;
            m
        }),
        ("oracle_grace_blocks", {
            let mut m = base;
            m.oracle_grace_blocks += 1;
            m
        }),
        ("fixed_price", {
            let mut m = base;
            m.fixed_price += 1;
            m
        }),
    ];
    assert_eq!(mutations.len(), 13, "every field must be mutated");
    for (field, mutated) in mutations {
        assert_ne!(
            execution_policy_digest(&channel, &mutated),
            pinned,
            "{field} left the policy digest alone"
        );
        // A recomputed digest does not help: the authorization pins the
        // one both parties agreed to.
        assert_eq!(
            check_authorization(&channel, &authorization, &mutated, 900).err(),
            Some(PaidWorkError::Mismatch {
                field: "execution_policy_digest"
            }),
            "{field} was accepted under a recomputed digest"
        );
    }
}

/// The channel opens its own credit commitment, so a policy the terms do
/// not commit to is a channel that cannot be built.
#[test]
fn a_channel_cannot_be_built_on_an_uncommitted_credit_policy() {
    let terms = payment_terms();
    let edge = EdgeId::from_bytes([0xe1; 32]);
    let build = |network: NetworkId, salt: &[u8; 32], policy: PaidChannelPolicyV1| {
        PaidChannel::new(network, edge, terms.clone(), salt, policy)
    };
    assert!(build(network(), &SALT, channel_policy()).is_ok());

    // MUTATION: a different compute credit limit under the same salt.
    let mut compute = channel_policy();
    compute.compute_credit_limit += 1;
    assert_eq!(
        build(network(), &SALT, compute).err(),
        Some(PaidWorkError::Mismatch {
            field: "private_policy_commitment"
        })
    );

    // MUTATION: a different delivery credit limit.
    let mut delivery = channel_policy();
    delivery.delivery_credit_limit += 1;
    assert!(build(network(), &SALT, delivery).is_err());

    // MUTATION: the same body under a different salt.
    assert!(build(network(), &[0x5b; 32], channel_policy()).is_err());

    // MUTATION: the same body and salt on a different network.
    let other = NetworkId::new(OTHER_NETWORK).expect("legal id");
    assert!(build(other, &SALT, channel_policy()).is_err());

    // The policy the channel opened is the policy it carries.
    let channel = channel();
    assert_eq!(*channel.channel_policy(), channel_policy());
}

/// A job priced above what the channel's credit limits cover is refused
/// at authorization, under the policy that actually prices the job.
///
/// The limits are per-channel and the price is per-authorization, so a
/// comparison made once at setup compares against whichever execution
/// policy happened to be in hand. This one compares against this job's.
#[test]
fn a_price_above_the_channel_credit_limits_is_refused() {
    let policy = execution_policy();
    let base = authorization();
    assert!(check_authorization(&channel(), &base, &policy, 900).is_ok());

    // A second execution policy on the same channel, priced above the
    // compute credit limit and still inside `max_job_price`. The channel
    // committed to neither price: it committed to two limits.
    let thin = PaidChannelPolicyV1 {
        compute_credit_limit: 300,
        delivery_credit_limit: 800,
    };
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network(), &SALT, &thin),
        ..payment_terms()
    };
    let channel = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        terms,
        &SALT,
        thin,
    )
    .expect("terms that commit to this credit policy");

    let mut dear = execution_policy();
    dear.fixed_price = 500;
    let mut authorization = authorization();
    authorization.channel_id = channel.id();
    authorization.payment_terms_hash = channel.payment_terms_hash();
    authorization.price = 500;
    authorization.execution_policy_digest = execution_policy_digest(&channel, &dear);
    authorization.prepared_input_digest = input_digest(&channel, &bundle());

    assert_eq!(
        check_authorization(&channel, &authorization, &dear, 900),
        Err(PaidWorkError::OverEnvelope {
            field: "price against compute_credit_limit",
            actual: 500,
            limit: 300
        })
    );

    // MUTATION: raise the compute limit alone. The delivery limit is a
    // separate rule and refuses on its own.
    let both = PaidChannelPolicyV1 {
        compute_credit_limit: 500,
        delivery_credit_limit: 499,
    };
    let terms = WorkPaymentTerms {
        private_policy_commitment: private_policy_commitment(network(), &SALT, &both),
        ..payment_terms()
    };
    let channel = PaidChannel::new(
        network(),
        EdgeId::from_bytes([0xe1; 32]),
        terms,
        &SALT,
        both,
    )
    .expect("terms that commit to this credit policy");
    authorization.payment_terms_hash = channel.payment_terms_hash();
    authorization.channel_id = channel.id();
    authorization.execution_policy_digest = execution_policy_digest(&channel, &dear);
    assert_eq!(
        check_authorization(&channel, &authorization, &dear, 900),
        Err(PaidWorkError::OverEnvelope {
            field: "price against delivery_credit_limit",
            actual: 500,
            limit: 499
        })
    );
}

/// Every bound the profile requires to be positive is refused at zero,
/// one field at a time.
#[test]
fn an_absent_execution_policy_bound_is_refused() {
    let base = execution_policy();
    assert!(check_execution_policy(&base).is_ok());

    let zeroed: Vec<(&str, PaidExecutionPolicyV1)> = vec![
        (
            "fixed_price",
            PaidExecutionPolicyV1 {
                fixed_price: 0,
                ..base
            },
        ),
        (
            "max_prompt_tokens",
            PaidExecutionPolicyV1 {
                max_prompt_tokens: 0,
                ..base
            },
        ),
        (
            "max_new_tokens",
            PaidExecutionPolicyV1 {
                max_new_tokens: 0,
                ..base
            },
        ),
        (
            "max_spool_bytes",
            PaidExecutionPolicyV1 {
                max_spool_bytes: 0,
                ..base
            },
        ),
        (
            "max_encoded_result_frame",
            PaidExecutionPolicyV1 {
                max_encoded_result_frame: 0,
                ..base
            },
        ),
        (
            "max_encoded_quote_response",
            PaidExecutionPolicyV1 {
                max_encoded_quote_response: 0,
                ..base
            },
        ),
        (
            "dispatch_margin_blocks",
            PaidExecutionPolicyV1 {
                dispatch_margin_blocks: 0,
                ..base
            },
        ),
        (
            "delivery_margin_blocks",
            PaidExecutionPolicyV1 {
                delivery_margin_blocks: 0,
                ..base
            },
        ),
        (
            "oracle_grace_blocks",
            PaidExecutionPolicyV1 {
                oracle_grace_blocks: 0,
                ..base
            },
        ),
    ];
    assert_eq!(zeroed.len(), 9, "every required bound must be zeroed");
    for (field, policy) in zeroed {
        assert_eq!(
            check_execution_policy(&policy),
            Err(PaidWorkError::PolicyZero { field }),
            "{field} was accepted at zero"
        );
    }

    // `max_stop_token_ids` is the one bound that may be zero: a channel
    // that admits no stop tokens is a usable channel.
    assert!(
        check_execution_policy(&PaidExecutionPolicyV1 {
            max_stop_token_ids: 0,
            ..base
        })
        .is_ok()
    );
}

// ── Prepared input graph ──────────────────────────────────────────────

/// The bundle's nested commitments must equal the authorization and the
/// policy; a digest match is not a graph check.
#[test]
fn prepared_input_graph_is_checked_not_assumed() {
    let channel = channel();
    let policy = execution_policy();
    let authorization = authorization();
    assert!(check_prepared_input(&channel, &authorization, &policy, &bundle()).is_ok());

    // MUTATION: a bundle for a different prompt, with its digest
    // recomputed so only the graph check can catch it.
    let other_prompt = TokenIds::from([1, 2, 3]);
    let other_execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        other_prompt.output_id(),
        text_policy().output_id(),
    );
    let other_bundle = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &other_execution,
        &other_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut repointed = authorization;
    repointed.prepared_input_digest = input_digest(&channel, &other_bundle);
    assert_eq!(
        check_prepared_input(&channel, &repointed, &policy, &other_bundle),
        Err(PaidWorkError::Mismatch {
            field: "text_execution id"
        })
    );

    // MUTATION: an over-long prompt.
    let long_prompt = TokenIds::from([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let long_execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        long_prompt.output_id(),
        text_policy().output_id(),
    );
    let long_request = EvaluateRequest {
        text_execution: long_execution.input_id().digest(),
        ..evaluate_request()
    };
    let long_bundle = PreparedPaidInputV1::new(
        &long_request,
        &manifest(),
        &long_execution,
        &long_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut long_auth = authorization;
    long_auth.prepared_input_digest = input_digest(&channel, &long_bundle);
    long_auth.request_commitment = Evaluate::commit_request(&long_request);
    assert_eq!(
        check_prepared_input(&channel, &long_auth, &policy, &long_bundle),
        Err(PaidWorkError::OverEnvelope {
            field: "prompt tokens",
            actual: 9,
            limit: 8
        })
    );

    // MUTATION: resume from a previous output instead of the identity
    // artifact this profile pins.
    let resumed_execution = TextExecution::new(
        SourceRef::input(text_execution().input_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    );
    let resumed_request = EvaluateRequest {
        text_execution: resumed_execution.input_id().digest(),
        ..evaluate_request()
    };
    let resumed_bundle = PreparedPaidInputV1::new(
        &resumed_request,
        &manifest(),
        &resumed_execution,
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut resumed_auth = authorization;
    resumed_auth.prepared_input_digest = input_digest(&channel, &resumed_bundle);
    resumed_auth.request_commitment = Evaluate::commit_request(&resumed_request);
    assert_eq!(
        check_prepared_input(&channel, &resumed_auth, &policy, &resumed_bundle),
        Err(PaidWorkError::Mismatch {
            field: "text_execution source"
        })
    );

    // MUTATION: another assurance mode under an otherwise legal bundle.
    let attested = EvaluateRequest {
        assurance: Assurance::AppleAppAttest,
        ..evaluate_request()
    };
    let attested_bundle = PreparedPaidInputV1::new(
        &attested,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut attested_auth = authorization;
    attested_auth.prepared_input_digest = input_digest(&channel, &attested_bundle);
    attested_auth.request_commitment = Evaluate::commit_request(&attested);
    assert_eq!(
        check_prepared_input(&channel, &attested_auth, &policy, &attested_bundle),
        Err(PaidWorkError::Mismatch {
            field: "request assurance"
        })
    );

    // MUTATION: a runner key that is not the channel's client.
    let delegated = EvaluateRequest {
        runner_public_key: PublicKey::Secp256k1(provider().party_key().to_bytes()),
        ..evaluate_request()
    };
    let delegated_bundle = PreparedPaidInputV1::new(
        &delegated,
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut delegated_auth = authorization;
    delegated_auth.prepared_input_digest = input_digest(&channel, &delegated_bundle);
    delegated_auth.request_commitment = Evaluate::commit_request(&delegated);
    assert_eq!(
        check_prepared_input(&channel, &delegated_auth, &policy, &delegated_bundle),
        Err(PaidWorkError::Mismatch {
            field: "runner_public_key"
        })
    );
}

/// Each binding in the bundle's graph is broken on its own.
///
/// Mutating a component and the record that names it together proves
/// only that *some* check fired. Here every case leaves the rest of the
/// graph intact and recomputes the bundle digest, so the named check is
/// the only thing that can refuse it — which is what makes the check's
/// removal a test failure rather than a silent loss.
#[test]
fn each_graph_binding_is_checked_on_its_own() {
    let channel = channel();
    let policy = execution_policy();
    let base = authorization();

    // A prompt body the execution does not name.
    let other_prompt = TokenIds::from([5, 5, 5, 5]);
    assert_ne!(other_prompt.output_id(), prompt_tokens().output_id());
    let mismatched_prompt = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &other_prompt,
        &text_policy(),
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_prompt);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_prompt),
        Err(PaidWorkError::Mismatch {
            field: "prompt_tokens id"
        })
    );

    // A generation policy the execution does not name.
    let other_policy = TextPolicy::from_u32_stop_tokens(32, [3]);
    assert_ne!(other_policy.output_id(), text_policy().output_id());
    let mismatched_policy = PreparedPaidInputV1::new(
        &evaluate_request(),
        &manifest(),
        &text_execution(),
        &prompt_tokens(),
        &other_policy,
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_policy);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_policy),
        Err(PaidWorkError::Mismatch {
            field: "text_policy id"
        })
    );

    // A manifest that is not the environment the request commits to.
    let other_manifest = ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR).unwrap(),
        ContentId::from_bytes([0x99; 32]),
    );
    assert_ne!(other_manifest.content_id(), manifest().content_id());
    let mismatched_manifest = PreparedPaidInputV1::new(
        &evaluate_request(),
        &other_manifest,
        &text_execution(),
        &prompt_tokens(),
        &text_policy(),
        &identity_artifact(),
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &mismatched_manifest);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &mismatched_manifest),
        Err(PaidWorkError::Mismatch {
            field: "manifest content id"
        })
    );

    // A request commitment the authorization does not carry.
    let mut restamped = base;
    restamped.request_commitment = RequestCommitment::from_digest(Digest::from_bytes([0x88; 32]));
    assert_eq!(
        check_prepared_input(&channel, &restamped, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "request_commitment"
        })
    );

    // An environment commitment the request does not name.
    let mut reenvironed = base;
    reenvironed.environment_commitment = ContentId::from_bytes([0x87; 32]);
    assert_eq!(
        check_prepared_input(&channel, &reenvironed, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "environment_commitment"
        })
    );

    // A policy pinned to a generation policy this bundle does not carry.
    let mut repinned = policy;
    repinned.generation_policy_digest = Digest::from_bytes([0x86; 32]);
    assert_eq!(
        check_prepared_input(&channel, &base, &repinned, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "generation_policy_digest"
        })
    );

    // A policy pinned to an identity artifact this bundle does not
    // carry.
    let mut resourced = policy;
    resourced.identity_source_digest = Digest::from_bytes([0x85; 32]);
    assert_eq!(
        check_prepared_input(&channel, &base, &resourced, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "identity_source_digest"
        })
    );

    // An identity artifact bound to another environment than the one
    // the request runs in. It is a legal artifact and a legal request;
    // what is wrong is the edge between them, and the provider reads
    // the model out of this end of it.
    let elsewhere = TextArtifact::identity(BoundTermId::from_bytes([0x83; 32]));
    let mut rebound_policy = policy;
    rebound_policy.identity_source_digest =
        match identity_source_digest(&elsewhere.canonical_bytes()) {
            Ok(digest) => digest,
            Err(error) => panic!("the identity hashes: {error}"),
        };
    let rebound_execution = TextExecution::new(
        SourceRef::output(elsewhere.output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    );
    let mut rebound_request = evaluate_request();
    rebound_request.text_execution = rebound_execution.input_id().digest();
    let rebound = PreparedPaidInputV1::new(
        &rebound_request,
        &manifest(),
        &rebound_execution,
        &prompt_tokens(),
        &text_policy(),
        &elsewhere,
    );
    let mut authorization = base;
    authorization.prepared_input_digest = input_digest(&channel, &rebound);
    authorization.request_commitment = Evaluate::commit_request(&rebound_request);
    assert_eq!(
        check_prepared_input(&channel, &authorization, &rebound_policy, &rebound),
        Err(PaidWorkError::Mismatch {
            field: "identity_artifact bound_term"
        })
    );

    // A bundle whose digest is not the one the authorization named at
    // all: the cheapest check, and the one that must not be the only
    // one.
    let mut unbound = base;
    unbound.prepared_input_digest = Digest::from_bytes([0x84; 32]);
    assert_eq!(
        check_prepared_input(&channel, &unbound, &policy, &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "prepared_input_digest"
        })
    );
}

/// Each bound of the resource envelope refuses on its own.
///
/// Every case here recomputes the bundle digest and leaves the rest of
/// the graph intact, so the named bound is the only thing that can
/// refuse it: deleting any one of them makes exactly one of these
/// assertions return `Ok`.
#[test]
fn each_envelope_bound_is_checked_on_its_own() {
    let channel = channel();
    let base = execution_policy();
    let authorization = authorization();
    assert!(check_prepared_input(&channel, &authorization, &base, &bundle()).is_ok());

    // A bundle larger than the complete quote response this channel
    // agreed to hold. Refused before its digest is even computed: an
    // endpoint does not hash a body it has not agreed to receive.
    let encoded = bundle().encode().expect("a representable bundle");
    let cramped = PaidExecutionPolicyV1 {
        max_encoded_quote_response: 100,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &cramped, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "prepared input length",
            actual: encoded.len() as u64,
            limit: 100
        })
    );
    // The exact length is legal; one byte less is not.
    let exact = PaidExecutionPolicyV1 {
        max_encoded_quote_response: encoded.len() as u32,
        ..base
    };
    assert!(check_prepared_input(&channel, &authorization, &exact, &bundle()).is_ok());

    // A generation longer than the policy admits.
    let short = PaidExecutionPolicyV1 {
        max_new_tokens: 63,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &short, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "max_new_tokens",
            actual: 64,
            limit: 63
        })
    );

    // More stop tokens than the policy admits.
    let few = PaidExecutionPolicyV1 {
        max_stop_token_ids: 1,
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &few, &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "stop token ids",
            actual: 2,
            limit: 1
        })
    );

    // A request authorized to generate nothing. Zero is inside every
    // bound above it, so nothing but its own rule refuses it.
    let silent = TextPolicy::from_u32_stop_tokens(0, [2, 1]);
    let (silent_bundle, silent_auth) = bundle_with_policy(&channel, &silent);
    let admits_silence = PaidExecutionPolicyV1 {
        generation_policy_digest: policy_digest_of(&silent),
        ..base
    };
    assert_eq!(
        check_prepared_input(&channel, &silent_auth, &admits_silence, &silent_bundle),
        Err(PaidWorkError::PolicyZero {
            field: "request max_new_tokens"
        })
    );
}

/// Rebuilds the bundle and the authorization around one replacement
/// generation policy, leaving every other binding intact.
fn bundle_with_policy(
    channel: &PaidChannel,
    policy: &TextPolicy,
) -> (PreparedPaidInputV1, PaidJobAuthorizationV1) {
    let execution = TextExecution::new(
        SourceRef::output(identity_artifact().output_id()),
        prompt_tokens().output_id(),
        policy.output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let bundle = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        policy,
        &identity_artifact(),
    );
    let authorization = PaidJobAuthorizationV1 {
        prepared_input_digest: input_digest(channel, &bundle),
        request_commitment: Evaluate::commit_request(&request),
        ..authorization()
    };
    (bundle, authorization)
}

/// This profile starts from the identity artifact and nothing else.
///
/// A job resumed from a previous output would be paid for work whose
/// input the bundle does not carry. The policy here is repinned to the
/// output artifact and the execution names it as its source, so the two
/// neighbouring rules — the source check and the identity commitment —
/// both pass, and only the artifact's kind refuses it.
#[test]
fn only_the_identity_artifact_may_start_a_paid_job() {
    let channel = channel();
    let resumed = TextArtifact::output(
        text_execution().input_id(),
        4,
        TextState::new(prompt_tokens().output_id()).output_id(),
        prompt_tokens().output_id(),
    );
    let execution = TextExecution::new(
        SourceRef::output(resumed.output_id()),
        prompt_tokens().output_id(),
        text_policy().output_id(),
    );
    let request = EvaluateRequest {
        text_execution: execution.input_id().digest(),
        ..evaluate_request()
    };
    let bundle = PreparedPaidInputV1::new(
        &request,
        &manifest(),
        &execution,
        &prompt_tokens(),
        &text_policy(),
        &resumed,
    );
    let authorization = PaidJobAuthorizationV1 {
        prepared_input_digest: input_digest(&channel, &bundle),
        request_commitment: Evaluate::commit_request(&request),
        ..authorization()
    };
    let policy = PaidExecutionPolicyV1 {
        identity_source_digest: identity_digest_of(&resumed),
        ..execution_policy()
    };
    assert_eq!(
        check_prepared_input(&channel, &authorization, &policy, &bundle),
        Err(PaidWorkError::Mismatch {
            field: "identity_artifact kind"
        })
    );
}

// ── Result, binding, payment ──────────────────────────────────────────

/// A result answers one job. Swapping two provider-signed results
/// between two authorizations rejects both payments.
#[test]
fn results_cannot_be_swapped_between_jobs() {
    let channel = channel();
    let first = authorization();
    let mut second = authorization();
    second.proposal_nonce ^= 0xff;

    let first_id = work_id(&channel, &first);
    let second_id = work_id(&channel, &second);
    assert_ne!(first_id, second_id);

    let first_result = job_result(first_id);
    let second_result = job_result(second_id);

    assert!(next_payment(&channel, &first, &first_result, 0, capacity()).is_ok());
    assert!(next_payment(&channel, &second, &second_result, 0, capacity()).is_ok());

    // MUTATION: pay the first job with the second job's result.
    assert_eq!(
        next_payment(&channel, &first, &second_result, 0, capacity()),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
    assert_eq!(
        next_payment(&channel, &second, &first_result, 0, capacity()),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
}

/// The result digest binds the output and the transcript, so re-signing
/// mutated output bytes produces a different digest and a different
/// binding.
#[test]
fn result_output_mutations_move_the_result_digest() {
    let channel = channel();
    let id = work_id(&channel, &authorization());
    let base = job_result(id);
    let pinned = check_result(&channel, id, &base).expect("a legal result");

    // MUTATION: different output bytes, honestly re-signed by the
    // provider. The digest moves, so the binding that named the old one
    // no longer describes this result.
    let mut different_output = base;
    different_output.canonical_output_digest = Digest::from_bytes([0x33; 32]);
    assert_ne!(result_digest(&channel, &different_output), pinned);

    // MUTATION: the same answer under a different transcript.
    let mut different_transcript = base;
    different_transcript.terminal_transcript_commitment =
        EventCommitment::from_digest(Digest::from_bytes([0x34; 32]));
    assert_ne!(result_digest(&channel, &different_transcript), pinned);
}

/// A new channel starts at cumulative 0, and the transition is checked
/// arithmetic against the edge's capacity.
#[test]
fn the_payment_transition_is_checked_arithmetic() {
    let channel = channel();
    let authorization = authorization();
    let result = job_result(work_id(&channel, &authorization));

    let (certificate, binding) = next_payment(&channel, &authorization, &result, 0, capacity())
        .expect("a legal first payment");
    assert_eq!(certificate.earned_cumulative(), 250);
    assert_eq!(certificate.payment_edge(), channel.payment_edge());
    assert_eq!(
        certificate.payment_terms_hash(),
        channel.payment_terms_hash()
    );
    assert_eq!(binding.work_id, work_id(&channel, &authorization));
    assert_eq!(binding.result_digest, result_digest(&channel, &result));
    assert_eq!(binding.certificate_digest, certificate.digest(network()));

    // The second payment continues the first: nothing here restates the
    // price, so the only way the cumulative moves is by adding it.
    let (second, _) = next_payment(&channel, &authorization, &result, 250, capacity())
        .expect("a legal second payment");
    assert_eq!(second.earned_cumulative(), 500);

    // MUTATION: a transition that would exceed the edge's capacity.
    let Some(thin) = work_payment_settlement(EdgeValues::new(400, 0, Fees::ZERO), 100) else {
        panic!("a funded edge prices both exits");
    };
    assert_eq!(thin.capacity(), 300);
    assert_eq!(
        next_payment(&channel, &authorization, &result, 100, thin),
        Err(PaidWorkError::OverCapacity {
            cumulative: 350,
            capacity: 300
        })
    );

    // MUTATION: a cumulative that would wrap.
    let Some(widest) = work_payment_settlement(EdgeValues::new(u64::MAX, 0, Fees::ZERO), 0) else {
        panic!("the largest edge is representable");
    };
    assert_eq!(
        next_payment(&channel, &authorization, &result, u64::MAX, widest),
        Err(PaidWorkError::Overflow {
            field: "earned cumulative"
        })
    );
}

/// One job's whole payment, as the ledger credits it.
///
/// Returns the four values `credit_payment` takes beside the channel, so
/// a mutation below can move exactly one of them.
fn payment_at(
    credited: u64,
    nonce: u64,
) -> (
    PaidJobAuthorizationV1,
    PaidJobResultV1,
    EarnedCertificate,
    PaymentBindingV1,
) {
    let channel = channel();
    let mut authorization = authorization();
    authorization.proposal_nonce = nonce;
    let result = job_result(work_id(&channel, &authorization));
    let (certificate, binding) =
        next_payment(&channel, &authorization, &result, credited, capacity())
            .expect("a legal payment");
    (authorization, result, certificate, binding)
}

/// The ledger credits exactly the payment this position produces.
///
/// Every mutation below moves one field and leaves the rest of the
/// payment intact, and every one of them is refused by name. A rule that
/// answered them all with one message would be a rule six inputs happen
/// to trip rather than six checks.
#[test]
fn the_ledger_credits_only_the_payment_this_position_produces() {
    let channel = channel();
    let (authorization, result, certificate, binding) = payment_at(0, 1);

    CreditLedger::new()
        .credit_payment(
            &channel,
            &authorization,
            &result,
            &binding,
            &certificate,
            capacity(),
        )
        .expect("a legal payment");

    let elsewhere = Digest::from_bytes([0x7a; 32]);
    let bindings: Vec<(&str, PaymentBindingV1)> = vec![
        (
            "binding work_id",
            PaymentBindingV1 {
                work_id: elsewhere,
                ..binding
            },
        ),
        (
            "binding result_digest",
            PaymentBindingV1 {
                result_digest: elsewhere,
                ..binding
            },
        ),
        (
            "binding certificate_digest",
            PaymentBindingV1 {
                certificate_digest: hellas_kernel::PayloadHash::from_bytes([0x7b; 32]),
                ..binding
            },
        ),
    ];
    for (field, mutated) in bindings {
        assert_ne!(mutated, binding, "{field} is the one thing varied");
        assert_eq!(
            CreditLedger::new().credit_payment(
                &channel,
                &authorization,
                &result,
                &mutated,
                &certificate,
                capacity(),
            ),
            Err(PaidWorkError::Mismatch { field })
        );
    }

    let certificates: Vec<(&str, EarnedCertificate)> = vec![
        (
            "certificate earned_cumulative",
            EarnedCertificate::new(channel.payment_edge(), channel.payment_terms_hash(), 500),
        ),
        (
            "certificate payment_edge",
            EarnedCertificate::new(
                EdgeId::from_bytes([0; 32]),
                channel.payment_terms_hash(),
                250,
            ),
        ),
        (
            "certificate payment_terms_hash",
            EarnedCertificate::new(
                channel.payment_edge(),
                TermsHash::from_bytes([0x9c; 32]),
                250,
            ),
        ),
    ];
    for (field, mutated) in certificates {
        assert_ne!(mutated, certificate, "{field} is the one thing varied");
        // The binding is left alone, so it is the binding this ledger
        // position expects and the check in front passes. What refuses
        // each case is therefore the certificate's own field and not its
        // neighbour — which also covers the case the neighbour cannot
        // see: an offered certificate that is not the one the binding
        // names.
        assert_eq!(
            CreditLedger::new().credit_payment(
                &channel,
                &authorization,
                &result,
                &binding,
                &mutated,
                capacity(),
            ),
            Err(PaidWorkError::Mismatch { field })
        );
    }

    // MUTATION: a result for another job entirely. The binding and the
    // certificate are both rebuilt around it, so the refusal is the
    // result↔authorization rule rather than a stale digest.
    let (_, other_result, ..) = payment_at(0, 9);
    assert_ne!(other_result, result);
    let (other_certificate, other_binding) =
        next_payment(&channel, &authorization, &result, 0, capacity()).expect("a legal payment");
    assert_eq!(
        CreditLedger::new().credit_payment(
            &channel,
            &authorization,
            &other_result,
            &other_binding,
            &other_certificate,
            capacity(),
        ),
        Err(PaidWorkError::Mismatch { field: "work_id" })
    );
}

/// A payment is not portable between channels, and the binding's lack
/// of a channel field is not what makes it portable.
///
/// Two things scope a payment, and neither is a channel id inside the
/// binding. The certificate names an edge and a terms body, which the
/// ledger checks; and the binding is signed as a digest that binds the
/// network and the channel, so a client signature made on one channel
/// does not verify on another. Both are asserted, because a reader who
/// noticed only the missing field would conclude the wrong thing.
#[test]
fn a_payment_does_not_cross_channels() {
    let channel = channel();
    let sibling = channel_on(network(), EdgeId::from_bytes([0xe2; 32]));
    assert_ne!(channel.id(), sibling.id());

    let authorization = authorization();
    let result = job_result(work_id(&channel, &authorization));
    let (certificate, binding) =
        next_payment(&channel, &authorization, &result, 0, capacity()).expect("a legal payment");

    // MUTATION: the same job, paid on the sibling's edge. The binding is
    // the one this position expects, so the check in front of the
    // certificate passes and the edge check is what refuses it.
    let foreign = EarnedCertificate::new(
        sibling.payment_edge(),
        channel.payment_terms_hash(),
        certificate.earned_cumulative(),
    );
    assert_eq!(
        CreditLedger::new().credit_payment(
            &channel,
            &authorization,
            &result,
            &binding,
            &foreign,
            capacity(),
        ),
        Err(PaidWorkError::Mismatch {
            field: "certificate payment_edge"
        })
    );

    // And the binding digest is a different digest in the two channels,
    // so the client signature beside it does not travel either.
    let here = payment_binding_digest(&channel, &binding);
    let there = payment_binding_digest(&sibling, &binding);
    assert_ne!(here, there);
    let payload = hellas_kernel::PayloadHash::from_bytes(here.into_bytes());
    let signature = client().sign(payload);
    assert!(!Secp256k1Verifier.verify_sig(
        signature,
        channel.client_key(),
        hellas_kernel::PayloadHash::from_bytes(there.into_bytes()),
    ));
}

/// One payment continues the last one; it does not start wherever it
/// likes.
///
/// Three distinct jobs in order, and then a fourth that restates a
/// cumulative the ledger has already passed.
#[test]
fn a_payment_must_continue_the_credited_total() {
    let channel = channel();
    let mut ledger = CreditLedger::new();
    let mut credited = 0;
    for nonce in 0..3_u64 {
        let (authorization, result, certificate, binding) = payment_at(credited, nonce);
        ledger
            .credit_payment(
                &channel,
                &authorization,
                &result,
                &binding,
                &certificate,
                capacity(),
            )
            .expect("a legal payment");
        credited += 250;
        assert_eq!(ledger.credited_cumulative(), credited);
    }
    assert_eq!(credited, 750);

    // MUTATION: a fresh job whose payment was built at cumulative zero —
    // internally consistent, and a restatement of an amount this ledger
    // has already credited.
    let (authorization, result, certificate, binding) = payment_at(0, 7);
    assert_eq!(certificate.earned_cumulative(), 250);
    assert_eq!(
        ledger.credit_payment(
            &channel,
            &authorization,
            &result,
            &binding,
            &certificate,
            capacity(),
        ),
        Err(PaidWorkError::Mismatch {
            field: "certificate earned_cumulative"
        })
    );
    assert_eq!(ledger.credited_cumulative(), 750);

    // The control: the same job at this ledger's own position.
    let (authorization, result, certificate, binding) = payment_at(750, 7);
    ledger
        .credit_payment(
            &channel,
            &authorization,
            &result,
            &binding,
            &certificate,
            capacity(),
        )
        .expect("the position this ledger is at");
    assert_eq!(ledger.credited_cumulative(), 1_000);
}

/// The binding digest is what the client signs, and every field of the
/// binding is inside it.
#[test]
fn payment_binding_digest_binds_every_field() {
    let channel = channel();
    let (.., base) = payment_at(0, 1);
    let pinned = payment_binding_digest(&channel, &base);

    let mutations: Vec<(&str, PaymentBindingV1)> = vec![
        (
            "work_id",
            PaymentBindingV1 {
                work_id: Digest::from_bytes([0; 32]),
                ..base
            },
        ),
        (
            "result_digest",
            PaymentBindingV1 {
                result_digest: Digest::from_bytes([0; 32]),
                ..base
            },
        ),
        (
            "certificate_digest",
            PaymentBindingV1 {
                certificate_digest: hellas_kernel::PayloadHash::from_bytes([0; 32]),
                ..base
            },
        ),
    ];
    assert_eq!(mutations.len(), 3);
    for (field, mutated) in mutations {
        assert_ne!(
            payment_binding_digest(&channel, &mutated),
            pinned,
            "{field}"
        );
    }

    // The signature is over the digest, so a mutated binding is not the
    // one the client signed.
    let payload = hellas_kernel::PayloadHash::from_bytes(pinned.into_bytes());
    let signature = client().sign(payload);
    assert!(Secp256k1Verifier.verify_sig(signature, channel.client_key(), payload));
    let moved = PaymentBindingV1 {
        work_id: Digest::from_bytes([0x5f; 32]),
        ..base
    };
    let moved_payload = hellas_kernel::PayloadHash::from_bytes(
        payment_binding_digest(&channel, &moved).into_bytes(),
    );
    assert!(!Secp256k1Verifier.verify_sig(signature, channel.client_key(), moved_payload));
}

// ── Canonical output ──────────────────────────────────────────────────

/// The normalized answer ignores chunk boundaries and binds everything
/// the oracle compares.
#[test]
fn canonical_output_digest_normalizes_chunking() {
    let network = network();
    let id = work_id(&channel(), &authorization());
    let terminal = EvaluateTerminal {
        final_position: 4,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x60; 32]),
        usage: EvaluateUsage {
            input_units: 4,
            output_units: 4,
        },
        billable_units: 8,
    };
    let tokens = [11, 12, 13, 14];
    let digest = canonical_output_digest(network, id, &tokens, &terminal).expect("legal terminal");

    // MUTATION: reorder the tokens.
    assert_ne!(
        canonical_output_digest(network, id, &[11, 12, 14, 13], &terminal).expect("legal"),
        digest
    );

    // MUTATION: another stop reason.
    let mut stopped = terminal.clone();
    stopped.stop_reason = EvaluateStopReason::MAX_OUTPUT;
    stopped.matched_stop_token_id = None;
    assert_ne!(
        canonical_output_digest(network, id, &tokens, &stopped).expect("legal"),
        digest
    );

    // MUTATION: another selected stop token.
    let mut witness = terminal.clone();
    witness.matched_stop_token_id = Some(2);
    assert_ne!(
        canonical_output_digest(network, id, &tokens, &witness).expect("legal"),
        digest
    );

    // MUTATION: another text artifact.
    let mut artifact = terminal.clone();
    artifact.text_artifact = Digest::from_bytes([0x61; 32]);
    assert_ne!(
        canonical_output_digest(network, id, &tokens, &artifact).expect("legal"),
        digest
    );

    // MUTATION: usage that does not describe the token list.
    let mut usage = terminal.clone();
    usage.usage.output_units = 3;
    assert_eq!(
        canonical_output_digest(network, id, &tokens, &usage),
        Err(PaidWorkError::Mismatch {
            field: "output token count"
        })
    );

    // MUTATION: a billable total that is not the sum.
    let mut billable = terminal.clone();
    billable.billable_units = 9;
    assert_eq!(
        canonical_output_digest(network, id, &tokens, &billable),
        Err(PaidWorkError::Mismatch {
            field: "billable units"
        })
    );

    // The same answer for another job is another digest.
    assert_ne!(
        canonical_output_digest(network, Digest::from_bytes([0; 32]), &tokens, &terminal)
            .expect("legal"),
        digest
    );
}

// ── Independent preimage reproduction ─────────────────────────────────

/// Rebuilds three complete preimages by hand and hashes them through the
/// crate's *other* hashing entry point.
///
/// [`Digest::hash`] chunks its input and takes a Merkle file hash;
/// `work.rs` streams into the allocation-free single-chunk hasher. If the
/// domain, the network's length prefix, the channel argument, or the
/// envelope-plus-body order in this file disagreed with the module's, the
/// two would not meet here. The first two preimages were also hashed
/// outside this workspace with `b3sum --keyed`, twice: once under the Xet
/// DATA key and once under the zero key. The third — the payment binding,
/// which this profile added — was not; its pinned value is this
/// workspace's own, and what it catches is a later change to the layout
/// rather than a disagreement with an outside implementation.
#[test]
fn digest_preimages_are_reproducible_by_hand() {
    let channel = channel();

    let mut preimage = b"hellas.work.channel.v2".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.payment_edge().as_bytes());
    preimage.extend_from_slice(channel.payment_terms_hash().as_bytes());
    preimage.extend_from_slice(payment_terms().bond_edge.as_bytes());
    preimage.extend_from_slice(payment_terms().bond_terms_hash().as_bytes());
    assert_eq!(Digest::hash(&preimage), channel.id());
    assert_eq!(preimage.len(), 22 + 16 + 128);

    let result = job_result(work_id(&channel, &authorization()));
    let mut preimage = b"hellas.work.paid-job-result.v1".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.id().as_bytes());
    preimage.push(1);
    preimage.push(3);
    preimage.extend_from_slice(result.work_id.as_bytes());
    preimage.extend_from_slice(result.terminal_transcript_commitment.as_bytes());
    preimage.extend_from_slice(result.canonical_output_digest.as_bytes());
    assert_eq!(Digest::hash(&preimage), result_digest(&channel, &result));
    assert_eq!(preimage.len(), 30 + 16 + 32 + 98);
    assert_eq!(
        hex(&Digest::hash(&preimage).into_bytes()),
        "7af77e5376b3f26a934861afd93c3a4bfe1cdcffd4a642d9bc2f22a55823f196"
    );

    // The payment binding, whose three fields are all 32 bytes: a round
    // trip agrees with any permutation of them, and this does not.
    let binding = PaymentBindingV1 {
        work_id: Digest::from_bytes([0xa1; 32]),
        result_digest: Digest::from_bytes([0xa2; 32]),
        certificate_digest: hellas_kernel::PayloadHash::from_bytes([0xd0; 32]),
    };
    let mut preimage = b"hellas.work.payment-binding.v1".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.id().as_bytes());
    preimage.push(1);
    preimage.push(4);
    preimage.extend_from_slice(&[0xa1; 32]);
    preimage.extend_from_slice(&[0xa2; 32]);
    preimage.extend_from_slice(&[0xd0; 32]);
    assert_eq!(preimage.len(), 30 + 16 + 32 + 98);
    assert_eq!(
        Digest::hash(&preimage),
        payment_binding_digest(&channel, &binding)
    );
    assert_eq!(
        hex(&payment_binding_digest(&channel, &binding).into_bytes()),
        "5a4a09be82eeeb121ca16ce6cefa64a8318af45d37c522c9141eaff96851940b"
    );
}

/// Rebuilds the normalized answer's preimage by hand, field by field.
///
/// The one digest in this module whose exact layout is fixed outside it:
/// the client's independent oracle recomputes this from its own
/// reexecution, so an implementation that agreed with `work.rs` and with
/// nothing else would be a check the two halves of a payment could pass
/// while meaning different things. Round-tripping cannot catch a
/// transposed pair of same-width fields — `final_position` beside
/// `input_units`, or the three usage counts among themselves — and this
/// does.
#[test]
fn the_canonical_output_preimage_is_reproducible_by_hand() {
    let id = work_id(&channel(), &authorization());
    let tokens: [u32; 3] = [7, 0, 0x0001_0203];
    let terminal = EvaluateTerminal {
        final_position: 3,
        stop_reason: EvaluateStopReason::MAX_OUTPUT,
        matched_stop_token_id: None,
        text_artifact: Digest::from_bytes([0x60; 32]),
        usage: EvaluateUsage {
            input_units: 5,
            output_units: 3,
        },
        billable_units: 8,
    };

    let mut preimage = b"hellas.work.evaluate-output.v2".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(id.as_bytes());
    preimage.extend_from_slice(&3_u64.to_be_bytes());
    preimage.extend_from_slice(&7_u32.to_be_bytes());
    preimage.extend_from_slice(&0_u32.to_be_bytes());
    preimage.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    preimage.extend_from_slice(&3_u64.to_be_bytes());
    preimage.push(2);
    preimage.push(0);
    preimage.extend_from_slice(&[0x60; 32]);
    preimage.extend_from_slice(&5_u64.to_be_bytes());
    preimage.extend_from_slice(&3_u64.to_be_bytes());
    preimage.extend_from_slice(&8_u64.to_be_bytes());
    // 30 domain, 16 network, 32 work id, 8 count, 12 tokens, 8 position,
    // 1 stop reason, 1 absent-witness marker, 32 artifact, 24 usage.
    assert_eq!(preimage.len(), 30 + 16 + 32 + 8 + 12 + 8 + 1 + 1 + 32 + 24);

    assert_eq!(
        Digest::hash(&preimage),
        canonical_output_digest(network(), id, &tokens, &terminal).expect("legal terminal"),
    );
    assert_eq!(
        hex(&Digest::hash(&preimage).into_bytes()),
        "83aa7b2b6e7f992893b308cf934e258540f9443dca657cd41102249870f7e027"
    );
}

// ── Carrying a transcript ─────────────────────────────────────────────

/// One signed transcript, for a request nothing else here uses.
fn spool_transcript() -> Vec<hellas_rpc::OutputEventEnvelope> {
    let Ok(key) = hellas_rpc::ProducerSigningKey::from_secret_bytes([0x42; 32]) else {
        panic!("a fixed scalar is a producer key");
    };
    let request = evaluate_request();
    let mut builder = hellas_rpc::evaluate::EvaluateOutputTranscriptBuilder::new(
        hellas_rpc::evaluate::input_commitment(&request),
        request.assurance,
        &key,
    );
    if let Err(error) = builder.push_token_delta(vec![5, 6, 7]) {
        panic!("a non-empty delta pushes: {error}");
    }
    let usage = EvaluateUsage {
        input_units: 4,
        output_units: 3,
    };
    match builder.finish(EvaluateTerminal {
        final_position: 3,
        stop_reason: EvaluateStopReason::STOP_TOKEN,
        matched_stop_token_id: Some(1),
        text_artifact: Digest::from_bytes([0x77; 32]),
        usage,
        billable_units: 7,
    }) {
        Ok(events) => events,
        Err(error) => panic!("the fixture transcript finishes: {error}"),
    }
}

/// A spooled transcript comes back as the events that were spooled.
///
/// Nothing in the protocol hashes these bytes, so what this pins is the
/// round trip and the budget — not a layout. The pairing that gives the
/// bytes their meaning is
/// `work_store::ChannelState`'s rebuild, and it is tested there.
#[test]
fn a_spooled_transcript_decodes_to_the_events_that_were_spooled() {
    let transcript = spool_transcript();
    let Ok(bytes) = encode_transcript(&transcript) else {
        panic!("the fixture transcript encodes");
    };
    assert_eq!(decode_transcript(&bytes, bytes.len()), Ok(transcript));

    // MUTATION: one byte short of what the bytes need.
    assert_eq!(
        decode_transcript(&bytes, bytes.len() - 1),
        Err(PaidWorkError::OverEnvelope {
            field: "transcript length",
            actual: bytes.len() as u64,
            limit: bytes.len() as u64 - 1,
        }),
    );

    // MUTATION: bytes that are not a transcript at all, inside budget.
    let refused = decode_transcript(b"not a transcript", 1 << 20);
    assert!(
        matches!(refused, Err(PaidWorkError::Transcript(_))),
        "unexpected answer: {refused:?}",
    );

    // An empty transcript is a legal encoding and an illegal result:
    // this codec carries events, and `terminal_result` is what refuses
    // a transcript that is not one job's terminal chain.
    let Ok(empty) = encode_transcript(&[]) else {
        panic!("an empty transcript encodes");
    };
    assert_eq!(decode_transcript(&empty, 1 << 20), Ok(Vec::new()));
}

// ── What one finished execution produced ──────────────────────────────

/// Hand-builds the three canonical bodies a finished execution derives,
/// and pins the artifact id they add up to.
///
/// This is the derivation two implementations depend on and neither
/// owns: the provider stores these bodies and signs the artifact id
/// inside its terminal event, and the client's oracle rebuilds the id
/// from the same inputs with no store at all. Sharing the code makes
/// them agree; this is what says what they agree *on*, in bytes rather
/// than by calling the function twice.
#[test]
fn the_completed_output_derivation_is_reproducible_by_hand() {
    const TOKEN_IDS_SCHEMA: &str = "hellas.evaluate.token_ids.v1";
    const TEXT_STATE_SCHEMA: &str = "hellas.evaluate.text.state.v1";
    const TEXT_ARTIFACT_OUTPUT_SCHEMA: &str = "hellas.evaluate.text.artifact.output.v1";

    let execution = TextExecutionId::from_bytes([0x41; 32]);
    let input_ids = [9_u32, 8, 7, 6];
    let output_tokens = [101_u32, 102, 103];
    let completed = completed_text(execution, &input_ids, &output_tokens);

    // DAG-CBOR by hand. A text head is `0x60 | len` below 24 and
    // `0x78, len` up to 255; a byte head for 32 bytes is `0x58, 32`;
    // an integer is its own value below 24 and `0x18, value` up to 255.
    fn text(out: &mut Vec<u8>, value: &str) {
        assert!(value.len() < 256, "the fixture schemas are short");
        if value.len() < 24 {
            out.push(0x60 | value.len() as u8);
        } else {
            out.push(0x78);
            out.push(value.len() as u8);
        }
        out.extend_from_slice(value.as_bytes());
    }
    fn integer(out: &mut Vec<u8>, value: u32) {
        assert!(value < 256, "the fixture values fit one byte");
        if value < 24 {
            out.push(value as u8);
        } else {
            out.push(0x18);
            out.push(value as u8);
        }
    }
    fn digest32(out: &mut Vec<u8>, bytes: &[u8; 32]) {
        out.extend_from_slice(&[0x58, 32]);
        out.extend_from_slice(bytes);
    }

    // `[schema, [tokens...]]`
    let token_ids_bytes = |tokens: &[u32]| {
        let mut out = vec![0x82];
        text(&mut out, TOKEN_IDS_SCHEMA);
        out.push(0x80 | tokens.len() as u8);
        for token in tokens {
            integer(&mut out, *token);
        }
        out
    };

    let generated = token_ids_bytes(&output_tokens);
    assert_eq!(completed.generated_tokens.canonical_bytes(), generated);
    let state_tokens = token_ids_bytes(&[9, 8, 7, 6, 101, 102, 103]);
    assert_eq!(completed.state_tokens.canonical_bytes(), state_tokens);

    // `[schema, tokens_id]`
    let mut state = vec![0x82];
    text(&mut state, TEXT_STATE_SCHEMA);
    digest32(&mut state, Digest::hash(&state_tokens).as_bytes());
    assert_eq!(completed.state.canonical_bytes(), state);

    // `[schema, execution, position, state_id, generated_id]`
    let mut artifact = vec![0x85];
    text(&mut artifact, TEXT_ARTIFACT_OUTPUT_SCHEMA);
    digest32(&mut artifact, execution.as_bytes());
    integer(&mut artifact, output_tokens.len() as u32);
    digest32(&mut artifact, Digest::hash(&state).as_bytes());
    digest32(&mut artifact, Digest::hash(&generated).as_bytes());
    assert_eq!(completed.artifact.canonical_bytes(), artifact);

    assert_eq!(
        hex(completed.artifact.output_id().as_bytes()),
        "47e767f99550bbafc883a2a3968ecdee60288b47e002038a15898d2e2e34f4d8"
    );

    // The control: one more input token is a different state and a
    // different artifact, though the generated tokens are the same.
    let longer = completed_text(execution, &[9, 8, 7, 6, 5], &output_tokens);
    assert_eq!(longer.generated_tokens, completed.generated_tokens);
    assert_ne!(longer.artifact, completed.artifact);
}
