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

use hellas_auth::Digest;
use hellas_channel::job::{
    check_authorization, check_paid_input as check_prepared_input, prepared_input_digest,
};
use hellas_channel::test_support::channel as fixture;
use hellas_channel::{
    job,
    model::work::{
        CreditLedger, JobDeadlines, JobPaymentPolicyV2, PaidChannel, PaidChannelPolicyV1,
        PaidJobAuthorizationV2, PaidJobResultV1, PaidWorkError, PaymentBindingV1, PrivateRecord,
        ResultOutcome, check_payment_policy_binding, check_result, decode_transcript,
        encode_transcript, next_payment, payment_binding_digest, private_policy_commitment,
        result_digest, work_id,
    },
};
use hellas_kernel::{
    BlockHeight, EarnedCertificate, EdgeId, EdgeValues, Fees, List, NetworkId, Parties, PartyKeys,
    Payout, Secp256k1Signer, Secp256k1Verifier, SigVerifier, TermsHash, WorkPaymentSettlement,
    WorkPaymentTerms, WorkStakeBondTerms, work_payment_settlement,
};
use hellas_rpc::{
    ContentId, ContentRef, EventCommitment, RequestCommitment, Retention,
    protocol::invocation::{InvocationPolicy, PreparedInvocation},
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The three fallible digests over variable-length bodies, unwrapped.
///
/// Every fixture body here is a few hundred bytes, so the only error
/// these can return — a body too long for its `u32` length prefix — is
/// noise at each of their sixteen call sites.
fn input_digest(channel: &PaidChannel, bundle: &PreparedInvocation) -> Digest {
    prepared_input_digest(channel, bundle).expect("a representable bundle")
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
        parties: Parties::new(
            PartyKeys::sole(provider().party_key()),
            PartyKeys::sole(client().party_key()),
        ),
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

fn bundle() -> PreparedInvocation {
    let mut input = fixture::bundle(0x77);
    input.request.runner_public_key =
        hellas_auth::PublicKey::Secp256k1(provider().party_key().to_bytes());
    input
}
fn work_policy() -> InvocationPolicy {
    fixture::work_policy()
}
fn work_policy_digest(channel: &PaidChannel, policy: &InvocationPolicy) -> Digest {
    job::policy_digest(channel.network(), channel.id(), policy).unwrap()
}
fn authorization() -> PaidJobAuthorizationV2 {
    job::propose(
        &channel(),
        &work_policy(),
        &payment_policy(),
        &bundle(),
        0x0102_0304_0506_0708,
        JobDeadlines {
            acceptance: 1000,
            terminal: 1050,
            payment: 1100,
        },
    )
    .unwrap()
}
fn job_result(work_id: Digest) -> PaidJobResultV1 {
    PaidJobResultV1 {
        work_id,
        terminal_transcript_commitment: EventCommitment::from_digest(Digest::from_bytes(
            [0x31; 32],
        )),
        canonical_output_digest: Digest::from_bytes([0x32; 32]),
        outcome: ResultOutcome::Finished,
        transcript_content: ContentRef::new(ContentId::from_bytes([0x35; 32]), 0x0102030405060708),
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
    assert_eq!(PaidJobAuthorizationV2::BODY_SIZE, 273);
    assert_eq!(PaidJobAuthorizationV2::ENCODED_SIZE, 275);
    assert_eq!(PaidJobResultV1::BODY_SIZE, 137);
    assert_eq!(PaidJobResultV1::ENCODED_SIZE, 139);
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
            "00", // finished
            "3535353535353535353535353535353535353535353535353535353535353535", // transcript object
            "0102030405060708", // transcript bytes
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

    let authorization = PaidJobAuthorizationV2 {
        channel_id: Digest::from_bytes([0x50; 32]),
        work_policy_digest: Digest::from_bytes([0x55; 32]),
        payment_policy_digest: Digest::from_bytes([0x59; 32]),
        input_content: hellas_rpc::ContentRef::new(ContentId::from_bytes([0x5a; 32]), 123),
        prepared_input_digest: Digest::from_bytes([0x56; 32]),
        proposal_nonce: 1,
        acceptance_deadline: 2,
        request_commitment: RequestCommitment::from_digest(Digest::from_bytes([0x57; 32])),
        environment_commitment: ContentId::from_bytes([0x58; 32]),
        price: 3,
        terminal_deadline: 4,
        payment_deadline: 5,
        retention: Retention::Retain,
    };
    assert_eq!(
        hex(&authorization.encode()),
        concat!(
            "01",
            "09", // format version 1, tag 9 = PAID_JOB_AUTHORIZATION_V2
            "5050505050505050505050505050505050505050505050505050505050505050", // channel_id
            "5555555555555555555555555555555555555555555555555555555555555555", // policy digest
            "5959595959595959595959595959595959595959595959595959595959595959", // payment policy
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", // input content id
            "000000000000007b", // input content bytes
            "5656565656565656565656565656565656565656565656565656565656565656", // prepared input
            "0000000000000001", // proposal_nonce
            "0000000000000002", // acceptance_deadline
            "5757575757575757575757575757575757575757575757575757575757575757", // request
            "5858585858585858585858585858585858585858585858585858585858585858", // environment
            "0000000000000003", // price
            "0000000000000004", // terminal_deadline
            "0000000000000005", // payment_deadline
            "01", // retained content
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
    assert_eq!(bytes.len(), PaidJobAuthorizationV2::ENCODED_SIZE);
    assert_eq!(PaidJobAuthorizationV2::decode(&bytes), Ok(authorization));
    // The five `u64`s, all `ff`, at the offsets the layout puts them.
    assert_eq!(hex(&bytes[170..186]), "ffffffffffffffffffffffffffffffff");
    assert_eq!(
        hex(&bytes[250..274]),
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
            expected: 139,
            actual: 138
        })
    );

    // MUTATION: one byte long.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PaidJobResultV1::decode(&trailing),
        Err(PaidWorkError::RecordLength {
            expected: 139,
            actual: 140
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
        PaidChannelPolicyV1::ENCODED_SIZE,
        PaidJobAuthorizationV2::ENCODED_SIZE,
        PaidJobResultV1::ENCODED_SIZE,
        PaymentBindingV1::ENCODED_SIZE,
    ];
    for (i, size) in sizes.iter().enumerate() {
        for other in &sizes[i + 1..] {
            assert_ne!(size, other);
        }
    }
    let mut result = job_result(Digest::from_bytes([0x30; 32])).encode();
    assert!(PaymentBindingV1::decode(&result).is_err());
    result[1] = 4;
    assert!(PaymentBindingV1::decode(&result).is_err());
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
        "a5f19693d012ce8a1b6aa6094ecc34e9bbe005587825bc4e193a484f0ab60251"
    );
    assert_eq!(
        hex(&work_id(&channel, &authorization()).into_bytes()),
        "383a70f2e0c87e6b9e709091e6aacfc6fa3165e8a45a8be8024e8e3eaf24ca15"
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
        "eb36293e12b4cd91c64c361051d23af77f51734fab4085f215be10af3c8d98c0"
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
            work_policy_digest(&here, &work_policy()),
            work_policy_digest(other, &work_policy()),
            "{label} shares this channel's policy digest"
        );
        assert_ne!(
            input_digest(&here, &bundle()),
            input_digest(other, &bundle()),
            "{label} shares this channel's prepared input digest"
        );
        // MUTATION: replay this channel's authorization on another one.
        assert_eq!(
            check_authorization(
                other,
                &authorization,
                &work_policy(),
                &payment_policy(),
                900
            ),
            Err(PaidWorkError::Mismatch {
                field: "channel_id"
            }),
            "{label} accepted a foreign authorization"
        );
    }
}

// ── Prepared input bundle ─────────────────────────────────────────────

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

// ── Authorization ─────────────────────────────────────────────────────

/// The happy path: both parties check the same authorization against
/// their own terms and sign the same digest.
#[test]
fn both_parties_sign_one_authorization_digest() {
    let channel = channel();
    let authorization = authorization();
    let work_id = check_authorization(
        &channel,
        &authorization,
        &work_policy(),
        &payment_policy(),
        900,
    )
    .expect("a legal authorization");
    check_prepared_input(&channel, &authorization, &work_policy(), &bundle())
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
    authorization: &PaidJobAuthorizationV2,
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

    let mutations: Vec<(&str, PaidJobAuthorizationV2)> = vec![
        ("channel_id", {
            let mut m = base;
            m.channel_id = Digest::from_bytes([0; 32]);
            m
        }),
        ("work_policy_digest", {
            let mut m = base;
            m.work_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("payment_policy_digest", {
            let mut m = base;
            m.payment_policy_digest = Digest::from_bytes([0; 32]);
            m
        }),
        ("input_content.id", {
            let mut m = base;
            m.input_content = hellas_rpc::ContentRef::new(
                ContentId::from_bytes([0; 32]),
                base.input_content.bytes(),
            );
            m
        }),
        ("input_content.bytes", {
            let mut m = base;
            m.input_content = hellas_rpc::ContentRef::new(
                base.input_content.id(),
                base.input_content.bytes() + 1,
            );
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
        ("retention", {
            let mut m = base;
            m.retention = Retention::Ephemeral;
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
    let policy = work_policy();
    let base = authorization();
    assert!(check_authorization(&channel, &base, &policy, &payment_policy(), 900).is_ok());

    // MUTATION: a free job.
    let mut zero_price = base;
    zero_price.price = 0;
    let mut zero_policy = payment_policy();
    zero_policy.fixed_price = 0;
    zero_price.payment_policy_digest = hellas_channel::model::work::job_payment_policy_digest(
        channel.network(),
        channel.id(),
        &zero_policy,
    );
    assert_eq!(
        check_authorization(&channel, &zero_price, &work_policy(), &zero_policy, 900),
        Err(PaidWorkError::PolicyZero {
            field: "fixed_price"
        })
    );

    // MUTATION: a price the bond does not cover.
    let mut over_bond = base;
    over_bond.price = 501;
    let mut over_policy = payment_policy();
    over_policy.fixed_price = 501;
    over_bond.payment_policy_digest = hellas_channel::model::work::job_payment_policy_digest(
        channel.network(),
        channel.id(),
        &over_policy,
    );
    assert_eq!(
        check_authorization(&channel, &over_bond, &work_policy(), &over_policy, 900),
        Err(PaidWorkError::PriceOutOfRange {
            price: 501,
            max_job_price: 500
        })
    );

    // MUTATION: a price that disagrees with the signed policy.
    let mut mispriced = base;
    mispriced.price = 249;
    assert_eq!(
        check_authorization(&channel, &mispriced, &policy, &payment_policy(), 900),
        Err(PaidWorkError::Mismatch { field: "price" })
    );

    // MUTATION: signing after the acceptance window closed.
    assert_eq!(
        check_authorization(&channel, &base, &policy, &payment_policy(), 1_001),
        Err(PaidWorkError::AcceptanceExpired {
            height: 1_001,
            deadline: 1_000
        })
    );

    // MUTATION: a payment deadline past the channel's admission horizon.
    let mut late = base;
    late.payment_deadline = 5_000;
    assert_eq!(
        check_authorization(&channel, &late, &policy, &payment_policy(), 900),
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
        check_authorization(&channel, &inverted, &policy, &payment_policy(), 900),
        Err(PaidWorkError::DeadlineOrder { .. })
    ));
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
    let policy = work_policy();
    let base = authorization();
    assert!(check_authorization(&channel(), &base, &policy, &payment_policy(), 900).is_ok());

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

    let mut dear = payment_policy();
    dear.fixed_price = 500;
    let mut authorization = authorization();
    authorization.channel_id = channel.id();
    authorization.price = 500;
    authorization.payment_policy_digest = hellas_channel::model::work::job_payment_policy_digest(
        channel.network(),
        channel.id(),
        &dear,
    );
    authorization.work_policy_digest = work_policy_digest(&channel, &work_policy());
    authorization.input_content =
        hellas_rpc::ContentRef::for_bytes(&bundle().canonical_bytes().unwrap());
    authorization.prepared_input_digest = input_digest(&channel, &bundle());

    assert_eq!(
        check_authorization(&channel, &authorization, &work_policy(), &dear, 900),
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
    authorization.channel_id = channel.id();
    authorization.payment_policy_digest = hellas_channel::model::work::job_payment_policy_digest(
        channel.network(),
        channel.id(),
        &dear,
    );
    authorization.work_policy_digest = work_policy_digest(&channel, &work_policy());
    assert_eq!(
        check_authorization(&channel, &authorization, &work_policy(), &dear, 900),
        Err(PaidWorkError::OverEnvelope {
            field: "price against delivery_credit_limit",
            actual: 500,
            limit: 499
        })
    );
}

// ── Prepared input graph ──────────────────────────────────────────────

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
    PaidJobAuthorizationV2,
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
    preimage.push(0);
    preimage.extend_from_slice(result.transcript_content.id().as_bytes());
    preimage.extend_from_slice(&result.transcript_content.bytes().to_be_bytes());
    assert_eq!(Digest::hash(&preimage), result_digest(&channel, &result));
    assert_eq!(preimage.len(), 30 + 16 + 32 + 139);
    assert_eq!(
        hex(&Digest::hash(&preimage).into_bytes()),
        "cb3111b193c16e52f54d851f9f7eafbb873413de95b5e4e0bb925b29abe93328"
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
        "715c9a47cd79490b150f871960e472254962b87c28d3b0fdb65edfa11fc06531"
    );
}

// ── Carrying a transcript ─────────────────────────────────────────────

/// One signed transcript, for a request nothing else here uses.
fn spool_transcript() -> Vec<hellas_rpc::OutputEventEnvelope> {
    fixture::transcript_for(&fixture::invocation_request(1), &[5, 6, 7])
}

/// A spooled transcript comes back as the events that were spooled.
///
/// Nothing in the protocol hashes these bytes, so what this pins is the
/// round trip and the budget — not a layout. The pairing that gives the
/// bytes their meaning is
/// `work_store::Channel`'s rebuild, and it is tested there.
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

fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
    hellas_channel::model::work::JobPaymentPolicyV2 {
        fixed_price: 250,
        dispatch_margin_blocks: 20,
        delivery_margin_blocks: 10,
        oracle_grace_blocks: 30,
    }
}

#[test]
fn every_payment_term_is_committed_and_checked_separately() {
    let channel = channel();
    let policy = work_policy();
    let base = payment_policy();
    let authorization = authorization();
    let mutations = [
        JobPaymentPolicyV2 {
            fixed_price: base.fixed_price + 1,
            ..base
        },
        JobPaymentPolicyV2 {
            dispatch_margin_blocks: base.dispatch_margin_blocks + 1,
            ..base
        },
        JobPaymentPolicyV2 {
            delivery_margin_blocks: base.delivery_margin_blocks + 1,
            ..base
        },
        JobPaymentPolicyV2 {
            oracle_grace_blocks: base.oracle_grace_blocks + 1,
            ..base
        },
    ];
    for changed in mutations {
        assert_eq!(
            check_authorization(&channel, &authorization, &policy, &changed, 900),
            Err(PaidWorkError::Mismatch {
                field: "payment_policy_digest"
            })
        );
        assert_eq!(
            check_payment_policy_binding(&channel, &authorization, &changed),
            Err(PaidWorkError::Mismatch {
                field: "payment_policy_digest"
            })
        );
    }
    // Recovery after the acceptance deadline checks the retained terms only.
    assert_eq!(
        check_payment_policy_binding(&channel, &authorization, &base),
        Ok(())
    );
}
