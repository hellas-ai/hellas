//! Fixed V2 encodings assembled field-by-field before caller migration.
use hellas_auth::Digest;
use hellas_auth::authority::{GrantId, NodeKey, PrincipalId, ResourceId, Revision, UnixMillis};
use hellas_kernel::{EdgeId, NetworkId, TermsHash};
use hellas_rpc::{ContentId, RequestCommitment};
use hellas_work::model::fetch::{FetchPolicyV2, fetch_policy_v2_digest};
use hellas_work::model::grant::*;
use hellas_work::model::work::{
    EvaluatePolicyV2, JobPaymentPolicyV2, PaidJobAuthorizationV2, PrivateRecord,
    evaluate_policy_v2_digest, job_payment_policy_digest, paid_work_v2_id,
};
fn network() -> NetworkId {
    NetworkId::new("funding-v2").unwrap()
}
fn channel() -> Digest {
    Digest::from_bytes([0xaa; 32])
}
fn d(n: u8) -> Digest {
    Digest::from_bytes([n; 32])
}
fn c(n: u8) -> ContentId {
    ContentId::from_bytes([n; 32])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
const EVALUATE: &str = "01060101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030102030405060708090a11121314151617182122232431323334";
const FETCH: &str = "01070101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020201020304050607081112131421222324252627283132333441424344";
const PAYMENT: &str = "01080102030405060708111213141516171821222324252627283132333435363738";
const PAID: &str = "0109010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080102030405060708111213141516171809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a212223242526272831323334353637384142434445464748";
const GRANT: &str = "010a01010101010101010101010101010101010101010101010101010101010101010f0f0f0f0f0f0f0f0202020202020202020202020202020203030303030303030d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d04040404040404040e0e0e0e0e0e0e0e050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060707070707070707080808080808080809090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c";

fn evaluate() -> EvaluatePolicyV2 {
    EvaluatePolicyV2 {
        allowed_environment: c(1),
        generation_policy_digest: d(2),
        identity_source_digest: d(3),
        max_prompt_tokens: 0x01020304,
        max_new_tokens: 0x05060708,
        max_stop_token_ids: 0x090a,
        max_spool_bytes: 0x1112131415161718,
        max_encoded_result_frame: 0x21222324,
        max_encoded_prepared_input: 0x31323334,
        max_upload_bytes: 0x31323334,
    }
}
fn fetch() -> FetchPolicyV2 {
    FetchPolicyV2 {
        allowed_environment: c(1),
        route_commitment: d(2),
        max_request_body_bytes: 0x01020304,
        max_output_events: 0x05060708,
        max_output_bytes: 0x11121314,
        max_spool_bytes: 0x2122232425262728,
        max_encoded_result_frame: 0x31323334,
        max_encoded_prepared_input: 0x41424344,
        max_upload_bytes: 0x41424344,
    }
}
fn payment() -> JobPaymentPolicyV2 {
    JobPaymentPolicyV2 {
        fixed_price: 0x0102030405060708,
        dispatch_margin_blocks: 0x1112131415161718,
        delivery_margin_blocks: 0x2122232425262728,
        oracle_grace_blocks: 0x3132333435363738,
    }
}
fn paid() -> PaidJobAuthorizationV2 {
    PaidJobAuthorizationV2 {
        channel_id: d(1),
        bond_edge: EdgeId::from_bytes([2; 32]),
        bond_terms_hash: TermsHash::from_bytes([3; 32]),
        payment_edge: EdgeId::from_bytes([4; 32]),
        payment_terms_hash: TermsHash::from_bytes([5; 32]),
        work_policy_digest: d(6),
        payment_policy_digest: d(7),
        prepared_input_digest: d(8),
        proposal_nonce: 0x0102030405060708,
        acceptance_deadline: 0x1112131415161718,
        request_commitment: RequestCommitment::from_digest(d(9)),
        environment_commitment: c(10),
        price: 0x2122232425262728,
        terminal_deadline: 0x3132333435363738,
        payment_deadline: 0x4142434445464748,
    }
}
fn grant() -> GrantJobAuthorizationV1 {
    GrantJobAuthorizationV1 {
        channel_id: ChannelId(d(1)),
        generation: 0x0f0f0f0f0f0f0f0f,
        grant_id: GrantId([2; 16]),
        grant_revision: Revision(0x0303030303030303),
        resource_id: ResourceId(d(13)),
        resource_revision: Revision(0x0404040404040404),
        pricing_revision: Revision(0x0e0e0e0e0e0e0e0e),
        work_policy_digest: d(5),
        prepared_input_digest: d(6),
        proposal_nonce: 0x0707070707070707,
        acceptance_deadline_ms: UnixMillis(0x0808080808080808),
        request_commitment: RequestCommitment::from_digest(d(9)),
        environment_commitment: c(10),
        terminal_deadline_ms: UnixMillis(0x0b0b0b0b0b0b0b0b),
        delivery_deadline_ms: UnixMillis(0x0c0c0c0c0c0c0c0c),
    }
}
fn record<R: PrivateRecord + std::fmt::Debug + PartialEq>(value: R, expected: &str, length: usize) {
    let golden = bytes(expected);
    assert_eq!(R::ENCODED_SIZE, length);
    assert_eq!(value.encode(), golden);
    assert_eq!(R::decode(&golden).unwrap(), value);
    for tag in 0..=255 {
        if tag == R::TAG {
            continue;
        }
        let mut wrong = golden.clone();
        wrong[1] = tag;
        assert!(R::decode(&wrong).is_err(), "accepted tag {tag}");
    }
    let mut extra = golden.clone();
    extra.push(0);
    assert!(R::decode(&extra).is_err());
    for length in 0..golden.len() {
        assert!(R::decode(&golden[..length]).is_err());
    }
    let mut version = golden;
    version[0] = 2;
    assert!(R::decode(&version).is_err());
}
#[test]
fn record_bytes_and_all_envelopes_are_pinned() {
    record(evaluate(), EVALUATE, 124);
    record(fetch(), FETCH, 94);
    record(payment(), PAYMENT, 34);
    record(paid(), PAID, 362);
    record(grant(), GRANT, 274);
}
// A frozen V1 envelope/width contract, not a production compatibility decoder.
// These predicates are necessary for every old decoder to accept any body.
fn legacy_accepts(tag: u8, size: usize, bytes: &[u8]) -> bool {
    bytes.len() == size && bytes[..2] == [1, tag]
}
#[test]
fn v1_and_v2_records_cannot_be_substituted_even_at_matching_lengths() {
    for (new, old_tag, old_size) in [
        (bytes(EVALUATE), 1, 156),
        (bytes(FETCH), 5, 126),
        (bytes(PAID), 2, 330),
    ] {
        assert!(!legacy_accepts(old_tag, old_size, &new));
        let mut padded = new.clone();
        padded.resize(old_size, 0);
        assert!(!legacy_accepts(old_tag, old_size, &padded));
        let mut old = padded;
        old[1] = old_tag;
        assert!(legacy_accepts(old_tag, old_size, &old));
        assert!(EvaluatePolicyV2::decode(&old).is_err());
        assert!(FetchPolicyV2::decode(&old).is_err());
        assert!(PaidJobAuthorizationV2::decode(&old).is_err());
    }
}
#[test]
fn independent_preimages_match_the_versioned_digest_domains() {
    let cases = [
        (
            "evaluate",
            "hellas.work.evaluate-policy.v2",
            EVALUATE,
            channel(),
            evaluate_policy_v2_digest(network(), channel(), &evaluate()),
        ),
        (
            "fetch",
            "hellas.work.fetch-policy.v2",
            FETCH,
            channel(),
            fetch_policy_v2_digest(network(), channel(), &fetch()),
        ),
        (
            "payment",
            "hellas.work.job-payment-policy.v2",
            PAYMENT,
            channel(),
            job_payment_policy_digest(network(), channel(), &payment()),
        ),
        (
            "paid",
            "hellas.work.paid-job-authorize.v2",
            PAID,
            channel(),
            paid_work_v2_id(network(), channel(), &paid()),
        ),
        (
            "grant",
            "hellas.work.grant-job-authorize.v1",
            GRANT,
            d(1),
            grant_work_id(network(), &grant()),
        ),
    ];
    for (name, domain, encoded, channel, actual) in cases {
        // Assemble without any production record encoder, network encoder or digest helper.
        let mut preimage = domain.as_bytes().to_vec();
        preimage.extend_from_slice(b"\x0afunding-v2");
        preimage.extend_from_slice(channel.as_bytes());
        preimage.extend_from_slice(&bytes(encoded));
        let expected = hellas_xet::XetHash::hash(&preimage);
        assert_eq!(actual.as_bytes(), expected.as_bytes());
        let golden = match name {
            "evaluate" => "8a5b986a498fbeb06bd9e39a75c553f8313b9959aa61c6ab7fdd88bf3a9d134d",
            "fetch" => "765620e321317fb009f643a048d3696ff7186cd7ae8eb2f28d479eb44344f991",
            "payment" => "acce5bee9ffcfc0a3d79884c2989384458aa52691b0750a7161da4800720d771",
            "paid" => "b99fcebdf53fd0d05c85bfe7311d0d3cad9e19f439f682d9a3e897c8cddd4fcb",
            "grant" => "ca6d0d0e9aebd8c39d5d671932e783ac58e99dc6786328e8feb96e05b572d53b",
            _ => unreachable!(),
        };
        assert_eq!(hex(expected.as_bytes()), golden);
        assert_eq!(hex(actual.as_bytes()), golden);
    }
}
fn principal(seed: u8) -> PrincipalId {
    let passkey = hellas_kernel::SoftPasskey::from_secret_scalar([seed; 32]).unwrap();
    PrincipalId::from_public_key(hellas_auth::PublicKey::P256(passkey.party_key().to_bytes()))
        .unwrap()
}
fn node(seed: u8) -> NodeKey {
    let key = hellas_auth::ProducerSigningKey::from_secret_bytes([0x40 + seed; 32]).unwrap();
    NodeKey::from_public_key(key.public_key()).unwrap()
}
#[test]
fn grant_channel_separates_every_identity_and_generation() {
    let derive = |network, p, g, c, n, generation| {
        grant_channel_id(
            network,
            ContentId::from_bytes([p; 32]),
            GrantId([g; 16]),
            ChannelClient {
                principal: principal(c),
                node: node(n),
            },
            generation,
        )
    };
    let expected = derive(network(), 1, 2, 3, 4, 5);
    for other in [
        derive(NetworkId::new("other").unwrap(), 1, 2, 3, 4, 5),
        derive(network(), 2, 2, 3, 4, 5),
        derive(network(), 1, 3, 3, 4, 5),
        derive(network(), 1, 2, 4, 4, 5),
        // Two devices of one principal never share a channel.
        derive(network(), 1, 2, 3, 5, 5),
        derive(network(), 1, 2, 3, 4, 6),
    ] {
        assert_ne!(other, expected);
    }
    let mut preimage = b"hellas.work.grant-channel.v4\x0afunding-v2".to_vec();
    preimage.extend_from_slice(&[1; 32]);
    preimage.extend_from_slice(&[2; 16]);
    preimage.push(hellas_auth::SignatureKind::P256.to_byte());
    preimage.extend_from_slice(principal(3).as_bytes());
    preimage.push(hellas_auth::SignatureKind::Secp256k1.to_byte());
    preimage.extend_from_slice(node(4).as_bytes());
    preimage.extend_from_slice(&5u64.to_be_bytes());
    assert_eq!(
        expected.0.as_bytes(),
        hellas_xet::XetHash::hash(&preimage).as_bytes()
    );
    assert_eq!(
        hex(expected.0.as_bytes()),
        "eedd2dc11a1e59965735c9c52b7d67e65eec0b529feee3a49eb7b6dd09a777a8"
    );
}
#[test]
fn a_zero_payment_term_is_rejected_independently_of_application_bounds() {
    payment().check().unwrap();
    for policy in [
        JobPaymentPolicyV2 {
            fixed_price: 0,
            ..payment()
        },
        JobPaymentPolicyV2 {
            dispatch_margin_blocks: 0,
            ..payment()
        },
        JobPaymentPolicyV2 {
            delivery_margin_blocks: 0,
            ..payment()
        },
        JobPaymentPolicyV2 {
            oracle_grace_blocks: 0,
            ..payment()
        },
    ] {
        assert!(policy.check().is_err());
    }
}

#[test]
fn payment_and_work_policy_commitments_are_independent_signed_fields() {
    let first = paid_work_v2_id(network(), channel(), &paid());
    let mut changed = paid();
    changed.payment_policy_digest = d(80);
    assert_ne!(first, paid_work_v2_id(network(), channel(), &changed));
    changed = paid();
    changed.work_policy_digest = d(80);
    assert_ne!(first, paid_work_v2_id(network(), channel(), &changed));
    assert_ne!(
        first,
        paid_work_v2_id(NetworkId::new("other").unwrap(), channel(), &paid())
    );
    assert_ne!(first, paid_work_v2_id(network(), d(80), &paid()));
}

#[test]
fn grant_generation_and_price_revision_are_signed_and_old_width_is_rejected() {
    let first = grant();
    let mut changed = first;
    changed.pricing_revision.0 += 1;
    assert_ne!(
        grant_work_id(network(), &first),
        grant_work_id(network(), &changed)
    );
    changed = first;
    changed.generation += 1;
    assert_ne!(
        grant_work_id(network(), &first),
        grant_work_id(network(), &changed)
    );
    let mut old = bytes(GRANT);
    old.drain(34..42);
    assert_eq!(old.len(), 266);
    assert!(GrantJobAuthorizationV1::decode(&old).is_err());
}
