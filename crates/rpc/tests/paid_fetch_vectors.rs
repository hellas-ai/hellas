//! Independent vectors and mutation proofs for the paid-fetch records.
//!
//! The fetch-profile companion to `paid_work_vectors.rs`, in the same
//! style: canonical encodings pinned as hex decoded field by field,
//! digests pinned as hex, and every refusal covered by a mutation that
//! names what it breaks.
//!
//! The signed input transcript is built with the nonce pinned rather than
//! through `build_input_events_with_retention`: that constructor draws the
//! nonce from `OsRng`, and a golden digest over a random nonce is a
//! different vector every run. The transcript here is otherwise the exact
//! eight events that constructor signs, and the randomized constructor is
//! exercised end-to-end in
//! `the_real_input_constructor_passes_the_whole_pipeline`.

#![cfg(feature = "work")]

use hellas_kernel::{
    BlockHeight, EdgeId, EdgeValues, Fees, List, NetworkId, Parties, Payout, Secp256k1Signer,
    Secp256k1Verifier, SigVerifier, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, build_input_events_with_retention, encode_fetch_event_payload,
    encode_fetch_terminal_payload, input_canonicalization, output_canonicalization,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel, Usage};
use hellas_rpc::protocol::work::{
    CreditLedger, JobDeadlines, PaidChannel, PaidChannelPolicyV1, PaidJobAuthorizationV1,
    PaidWorkError, PrivateRecord, check_authorization, check_result, execution_policy_digest,
    next_payment, result_digest, signing_hash, work_id,
};
use hellas_rpc::protocol::work_fetch::{
    FetchRoutePolicy, PaidFetchPolicyV1, PreparedPaidFetchInputV1, check_fetch_authorization,
    check_fetch_policy, check_prepared_fetch_input, fetch_canonical_output_digest,
    fetch_policy_digest, fetch_route_commitment, prepared_fetch_input_digest,
    propose_fetch_authorization, terminal_fetch_result,
};
use hellas_rpc::{
    Assurance, ContentId, Digest, FetchEnvironment, InputCommitment, InputEventEnvelope,
    InputTranscriptBuilder, Operation, OutputEventEnvelope, ProducerSigningKey, ProgramManifest,
    PublicKey, RequestCommitment, Retention, scheme_id,
};

// ── Fixtures ──────────────────────────────────────────────────────────

const NETWORK: &str = "hellas-devnet-1";
const OTHER_NETWORK: &str = "hellas-devnet-22";
const SALT: [u8; 32] = [0x5a; 32];

/// The pinned `request.nonce`. `build_input_events_with_retention` draws
/// this from `OsRng`; the golden digests below need it fixed.
const NONCE: [u8; 32] = [7; 32];
const PROPOSAL_NONCE: u64 = 0x0102_0304_0506_0708;
const SERVICE: &str = "openai";
const METHOD: &str = "responses";
const REQUEST_BODY: &[u8] = br#"{"model":"gpt-5.2","input":"paid fetch"}"#;

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn network() -> NetworkId {
    NetworkId::new(NETWORK).expect("legal network id")
}

/// The settlement signer the channel terms name as the client.
fn client() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([3; 32]).expect("legal scalar")
}

/// The settlement signer the channel terms name as the provider.
fn provider() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([4; 32]).expect("legal scalar")
}

/// The transcript signing key over the client's secret: a signed fetch
/// input is the client's request, so its key and the settlement key are
/// the one scalar in two wrappers.
fn caller_key() -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([3; 32]).expect("legal scalar")
}

/// The transcript signing key over the provider's secret.
fn producer_key() -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([4; 32]).expect("legal scalar")
}

fn channel_policy() -> PaidChannelPolicyV1 {
    PaidChannelPolicyV1 {
        compute_credit_limit: 700,
        delivery_credit_limit: 800,
    }
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
        private_policy_commitment: hellas_rpc::protocol::work::private_policy_commitment(
            network(),
            &SALT,
            &channel_policy(),
        ),
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
fn channel_on(network: NetworkId, payment_edge: EdgeId) -> PaidChannel {
    let terms = WorkPaymentTerms {
        private_policy_commitment: hellas_rpc::protocol::work::private_policy_commitment(
            network,
            &SALT,
            &channel_policy(),
        ),
        ..payment_terms()
    };
    PaidChannel::new(network, payment_edge, terms, &SALT, channel_policy())
        .expect("terms that commit to this credit policy")
}

fn environment() -> FetchEnvironment {
    FetchEnvironment::OpenAiResponses
}

fn manifest() -> ProgramManifest {
    environment().manifest()
}

fn route() -> FetchRoutePolicy {
    FetchRoutePolicy::sealed_route(SERVICE, METHOD).expect("a legal route")
}

fn route_commitment() -> Digest {
    fetch_route_commitment(&route().canonical_body_bytes()).expect("a representable route body")
}

fn fetch_policy() -> PaidFetchPolicyV1 {
    PaidFetchPolicyV1 {
        allowed_environment: environment().manifest_id(),
        route_commitment: route_commitment(),
        max_request_body_bytes: 4_096,
        max_output_events: 64,
        max_output_bytes: 1_048_576,
        max_spool_bytes: 65_536,
        max_encoded_result_frame: 262_144,
        max_encoded_prepared_input: 1_048_576,
        dispatch_margin_blocks: 20,
        delivery_margin_blocks: 10,
        oracle_grace_blocks: 30,
        fixed_price: 250,
    }
}

fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 1_000,
        terminal: 1_050,
        payment: 1_100,
    }
}

/// Signs the eight fetch input events in the order
/// `build_input_events_with_retention` pushes them, with the nonce pinned.
fn signed_input(
    key: &ProducerSigningKey,
    assurance: Assurance,
    environment: ContentId,
    service: &str,
    method: &str,
    body: &[u8],
) -> Vec<InputEventEnvelope> {
    let mut builder = InputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, assurance),
        key,
        input_canonicalization(),
    );
    builder
        .push("assurance", vec![assurance.to_byte()])
        .unwrap();
    builder
        .push("execution.environment", environment.as_bytes().to_vec())
        .unwrap();
    builder.push("request.nonce", NONCE.to_vec()).unwrap();
    builder
        .push("service", service.as_bytes().to_vec())
        .unwrap();
    builder.push("method", method.as_bytes().to_vec()).unwrap();
    builder
        .push(
            "request.retain",
            vec![u8::from(Retention::Retain.should_retain())],
        )
        .unwrap();
    builder.push("request.body", body.to_vec()).unwrap();
    builder.push("input.end", Vec::new()).unwrap();
    builder.finish().unwrap().0
}

fn input_events() -> Vec<InputEventEnvelope> {
    signed_input(
        &caller_key(),
        Assurance::ProducerSigned,
        environment().manifest_id(),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    )
}

/// The request commitment exactly as the fetch ticket flow reads it: the
/// verified input transcript's commitment, re-wrapped.
fn input_request_commitment() -> RequestCommitment {
    let input = hellas_rpc::fetch::verify_input_events(&input_events())
        .expect("the fixture transcript verifies");
    RequestCommitment::from_digest(input.input_commitment.digest())
}

fn bundle() -> PreparedPaidFetchInputV1 {
    PreparedPaidFetchInputV1::new(&input_events(), &manifest()).expect("a legal transcript")
}

fn propose(
    channel: &PaidChannel,
    policy: &PaidFetchPolicyV1,
    bundle: &PreparedPaidFetchInputV1,
) -> PaidJobAuthorizationV1 {
    propose_fetch_authorization(channel, policy, bundle, PROPOSAL_NONCE, deadlines())
        .expect("a legal proposal")
}

fn authorization() -> PaidJobAuthorizationV1 {
    propose(&channel(), &fetch_policy(), &bundle())
}

/// Assembles bundle bytes from two arbitrary bodies, so a test can build
/// a spelling the constructor would never produce.
fn assemble(bodies: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for body in bodies {
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(body);
    }
    bytes
}

fn input_digest(channel: &PaidChannel, bundle: &PreparedPaidFetchInputV1) -> Digest {
    prepared_fetch_input_digest(channel, bundle).expect("a representable bundle")
}

/// One semantic output event payload, encoded with the fetch profile's
/// own payload codec: the paid layer treats payloads as opaque, but the
/// fixture answers are real ones.
fn event_payload(delta: &str) -> Vec<u8> {
    encode_fetch_event_payload(&OutputEvent::TextDelta {
        index: 0,
        delta: delta.to_string(),
        channel: TextChannel::Output,
    })
    .expect("a legal event payload")
}

fn terminal_payload() -> Vec<u8> {
    encode_fetch_terminal_payload(&OutputEvent::Finished {
        stop_reason: StopReason::EndOfText,
        usage: Some(Usage {
            input_tokens: Some(12),
            output_tokens: Some(2),
            total_tokens: Some(14),
        }),
    })
    .expect("a legal terminal payload")
}

/// The provider-signed output transcript answering the authorization's
/// request: two semantic events and a terminal.
fn output_transcript(authorization: &PaidJobAuthorizationV1) -> Vec<OutputEventEnvelope> {
    let input = InputCommitment::from_digest(authorization.request_commitment.digest());
    let key = producer_key();
    let mut builder = FetchOutputTranscriptBuilder::new(input, Assurance::ProducerSigned, &key);
    builder.push_event(event_payload("paid ")).unwrap();
    builder.push_event(event_payload("fetch")).unwrap();
    builder.finish(terminal_payload()).unwrap()
}

// ── Golden encodings ──────────────────────────────────────────────────

/// The fetch policy record's exact bytes, decoded field by field.
#[test]
fn golden_fetch_policy_encoding_is_pinned() {
    assert_eq!(PaidFetchPolicyV1::BODY_SIZE, 124);
    assert_eq!(PaidFetchPolicyV1::ENCODED_SIZE, 126);

    let policy = PaidFetchPolicyV1 {
        allowed_environment: ContentId::from_bytes([0x40; 32]),
        route_commitment: Digest::from_bytes([0x41; 32]),
        max_request_body_bytes: 1,
        max_output_events: 2,
        max_output_bytes: 3,
        max_spool_bytes: 4,
        max_encoded_result_frame: 5,
        max_encoded_prepared_input: 6,
        dispatch_margin_blocks: 7,
        delivery_margin_blocks: 8,
        oracle_grace_blocks: 9,
        fixed_price: 10,
    };
    assert_eq!(
        hex(&policy.encode()),
        concat!(
            "01",
            "05", // format version 1, tag 5 = PAID_FETCH_POLICY
            "4040404040404040404040404040404040404040404040404040404040404040", // environment
            "4141414141414141414141414141414141414141414141414141414141414141", // route
            "00000001", // max_request_body_bytes
            "00000002", // max_output_events
            "00000003", // max_output_bytes
            "0000000000000004", // max_spool_bytes
            "00000005", // max_encoded_result_frame
            "00000006", // max_encoded_prepared_input
            "0000000000000007", // dispatch_margin_blocks
            "0000000000000008", // delivery_margin_blocks
            "0000000000000009", // oracle_grace_blocks
            "000000000000000a", // fixed_price
        )
    );
    assert_eq!(PaidFetchPolicyV1::decode(&policy.encode()), Ok(policy));
}

/// Wrong tag, wrong version, truncation, and a trailing byte all reject,
/// on the new record.
#[test]
fn fetch_policy_envelope_mutations_reject() {
    let bytes = fetch_policy().encode();
    assert!(PaidFetchPolicyV1::decode(&bytes).is_ok());

    // MUTATION: the fetch policy presented under the evaluate policy tag.
    // Both are policies; only the envelope says which profile they are.
    let mut evaluate_tag = bytes.clone();
    evaluate_tag[1] = 1;
    assert_eq!(
        PaidFetchPolicyV1::decode(&evaluate_tag),
        Err(PaidWorkError::WrongRecordTag {
            expected: 5,
            actual: 1
        })
    );

    // MUTATION: a future format version.
    let mut wrong_version = bytes.clone();
    wrong_version[0] = 2;
    assert_eq!(
        PaidFetchPolicyV1::decode(&wrong_version),
        Err(PaidWorkError::UnknownFormatVersion { actual: 2 })
    );

    // MUTATION: one byte short.
    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        PaidFetchPolicyV1::decode(truncated),
        Err(PaidWorkError::RecordLength {
            expected: 126,
            actual: 125
        })
    );

    // MUTATION: one byte long.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        PaidFetchPolicyV1::decode(&trailing),
        Err(PaidWorkError::RecordLength {
            expected: 126,
            actual: 127
        })
    );
}

/// The two route-policy bodies, hand-decoded.
#[test]
fn golden_route_body_encodings_are_pinned() {
    // ["hellas.work.fetch-route.sealed.v1", "openai", "responses"]: a
    // three-element array, the 33-byte schema, the two route components.
    let sealed = route().canonical_body_bytes();
    assert_eq!(
        hex(&sealed),
        concat!(
            "83",   // array(3)
            "7821", // str(33)
            "68656c6c61732e776f726b2e66657463682d726f7574652e7365616c65642e7631",
            "66",                 // str(6)
            "6f70656e6169",       // "openai"
            "69",                 // str(9)
            "726573706f6e736573", // "responses"
        )
    );
    assert_eq!(
        FetchRoutePolicy::from_canonical_body_bytes(&sealed),
        Ok(route())
    );

    // ["hellas.work.fetch-route.open.v1", 1, ["api.openai.com"]]: the pin
    // as the integer 1, and one host.
    let open = FetchRoutePolicy::open_fetch(true, vec!["api.openai.com".to_string()]);
    let open_bytes = open.canonical_body_bytes();
    assert_eq!(
        hex(&open_bytes),
        concat!(
            "83",   // array(3)
            "781f", // str(31)
            "68656c6c61732e776f726b2e66657463682d726f7574652e6f70656e2e7631",
            "01",                           // require_spki_pin = true
            "81",                           // array(1)
            "6e",                           // str(14)
            "6170692e6f70656e61692e636f6d", // "api.openai.com"
        )
    );
    assert_eq!(
        FetchRoutePolicy::from_canonical_body_bytes(&open_bytes),
        Ok(open)
    );
}

/// The route codec's refusals: unknown schema, wrong shape, a pin that is
/// not 0 or 1, a trailing byte, a noncanonical spelling, and route
/// components the transcript scheme would not admit.
#[test]
fn route_policy_refusals() {
    let sealed = route().canonical_body_bytes();

    // MUTATION: an unknown schema tag.
    let unknown_schema = {
        let mut body = Vec::new();
        body.push(0x83);
        body.extend_from_slice(&[0x78, 0x21]);
        body.extend_from_slice(b"hellas.work.fetch-route.sealed.v9");
        body.extend_from_slice(&sealed[sealed.len() - 17..]);
        body
    };
    assert!(unknown_schema.len() == sealed.len());
    assert!(
        FetchRoutePolicy::from_canonical_body_bytes(&unknown_schema)
            .expect_err("an unknown schema must not parse")
            .to_string()
            .contains("unexpected fetch route schema tag")
    );

    // MUTATION: the array shortened to two elements.
    let mut short = sealed.clone();
    short[0] = 0x82;
    assert!(
        FetchRoutePolicy::from_canonical_body_bytes(&short)
            .expect_err("a shortened array must not parse")
            .to_string()
            .contains("expected array length 3, got 2")
    );

    // MUTATION: a trailing byte.
    let mut trailing = sealed.clone();
    trailing.push(0);
    assert!(
        FetchRoutePolicy::from_canonical_body_bytes(&trailing)
            .expect_err("a trailing byte must not parse")
            .to_string()
            .contains("trailing bytes")
    );

    // MUTATION: the pin spelled as the integer 2.
    let mut bad_pin =
        FetchRoutePolicy::open_fetch(true, Vec::<String>::new()).canonical_body_bytes();
    let pin = bad_pin.len() - 2; // [schema, pin, empty array]: pin is third from last
    assert_eq!(bad_pin[pin], 1);
    bad_pin[pin] = 2;
    assert!(
        FetchRoutePolicy::from_canonical_body_bytes(&bad_pin)
            .expect_err("a pin of 2 must not parse")
            .to_string()
            .contains("require_spki_pin must be 0 or 1")
    );

    // MUTATION: an empty service in the constructor and in a body.
    assert!(matches!(
        FetchRoutePolicy::sealed_route("", METHOD),
        Err(hellas_rpc::fetch::FetchProtocolError::EmptyService)
    ));
    assert!(matches!(
        FetchRoutePolicy::sealed_route(SERVICE, ""),
        Err(hellas_rpc::fetch::FetchProtocolError::EmptyMethod)
    ));
    let overlong = "x".repeat(hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES + 1);
    assert!(matches!(
        FetchRoutePolicy::sealed_route(&overlong, METHOD),
        Err(hellas_rpc::fetch::FetchProtocolError::RouteComponentLimit {
            field: "service",
            ..
        })
    ));
    let mut empty_service = sealed.clone();
    let service_at = empty_service.len() - "openai".len() - "responses".len() - 2;
    empty_service[service_at] = 0x60; // str(0)
    let mut shortened = empty_service[..service_at + 1].to_vec();
    shortened.extend_from_slice(&empty_service[service_at + 1 + "openai".len()..]);
    assert!(
        FetchRoutePolicy::from_canonical_body_bytes(&shortened)
            .expect_err("an empty service must not parse")
            .to_string()
            .contains("fetch service must not be empty")
    );

    // The allowlist is a set: the constructor sorts and deduplicates, so
    // the canonical body of a shuffled, doubled list is the same bytes.
    let shuffled = FetchRoutePolicy::open_fetch(
        false,
        vec![
            "b.example".to_string(),
            "a.example".to_string(),
            "b.example".to_string(),
        ],
    );
    let sorted = FetchRoutePolicy::open_fetch(
        false,
        vec!["a.example".to_string(), "b.example".to_string()],
    );
    assert_eq!(shuffled, sorted);
}

// ── Golden digests ────────────────────────────────────────────────────

/// The profile's pinned digests, over the deterministic fixture.
#[test]
fn golden_fetch_digests_are_pinned() {
    // XFH("hellas.work.fetch-route.v1" || u32be(len) || route body), both
    // variants.
    assert_eq!(
        hex(route_commitment().as_bytes()),
        "a2e44135e61c07424562ab53dfe8b74d18ddd6872d39a59d9206485d4ac41530"
    );
    let open = FetchRoutePolicy::open_fetch(true, vec!["api.openai.com".to_string()]);
    assert_eq!(
        hex(fetch_route_commitment(&open.canonical_body_bytes())
            .expect("a representable route body")
            .as_bytes()),
        "55e7ccf1928e21128357726422c637ddc5cf0437dde10568f0f2f83e0d69c299"
    );
    let channel = channel();
    // XH("hellas.work.fetch-policy.v1" || network || channel || record).
    assert_eq!(
        hex(fetch_policy_digest(&channel, &fetch_policy()).as_bytes()),
        "6a675a75bd5b40e8fad1e35272f1c971a1a9cc34a8b756ab5298cc747ff55ede"
    );
    // XFH("hellas.work.prepared-fetch-input.v1" || network || channel ||
    // bundle).
    assert_eq!(
        hex(input_digest(&channel, &bundle()).as_bytes()),
        "8bb0796694ed05a0e32fe2f40d32b16256bc802fbe073a8a5a06e6c59e58c3a9"
    );
    // XH("hellas.work.paid-job-authorize.v1" || network || channel ||
    // authorization): the shared record, signed under this profile.
    assert_eq!(
        hex(work_id(&channel, &authorization()).as_bytes()),
        "0258caba196b7a4c13c1ad8ea8f575ea9b943f58e80d73c17a3d41d534de0f30"
    );
}

/// The same bodies in another channel are other digests, and the check
/// that names the channel refuses them.
#[test]
fn fetch_records_do_not_cross_channels() {
    let here = channel();
    let sibling = channel_on(network(), EdgeId::from_bytes([0xe2; 32]));
    let elsewhere = channel_on(
        NetworkId::new(OTHER_NETWORK).expect("legal network id"),
        here.payment_edge(),
    );
    let authorization = authorization();

    assert_ne!(here.id(), sibling.id());
    for (label, other) in [("sibling", &sibling), ("elsewhere", &elsewhere)] {
        assert_ne!(
            fetch_policy_digest(&here, &fetch_policy()),
            fetch_policy_digest(other, &fetch_policy()),
            "{label} shares this channel's fetch policy digest"
        );
        assert_ne!(
            input_digest(&here, &bundle()),
            input_digest(other, &bundle()),
            "{label} shares this channel's prepared fetch input digest"
        );
        // MUTATION: replay this channel's fetch authorization on another
        // one.
        assert_eq!(
            check_fetch_authorization(other, &authorization, &fetch_policy(), 900),
            Err(PaidWorkError::Mismatch {
                field: "channel_id"
            }),
            "{label} accepted a foreign authorization"
        );
    }
}

// ── Prepared fetch input bundle ───────────────────────────────────────

/// The bundle encodes as two big-endian lengths and two bodies, and its
/// digest is reproducible from the same two component bodies.
#[test]
fn prepared_fetch_input_is_reproducible_from_its_components() {
    let bundle = bundle();
    let encoded = bundle.encode().expect("a representable bundle");

    // The bundle body is the canonical DAG-CBOR of the signed events;
    // rebuilding it from the decoded events must give the same bytes.
    let transcript = bundle.parts().expect("the canonical bodies parse");
    let reencoded = hellas_rpc::canonical_dag_cbor(&transcript.fetch_input_transcript)
        .expect("the decoded events re-encode");
    let manifest_bytes = manifest().canonical_bytes();
    let expected = assemble(&[&reencoded, &manifest_bytes]);
    assert_eq!(encoded, expected);

    let decoded = PreparedPaidFetchInputV1::decode(&encoded, 1_048_576).expect("legal bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(
        decoded
            .parts()
            .expect("the canonical bodies parse")
            .manifest
            .canonical_bytes(),
        manifest_bytes
    );
    assert_eq!(
        input_digest(&channel(), &decoded),
        input_digest(&channel(), &bundle)
    );
}

/// Padding, shortening, or re-labelling the bundle rejects rather than
/// producing a second acceptable spelling of the same job.
#[test]
fn prepared_fetch_input_mutations_reject() {
    let encoded = bundle().encode().expect("a representable bundle");
    let budget = 1_048_576;
    assert!(PreparedPaidFetchInputV1::decode(&encoded, budget).is_ok());

    // MUTATION: one appended byte.
    let mut trailing = encoded.clone();
    trailing.push(0);
    let err = PreparedPaidFetchInputV1::decode(&trailing, budget)
        .expect_err("a trailing byte must not decode");
    assert!(
        err.to_string()
            .contains("trailing bytes after prepared fetch input"),
        "{err}"
    );

    // MUTATION: the first declared length one byte short. The manifest's
    // length is then read out of the transcript's tail and refused before
    // anything is allocated for it.
    let mut short_length = encoded.clone();
    let first_len = u32::from_be_bytes([
        short_length[0],
        short_length[1],
        short_length[2],
        short_length[3],
    ]);
    short_length[..4].copy_from_slice(&(first_len - 1).to_be_bytes());
    let err = PreparedPaidFetchInputV1::decode(&short_length, budget)
        .expect_err("a shortened length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: u32::MAX in the first length.
    let mut huge = encoded.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let err = PreparedPaidFetchInputV1::decode(&huge, budget)
        .expect_err("a u32::MAX length must not decode");
    assert!(err.to_string().contains("budget"), "{err}");

    // MUTATION: a bundle one byte over its budget; the exact budget is
    // legal.
    let err = PreparedPaidFetchInputV1::decode(&encoded, encoded.len() - 1)
        .expect_err("a bundle over its budget must not decode");
    assert!(err.to_string().contains("budget"), "{err}");
    assert!(PreparedPaidFetchInputV1::decode(&encoded, encoded.len()).is_ok());

    // MUTATION: the two bodies swapped. The transcript is not a manifest.
    let transcript_bytes = &encoded[4..4 + (first_len as usize)];
    let swapped = assemble(&[&manifest().canonical_bytes(), transcript_bytes]);
    let err = PreparedPaidFetchInputV1::decode(&swapped, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("swapped components must not parse");
    assert!(!err.to_string().is_empty(), "{err}");

    // MUTATION: a noncanonical transcript body — the DAG-CBOR array
    // header re-spelled with a wider integer width.
    let mut widened = transcript_bytes.to_vec();
    assert_eq!(widened[0], 0x88, "the transcript is an eight-element array");
    widened.splice(0..1, [0x98, 0x08]);
    let noncanonical = assemble(&[&widened, &manifest().canonical_bytes()]);
    let err = PreparedPaidFetchInputV1::decode(&noncanonical, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("a noncanonical transcript must not parse");
    assert!(err.to_string().contains("canonical"), "{err}");

    // MUTATION: a noncanonical manifest body — trailing garbage inside
    // the second segment.
    let mut noncanonical_manifest = manifest().canonical_bytes();
    noncanonical_manifest.push(0);
    let noncanonical = assemble(&[transcript_bytes, &noncanonical_manifest]);
    let err = PreparedPaidFetchInputV1::decode(&noncanonical, budget)
        .expect("lengths are still well formed")
        .parts()
        .expect_err("a noncanonical manifest body must not parse");
    assert!(err.to_string().contains("trailing bytes"), "{err}");
}

/// Rebuilds the fetch policy preimage by hand and hashes it through the
/// crate's *other* hashing entry point.
///
/// Same discipline as `digest_preimages_are_reproducible_by_hand` in
/// `paid_work_vectors.rs`: if the domain, the network's length prefix,
/// the channel argument, or the envelope-plus-body order disagreed with
/// the module's, the two would not meet here.
#[test]
fn fetch_policy_preimage_is_reproducible_by_hand() {
    let channel = channel();

    let mut preimage = b"hellas.work.fetch-policy.v1".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.id().as_bytes());
    preimage.extend_from_slice(&fetch_policy().encode());
    assert_eq!(
        Digest::hash(&preimage),
        fetch_policy_digest(&channel, &fetch_policy())
    );

    // The route commitment: domain, u32 length prefix, body.
    let route_body = route().canonical_body_bytes();
    let mut preimage = b"hellas.work.fetch-route.v1".to_vec();
    preimage.extend_from_slice(&(route_body.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&route_body);
    assert_eq!(Digest::hash(&preimage), route_commitment());

    // The prepared input: domain, network, channel, bundle.
    let mut preimage = b"hellas.work.prepared-fetch-input.v1".to_vec();
    preimage.push(NETWORK.len() as u8);
    preimage.extend_from_slice(NETWORK.as_bytes());
    preimage.extend_from_slice(channel.id().as_bytes());
    preimage.extend_from_slice(&bundle().encode().expect("a representable bundle"));
    assert_eq!(Digest::hash(&preimage), input_digest(&channel, &bundle()));
}

// ── Authorization ─────────────────────────────────────────────────────

/// The proposal derives every field the channel, policy, and bundle fix,
/// and the request commitment is the fetch ticket flow's: the verified
/// input transcript's own commitment.
#[test]
fn propose_fetch_authorization_derives_every_field() {
    let channel = channel();
    let terms = payment_terms();
    let authorization = authorization();

    assert_eq!(authorization.channel_id, channel.id());
    assert_eq!(authorization.bond_edge, terms.bond_edge);
    assert_eq!(authorization.bond_terms_hash, terms.bond_terms_hash());
    assert_eq!(authorization.payment_edge, channel.payment_edge());
    assert_eq!(
        authorization.payment_terms_hash,
        channel.payment_terms_hash()
    );
    assert_eq!(
        authorization.execution_policy_digest,
        fetch_policy_digest(&channel, &fetch_policy())
    );
    assert_eq!(
        authorization.prepared_input_digest,
        input_digest(&channel, &bundle())
    );
    assert_eq!(authorization.proposal_nonce, PROPOSAL_NONCE);
    assert_eq!(authorization.acceptance_deadline, 1_000);
    assert_eq!(authorization.request_commitment, input_request_commitment());
    assert_eq!(
        authorization.environment_commitment,
        environment().manifest_id()
    );
    assert_eq!(authorization.price, 250);
    assert_eq!(authorization.terminal_deadline, 1_050);
    assert_eq!(authorization.payment_deadline, 1_100);

    // The signing bytes both parties produce are the authorization's
    // `work_id`, and both settlement keys verify over them.
    let id = check_fetch_authorization(&channel, &authorization, &fetch_policy(), 900)
        .expect("a legal authorization");
    assert_eq!(id, work_id(&channel, &authorization));
    let payload = signing_hash(id);
    let verifier = Secp256k1Verifier;
    assert!(verifier.verify_sig(client().sign(payload), channel.client_key(), payload));
    assert!(verifier.verify_sig(provider().sign(payload), channel.provider_key(), payload));
}

/// The fetch authorization refusals: the wiring of the shared core to
/// this profile's policy, plus the profile's own zero-bound rule.
#[test]
fn check_fetch_authorization_refusals() {
    let channel = channel();
    let policy = fetch_policy();
    let base = authorization();
    assert!(check_fetch_authorization(&channel, &base, &policy, 900).is_ok());

    // MUTATION: a policy whose digest is not the one the authorization
    // names.
    let mut other_policy = policy;
    other_policy.max_output_events += 1;
    assert_eq!(
        check_fetch_authorization(&channel, &base, &other_policy, 900),
        Err(PaidWorkError::Mismatch {
            field: "execution_policy_digest"
        })
    );

    // MUTATION: a zero bound. The policy check fires before any
    // comparison.
    let mut zeroed_policy = policy;
    zeroed_policy.max_output_bytes = 0;
    let zeroed = propose(&channel, &zeroed_policy, &bundle());
    assert_eq!(
        check_fetch_authorization(&channel, &zeroed, &zeroed_policy, 900),
        Err(PaidWorkError::PolicyZero {
            field: "max_output_bytes"
        })
    );

    // MUTATION: a price that disagrees with the signed policy.
    let mut mispriced = base;
    mispriced.price = 249;
    assert_eq!(
        check_fetch_authorization(&channel, &mispriced, &policy, 900),
        Err(PaidWorkError::Mismatch { field: "price" })
    );

    // MUTATION: a price the bond does not cover, honestly proposed under
    // a policy that names it.
    let mut dear_policy = policy;
    dear_policy.fixed_price = 501;
    let dear = propose(&channel, &dear_policy, &bundle());
    assert_eq!(
        check_fetch_authorization(&channel, &dear, &dear_policy, 900),
        Err(PaidWorkError::PriceOutOfRange {
            price: 501,
            max_job_price: 500
        })
    );

    // MUTATION: signing after the acceptance window closed.
    assert_eq!(
        check_fetch_authorization(&channel, &base, &policy, 1_001),
        Err(PaidWorkError::AcceptanceExpired {
            height: 1_001,
            deadline: 1_000
        })
    );

    // MUTATION: a payment deadline past the channel's admission horizon.
    let mut late = base;
    late.payment_deadline = 5_000;
    assert_eq!(
        check_fetch_authorization(&channel, &late, &policy, 900),
        Err(PaidWorkError::DeadlineOrder {
            acceptance: 1_000,
            terminal: 1_050,
            payment: 5_000,
            horizon: 5_000
        })
    );
}

/// Every bound the profile requires to be positive is refused at zero,
/// one field at a time.
#[test]
fn an_absent_fetch_policy_bound_is_refused() {
    let base = fetch_policy();
    assert!(check_fetch_policy(&base).is_ok());

    let zeroed: Vec<(&str, PaidFetchPolicyV1)> = vec![
        (
            "fixed_price",
            PaidFetchPolicyV1 {
                fixed_price: 0,
                ..base
            },
        ),
        (
            "max_request_body_bytes",
            PaidFetchPolicyV1 {
                max_request_body_bytes: 0,
                ..base
            },
        ),
        (
            "max_output_events",
            PaidFetchPolicyV1 {
                max_output_events: 0,
                ..base
            },
        ),
        (
            "max_output_bytes",
            PaidFetchPolicyV1 {
                max_output_bytes: 0,
                ..base
            },
        ),
        (
            "max_spool_bytes",
            PaidFetchPolicyV1 {
                max_spool_bytes: 0,
                ..base
            },
        ),
        (
            "max_encoded_result_frame",
            PaidFetchPolicyV1 {
                max_encoded_result_frame: 0,
                ..base
            },
        ),
        (
            "max_encoded_prepared_input",
            PaidFetchPolicyV1 {
                max_encoded_prepared_input: 0,
                ..base
            },
        ),
        (
            "dispatch_margin_blocks",
            PaidFetchPolicyV1 {
                dispatch_margin_blocks: 0,
                ..base
            },
        ),
        (
            "delivery_margin_blocks",
            PaidFetchPolicyV1 {
                delivery_margin_blocks: 0,
                ..base
            },
        ),
        (
            "oracle_grace_blocks",
            PaidFetchPolicyV1 {
                oracle_grace_blocks: 0,
                ..base
            },
        ),
    ];
    assert_eq!(zeroed.len(), 10, "every required bound must be zeroed");
    for (field, policy) in zeroed {
        assert_eq!(
            check_fetch_policy(&policy),
            Err(PaidWorkError::PolicyZero { field }),
            "{field} was accepted at zero"
        );
    }
}

/// Every fetch-policy field is inside the digest the authorization pins.
#[test]
fn every_fetch_policy_field_moves_its_digest() {
    let channel = channel();
    let base = fetch_policy();
    let pinned = fetch_policy_digest(&channel, &base);

    let mutations: Vec<(&str, PaidFetchPolicyV1)> = vec![
        ("allowed_environment", {
            let mut m = base;
            m.allowed_environment = ContentId::from_bytes([0; 32]);
            m
        }),
        ("route_commitment", {
            let mut m = base;
            m.route_commitment = Digest::from_bytes([0; 32]);
            m
        }),
        ("max_request_body_bytes", {
            let mut m = base;
            m.max_request_body_bytes += 1;
            m
        }),
        ("max_output_events", {
            let mut m = base;
            m.max_output_events += 1;
            m
        }),
        ("max_output_bytes", {
            let mut m = base;
            m.max_output_bytes += 1;
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
        ("max_encoded_prepared_input", {
            let mut m = base;
            m.max_encoded_prepared_input += 1;
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
    assert_eq!(mutations.len(), 12, "every field must be mutated");
    for (field, mutated) in mutations {
        assert_ne!(
            fetch_policy_digest(&channel, &mutated),
            pinned,
            "{field} left the policy digest alone"
        );
    }
}

// ── Prepared input checks ─────────────────────────────────────────────

/// The happy path, and the key correspondence it stands on: the
/// transcript's caller key and the channel's client settlement key are
/// the one scalar.
#[test]
fn check_prepared_fetch_input_happy_path() {
    let channel = channel();
    assert_eq!(
        caller_key().public_key(),
        PublicKey::Secp256k1(channel.client_key().to_bytes()),
        "the fixture caller must be the channel's client"
    );
    assert_eq!(
        producer_key().public_key(),
        PublicKey::Secp256k1(channel.provider_key().to_bytes()),
        "the fixture producer must be the channel's provider"
    );
    check_prepared_fetch_input(
        &channel,
        &authorization(),
        &fetch_policy(),
        &route(),
        &bundle(),
    )
    .expect("a legal prepared fetch input");
}

/// Each binding the check makes is broken on its own, with the bundle
/// digest and the authorization recomputed so the named check is the
/// only thing that can refuse it.
#[test]
fn each_fetch_input_binding_is_checked_on_its_own() {
    let channel = channel();
    let policy = fetch_policy();
    let base = authorization();
    assert!(check_prepared_fetch_input(&channel, &base, &policy, &route(), &bundle()).is_ok());

    // A bundle whose digest is not the one the authorization named.
    let mut unbound = base;
    unbound.prepared_input_digest = Digest::from_bytes([0x84; 32]);
    assert_eq!(
        check_prepared_fetch_input(&channel, &unbound, &policy, &route(), &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "prepared_input_digest"
        })
    );

    // A bundle larger than the policy's prepared-input bound. Refused
    // before its digest is even computed.
    let encoded = bundle().encode().expect("a representable bundle");
    let cramped = PaidFetchPolicyV1 {
        max_encoded_prepared_input: 100,
        ..policy
    };
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &cramped, &route(), &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "prepared input length",
            actual: encoded.len() as u64,
            limit: 100
        })
    );
    // The exact length is legal; one byte less is not.
    let exact = PaidFetchPolicyV1 {
        max_encoded_prepared_input: encoded.len() as u32,
        ..policy
    };
    assert!(check_prepared_fetch_input(&channel, &base, &exact, &route(), &bundle()).is_ok());

    // Input events signed by the provider's key rather than the client's:
    // a self-consistent chain whose caller is not this channel's client.
    let delegated_events = signed_input(
        &producer_key(),
        Assurance::ProducerSigned,
        environment().manifest_id(),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    let delegated_bundle =
        PreparedPaidFetchInputV1::new(&delegated_events, &manifest()).expect("a legal transcript");
    let delegated = propose(&channel, &policy, &delegated_bundle);
    assert_eq!(
        check_prepared_fetch_input(&channel, &delegated, &policy, &route(), &delegated_bundle),
        Err(PaidWorkError::Mismatch {
            field: "caller_key"
        })
    );

    // Another assurance mode under an otherwise legal bundle.
    let attested_events = signed_input(
        &caller_key(),
        Assurance::AppleAppAttest,
        environment().manifest_id(),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    let attested_bundle =
        PreparedPaidFetchInputV1::new(&attested_events, &manifest()).expect("a legal transcript");
    let attested = propose(&channel, &policy, &attested_bundle);
    assert_eq!(
        check_prepared_fetch_input(&channel, &attested, &policy, &route(), &attested_bundle),
        Ok(())
    );

    // A route body the policy does not commit to: the commitment check
    // fires before the route may constrain anything.
    let mut rerouted_policy = policy;
    rerouted_policy.route_commitment = Digest::from_bytes([0x86; 32]);
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &rerouted_policy, &route(), &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "route_commitment"
        })
    );

    // A sealed route whose service the signed events do not name, with
    // the policy's commitment honestly recomputed over it.
    let other_service = FetchRoutePolicy::sealed_route("anthropic", METHOD).expect("a legal route");
    let mut resold_policy = policy;
    resold_policy.route_commitment =
        fetch_route_commitment(&other_service.canonical_body_bytes()).expect("representable");
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &resold_policy, &other_service, &bundle()),
        Err(PaidWorkError::Mismatch { field: "service" })
    );

    // The method, on its own.
    let other_method = FetchRoutePolicy::sealed_route(SERVICE, "chat").expect("a legal route");
    let mut resold_policy = policy;
    resold_policy.route_commitment =
        fetch_route_commitment(&other_method.canonical_body_bytes()).expect("representable");
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &resold_policy, &other_method, &bundle()),
        Err(PaidWorkError::Mismatch { field: "method" })
    );

    // Events that name another environment than the bundle's manifest.
    let elsewhere_events = signed_input(
        &caller_key(),
        Assurance::ProducerSigned,
        ContentId::from_bytes([0x99; 32]),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    let elsewhere_bundle =
        PreparedPaidFetchInputV1::new(&elsewhere_events, &manifest()).expect("a legal transcript");
    let elsewhere = propose(&channel, &policy, &elsewhere_bundle);
    assert_eq!(
        check_prepared_fetch_input(&channel, &elsewhere, &policy, &route(), &elsewhere_bundle),
        Err(PaidWorkError::Mismatch {
            field: "manifest content id"
        })
    );

    // An authorization whose environment commitment is not the events'.
    let mut reenvironed = base;
    reenvironed.environment_commitment = ContentId::from_bytes([0x87; 32]);
    assert_eq!(
        check_prepared_fetch_input(&channel, &reenvironed, &policy, &route(), &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "environment_commitment"
        })
    );

    // A policy whose allowed environment is not the manifest's.
    let mut rehomed_policy = policy;
    rehomed_policy.allowed_environment = ContentId::from_bytes([0x85; 32]);
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &rehomed_policy, &route(), &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "allowed_environment"
        })
    );

    // A request commitment the authorization does not carry.
    let mut restamped = base;
    restamped.request_commitment = RequestCommitment::from_digest(Digest::from_bytes([0x88; 32]));
    assert_eq!(
        check_prepared_fetch_input(&channel, &restamped, &policy, &route(), &bundle()),
        Err(PaidWorkError::Mismatch {
            field: "request_commitment"
        })
    );

    // A request body over the policy's bound. The fetch protocol's own
    // 1 MiB bound still holds; the policy's tighter one is what refuses
    // here.
    let tight = PaidFetchPolicyV1 {
        max_request_body_bytes: 2,
        ..policy
    };
    assert_eq!(
        check_prepared_fetch_input(&channel, &base, &tight, &route(), &bundle()),
        Err(PaidWorkError::OverEnvelope {
            field: "request body",
            actual: REQUEST_BODY.len() as u64,
            limit: 2
        })
    );
}

/// Open Fetch requires its HTTPS interpreter and enforces the signed host/pin contract.
#[test]
fn open_fetch_checks_manifest_host_and_tls_pins() {
    let channel = channel();
    let route = FetchRoutePolicy::open_fetch(true, vec!["api.example.com".into()]);
    let environment = hellas_rpc::FetchEnvironment::Http;
    let mut policy = fetch_policy();
    policy.allowed_environment = environment.manifest_id();
    policy.route_commitment = fetch_route_commitment(&route.canonical_body_bytes()).unwrap();
    let make = |host: &str, pins: Vec<String>| {
        let body = serde_json::to_vec(&serde_json::json!({
            "url": format!("https://{host}/v1/messages"), "method":"POST", "body_base64":"e30=",
            "tls":{"roots":{"mode":"web_pki"},"spki_sha256":pins}, "max_response_bytes":4096
        }))
        .unwrap();
        let events = signed_input(
            &caller_key(),
            Assurance::AppleAppAttest,
            environment.manifest_id(),
            SERVICE,
            METHOD,
            &body,
        );
        PreparedPaidFetchInputV1::new(&events, &environment.manifest()).unwrap()
    };
    for (host, pins, valid) in [
        ("api.example.com", vec!["01".repeat(32)], true),
        ("other.example", vec!["01".repeat(32)], false),
        ("api.example.com", vec![], false),
    ] {
        let bundle = make(host, pins);
        let auth = propose(&channel, &policy, &bundle);
        assert_eq!(
            check_prepared_fetch_input(&channel, &auth, &policy, &route, &bundle).is_ok(),
            valid
        );
    }
    let sealed = bundle();
    let mut old = fetch_policy();
    old.route_commitment = policy.route_commitment;
    assert!(
        check_prepared_fetch_input(
            &channel,
            &propose(&channel, &old, &sealed),
            &old,
            &route,
            &sealed
        )
        .is_err()
    );
}

#[test]
fn paid_fetch_result_cannot_downgrade_the_signed_assurance() {
    use hellas_rpc::protocol::work_profile::PreparedPaidWorkInput;
    let channel = channel();
    let input = signed_input(
        &caller_key(),
        Assurance::AppleAppAttest,
        environment().manifest_id(),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    let bundle = PreparedPaidFetchInputV1::new(&input, &manifest()).unwrap();
    let auth = propose(&channel, &fetch_policy(), &bundle);
    let prepared = PreparedPaidWorkInput::Fetch(bundle);
    let weaker = output_transcript(&auth);
    assert!(prepared.terminal_result(&channel, &auth, &weaker).is_err());
    let key = producer_key();
    let builder = FetchOutputTranscriptBuilder::new(
        InputCommitment::from_digest(auth.request_commitment.digest()),
        Assurance::AppleAppAttest,
        &key,
    );
    let output = builder
        .finish(weaker.last().unwrap().payload().to_vec())
        .unwrap();
    assert!(prepared.terminal_result(&channel, &auth, &output).is_ok());
}

// ── The terminal result ───────────────────────────────────────────────

/// The golden result: one legal job carried from proposal to a signed
/// result, every digest pinned.
#[test]
fn terminal_fetch_result_is_pinned() {
    let channel = channel();
    let authorization = authorization();
    let transcript = output_transcript(&authorization);
    let result = terminal_fetch_result(
        &channel,
        &authorization,
        &transcript,
        Assurance::ProducerSigned,
    )
    .expect("a legal terminal transcript");

    assert_eq!(result.work_id, work_id(&channel, &authorization));
    assert_eq!(
        hex(result.terminal_transcript_commitment.as_bytes()),
        "986663facdd944d47bd210bc3379ac5aba2c48e31b7a303ccdee128a455172af"
    );
    assert_eq!(
        hex(result.canonical_output_digest.as_bytes()),
        "d7749786cb4d09c0949760f9cad1c6289a32a3fbfa62217f14c51eba40567975"
    );
    assert_eq!(
        hex(result_digest(&channel, &result).as_bytes()),
        "2d8d52936484533b65b37ed0e6d983eff30a7e8cf0d82c81821879d58888265b"
    );

    // The result record round-trips through the wire codec and the
    // profile-agnostic result check accepts it.
    let encoded = result.encode();
    assert_eq!(
        hellas_rpc::protocol::work::PaidJobResultV1::decode(&encoded),
        Ok(result)
    );
    assert_eq!(
        check_result(&channel, result.work_id, &result).expect("a legal result"),
        result_digest(&channel, &result)
    );
}

/// The result builder's refusals: an empty transcript, a transcript for
/// another request, a transcript the provider did not sign, and a
/// transcript whose last event is not a terminal.
#[test]
fn terminal_fetch_result_refusals() {
    let channel = channel();
    let authorization = authorization();

    // MUTATION: an empty transcript.
    assert!(matches!(
        terminal_fetch_result(&channel, &authorization, &[], Assurance::ProducerSigned),
        Err(PaidWorkError::Transcript(_))
    ));

    // MUTATION: a well-formed fetch transcript answering a different
    // request.
    let wrong_input = InputCommitment::from_digest(Digest::from_bytes([0x99; 32]));
    let key = producer_key();
    let builder = FetchOutputTranscriptBuilder::new(wrong_input, Assurance::ProducerSigned, &key);
    let wrong_request = builder.finish(terminal_payload()).unwrap();
    assert!(matches!(
        terminal_fetch_result(
            &channel,
            &authorization,
            &wrong_request,
            Assurance::ProducerSigned
        ),
        Err(PaidWorkError::Transcript(_))
    ));

    // MUTATION: the client signs the output. The chain verifies; the
    // producer is not the channel's provider.
    let input = InputCommitment::from_digest(authorization.request_commitment.digest());
    let key = caller_key();
    let mut builder = FetchOutputTranscriptBuilder::new(input, Assurance::ProducerSigned, &key);
    builder.push_event(event_payload("paid ")).unwrap();
    let client_signed = builder.finish(terminal_payload()).unwrap();
    assert_eq!(
        terminal_fetch_result(
            &channel,
            &authorization,
            &client_signed,
            Assurance::ProducerSigned
        ),
        Err(PaidWorkError::Mismatch {
            field: "transcript producer key"
        })
    );

    // MUTATION: the chain ends in a semantic event rather than a
    // terminal.
    let key = producer_key();
    let mut builder = hellas_rpc::OutputTranscriptBuilder::new(
        scheme_id(Operation::Fetch, Assurance::ProducerSigned),
        input,
        &key,
        output_canonicalization(),
    );
    builder
        .push("response.event", event_payload("paid "))
        .unwrap();
    let no_terminal = builder.finish().unwrap().0;
    assert!(matches!(
        terminal_fetch_result(
            &channel,
            &authorization,
            &no_terminal,
            Assurance::ProducerSigned
        ),
        Err(PaidWorkError::Transcript(_))
    ));
}

/// The normalized fetch answer ignores event boundaries and binds the
/// network and the job.
#[test]
fn fetch_output_digest_normalizes_chunking() {
    let network = network();
    let id = work_id(&channel(), &authorization());
    let first = event_payload("paid ");
    let second = event_payload("fetch");
    let terminal = terminal_payload();
    let digest =
        fetch_canonical_output_digest(network, id, &[first.clone(), second.clone()], &terminal);

    // The same bytes signed as one event rather than two: the boundary
    // is not part of the answer.
    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    assert_eq!(
        fetch_canonical_output_digest(network, id, &[joined], &terminal),
        digest
    );

    // MUTATION: a different answer.
    assert_ne!(
        fetch_canonical_output_digest(network, id, &[second, first], &terminal),
        digest
    );

    // MUTATION: a different terminal.
    let other_terminal = encode_fetch_terminal_payload(&OutputEvent::Finished {
        stop_reason: StopReason::EndOfText,
        usage: None,
    })
    .expect("a legal terminal payload");
    assert_ne!(
        fetch_canonical_output_digest(
            network,
            id,
            &[event_payload("paid "), event_payload("fetch")],
            &other_terminal
        ),
        digest
    );

    // The same answer for another job, or on another network, is another
    // digest.
    assert_ne!(
        fetch_canonical_output_digest(
            network,
            Digest::from_bytes([0; 32]),
            &[event_payload("paid "), event_payload("fetch")],
            &terminal
        ),
        digest
    );
    let other_network = NetworkId::new(OTHER_NETWORK).expect("legal network id");
    assert_ne!(
        fetch_canonical_output_digest(
            other_network,
            id,
            &[event_payload("paid "), event_payload("fetch")],
            &terminal
        ),
        digest
    );

    // And the pinned value: the answer bytes are the flattened payload
    // stream and nothing else.
    assert_eq!(
        hex(digest.as_bytes()),
        "d7749786cb4d09c0949760f9cad1c6289a32a3fbfa62217f14c51eba40567975"
    );
}

// ── The profile-agnostic tail ─────────────────────────────────────────

/// A fetch result pays through the shared payment machinery unchanged:
/// the profile ends at `terminal_fetch_result`, and what consensus
/// settles is built from the same records as an evaluate job's.
#[test]
fn fetch_result_pays_through_the_shared_ledger() {
    let channel = channel();
    let authorization = authorization();
    let transcript = output_transcript(&authorization);
    let result = terminal_fetch_result(
        &channel,
        &authorization,
        &transcript,
        Assurance::ProducerSigned,
    )
    .expect("a legal terminal transcript");

    let (certificate, binding) =
        next_payment(&channel, &authorization, &result, 0, capacity()).expect("a legal payment");
    assert_eq!(certificate.earned_cumulative(), 250);
    assert_eq!(binding.work_id, work_id(&channel, &authorization));
    assert_eq!(binding.result_digest, result_digest(&channel, &result));
    assert_eq!(binding.certificate_digest, certificate.digest(network()));

    CreditLedger::new()
        .credit_payment(
            &channel,
            &authorization,
            &result,
            &binding,
            &certificate,
            capacity(),
        )
        .expect("the ledger credits the fetch job's payment");
}

// ── The real constructor, end to end ──────────────────────────────────

/// The randomized fetch constructor's transcript passes the whole paid
/// pipeline: propose, both checks, and the terminal result.
#[test]
fn the_real_input_constructor_passes_the_whole_pipeline() {
    let channel = channel();
    let events = build_input_events_with_retention(
        SERVICE,
        METHOD,
        REQUEST_BODY,
        environment().manifest_id(),
        Assurance::ProducerSigned,
        &caller_key(),
        Retention::Retain,
    )
    .expect("the real constructor builds a legal transcript");
    let bundle = PreparedPaidFetchInputV1::new(&events, &manifest()).expect("a legal transcript");
    let authorization = propose(&channel, &fetch_policy(), &bundle);

    check_fetch_authorization(&channel, &authorization, &fetch_policy(), 900)
        .expect("a legal authorization");
    check_prepared_fetch_input(&channel, &authorization, &fetch_policy(), &route(), &bundle)
        .expect("a legal prepared input");

    let transcript = output_transcript(&authorization);
    let result = terminal_fetch_result(
        &channel,
        &authorization,
        &transcript,
        Assurance::ProducerSigned,
    )
    .expect("a legal terminal transcript");
    assert_eq!(result.work_id, work_id(&channel, &authorization));
}

// ── Bounds ────────────────────────────────────────────────────────────

/// The fetch module's one fixed-record preimage is measured, not assumed,
/// to be under the single-chunk limit — and is actually hashed, on the
/// longest legal network id.
#[test]
fn widest_fetch_preimage_is_measured() {
    let longest_network =
        NetworkId::new(&"n".repeat(hellas_kernel::MAX_NETWORK_ID_LENGTH)).expect("legal id");
    let encoded_network = 1 + hellas_kernel::MAX_NETWORK_ID_LENGTH;

    let widest = "hellas.work.fetch-policy.v1".len()
        + encoded_network
        + 32
        + PaidFetchPolicyV1::ENCODED_SIZE;
    assert_eq!(widest, 27 + 64 + 32 + 126);
    assert_eq!(widest, 249);
    assert!(widest < hellas_xet::MIN_CHUNK_SIZE);

    // The variable-body domains are streamed; asserting their digests
    // still compute over a multi-chunk body is what makes the choice of
    // hasher load-bearing.
    let mut big_body = route().canonical_body_bytes();
    big_body.extend_from_slice(&[0xab; 20_000]);
    let mut preimage = b"hellas.work.fetch-route.v1".to_vec();
    preimage.extend_from_slice(&(big_body.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&big_body);
    assert_eq!(
        fetch_route_commitment(&big_body).expect("a representable body"),
        Digest::hash(&preimage)
    );

    // The widest fixed preimage must hash rather than panic, so it is
    // actually hashed here.
    let channel = channel_on(longest_network, EdgeId::from_bytes([0xe1; 32]));
    let _ = fetch_policy_digest(&channel, &fetch_policy());
}

// ── Profile separation ────────────────────────────────────────────────

/// The two profiles share the channel, the authorization record, and the
/// payment tail, and nothing else: each profile's check refuses the other
/// profile's policy, and the digests differ under every body.
#[test]
fn the_two_profiles_do_not_mix() {
    let channel = channel();
    let fetch_policy = fetch_policy();

    // An evaluate execution policy over the same environment is not a
    // fetch policy: different domains, different digests.
    let evaluate_policy = hellas_rpc::protocol::work::PaidExecutionPolicyV1 {
        allowed_environment: fetch_policy.allowed_environment,
        generation_policy_digest: Digest::from_bytes([0x41; 32]),
        identity_source_digest: Digest::from_bytes([0x42; 32]),
        max_prompt_tokens: 8,
        max_new_tokens: 64,
        max_stop_token_ids: 4,
        max_spool_bytes: fetch_policy.max_spool_bytes,
        max_encoded_result_frame: fetch_policy.max_encoded_result_frame,
        max_encoded_quote_response: fetch_policy.max_encoded_prepared_input,
        dispatch_margin_blocks: fetch_policy.dispatch_margin_blocks,
        delivery_margin_blocks: fetch_policy.delivery_margin_blocks,
        oracle_grace_blocks: fetch_policy.oracle_grace_blocks,
        fixed_price: fetch_policy.fixed_price,
    };
    assert_ne!(
        execution_policy_digest(&channel, &evaluate_policy),
        fetch_policy_digest(&channel, &fetch_policy)
    );

    // The fetch authorization names the fetch policy's digest, so the
    // evaluate check refuses it on exactly that field.
    assert_eq!(
        check_authorization(&channel, &authorization(), &evaluate_policy, 900),
        Err(PaidWorkError::Mismatch {
            field: "execution_policy_digest"
        })
    );
    // And the fetch check refuses an authorization that names the
    // evaluate policy.
    let mut evaluate_signed = authorization();
    evaluate_signed.execution_policy_digest = execution_policy_digest(&channel, &evaluate_policy);
    assert_eq!(
        check_fetch_authorization(&channel, &evaluate_signed, &fetch_policy, 900),
        Err(PaidWorkError::Mismatch {
            field: "execution_policy_digest"
        })
    );
}
