//! Fetch is one application inside the generic paid invocation and result records.
//! The inner request nonce and outer invocation nonce are fixed for these vectors.
use hellas_auth::ProducerSigningKey;
use hellas_channel::test_support::test_responses_contract;
use hellas_channel::{
    job,
    model::work::{
        CreditLedger, JobDeadlines, PaidChannel, PaidChannelPolicyV1, PaidJobAuthorizationV2,
        PaidJobResultV1, PaidWorkError, PrivateRecord, ResultOutcome, check_result, next_payment,
        result_digest, work_id,
    },
};
use hellas_kernel::{
    BlockHeight, EdgeId, EdgeValues, Fees, List, NetworkId, Parties, PartyKeys, Payout,
    Secp256k1Signer, WorkPaymentSettlement, WorkPaymentTerms, WorkStakeBondTerms,
    work_payment_settlement,
};
use hellas_rpc::fetch::{
    build_input_events_with_retention, encode_fetch_event_payload, encode_fetch_terminal_payload,
    input_canonicalization,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel, Usage};
use hellas_rpc::{
    Assurance, ContentId, InputEventEnvelope, InputTranscriptBuilder, Operation,
    OutputEventEnvelope, Retention,
    protocol::invocation::{
        Admission, InvocationPolicy, Limits, PreparedInvocation,
        fetch::{
            self as invocation_fetch, FetchAdmission, FetchLimits, FetchRoutePolicy, RouteError,
        },
        output::{FailureReason, InvocationOutput, Outcome},
    },
    scheme_id,
};
const NETWORK: &str = "hellas-devnet-1";
const OTHER_NETWORK: &str = "hellas-devnet-22";
const SALT: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 32] = [7; 32];
const PROPOSAL_NONCE: u64 = 0x0102_0304_0506_0708;
const SERVICE: &str = "openai";
const METHOD: &str = "responses";
const REQUEST_BODY: &[u8] = br#"{"model":"gpt-5.2","input":"paid fetch"}"#;
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

fn client() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([3; 32]).expect("legal scalar")
}

fn provider() -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([4; 32]).expect("legal scalar")
}

fn caller_key() -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([3; 32]).expect("legal scalar")
}

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
        private_policy_commitment: hellas_channel::model::work::private_policy_commitment(
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

fn channel_on(network: NetworkId, payment_edge: EdgeId) -> PaidChannel {
    let terms = WorkPaymentTerms {
        private_policy_commitment: hellas_channel::model::work::private_policy_commitment(
            network,
            &SALT,
            &channel_policy(),
        ),
        ..payment_terms()
    };
    PaidChannel::new(network, payment_edge, terms, &SALT, channel_policy())
        .expect("terms that commit to this credit policy")
}

fn environment() -> hellas_rpc::FetchContract {
    test_responses_contract()
}

fn route() -> FetchRoutePolicy {
    FetchRoutePolicy::sealed_route(SERVICE, METHOD).expect("a legal route")
}

fn deadlines() -> JobDeadlines {
    JobDeadlines {
        acceptance: 1_000,
        terminal: 1_050,
        payment: 1_100,
    }
}

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
            vec![u8::from(Retention::Ephemeral.should_retain())],
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

fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
    hellas_channel::model::work::JobPaymentPolicyV2 {
        fixed_price: 250,
        dispatch_margin_blocks: 20,
        delivery_margin_blocks: 10,
        oracle_grace_blocks: 30,
    }
}

fn fetch_policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: environment(),
                route: route(),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 262144,
                    max_encoded_prepared_input: 1048576,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes: 1048576,
            max_output_bytes: 1048576,
            max_steps: 1,
            execution_timeout_ms: 60000,
        },
    }
}
fn prepare(events: &[InputEventEnvelope], policy: &InvocationPolicy) -> PreparedInvocation {
    invocation_fetch::prepare(
        events,
        &environment(),
        producer_key().public_key(),
        policy.canonical_bytes().unwrap(),
        NONCE,
    )
    .unwrap()
}
fn bundle() -> PreparedInvocation {
    prepare(&input_events(), &fetch_policy())
}
fn propose(
    channel: &PaidChannel,
    policy: &InvocationPolicy,
    input: &PreparedInvocation,
) -> PaidJobAuthorizationV2 {
    job::propose(
        channel,
        policy,
        &payment_policy(),
        input,
        PROPOSAL_NONCE,
        deadlines(),
    )
    .unwrap()
}
fn authorization() -> PaidJobAuthorizationV2 {
    propose(&channel(), &fetch_policy(), &bundle())
}
fn output() -> InvocationOutput {
    invocation_fetch::output(
        &[event_payload("paid "), event_payload("fetch")],
        &terminal_payload(),
    )
    .unwrap()
}
fn output_transcript(input: &PreparedInvocation) -> Vec<OutputEventEnvelope> {
    output()
        .sign(&input.request, &producer_key(), 1024)
        .unwrap()
}
fn result(
    input: &PreparedInvocation,
    events: &[OutputEventEnvelope],
) -> Result<PaidJobResultV1, PaidWorkError> {
    job::paid_terminal_result(
        &channel(),
        &propose(&channel(), &fetch_policy(), input),
        &fetch_policy(),
        input,
        events,
    )
}

#[test]
fn golden_fetch_invocation_digests_are_pinned() {
    let input = bundle();
    let a = authorization();
    let transcript = output_transcript(&input);
    let r = result(&input, &transcript).unwrap();
    let values = [
        (
            "policy",
            job::policy_digest(network(), channel().id(), &fetch_policy())
                .unwrap()
                .to_string(),
        ),
        (
            "prepared",
            job::prepared_input_digest(&channel(), &input)
                .unwrap()
                .to_string(),
        ),
        (
            "request",
            hex(input.request.commitment().unwrap().as_bytes()),
        ),
        ("work", work_id(&channel(), &a).to_string()),
        ("terminal", hex(r.terminal_transcript_commitment.as_bytes())),
        ("output", r.canonical_output_digest.to_string()),
        ("transcript", r.transcript_content.id().to_string()),
        ("result", result_digest(&channel(), &r).to_string()),
    ];
    let expected = [
        "8efceb77b1bed4f24ee83a81f1928280ab60df68f9f678ad5e2313e7a919332c",
        "3e77bb082e940350604f12cfbefad39075da18fbc4ed6fd619fdba35801e337a",
        "49de467ef4334be374b748326d015ed07fb439b7b8f16df04f8b9a3a41100198",
        "c2d5c2e82fadb86b81e85bd3b54fd4e713abbd90d9fe77f73894d20e3164ba4a",
        "bccf5d4dd97b81660d9c0296f4039922ae875fa067a21b0e6940b5fccc679297",
        "413bc901a9367bc949f5d53dfbe151e10aa0d9b7da9d748436496b576bc4c368",
        "6e223dd82ad6548d1fa38373aaec2b6dc9baf3e856b1910f17e8c776ddcec1f0",
        "d90b861fba773436e1808b3405f8f751f242d11c0c3919b0949e30c279204a69",
    ];
    assert_eq!(
        values.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(PaidJobResultV1::decode(&r.encode()).unwrap(), r);
    assert_eq!(
        check_result(&channel(), r.work_id, &r).unwrap(),
        result_digest(&channel(), &r)
    );
}

#[test]
fn prepared_fetch_input_is_reproducible_and_rejects_noncanonical_or_over_budget_bytes() {
    let input = bundle();
    let bytes = input.canonical_bytes().unwrap();
    assert_eq!(
        PreparedInvocation::from_canonical_bytes(&bytes, bytes.len()).unwrap(),
        input
    );
    assert!(PreparedInvocation::from_canonical_bytes(&bytes, bytes.len() - 1).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PreparedInvocation::from_canonical_bytes(&trailing, trailing.len()).is_err());
    for len in 0..bytes.len() {
        assert!(PreparedInvocation::from_canonical_bytes(&bytes[..len], bytes.len()).is_err());
    }
    let mut fields = serde_json::to_value(&input).unwrap();
    fields["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PreparedInvocation>(fields).is_err());
}

#[test]
fn policy_fields_and_route_are_bound_to_owner_authorization() {
    let base = fetch_policy();
    let a = authorization();
    let mut variants = Vec::new();
    for field in [
        "max_upload_bytes",
        "max_output_bytes",
        "max_steps",
        "execution_timeout_ms",
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        let n = value["limits"][field].as_u64().unwrap();
        value["limits"][field] = serde_json::json!(n + 1);
        variants.push(serde_json::from_value::<InvocationPolicy>(value).unwrap());
    }
    for field in [
        "max_request_body_bytes",
        "max_output_events",
        "max_spool_bytes",
        "max_encoded_result_frame",
        "max_encoded_prepared_input",
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        let n = value["admissions"][0]["admission"]["limits"][field]
            .as_u64()
            .unwrap();
        value["admissions"][0]["admission"]["limits"][field] = serde_json::json!(n + 1);
        variants.push(serde_json::from_value::<InvocationPolicy>(value).unwrap());
    }
    let mut changed = base.clone();
    let Admission::Fetch { admission } = &mut changed.admissions[0] else {
        unreachable!()
    };
    admission.route = FetchRoutePolicy::sealed_route("other", METHOD).unwrap();
    variants.push(changed);
    assert_eq!(variants.len(), 10);
    for policy in variants {
        assert_ne!(
            job::policy_digest(network(), channel().id(), &policy).unwrap(),
            a.work_policy_digest
        );
        assert!(job::check_authorization(&channel(), &a, &policy, &payment_policy(), 900).is_err());
    }
}

#[test]
fn every_common_and_fetch_bound_rejects_zero() {
    let base = fetch_policy();
    base.validate().unwrap();
    for field in [
        "max_upload_bytes",
        "max_output_bytes",
        "max_steps",
        "execution_timeout_ms",
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        value["limits"][field] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<InvocationPolicy>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for field in [
        "max_request_body_bytes",
        "max_output_events",
        "max_spool_bytes",
        "max_encoded_result_frame",
        "max_encoded_prepared_input",
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        value["admissions"][0]["admission"]["limits"][field] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<InvocationPolicy>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}

#[test]
fn request_caller_assurance_route_contract_and_retention_are_checked() {
    let policy = fetch_policy();
    let good = bundle();
    let a = authorization();
    assert!(job::check_paid_input(&channel(), &a, &policy, &good).is_ok());
    for events in [
        signed_input(
            &producer_key(),
            Assurance::ProducerSigned,
            environment().manifest_id(),
            SERVICE,
            METHOD,
            REQUEST_BODY,
        ),
        signed_input(
            &caller_key(),
            Assurance::ProducerSigned,
            environment().manifest_id(),
            "other",
            METHOD,
            REQUEST_BODY,
        ),
        signed_input(
            &caller_key(),
            Assurance::ProducerSigned,
            environment().manifest_id(),
            SERVICE,
            "other",
            REQUEST_BODY,
        ),
        signed_input(
            &caller_key(),
            Assurance::ProducerSigned,
            environment().manifest_id(),
            SERVICE,
            METHOD,
            &serde_json::to_vec(&"x".repeat(4097)).unwrap(),
        ),
    ] {
        let input = prepare(&events, &policy);
        let auth = propose(&channel(), &policy, &input);
        assert!(job::check_paid_input(&channel(), &auth, &policy, &input).is_err());
    }
    let retained = build_input_events_with_retention(
        SERVICE,
        METHOD,
        REQUEST_BODY,
        environment().manifest_id(),
        Assurance::ProducerSigned,
        &caller_key(),
        Retention::Retain,
    )
    .unwrap();
    assert!(
        invocation_fetch::prepare(
            &retained,
            &environment(),
            producer_key().public_key(),
            policy.canonical_bytes().unwrap(),
            NONCE
        )
        .is_err()
    );
    let foreign = signed_input(
        &caller_key(),
        Assurance::ProducerSigned,
        ContentId::from_bytes([9; 32]),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    assert!(
        invocation_fetch::prepare(
            &foreign,
            &environment(),
            producer_key().public_key(),
            policy.canonical_bytes().unwrap(),
            NONCE
        )
        .is_err()
    );
    let mut forged = good.clone();
    forged.request.retain = true;
    let auth = propose(&channel(), &policy, &forged);
    assert!(job::check_paid_input(&channel(), &auth, &policy, &forged).is_err());
}

#[test]
fn records_do_not_cross_channels_or_networks() {
    let here = channel();
    let input = bundle();
    let a = authorization();
    let r = result(&input, &output_transcript(&input)).unwrap();
    for other in [
        channel_on(network(), EdgeId::from_bytes([0xe2; 32])),
        channel_on(NetworkId::new(OTHER_NETWORK).unwrap(), here.payment_edge()),
    ] {
        assert_ne!(work_id(&here, &a), work_id(&other, &a));
        assert_ne!(result_digest(&here, &r), result_digest(&other, &r));
        assert!(
            job::check_authorization(&other, &a, &fetch_policy(), &payment_policy(), 900).is_err()
        );
        assert!(job::check_paid_input(&other, &a, &fetch_policy(), &input).is_err());
    }
}

#[test]
fn terminal_refusals_reject_missing_wrong_request_wrong_provider_and_incomplete_chains() {
    let input = bundle();
    let good = output_transcript(&input);
    assert!(result(&input, &good).is_ok());
    assert!(result(&input, &[]).is_err());
    assert!(result(&input, &good[..good.len() - 1]).is_err());
    let mut other = input.request.clone();
    other.nonce[0] ^= 1;
    assert!(
        result(
            &input,
            &output().sign(&other, &producer_key(), 1024).unwrap()
        )
        .is_err()
    );
    other.runner_public_key = caller_key().public_key();
    assert!(result(&input, &output().sign(&other, &caller_key(), 1024).unwrap()).is_err());
    let mut corrupted = good;
    corrupted[0] = output().sign(&other, &caller_key(), 1024).unwrap()[0].clone();
    assert!(result(&input, &corrupted).is_err());
}

#[test]
fn paid_fetch_result_cannot_downgrade_the_signed_assurance() {
    let events = signed_input(
        &caller_key(),
        Assurance::AppleAppAttest,
        environment().manifest_id(),
        SERVICE,
        METHOD,
        REQUEST_BODY,
    );
    let input = prepare(&events, &fetch_policy());
    let mut weaker = input.request.clone();
    weaker.assurance = Assurance::ProducerSigned;
    assert!(
        result(
            &input,
            &output().sign(&weaker, &producer_key(), 1024).unwrap()
        )
        .is_err()
    );
    assert!(result(&input, &output_transcript(&input)).is_ok());
}

#[test]
fn artifact_chunk_boundaries_preserve_normalized_output_but_bind_exact_transcript() {
    let input = bundle();
    let out = output();
    let one = out.sign(&input.request, &producer_key(), 1024).unwrap();
    let many = out.sign(&input.request, &producer_key(), 7).unwrap();
    let a = result(&input, &one).unwrap();
    let b = result(&input, &many).unwrap();
    assert_eq!(a.canonical_output_digest, b.canonical_output_digest);
    assert_ne!(
        a.terminal_transcript_commitment,
        b.terminal_transcript_commitment
    );
    assert_ne!(a.transcript_content, b.transcript_content);
    let changed = invocation_fetch::output(&[event_payload("other")], &terminal_payload()).unwrap();
    let c = result(
        &input,
        &changed.sign(&input.request, &producer_key(), 1024).unwrap(),
    )
    .unwrap();
    assert_ne!(a.canonical_output_digest, c.canonical_output_digest);
}

#[test]
fn fetch_result_pays_through_the_shared_ledger() {
    let channel = channel();
    let authorization = authorization();
    let input = bundle();
    let result = result(&input, &output_transcript(&input)).unwrap();
    let (certificate, binding) =
        next_payment(&channel, &authorization, &result, 0, capacity()).unwrap();
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
        .unwrap();
}

#[test]
fn failed_terminals_are_authenticated_but_never_payable() {
    let input = bundle();
    let failed = InvocationOutput {
        outcome: Outcome::Failed(FailureReason::Execution),
        artifacts: vec![],
        metadata: hellas_rpc::JsonBytes(vec![]),
    };
    let transcript = failed.sign(&input.request, &producer_key(), 1024).unwrap();
    let r = result(&input, &transcript).unwrap();
    assert_eq!(r.outcome, ResultOutcome::Failed);
    assert!(next_payment(&channel(), &authorization(), &r, 0, capacity()).is_err());
}

#[test]
fn the_real_input_constructor_passes_the_whole_pipeline() {
    let events = build_input_events_with_retention(
        SERVICE,
        METHOD,
        REQUEST_BODY,
        environment().manifest_id(),
        Assurance::ProducerSigned,
        &caller_key(),
        Retention::Ephemeral,
    )
    .unwrap();
    let input = prepare(&events, &fetch_policy());
    let a = propose(&channel(), &fetch_policy(), &input);
    job::check_authorization(&channel(), &a, &fetch_policy(), &payment_policy(), 900).unwrap();
    job::check_paid_input(&channel(), &a, &fetch_policy(), &input).unwrap();
    assert_eq!(
        result(&input, &output_transcript(&input)).unwrap().work_id,
        work_id(&channel(), &a)
    );
}

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
        Err(RouteError::EmptyService)
    ));
    assert!(matches!(
        FetchRoutePolicy::sealed_route(SERVICE, ""),
        Err(RouteError::EmptyMethod)
    ));
    let overlong = "x".repeat(hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES + 1);
    assert!(matches!(
        FetchRoutePolicy::sealed_route(&overlong, METHOD),
        Err(RouteError::RouteComponentLimit {
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
            .contains("fetch service is empty")
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
