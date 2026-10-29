use super::fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy};
use super::*;
use crate::{Assurance, FetchContract, FetchEgress, FetchSchema, Retention};
use hellas_auth::ProducerSigningKey;

fn fetch_admission() -> FetchAdmission {
    FetchAdmission {
        contract: FetchContract::http().unwrap(),
        route: FetchRoutePolicy::open_fetch(false, vec!["example.com".into()]),
        limits: FetchLimits {
            max_request_body_bytes: 64 << 10,
            max_output_events: 1024,
            max_spool_bytes: 4 << 20,
            max_encoded_result_frame: 1 << 20,
            max_encoded_prepared_input: 1 << 20,
        },
    }
}
fn policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![
            Admission::Compute {
                evaluator: compute::EVALUATOR.into(),
            },
            Admission::Fetch {
                admission: fetch_admission(),
            },
        ],
        limits: Limits {
            max_upload_bytes: 1 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 1024,
            execution_timeout_ms: 90_000,
        },
    }
}
fn fetch_mut(policy: &mut InvocationPolicy) -> &mut FetchAdmission {
    let Admission::Fetch { admission } = &mut policy.admissions[1] else {
        unreachable!()
    };
    admission
}

#[test]
fn every_policy_term_changes_the_committed_identity() {
    let base = policy();
    let id = base.content_id().unwrap();
    let changes: &[fn(&mut InvocationPolicy)] = &[
        |p| p.limits.max_upload_bytes += 1,
        |p| p.limits.max_output_bytes += 1,
        |p| p.limits.max_steps += 1,
        |p| p.limits.execution_timeout_ms += 1,
        |p| p.admissions.remove(0).validate().unwrap(),
        |p| {
            p.admissions[0] = Admission::Compute {
                evaluator: "another/evaluator-1".into(),
            }
        },
        |p| fetch_mut(p).route = FetchRoutePolicy::open_fetch(true, vec!["example.com".into()]),
        |p| fetch_mut(p).route = FetchRoutePolicy::open_fetch(false, vec!["example.net".into()]),
        |p| fetch_mut(p).route = FetchRoutePolicy::sealed_route("http", "fetch").unwrap(),
        |p| fetch_mut(p).limits.max_request_body_bytes += 1,
        |p| fetch_mut(p).limits.max_output_events += 1,
        |p| fetch_mut(p).limits.max_spool_bytes += 1,
        |p| fetch_mut(p).limits.max_encoded_result_frame += 1,
        |p| fetch_mut(p).limits.max_encoded_prepared_input += 1,
        |p| {
            fetch_mut(p).contract = FetchContract::new(
                "http-0.0.2",
                FetchSchema::HttpV1,
                "driver",
                FetchEgress::RequestHttps,
            )
            .unwrap()
        },
        |p| {
            fetch_mut(p).contract = FetchContract::new(
                "http-0.0.1",
                FetchSchema::HttpV1,
                "another-driver",
                FetchEgress::RequestHttps,
            )
            .unwrap()
        },
        |p| {
            fetch_mut(p).contract = FetchContract::new(
                "http-0.0.1",
                FetchSchema::HttpV1,
                "driver",
                FetchEgress::FixedHttps("https://example.com/".into()),
            )
            .unwrap()
        },
    ];
    for (index, change) in changes.iter().enumerate() {
        let mut changed = base.clone();
        change(&mut changed);
        assert_ne!(
            changed.content_id().unwrap(),
            id,
            "unbound policy field {index}"
        );
        let bytes = changed.canonical_bytes().unwrap();
        assert_eq!(
            InvocationPolicy::from_canonical_bytes(&bytes).unwrap(),
            changed
        );
        let mut prepared = prepared("https://example.com/", false, Retention::Ephemeral);
        let original_policy = prepared.policy_digest();
        prepared.application_policy = JsonBytes(bytes);
        assert_ne!(prepared.policy_digest(), original_policy);
    }
    let contract = |adaptor: &str, schema, driver: &str, endpoint: &str| {
        FetchContract::new(
            adaptor,
            schema,
            driver,
            FetchEgress::FixedHttps(endpoint.into()),
        )
        .unwrap()
    };
    let mut base = policy();
    fetch_mut(&mut base).contract = contract(
        "adapter-1",
        FetchSchema::HttpV1,
        "driver-1",
        "https://example.com/",
    );
    let expected = base.content_id().unwrap();
    for (adaptor, schema, driver, endpoint) in [
        (
            "adapter-2",
            FetchSchema::HttpV1,
            "driver-1",
            "https://example.com/",
        ),
        (
            "adapter-1",
            FetchSchema::StatelessResponsesV1,
            "driver-1",
            "https://example.com/",
        ),
        (
            "adapter-1",
            FetchSchema::HttpV1,
            "driver-2",
            "https://example.com/",
        ),
        (
            "adapter-1",
            FetchSchema::HttpV1,
            "driver-1",
            "https://example.net/",
        ),
    ] {
        let mut altered = base.clone();
        fetch_mut(&mut altered).contract = contract(adaptor, schema, driver, endpoint);
        assert_ne!(altered.content_id().unwrap(), expected);
    }
}

#[test]
fn policy_is_bounded_canonical_and_has_no_compile_budget() {
    let p = policy();
    let bytes = p.canonical_bytes().unwrap();
    assert_eq!(
        p.content_id().unwrap().to_string(),
        "7290cb2b26f9a81b4a0f64098b701603fc631c8969a632ba221c9b4ac41fa8c3"
    );
    assert_eq!(InvocationPolicy::from_canonical_bytes(&bytes).unwrap(), p);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(InvocationPolicy::from_canonical_bytes(&trailing).is_err());
    assert!(
        InvocationPolicy::from_canonical_bytes(&vec![0; policy::MAX_POLICY_BYTES + 1]).is_err()
    );
    let mut empty = p.clone();
    empty.admissions.clear();
    assert!(empty.canonical_bytes().is_err());
    let mut duplicate = p.clone();
    duplicate.admissions.push(duplicate.admissions[0].clone());
    assert!(duplicate.canonical_bytes().is_err());
    for zero in 0..4 {
        let mut p = p.clone();
        match zero {
            0 => p.limits.max_upload_bytes = 0,
            1 => p.limits.max_output_bytes = 0,
            2 => p.limits.max_steps = 0,
            _ => p.limits.execution_timeout_ms = 0,
        }
        assert!(p.canonical_bytes().is_err());
    }
    let mut json = serde_json::to_value(&p).unwrap();
    json["limits"]["compile_timeout_ms"] = 120000.into();
    assert!(serde_json::from_value::<InvocationPolicy>(json).is_err());
}

#[test]
fn fetch_route_bytes_keep_the_existing_vectors() {
    let sealed = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    let hex = |bytes: Vec<u8>| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(sealed.canonical_body_bytes()),
        "83782168656c6c61732e776f726b2e66657463682d726f7574652e7365616c65642e7631666f70656e616969726573706f6e736573"
    );
    let open = FetchRoutePolicy::open_fetch(
        true,
        vec![" API.OpenAI.com ".into(), "api.openai.com".into()],
    );
    assert_eq!(
        hex(open.canonical_body_bytes()),
        "83781f68656c6c61732e776f726b2e66657463682d726f7574652e6f70656e2e763101816e6170692e6f70656e61692e636f6d"
    );
    assert_eq!(
        FetchRoutePolicy::from_canonical_body_bytes(&open.canonical_body_bytes()).unwrap(),
        open
    );
}

fn caller() -> hellas_auth::PublicKey {
    ProducerSigningKey::from_secret_bytes([9; 32])
        .unwrap()
        .public_key()
}
fn runner() -> ProducerSigningKey {
    ProducerSigningKey::from_secret_bytes([17; 32]).unwrap()
}
fn prepared(url: &str, pinned: bool, retention: Retention) -> PreparedInvocation {
    prepared_for(FetchContract::http().unwrap(), url, pinned, retention)
}
fn prepared_for(
    contract: FetchContract,
    url: &str,
    pinned: bool,
    retention: Retention,
) -> PreparedInvocation {
    let key = ProducerSigningKey::from_secret_bytes([9; 32]).unwrap();
    let request = crate::http_fetch::HttpFetchRequest {
        url: url.into(),
        method: "GET".into(),
        headers: vec![],
        body_base64: String::new(),
        credential: None,
        tls: crate::http_fetch::HttpTls {
            roots: crate::http_fetch::HttpTrustRoots::WebPki,
            spki_sha256: if pinned {
                vec!["11".repeat(32)]
            } else {
                vec![]
            },
        },
        max_response_bytes: 64,
    };
    let events = crate::fetch::build_input_events_with_retention(
        "http",
        "fetch",
        &serde_json::to_vec(&request).unwrap(),
        contract.manifest_id(),
        Assurance::ProducerSigned,
        &key,
        retention,
    )
    .unwrap();
    fetch::prepare(
        &events,
        &contract,
        runner().public_key(),
        policy().canonical_bytes().unwrap(),
        [7; 32],
    )
    .unwrap()
}

#[test]
fn fetch_invocation_preserves_the_signed_request_and_enforces_egress() {
    let p = prepared("https://example.com/", true, Retention::Ephemeral);
    let mut admission = fetch_admission();
    let input = fetch::validate_input(&p, &admission, 1024, &caller()).unwrap();
    assert_eq!(input.retention, Retention::Ephemeral);
    assert_eq!(
        Admission::Fetch {
            admission: admission.clone()
        }
        .retention(),
        Retention::Ephemeral
    );
    assert_eq!(input.caller_key, caller());
    assert_eq!(p.request.runner_public_key, runner().public_key());
    assert_ne!(input.caller_key, p.request.runner_public_key);
    let output = output::InvocationOutput {
        outcome: output::Outcome::Succeeded,
        artifacts: vec![],
        metadata: JsonBytes(vec![]),
    };
    let events = output.sign(&p.request, &runner(), 64).unwrap();
    output::verify(
        &p.request,
        &runner().public_key(),
        &events,
        MAX_INVOCATION_BYTES,
    )
    .unwrap();
    assert!(output::verify(&p.request, &caller(), &events, MAX_INVOCATION_BYTES).is_err());
    let events: Vec<crate::InputEventEnvelope> =
        crate::protocol::value::decode_canonical_dag_cbor(p.input.artifacts[0].bytes.as_bytes())
            .unwrap();
    assert_eq!(input, crate::fetch::verify_input_events(&events).unwrap());
    admission.route = FetchRoutePolicy::open_fetch(true, vec!["example.com".into()]);
    fetch::validate_input(&p, &admission, 1024, &caller()).unwrap();
    assert!(
        fetch::validate_input(
            &prepared("https://example.net/", true, Retention::Ephemeral),
            &admission,
            1024,
            &caller()
        )
        .is_err()
    );
    assert!(
        fetch::validate_input(
            &prepared("https://example.com/", false, Retention::Ephemeral),
            &admission,
            1024,
            &caller()
        )
        .is_err()
    );
    admission.route = FetchRoutePolicy::sealed_route("http", "another-method").unwrap();
    assert!(fetch::validate_input(&p, &admission, 1024, &caller()).is_err());
}

#[test]
fn fetch_resource_boundaries_refuse_before_execution() {
    let p = prepared("https://example.com/", false, Retention::Ephemeral);
    let mut admission = fetch_admission();
    let bytes = fetch::validate_input(&p, &admission, 1024, &caller())
        .unwrap()
        .body
        .0
        .len() as u32;
    admission.limits.max_request_body_bytes = bytes;
    fetch::validate_input(&p, &admission, 1024, &caller()).unwrap();
    admission.limits.max_request_body_bytes = bytes - 1;
    assert!(fetch::validate_input(&p, &admission, 1024, &caller()).is_err());
    admission.limits.max_request_body_bytes = bytes;
    admission.limits.max_encoded_prepared_input = p.canonical_bytes().unwrap().len() as u32;
    fetch::validate_input(&p, &admission, 1024, &caller()).unwrap();
    admission.limits.max_encoded_prepared_input -= 1;
    assert!(fetch::validate_input(&p, &admission, 1024, &caller()).is_err());
    admission = fetch_admission();
    fetch::validate_input(&p, &admission, 88, &caller()).unwrap();
    assert!(fetch::validate_input(&p, &admission, 85, &caller()).is_err());
}

#[test]
fn fetch_inner_signature_and_outer_identity_are_both_required() {
    let p = prepared("https://example.com/", false, Retention::Ephemeral);
    let admission = fetch_admission();
    let wrong_client = ProducerSigningKey::from_secret_bytes([10; 32])
        .unwrap()
        .public_key();
    assert!(fetch::validate_input(&p, &admission, 1024, &wrong_client).is_err());
    let mut assurance = p.clone();
    assurance.request.assurance = Assurance::AppleAppAttest;
    assert!(fetch::validate_input(&assurance, &admission, 1024, &caller()).is_err());
    let mut retention = p.clone();
    retention.request.retain = true;
    assert!(fetch::validate_input(&retention, &admission, 1024, &caller()).is_err());
    let mut forged = p.clone();
    let mut events: Vec<crate::InputEventEnvelope> =
        crate::protocol::value::decode_canonical_dag_cbor(
            forged.input.artifacts[0].bytes.as_bytes(),
        )
        .unwrap();
    let index = events
        .iter()
        .position(|event| event.event().body().kind() == "request.body")
        .unwrap();
    let original = &events[index];
    let commitment = original.event_commitment();
    let signed = crate::SignedInputEvent::from_parts(
        original.event().body().clone(),
        *events[0].event().signature(),
        *original.event().public_key(),
    )
    .unwrap();
    // Only the signature changes; payload hashes and the complete chain remain
    // valid, so chain checks cannot conceal a missing signature verification.
    let payload = original.payload().to_vec();
    events[index] = crate::InputEventEnvelope::new(signed, payload).unwrap();
    assert_eq!(events[index].event_commitment(), commitment);
    forged.input.artifacts[0].bytes = JsonBytes(encode(&events).unwrap());
    forged.request.input = forged.input.content_id().unwrap();
    forged.validate().unwrap();
    assert!(fetch::validate_input(&forged, &admission, 1024, &caller()).is_err());
    let mut role = p.clone();
    role.input.artifacts[0].name = "another-role".into();
    role.request.input = role.input.content_id().unwrap();
    assert!(fetch::validate_input(&role, &admission, 1024, &caller()).is_err());
    let mut contract = p.clone();
    contract.input.parameters = JsonBytes(
        fetch::Parameters {
            contract: FetchContract::new(
                "another-adaptor",
                FetchSchema::HttpV1,
                "driver",
                FetchEgress::RequestHttps,
            )
            .unwrap(),
        }
        .canonical_bytes()
        .unwrap(),
    );
    contract.request.input = contract.input.content_id().unwrap();
    assert!(fetch::validate_input(&contract, &admission, 1024, &caller()).is_err());
}

#[test]
fn retained_fetch_is_refused_even_when_inner_and_outer_requests_agree() {
    let mut p = prepared("https://example.com/", false, Retention::Ephemeral);
    let admission = fetch_admission();
    let input = fetch::validate_input(&p, &admission, 1024, &caller()).unwrap();
    let key = ProducerSigningKey::from_secret_bytes([9; 32]).unwrap();
    let events = crate::fetch::build_input_events_with_retention(
        "http",
        "fetch",
        input.body.as_bytes(),
        admission.contract.manifest_id(),
        Assurance::ProducerSigned,
        &key,
        Retention::Retain,
    )
    .unwrap();
    assert!(
        fetch::prepare(
            &events,
            &admission.contract,
            runner().public_key(),
            p.application_policy.0.clone(),
            [8; 32]
        )
        .is_err()
    );
    p.input.artifacts[0].bytes = JsonBytes(encode(&events).unwrap());
    p.request.input = p.input.content_id().unwrap();
    p.request.retain = true;
    p.validate().unwrap();
    assert!(
        fetch::validate_input(&p, &admission, 1024, &caller())
            .unwrap_err()
            .to_string()
            .contains("ephemeral")
    );
}

#[test]
fn a_fixed_fetch_contract_refuses_a_different_signed_endpoint() {
    let contract = FetchContract::new(
        "http-0.0.1",
        FetchSchema::HttpV1,
        "driver",
        FetchEgress::FixedHttps("https://example.com/allowed".into()),
    )
    .unwrap();
    let mut admission = fetch_admission();
    admission.contract = contract.clone();
    admission.route = FetchRoutePolicy::sealed_route("http", "fetch").unwrap();
    let good = prepared_for(
        contract.clone(),
        "https://example.com/allowed",
        false,
        Retention::Ephemeral,
    );
    fetch::validate_input(&good, &admission, 1024, &caller()).unwrap();
    let wrong = prepared_for(
        contract,
        "https://example.com/other",
        false,
        Retention::Ephemeral,
    );
    assert!(
        fetch::validate_input(&wrong, &admission, 1024, &caller())
            .unwrap_err()
            .to_string()
            .contains("endpoint")
    );
}

fn compute_prepared(policy: &InvocationPolicy, plan: &compute::Plan) -> PreparedInvocation {
    let manifest = compute::Environment {
        sources: vec![crate::ContentRef::for_bytes(b"program")],
        assets: vec![],
    }
    .manifest()
    .unwrap();
    let input = InvocationInput {
        parameters: JsonBytes(plan.canonical_bytes().unwrap()),
        artifacts: vec![],
    };
    PreparedInvocation::new(
        InvocationRequest {
            execution_environment: manifest.content_id(),
            input: input.content_id().unwrap(),
            runner_public_key: runner().public_key(),
            nonce: [31; 32],
            assurance: Assurance::ProducerSigned,
            retain: true,
        },
        &manifest,
        input,
        policy.canonical_bytes().unwrap(),
    )
    .unwrap()
}
fn step_plan() -> compute::Plan {
    compute::Plan {
        calls: vec![],
        step: Some(compute::Step {
            entry: "next".into(),
            args: vec![],
            bind: vec![compute::Bind::Name("token".into())],
            emit: "token".into(),
            stop: compute::Stop {
                any_of: vec![9],
                max_steps: 2,
            },
        }),
        outputs: vec![],
    }
}
fn compute_result(values: &[u64], stop: compute::StopReason) -> output::InvocationOutput {
    output::InvocationOutput {
        outcome: output::Outcome::Succeeded,
        artifacts: vec![Artifact::new(
            "emitted",
            "catena.u64le.v1",
            values.iter().flat_map(|v| v.to_le_bytes()).collect(),
        )],
        metadata: JsonBytes(
            encode(&compute::RunMetadata {
                steps: values.len() as u64,
                stop: Some(stop),
            })
            .unwrap(),
        ),
    }
}
fn http_result(events: Vec<crate::output::HttpResponseEvent>) -> output::InvocationOutput {
    let events: Vec<_> = events
        .into_iter()
        .map(|event| {
            crate::fetch::encode_fetch_event_payload(&crate::output::OutputEvent::Adaptor(
                crate::output::AdaptorEvent::Http(event),
            ))
            .unwrap()
        })
        .collect();
    let terminal =
        crate::fetch::encode_fetch_terminal_payload(&crate::output::OutputEvent::Finished {
            stop_reason: crate::output::StopReason::EndOfText,
            usage: None,
        })
        .unwrap();
    fetch::output(&events, &terminal).unwrap()
}
fn http_head() -> crate::output::HttpResponseEvent {
    crate::output::HttpResponseEvent::Head {
        status: 200,
        headers: vec![],
    }
}
fn http_body(bytes: &[u8]) -> crate::output::HttpResponseEvent {
    use base64::Engine;
    crate::output::HttpResponseEvent::Body {
        base64: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

#[test]
fn application_admission_binds_owner_bytes_caller_and_staging_classification() {
    let p = policy();
    let mut prepared = prepared("https://example.com/", false, Retention::Ephemeral);
    let admitted = p.admit(&prepared, &caller()).unwrap();
    assert_eq!(admitted.capacity_domain, CapacityDomain::Fetch);
    assert_eq!(admitted.retention, Retention::Ephemeral);
    assert_eq!(admitted.max_spool_bytes, 4 << 20);
    assert_eq!(admitted.max_encoded_result_frame, 1 << 20);
    assert_eq!(
        p.classify_manifest(&prepared.manifest().unwrap()).unwrap(),
        admitted
    );
    assert!(p.admit(&prepared, &runner().public_key()).is_err());
    prepared.application_policy.0.push(0);
    assert!(p.admit(&prepared, &caller()).is_err());
    let mut approved = p.clone();
    approved.limits.max_upload_bytes += 1;
    prepared.application_policy = JsonBytes(approved.canonical_bytes().unwrap());
    assert!(p.admit(&prepared, &caller()).is_err());

    let compute = compute_prepared(&p, &step_plan());
    let facts = p.classify_manifest(&compute.manifest().unwrap()).unwrap();
    assert_eq!(facts.capacity_domain, CapacityDomain::Gpu);
    assert_eq!(facts.retention, Retention::Retain);
    let wrong = crate::ProgramManifest::new(
        crate::Application::new(compute::EVALUATOR, "another-adaptor").unwrap(),
        compute.manifest().unwrap().root(),
    );
    assert!(p.classify_manifest(&wrong).is_err());
    let mut routes = p.clone();
    let mut other = fetch_admission();
    other.route = FetchRoutePolicy::open_fetch(false, vec!["example.net".into()]);
    routes
        .admissions
        .push(Admission::Fetch { admission: other });
    routes.validate().unwrap();
    assert_eq!(
        routes
            .admissions_for(&FetchContract::http().unwrap().manifest())
            .count(),
        2
    );
    let mut forged = p;
    forged.admissions = vec![Admission::Compute {
        evaluator: crate::protocol::fetch_contract::FETCH_EVALUATOR.into(),
    }];
    assert!(
        forged
            .classify_manifest(&prepared.manifest().unwrap())
            .is_err()
    );
    let unknown = crate::ProgramManifest::new(
        crate::Application::new("unknown/evaluator", compute::ADAPTOR).unwrap(),
        compute.manifest().unwrap().root(),
    );
    forged.admissions = vec![Admission::Compute {
        evaluator: "unknown/evaluator".into(),
    }];
    assert!(forged.classify_manifest(&unknown).is_err());
}

#[test]
fn application_admission_checks_compute_bounds_without_content_acquisition() {
    let mut p = policy();
    p.limits.max_steps = 2;
    p.limits.max_output_bytes = 16;
    let plan = step_plan();
    let prepared = compute_prepared(&p, &plan);
    p.admit(&prepared, &caller()).unwrap();
    let mut grant = prepared.clone();
    grant.request.retain = false;
    p.admit(&grant, &caller()).unwrap();
    for mutate in [
        (|p: &mut compute::Plan| p.step.as_mut().unwrap().stop.max_steps = 0)
            as fn(&mut compute::Plan),
        |p| p.step.as_mut().unwrap().stop.max_steps = 3,
        |p| {
            p.outputs.push(compute::Declared {
                slot: "other".into(),
                kind: compute::OutputKind::Scalar(compute::ValueKind::Bool),
            })
        },
        |p| {
            p.outputs.push(compute::Declared {
                slot: "emitted".into(),
                kind: compute::OutputKind::Buffer { max_bytes: 0 },
            })
        },
        |p| {
            p.outputs.push(compute::Declared {
                slot: "other".into(),
                kind: compute::OutputKind::Scalar(compute::ValueKind::MemOwn),
            })
        },
    ] {
        let mut invalid = plan.clone();
        mutate(&mut invalid);
        assert!(p.admit(&compute_prepared(&p, &invalid), &caller()).is_err());
    }
}

#[test]
fn application_result_hook_checks_compute_stop_rule_and_exact_transcript_identity() {
    let p = policy();
    let prepared = compute_prepared(&p, &step_plan());
    let good = compute_result(&[7, 9], compute::StopReason::Matched(9));
    let events = good.sign(&prepared.request, &runner(), 8).unwrap();
    let verified = prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
    assert_eq!(verified.output, good);
    assert!(verified.output.is_success());
    assert_eq!(verified.output_id, good.content_id().unwrap());
    assert_eq!(verified.transcript_bytes, encode(&events).unwrap());
    assert_eq!(
        verified.transcript,
        crate::ContentRef::for_bytes(&verified.transcript_bytes)
    );
    assert_ne!(verified.transcript.id(), verified.output_id);
    for invalid in [
        compute_result(&[9, 7], compute::StopReason::MaxSteps),
        compute_result(&[7], compute::StopReason::MaxSteps),
        compute_result(&[7, 9], compute::StopReason::MaxSteps),
    ] {
        let events = invalid.sign(&prepared.request, &runner(), 8).unwrap();
        // These are authentic provider results; only application checking refuses them.
        output::verify(
            &prepared.request,
            &runner().public_key(),
            &events,
            MAX_INVOCATION_BYTES,
        )
        .unwrap();
        assert!(
            prepared
                .verify_output(&p, &caller(), &runner().public_key(), &events)
                .is_err()
        );
    }
}

#[test]
fn application_result_hook_authenticates_failed_outcomes_without_promoting_them() {
    let p = policy();
    let prepared = compute_prepared(&p, &step_plan());
    let failed = output::InvocationOutput {
        outcome: output::Outcome::Failed(output::FailureReason::Compilation),
        artifacts: vec![],
        metadata: JsonBytes(vec![]),
    };
    let events = failed.sign(&prepared.request, &runner(), 8).unwrap();
    let verified = prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
    assert!(!verified.output.is_success());
    assert_eq!(verified.output.outcome, failed.outcome);
    assert!(compute::validate_output(&step_plan(), &verified.output).is_err());
    assert!(
        prepared
            .verify_output(&p, &caller(), &caller(), &events)
            .is_err()
    );
    let mut other = prepared;
    other.request.nonce[0] ^= 1;
    assert!(
        other
            .verify_output(&p, &caller(), &runner().public_key(), &events)
            .is_err()
    );
}

#[test]
fn application_result_hook_preserves_http_payloads_and_checks_response_shapes() {
    let p = policy();
    let prepared = prepared("https://example.com/", false, Retention::Ephemeral);
    let good = http_result(vec![http_head(), http_body(b"hello")]);
    let events = good.sign(&prepared.request, &runner(), 64).unwrap();
    let verified = prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
    assert!(verified.output.is_success());
    let decoded = fetch::decode_output(&verified.output, &runner().public_key()).unwrap();
    let payloads = decoded.output_event_payloads();
    assert_eq!(
        payloads.0[1],
        crate::fetch::encode_fetch_event_payload(&crate::output::OutputEvent::Adaptor(
            crate::output::AdaptorEvent::Http(http_body(b"hello"))
        ))
        .unwrap()
    );
    for invalid in [
        http_result(vec![http_body(b"hello")]),
        http_result(vec![http_head(), http_head()]),
        http_result(vec![http_head(), http_body(&[1; 65])]),
    ] {
        let events = invalid.sign(&prepared.request, &runner(), 64).unwrap();
        output::verify(
            &prepared.request,
            &runner().public_key(),
            &events,
            MAX_INVOCATION_BYTES,
        )
        .unwrap();
        assert!(
            prepared
                .verify_output(&p, &caller(), &runner().public_key(), &events)
                .is_err()
        );
    }
}

#[test]
fn all_applicable_routes_are_checked_without_mixing_their_result_bounds() {
    let base = prepared("https://example.com/", false, Retention::Ephemeral);
    let output = http_result(vec![http_head(), http_body(b"hello")]);
    let events = output.sign(&base.request, &runner(), 64).unwrap();
    let frame = events
        .iter()
        .map(|e| encode(e).unwrap().len())
        .max()
        .unwrap();
    let spool = encode(&events).unwrap().len();
    let mut first = fetch_admission();
    first.limits.max_encoded_result_frame = frame as u32 - 1;
    let mut second = fetch_admission();
    second.limits.max_spool_bytes = spool as u64 - 1;
    let mut p = policy();
    p.admissions = vec![
        Admission::Fetch { admission: first },
        Admission::Fetch { admission: second },
    ];
    let mut prepared = base;
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    let facts = p.admit(&prepared, &caller()).unwrap();
    assert!(facts.max_encoded_result_frame as usize >= frame);
    assert!(facts.max_spool_bytes as usize >= spool);
    assert!(
        prepared
            .verify_output(&p, &caller(), &runner().public_key(), &events)
            .is_err()
    );
    let mut wrong_host = fetch_admission();
    wrong_host.route = FetchRoutePolicy::open_fetch(false, vec!["example.net".into()]);
    p.admissions = vec![
        Admission::Fetch {
            admission: wrong_host,
        },
        Admission::Fetch {
            admission: fetch_admission(),
        },
    ];
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    p.admit(&prepared, &caller()).unwrap();
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
}

#[test]
fn failed_application_prefixes_still_obey_owner_byte_and_event_bounds() {
    let mut p = policy();
    p.limits.max_output_bytes = 8;
    let mut plan = step_plan();
    plan.step.as_mut().unwrap().stop.max_steps = 1;
    let prepared_compute = compute_prepared(&p, &plan);
    for bytes in [8, 9] {
        let failed = output::InvocationOutput {
            outcome: output::Outcome::Failed(output::FailureReason::Execution),
            artifacts: vec![Artifact::new("emitted", "catena.u64le.v1", vec![1; bytes])],
            metadata: JsonBytes(vec![]),
        };
        let events = failed
            .sign(&prepared_compute.request, &runner(), 64)
            .unwrap();
        assert_eq!(
            prepared_compute
                .verify_output(&p, &caller(), &runner().public_key(), &events)
                .is_ok(),
            bytes == 8
        );
    }
    p.limits.max_output_bytes = 128;
    let mut prepared = prepared("https://example.com/", false, Retention::Ephemeral);
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    let payload =
        crate::fetch::encode_fetch_event_payload(&crate::output::OutputEvent::TextDelta {
            index: 0,
            delta: "x".repeat(129),
            channel: crate::output::TextChannel::Output,
        })
        .unwrap();
    let overbudget = output::InvocationOutput {
        outcome: output::Outcome::Failed(output::FailureReason::Execution),
        artifacts: vec![Artifact::new(
            fetch::RESPONSE_EVENTS,
            fetch::RESPONSE_EVENTS_FORMAT,
            fetch::frame_event(&payload).unwrap(),
        )],
        metadata: JsonBytes(vec![]),
    };
    let events = overbudget.sign(&prepared.request, &runner(), 64).unwrap();
    assert!(
        prepared
            .verify_output(&p, &caller(), &runner().public_key(), &events)
            .is_err()
    );
    let good = http_result(vec![http_head(), http_body(b"hi")]);
    let decoded = fetch::decode_output(&good, &runner().public_key()).unwrap();
    p.limits.max_output_bytes = decoded
        .output_event_payloads()
        .0
        .iter()
        .map(|payload| payload.len() as u64)
        .sum();
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    let mut failed = good;
    failed.outcome = output::Outcome::Failed(output::FailureReason::Execution);
    failed.metadata = JsonBytes(vec![]);
    let events = failed.sign(&prepared.request, &runner(), 64).unwrap();
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
    fetch_mut(&mut p).limits.max_output_events = 2;
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    assert!(
        prepared
            .verify_output(&p, &caller(), &runner().public_key(), &events)
            .is_err()
    );
    // Ending mid-event is a normal failure prefix and remains authentic, bounded data.
    failed.artifacts[0].bytes.0.truncate(5);
    let events = failed.sign(&prepared.request, &runner(), 64).unwrap();
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
}

#[test]
fn public_application_hooks_enforce_encoded_input_frame_spool_and_event_bounds() {
    let base = prepared("https://example.com/", false, Retention::Ephemeral);
    let result = http_result(vec![http_head(), http_body(b"hi")]);
    let events = result.sign(&base.request, &runner(), 64).unwrap();
    for mutate in [
        (|p: &mut InvocationPolicy| fetch_mut(p).limits.max_encoded_result_frame = 1)
            as fn(&mut InvocationPolicy),
        |p| fetch_mut(p).limits.max_spool_bytes = 1,
        |p| fetch_mut(p).limits.max_output_events = 1,
    ] {
        let mut p = policy();
        mutate(&mut p);
        let mut prepared = base.clone();
        prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
        p.admit(&prepared, &caller()).unwrap();
        assert!(
            prepared
                .verify_output(&p, &caller(), &runner().public_key(), &events)
                .is_err()
        );
    }
    let mut p = policy();
    fetch_mut(&mut p).limits.max_encoded_prepared_input = 1;
    let mut prepared = base;
    prepared.application_policy = JsonBytes(p.canonical_bytes().unwrap());
    assert!(p.admit(&prepared, &caller()).is_err());
}

#[test]
fn compute_derived_reservation_covers_actual_signed_framing_and_retained_events() {
    let mut p = policy();
    p.admissions.truncate(1);
    p.limits.max_steps = 1;
    for bytes in [1, 23, 24, 255, 256, 65535, 65536, 65537, 1 << 20] {
        p.limits.max_output_bytes = bytes as u64;
        let plan = compute::Plan {
            calls: vec![],
            step: None,
            outputs: vec![compute::Declared {
                slot: "x".repeat(256),
                kind: compute::OutputKind::Buffer {
                    max_bytes: bytes as u64,
                },
            }],
        };
        let mut prepared = compute_prepared(&p, &plan);
        prepared.request.retain = false;
        let facts = p.admit(&prepared, &caller()).unwrap();
        let result = output::InvocationOutput {
            outcome: output::Outcome::Succeeded,
            artifacts: vec![Artifact::new(
                "x".repeat(256),
                "catena.bytes.v1",
                vec![255; bytes],
            )],
            metadata: JsonBytes(
                encode(&compute::RunMetadata {
                    steps: 0,
                    stop: None,
                })
                .unwrap(),
            ),
        };
        let events = result
            .sign(&prepared.request, &runner(), output::MAX_CHUNK_BYTES)
            .unwrap();
        let payload: u64 = events
            .iter()
            .map(|event| event.payload().len() as u64)
            .sum();
        assert!(payload <= facts.max_transcript_payload_bytes);
        assert!(encode(&events).unwrap().len() as u64 <= facts.max_spool_bytes);
        let mut grant_ram = 0u64;
        for event in &events {
            let charge = event.payload().len() as u64 * 2 + 1024;
            grant_ram += charge;
            assert!(charge <= u64::from(facts.max_encoded_result_frame));
            assert!(encode(event).unwrap().len() <= facts.max_encoded_result_frame as usize);
        }
        assert!(grant_ram <= facts.max_spool_bytes);
        let verified = prepared
            .verify_output(&p, &caller(), &runner().public_key(), &events)
            .unwrap();
        assert!(verified.output.is_success());
    }

    // The v1 artifact maximum includes empty outputs and full-length labels.
    p.limits.max_output_bytes = 1;
    let outputs: Vec<_> = (0..MAX_ARTIFACTS)
        .map(|i| compute::Declared {
            slot: format!("{}{:02}", "x".repeat(254), i),
            kind: compute::OutputKind::Buffer { max_bytes: 0 },
        })
        .collect();
    let plan = compute::Plan {
        calls: vec![],
        step: None,
        outputs,
    };
    let prepared = compute_prepared(&p, &plan);
    let mut result = output::InvocationOutput {
        outcome: output::Outcome::Failed(output::FailureReason::Execution),
        artifacts: plan
            .outputs
            .iter()
            .map(|d| Artifact::new(&d.slot, "x".repeat(256), vec![]))
            .collect(),
        metadata: JsonBytes(vec![]),
    };
    let events = result
        .sign(&prepared.request, &runner(), output::MAX_CHUNK_BYTES)
        .unwrap();
    assert_eq!(events.len(), MAX_ARTIFACTS + 1);
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
    result.outcome = output::Outcome::Succeeded;
    result.metadata = JsonBytes(
        encode(&compute::RunMetadata {
            steps: 0,
            stop: None,
        })
        .unwrap(),
    );
    for artifact in &mut result.artifacts {
        artifact.format = "catena.bytes.v1".into();
    }
    let events = result
        .sign(&prepared.request, &runner(), output::MAX_CHUNK_BYTES)
        .unwrap();
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();

    p.limits.max_steps = 1000;
    p.limits.max_output_bytes = 8000;
    let mut plan = step_plan();
    plan.step.as_mut().unwrap().stop.max_steps = 1000;
    let prepared = compute_prepared(&p, &plan);
    let result = compute_result(&vec![7; 1000], compute::StopReason::MaxSteps);
    let events = result.sign(&prepared.request, &runner(), 8).unwrap();
    assert_eq!(events.len(), 1001);
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &events)
        .unwrap();
}

#[test]
fn compute_event_cap_refuses_excessive_fragmentation_within_the_raw_byte_allowance() {
    let mut p = policy();
    p.admissions.truncate(1);
    p.limits.max_steps = 1;
    p.limits.max_output_bytes = 8192;
    let plan = compute::Plan {
        calls: vec![],
        step: None,
        outputs: vec![compute::Declared {
            slot: "buffer".into(),
            kind: compute::OutputKind::Buffer { max_bytes: 8192 },
        }],
    };
    let prepared = compute_prepared(&p, &plan);
    let result = output::InvocationOutput {
        outcome: output::Outcome::Succeeded,
        artifacts: vec![Artifact::new("buffer", "catena.bytes.v1", vec![255; 8000])],
        metadata: JsonBytes(
            encode(&compute::RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let facts = p.admit(&prepared, &caller()).unwrap();
    let ordinary = result
        .sign(&prepared.request, &runner(), output::MAX_CHUNK_BYTES)
        .unwrap();
    prepared
        .verify_output(&p, &caller(), &runner().public_key(), &ordinary)
        .unwrap();
    let fragmented = result.sign(&prepared.request, &runner(), 80).unwrap();
    assert!(fragmented.len() as u64 > facts.max_output_events);
    assert!((encode(&fragmented).unwrap().len() as u64) < facts.max_spool_bytes);
    let retained: usize = fragmented
        .iter()
        .map(|e| {
            e.retained_heap_bytes().unwrap() + 4 * std::mem::size_of::<crate::OutputEventEnvelope>()
        })
        .sum();
    assert!((retained as u64) < facts.max_spool_bytes);
    output::verify(
        &prepared.request,
        &runner().public_key(),
        &fragmented,
        facts.max_transcript_payload_bytes as usize,
    )
    .unwrap();
    assert!(
        prepared
            .verify_output(&p, &caller(), &runner().public_key(), &fragmented)
            .is_err()
    );
}

fn closure_manifest(root: &[u8]) -> crate::ProgramManifest {
    crate::ProgramManifest::new(
        crate::Application::new(compute::EVALUATOR, compute::ADAPTOR).unwrap(),
        crate::ContentId::hash(root),
    )
}

#[test]
fn content_closure_opens_the_signed_root_and_returns_unique_exact_references() {
    let source = crate::ContentRef::for_bytes(b"program source");
    let weights = crate::ContentRef::new(crate::ContentId::from_bytes([55; 32]), 1 << 30);
    let environment = compute::Environment {
        sources: vec![source, source],
        assets: vec![
            compute::NamedAsset {
                name: "weights".into(),
                object: weights,
            },
            compute::NamedAsset {
                name: "alias".into(),
                object: weights,
            },
            compute::NamedAsset {
                name: "source".into(),
                object: source,
            },
        ],
    };
    let bytes = environment.canonical_bytes().unwrap();
    assert_eq!(
        compute::Environment::from_canonical_bytes(&bytes).unwrap(),
        environment
    );
    let manifest = environment.manifest().unwrap();
    let actual = policy().content_closure(&manifest, &bytes).unwrap();
    assert_eq!(actual.len(), 3);
    assert!(actual.contains(&crate::ContentRef::for_bytes(&bytes)));
    assert!(actual.contains(&source));
    assert!(actual.contains(&weights));
    assert!(
        actual
            .windows(2)
            .all(|objects| objects[0].id() < objects[1].id())
    );

    let mut other = environment;
    other.sources.clear();
    assert!(
        policy()
            .content_closure(&manifest, &other.canonical_bytes().unwrap())
            .is_err()
    );
    let mut unapproved = policy();
    unapproved.admissions.remove(0);
    assert!(unapproved.content_closure(&manifest, &bytes).is_err());
    let fetch = FetchContract::http().unwrap().manifest();
    assert!(policy().content_closure(&fetch, &[]).unwrap().is_empty());
    assert!(policy().content_closure(&fetch, &bytes).is_err());
}

#[test]
fn content_closure_refuses_conflicting_lengths_names_and_impossible_source_sizes() {
    let object = crate::ContentRef::for_bytes(b"source");
    let environment = compute::Environment {
        sources: vec![object],
        assets: vec![compute::NamedAsset {
            name: "asset".into(),
            object,
        }],
    };
    let changes: &[fn(&mut compute::Environment)] = &[
        |e| {
            e.assets[0].object = crate::ContentRef::new(e.sources[0].id(), e.sources[0].bytes() + 1)
        },
        |e| e.assets.push(e.assets[0].clone()),
        |e| e.assets[0].name.clear(),
        |e| e.assets[0].name = "x".repeat(257),
        |e| {
            e.sources[0] = crate::ContentRef::new(e.sources[0].id(), compute::MAX_SOURCE_BYTES + 1);
            e.assets.clear();
        },
    ];
    for change in changes {
        let mut changed = environment.clone();
        change(&mut changed);
        let bytes = changed.canonical_bytes().unwrap();
        assert!(
            policy()
                .content_closure(&closure_manifest(&bytes), &bytes)
                .is_err()
        );
    }
}

#[test]
fn content_closure_bounds_reference_arrays_before_decoding_their_members() {
    let empty = compute::Environment {
        sources: vec![],
        assets: vec![],
    }
    .canonical_bytes()
    .unwrap();
    for field in ["assets", "sources"] {
        let mut bytes = empty.clone();
        let mut needle = encode(&field).unwrap();
        needle.push(0x80);
        let offset = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap()
            + needle.len()
            - 1;
        let mut length = crate::DagCborEncoder::new();
        length.array((compute::MAX_ENVIRONMENT_REFERENCES + 1) as u64);
        let mut members = length.into_bytes();
        members.extend(std::iter::repeat_n(
            0,
            compute::MAX_ENVIRONMENT_REFERENCES + 1,
        ));
        bytes.splice(offset..offset + 1, members);
        assert!(bytes.len() <= compute::MAX_ENVIRONMENT_BYTES);
        let error = policy()
            .content_closure(&closure_manifest(&bytes), &bytes)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("too many compute content references"),
            "member decoding preceded the array bound: {error}"
        );
    }
    let bytes = vec![0; compute::MAX_ENVIRONMENT_BYTES + 1];
    let error = policy()
        .content_closure(&closure_manifest(&bytes), &bytes)
        .unwrap_err();
    assert!(error.to_string().contains("exceeds its byte budget"));
}

#[test]
fn content_closure_refuses_noncanonical_or_trailing_root_bytes_even_with_matching_hashes() {
    let root = compute::Environment {
        sources: vec![],
        assets: vec![],
    }
    .canonical_bytes()
    .unwrap();
    let mut trailing = root.clone();
    trailing.push(0);
    assert!(
        policy()
            .content_closure(&closure_manifest(&trailing), &trailing)
            .is_err()
    );
    let mut noncanonical = vec![0x98, 2];
    noncanonical.extend_from_slice(&root[1..]);
    assert!(
        policy()
            .content_closure(&closure_manifest(&noncanonical), &noncanonical)
            .is_err()
    );
    let key = encode(&"assets").unwrap();
    let fields = root
        .windows(key.len())
        .position(|bytes| bytes == key)
        .unwrap();
    let mut wrong_count = root.clone();
    assert_eq!(wrong_count[fields - 1], 0xa2);
    wrong_count[fields - 1] = 0xa3;
    assert!(
        policy()
            .content_closure(&closure_manifest(&wrong_count), &wrong_count)
            .is_err()
    );
    let mut reordered = root[..fields].to_vec();
    reordered.extend_from_slice(&encode(&"sources").unwrap());
    reordered.push(0x80);
    reordered.extend_from_slice(&key);
    reordered.push(0x80);
    assert!(
        policy()
            .content_closure(&closure_manifest(&reordered), &reordered)
            .is_err()
    );
}

#[test]
fn compute_evaluator_matches_locked_catena_revision() {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
    let mut packages = lock
        .split("\n[[package]]\n")
        .filter(|package| package.lines().any(|line| line == "name = \"catena-lang\""));
    let package = packages.next().expect("catena-lang is locked");
    assert!(packages.next().is_none(), "multiple catena-lang revisions");
    let revision = package
        .lines()
        .find_map(|line| {
            line.strip_prefix(
                "source = \"git+https://github.com/hellas-ai/catena-lang.git?branch=master#",
            )
            .and_then(|source| source.strip_suffix('"'))
        })
        .expect("catena-lang is pinned to upstream master");
    assert_eq!(revision.len(), 40);
    assert!(revision.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        compute::EVALUATOR,
        format!("hellas/catena-{}", &revision[..12]),
        "compute evaluator must identify the locked Catena compiler"
    );
}
