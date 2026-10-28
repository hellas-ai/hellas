use super::*;
use crate::model::grant::ChannelId;
use crate::model::work::{PrivateRecord, next_payment};
use crate::test_support::channel as fixture;
use hellas_auth::authority::{GrantId, ResourceId, Revision, UnixMillis};
use hellas_rpc::JsonBytes;
use hellas_rpc::protocol::invocation::output::{FailureReason, InvocationOutput, Outcome};

fn grant(a: &PaidJobAuthorizationV2) -> GrantJobAuthorizationV1 {
    GrantJobAuthorizationV1 {
        channel_id: ChannelId(a.channel_id),
        generation: 0,
        grant_id: GrantId([7; 16]),
        grant_revision: Revision(1),
        resource_id: ResourceId(Digest::hash(b"resource")),
        resource_revision: Revision(1),
        pricing_revision: Revision(1),
        work_policy_digest: a.work_policy_digest,
        input_content: a.input_content,
        prepared_input_digest: a.prepared_input_digest,
        proposal_nonce: a.proposal_nonce,
        acceptance_deadline_ms: UnixMillis(100),
        request_commitment: a.request_commitment,
        environment_commitment: a.environment_commitment,
        terminal_deadline_ms: UnixMillis(200),
        delivery_deadline_ms: UnixMillis(300),
    }
}
#[test]
fn every_invocation_binding_is_checked_for_both_funding_forms() {
    let ready = fixture::ready();
    let context = WorkContext::from(ready.channel());
    let policy = fixture::work_policy();
    let paid_input = fixture::bundle(1);
    let paid = propose(
        ready.channel(),
        &policy,
        &fixture::payment_policy(),
        &paid_input,
        1,
        fixture::deadlines(),
    )
    .unwrap();
    let mut granted_input = paid_input.clone();
    granted_input.request.retain = false;
    let granted = grant(
        &propose(
            ready.channel(),
            &policy,
            &fixture::payment_policy(),
            &granted_input,
            1,
            fixture::deadlines(),
        )
        .unwrap(),
    );
    for (input, binding) in [
        (&paid_input, JobInputBinding::from(&paid)),
        (&granted_input, JobInputBinding::from(&granted)),
    ] {
        assert!(check_input(&context, &binding, &policy, input).is_ok());
        let changes: &[fn(&mut JobInputBinding)] = &[
            |a| a.work_policy_digest = Digest::hash(b"another policy"),
            |a| {
                a.input_content = ContentRef::new(a.input_content.id(), a.input_content.bytes() + 1)
            },
            |a| a.prepared_input_digest = Digest::hash(b"another prepared input"),
            |a| {
                a.request_commitment =
                    RequestCommitment::from_digest(Digest::hash(b"another request"))
            },
            |a| a.environment_commitment = ContentId::hash(b"another manifest"),
            |a| {
                a.retention = if a.retention == Retention::Retain {
                    Retention::Ephemeral
                } else {
                    Retention::Retain
                }
            },
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut changed = binding;
            change(&mut changed);
            assert!(
                check_input(&context, &changed, &policy, input).is_err(),
                "unbound funded input field {index}"
            );
        }
    }
}
#[test]
fn fresh_authorizations_cannot_admit_another_provider_or_owner_policy() {
    let ready = fixture::ready();
    let policy = fixture::work_policy();
    for provider in [false, true] {
        let mut input = fixture::bundle(1);
        if provider {
            input.request.runner_public_key =
                PublicKey::Secp256k1(fixture::signer(0x23).party_key().to_bytes());
        } else {
            let mut other = policy.clone();
            other.limits.max_output_bytes += 1;
            input.application_policy = JsonBytes(other.canonical_bytes().unwrap());
        }
        let authorization = propose(
            ready.channel(),
            &policy,
            &fixture::payment_policy(),
            &input,
            1,
            fixture::deadlines(),
        )
        .unwrap();
        assert!(check_paid_input(ready.channel(), &authorization, &policy, &input).is_err());
    }
}
#[test]
fn grants_override_compute_retention_and_paid_compute_cannot_bypass_it() {
    let ready = fixture::ready();
    let policy = fixture::work_policy();
    let mut input = fixture::bundle(1);
    input.request.retain = false;
    let authorization = propose(
        ready.channel(),
        &policy,
        &fixture::payment_policy(),
        &input,
        1,
        fixture::deadlines(),
    )
    .unwrap();
    assert!(check_paid_input(ready.channel(), &authorization, &policy, &input).is_err());
    assert!(
        check_input(
            &ready.channel().into(),
            &(&grant(&authorization)).into(),
            &policy,
            &input
        )
        .is_ok()
    );
    input.request.retain = true;
    let retained = propose(
        ready.channel(),
        &policy,
        &fixture::payment_policy(),
        &input,
        1,
        fixture::deadlines(),
    )
    .unwrap();
    assert!(
        check_input(
            &ready.channel().into(),
            &(&grant(&retained)).into(),
            &policy,
            &input
        )
        .is_err()
    );
}
#[test]
fn signed_failed_terminals_are_authentic_and_never_payable() {
    let ready = fixture::ready();
    let input = fixture::bundle(1);
    let policy = fixture::work_policy();
    let authorization = propose(
        ready.channel(),
        &policy,
        &fixture::payment_policy(),
        &input,
        1,
        fixture::deadlines(),
    )
    .unwrap();
    let events = InvocationOutput {
        outcome: Outcome::Failed(FailureReason::Execution),
        artifacts: vec![],
        metadata: JsonBytes(vec![]),
    }
    .sign(&input.request, &fixture::provider_producer(), 1024)
    .unwrap();
    let result =
        paid_terminal_result(ready.channel(), &authorization, &policy, &input, &events).unwrap();
    assert_eq!(result.outcome, ResultOutcome::Failed);
    assert_eq!(PaidJobResultV1::decode(&result.encode()).unwrap(), result);
    assert!(
        next_payment(
            ready.channel(),
            &authorization,
            &result,
            0,
            fixture::settlement()
        )
        .is_err()
    );
    let mut unknown = result.encode();
    unknown[2 + 3 * 32] = 2;
    assert!(PaidJobResultV1::decode(&unknown).is_err());
}
#[test]
fn verification_accepts_signed_declared_shapes_without_reexecuting_the_program() {
    let ready = fixture::ready();
    let input = fixture::bundle(1);
    let policy = fixture::work_policy();
    let authorization = propose(
        ready.channel(),
        &policy,
        &fixture::payment_policy(),
        &input,
        1,
        fixture::deadlines(),
    )
    .unwrap();
    let events = fixture::transcript_for(&input.request, &[999, 42]);
    let result =
        paid_terminal_result(ready.channel(), &authorization, &policy, &input, &events).unwrap();
    assert_eq!(result.outcome, ResultOutcome::Finished);
    assert!(
        check_result(
            &ready.channel().into(),
            work_id(ready.channel(), &authorization),
            &(&authorization).into(),
            &policy,
            &input,
            &events,
            &result
        )
        .is_ok()
    );
}

#[test]
fn every_prepared_invocation_and_policy_field_is_bound_for_paid_and_grant_inputs() {
    use hellas_rpc::protocol::invocation::{Admission, Artifact};
    let ready = fixture::ready();
    let policy = fixture::work_policy();
    for granted in [false, true] {
        let mut input = fixture::bundle(1);
        input.request.retain = !granted;
        input
            .input
            .artifacts
            .push(Artifact::new("seed", "catena.bytes.v1", vec![1]));
        input.request.input = input.input.content_id().unwrap();
        let a = propose(
            ready.channel(),
            &policy,
            &fixture::payment_policy(),
            &input,
            1,
            fixture::deadlines(),
        )
        .unwrap();
        let binding = if granted {
            JobInputBinding::from(&grant(&a))
        } else {
            JobInputBinding::from(&a)
        };
        let context = WorkContext::from(ready.channel());
        assert!(check_input(&context, &binding, &policy, &input).is_ok());
        let changes: &[fn(&mut PreparedInvocation)] = &[
            |p| p.request.execution_environment = ContentId::hash(b"foreign environment"),
            |p| p.request.input = ContentId::hash(b"foreign input"),
            |p| {
                p.request.runner_public_key =
                    PublicKey::Secp256k1(fixture::signer(0x23).party_key().to_bytes())
            },
            |p| p.request.nonce[0] ^= 1,
            |p| p.request.assurance = hellas_rpc::Assurance::AppleAppAttest,
            |p| p.request.retain = !p.request.retain,
            |p| {
                p.input.parameters.0.push(0);
                p.request.input = p.input.content_id().unwrap();
            },
            |p| {
                p.input.artifacts[0].name = "other".into();
                p.request.input = p.input.content_id().unwrap();
            },
            |p| {
                p.input.artifacts[0].format = "other.format.v1".into();
                p.request.input = p.input.content_id().unwrap();
            },
            |p| {
                p.input.artifacts[0].bytes.0[0] ^= 1;
                p.request.input = p.input.content_id().unwrap();
            },
            |p| p.application_policy.0.push(0),
            |p| {
                let old = p.manifest().unwrap();
                let manifest = hellas_rpc::ProgramManifest::new(
                    old.application().clone(),
                    ContentId::hash(b"another root"),
                );
                p.request.execution_environment = manifest.content_id();
                *p = PreparedInvocation::new(
                    p.request.clone(),
                    &manifest,
                    p.input.clone(),
                    p.application_policy.0.clone(),
                )
                .unwrap();
            },
            |p| {
                let old = p.manifest().unwrap();
                let manifest = hellas_rpc::ProgramManifest::new(
                    hellas_rpc::Application::new("other/evaluator", old.application().adaptor())
                        .unwrap(),
                    old.root(),
                );
                p.request.execution_environment = manifest.content_id();
                *p = PreparedInvocation::new(
                    p.request.clone(),
                    &manifest,
                    p.input.clone(),
                    p.application_policy.0.clone(),
                )
                .unwrap();
            },
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut changed = input.clone();
            change(&mut changed);
            assert!(
                check_input(&context, &binding, &policy, &changed).is_err(),
                "prepared field {index}, granted={granted}"
            );
            if let Ok(digest) = prepared_input_digest(ready.channel(), &changed) {
                assert_ne!(digest, binding.prepared_input_digest);
            }
        }
        let mut policies = Vec::new();
        for field in [
            "max_upload_bytes",
            "max_output_bytes",
            "max_steps",
            "execution_timeout_ms",
        ] {
            let mut value = serde_json::to_value(&policy).unwrap();
            value["limits"][field] =
                serde_json::json!(value["limits"][field].as_u64().unwrap() + 1);
            policies.push(serde_json::from_value::<InvocationPolicy>(value).unwrap());
        }
        let mut other = policy.clone();
        other.admissions = vec![Admission::Compute {
            evaluator: "other/evaluator".into(),
        }];
        policies.push(other);
        for changed in policies {
            assert_ne!(
                policy_digest(context.network, context.channel, &changed).unwrap(),
                binding.work_policy_digest
            );
            assert!(check_input(&context, &binding, &changed, &input).is_err());
        }
    }
}
