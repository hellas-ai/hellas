//! Meter only fully verified application output. Generic invocations cost one request.
use crate::model::grant::{
    budget::{Charge, Meter, Usage},
    records::GrantPolicy,
};
use crate::model::http_usage::{AccountingProfile, Mode, UsageDecoder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent};
use hellas_rpc::protocol::invocation::output::{FailureReason, InvocationOutput, Outcome};

/// A conservative charge plus whether the incomplete result is evidence
/// against the shared backend. Caller-selected caps and upstream rejections
/// settle as unknown without quarantining a healthy resource.
pub(super) struct UsageObservation {
    pub usage: Usage,
    pub fault: bool,
}
pub(super) fn usage(
    policy: &GrantPolicy,
    domain: hellas_rpc::protocol::invocation::CapacityDomain,
    input: &hellas_rpc::protocol::invocation::PreparedInvocation,
    output: &InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> UsageObservation {
    match observed(policy, domain, input, output, provider) {
        Verdict::Observed(charge) => UsageObservation {
            usage: Usage::Observed(charge),
            fault: false,
        },
        Verdict::NoFault => UsageObservation {
            usage: Usage::Unknown,
            fault: false,
        },
        Verdict::Fault => UsageObservation {
            usage: Usage::Unknown,
            fault: true,
        },
    }
}
enum Verdict {
    Observed(Charge),
    /// Incomplete for reasons the caller or the upstream exchange controls.
    NoFault,
    /// The provider's result is missing, unverifiable or unaccountable.
    Fault,
}
impl Verdict {
    /// A verified 2xx body that still cannot be metered faults the backend;
    /// a 4xx body does not. A caller-selected cap is signed on the output as
    /// [`FailureReason::CallerLimit`] instead of being inferred from bytes.
    fn incomplete(status: Option<u16>) -> Self {
        if status.is_some_and(|status| (400..500).contains(&status)) {
            Self::NoFault
        } else {
            Self::Fault
        }
    }
}
fn observed(
    policy: &GrantPolicy,
    domain: hellas_rpc::protocol::invocation::CapacityDomain,
    input: &hellas_rpc::protocol::invocation::PreparedInvocation,
    output: &InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Verdict {
    let mut charge = Charge::default();
    charge.set(Meter::Requests, 1);
    // The provider that enforced the caller's signed cap signs this reason
    // into the authenticated output; it is not a backend failure.
    if matches!(output.outcome, Outcome::Failed(FailureReason::CallerLimit)) {
        return Verdict::NoFault;
    }
    if domain == hellas_rpc::protocol::invocation::CapacityDomain::Gpu {
        return Verdict::Observed(charge);
    }
    let Ok(parameters) = hellas_rpc::protocol::invocation::fetch::Parameters::from_canonical_bytes(
        input.input.parameters.as_bytes(),
    ) else {
        return Verdict::NoFault;
    };
    if policy.responses.is_none() && policy.https.is_none() {
        return Verdict::Observed(charge);
    }
    if parameters.contract.schema() == hellas_rpc::FetchSchema::StatelessResponsesV1 {
        let Ok(response) = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider)
        else {
            return Verdict::Fault;
        };
        let (_, terminal) = response.output_event_payloads();
        let Ok(hellas_rpc::fetch::FetchTerminalPayload::Finished { usage, .. }) =
            hellas_rpc::fetch::decode_fetch_terminal_payload(terminal)
        else {
            return Verdict::Fault;
        };
        let Some(usage) = usage else {
            return Verdict::Fault;
        };
        let Some(output) = usage.output_tokens else {
            return Verdict::Fault;
        };
        if let Some(total) = usage.total_tokens
            && (total < output
                || usage
                    .input_tokens
                    .is_some_and(|input| input.checked_add(output) != Some(total)))
        {
            return Verdict::Fault;
        }
        charge.set(Meter::OutputTokens, output);
        return Verdict::Observed(charge);
    }
    let Some(resource) = policy.https.as_ref() else {
        return Verdict::NoFault;
    };
    if resource.accounting == AccountingProfile::None {
        return Verdict::Observed(charge);
    }
    // Admission permits empty GET/HEAD requests on unmodelled health paths
    // without reserving output tokens. Classify the same signed request at
    // settlement so a non-generating response cannot fault the resource.
    let [artifact] = input.input.artifacts.as_slice() else {
        return Verdict::NoFault;
    };
    let Ok(signed_events) =
        hellas_rpc::protocol::value::decode_canonical_dag_cbor::<Vec<_>>(artifact.bytes.as_bytes())
    else {
        return Verdict::NoFault;
    };
    let Ok(signed) = hellas_rpc::fetch::verify_input_events(&signed_events) else {
        return Verdict::NoFault;
    };
    let Ok(request) = hellas_rpc::http_fetch::HttpFetchRequest::decode(signed.body.as_bytes())
    else {
        return Verdict::NoFault;
    };
    if matches!(request.method.as_str(), "GET" | "HEAD")
        && request.body().is_ok_and(|body| body.is_empty())
        && resource.matches(&request).ok() == Some(0)
    {
        return Verdict::Observed(charge);
    }
    let Ok(response) = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider)
    else {
        if output.is_success() {
            return Verdict::Fault;
        }
        // A failed execution still carries its authenticated event prefix.
        // Its head distinguishes an upstream rejection from a corrupt backend;
        // a caller-capped failure already carries its signed reason above.
        let Some(status) = failed_status(output) else {
            return Verdict::Fault;
        };
        return Verdict::incomplete(Some(status));
    };
    let (events, _) = response.output_event_payloads();
    let mut decoder = UsageDecoder::new(Mode::Strict(resource.accounting), None, None);
    let mut head = false;
    let mut status = None;
    for event in events {
        match hellas_rpc::fetch::decode_fetch_event_payload(event) {
            Ok(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: head_status,
                headers,
            }))) => {
                if head {
                    return Verdict::Fault;
                }
                head = true;
                status = Some(head_status);
                let header = |key: &str| -> Option<Option<&str>> {
                    let mut values = headers
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case(key))
                        .map(|(_, v)| v.as_str());
                    let value = values.next();
                    values.next().is_none().then_some(value)
                };
                let Some(content_type) = header("content-type") else {
                    return Verdict::incomplete(status);
                };
                let Some(content_encoding) = header("content-encoding") else {
                    return Verdict::incomplete(status);
                };
                decoder.content(content_type, content_encoding);
            }
            Ok(OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 }))) => {
                if !head {
                    return Verdict::Fault;
                }
                let Ok(bytes) = STANDARD.decode(base64) else {
                    return Verdict::Fault;
                };
                decoder.push(&bytes);
            }
            _ => return Verdict::Fault,
        }
    }
    decoder.finish();
    let Ok((_, output)) = decoder.strict_usage() else {
        return Verdict::incomplete(status);
    };
    charge.set(Meter::OutputTokens, output);
    Verdict::Observed(charge)
}
/// The status carried by a failed execution's authenticated response-event
/// prefix, if it is structurally readable.
fn failed_status(output: &InvocationOutput) -> Option<u16> {
    let [artifact] = output.artifacts.as_slice() else {
        return None;
    };
    if artifact.name != hellas_rpc::protocol::invocation::fetch::RESPONSE_EVENTS
        || artifact.format != hellas_rpc::protocol::invocation::fetch::RESPONSE_EVENTS_FORMAT
    {
        return None;
    }
    let mut remaining = artifact.bytes.as_bytes();
    let mut status = None;
    while !remaining.is_empty() {
        let header = remaining.get(..4)?;
        let len = u32::from_be_bytes(header.try_into().ok()?) as usize;
        remaining = &remaining[4..];
        // A failed live stream can end midway through its final event frame.
        let Some(payload) = remaining.get(..len) else {
            break;
        };
        remaining = &remaining[len..];
        match hellas_rpc::fetch::decode_fetch_event_payload(payload).ok()? {
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: head_status,
                ..
            })) if status.is_none() => status = Some(head_status),
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { .. }))
                if status.is_some() => {}
            _ => return None,
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::Assurance;
    use hellas_rpc::http_fetch::HttpFetchRequest;

    fn transcript(usage: Option<hellas_rpc::output::Usage>) -> InvocationOutput {
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: hellas_rpc::output::StopReason::EndOfText,
            usage,
        })
        .unwrap();
        hellas_rpc::protocol::invocation::fetch::output(&[], &terminal).unwrap()
    }
    fn metered(policy: &GrantPolicy, output: &InvocationOutput) -> Usage {
        let key = hellas_channel::test_support::principal(1).1;
        let contract = hellas_channel::test_support::test_responses_contract();
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            b"{}",
            contract.manifest_id(),
            Assurance::ProducerSigned,
            &key,
            hellas_rpc::Retention::Ephemeral,
        )
        .unwrap();
        let provider = hellas_channel::test_support::principal(2).1.public_key();
        let input = hellas_rpc::protocol::invocation::fetch::prepare(
            &events,
            &contract,
            provider,
            policy.invocation_policy.canonical_bytes().unwrap(),
            [1; 32],
        )
        .unwrap();
        super::usage(
            policy,
            hellas_rpc::protocol::invocation::CapacityDomain::Fetch,
            &input,
            output,
            &provider,
        )
        .usage
    }

    #[test]
    fn responses_meter_the_final_output_count_including_zero_and_overruns() {
        let policy = crate::test_support::policy();
        for output in [0, 2, 8, 9, u64::MAX] {
            // Input is not reserved by this schema; a known output count does not
            // authorize charging an unbounded input meter.
            let events = transcript(Some(hellas_rpc::output::Usage {
                input_tokens: None,
                output_tokens: Some(output),
                total_tokens: None,
            }));
            assert_eq!(
                metered(&policy, &events),
                Usage::Observed(Charge([1, 0, output, 0, 0]))
            );
        }
        let events = transcript(Some(hellas_rpc::output::Usage {
            input_tokens: Some(3),
            output_tokens: Some(2),
            total_tokens: Some(5),
        }));
        assert_eq!(
            metered(&policy, &events),
            Usage::Observed(Charge([1, 0, 2, 0, 0]))
        );
        assert_eq!(
            metered(
                &policy,
                &InvocationOutput {
                    outcome: hellas_rpc::protocol::invocation::output::Outcome::Succeeded,
                    artifacts: vec![],
                    metadata: hellas_rpc::JsonBytes(vec![])
                }
            ),
            Usage::Unknown
        );
    }

    fn http_input(
        policy: &GrantPolicy,
    ) -> (
        hellas_rpc::protocol::invocation::PreparedInvocation,
        hellas_auth::ProducerSigningKey,
    ) {
        let key = hellas_channel::test_support::principal(2).1;
        let contract = hellas_rpc::FetchContract::http().unwrap();
        let request = HttpFetchRequest {
            url: "https://glm.test/v1/chat/completions".into(),
            method: "POST".into(),
            headers: vec![],
            body_base64: String::new(),
            tls: hellas_rpc::http_fetch::HttpTls {
                roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            credential: None,
            max_response_bytes: 1,
        };
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai",
            "responses",
            &serde_json::to_vec(&request).unwrap(),
            contract.manifest_id(),
            Assurance::ProducerSigned,
            &hellas_channel::test_support::principal(1).1,
            hellas_rpc::Retention::Ephemeral,
        )
        .unwrap();
        let input = hellas_rpc::protocol::invocation::fetch::prepare(
            &events,
            &contract,
            key.public_key(),
            policy.invocation_policy.canonical_bytes().unwrap(),
            [1; 32],
        )
        .unwrap();
        (input, key)
    }

    /// Sign a failed HTTP result whose authenticated prefix is the response
    /// head and no body bytes, as the provider produces at a signed cap.
    fn http_failure(
        input: &hellas_rpc::protocol::invocation::PreparedInvocation,
        key: &hellas_auth::ProducerSigningKey,
        reason: FailureReason,
    ) -> InvocationOutput {
        use hellas_rpc::protocol::invocation::output::{OutputStream, verify};
        let head = hellas_rpc::fetch::encode_fetch_event_payload(&OutputEvent::Adaptor(
            AdaptorEvent::Http(HttpResponseEvent::Head {
                status: 200,
                headers: vec![
                    ("content-type".into(), "text/event-stream".into()),
                    ("content-encoding".into(), "identity".into()),
                ],
            }),
        ))
        .unwrap();
        let mut framed = (head.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&head);
        let mut stream = OutputStream::new(&input.request, key, 65_536).unwrap();
        stream
            .push(
                hellas_rpc::protocol::invocation::fetch::RESPONSE_EVENTS,
                hellas_rpc::protocol::invocation::fetch::RESPONSE_EVENTS_FORMAT,
                0,
                &framed,
            )
            .unwrap();
        let (_, events) = stream.fail(reason).unwrap();
        verify(&input.request, &key.public_key(), &events, 65_536).unwrap()
    }

    fn http_observation(
        policy: &GrantPolicy,
        input: &hellas_rpc::protocol::invocation::PreparedInvocation,
        key: &hellas_auth::ProducerSigningKey,
        reason: FailureReason,
    ) -> UsageObservation {
        let output = http_failure(input, key, reason);
        super::usage(
            policy,
            hellas_rpc::protocol::invocation::CapacityDomain::Fetch,
            input,
            &output,
            &key.public_key(),
        )
    }

    fn http_policy() -> GrantPolicy {
        let mut policy = crate::test_support::policy();
        crate::test_support::use_https(
            &mut policy,
            crate::test_support::chat_resource("https://glm.test", 8),
        );
        policy
    }

    #[test]
    fn a_signed_caller_limit_is_not_a_backend_fault() {
        let policy = http_policy();
        let (input, key) = http_input(&policy);
        let observation = http_observation(&policy, &input, &key, FailureReason::CallerLimit);
        assert_eq!(observation.usage, Usage::Unknown);
        assert!(!observation.fault);
    }

    #[test]
    fn the_same_prefix_with_an_execution_failure_still_faults() {
        let policy = http_policy();
        let (input, key) = http_input(&policy);
        let observation = http_observation(&policy, &input, &key, FailureReason::Execution);
        assert_eq!(observation.usage, Usage::Unknown);
        assert!(observation.fault);
    }

    #[test]
    fn missing_output_or_contradictory_totals_never_turn_into_a_zero_charge() {
        let policy = crate::test_support::policy();
        for observed in [
            None,
            Some(hellas_rpc::output::Usage {
                input_tokens: Some(3),
                output_tokens: None,
                total_tokens: Some(3),
            }),
            Some(hellas_rpc::output::Usage {
                input_tokens: Some(3),
                output_tokens: Some(2),
                total_tokens: Some(4),
            }),
            Some(hellas_rpc::output::Usage {
                input_tokens: None,
                output_tokens: Some(2),
                total_tokens: Some(1),
            }),
            Some(hellas_rpc::output::Usage {
                input_tokens: Some(u64::MAX),
                output_tokens: Some(2),
                total_tokens: Some(1),
            }),
        ] {
            assert_eq!(metered(&policy, &transcript(observed)), Usage::Unknown);
        }
    }
}
