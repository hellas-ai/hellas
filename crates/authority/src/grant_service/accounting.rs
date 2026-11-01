//! Meter only fully verified application output. Generic invocations cost one request.
use crate::model::grant::{
    budget::{Charge, Meter, Usage},
    records::GrantPolicy,
};
use crate::model::http_usage::{AccountingProfile, Mode, UsageDecoder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::http_fetch::HttpFetchRequest;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent};
use hellas_rpc::protocol::invocation::output::InvocationOutput;

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
    /// a 4xx body or a prefix that reached the caller's signed cap does not.
    fn incomplete(status: Option<u16>, body_bytes: usize, request: &HttpFetchRequest) -> Self {
        if body_bytes as u64 >= u64::from(request.max_response_bytes)
            || status.is_some_and(|status| (400..500).contains(&status))
        {
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
        // Inspect that prefix so a caller-capped or rejected exchange is not
        // mistaken for a corrupt backend.
        let Some((status, body_bytes)) = failed_prefix(output) else {
            return Verdict::Fault;
        };
        return Verdict::incomplete(status, body_bytes, &request);
    };
    let (events, _) = response.output_event_payloads();
    let mut decoder = UsageDecoder::new(Mode::Strict(resource.accounting), None, None);
    let mut head = false;
    let mut status = None;
    let mut body_bytes = 0usize;
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
                    return Verdict::incomplete(status, body_bytes, &request);
                };
                let Some(content_encoding) = header("content-encoding") else {
                    return Verdict::incomplete(status, body_bytes, &request);
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
                body_bytes = body_bytes.saturating_add(bytes.len());
                decoder.push(&bytes);
            }
            _ => return Verdict::Fault,
        }
    }
    decoder.finish();
    let Ok((_, output)) = decoder.strict_usage() else {
        return Verdict::incomplete(status, body_bytes, &request);
    };
    charge.set(Meter::OutputTokens, output);
    Verdict::Observed(charge)
}
/// The status and complete body bytes carried by a failed execution's
/// authenticated response-event prefix, if it is structurally readable.
fn failed_prefix(output: &InvocationOutput) -> Option<(Option<u16>, usize)> {
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
    let mut body_bytes = 0usize;
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
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 }))
                if status.is_some() =>
            {
                body_bytes = body_bytes.saturating_add(STANDARD.decode(base64).ok()?.len());
            }
            _ => return None,
        }
    }
    Some((status, body_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::Assurance;

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
