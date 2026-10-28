//! Meter only fully verified application output. Generic invocations cost one request.
use crate::model::grant::{
    budget::{Charge, Meter, Usage},
    records::GrantPolicy,
};
use crate::model::http_usage::{AccountingProfile, Mode, UsageDecoder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent};
use hellas_rpc::protocol::invocation::output::InvocationOutput;

pub(super) fn usage(
    policy: &GrantPolicy,
    domain: hellas_rpc::protocol::invocation::CapacityDomain,
    input: &hellas_rpc::protocol::invocation::PreparedInvocation,
    output: &InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Usage {
    observed(policy, domain, input, output, provider).map_or(Usage::Unknown, Usage::Observed)
}
fn observed(
    policy: &GrantPolicy,
    domain: hellas_rpc::protocol::invocation::CapacityDomain,
    input: &hellas_rpc::protocol::invocation::PreparedInvocation,
    output: &InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Option<Charge> {
    let mut charge = Charge::default();
    charge.set(Meter::Requests, 1);
    if domain == hellas_rpc::protocol::invocation::CapacityDomain::Gpu {
        return Some(charge);
    }
    let parameters = hellas_rpc::protocol::invocation::fetch::Parameters::from_canonical_bytes(
        input.input.parameters.as_bytes(),
    )
    .ok()?;
    if policy.responses.is_none() && policy.https.is_none() {
        return Some(charge);
    }
    let output = hellas_rpc::protocol::invocation::fetch::decode_output(output, provider).ok()?;
    let (events, terminal) = output.output_event_payloads();
    if parameters.contract.schema() == hellas_rpc::FetchSchema::StatelessResponsesV1 {
        let hellas_rpc::fetch::FetchTerminalPayload::Finished { usage, .. } =
            hellas_rpc::fetch::decode_fetch_terminal_payload(terminal).ok()?;
        let usage = usage?;
        let output = usage.output_tokens?;
        if let Some(total) = usage.total_tokens
            && (total < output
                || usage
                    .input_tokens
                    .is_some_and(|input| input.checked_add(output) != Some(total)))
        {
            return None;
        }
        charge.set(Meter::OutputTokens, output);
        return Some(charge);
    }
    let resource = policy.https.as_ref()?;
    if resource.accounting == AccountingProfile::None {
        return Some(charge);
    }
    let mut decoder = UsageDecoder::new(Mode::Strict(resource.accounting), None, None);
    let mut head = false;
    for event in events {
        match hellas_rpc::fetch::decode_fetch_event_payload(event).ok()? {
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                status: _,
                headers,
            })) => {
                if head {
                    return None;
                }
                head = true;
                let header = |key: &str| -> Option<Option<&str>> {
                    let mut values = headers
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case(key))
                        .map(|(_, v)| v.as_str());
                    let value = values.next();
                    values.next().is_none().then_some(value)
                };
                decoder.content(header("content-type")?, header("content-encoding")?);
            }
            OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body { base64 })) => {
                if !head {
                    return None;
                }
                decoder.push(&STANDARD.decode(base64).ok()?);
            }
            _ => return None,
        }
    }
    decoder.finish();
    let (_, output) = decoder.strict_usage().ok()?;
    charge.set(Meter::OutputTokens, output);
    Some(charge)
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
