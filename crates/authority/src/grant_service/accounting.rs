//! Meter only a fully verified transcript. Unknown Fetch usage settles at the
//! signed reserve; native Evaluate's terminal supplies exact token counts.
use crate::model::grant::{
    budget::{Charge, Meter, Usage},
    records::GrantPolicy,
};
use crate::model::http_usage::{AccountingProfile, Mode, UsageDecoder};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_channel::model::profile::WorkPolicy;
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent};
use std::time::Duration;

pub(super) fn usage(
    policy: &GrantPolicy,
    events: &[OutputEventEnvelope],
    elapsed: Option<Duration>,
) -> Usage {
    observed(policy, events, elapsed).map_or(Usage::Unknown, Usage::Observed)
}
fn observed(
    policy: &GrantPolicy,
    events: &[OutputEventEnvelope],
    elapsed: Option<Duration>,
) -> Option<Charge> {
    let mut charge = Charge::default();
    charge.set(Meter::Requests, 1);
    if matches!(policy.work, WorkPolicy::Evaluate(_)) {
        let terminal =
            hellas_rpc::evaluate::decode_terminal_payload(events.last()?.payload()).ok()?;
        charge.set(Meter::InputTokens, terminal.usage.input_units);
        charge.set(Meter::OutputTokens, terminal.usage.output_units);
        charge.set(
            Meter::DeviceMillis,
            elapsed?.as_millis().min(u128::from(u64::MAX)) as u64,
        );
        return Some(charge);
    }
    if policy.responses.is_some() {
        let hellas_rpc::fetch::FetchTerminalPayload::Finished { usage, .. } =
            hellas_rpc::fetch::decode_fetch_terminal_payload(events.last()?.payload()).ok()?;
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
    let Some(resource) = &policy.https else {
        return Some(charge);
    };
    if resource.accounting == AccountingProfile::None {
        return Some(charge);
    }
    let mut decoder = UsageDecoder::new(Mode::Strict(resource.accounting), None, None);
    let mut head = false;
    for event in events {
        if event.event().body().kind() != hellas_rpc::fetch::OUTPUT_EVENT_KIND {
            continue;
        }
        match hellas_rpc::fetch::decode_fetch_event_payload(event.payload()).ok()? {
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
    use hellas_auth::Digest;
    use hellas_rpc::{Assurance, InputCommitment, fetch::FetchOutputTranscriptBuilder};

    fn transcript(usage: Option<hellas_rpc::output::Usage>) -> Vec<OutputEventEnvelope> {
        let key = hellas_channel::test_support::principal(2).1;
        FetchOutputTranscriptBuilder::new(
            InputCommitment::from_digest(Digest::hash(b"accounting fixture")),
            Assurance::ProducerSigned,
            &key,
        )
        .finish(
            hellas_rpc::fetch::encode_fetch_terminal_payload(&OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage,
            })
            .unwrap(),
        )
        .unwrap()
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
                usage(&policy, &events, None),
                Usage::Observed(Charge([1, 0, output, 0, 0]))
            );
        }
        let events = transcript(Some(hellas_rpc::output::Usage {
            input_tokens: Some(3),
            output_tokens: Some(2),
            total_tokens: Some(5),
        }));
        assert_eq!(
            usage(&policy, &events, None),
            Usage::Observed(Charge([1, 0, 2, 0, 0]))
        );
        assert_eq!(usage(&policy, &[], None), Usage::Unknown);
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
            assert_eq!(usage(&policy, &transcript(observed), None), Usage::Unknown);
        }
    }
}
