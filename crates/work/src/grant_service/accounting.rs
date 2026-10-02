//! Meter only a fully verified transcript. Unknown HTTP usage settles at the
//! signed reserve; native Evaluate's terminal supplies exact token counts.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::OutputEventEnvelope;
use hellas_rpc::http_usage::{AccountingProfile, Mode, UsageDecoder};
use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent};
use hellas_rpc::protocol::work_grant::{
    budget::{Charge, Meter, Usage},
    records::GrantPolicy,
};
use hellas_rpc::protocol::work_profile::WorkPolicy;
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
