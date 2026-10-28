//! Fetch admission and its signed request events inside the common invocation.
use super::{bound, domain_is, encode, error};
use crate::FetchContract;
#[cfg(feature = "fetch")]
use crate::JsonBytes;
use crate::protocol::{
    fetch_contract::MAX_FETCH_ROUTE_COMPONENT_BYTES,
    value::{CanonicalDecodeError, CanonicalDecoder},
};
use serde::{Deserialize, Serialize};

/// Schema tag of the sealed-route body.
const SEALED_ROUTE_SCHEMA: &str = "hellas.work.fetch-route.sealed.v1";
/// Schema tag of the open-fetch body.
const OPEN_FETCH_SCHEMA: &str = "hellas.work.fetch-route.open.v1";

/// Canonical route policy. Its variable-length body is committed by digest in
/// the fixed-width `FetchPolicyV2` record and opened during input validation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FetchRoutePolicy {
    /// Requires the signed request to use this service and method.
    SealedRoute {
        /// The signed `service` component, e.g. `openai`.
        service: String,
        /// The signed `method` component, e.g. `responses`.
        method: String,
    },
    /// Caller-signed HTTPS URLs under the generic HTTP manifest. Host and
    /// required-pin constraints are checked before paid acceptance; the driver
    /// enforces normal certificate validation, DNS/address checks and no redirects.
    /// An empty host list permits any public host under the operator's egress policy.
    OpenFetch {
        /// Whether the driver must pin the upstream's SPKI.
        require_spki_pin: bool,
        /// Hosts the driver may egress to; empty means any public host.
        allowed_hosts: Vec<String>,
    },
}

impl FetchRoutePolicy {
    /// Builds a route with nonempty service and method components bounded by
    /// `MAX_FETCH_ROUTE_COMPONENT_BYTES`.
    pub fn sealed_route(
        service: impl Into<String>,
        method: impl Into<String>,
    ) -> Result<Self, RouteError> {
        let service = service.into();
        let method = method.into();
        if service.is_empty() {
            return Err(RouteError::EmptyService);
        }
        if method.is_empty() {
            return Err(RouteError::EmptyMethod);
        }
        if service.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
            return Err(RouteError::RouteComponentLimit {
                field: "service",
                actual: service.len(),
            });
        }
        if method.len() > MAX_FETCH_ROUTE_COMPONENT_BYTES {
            return Err(RouteError::RouteComponentLimit {
                field: "method",
                actual: method.len(),
            });
        }
        Ok(Self::SealedRoute { service, method })
    }

    /// Sorts and deduplicates the host allowlist before commitment. Admission checks
    /// exact hosts and required pins; the HTTPS driver checks certificates and addresses.
    #[must_use]
    pub fn open_fetch(require_spki_pin: bool, allowed_hosts: impl Into<Vec<String>>) -> Self {
        // Admission compares against Url::host_str, which is lowercase
        // punycode; normalize here so a host spelled with case or padding
        // can still match, and drop entries that never could.
        let mut allowed_hosts: Vec<String> = allowed_hosts
            .into()
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        allowed_hosts.sort_unstable();
        allowed_hosts.dedup();
        Self::OpenFetch {
            require_spki_pin,
            allowed_hosts,
        }
    }

    /// Canonical route encoding. The pin flag is encoded as integer 0 or 1.
    #[must_use]
    pub fn canonical_body_bytes(&self) -> Vec<u8> {
        let mut encoder = crate::DagCborEncoder::new();
        match self {
            Self::SealedRoute { service, method } => {
                encoder.array(3);
                encoder.str(SEALED_ROUTE_SCHEMA);
                encoder.str(service);
                encoder.str(method);
            }
            Self::OpenFetch {
                require_spki_pin,
                allowed_hosts,
            } => {
                encoder.array(3);
                encoder.str(OPEN_FETCH_SCHEMA);
                encoder.u64(u64::from(*require_spki_pin));
                encoder.array(allowed_hosts.len() as u64);
                for host in allowed_hosts {
                    encoder.str(host);
                }
            }
        }
        encoder.into_bytes()
    }

    /// Rejects unknown schemas, invalid components, noncanonical encodings and
    /// trailing bytes. Re-encoding must reproduce the input.
    pub fn from_canonical_body_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        let mut decoder = CanonicalDecoder::new(bytes);
        let len = decoder.array_len()?;
        let policy = match decoder.str()? {
            SEALED_ROUTE_SCHEMA => {
                if len != 3 {
                    return Err(CanonicalDecodeError::new(format!(
                        "{SEALED_ROUTE_SCHEMA} expected array length 3, got {len}"
                    )));
                }
                let service = decoder.str()?.to_string();
                let method = decoder.str()?.to_string();
                Self::sealed_route(service, method)
                    .map_err(|error| CanonicalDecodeError::new(error.to_string()))?
            }
            OPEN_FETCH_SCHEMA => {
                if len != 3 {
                    return Err(CanonicalDecodeError::new(format!(
                        "{OPEN_FETCH_SCHEMA} expected array length 3, got {len}"
                    )));
                }
                let require_spki_pin = match decoder.u64()? {
                    0 => false,
                    1 => true,
                    other => {
                        return Err(CanonicalDecodeError::new(format!(
                            "require_spki_pin must be 0 or 1, got {other}"
                        )));
                    }
                };
                let hosts = decoder.array_len()?;
                let mut allowed_hosts = Vec::with_capacity(hosts);
                for _ in 0..hosts {
                    allowed_hosts.push(decoder.str()?.to_string());
                }
                Self::open_fetch(require_spki_pin, allowed_hosts)
            }
            other => {
                return Err(CanonicalDecodeError::new(format!(
                    "unexpected fetch route schema tag {other:?}"
                )));
            }
        };
        decoder.finish()?;
        if policy.canonical_body_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "fetch route policy is not in canonical DAG-CBOR form",
            ));
        }
        Ok(policy)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("fetch service is empty")]
    EmptyService,
    #[error("fetch method is empty")]
    EmptyMethod,
    #[error("fetch route {field} is {actual} bytes, over its bound")]
    RouteComponentLimit { field: &'static str, actual: usize },
}

/// Fetch-specific bounds; upload, output bytes and execution time belong to the
/// common invocation limits signed by the provider's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchLimits {
    pub max_request_body_bytes: u32,
    pub max_output_events: u32,
    pub max_spool_bytes: u64,
    pub max_encoded_result_frame: u32,
    pub max_encoded_prepared_input: u32,
}
impl FetchLimits {
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        if self.max_request_body_bytes == 0
            || self.max_output_events == 0
            || self.max_spool_bytes == 0
            || self.max_encoded_result_frame == 0
            || self.max_encoded_prepared_input == 0
        {
            return Err(error("Fetch resource bounds must be positive"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchAdmission {
    pub contract: FetchContract,
    pub route: FetchRoutePolicy,
    pub limits: FetchLimits,
}
impl FetchAdmission {
    pub fn validate(&self) -> Result<(), CanonicalDecodeError> {
        self.limits.validate()?;
        FetchRoutePolicy::from_canonical_body_bytes(&self.route.canonical_body_bytes())?;
        Ok(())
    }
}

const PARAMETERS_DOMAIN: &str = "hellas.invocation.fetch-parameters.v1";
pub const REQUEST_EVENTS: &str = "request.events";
pub const REQUEST_EVENTS_FORMAT: &str = "hellas.fetch.input-events.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub contract: FetchContract,
}
impl Parameters {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalDecodeError> {
        encode(&(PARAMETERS_DOMAIN, self))
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalDecodeError> {
        bound(
            bytes,
            crate::protocol::fetch_contract::MAX_FETCH_CONTRACT_BYTES + 1024,
        )?;
        let (domain, parameters): (String, Self) =
            crate::protocol::value::decode_canonical_dag_cbor(bytes)?;
        domain_is(&domain, PARAMETERS_DOMAIN)?;
        Ok(parameters)
    }
}

#[cfg(feature = "fetch")]
pub fn prepare(
    events: &[crate::InputEventEnvelope],
    contract: &FetchContract,
    runner_public_key: hellas_auth::PublicKey,
    application_policy: Vec<u8>,
    nonce: [u8; 32],
) -> Result<super::PreparedInvocation, CanonicalDecodeError> {
    let input = crate::fetch::verify_input_events(events).map_err(|e| error(e.to_string()))?;
    if input.retention != crate::Retention::Ephemeral {
        return Err(error("paid Fetch requires an ephemeral signed request"));
    }
    if input.execution_environment != contract.manifest_id() {
        return Err(error("Fetch request does not name its contract"));
    }
    let input_body = super::InvocationInput {
        parameters: JsonBytes(
            Parameters {
                contract: contract.clone(),
            }
            .canonical_bytes()?,
        ),
        artifacts: vec![super::Artifact::new(
            REQUEST_EVENTS,
            REQUEST_EVENTS_FORMAT,
            encode(&events)?,
        )],
    };
    let request = super::InvocationRequest {
        execution_environment: contract.manifest_id(),
        input: input_body.content_id()?,
        runner_public_key,
        assurance: input.assurance,
        retain: input.retention.should_retain(),
        nonce,
    };
    super::PreparedInvocation::new(
        request,
        &contract.manifest(),
        input_body,
        application_policy,
    )
}

#[cfg(feature = "fetch")]
pub fn validate_input(
    prepared: &super::PreparedInvocation,
    admission: &FetchAdmission,
    max_output_bytes: u64,
    caller: &hellas_auth::PublicKey,
) -> Result<crate::fetch::FetchInput, CanonicalDecodeError> {
    use crate::{FetchEgress, FetchSchema};
    prepared.validate()?;
    admission.validate()?;
    if prepared.canonical_bytes()?.len() > admission.limits.max_encoded_prepared_input as usize {
        return Err(error("Fetch prepared input exceeds limit"));
    }
    let parameters = Parameters::from_canonical_bytes(prepared.input.parameters.as_bytes())?;
    if parameters.contract != admission.contract
        || parameters.contract.manifest() != prepared.manifest()?
    {
        return Err(error("Fetch contract does not match the admitted manifest"));
    }
    let [artifact] = prepared.input.artifacts.as_slice() else {
        return Err(error("Fetch requires exactly its signed request events"));
    };
    if artifact.name != REQUEST_EVENTS || artifact.format != REQUEST_EVENTS_FORMAT {
        return Err(error("Fetch request artifact has the wrong identity"));
    }
    let events: Vec<crate::InputEventEnvelope> =
        crate::protocol::value::decode_canonical_dag_cbor(artifact.bytes.as_bytes())?;
    let input = crate::fetch::verify_input_events(&events).map_err(|e| error(e.to_string()))?;
    if input.retention != crate::Retention::Ephemeral || prepared.request.retain {
        return Err(error("paid Fetch requires an ephemeral signed request"));
    }
    if input.caller_key != *caller
        || input.assurance != prepared.request.assurance
        || input.execution_environment != prepared.request.execution_environment
        || input.retention.should_retain() != prepared.request.retain
    {
        return Err(error("Fetch signed request differs from its invocation"));
    }
    if input.body.0.len() > admission.limits.max_request_body_bytes as usize {
        return Err(error("Fetch request body exceeds limit"));
    }
    if let FetchRoutePolicy::SealedRoute { service, method } = &admission.route
        && (input.service != *service || input.method != *method)
    {
        return Err(error("Fetch signed route is not admitted"));
    }
    if parameters.contract.schema() == FetchSchema::HttpV1 {
        let request = crate::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
            .map_err(|e| error(e.to_string()))?;
        if let FetchEgress::FixedHttps(endpoint) = parameters.contract.egress()
            && request.url != *endpoint
        {
            return Err(error("Fetch request differs from the contract endpoint"));
        }
    }
    if let FetchRoutePolicy::OpenFetch {
        require_spki_pin,
        allowed_hosts,
    } = &admission.route
    {
        if parameters.contract.schema() != FetchSchema::HttpV1 {
            return Err(error("open Fetch requires the HTTPS schema"));
        }
        let request = crate::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
            .map_err(|e| error(e.to_string()))?;
        let url = request.parsed_url().map_err(|e| error(e.to_string()))?;
        if (*require_spki_pin && request.tls.spki_sha256.is_empty())
            || (!allowed_hosts.is_empty()
                && !allowed_hosts
                    .iter()
                    .any(|host| Some(host.as_str()) == url.host_str()))
        {
            return Err(error("Fetch host or TLS pin is not admitted"));
        }
        if u64::from(request.max_response_bytes) > max_output_bytes / 4 * 3 {
            return Err(error("Fetch response bound exceeds deliverable output"));
        }
    }
    Ok(input)
}

pub const RESPONSE_EVENTS: &str = "response.events";
pub const RESPONSE_EVENTS_FORMAT: &str = "hellas.fetch.output-events.v1";
#[cfg(feature = "fetch")]
const OUTPUT_DOMAIN: &str = "hellas.invocation.fetch-output.v1";

/// Exact length-prefixed response.event bytes; transport chunks may split frames.
#[cfg(feature = "fetch")]
pub fn frame_event(payload: &[u8]) -> Result<Vec<u8>, CanonicalDecodeError> {
    crate::fetch::decode_fetch_event_payload(payload).map_err(|e| error(e.to_string()))?;
    let len =
        u32::try_from(payload.len()).map_err(|_| error("Fetch event exceeds its frame bound"))?;
    let mut bytes = Vec::with_capacity(payload.len() + 4);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
#[cfg(feature = "fetch")]
pub fn output(
    event_payloads: &[Vec<u8>],
    terminal_payload: &[u8],
) -> Result<super::output::InvocationOutput, CanonicalDecodeError> {
    crate::fetch::decode_fetch_terminal_payload(terminal_payload)
        .map_err(|e| error(e.to_string()))?;
    let mut bytes = Vec::new();
    for payload in event_payloads {
        bytes.extend_from_slice(&frame_event(payload)?);
    }
    Ok(super::output::InvocationOutput {
        outcome: super::output::Outcome::Succeeded,
        artifacts: vec![super::Artifact::new(
            RESPONSE_EVENTS,
            RESPONSE_EVENTS_FORMAT,
            bytes,
        )],
        metadata: JsonBytes(encode(&(
            OUTPUT_DOMAIN,
            JsonBytes(terminal_payload.to_vec()),
        ))?),
    })
}
#[cfg(feature = "fetch")]
pub fn decode_output(
    output: &super::output::InvocationOutput,
    provider: &hellas_auth::PublicKey,
) -> Result<crate::fetch::FetchOutput, CanonicalDecodeError> {
    if !output.is_success() {
        return Err(error("failed Fetch has no complete response"));
    }
    let [artifact] = output.artifacts.as_slice() else {
        return Err(error("Fetch output requires its response events artifact"));
    };
    if artifact.name != RESPONSE_EVENTS || artifact.format != RESPONSE_EVENTS_FORMAT {
        return Err(error("Fetch response artifact identity mismatch"));
    }
    let mut remaining = artifact.bytes.as_bytes();
    let mut events = Vec::new();
    while !remaining.is_empty() {
        let header = remaining
            .get(..4)
            .ok_or_else(|| error("truncated Fetch event length"))?;
        let len = u32::from_be_bytes(header.try_into().unwrap()) as usize;
        remaining = &remaining[4..];
        let payload = remaining
            .get(..len)
            .ok_or_else(|| error("truncated Fetch event body"))?;
        crate::fetch::decode_fetch_event_payload(payload).map_err(|e| error(e.to_string()))?;
        events.push(payload.to_vec());
        remaining = &remaining[len..];
        if events.len() >= crate::fetch::MAX_FETCH_OUTPUT_EVENTS {
            return Err(error("Fetch response event bound exceeded"));
        }
    }
    let (domain, terminal): (String, JsonBytes) =
        crate::protocol::value::decode_canonical_dag_cbor(output.metadata.as_bytes())?;
    domain_is(&domain, OUTPUT_DOMAIN)?;
    crate::fetch::decode_fetch_terminal_payload(terminal.as_bytes())
        .map_err(|e| error(e.to_string()))?;
    Ok(crate::fetch::FetchOutput::from_authenticated_payloads(
        *provider, events, terminal.0,
    ))
}
#[cfg(feature = "fetch")]
pub fn validate_failed_output(
    admission: &FetchAdmission,
    max_output_bytes: u64,
    output: &super::output::InvocationOutput,
) -> Result<(), CanonicalDecodeError> {
    if output.artifacts.is_empty() {
        return Ok(());
    }
    let [artifact] = output.artifacts.as_slice() else {
        return Err(error("failed Fetch has unexpected response artifacts"));
    };
    if artifact.name != RESPONSE_EVENTS || artifact.format != RESPONSE_EVENTS_FORMAT {
        return Err(error("failed Fetch response artifact identity mismatch"));
    }
    let mut remaining = artifact.bytes.as_bytes();
    let mut events = 0usize;
    let mut payload_bytes = 0u64;
    // A failed live stream can end midway through the last event frame.
    while !remaining.is_empty() {
        events += 1;
        let Some(header) = remaining.get(..4) else {
            break;
        };
        let len = u32::from_be_bytes(header.try_into().unwrap()) as usize;
        remaining = &remaining[4..];
        let available = len.min(remaining.len());
        payload_bytes += available as u64;
        remaining = &remaining[available..];
    }
    if events.saturating_add(1) > admission.limits.max_output_events as usize
        || events.saturating_add(1) > crate::fetch::MAX_FETCH_OUTPUT_EVENTS
        || payload_bytes > max_output_bytes
        || payload_bytes > crate::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64
    {
        return Err(error("failed Fetch prefix exceeds its output bounds"));
    }
    Ok(())
}
#[cfg(feature = "fetch")]
pub fn validate_output(
    prepared: &super::PreparedInvocation,
    admission: &FetchAdmission,
    max_output_bytes: u64,
    provider: &hellas_auth::PublicKey,
    output: &super::output::InvocationOutput,
) -> Result<(), CanonicalDecodeError> {
    let response = decode_output(output, provider)?;
    let (events, terminal) = response.output_event_payloads();
    let total = events
        .iter()
        .try_fold(terminal.len() as u64, |sum, payload| {
            sum.checked_add(payload.len() as u64)
        })
        .ok_or_else(|| error("Fetch output size overflow"))?;
    if events.len().saturating_add(1) > admission.limits.max_output_events as usize
        || total > max_output_bytes
        || total > crate::fetch::MAX_FETCH_OUTPUT_PAYLOAD_BYTES as u64
    {
        return Err(error("Fetch response exceeds its output bounds"));
    }
    let terminal =
        crate::fetch::decode_fetch_terminal_payload(terminal).map_err(|e| error(e.to_string()))?;
    if matches!(
        terminal,
        crate::fetch::FetchTerminalPayload::Finished {
            stop_reason: crate::output::StopReason::Cancelled,
            ..
        }
    ) {
        return Err(error("cancelled Fetch is not a successful result"));
    }
    if admission.contract.schema() == crate::FetchSchema::HttpV1 {
        let input_artifact = &prepared.input.artifacts[0];
        let input_events: Vec<crate::InputEventEnvelope> =
            crate::protocol::value::decode_canonical_dag_cbor(input_artifact.bytes.as_bytes())?;
        let input =
            crate::fetch::verify_input_events(&input_events).map_err(|e| error(e.to_string()))?;
        let request = crate::http_fetch::HttpFetchRequest::decode(input.body.as_bytes())
            .map_err(|e| error(e.to_string()))?;
        crate::http_fetch::HttpFetchResponse::from_output(&request, &response)
            .map_err(|e| error(e.to_string()))?;
    }
    Ok(())
}
