//! Execution policy parsing shared by payment and grant configuration.
use hellas_rpc::{
    ContentId,
    protocol::{
        Digest,
        work::{EvaluatePolicyV2, check_work_policy},
        work_fetch::{FetchPolicyV2, FetchRoutePolicy, fetch_route_commitment},
        work_profile::WorkPolicy,
    },
};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ResourceConfigError {
    #[error("{field} is not a ContentId: {source}")]
    ContentId {
        field: &'static str,
        source: <ContentId as std::str::FromStr>::Err,
    },
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
    #[error("{field} is not hexadecimal: {source}")]
    Hex {
        field: &'static str,
        source: hex::FromHexError,
    },
    #[error("{field} must be {expected} bytes, found {actual}")]
    Length {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("execution policy is not usable: {0}")]
    Policy(#[from] hellas_rpc::protocol::work::PaidWorkError),
}
type Result<T> = std::result::Result<T, ResourceConfigError>;

/// Required execution-policy fields. Defaults could change the terms being signed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionPolicyFile {
    allowed_environment: String,
    generation_policy_digest: String,
    identity_source_digest: String,
    max_prompt_tokens: u32,
    max_new_tokens: u32,
    max_stop_token_ids: u16,
    max_spool_bytes: u64,
    max_encoded_result_frame: u32,
    max_encoded_prepared_input: u32,
}

impl ExecutionPolicyFile {
    pub(crate) fn into_policy(self) -> Result<EvaluatePolicyV2> {
        let allowed_environment: ContentId =
            self.allowed_environment
                .parse()
                .map_err(|source| ResourceConfigError::ContentId {
                    field: "policies.execution.allowed_environment",
                    source,
                })?;
        let policy = EvaluatePolicyV2 {
            allowed_environment,
            generation_policy_digest: parse_digest(
                "policies.execution.generation_policy_digest",
                &self.generation_policy_digest,
            )?,
            identity_source_digest: parse_digest(
                "policies.execution.identity_source_digest",
                &self.identity_source_digest,
            )?,
            max_prompt_tokens: self.max_prompt_tokens,
            max_new_tokens: self.max_new_tokens,
            max_stop_token_ids: self.max_stop_token_ids,
            max_spool_bytes: self.max_spool_bytes,
            max_encoded_result_frame: self.max_encoded_result_frame,
            max_encoded_prepared_input: self.max_encoded_prepared_input,
        };
        // Validate with the protocol rules before any channel is proposed.
        check_work_policy(&policy)?;
        Ok(policy)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchPolicyFile {
    allowed_environment: String,
    service: Option<String>,
    method: Option<String>,
    open_fetch: Option<OpenFetchPolicyFile>,
    max_request_body_bytes: u32,
    max_output_events: u32,
    max_output_bytes: u32,
    max_spool_bytes: u64,
    max_encoded_result_frame: u32,
    max_encoded_prepared_input: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenFetchPolicyFile {
    #[serde(default)]
    require_spki_pin: bool,
    #[serde(default)]
    allowed_hosts: Vec<String>,
}

impl FetchPolicyFile {
    pub(crate) fn into_policy(self) -> Result<WorkPolicy> {
        let route = match (self.service, self.method, self.open_fetch) {
            (Some(service), Some(method), None) => FetchRoutePolicy::sealed_route(service, method)?,
            (None, None, Some(open)) => {
                FetchRoutePolicy::open_fetch(open.require_spki_pin, open.allowed_hosts)
            }
            _ => {
                return Err(ResourceConfigError::Invalid {
                    field: "policies.fetch",
                    reason: "requires service+method or open_fetch",
                });
            }
        };
        let policy = FetchPolicyV2 {
            allowed_environment: self.allowed_environment.parse().map_err(|source| {
                ResourceConfigError::ContentId {
                    field: "policies.fetch.allowed_environment",
                    source,
                }
            })?,
            route_commitment: fetch_route_commitment(&route.canonical_body_bytes())?,
            max_request_body_bytes: self.max_request_body_bytes,
            max_output_events: self.max_output_events,
            max_output_bytes: self.max_output_bytes,
            max_spool_bytes: self.max_spool_bytes,
            max_encoded_result_frame: self.max_encoded_result_frame,
            max_encoded_prepared_input: self.max_encoded_prepared_input,
        };
        let profile = WorkPolicy::Fetch { policy, route };
        profile.check()?;
        Ok(profile)
    }
}

pub(crate) fn parse_hex(field: &'static str, raw: &str) -> Result<Vec<u8>> {
    let bytes =
        hex::decode(raw.trim()).map_err(|source| ResourceConfigError::Hex { field, source })?;
    if bytes.is_empty() {
        return Err(ResourceConfigError::Invalid {
            field,
            reason: "must not be empty",
        });
    }
    Ok(bytes)
}

pub(crate) fn parse_fixed_hex<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N]> {
    let bytes = parse_hex(field, raw)?;
    let Ok(bytes) = <[u8; N]>::try_from(bytes.as_slice()) else {
        return Err(ResourceConfigError::Length {
            field,
            expected: N,
            actual: bytes.len(),
        });
    };
    Ok(bytes)
}

pub(crate) fn parse_digest(field: &'static str, raw: &str) -> Result<Digest> {
    Ok(Digest::from_bytes(parse_fixed_hex(field, raw)?))
}
