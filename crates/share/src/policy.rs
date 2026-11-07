use hellas_auth::authority::{ResourceId, Revision};
use hellas_authority::model::grant::records::{GrantError, GrantPolicy};
use hellas_rpc::protocol::invocation::{
    Admission, InvocationPolicy, Limits,
    fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy},
};

#[allow(clippy::too_many_arguments)]
pub fn responses_policy(
    resource: ResourceId,
    account: ResourceId,
    revision: Revision,
    service: &str,
    method: &str,
    responses: hellas_authority::model::grant::responses::ResponsesResource,
    pricing: hellas_authority::model::grant::pricing::Pricing,
    max_job_millis: std::num::NonZeroU64,
) -> Result<GrantPolicy, GrantError> {
    let route =
        FetchRoutePolicy::sealed_route(service, method).map_err(|_| GrantError::Malformed)?;
    let contract = crate::responses_contract().map_err(|_| GrantError::Malformed)?;
    let policy = GrantPolicy {
        resource,
        account,
        revision,
        name: "responses".into(),
        invocation_policy: InvocationPolicy {
            admissions: vec![Admission::Fetch {
                admission: FetchAdmission {
                    contract,
                    route,
                    limits: FetchLimits {
                        max_request_body_bytes: 64 << 10,
                        max_output_events: 4096,
                        max_spool_bytes: 4 << 20,
                        max_encoded_result_frame: 4 << 20,
                        max_encoded_prepared_input: 128 << 10,
                    },
                },
            }],
            limits: Limits {
                max_upload_bytes: 128 << 10,
                max_output_bytes: 1 << 20,
                max_steps: 1,
                execution_timeout_ms: max_job_millis.get(),
            },
        },
        https: None,
        responses: Some(responses),
        pricing,
    };
    policy.validate()?;
    Ok(policy)
}
