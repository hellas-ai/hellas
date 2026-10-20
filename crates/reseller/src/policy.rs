use hellas_auth::authority::{ResourceId, Revision};
use hellas_work::model::{
    fetch::{FetchPolicyV2, FetchRoutePolicy, fetch_route_commitment},
    grant::records::{GrantError, GrantPolicy},
    profile::WorkPolicy,
};

pub fn responses_policy(
    resource: ResourceId,
    account: ResourceId,
    revision: Revision,
    service: &str,
    method: &str,
    responses: hellas_work::model::grant::responses::ResponsesResource,
    pricing: hellas_work::model::grant::pricing::Pricing,
) -> Result<GrantPolicy, GrantError> {
    let route =
        FetchRoutePolicy::sealed_route(service, method).map_err(|_| GrantError::Malformed)?;
    let contract = crate::responses_contract().map_err(|_| GrantError::Malformed)?;
    let policy = GrantPolicy {
        resource,
        account,
        revision,
        name: "responses".into(),
        work: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: contract.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes())
                    .map_err(|_| GrantError::Malformed)?,
                max_request_body_bytes: 64 << 10,
                max_output_events: 4096,
                max_output_bytes: 1 << 20,
                max_spool_bytes: 4 << 20,
                max_encoded_result_frame: 4 << 20,
                max_encoded_prepared_input: 128 << 10,
            },
            route,
            contract,
        },
        https: None,
        responses: Some(responses),
        pricing,
    };
    policy.validate()?;
    Ok(policy)
}
