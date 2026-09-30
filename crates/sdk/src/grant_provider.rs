//! Startup reconciliation for a host-owned list of contact enrollments.
use crate::{FetchRoute, FetchRouteRegistry, ProviderError};
use hellas_rpc::{
    FetchEnvironment, ProviderEnrollmentBundle,
    protocol::{
        work_fetch::*,
        work_grant::{budget::Limit, records::*, *},
        work_profile::WorkPolicy,
    },
};
use hellas_work::{grant_service::wall_clock, work_store::grant::GrantStore};
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
    path::Path,
};

pub struct GrantProviderOptions {
    pub grantees: Vec<Principal>,
    pub policies: Vec<GrantPolicy>,
    /// Per-grantee limits; machine concurrency is shared across all fundings.
    pub limits: Vec<Limit>,
    pub max_job_millis: NonZeroU64,
}

pub fn responses_policy(service: &str, method: &str) -> Result<GrantPolicy, GrantError> {
    let route =
        FetchRoutePolicy::sealed_route(service, method).map_err(|_| GrantError::Malformed)?;
    Ok(GrantPolicy {
        name: "responses".into(),
        work: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
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
        },
        https: None,
    })
}

pub(crate) fn prepare(
    options: &GrantProviderOptions,
    directory: &Path,
    provider: ProviderEnrollmentBundle,
    owner: Principal,
    routes: &FetchRouteRegistry,
    concurrent: usize,
) -> Result<GrantStore, ProviderError> {
    let concurrent = u16::try_from(concurrent)
        .ok()
        .and_then(NonZeroU16::new)
        .filter(|n| n.get() <= 256)
        .ok_or(GrantError::Limits)?;
    for policy in &options.policies {
        policy.validate()?;
        let WorkPolicy::Fetch {
            policy: fetch,
            route: FetchRoutePolicy::SealedRoute { service, method },
        } = &policy.work
        else {
            return Err(GrantError::OutOfScope.into());
        };
        if routes
            .entry(&FetchRoute::new(service, method))
            .is_none_or(|entry| entry.execution_environment() != fetch.allowed_environment)
        {
            return Err(GrantError::OutOfScope.into());
        }
    }
    let mut desired = BTreeMap::new();
    for principal in &options.grantees {
        let digest = hellas_rpc::Digest::hash(
            &[
                b"hellas.work.contact-grant.v1".as_slice(),
                provider.content_id().as_bytes(),
                principal.id().0.as_bytes(),
            ]
            .concat(),
        );
        let id = GrantId(digest.as_bytes()[..16].try_into().expect("fixed slice"));
        let def = GrantDef {
            id,
            revision: Revision(1),
            kind: GrantKind::Principal(principal.clone()),
            policies: options.policies.clone(),
            limits: options.limits.clone(),
            weight: NonZeroU16::new(1).unwrap(),
            max_job_millis: options.max_job_millis,
            max_in_flight: concurrent,
            expires: None,
            state: GrantState::Active,
            // Supplying the host's account-backed sealed routes is explicit consent.
            allow_account_backed: true,
        };
        def.validate()?;
        if desired.insert(id, def).is_some() {
            return Err(GrantError::Malformed.into());
        }
    }
    let now = wall_clock();
    let mut store = GrantStore::open(&directory.join("grants"), grant_network(), provider, now)?;
    store.bind_owner(owner, now)?;
    // Preflight the entire list before updating terms. Failed startup never opens
    // a listener; interruption between durable records is completed on restart.
    let existing: Vec<_> = store.state().grants().cloned().collect();
    if existing.len()
        + desired
            .keys()
            .filter(|id| store.state().grant(**id).is_none())
            .count()
        > 256
    {
        return Err(GrantError::StateCapacity.into());
    }
    let mut changes = vec![];
    for old in &existing {
        if matches!(old.kind, GrantKind::Owner(_)) {
            return Err(GrantError::OutOfScope.into());
        }
        if let Some(def) = desired.get_mut(&old.id) {
            if old.state == GrantState::Revoked {
                return Err(ProviderError::RevokedContact);
            }
            def.revision = old.revision;
            if def == old {
                continue;
            }
            def.revision.0 = old
                .revision
                .0
                .checked_add(1)
                .ok_or(GrantError::StateCapacity)?;
        } else if old.state != GrantState::Revoked {
            let mut revoked = old.clone();
            revoked.revision.0 = old
                .revision
                .0
                .checked_add(1)
                .ok_or(GrantError::StateCapacity)?;
            revoked.state = GrantState::Revoked;
            changes.push(revoked);
        }
    }
    changes.extend(
        desired
            .into_values()
            .filter(|def| store.state().grant(def.id) != Some(def)),
    );
    store.configure_machine(vec![], concurrent.get(), now)?;
    for def in changes {
        store.define(def, now)?;
    }
    Ok(store)
}
