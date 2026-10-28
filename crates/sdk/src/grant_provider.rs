//! Validate available resources and open explicitly initialized provider authority.
use crate::{FetchRoute, FetchRouteRegistry};
use std::{collections::BTreeSet, num::NonZeroU64};
use {
    hellas_authority::model::grant::records::GrantError,
    hellas_authority::model::grant::records::GrantPolicy,
    hellas_rpc::protocol::invocation::{Admission, fetch::FetchRoutePolicy},
};

#[derive(Debug, thiserror::Error)]
pub enum GrantProviderError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error("resource {0} requires a Compute backend")]
    ComputeUnavailable(String),
    #[error("resource {0} names an unavailable Fetch route or environment")]
    MissingRoute(String),
    #[error("resource {0} requires a named Fetch route")]
    UnsealedRoute(String),
}

/// Resources available in the executor the host will start.
pub enum ProviderResources<'a> {
    Fetch(&'a FetchRouteRegistry),
    ComputeAndFetch(&'a FetchRouteRegistry),
}
impl ProviderResources<'_> {
    pub fn validate(&self, policies: &[GrantPolicy]) -> Result<(), GrantProviderError> {
        if policies.len() > 16 {
            return Err(GrantError::Limits.into());
        }
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let routes = match self {
            Self::Fetch(routes) | Self::ComputeAndFetch(routes) => routes,
        };
        for resource in policies {
            resource.validate()?;
            if !names.insert(&resource.name) || !ids.insert(resource.resource) {
                return Err(GrantError::Malformed.into());
            }
            for admission in &resource.invocation_policy.admissions {
                match admission {
                    Admission::Compute { .. } => {
                        if matches!(self, Self::Fetch(_)) {
                            return Err(GrantProviderError::ComputeUnavailable(
                                resource.name.clone(),
                            ));
                        }
                    }
                    Admission::Fetch { admission } => match &admission.route {
                        FetchRoutePolicy::SealedRoute { service, method } => {
                            if routes
                                .entry(&FetchRoute::new(service, method))
                                .is_none_or(|entry| {
                                    entry.execution_environment()
                                        != admission.contract.manifest_id()
                                })
                            {
                                return Err(GrantProviderError::MissingRoute(
                                    resource.name.clone(),
                                ));
                            }
                        }
                        _ => return Err(GrantProviderError::UnsealedRoute(resource.name.clone())),
                    },
                }
            }
        }
        Ok(())
    }
}

/// Available resources for checked administration, never startup permission grants.
#[derive(Clone)]
pub struct GrantProviderOptions {
    pub policies: Vec<GrantPolicy>,
    pub max_job_millis: NonZeroU64,
}
