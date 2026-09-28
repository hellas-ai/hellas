use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use crate::fetch_policy::{FetchRoute, FetchRoutePolicy};
use crate::fetch_projection::FetchAdaptorFactory;
use crate::fetch_provider::FetchProvider;
use hellas_rpc::ContentId;

/// The route table: the single source of fetch dispatch truth.
///
/// A route maps `(service, method)` — the pair a caller commits to in the
/// input transcript — to exactly one provider driver, trusted adaptor, and
/// route-wide capability policy. Providers never inspect `service`/`method`;
/// they only receive requests for the route they were registered under. The
/// adaptor supplies its own trusted execution-environment commitment, so a
/// route cannot advertise a different implementation or config.
#[derive(Clone, Default)]
pub struct FetchRouteRegistry {
    routes: HashMap<FetchRoute, FetchRouteEntry>,
}

#[derive(Clone)]
pub struct FetchRouteEntry {
    execution_environment: ContentId,
    pub(crate) provider: Arc<dyn FetchProvider>,
    pub(crate) adaptor_factory: Arc<dyn FetchAdaptorFactory>,
    /// Route-wide self-protection, independent of caller: what this upstream
    /// can safely satisfy. Admission validates against the intersection of
    /// this and the caller's grant.
    pub capabilities: FetchRoutePolicy,
}

impl FetchRouteEntry {
    /// Binds one provider-local credential source to a trusted adaptor.
    ///
    /// Credentials and capabilities remain local policy. The quoted manifest
    /// identity is always derived from the same adaptor object that constructs
    /// the request and interprets the response.
    pub fn new(
        provider: Arc<dyn FetchProvider>,
        adaptor_factory: Arc<dyn FetchAdaptorFactory>,
        capabilities: FetchRoutePolicy,
    ) -> Result<Self, FetchRouteBindingError> {
        let execution_environment = adaptor_factory.execution_environment();
        let provider_environment = provider.execution_environment();
        if provider_environment != execution_environment {
            return Err(FetchRouteBindingError {
                provider: provider_environment,
                adaptor: execution_environment,
            });
        }
        Ok(Self {
            execution_environment,
            provider,
            adaptor_factory,
            capabilities,
        })
    }

    /// Returns the trusted execution-environment commitment quoted for this
    /// route.
    #[must_use]
    pub const fn execution_environment(&self) -> ContentId {
        self.execution_environment
    }
}

impl std::fmt::Debug for FetchRouteRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set()
            .entries(
                self.routes
                    .keys()
                    .map(|route| format!("{}/{}", route.service, route.method)),
            )
            .finish()
    }
}

impl FetchRouteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        route: FetchRoute,
        entry: FetchRouteEntry,
    ) -> Result<(), DuplicateFetchRoute> {
        match self.routes.entry(route) {
            Entry::Occupied(occupied) => Err(DuplicateFetchRoute {
                service: occupied.key().service.clone(),
                method: occupied.key().method.clone(),
            }),
            Entry::Vacant(vacant) => {
                vacant.insert(entry);
                Ok(())
            }
        }
    }

    /// Whether at least one configured route implements this trusted manifest.
    pub fn has_environment(&self, environment: ContentId) -> bool {
        self.routes
            .values()
            .any(|entry| entry.execution_environment() == environment)
    }

    pub fn entry(&self, route: &FetchRoute) -> Option<&FetchRouteEntry> {
        self.routes.get(route)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("fetch route {service}/{method} is registered twice")]
pub struct DuplicateFetchRoute {
    pub service: String,
    pub method: String,
}

#[derive(Debug, thiserror::Error)]
#[error("fetch provider environment {provider} does not match adaptor environment {adaptor}")]
pub struct FetchRouteBindingError {
    provider: ContentId,
    adaptor: ContentId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FetchAdaptorError, FetchAdaptorSession, FetchCall, MockFetchProvider};

    struct FixedAdaptor(ContentId);

    impl crate::FetchAdaptorFactory for FixedAdaptor {
        fn execution_environment(&self) -> ContentId {
            self.0
        }

        fn create(&self, _request: &FetchCall) -> Result<FetchAdaptorSession, FetchAdaptorError> {
            unreachable!("route binding does not prepare a request")
        }
    }

    #[test]
    fn route_refuses_a_provider_for_another_trusted_environment() {
        let provider_environment = ContentId::from_bytes([1; 32]);
        let adaptor_environment = ContentId::from_bytes([2; 32]);
        let provider = Arc::new(MockFetchProvider::new(provider_environment));

        let result = FetchRouteEntry::new(
            provider,
            Arc::new(FixedAdaptor(adaptor_environment)),
            FetchRoutePolicy::default(),
        );

        assert!(matches!(result, Err(FetchRouteBindingError { .. })));
    }
}
