//! Validate execution resources before opening and reconciling a provider journal.
use crate::{FetchRoute, FetchRouteRegistry, grant_config::GrantConfig};
use hellas_rpc::{
    Digest, FetchEnvironment, ProviderEnrollmentBundle,
    protocol::{
        work_fetch::{FetchPolicyV2, FetchRoutePolicy, fetch_route_commitment},
        work_grant::{
            GrantId, Revision,
            budget::{BudgetNode, Limit},
            grant_network, owner_grant_id,
            records::{GrantDef, GrantError, GrantKind, GrantPolicy, GrantState, Principal},
        },
        work_profile::WorkPolicy,
    },
};
use hellas_work::{
    grant_service::wall_clock,
    work_store::grant::{
        GrantStore, GrantStoreError,
        ledger::{Ledger, LedgerError},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU64},
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum GrantProviderError {
    #[error(transparent)]
    Grant(#[from] GrantError),
    #[error(transparent)]
    Store(#[from] GrantStoreError),
    #[error(transparent)]
    Limits(#[from] LedgerError),
    #[error("resource {0} requires an Evaluate backend")]
    EvaluateUnavailable(String),
    #[error("resource {0} names an unavailable Fetch route or environment")]
    MissingRoute(String),
    #[error("resource {0} requires a named Fetch route")]
    UnsealedRoute(String),
    #[error("a revoked contact cannot be re-enabled; import a newly issued contact enrollment")]
    RevokedContact,
}

/// Resources available in the executor the host will start.
pub enum ProviderResources<'a> {
    Fetch(&'a FetchRouteRegistry),
    EvaluateAndFetch(&'a FetchRouteRegistry),
}
impl ProviderResources<'_> {
    pub fn validate(&self, policies: &[GrantPolicy]) -> Result<(), GrantProviderError> {
        if policies.len() > 16 {
            return Err(GrantError::Limits.into());
        }
        let mut names = BTreeSet::new();
        let routes = match self {
            Self::Fetch(routes) | Self::EvaluateAndFetch(routes) => routes,
        };
        for resource in policies {
            resource.validate()?;
            if !names.insert(&resource.name) {
                return Err(GrantError::Malformed.into());
            }
            match &resource.work {
                WorkPolicy::Evaluate(_) => {
                    if matches!(self, Self::Fetch(_)) {
                        return Err(GrantProviderError::EvaluateUnavailable(
                            resource.name.clone(),
                        ));
                    }
                }
                WorkPolicy::Fetch {
                    policy,
                    route: FetchRoutePolicy::SealedRoute { service, method },
                } => {
                    if routes
                        .entry(&FetchRoute::new(service, method))
                        .is_none_or(|entry| {
                            entry.execution_environment() != policy.allowed_environment
                        })
                    {
                        return Err(GrantProviderError::MissingRoute(resource.name.clone()));
                    }
                }
                WorkPolicy::Fetch { .. } => {
                    return Err(GrantProviderError::UnsealedRoute(resource.name.clone()));
                }
            }
        }
        Ok(())
    }
}

pub struct GrantProviderOptions {
    pub grantees: Vec<Principal>,
    pub policies: Vec<GrantPolicy>,
    /// Per-grantee limits; machine concurrency is shared across all fundings.
    pub limits: Vec<Limit>,
    pub max_job_millis: NonZeroU64,
}

pub struct ManagedGrantOptions {
    pub config: GrantConfig,
    pub provider: Principal,
    pub owner: Option<Principal>,
}

/// A validated startup plan shared by SDK providers, serve and the local owner.
/// Construction performs no I/O. Opening retains journal counters and revocations.
pub struct GrantProviderPlan {
    directory: PathBuf,
    provider: ProviderEnrollmentBundle,
    machine: MachineAllowance,
    desired: DesiredGrants,
}

enum MachineAllowance {
    Preserve {
        initial_concurrency: u16,
    },
    Replace {
        limits: Vec<Limit>,
        concurrency: u16,
    },
}
enum DesiredGrants {
    Managed {
        owner: Option<Box<GrantDef>>,
        revise: bool,
    },
    Contacts {
        owner: Box<Principal>,
        grants: BTreeMap<GrantId, GrantDef>,
    },
}

impl GrantProviderPlan {
    pub fn managed(
        options: &ManagedGrantOptions,
        resources: ProviderResources<'_>,
    ) -> Result<Self, GrantProviderError> {
        let config = &options.config;
        resources.validate(&config.resources)?;
        validate_machine(
            config.machine_limits.as_deref().unwrap_or_default(),
            config.max_in_flight,
        )?;
        let owner = options
            .owner
            .as_ref()
            .map(|owner| {
                let definition = GrantDef {
                    id: owner_grant_id(
                        grant_network(),
                        options.provider.bundle().content_id(),
                        owner.id(),
                    ),
                    revision: Revision(1),
                    kind: GrantKind::Owner(owner.clone()),
                    policies: config.resources.clone(),
                    limits: vec![],
                    max_job_millis: config.max_job_millis,
                    max_in_flight: NonZeroU16::new(256).expect("positive"),
                    expires: None,
                    state: GrantState::Active,
                    allow_account_backed: true,
                };
                definition.validate()?;
                Ok::<_, GrantProviderError>(Box::new(definition))
            })
            .transpose()?;
        Ok(Self {
            directory: config.journal_root.clone(),
            provider: options.provider.bundle().clone(),
            machine: match &config.machine_limits {
                Some(limits) => MachineAllowance::Replace {
                    limits: limits.clone(),
                    concurrency: config.max_in_flight,
                },
                None => MachineAllowance::Preserve {
                    initial_concurrency: config.max_in_flight,
                },
            },
            desired: DesiredGrants::Managed {
                owner,
                revise: config.machine_limits.is_some() || !config.resources.is_empty(),
            },
        })
    }

    pub fn contacts(
        options: &GrantProviderOptions,
        directory: &Path,
        provider: ProviderEnrollmentBundle,
        owner: Principal,
        routes: &FetchRouteRegistry,
        concurrent: usize,
    ) -> Result<Self, GrantProviderError> {
        provider.check_grant_provider()?;
        if owner.transport() != provider.grant_transport()?
            || owner.producer() != provider.grant_producer()?
        {
            return Err(GrantError::Audience.into());
        }
        ProviderResources::Fetch(routes).validate(&options.policies)?;
        let concurrent = u16::try_from(concurrent)
            .ok()
            .and_then(NonZeroU16::new)
            .filter(|n| n.get() <= 256)
            .ok_or(GrantError::Limits)?;
        if options.grantees.len() > 256 {
            return Err(GrantError::StateCapacity.into());
        }
        let mut desired = BTreeMap::new();
        for principal in &options.grantees {
            let digest = Digest::hash(
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

        Ok(Self {
            directory: directory.join("grants"),
            provider,
            machine: MachineAllowance::Replace {
                limits: vec![],
                concurrency: concurrent.get(),
            },
            desired: DesiredGrants::Contacts {
                owner: Box::new(owner),
                grants: desired,
            },
        })
    }

    pub fn open(self) -> Result<GrantStore, GrantProviderError> {
        let now = wall_clock();
        let mut store = GrantStore::open(&self.directory, grant_network(), self.provider, now)?;
        let changes = match self.desired {
            DesiredGrants::Contacts { owner, grants } => {
                let changes = contact_changes(&store, grants)?;
                store.bind_owner(*owner, now)?;
                changes
            }
            DesiredGrants::Managed { owner, revise } => owner_changes(&store, owner, revise)?,
        };
        match self.machine {
            MachineAllowance::Replace {
                limits,
                concurrency,
            } => store.configure_machine(limits, concurrency, now)?,
            MachineAllowance::Preserve {
                initial_concurrency,
            } => {
                if store.state().ledger().node(BudgetNode::Machine).is_none() {
                    store.configure_machine(vec![], initial_concurrency, now)?;
                }
            }
        }
        for definition in changes {
            store.define(definition, now)?;
        }
        Ok(store)
    }
}

fn validate_machine(limits: &[Limit], concurrency: u16) -> Result<(), GrantProviderError> {
    if concurrency > 256 {
        return Err(GrantError::Limits.into());
    }
    Ledger::default().configure(BudgetNode::Machine, limits.to_vec(), concurrency)?;
    Ok(())
}

fn owner_changes(
    store: &GrantStore,
    owner: Option<Box<GrantDef>>,
    revise: bool,
) -> Result<Vec<GrantDef>, GrantProviderError> {
    let Some(owner) = owner else {
        return Ok(vec![]);
    };
    let Some(existing) = store.state().grant(owner.id) else {
        return Ok(vec![*owner]);
    };
    if !revise
        || existing.state == GrantState::Revoked
        || (existing.policies == owner.policies && existing.max_job_millis == owner.max_job_millis)
    {
        return Ok(vec![]);
    }
    let mut changed = existing.clone();
    changed.revision.0 = changed
        .revision
        .0
        .checked_add(1)
        .ok_or(GrantError::StateCapacity)?;
    changed.policies = owner.policies;
    changed.max_job_millis = owner.max_job_millis;
    changed.validate()?;
    Ok(vec![changed])
}

fn contact_changes(
    store: &GrantStore,
    mut desired: BTreeMap<GrantId, GrantDef>,
) -> Result<Vec<GrantDef>, GrantProviderError> {
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
                return Err(GrantProviderError::RevokedContact);
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
    Ok(changes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_resources_and_limits_are_rejected_before_opening_a_journal() {
        let root = tempfile::tempdir().unwrap();
        let peer = iroh::SecretKey::from_bytes(&[3; 32]).public();
        let provider = Principal::verify(crate::test_identity::enrollment(peer).0).unwrap();
        let mut options = ManagedGrantOptions {
            config: GrantConfig::unconfigured(root.path()),
            provider: provider.clone(),
            owner: Some(provider),
        };
        let routes = FetchRouteRegistry::default();
        options
            .config
            .resources
            .push(responses_policy("missing", "responses").unwrap());
        assert!(matches!(
            GrantProviderPlan::managed(&options, ProviderResources::Fetch(&routes)),
            Err(GrantProviderError::MissingRoute(_))
        ));
        assert!(!options.config.journal_root.exists());
        options.config.resources.clear();
        let limit = Limit {
            meter: hellas_rpc::protocol::work_grant::budget::Meter::Requests,
            window: hellas_rpc::protocol::work_grant::budget::Window::Total,
            amount: 1,
        };
        options.config.machine_limits = Some(vec![limit, limit]);
        assert!(matches!(
            GrantProviderPlan::managed(&options, ProviderResources::Fetch(&routes)),
            Err(GrantProviderError::Limits(LedgerError::InvalidLimits))
        ));
        assert!(!options.config.journal_root.exists());
    }
}
