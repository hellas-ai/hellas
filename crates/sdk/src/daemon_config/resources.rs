use super::*;
use hellas_auth::{Digest, authority::Revision};
use hellas_authority::model::grant::{
    configuration::{ConfiguredBudget, NodeConfiguration},
    pricing::{Pricing, UnitPrice},
    records::{ConfigChange, GrantPolicy},
    resource::{AccountingProfile, HttpsResource, PathModelPolicy},
    responses::ResponsesResource,
};
use hellas_client::model::ModelSpec;
use hellas_gateway::Presentation;
use hellas_rpc::protocol::invocation::{Admission, InvocationPolicy, Limits, Match};

/// Operator terms for a named resource. Core derives the executable policy and
/// the authority journal assigns its revision at commit.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub name: String,
    pub backend: String,
    pub resource: ResourceId,
    pub account: ResourceId,
    #[serde(default)]
    pub config_change: ConfigChange,
    #[serde(default)]
    pub rates: Option<Vec<UnitPrice>>,
    #[serde(default = "job_millis")]
    pub max_job_millis: std::num::NonZeroU64,
    pub kind: ResourceKind,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceKind {
    Model {
        package: ModelSpec,
        /// When omitted, derive the exact programs and setup entries from the package.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rules: Option<Vec<Match>>,
    },
    Https {
        https: HttpsResource,
    },
    Responses {
        responses: ResponsesResource,
    },
}
fn account_backed(https: &HttpsResource, credentials: &[Credential]) -> bool {
    credentials.iter().any(|credential| {
        credential.allowed_origins.contains(&https.origin)
            && credential.allowed_paths.iter().any(|scope| {
                https
                    .paths
                    .iter()
                    .any(|path| hellas_rpc::http_fetch::path::matches(scope, path))
            })
            && credential
                .allowed_methods
                .iter()
                .any(|method| https.methods.contains(method))
    })
}
fn job_millis() -> std::num::NonZeroU64 {
    std::num::NonZeroU64::new(300_000).unwrap()
}
fn id(domain: &str, name: &str) -> ResourceId {
    ResourceId(Digest::hash(
        format!("hellas.daemon.{domain}.v1:{name}").as_bytes(),
    ))
}
impl Resource {
    pub fn new(name: String, backend: String, kind: ResourceKind) -> Self {
        Self {
            resource: id("resource", &name),
            account: id("account", &backend),
            name,
            backend,
            kind,
            config_change: Default::default(),
            rates: None,
            max_job_millis: job_millis(),
        }
    }
}
impl Document {
    /// All native packages and the backends that serve them, from routes and grants alike.
    pub(crate) fn model_bindings(&self) -> impl Iterator<Item = (&ModelSpec, &String)> {
        let routes = self
            .routes
            .iter()
            .filter_map(|r| Some((r.model_package()?.1, &r.backends)));
        routes
            .flat_map(|(spec, ids)| ids.iter().map(move |id| (spec, id)))
            .chain(self.resources.iter().filter_map(|r| match &r.kind {
                ResourceKind::Model { package, .. } => Some((package, &r.backend)),
                _ => None,
            }))
    }

    pub(crate) fn model_evaluators(
        &self,
        info: &[hellas_gateway::BackendInfo],
    ) -> BTreeMap<ModelSpec, std::collections::BTreeSet<String>> {
        let mut requested = BTreeMap::new();
        for (spec, id) in self.model_bindings() {
            let evaluators: &mut std::collections::BTreeSet<_> =
                requested.entry(spec.clone()).or_default();
            evaluators
                .extend(hellas_gateway::BackendInfo::evaluator_for(info, id).map(str::to_owned));
        }
        requested
    }

    #[cfg(any(test, feature = "integration-tests"))]
    pub(crate) async fn configuration_for_test(
        &self,
        info: &[hellas_gateway::BackendInfo],
    ) -> Result<NodeConfiguration, crate::daemon::Error> {
        let mut models = hellas_gateway::router::Models::new();
        for (path, evaluators) in self.model_evaluators(info) {
            let packages = path.open_many(evaluators, None).await?;
            models.insert(path, Ok(packages));
        }
        self.configuration(info, &models)
    }

    pub(crate) fn configuration(
        &self,
        backends: &[hellas_gateway::BackendInfo],
        models: &hellas_gateway::router::Models,
    ) -> Result<NodeConfiguration, crate::daemon::Error> {
        let mut inputs = self.resources.clone();
        for (id, backend) in &self.backends {
            if inputs.iter().any(|r| r.backend == *id)
                || !self
                    .listeners
                    .values()
                    .any(|l| matches!(l, Listener::Iroh { backends, .. } if backends.contains(id)))
            {
                continue;
            }
            match &backend.kind {
                BackendKind::Local { .. } => {
                    for route in self.routes.iter().filter(|r| r.backends.contains(id)) {
                        if let Some((model, package)) = route.model_package() {
                            let mut resource = Resource::new(
                                model.to_owned(),
                                id.clone(),
                                ResourceKind::Model {
                                    package: package.clone(),
                                    rules: None,
                                },
                            );
                            resource.rates = Some(vec![]);
                            resource.max_job_millis = std::num::NonZeroU64::new(900_000).unwrap();
                            inputs.push(resource);
                        }
                    }
                }
                BackendKind::Fetch {
                    upstream: Upstream::Http { credentials, .. },
                    ..
                } => {
                    let mut resource: Option<HttpsResource> = None;
                    for route in &self.routes {
                        let Presentation::Http { targets } = &route.presentation else {
                            continue;
                        };
                        let Some(target) = targets.get(id) else {
                            continue;
                        };
                        let Some(models) = &target.route.models else {
                            continue;
                        };
                        let url = url::Url::parse(&target.route.url)?;
                        let tls = target
                            .route
                            .validate()?
                            .tls
                            .ok_or("HTTPS model resources require TLS")?;
                        let https = resource.get_or_insert_with(|| HttpsResource {
                            queries: Default::default(),
                            origin: url.origin().ascii_serialization(),
                            paths: vec![],
                            methods: vec!["POST".into()],
                            account_backed: false,
                            tls,
                            accounting: AccountingProfile::None,
                            max_output_tokens: 0,
                            max_response_bytes: target.route.max_response_bytes,
                            model_policy: Some(vec![]),
                        });
                        if url.origin().ascii_serialization() != https.origin {
                            return Err("model upstream routes have different origins".into());
                        }
                        let policies = https
                            .model_policy
                            .as_mut()
                            .ok_or("missing model policies")?;
                        if let Some(policy) = policies.iter_mut().find(|p| p.path == url.path()) {
                            for model in models {
                                if !policy.models.contains(model) {
                                    policy.models.push(model.clone());
                                }
                            }
                        } else {
                            https.paths.push(url.path().into());
                            policies.push(PathModelPolicy {
                                path: url.path().into(),
                                models: models.clone(),
                            });
                        }
                    }
                    if let Some(mut https) = resource {
                        https.account_backed = account_backed(&https, credentials);
                        let mut resource =
                            Resource::new(id.clone(), id.clone(), ResourceKind::Https { https });
                        resource.rates = Some(vec![]);
                        resource.max_job_millis = std::num::NonZeroU64::new(86_400_000).unwrap();
                        inputs.push(resource);
                    }
                }
                BackendKind::Fetch { .. }
                | BackendKind::Grant { .. }
                | BackendKind::Paid { .. } => {}
            }
        }
        let mut resources = Vec::with_capacity(inputs.len());
        let mut accounts: BTreeMap<_, _> = self.budgets.iter().cloned().collect();
        if accounts.len() != self.budgets.len() {
            return Err("duplicate account budget".into());
        }
        for (index, input) in inputs.into_iter().enumerate() {
            let backend = self
                .backends
                .get(&input.backend)
                .ok_or("resource backend is missing")?;
            resources.push(input.policy(
                backend,
                backends,
                models,
                index >= self.resources.len(),
            )?);
            accounts.entry(input.account).or_insert(ConfiguredBudget {
                max_in_flight: u16::try_from(backend.max_in_flight.get())?.try_into()?,
                limits: vec![],
            });
        }
        accounts.retain(|id, _| resources.iter().any(|p| p.account == *id));
        let machine = self.machine.clone().or_else(|| {
            (!resources.is_empty()).then(|| ConfiguredBudget {
                max_in_flight: std::num::NonZeroU16::new(64).unwrap(),
                limits: vec![],
            })
        });
        Ok(NodeConfiguration::new(machine, accounts, resources)?)
    }
}
impl Resource {
    fn policy(
        &self,
        backend: &Backend,
        backends: &[hellas_gateway::BackendInfo],
        models: &hellas_gateway::router::Models,
        model_route: bool,
    ) -> Result<GrantPolicy, crate::daemon::Error> {
        let (invocation_policy, backend_evaluator, https, responses) =
            match (&self.kind, &backend.kind) {
                (ResourceKind::Model { package, rules }, BackendKind::Local { .. }) => {
                    let evaluator =
                        hellas_gateway::BackendInfo::evaluator_for(backends, &self.backend)
                            .ok_or("local backend has no evaluator")?;
                    let package = models
                        .get(package)
                        .ok_or("model was not prepared")?
                        .as_ref()
                        .map_err(|error| error.clone())?
                        .get(evaluator)
                        .ok_or("model evaluator was not prepared")?;
                    let admissions = match rules {
                        Some(rules) => {
                            if rules.len()
                                > hellas_rpc::protocol::invocation::policy::MAX_COMPUTE_PROGRAMS
                            {
                                return Err("too many model resource rules".into());
                            }
                            rules.iter().cloned().map(Admission::Compute).collect()
                        }
                        None => package.compute_admissions()?,
                    };
                    (
                        InvocationPolicy {
                            admissions,
                            limits: Limits {
                                max_upload_bytes: 8 << 20,
                                max_output_bytes: 4 << 20,
                                max_steps: 4096,
                                execution_timeout_ms: self.max_job_millis.get(),
                            },
                        },
                        Some(evaluator.to_owned()),
                        None,
                        None,
                    )
                }
                (kind, BackendKind::Fetch { upstream, .. }) => {
                    let (https, responses) = match (kind, upstream) {
                        (ResourceKind::Https { https }, Upstream::Http { credentials, .. }) => {
                            if https.account_backed != account_backed(https, credentials) {
                                return Err(
                                    "HTTPS account_backed disagrees with backend credential scopes"
                                        .into(),
                                );
                            }
                            (Some(https.clone()), None)
                        }
                        (
                            ResourceKind::Responses { responses },
                            Upstream::OpenaiResponses { .. },
                        ) => (None, Some(responses.clone())),
                        _ => return Err("resource and backend protocols disagree".into()),
                    };
                    let mut policy = backend.fetch_policy()?;
                    if !model_route {
                        policy.limits = Limits {
                            max_upload_bytes: 128 << 10,
                            max_output_bytes: if responses.is_some() {
                                1 << 20
                            } else {
                                4 << 20
                            },
                            max_steps: 1,
                            execution_timeout_ms: self.max_job_millis.get(),
                        };
                        for admission in &mut policy.admissions {
                            if let Admission::Fetch { admission } = admission {
                                admission.limits =
                                    hellas_rpc::protocol::invocation::fetch::FetchLimits {
                                        max_request_body_bytes: 64 << 10,
                                        max_output_events: 4096,
                                        max_spool_bytes: if responses.is_some() {
                                            4 << 20
                                        } else {
                                            8 << 20
                                        },
                                        max_encoded_result_frame: 4 << 20,
                                        max_encoded_prepared_input: 128 << 10,
                                    };
                            }
                        }
                    }
                    (policy, None, https, responses)
                }
                _ => return Err("resource and backend protocols disagree".into()),
            };
        Ok(GrantPolicy {
            resource: self.resource,
            account: self.account,
            revision: Revision(1),
            name: self.name.clone(),
            config_change: self.config_change,
            invocation_policy,
            backend_evaluator,
            https,
            responses,
            pricing: Pricing {
                revision: Revision(1),
                rates: self.rates.clone(),
            },
        })
    }
}
