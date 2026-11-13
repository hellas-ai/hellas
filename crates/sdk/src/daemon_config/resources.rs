use super::*;
use hellas_auth::{Digest, authority::Revision};
use hellas_authority::model::grant::{
    configuration::{ConfiguredBudget, NodeConfiguration},
    pricing::{Pricing, UnitPrice},
    records::{ConfigChange, GrantPolicy},
    resource::{AccountingProfile, HttpsResource, PathModelPolicy},
    responses::ResponsesResource,
};
use hellas_gateway::Presentation;
use hellas_rpc::protocol::invocation::{Admission, ComputePrograms, InvocationPolicy, Limits};

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
        package: PathBuf,
    },
    Https {
        https: HttpsResource,
        /// Private provider binding; never included in a signed offer.
        #[serde(default)]
        credential: Option<String>,
    },
    Responses {
        responses: ResponsesResource,
    },
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
    pub(crate) fn model_evaluators(
        &self,
        info: &[hellas_gateway::BackendInfo],
    ) -> BTreeMap<PathBuf, std::collections::BTreeSet<String>> {
        let mut requested: BTreeMap<PathBuf, std::collections::BTreeSet<String>> = BTreeMap::new();
        for route in &self.routes {
            if let Presentation::Model { package, .. } = &route.presentation {
                let evaluators = requested.entry(package.clone()).or_default();
                for id in &route.backends {
                    if let Some(evaluator) = info
                        .iter()
                        .find(|backend| backend.id == *id)
                        .and_then(|backend| backend.evaluator.clone())
                    {
                        evaluators.insert(evaluator);
                    }
                }
            }
        }
        for resource in &self.resources {
            if let ResourceKind::Model { package } = &resource.kind {
                let evaluators = requested.entry(package.clone()).or_default();
                if let Some(evaluator) = info
                    .iter()
                    .find(|backend| backend.id == resource.backend)
                    .and_then(|backend| backend.evaluator.clone())
                {
                    evaluators.insert(evaluator);
                }
            }
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
            let packages =
                hellas_client::model::ModelPackage::open_many(&path, evaluators, None).await?;
            models.insert(path, Ok(packages));
        }
        self.configuration(info, &models)
    }

    /// The same provider resource definitions drive public policy and private bindings.
    fn configured_resources(&self) -> Result<Vec<Resource>, crate::daemon::Error> {
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
                        if let Presentation::Model { model, package, .. } = &route.presentation {
                            let mut resource = Resource::new(
                                model.clone(),
                                id.clone(),
                                ResourceKind::Model {
                                    package: package.clone(),
                                },
                            );
                            resource.rates = Some(vec![]);
                            resource.max_job_millis = std::num::NonZeroU64::new(900_000).unwrap();
                            inputs.push(resource);
                        }
                    }
                }
                BackendKind::Fetch {
                    upstream: Upstream::Http { credential, .. },
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
                        let https = resource.get_or_insert_with(|| HttpsResource {
                            origin: url.origin().ascii_serialization(),
                            paths: vec![],
                            methods: vec!["POST".into()],
                            account_backed: credential.is_some(),
                            tls: target.route.tls.clone(),
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
                    if let Some(https) = resource {
                        let mut resource = Resource::new(
                            id.clone(),
                            id.clone(),
                            ResourceKind::Https {
                                https,
                                credential: credential.clone(),
                            },
                        );
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
        Ok(inputs)
    }

    pub(crate) fn http_credentials(
        &self,
        backend: &str,
    ) -> Result<BTreeMap<ResourceId, Option<String>>, crate::daemon::Error> {
        Ok(self
            .configured_resources()?
            .into_iter()
            .filter_map(|resource| {
                if resource.backend != backend {
                    return None;
                }
                match resource.kind {
                    ResourceKind::Https { credential, .. } => Some((resource.resource, credential)),
                    _ => None,
                }
            })
            .collect())
    }

    pub(crate) fn configuration(
        &self,
        backends: &[hellas_gateway::BackendInfo],
        models: &hellas_gateway::router::Models,
    ) -> Result<NodeConfiguration, crate::daemon::Error> {
        let inputs = self.configured_resources()?;
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
        let (invocation_policy, https, responses) = match (&self.kind, &backend.kind) {
            (ResourceKind::Model { package }, BackendKind::Local { .. }) => {
                let evaluator = backends
                    .iter()
                    .find(|b| b.id == self.backend)
                    .and_then(|b| b.evaluator.as_deref())
                    .ok_or("local backend has no evaluator")?;
                let package = models
                    .get(package)
                    .ok_or("model was not prepared")?
                    .as_ref()
                    .map_err(|error| error.clone())?
                    .get(evaluator)
                    .ok_or("model evaluator was not prepared")?;
                let programs = if package.is_image() {
                    ComputePrograms::Any {}
                } else {
                    ComputePrograms::Only {
                        manifests: vec![package.program()?.manifest],
                    }
                };
                (
                    InvocationPolicy {
                        admissions: vec![Admission::Compute {
                            evaluator: evaluator.into(),
                            programs,
                        }],
                        limits: Limits {
                            max_upload_bytes: 8 << 20,
                            max_output_bytes: 4 << 20,
                            max_steps: 4096,
                            execution_timeout_ms: self.max_job_millis.get(),
                        },
                    },
                    None,
                    None,
                )
            }
            (kind, BackendKind::Fetch { upstream, .. }) => {
                let (https, responses) = match (kind, upstream) {
                    (
                        ResourceKind::Https { https, credential },
                        Upstream::Http { credentials, .. },
                    ) => {
                        if credential
                            .as_ref()
                            .is_some_and(|key| !credentials.contains_key(key))
                        {
                            return Err("unknown HTTPS credential alias".into());
                        }
                        let mut https = https.clone();
                        https.account_backed = credential.is_some();
                        (Some(https), None)
                    }
                    (ResourceKind::Responses { responses }, Upstream::OpenaiResponses { .. }) => {
                        (None, Some(responses.clone()))
                    }
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
                (policy, https, responses)
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
            https,
            responses,
            pricing: Pricing {
                revision: Revision(1),
                rates: self.rates.clone(),
            },
        })
    }
}
