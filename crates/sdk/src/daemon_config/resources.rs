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
    Https { https: HttpsResource },
    Responses { responses: ResponsesResource },
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
    pub(crate) async fn configuration(
        &self,
        backends: &[hellas_gateway::BackendInfo],
    ) -> Result<NodeConfiguration, crate::daemon::Error> {
        let mut resources = Vec::new();
        let mut accounts: BTreeMap<_, _> = self.budgets.iter().cloned().collect();
        if accounts.len() != self.budgets.len() {
            return Err("duplicate account budget".into());
        }
        for input in &self.resources {
            let backend = self
                .backends
                .get(&input.backend)
                .ok_or("resource backend is missing")?;
            let BackendKind::Fetch { upstream, .. } = &backend.kind else {
                return Err("resource backend is not Fetch".into());
            };
            let (https, responses) = match (&input.kind, upstream) {
                (ResourceKind::Https { https }, Upstream::Http { credentials, .. }) => {
                    if https
                        .credential
                        .as_ref()
                        .is_some_and(|key| !credentials.contains_key(key))
                    {
                        return Err("unknown HTTPS credential alias".into());
                    }
                    (Some(https.clone()), None)
                }
                (ResourceKind::Responses { responses }, Upstream::OpenaiResponses { .. }) => {
                    (None, Some(responses.clone()))
                }
                _ => return Err("resource and backend protocols disagree".into()),
            };
            let mut invocation_policy = backend.fetch_policy()?;
            invocation_policy.limits = Limits {
                max_upload_bytes: 128 << 10,
                max_output_bytes: if responses.is_some() {
                    1 << 20
                } else {
                    4 << 20
                },
                max_steps: 1,
                execution_timeout_ms: input.max_job_millis.get(),
            };
            for admission in &mut invocation_policy.admissions {
                if let Admission::Fetch { admission } = admission {
                    admission.limits = hellas_rpc::protocol::invocation::fetch::FetchLimits {
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
            resources.push(GrantPolicy {
                resource: input.resource,
                account: input.account,
                revision: Revision(1),
                name: input.name.clone(),
                config_change: input.config_change,
                invocation_policy,
                https,
                responses,
                pricing: Pricing {
                    revision: Revision(1),
                    rates: input.rates.clone(),
                },
            });
            accounts.entry(input.account).or_insert(ConfiguredBudget {
                max_in_flight: u16::try_from(backend.max_in_flight.get())?.try_into()?,
                limits: vec![],
            });
        }
        // The CLI's model routes also publish their local resources when serving over iroh.
        for (backend_id, backend) in &self.backends {
            if self.resources.iter().any(|r| r.backend == *backend_id)
                || !self.listeners.values().any(|l| matches!(l, Listener::Iroh { backends, .. } if backends.contains(backend_id))) {
                continue;
            }
            let mut add = |name: &str, invocation_policy, https| {
                let account = id("account", backend_id);
                accounts.entry(account).or_insert(ConfiguredBudget {
                    max_in_flight: u16::try_from(backend.max_in_flight.get())?.try_into()?,
                    limits: vec![],
                });
                resources.push(GrantPolicy {
                    resource: id("resource", name),
                    account,
                    revision: Revision(1),
                    name: name.into(),
                    config_change: Default::default(),
                    invocation_policy,
                    https,
                    responses: None,
                    pricing: Pricing {
                        revision: Revision(1),
                        rates: Some(vec![]),
                    },
                });
                Ok::<_, crate::daemon::Error>(())
            };
            match &backend.kind {
                BackendKind::Local { .. } => {
                    for route in self
                        .routes
                        .iter()
                        .filter(|r| r.backends.contains(backend_id))
                    {
                        let Presentation::Model { model, package, .. } = &route.presentation else {
                            continue;
                        };
                        let evaluator = backends
                            .iter()
                            .find(|b| b.id == *backend_id)
                            .and_then(|b| b.evaluator.as_deref())
                            .ok_or("local backend has no evaluator")?;
                        let package =
                            hellas_client::model::ModelPackage::open(package, evaluator).await?;
                        let programs = if package.is_image() {
                            ComputePrograms::Any {}
                        } else {
                            ComputePrograms::Only {
                                manifests: vec![package.program()?.manifest],
                            }
                        };
                        add(
                            model,
                            InvocationPolicy {
                                admissions: vec![Admission::Compute {
                                    evaluator: evaluator.into(),
                                    programs,
                                }],
                                limits: Limits {
                                    max_upload_bytes: 8 << 20,
                                    max_output_bytes: 4 << 20,
                                    max_steps: 4096,
                                    execution_timeout_ms: 900_000,
                                },
                            },
                            None,
                        )?;
                    }
                }
                BackendKind::Fetch {
                    upstream: Upstream::Http { .. },
                    ..
                } => {
                    let targets: Vec<_> = self
                        .routes
                        .iter()
                        .filter_map(|r| match &r.presentation {
                            Presentation::Http { targets } => {
                                targets.get(backend_id).filter(|t| t.route.models.is_some())
                            }
                            _ => None,
                        })
                        .collect();
                    let Some(first) = targets.first() else {
                        continue;
                    };
                    let origin = url::Url::parse(&first.route.url)?
                        .origin()
                        .ascii_serialization();
                    let mut paths = BTreeMap::<String, Vec<String>>::new();
                    for target in &targets {
                        let url = url::Url::parse(&target.route.url)?;
                        if url.origin().ascii_serialization() != origin {
                            return Err("model upstream routes have different origins".into());
                        }
                        let models = paths.entry(url.path().into()).or_default();
                        for model in target
                            .route
                            .models
                            .as_ref()
                            .ok_or("missing model selector")?
                        {
                            if !models.contains(model) {
                                models.push(model.clone());
                            }
                        }
                    }
                    add(
                        backend_id,
                        backend.fetch_policy()?,
                        Some(HttpsResource {
                            origin,
                            paths: paths.keys().cloned().collect(),
                            methods: vec!["POST".into()],
                            credential: first.route.credential.clone(),
                            tls: first.route.tls.clone(),
                            accounting: AccountingProfile::None,
                            max_output_tokens: 0,
                            max_response_bytes: first.route.max_response_bytes,
                            model_policy: Some(
                                paths
                                    .into_iter()
                                    .map(|(path, models)| PathModelPolicy { path, models })
                                    .collect(),
                            ),
                        }),
                    )?;
                }
                _ => {}
            }
        }
        accounts.retain(|id, _| resources.iter().any(|p| p.account == *id));
        let machine = self.machine.clone().or_else(|| {
            (!resources.is_empty()).then(|| ConfiguredBudget {
                max_in_flight: std::num::NonZeroU16::new(256).unwrap(),
                limits: vec![],
            })
        });
        Ok(NodeConfiguration::new(machine, accounts, resources)?)
    }
}
