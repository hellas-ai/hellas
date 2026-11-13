use super::*;
use hellas_auth::{
    Digest,
    authority::{ResourceId, Revision},
};
use hellas_authority::model::grant::{
    configuration::{ConfiguredBudget, NodeConfiguration},
    pricing::Pricing,
    records::GrantPolicy,
    resource::{AccountingProfile, HttpsResource, PathModelPolicy},
};
use hellas_rpc::protocol::invocation::{Admission, ComputePrograms, InvocationPolicy, Limits};
use std::collections::BTreeMap;

fn resource(name: &str) -> ResourceId {
    ResourceId(Digest::hash(
        format!("hellas.daemon.resource.v1:{name}").as_bytes(),
    ))
}

/// The route verbs publish bounded resources for their own entries. Other
/// authority configuration, including operator budgets, remains explicit.
pub(super) async fn refresh(
    document: &mut Document,
    evaluator: Option<&str>,
    catalogue: &[GrantPolicy],
) -> Result<()> {
    let previous = |name: &str| {
        document
            .authority
            .resources()
            .iter()
            .chain(catalogue)
            .find(|policy| policy.resource == resource(name))
    };
    let mut resources: Vec<_> = document
        .authority
        .resources()
        .iter()
        .filter(|policy| policy.resource != resource(&policy.name))
        .cloned()
        .collect();
    let mut accounts: BTreeMap<_, _> = document.authority.accounts().cloned().collect();
    for (id, backend) in &document.backends {
        match &backend.kind {
            BackendKind::Local { .. } => {
                for route in document
                    .routes
                    .iter()
                    .filter(|route| route.backends.contains(id))
                {
                    let Presentation::Model { model, package, .. } = &route.presentation else {
                        continue;
                    };
                    let evaluator = evaluator.context("local models require the compute build")?;
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
                        previous(model),
                        &mut resources,
                        &mut accounts,
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
                        backend.max_in_flight,
                    )?;
                }
            }
            BackendKind::Fetch {
                upstream: hellas_sdk::daemon_config::Upstream::OpenaiHttp { .. },
                ..
            } => {
                let targets: Vec<_> = document
                    .routes
                    .iter()
                    .filter_map(|route| match &route.presentation {
                        Presentation::Http { targets } => targets.get(id),
                        _ => None,
                    })
                    .collect();
                let Some(first) = targets.first() else {
                    continue;
                };
                let url = reqwest::Url::parse(&first.route.url)?;
                let mut paths = BTreeMap::<String, Vec<String>>::new();
                for target in &targets {
                    let path = reqwest::Url::parse(&target.route.url)?.path().to_owned();
                    let models = paths.entry(path).or_default();
                    for model in target
                        .route
                        .models
                        .as_ref()
                        .context("model route needs an exact model")?
                    {
                        if !models.contains(model) {
                            models.push(model.clone());
                        }
                    }
                }
                let template = HttpsResource {
                    origin: url.origin().ascii_serialization(),
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
                };
                add(
                    previous(id),
                    &mut resources,
                    &mut accounts,
                    id,
                    backend.fetch_policy().map_err(anyhow::Error::from_boxed)?,
                    Some(template),
                    backend.max_in_flight,
                )?;
            }
            _ => {}
        }
    }
    accounts.retain(|id, _| resources.iter().any(|policy| policy.account == *id));
    let machine = document.authority.machine().cloned().or_else(|| {
        (!resources.is_empty()).then(|| ConfiguredBudget {
            max_in_flight: std::num::NonZeroU16::new(64).unwrap(),
            limits: vec![],
        })
    });
    document.authority = NodeConfiguration::new(machine, accounts, resources)?;
    Ok(())
}

fn add(
    previous: Option<&GrantPolicy>,
    resources: &mut Vec<GrantPolicy>,
    accounts: &mut BTreeMap<ResourceId, ConfiguredBudget>,
    name: &str,
    invocation_policy: InvocationPolicy,
    https: Option<HttpsResource>,
    capacity: std::num::NonZeroUsize,
) -> Result<()> {
    let id = resource(name);
    let account = ResourceId(Digest::hash(
        format!("hellas.daemon.account.v1:{name}").as_bytes(),
    ));
    let mut policy = GrantPolicy {
        resource: id,
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
    };
    if let Some(old) = previous {
        policy.revision = old.revision;
        policy.config_change = old.config_change;
        policy.pricing = old.pricing.clone();
        if policy != *old {
            policy.revision = old.revision.next().context("resource revision exhausted")?;
        }
    }
    accounts.entry(account).or_insert(ConfiguredBudget {
        max_in_flight: u16::try_from(capacity.get())?.try_into()?,
        limits: vec![],
    });
    resources.push(policy);
    Ok(())
}
