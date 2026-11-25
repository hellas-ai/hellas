//! HTTP route declarations and execution on the selected backend.
use crate::{WorkExecutionBackend, WorkFetchRequest, WorkGatewayError, WorkOutputStream};
use hellas_client::model::{ModelKind, ModelPackage, ModelRequest, ModelSpec};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub backends: Vec<String>,
    #[serde(flatten)]
    pub presentation: Presentation,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Presentation {
    Model {
        model: String,
        package: ModelSpec,
        modality: ModelKind,
        #[serde(default = "default_tokens")]
        max_tokens: u32,
    },
    Responses {
        service: String,
        method: String,
        #[serde(default)]
        models: Vec<String>,
        #[serde(default)]
        overrides: serde_json::Map<String, serde_json::Value>,
    },
    Http {
        targets: BTreeMap<String, HttpTarget>,
    },
    Speech {
        model: String,
        target: crate::speech::SpeechTarget,
    },
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTarget {
    pub service: String,
    pub method: String,
    pub route: crate::HttpRoute,
}

fn default_tokens() -> u32 {
    128
}

impl Route {
    /// Packages needed by model presentations, including native speech.
    pub fn model_package(&self) -> Option<(&str, &ModelSpec)> {
        match &self.presentation {
            Presentation::Model { model, package, .. }
            | Presentation::Speech {
                model,
                target: crate::speech::SpeechTarget::Native { package, .. },
            } => Some((model, package)),
            _ => None,
        }
    }

    pub fn keys(&self) -> Vec<(String, String, Option<String>)> {
        let (paths, method, models) = match &self.presentation {
            Presentation::Model {
                model, modality, ..
            } => (
                match modality {
                    ModelKind::Text => crate::state::PATHS.to_vec(),
                    ModelKind::Decision => vec![crate::decision::PATH],
                    ModelKind::Transcription => vec![crate::audio::PATH],
                    ModelKind::Speech => vec![crate::speech::PATH],
                    ModelKind::Image => vec![crate::image::PATH],
                },
                "POST",
                vec![model.clone()],
            ),
            Presentation::Responses { models, .. } => {
                (vec![crate::responses_fetch::PATH], "POST", models.clone())
            }
            Presentation::Speech { model, .. } => {
                (vec![crate::speech::PATH], "POST", vec![model.clone()])
            }
            Presentation::Http { targets } => {
                let Some(target) = targets.values().next() else {
                    return vec![];
                };
                let route = &target.route;
                (
                    vec![route.path.as_str()],
                    route.method.as_str(),
                    route.models.clone().unwrap_or_default(),
                )
            }
        };
        paths
            .into_iter()
            .flat_map(|path| {
                if models.is_empty() {
                    vec![(path.into(), method.into(), None)]
                } else {
                    models
                        .iter()
                        .map(|model| (path.into(), method.into(), Some(model.clone())))
                        .collect()
                }
            })
            .collect()
    }
}

pub(crate) struct RouteExecution {
    pub work: Arc<dyn WorkExecutionBackend>,
    pub packages: BTreeMap<String, Arc<ModelPackage>>,
}

impl RouteExecution {
    pub fn require_kind(&self, kind: ModelKind) -> crate::GatewayResult<()> {
        if self.packages.is_empty() || self.packages.values().any(|package| package.kind() != kind)
        {
            return Err(crate::GatewayError::Presentation(
                "model package does not match presentation".into(),
            ));
        }
        Ok(())
    }

    pub async fn compute<'r>(
        &self,
        selection: &mut crate::routing::Selection,
        needs_step_bound: bool,
        request: impl Fn(Option<u64>) -> ModelRequest<'r>,
    ) -> Result<(Arc<ModelPackage>, WorkOutputStream<crate::ComputeEvent>), WorkGatewayError> {
        let request = &request;
        execute(selection, |id, job| async move {
            let backends = self.work.backends();
            let evaluator = crate::BackendInfo::evaluator_for(&backends, &id)
                .ok_or(WorkGatewayError::Unsupported)?;
            let package = self
                .packages
                .get(evaluator)
                .ok_or(WorkGatewayError::Unsupported)?;
            let steps = if needs_step_bound {
                self.work.max_steps(&id).await?
            } else {
                None
            };
            let prepared = package
                .render_job(&request(steps))
                .await
                .map_err(|error| WorkGatewayError::Rejected(error.into()))?;
            Ok((package.clone(), self.work.run(&id, job, prepared)?))
        })
        .await
    }

    pub async fn fetch(
        &self,
        selection: &mut crate::routing::Selection,
        request: impl Fn(&str) -> Result<WorkFetchRequest, WorkGatewayError>,
    ) -> Result<crate::WorkFetchStream, WorkGatewayError> {
        let request = &request;
        execute(selection, |id, job| async move {
            Ok(((), self.work.fetch(&id, job, request(&id)?)?))
        })
        .await
        .map(|(_, stream)| stream)
    }
}

// No presentation sees output until the shared failover boundary is resolved.
async fn execute<T, E: Send + 'static, F>(
    selection: &mut crate::routing::Selection,
    attempt: impl Fn(String, Arc<crate::jobs::Job>) -> F,
) -> Result<(T, WorkOutputStream<E>), WorkGatewayError>
where
    F: std::future::Future<Output = Result<(T, WorkOutputStream<E>), WorkGatewayError>>,
{
    use futures::StreamExt;
    let mut last = WorkGatewayError::Busy(crate::WorkGatewayBusy);
    let mut payment_required = None;
    while let Some(id) = selection.next() {
        let started = async {
            let (target, mut stream) = attempt(id.clone(), selection.job.clone()).await?;
            let first = stream.next().await.ok_or_else(|| {
                WorkGatewayError::Execution("execution ended before acceptance".into())
            })??;
            Ok((
                target,
                Box::pin(futures::stream::iter([Ok(first)]).chain(stream)) as WorkOutputStream<E>,
            ))
        }
        .await;
        match started {
            Ok(stream) => {
                selection.accept(&id);
                return Ok(stream);
            }
            Err(WorkGatewayError::PreProposal(error)) => match *error {
                WorkGatewayError::PaymentRequired(reason) => {
                    payment_required.get_or_insert((id, reason));
                }
                error => last = error,
            },
            Err(error) => return Err(error),
        }
    }
    if let Some((backend, reason)) = payment_required {
        selection.backend = Some(backend);
        return Err(reason.into());
    }
    Err(last)
}
