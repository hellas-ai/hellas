//! HTTP route declarations and execution on the selected backend.
use crate::{WorkExecutionBackend, WorkFetchRequest, WorkGatewayError, WorkOutputStream};
use hellas_client::model::{ModelKind, ModelPackage, ModelRequest};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub backends: Vec<String>,
    #[serde(flatten)]
    pub presentation: Presentation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Presentation {
    Model {
        model: String,
        package: PathBuf,
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
        service: String,
        method: String,
        route: crate::HttpRoute,
    },
}
fn default_tokens() -> u32 {
    128
}

impl Route {
    pub(crate) fn keys(&self) -> Vec<(String, String, Option<String>)> {
        let (paths, method, models) = match &self.presentation {
            Presentation::Model { model, package, .. } => (
                match ModelKind::of(package) {
                    ModelKind::Text => crate::state::PATHS.to_vec(),
                    ModelKind::Transcription => vec![crate::audio::PATH],
                    ModelKind::Image => vec![crate::image::PATH],
                },
                "POST",
                vec![model.clone()],
            ),
            Presentation::Responses { models, .. } => {
                (vec![crate::responses_fetch::PATH], "POST", models.clone())
            }
            Presentation::Http { route, .. } => (
                vec![route.path.as_str()],
                route.method.as_str(),
                route.models.clone().unwrap_or_default(),
            ),
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
    pub async fn open(
        route: &Route,
        work: Arc<dyn WorkExecutionBackend>,
    ) -> crate::GatewayResult<Arc<Self>> {
        let packages = match &route.presentation {
            Presentation::Model { package, .. } => {
                let backends = work.backends();
                let evaluators = route
                    .backends
                    .iter()
                    .map(|id| {
                        backends
                            .iter()
                            .find(|b| b.id == *id)
                            .and_then(|b| b.evaluator.clone())
                            .ok_or_else(|| {
                                crate::GatewayError::Presentation(
                                    format!("backend {id} has no Compute evaluator").into(),
                                )
                            })
                    })
                    .collect::<crate::GatewayResult<Vec<_>>>()?;
                ModelPackage::open_many(package, evaluators)
                    .await
                    .map_err(|error| crate::GatewayError::Presentation(error.into()))?
            }
            _ => BTreeMap::new(),
        };
        Ok(Arc::new(Self { work, packages }))
    }

    pub async fn compute(
        &self,
        selection: &mut crate::routing::Selection,
        request: &ModelRequest<'_>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(Arc<ModelPackage>, WorkOutputStream<crate::ComputeEvent>), WorkGatewayError> {
        let mut last = WorkGatewayError::Busy(crate::WorkGatewayBusy);
        while let Some(id) = selection.next() {
            let evaluator = self
                .work
                .backends()
                .into_iter()
                .find(|b| b.id == id)
                .and_then(|b| b.evaluator)
                .ok_or(WorkGatewayError::Unsupported)?;
            let package = self
                .packages
                .get(&evaluator)
                .ok_or(WorkGatewayError::Unsupported)?
                .clone();
            let attempt = async {
                let job = package
                    .render_job(request)
                    .await
                    .map_err(|error| WorkGatewayError::Rejected(error.into()))?;
                first(self.work.run(&id, job)).await
            };
            match crate::before_deadline(deadline, attempt)
                .await
                .map_err(|_| WorkGatewayError::Timeout("preparation timed out".into()))?
            {
                Ok(stream) => {
                    selection.accept(&id);
                    return Ok((package, stream));
                }
                Err(WorkGatewayError::PreProposal(error)) => last = *error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }

    pub async fn fetch(
        &self,
        selection: &mut crate::routing::Selection,
        request: WorkFetchRequest,
    ) -> Result<crate::WorkFetchStream, WorkGatewayError> {
        let mut last = WorkGatewayError::Busy(crate::WorkGatewayBusy);
        while let Some(id) = selection.next() {
            match first(self.work.fetch(&id, request.clone())).await {
                Ok(stream) => {
                    selection.accept(&id);
                    return Ok(stream);
                }
                Err(WorkGatewayError::PreProposal(error)) => last = *error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }
}

// No presentation sees output until the failover boundary has been resolved.
async fn first<E: Send + 'static>(
    stream: Result<WorkOutputStream<E>, WorkGatewayError>,
) -> Result<WorkOutputStream<E>, WorkGatewayError> {
    use futures::StreamExt;
    let mut stream = stream?;
    match stream.next().await {
        Some(Err(error)) => Err(error),
        Some(Ok(event)) => Ok(Box::pin(
            futures::stream::once(std::future::ready(Ok(event))).chain(stream),
        )),
        None => Err(WorkGatewayError::Execution(
            "execution ended before acceptance".into(),
        )),
    }
}
