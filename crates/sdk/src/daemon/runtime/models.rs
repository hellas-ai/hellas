use super::{Result, Runtime};
#[cfg(feature = "compute")]
use crate::daemon_config::BackendKind;
use crate::daemon_config::Document;
#[cfg(feature = "compute")]
use anyhow::Context as _;
use hellas_client::model::ModelPackage;
use hellas_gateway::{BackendInfo, router::Models};
use hellas_rpc::ContentRef;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

pub(in crate::daemon) type Files = BTreeMap<PathBuf, ContentRef>;
#[cfg(not(feature = "compute"))]
pub(in crate::daemon) type ModelIndex = ();
#[cfg(feature = "compute")]
pub(in crate::daemon) struct ModelIndex {
    files: Files,
    hub: Vec<hellas_store::hf::PinnedFile>,
    models: Vec<(PathBuf, hellas_rpc::protocol::invocation::compute::Model)>,
}
#[derive(Default)]
pub(super) struct Cached {
    sources: hellas_client::model::ModelFiles,
    files: Files,
    packages: BTreeMap<String, Arc<ModelPackage>>,
}
impl Runtime {
    pub async fn models(
        &self,
        document: &Document,
        info: &[BackendInfo],
    ) -> (
        Models,
        BTreeMap<String, std::result::Result<ModelIndex, String>>,
    ) {
        let requested = document.model_evaluators(info);
        let mut cache = self.models.lock().await;
        cache.retain(|path, _| requested.contains_key(path));
        let mut models = Models::new();
        for (path, evaluators) in requested {
            let prepared: Result<_> = async {
                if evaluators.is_empty() {
                    return Err("model has no registered evaluator".into());
                }
                let cached = cache.entry(path.clone()).or_default();
                let has_local = path.paths().any(hellas_client::model::is_local);
                if has_local || cached.packages.is_empty() {
                    let sources = path.files().await?;
                    let files = self
                        .options
                        .content
                        .inspect_files(sources.local.clone())
                        .await?;
                    if cached.files != files {
                        cached.packages.clear();
                        cached.files = files;
                    }
                    cached.sources = sources;
                }
                let missing = evaluators
                    .iter()
                    .filter(|evaluator| !cached.packages.contains_key(*evaluator))
                    .cloned()
                    .collect::<Vec<_>>();
                cached
                    .packages
                    .extend(path.open_many(missing, Some(&self.options.content)).await?);
                Ok(cached
                    .packages
                    .iter()
                    .filter(|(id, _)| evaluators.contains(*id))
                    .map(|(id, package)| (id.clone(), package.clone()))
                    .collect())
            }
            .await;
            models.insert(path, prepared.map_err(|error| error.to_string()));
        }
        #[cfg(not(feature = "compute"))]
        return (models, BTreeMap::new());
        #[cfg(feature = "compute")]
        {
            let mut index = BTreeMap::new();
            for (id, backend) in &document.backends {
                let BackendKind::Local { content, .. } = &backend.kind else {
                    continue;
                };
                let paths: std::collections::BTreeSet<_> = document
                    .model_bindings()
                    .filter_map(|(spec, backend)| (backend == id).then_some(spec))
                    .collect();
                let files: Result<_> = async {
                    let mut files = self.options.content.inspect_files(content.clone()).await?;
                    let mut hub = Vec::new();
                    let mut catalogs = Vec::new();
                    for spec in paths {
                        let packages = models[spec]
                            .as_ref()
                            .map_err(|e| anyhow::anyhow!(e.clone()))?;
                        let package = packages
                            .values()
                            .next()
                            .context("model has no registered evaluator")?;
                        let cached = &cache[spec];
                        files.extend(cached.files.clone());
                        hub.extend_from_slice(&cached.sources.hub);
                        catalogs.push((spec.model.clone(), package.model().clone()));
                    }
                    Ok(ModelIndex {
                        files,
                        hub,
                        models: catalogs,
                    })
                }
                .await;
                index.insert(id.clone(), files.map_err(|err| err.to_string()));
            }
            (models, index)
        }
    }

    /// Cache inspection is read-only; activation publishes the exact prepared objects.
    #[cfg(feature = "compute")]
    pub async fn index(&self, index: ModelIndex) -> Result<()> {
        let ModelIndex { files, hub, models } = index;
        use hellas_store::content::{ContentStore, IndexMode, PinTarget, PinValue, Scope, Target};
        for file in hub {
            file.acquire(&self.options.content).await?;
        }
        let mut indexed = self.indexed.lock().await;
        if !files
            .iter()
            .all(|(path, object)| indexed.get(path) == Some(object))
        {
            let inspected = self
                .options
                .content
                .inspect_files(files.keys().cloned().collect())
                .await?;
            if inspected != files {
                return Err("model content changed after preparation".into());
            }
            let mut next = indexed.clone();
            next.extend(files.iter().map(|(path, object)| (path.clone(), *object)));
            self.options
                .content
                .rescan(next.keys().cloned().collect(), IndexMode::Resume)
                .await?;
            for object in files.into_values() {
                let pin = PinTarget::model_object(object)?;
                let old =
                    hellas_store::content::owner_pin(&self.options.content, &pin.name).await?;
                let value = PinValue {
                    target: Target::Object(object),
                    policy: pin.policy,
                    expires: None,
                };
                if old.as_ref() != Some(&value) {
                    self.options
                        .content
                        .set_pin(&Scope::Owner, &pin.name, old.as_ref(), Some(value))
                        .await?;
                }
            }
            *indexed = next;
        }
        drop(indexed);
        for (path, model) in models {
            if let Some(uri) = hellas_client::model::peer_uri(&path) {
                hellas_client::model::acquire_peer_model(uri, &self.options.content).await?;
            }
            hellas_client::model::publish_model(&self.options.content, &model).await?;
        }
        Ok(())
    }
}
