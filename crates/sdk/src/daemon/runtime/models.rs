use super::{Result, Runtime};
use crate::daemon_config::{BackendKind, Document, ResourceKind};
use hellas_client::model::ModelPackage;
use hellas_gateway::{BackendInfo, Presentation, router::Models};
use hellas_rpc::ContentRef;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

pub(in crate::daemon) type Files = BTreeMap<PathBuf, ContentRef>;
pub(super) struct Cached {
    files: Files,
    packages: BTreeMap<String, Arc<ModelPackage>>,
}
impl Runtime {
    pub async fn models(
        &self,
        document: &Document,
        info: &[BackendInfo],
    ) -> (Models, BTreeMap<String, std::result::Result<Files, String>>) {
        let requested = document.model_evaluators(info);
        let mut cache = self.models.lock().await;
        cache.retain(|path, _| requested.contains_key(path));
        let mut models = Models::new();
        for (path, evaluators) in requested {
            let prepared: Result<_> = async {
                if evaluators.is_empty() {
                    return Err("model has no registered evaluator".into());
                }
                let files = self
                    .options
                    .content
                    .inspect_files(vec![path.clone()])
                    .await?;
                let cached = cache.entry(path.clone()).or_insert_with(|| Cached {
                    files: Files::new(),
                    packages: BTreeMap::new(),
                });
                if cached.files != files {
                    cached.packages.clear();
                    cached.files = files;
                }
                let missing = evaluators
                    .iter()
                    .filter(|evaluator| !cached.packages.contains_key(*evaluator))
                    .cloned()
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    cached.packages.extend(
                        ModelPackage::open_many(&path, missing, Some(&self.options.content))
                            .await?,
                    );
                }
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
        drop(cache);
        let mut index = BTreeMap::new();
        for (id, backend) in &document.backends {
            let BackendKind::Local { content, .. } = &backend.kind else {
                continue;
            };
            let mut paths = BTreeSet::new();
            paths.extend(
                document
                    .routes
                    .iter()
                    .filter(|route| route.backends.contains(id))
                    .filter_map(|route| match &route.presentation {
                        Presentation::Model { package, .. } => Some(package.clone()),
                        _ => None,
                    }),
            );
            paths.extend(
                document
                    .resources
                    .iter()
                    .filter(|resource| resource.backend == *id)
                    .filter_map(|resource| match &resource.kind {
                        ResourceKind::Model { package } => Some(package.clone()),
                        _ => None,
                    }),
            );
            if let Err(error) = paths
                .iter()
                .try_for_each(|path| ModelPackage::require_local_weights(path))
            {
                index.insert(id.clone(), Err(error.to_string()));
                continue;
            }
            paths.extend(content.iter().cloned());
            index.insert(
                id.clone(),
                self.options
                    .content
                    .inspect_files(paths.into_iter().collect())
                    .await
                    .map_err(|error| error.to_string()),
            );
        }
        (models, index)
    }

    /// Cache inspection is read-only; activation publishes the exact prepared objects.
    #[cfg(feature = "compute")]
    pub async fn index(&self, files: Files) -> Result<()> {
        use hellas_store::content::{
            ContentStore, IndexMode, PinName, PinPolicy, PinValue, Scope, Target,
        };
        let mut indexed = self.indexed.lock().await;
        if files
            .iter()
            .all(|(path, object)| indexed.get(path) == Some(object))
        {
            return Ok(());
        }
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
            let name = PinName::new(format!("models/{}", object.id()))?;
            let old = hellas_store::content::owner_pin(&self.options.content, &name).await?;
            let value = PinValue {
                target: Target::Object(object),
                policy: PinPolicy::Jobs,
                expires: None,
            };
            if old.as_ref() != Some(&value) {
                self.options
                    .content
                    .set_pin(&Scope::Owner, &name, old.as_ref(), Some(value))
                    .await?;
            }
        }
        *indexed = next;
        Ok(())
    }
}
