//! Read a content-addressed model through the selected provider's content service.
use anyhow::{Context, Result, ensure};
use futures::StreamExt;
use hellas_rpc::{ContentId, ContentRef, protocol::invocation::compute::Model};
use hellas_store::content::{ContentStore, Path, PinName, RemoteStore, Reservations, Scope};
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{Arc, LazyLock},
};

#[derive(Debug, thiserror::Error)]
#[error("model is unavailable under the provider's content policy")]
pub struct CatalogUnavailable;

#[derive(Clone)]
pub(crate) struct PeerModel {
    pub(crate) model: Arc<Model>,
    store: Arc<dyn ContentStore>,
    pin: PinName,
    _endpoint: Option<iroh::Endpoint>,
}

// The synchronous GGUF and safetensors parsers also serve callers outside Tokio.
// Drive content requests on one I/O worker, independent of the caller's runtime.
fn peer_io<T: Send + 'static>(
    future: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    static IO: LazyLock<std::io::Result<tokio::runtime::Runtime>> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("model-content")
            .enable_all()
            .build()
    });
    let runtime = IO
        .as_ref()
        .map_err(|e| anyhow::anyhow!("model content runtime: {e}"))?;
    let (sender, result) = std::sync::mpsc::sync_channel(1);
    runtime.spawn(async move {
        let _ = sender.send(future.await);
    });
    result.recv()?
}

impl PeerModel {
    pub(super) fn open(id: ContentId, seeds: Vec<iroh::EndpointAddr>) -> Result<Self> {
        peer_io(Self::public(id, seeds))
    }

    async fn public(id: ContentId, seeds: Vec<iroh::EndpointAddr>) -> Result<Self> {
        use hellas_rpc::services::content::Content;
        ensure!(!seeds.is_empty(), "no peer known to hold {id}; add ?seed=");
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .bind()
            .await?;
        hellas_wire::iroh::close_on_error(&endpoint, async {
            let pool = hellas_wire::iroh::Pool::for_service::<Content>(
                endpoint.clone(),
                Default::default(),
            );
            for seed in seeds {
                let Ok(transport) = pool.transport(seed).await else {
                    continue;
                };
                let remote = RemoteStore::new(
                    transport,
                    Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
                )
                .reuse_read_manifest();
                match Self::connect(id, remote, Some(endpoint.clone())).await {
                    Err(error) if error.is::<CatalogUnavailable>() => continue,
                    result => return result,
                }
            }
            Err(CatalogUnavailable.into())
        })
        .await
    }

    pub(super) async fn connect(
        id: ContentId,
        remote: impl ContentStore + 'static,
        endpoint: Option<iroh::Endpoint>,
    ) -> Result<Self> {
        let pin = model_pin(id)?;
        let at = Path::new(pin.clone(), "model".into())?;
        let object = match remote.stat(&Scope::Public, &at).await {
            Ok(Some(stat)) => stat.target.object(),
            Ok(None)
            | Err(hellas_store::content::Error::Denied | hellas_store::content::Error::Missing) => {
                return Err(CatalogUnavailable.into());
            }
            Err(error) => return Err(error.into()),
        };
        ensure!(
            object.id() == id
                && object.bytes()
                    <= hellas_rpc::protocol::invocation::compute::MAX_ENVIRONMENT_BYTES as u64,
            "unexpected model object identity or size"
        );
        let bytes = read(&remote, &at, object, 0..object.bytes()).await?;
        let model = Model::from_canonical_bytes(&bytes)?;
        ensure!(model.content_id()? == id, "model identity mismatch");

        Ok(Self {
            model: Arc::new(model),
            store: Arc::new(remote),
            pin,
            _endpoint: endpoint,
        })
    }

    pub(crate) fn object(&self, name: &str) -> Result<ContentRef> {
        self.model
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.object)
            .with_context(|| format!("missing model asset {name}"))
    }

    pub(crate) fn read(&self, object: ContentRef, range: Range<u64>) -> Result<Vec<u8>> {
        let at = Path::new(self.pin.clone(), object.id().to_string())?;
        let store = self.store.clone();
        peer_io(async move { read(&*store, &at, object, range).await })
    }
}

/// Acquire all original objects for a peer-backed local executor.
pub async fn acquire_peer_model(
    id: ContentId,
    seeds: Vec<iroh::EndpointAddr>,
    store: &hellas_store::content::DiskStore,
) -> Result<()> {
    use hellas_store::content::PinTarget;
    let peer = PeerModel::public(id, seeds).await?;
    for asset in &peer.model.assets {
        let object = asset.object;
        let at = Path::new(peer.pin.clone(), object.id().to_string())?;
        store
            .acquire_peer_object(&*peer.store, &at, object, PinTarget::model_object(object)?)
            .await?;
    }
    Ok(())
}

async fn read(
    store: &dyn ContentStore,
    at: &Path,
    expected: ContentRef,
    range: Range<u64>,
) -> Result<Vec<u8>> {
    ensure!(
        range.start <= range.end && range.end <= expected.bytes(),
        "invalid model asset range"
    );
    let mut stream = store.read(&Scope::Public, at, range.clone()).await?;
    ensure!(
        stream.object == expected,
        "peer asset differs from the model"
    );
    let length = usize::try_from(range.end - range.start)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    while let Some(chunk) = stream.bytes.next().await {
        let chunk = chunk?;
        ensure!(chunk.len() <= length - bytes.len(), "oversized model range");
        bytes.extend_from_slice(&chunk);
    }
    ensure!(bytes.len() == length, "incomplete model range");
    Ok(bytes)
}

fn model_pin(id: ContentId) -> hellas_store::content::Result<PinName> {
    PinName::new(format!("models/by-id/{id}"))
}

/// Publish a model whose complete asset set is already held by this store.
/// Its catalog starts private to jobs. The owner controls subsequent visibility.
pub async fn publish_model(store: &impl ContentStore, model: &Model) -> Result<()> {
    use hellas_store::content::{Error, PinPolicy, PinValue, Target, Tree, owner_pin};
    let model_ref =
        hellas_channel::content::upload_object(store, &model.canonical_bytes()?).await?;
    let mut children = BTreeMap::from([("model".into(), Target::Object(model_ref))]);
    for asset in &model.assets {
        children.insert(asset.object.id().to_string(), Target::Object(asset.object));
    }
    let tree = Tree::new(children.into_iter().collect())?;
    let root = hellas_channel::content::upload_object(store, &tree.bytes()).await?;
    let name = model_pin(model_ref.id())?;
    let target = Target::Tree(root);
    let value = PinValue {
        target,
        policy: PinPolicy::Jobs,
        expires: None,
    };
    match store.set_pin(&Scope::Owner, &name, None, Some(value)).await {
        Ok(_) => Ok(()),
        Err(Error::Conflict) => {
            ensure!(
                owner_pin(store, &name)
                    .await?
                    .is_some_and(|pin| pin.target == target),
                "model publication pin names a different tree"
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
