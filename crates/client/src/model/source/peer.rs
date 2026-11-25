//! Read a content-addressed model through the selected provider's content service.
use anyhow::{Context, Result, ensure};
use futures::StreamExt;
use hellas_rpc::{ContentId, ContentRef, protocol::invocation::compute::Model};
use hellas_store::content::{ContentStore, Path, PinName, RemoteStore, Reservations, Scope};
use hellas_wire::{ServiceMarker, iroh::IrohTransport};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
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
    pub(super) fn open(uri: &str) -> Result<Self> {
        peer_io(Self::public(uri.to_owned()))
    }

    async fn public(uri: String) -> Result<Self> {
        let (id, address) = peer_locator(&uri)?;
        let address = address.context("hellas://model-id needs a provider; use --provider, --access, or append @NODE_ID[@IP:PORT]")?;
        let endpoint = if address.ip_addrs().next().is_some() {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        } else {
            iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        }
        .bind()
        .await?;
        let connection = endpoint
            .connect(
                address,
                hellas_rpc::services::content::Content::ALPN.as_bytes(),
            )
            .await?;
        let remote = RemoteStore::new(
            IrohTransport::new(connection),
            Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        );

        Self::connect(id, remote, Some(endpoint)).await
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

pub fn peer_locator(uri: &str) -> Result<(ContentId, Option<iroh::EndpointAddr>)> {
    let mut parts = uri
        .strip_prefix("hellas://")
        .context("expected a model URI")?
        .split('@');
    let id = parts.next().unwrap().parse()?;
    let Some(node) = parts.next() else {
        return Ok((id, None));
    };
    let mut address = iroh::EndpointAddr::new(node.parse()?);
    for socket in parts {
        address = address.with_ip_addr(
            socket
                .parse::<SocketAddr>()
                .context("invalid model peer address")?,
        );
    }
    Ok((id, Some(address)))
}

/// Acquire all original objects for a peer-backed local executor.
pub async fn acquire_peer_model(uri: &str, store: &hellas_store::content::DiskStore) -> Result<()> {
    use hellas_store::content::PinTarget;
    let peer = PeerModel::public(uri.to_owned()).await?;
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
