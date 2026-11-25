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
    sync::{Arc, mpsc},
};

#[derive(Debug, thiserror::Error)]
#[error("model is unavailable under the provider's content policy")]
pub struct CatalogUnavailable;

#[derive(Clone)]
pub(crate) struct PeerModel {
    pub(crate) model: Arc<Model>,
    reads: tokio::sync::mpsc::UnboundedSender<Read>,
}

struct Read {
    object: ContentRef,
    range: Range<u64>,
    response: mpsc::SyncSender<Result<Vec<u8>>>,
}

impl PeerModel {
    pub(super) fn open(uri: &str) -> Result<Self> {
        let (id, address) = peer_address(uri)?;
        Self::connect(id, async move {
            let (remote, endpoint) = public_store(address).await?;
            Ok((remote, Some(endpoint)))
        })
    }

    pub(super) fn connect<S: ContentStore + 'static>(
        id: ContentId,
        connection: impl Future<Output = Result<(S, Option<iroh::Endpoint>)>> + Send + 'static,
    ) -> Result<Self> {
        let pin = model_pin(id)?;
        let (reads, mut requests) = tokio::sync::mpsc::unbounded_channel::<Read>();
        let (ready, wait) = mpsc::sync_channel(1);
        // Synchronous kind inspection and header parsers can be called on or off
        // a Tokio runtime. A dedicated reactor drives their verified peer reads.
        std::thread::Builder::new()
            .name("model-content".into())
            .spawn(move || {
                let open = async {
                    let (remote, endpoint) = connection.await?;
                    let model = read_model(&remote, &pin, id).await?;
                    Ok::<_, anyhow::Error>((remote, endpoint, model))
                };
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let result = runtime.map_err(anyhow::Error::from).and_then(|runtime| {
                    let (remote, endpoint, model) = runtime.block_on(open)?;
                    Ok((runtime, remote, endpoint, model))
                });
                let (runtime, remote, _endpoint, model) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if ready.send(Ok(Arc::new(model))).is_err() {
                    return;
                }
                runtime.block_on(async {
                    while let Some(request) = requests.recv().await {
                        let result = async {
                            let at = Path::new(pin.clone(), request.object.id().to_string())?;
                            read(&remote, &at, request.object, request.range).await
                        }
                        .await;
                        let _ = request.response.send(result);
                    }
                });
            })?;
        Ok(Self {
            model: wait.recv()??,
            reads,
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

    pub(crate) fn read(&self, name: &str, range: Range<u64>) -> Result<Vec<u8>> {
        let object = self.object(name)?;
        ensure!(
            range.start <= range.end && range.end <= object.bytes(),
            "invalid model asset range"
        );
        let (response, result) = mpsc::sync_channel(1);
        self.reads
            .send(Read {
                object,
                range,
                response,
            })
            .map_err(|_| anyhow::anyhow!("model peer disconnected"))?;
        result.recv()?
    }
}

fn peer_address(uri: &str) -> Result<(ContentId, iroh::EndpointAddr)> {
    let (id, contact) = uri.strip_prefix("hellas://").context("expected a model URI")?
            .split_once('@').context("hellas://model-id needs a provider; use --provider, --access, or append @NODE_ID[@IP:PORT]")?;
    let id: ContentId = id.parse()?;
    let mut fields = contact.split('@');
    let node: iroh::EndpointId = fields.next().context("missing content provider")?.parse()?;
    let mut address = iroh::EndpointAddr::new(node);
    for direct in fields {
        address = address.with_ip_addr(
            direct
                .parse::<SocketAddr>()
                .context("invalid model peer address")?,
        );
    }

    Ok((id, address))
}

async fn public_store(
    address: iroh::EndpointAddr,
) -> Result<(RemoteStore<IrohTransport>, iroh::Endpoint)> {
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

    Ok((remote, endpoint))
}

async fn read_model(remote: &impl ContentStore, pin: &PinName, id: ContentId) -> Result<Model> {
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
    let bytes = read(remote, &at, object, 0..object.bytes()).await?;
    let model = Model::from_canonical_bytes(&bytes)?;
    ensure!(model.content_id()? == id, "model identity mismatch");

    Ok(model)
}

/// Acquire all original objects for a peer-backed local executor.
pub async fn acquire_peer_model(uri: &str, store: &hellas_store::content::DiskStore) -> Result<()> {
    use hellas_store::content::{PinPolicy, PinTarget, Target, owner_pin};
    let (id, addr) = peer_address(uri)?;
    let (remote, _endpoint) = public_store(addr).await?;
    let pin = model_pin(id)?;
    let model = read_model(&remote, &pin, id).await?;
    for asset in &model.assets {
        let object = asset.object;
        let name = PinName::new(format!("models/{}", object.id()))?;
        if owner_pin(store, &name).await?.is_some_and(|value| {
            value.target == Target::Object(object)
                && value.policy == PinPolicy::Jobs
                && value.expires.is_none()
        }) {
            continue;
        }
        let at = Path::new(pin.clone(), object.id().to_string())?;
        store
            .acquire_peer_object(
                &remote,
                &at,
                object,
                PinTarget {
                    name,
                    policy: PinPolicy::Jobs,
                },
            )
            .await?;
    }
    Ok(())
}

async fn read(
    store: &impl ContentStore,
    at: &Path,
    expected: ContentRef,
    range: Range<u64>,
) -> Result<Vec<u8>> {
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
    let valid = |value: PinValue| {
        ensure!(
            value.target == target,
            "model publication pin names a different tree"
        );
        Ok(())
    };
    if let Some(existing) = owner_pin(store, &name).await? {
        return valid(existing);
    }
    let value = PinValue {
        target,
        policy: PinPolicy::Jobs,
        expires: None,
    };
    match store.set_pin(&Scope::Owner, &name, None, Some(value)).await {
        Ok(_) => Ok(()),
        Err(Error::Conflict) => valid(
            owner_pin(store, &name)
                .await?
                .context("model publication was removed")?,
        ),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
