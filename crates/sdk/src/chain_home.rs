//! Chain-owned content recovery shared by native hosts and the CLI.
use crate::paid_provider::{MountedSetup, MountedWork, WorkRunner, WorkRunnerConfig};
use hellas_chain::chain_dir::ChainDir;
use hellas_private::StoreLocation;
use hellas_store::content::{DiskStore, IndexMode, Reservations};

#[derive(Debug, thiserror::Error)]
pub enum ChainHomeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Content(#[from] hellas_store::content::Error),
    #[error(transparent)]
    Provider(#[from] crate::paid_provider::PaidProviderError),
    #[error(transparent)]
    Client(#[from] crate::paid_client::PaidClientError),
}

/// Restore the provider chains bound to this store, including unconfigured chains,
/// then finish recovery. This does not drive or close their channels.
pub async fn recover_provider_chains(
    home: &StoreLocation,
    settlement_key: &hellas_kernel::Secp256k1Signer,
    content: &DiskStore,
) -> Result<(), ChainHomeError> {
    for chain in ChainDir::discover(home)? {
        if provider_content_identity(&chain)? != Some(content.identity()) {
            continue;
        }
        // DiskStore retains the restored pins and reservations after writers close.
        WorkRunner::discover(
            WorkRunnerConfig {
                chain,
                settlement_key: settlement_key.clone(),
            },
            MountedWork::default(),
            MountedSetup::with_content_store(content.clone()),
        )
        .await?;
    }
    content.finish_recovery().await?;
    Ok(())
}

fn provider_content_identity(chain: &ChainDir) -> std::io::Result<Option<[u8; 16]>> {
    let path = chain.provider().join("content-store");
    match hellas_private::read_bounded_regular_file(&path, 16) {
        Ok(bytes) => bytes.try_into().map(Some).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid content store binding: {}", path.display()),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn bind_provider_content(chain: &ChainDir, content: &DiskStore) -> std::io::Result<()> {
    let root = chain.provider();
    root.durability().create_dir_all(&root)?;
    let path = root.join("content-store");
    let lock = hellas_private::open_lock_beside(&path)?;
    lock.try_lock().map_err(std::io::Error::from)?;
    match provider_content_identity(chain)? {
        Some(identity) if identity != content.identity() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "chain {} is bound to content store {}; cannot use content store {}",
                chain.as_path().display(),
                hex::encode(identity),
                hex::encode(content.identity())
            ),
        )),
        Some(_) => Ok(()),
        None => root
            .durability()
            .write_atomically(&path, ".binding", &content.identity()),
    }
}

/// Open the chain's shared client content store and recover every provider root
/// before cleanup, including providers other than the next operation's target.
pub async fn open_client_content(chain: &ChainDir) -> Result<DiskStore, ChainHomeError> {
    open_content(chain.client().child("content"), chain, || {
        chain.client_journal_roots()
    })
    .await
}

/// Open one provider's gateway content store and recover its journals before cleanup.
pub async fn open_gateway_content(
    chain: &ChainDir,
    provider: hellas_client::ProviderAddress,
) -> Result<DiskStore, ChainHomeError> {
    let root = crate::paid_client::PaidJournalKind::Gateway.journal_root(chain, provider);
    open_content(root.child("content"), chain, || Ok(vec![root])).await
}

async fn open_content(
    location: StoreLocation,
    chain: &ChainDir,
    journals: impl FnOnce() -> std::io::Result<Vec<StoreLocation>>,
) -> Result<DiskStore, ChainHomeError> {
    let store = DiskStore::open(
        location,
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        false,
    )
    .await?;
    let restored = async {
        for root in journals()? {
            crate::paid_client::recover_content(&root, chain.network(), &store).await?;
        }
        store.finish_recovery().await?;
        Ok(())
    }
    .await;
    if let Err(error) = restored {
        store.close().await;
        return Err(error);
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provider_recovery_restores_retained_content_before_cleanup() {
        use crate::provider::tests::node::{bundle, write_accepted_channel, write_setup_journal};
        use hellas_channel::test_support::channel::{content_store, provider};
        use hellas_store::content::{ContentStore as _, LocalStore, Scope, owner_pins};

        let directory = tempfile::tempdir().unwrap();
        write_setup_journal(directory.path()).await;
        write_accepted_channel(directory.path()).await;
        let content = content_store(directory.path()).await;
        let home = StoreLocation::for_test(directory.path());
        let chain = ChainDir::discover(&home).unwrap().pop().unwrap();
        bind_provider_content(&chain, &content).unwrap();
        let identity = content.identity();
        let pins = owner_pins(&content, "channel/").await.unwrap();
        assert_eq!(pins.len(), 1);
        for (name, pin) in &pins {
            content
                .set_pin(&Scope::Owner, name, Some(pin), None)
                .await
                .unwrap();
        }
        content.close().await;
        let other = content_store(&directory.path().join("other-store")).await;
        assert_ne!(identity, other.identity());
        let other_chain = crate::test_support::chain_dir(
            directory.path(),
            hellas_kernel::NetworkId::new("other-chain").unwrap(),
        );
        WorkRunner::discover(
            WorkRunnerConfig {
                chain: other_chain,
                settlement_key: provider(),
            },
            MountedWork::default(),
            MountedSetup::with_content_store(other.clone()),
        )
        .await
        .unwrap();
        recover_provider_chains(&home, &provider(), &other)
            .await
            .unwrap();
        let error = WorkRunner::discover(
            WorkRunnerConfig {
                chain,
                settlement_key: provider(),
            },
            MountedWork::default(),
            MountedSetup::with_content_store(other.clone()),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains(&hex::encode(identity)));
        assert!(error.contains(&hex::encode(other.identity())));
        other.close().await;
        let content = content_store(directory.path()).await;
        assert_eq!(identity, content.identity());
        recover_provider_chains(
            &StoreLocation::for_test(directory.path()),
            &provider(),
            &content,
        )
        .await
        .unwrap();
        assert_eq!(owner_pins(&content, "channel/").await.unwrap(), pins);
        assert_eq!(content.collect(&Scope::Owner).await.unwrap().objects, 0);
        let input = bundle().canonical_bytes().unwrap();
        let bytes = hellas_channel::content::read(
            &LocalStore::Disk(content.clone()),
            &Scope::Owner,
            hellas_rpc::ContentRef::for_bytes(&input),
            input.len() as u64,
        )
        .await
        .unwrap();
        assert_eq!(bytes, input);
        content.close().await;
    }

    #[tokio::test]
    async fn invalid_client_roots_close_content_after_refusing_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::for_test(directory.path());
        let profile =
            hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
        let chain = ChainDir::open(&home, &profile).unwrap();
        let root = chain.client_journals("not-a-directory");
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::write(&root, b"bad root").unwrap();
        assert!(open_client_content(&chain).await.is_err());
        std::fs::remove_file(&root).unwrap();
        let content = open_client_content(&chain).await.unwrap();
        content.close().await;
    }
}
