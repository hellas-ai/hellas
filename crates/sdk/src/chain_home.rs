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

/// Restore pins and reservations from all retained provider chains, including
/// unconfigured chains. This does not drive or close their channels, and does
/// not finish the store's recovery barrier: the host owns that barrier.
pub async fn recover_provider_chains(
    home: &StoreLocation,
    settlement_key: &hellas_kernel::Secp256k1Signer,
    content: &DiskStore,
) -> Result<(), ChainHomeError> {
    for chain in ChainDir::discover(home)? {
        let recovered = WorkRunner::discover(
            WorkRunnerConfig {
                chain,
                settlement_key: settlement_key.clone(),
            },
            MountedWork::default(),
            MountedSetup::with_content_store(content.clone()),
        )
        .await?;
        // DiskStore retains the restored pins and reservations after writers close.
        drop(recovered);
    }
    Ok(())
}

/// Open the chain's shared client content store and recover every provider root
/// before cleanup, including providers other than the next operation's target.
pub async fn open_client_content(chain: &ChainDir) -> Result<DiskStore, ChainHomeError> {
    let store = DiskStore::open(
        chain.client().child("content"),
        vec![],
        IndexMode::Resume,
        None,
        Reservations::ram(hellas_channel::content::DEFAULT_MAX_STAGING_BYTES),
        false,
    )
    .await?;
    let restored = async {
        for root in chain.client_journal_roots()? {
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
    async fn refused_client_recovery_closes_the_store_before_reopening() {
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
