//! Restore every client journal's content obligations before node collection.
use super::*;
use hellas_channel::work_store::{
    ChannelStore,
    journal::{Journal, JournalKind},
};
use hellas_kernel::NetworkId;
use hellas_private::StoreLocation;
use hellas_store::content::DiskStore;
use std::collections::BTreeMap;

/// Restore one configured client journal root using canonical setup/channel
/// replay. This performs no chain read and does not open admission. The host
/// must call it for every root sharing the upper before `finish_recovery`.
/// Ordinary online setup/origin/chain checks still gate admission and execution.
pub async fn recover_content(
    root: &StoreLocation,
    network: NetworkId,
    content: &DiskStore,
) -> Result<()> {
    let found = hellas_channel::work_store::discover_setups(root, network).await?;
    if !found.unidentified.is_empty() {
        return Err(PaidClientError::MissingState("unidentified client journal"));
    }
    let mut unmatched = BTreeMap::new();
    for stem in Journal::stems(root).map_err(hellas_channel::work_store::WorkStoreError::from)? {
        if !stem.starts_with("channel-") {
            continue;
        }
        let (id, replay) = Journal::inspect(root, &stem)
            .await
            .map_err(hellas_channel::work_store::WorkStoreError::from)?;
        if id.kind != JournalKind::Channel
            || id.role != Role::Client
            || stem != format!("channel-{}", hex::encode(id.key))
        {
            return Err(PaidClientError::UnmatchedChannel {
                path: Journal::path(root, &stem),
            });
        }
        if replay.checkpoint.is_some() || !replay.records.is_empty() {
            unmatched.insert(id.key, Journal::path(root, &stem));
        }
    }
    let verifier = Secp256k1Verifier::new();
    for entry in found
        .setups
        .into_iter()
        .filter(|entry| entry.role == Role::Client)
    {
        let setup =
            SetupStore::open_existing(root, network, entry.bond_edge, Role::Client, &verifier)
                .await?
                .into_state()
                .await;
        if let Some(descriptor) = setup.close_descriptor() {
            let recovered = ChannelStore::recover(
                root,
                descriptor.channel().clone(),
                Role::Client,
                content.clone(),
                &verifier,
            )
            .await?;
            if let Some(store) = recovered {
                unmatched.remove(&ChannelStore::journal_key(store.state().channel()));
                // Journal::Drop closes synchronously. The shared Disk Core keeps
                // the restored pins and Work reservations after this handle ends.
            }
        }
    }
    if let Some((_, path)) = unmatched.into_iter().next() {
        return Err(PaidClientError::UnmatchedChannel { path });
    }
    Ok(())
}
