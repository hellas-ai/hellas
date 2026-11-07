use super::*;
use crate::test_support::{accept, proposal, setup};
use hellas_auth::assert_err;
use hellas_private::StoreLocation;

impl NodeStore {
    pub(crate) async fn pause_next_statement(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        self.journal.pause_next_statement().await
    }

    pub(crate) async fn resume_statements(&mut self, release: std::sync::mpsc::Sender<()>) {
        self.journal.resume_statements(release).await;
    }

    pub(crate) const fn journal_len(&self) -> u64 {
        self.journal.len()
    }

    /// Makes every later journal write fail inside the database.
    pub(crate) async fn refuse_writes(&mut self) {
        self.journal.refuse("INSERT", "record").await;
        self.journal.refuse("UPDATE", "journal").await;
    }
}

#[tokio::test]
async fn a_poisoned_writer_refuses_new_acceptance_until_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, caller) = setup(directory.path()).await;
    let before = store.state().clone();
    store.refuse_writes().await;
    let (first, signature, input) = proposal(&store, 1);
    assert_err!(
        accept(&mut store, &caller, (first, signature, &input), 1000).await,
        NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Sqlx(_))
    );
    let (next, signature, input) = proposal(&store, 2);
    assert_err!(
        accept(&mut store, &caller, (next, signature, &input), 1000).await,
        NodeStoreError::Journal(hellas_channel::work_store::journal::JournalError::Poisoned)
    );
    assert_eq!(store.state(), &before);
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    let mut store = NodeStore::open(
        &location,
        hellas_channel::test_support::network(),
        None,
        UnixMillis(1000),
    )
    .await
    .unwrap();
    assert_eq!(store.state(), &before);
    accept(&mut store, &caller, (next, signature, &input), 1000)
        .await
        .unwrap();
}

/// A rotated journal has no initialization frame to enforce the frame version.
/// Its snapshot must reject state produced under the old attribution rules too.
#[tokio::test]
async fn old_checkpoint_cannot_bypass_the_journal_format_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = setup(directory.path()).await;
    let mut snapshot = serde_json::to_value(store.state.snapshot().unwrap()).unwrap();
    snapshot["namespace"] = serde_json::json!("hellas.node.checkpoint.v2");
    let snapshot: Snapshot = serde_json::from_value(snapshot).unwrap();
    store
        .journal
        .rotate(&encode(&snapshot).unwrap())
        .await
        .unwrap();
    drop(store);
    let location = StoreLocation::for_test(directory.path());
    assert!(matches!(
        NodeStore::open_initialized(&location, hellas_channel::test_support::network()).await,
        Err(NodeStoreError::Malformed)
    ));
}
