use super::*;
use crate::test_support::{accept, proposal, setup};
use hellas_auth::assert_err;

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
        NodeStoreError::Journal(crate::work_store::journal::JournalError::Sqlx(_))
    );
    let (next, signature, input) = proposal(&store, 2);
    assert_err!(
        accept(&mut store, &caller, (next, signature, &input), 1000).await,
        NodeStoreError::Journal(crate::work_store::journal::JournalError::Poisoned)
    );
    assert_eq!(store.state(), &before);
    drop(store);
    let mut store = NodeStore::open(
        directory.path(),
        crate::test_support::network(),
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
