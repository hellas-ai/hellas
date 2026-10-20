use super::*;
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Barrier, mpsc},
};

async fn assert_locked(directory: &Path) {
    assert_err!(
        Journal::open_latest(directory, "duty", id()).await,
        JournalError::Locked { .. }
    );
    assert_err!(
        Journal::open_existing(directory, "duty", id()).await,
        JournalError::Locked { .. }
    );
    assert_err!(
        Journal::inspect(directory, "duty").await,
        JournalError::Locked { .. }
    );
}

#[tokio::test]
async fn ownership_probe() {
    let Some(directory) = std::env::var_os("HELLAS_JOURNAL_OWNERSHIP_PROBE") else {
        return;
    };
    assert_locked(Path::new(&directory)).await;
}

#[tokio::test]
async fn a_journal_keeps_one_owner_across_rotation_and_processes() {
    let directory = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(directory.path(), "duty", id())
        .await
        .unwrap();
    journal.append(b"accepted").await.unwrap();
    assert_locked(directory.path()).await;
    // A separate journal in this directory does not share the lock.
    let other = Journal::open_latest(directory.path(), "independent", id())
        .await
        .unwrap();
    drop(other);
    journal.rotate(CHECKPOINT).await.unwrap();
    assert_locked(directory.path()).await;
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("work_store::journal::tests::ownership::ownership_probe")
        .env("HELLAS_JOURNAL_OWNERSHIP_PROBE", directory.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    journal.append(b"completed").await.unwrap();
    drop(journal);
    let (_, replay) = Journal::inspect(directory.path(), "duty").await.unwrap();
    assert_eq!(replay.checkpoint.as_deref(), Some(CHECKPOINT));
    assert_eq!(replay.records, vec![b"completed".to_vec()]);
    let (_, replay) = Journal::open_existing(directory.path(), "duty", id())
        .await
        .unwrap();
    assert_eq!(replay.records, vec![b"completed".to_vec()]);
}

#[tokio::test]
async fn racing_creators_leave_one_owner() {
    let directory = tempfile::tempdir().unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let (sender, results) = mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..2 {
            let barrier = barrier.clone();
            let sender = sender.clone();
            let path = directory.path();
            scope.spawn(move || {
                barrier.wait();
                // Keep the successful handle alive in the channel until both
                // contenders finish, so sequential acquisition cannot pass.
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                sender
                    .send(runtime.block_on(Journal::open_latest(path, "duty", id())))
                    .unwrap();
            });
        }
        barrier.wait();
    });
    drop(sender);
    let outcomes: Vec<_> = results.into_iter().collect();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(JournalError::Locked { .. })))
            .count(),
        1
    );
    assert_locked(directory.path()).await;
    drop(outcomes);
    assert!(
        Journal::open_existing(directory.path(), "duty", id())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn invalid_stems_cannot_create_a_file_outside_the_directory() {
    let directory = tempfile::tempdir().unwrap();
    for stem in ["", "..", "../outside", "nested/name", "nested\\name"] {
        assert!(
            Journal::open_latest(directory.path(), stem, id())
                .await
                .is_err()
        );
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
