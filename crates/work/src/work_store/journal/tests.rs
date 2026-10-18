use super::*;
use hellas_auth::assert_err;

mod ownership;

const fn id() -> JournalId {
    JournalId {
        kind: JournalKind::Setup,
        role: Role::Client,
        key: [0x5a; 32],
    }
}
const PREDECESSOR: [&[u8]; 3] = [b"one", b"two", b"three"];
const CHECKPOINT: &[u8] = b"the state the predecessor reached";

impl Journal {
    /// Makes the database itself refuse every `operation` on `table`,
    /// the way a full disk or an I/O error would.
    pub(crate) async fn refuse(&mut self, operation: &str, table: &str) {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE TEMP TRIGGER refuse_{operation}_{table} BEFORE {operation} ON {table} \
             BEGIN SELECT RAISE(ABORT, 'refused'); END"
        )))
        .execute(self.connection.as_mut().unwrap())
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn the_durability_configuration_is_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(journal.connection.as_mut().unwrap())
        .await
        .unwrap();
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(journal.connection.as_mut().unwrap())
        .await
        .unwrap();
    let locking_mode: String = sqlx::query_scalar("PRAGMA locking_mode")
        .fetch_one(journal.connection.as_mut().unwrap())
        .await
        .unwrap();
    let secure_delete: i64 = sqlx::query_scalar("PRAGMA secure_delete")
        .fetch_one(journal.connection.as_mut().unwrap())
        .await
        .unwrap();
    assert_eq!(journal_mode, "wal");
    assert_eq!(synchronous, 2, "FULL");
    assert_eq!(locking_mode, "exclusive");
    assert_eq!(secure_delete, 1);
}

#[tokio::test]
async fn a_rotation_replays_as_its_checkpoint_and_what_followed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    for record in PREDECESSOR {
        journal.append(record).await.unwrap();
    }
    journal.rotate(CHECKPOINT).await.unwrap();
    assert_eq!(journal.generation(), 1);
    assert!(journal.is_empty());
    journal.append(b"after").await.unwrap();
    drop(journal);
    let (reopened, replay) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.len(), 1);
    assert_eq!(replay.checkpoint.as_deref(), Some(CHECKPOINT));
    assert_eq!(replay.records, vec![b"after".to_vec()]);
}

#[tokio::test]
async fn a_rotation_that_cannot_commit_leaves_its_predecessor() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    for record in PREDECESSOR {
        journal.append(record).await.unwrap();
    }
    // The checkpoint is stored, and then deleting the records it replaces
    // fails: the transaction must not keep either half.
    journal.refuse("DELETE", "record").await;
    assert_err!(journal.rotate(CHECKPOINT).await, JournalError::Sqlx(_));
    assert_eq!(journal.generation(), 0);
    assert_err!(journal.append(b"four").await, JournalError::Poisoned);
    assert_err!(journal.rotate(CHECKPOINT).await, JournalError::Poisoned);
    drop(journal);
    let (mut reopened, replay) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    assert_eq!(reopened.generation(), 0);
    assert_eq!(replay.checkpoint, None);
    assert_eq!(replay.records, PREDECESSOR);
    reopened.append(b"four").await.unwrap();
    drop(reopened);
    let (_, replay) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    assert_eq!(replay.records.len(), 4);
}

#[tokio::test]
async fn the_reserve_outlives_a_rotation_that_cannot_complete() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    for _ in 0..MAX_ACTIVE_FRAMES - DUTY_RESERVE_FRAMES {
        journal.append(b"x").await.unwrap();
    }
    assert!(journal.at_soft_limit());
    assert_err!(
        journal.rotate(&vec![0; MAX_CHECKPOINT_BYTES + 1]).await,
        JournalError::CheckpointTooLarge { .. }
    );
    assert_eq!(journal.generation(), 0);
    for _ in 0..DUTY_RESERVE_FRAMES {
        journal.append(b"x").await.unwrap();
    }
    assert_err!(journal.append(b"x").await, JournalError::Full { frames, .. } if frames == MAX_ACTIVE_FRAMES);
    journal.rotate(CHECKPOINT).await.unwrap();
    journal.append(b"x").await.unwrap();
}

#[tokio::test]
async fn a_failed_append_poisons_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    journal.refuse("INSERT", "record").await;
    assert_err!(journal.append(b"one record").await, JournalError::Sqlx(_));
    assert_err!(
        journal.append(b"another record").await,
        JournalError::Poisoned
    );
}

#[tokio::test]
async fn a_lost_write_acknowledgement_requires_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    {
        // One poll hands the insert to sqlx's worker; dropping the future
        // then loses its acknowledgement, not the write.
        let mut append = std::pin::pin!(journal.append(b"uncertain append"));
        assert!(futures::poll!(append.as_mut()).is_pending());
    }
    assert_err!(
        journal.append(b"must not append").await,
        JournalError::Poisoned
    );
    drop(journal);
    let (mut journal, replay) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    assert_eq!(replay.records, vec![b"uncertain append".to_vec()]);
    journal.append(b"reconciled").await.unwrap();
}

#[tokio::test]
async fn an_oversized_record_does_not_poison_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut journal, _) = Journal::open_latest(dir.path(), "duty", id())
        .await
        .unwrap();
    assert_err!(
        journal.append(&vec![0; MAX_RECORD_BYTES + 1]).await,
        JournalError::RecordTooLarge { .. }
    );
    journal.append(b"one record").await.unwrap();
    assert_eq!(journal.len(), 1);
}
