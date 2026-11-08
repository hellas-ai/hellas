use super::*;
use hellas_auth::assert_err;
use hellas_private::StoreLocation;

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

#[tokio::test]
async fn the_durability_configuration_is_pinned() {
    assert_eq!(
        hellas_private::Durability::default(),
        hellas_private::Durability::Crash
    );
    for (durability, expected) in [
        (hellas_private::Durability::Crash, 1),
        (hellas_private::Durability::Power, 2),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let location = StoreLocation::for_test(dir.path()).with_durability(durability);
        let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
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
        assert_eq!(synchronous, expected);
        let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(journal.connection.as_mut().unwrap())
            .await
            .unwrap();
        assert_eq!(busy, SQLITE_BUSY_TIMEOUT.as_millis() as i64);
        #[cfg(target_os = "macos")]
        {
            let flush: i64 = sqlx::query_scalar("PRAGMA fullfsync")
                .fetch_one(journal.connection.as_mut().unwrap())
                .await
                .unwrap();
            assert_eq!(
                flush,
                i64::from(durability == hellas_private::Durability::Power)
            );
        }
        assert_eq!(locking_mode, "exclusive");
        assert_eq!(secure_delete, 1);
    }
}

#[tokio::test]
async fn a_rotation_replays_as_its_checkpoint_and_what_followed() {
    let dir = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    for record in PREDECESSOR {
        journal.append(record).await.unwrap();
    }
    journal.rotate(CHECKPOINT).await.unwrap();
    assert_eq!(journal.generation(), 1);
    assert!(journal.is_empty());
    journal.append(b"after").await.unwrap();
    drop(journal);
    let (reopened, replay) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.len(), 1);
    assert_eq!(replay.checkpoint.as_deref(), Some(CHECKPOINT));
    assert_eq!(replay.records, vec![b"after".to_vec()]);
}

#[tokio::test]
async fn a_rotation_that_cannot_commit_leaves_its_predecessor() {
    let dir = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
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
    let (mut reopened, replay) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    assert_eq!(reopened.generation(), 0);
    assert_eq!(replay.checkpoint, None);
    assert_eq!(replay.records, PREDECESSOR);
    reopened.append(b"four").await.unwrap();
    drop(reopened);
    let (_, replay) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    assert_eq!(replay.records.len(), 4);
}

#[tokio::test]
async fn the_reserve_outlives_a_rotation_that_cannot_complete() {
    let dir = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
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
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
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
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    let (started, release) = journal.pause_next_statement().await;
    {
        let mut append = std::pin::pin!(journal.append(b"uncertain append"));
        tokio::select! {
            entered = started => entered.unwrap(),
            result = &mut append => panic!("append completed before cancellation: {result:?}"),
        }
        // SQLite has started the insert; cancellation loses its acknowledgement.
    }
    assert_err!(
        journal.append(b"must not append").await,
        JournalError::Poisoned
    );
    journal.resume_statements(release).await;
    drop(journal);
    let (mut journal, replay) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    assert_eq!(replay.records, vec![b"uncertain append".to_vec()]);
    journal.append(b"reconciled").await.unwrap();
}

#[tokio::test]
async fn an_oversized_record_does_not_poison_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    assert_err!(
        journal.append(&vec![0; MAX_RECORD_BYTES + 1]).await,
        JournalError::RecordTooLarge { .. }
    );
    journal.append(b"one record").await.unwrap();
    assert_eq!(journal.len(), 1);
}

#[tokio::test]
async fn a_rotation_leaves_no_deleted_record_on_disk() {
    const SENTINEL: &[u8] = b"rotated-away-payload-sentinel";
    let dir = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(dir.path());
    let (mut journal, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    journal.append(&SENTINEL.repeat(64)).await.unwrap();
    journal.rotate(b"checkpoint").await.unwrap();
    let path = Journal::path(&location, "duty");
    for file in [path.clone(), path.with_extension("sqlite-wal")] {
        let bytes = std::fs::read(&file).unwrap_or_default();
        assert!(
            !bytes.windows(SENTINEL.len()).any(|w| w == SENTINEL),
            "{} still holds a rotated record",
            file.display()
        );
    }
}

#[tokio::test]
async fn pre_cutover_journals_are_refused_without_migration_or_legacy_replay() {
    let directory = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(directory.path());
    let path = Journal::path(&location, "old");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO record(payload) VALUES (?)")
        .bind(b"old private metadata".as_slice())
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    assert!(matches!(
        Journal::open_latest(&location, "old", id()).await,
        Err(JournalError::Version { found: 0 })
    ));
    assert!(matches!(
        Journal::open_existing(&location, "old", id()).await,
        Err(JournalError::Version { found: 0 })
    ));
    assert!(matches!(
        Journal::inspect(&location, "old").await,
        Err(JournalError::Version { found: 0 })
    ));
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT payload FROM record")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(bytes, b"old private metadata");
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(version, 0);
    connection.close().await.unwrap();
}

/// A version-1 journal recorded a contiguous block cursor. It belongs to a
/// chain this binary no longer follows, so it is refused, not read.
#[tokio::test]
async fn a_block_cursor_journal_is_refused_without_migration() {
    let directory = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(directory.path());
    let (journal, _) = Journal::open_latest(&location, "v1", id()).await.unwrap();
    drop(journal);
    let options = SqliteConnectOptions::new().filename(Journal::path(&location, "v1"));
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql("PRAGMA user_version = 1")
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
    assert!(matches!(
        Journal::open_latest(&location, "v1", id()).await,
        Err(JournalError::Version { found: 1 })
    ));
}

#[tokio::test]
async fn failed_header_validation_releases_the_writer_before_returning() {
    let root = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(root.path());
    let (mut original, _) = Journal::open_latest(&location, "duty", id()).await.unwrap();
    original.append(b"authoritative").await.unwrap();
    original.close().await;
    let wrong = JournalId {
        role: Role::Provider,
        ..id()
    };
    assert!(matches!(
        Journal::open_existing(&location, "duty", wrong).await,
        Err(JournalError::HeaderMismatch { .. })
    ));
    let (mut reopened, replay) = Journal::open_existing(&location, "duty", id())
        .await
        .unwrap();
    assert_eq!(replay.records, vec![b"authoritative".to_vec()]);
    reopened.close().await;
}
