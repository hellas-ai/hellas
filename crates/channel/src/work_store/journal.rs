//! Append-only, durable journal with exclusive ownership, one SQLite
//! database per journal.
//!
//! An append returns only once its transaction is committed and synced, so
//! a record a caller has acted on is never lost on replay. Replay hands
//! back the checkpoint and then every later record in the order it was
//! appended. Rotation stores the checkpoint and deletes the records it
//! replaces in one transaction, so a crash leaves either the generation
//! before it or the one after it, never a mix of the two.

use hex::encode as hex;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::Connection as _;
use sqlx::migrate::MigrateError;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqliteLockingMode,
    SqlitePoolOptions, SqliteSynchronous,
};

use hellas_rpc::observe::{LEVEL, TARGET, Timing};

const PARTITION: &str = "journals";
const EXTENSION: &str = "sqlite";
/// SQLite primary result codes the journal tells apart.
const SQLITE_BUSY: i32 = 5;
const SQLITE_LOCKED: i32 = 6;
const SQLITE_NOTADB: i32 = 26;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Largest metadata/result record this journal writes or reads back.
/// Compute input bodies live in verified payload objects referenced by the
/// journal; profile-specific bounds are checked before acceptance.
pub const MAX_RECORD_BYTES: usize = 4 << 20;

/// Most payload bytes, checkpoint included, one generation may hold. Hard,
/// to bound replay; refusing past it is not a poisoning.
pub const MAX_ACTIVE_JOURNAL_BYTES: u64 = 64 << 20;

/// Most records one generation may hold.
pub const MAX_ACTIVE_FRAMES: u64 = 4096;

/// Bytes kept back for a duty already under way — the close, the answer
/// and the cursor advances after an exported signature — when a rotation
/// cannot complete. New work stops at the soft limit instead.
pub const DUTY_RESERVE_BYTES: u64 = 16 << 20;

/// Records kept back for the same reason.
pub const DUTY_RESERVE_FRAMES: u64 = 16;

/// Largest checkpoint a rotation may write. It bounds the *state* an
/// endpoint may reach, so it is checked before a signature is exported.
pub const MAX_CHECKPOINT_BYTES: usize = MAX_RECORD_BYTES;

/// Which journal format a database holds, so a channel journal handed to
/// the setup reader fails to open rather than replaying as the wrong kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalKind {
    /// The two-Open handshake and its recovery state.
    Setup = 1,
    /// One channel's job, credit, and certificate.
    Channel = 2,
    /// Provider accounting whose request and response bodies never reach disk.
    /// A different kind prevents reopening a payload-bearing journal as ZDR.
    MetadataChannel = 3,
    /// Provider-wide, metadata-only grant tree and channel books.
    Grant = 4,
}

/// Which side of the channel this endpoint is. Stored with the journal
/// because the transition rules differ by role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The party that funds the payment edge and signs certificates.
    Client = 1,
    /// The party that stakes the bond, executes, and is paid.
    Provider = 2,
}

/// What a journal is about: its kind, its role, and the 32-byte key of the
/// thing it records. A journal stored under one identity does not open as
/// another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalId {
    /// Which journal this is.
    pub kind: JournalKind,
    /// Which side of the channel wrote it.
    pub role: Role,
    /// What it is about: a channel id, or a hash over the network and an
    /// edge or a counterparty key.
    pub key: [u8; 32],
}

/// Why a journal is not usable.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("initialized journal is missing from {directory}")]
    Missing { directory: PathBuf },
    #[error("journal i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal database failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// The database's schema is not one this binary migrates.
    #[error("journal schema failed: {0}")]
    Migrate(#[from] MigrateError),
    #[error("journal generation space exhausted")]
    GenerationExhausted,
    /// Another handle, in this process or another, holds this journal.
    #[error("another process holds the journal at {path}")]
    Locked { path: PathBuf },
    /// Not a SQLite database holding a journal, unlike [`Self::HeaderMismatch`],
    /// which is a journal that is somebody else's.
    #[error("the file at {path} is not a journal database")]
    NotAJournal { path: PathBuf },
    #[error("the file at {path} is not this endpoint's {kind:?} journal")]
    HeaderMismatch { path: PathBuf, kind: JournalKind },
    #[error("journal record of {len} bytes exceeds the {MAX_RECORD_BYTES}-byte maximum")]
    RecordTooLarge { len: usize },
    /// A write failed, so the durable state is unknown to this handle.
    /// Reopening is the only way to find out.
    #[error("a journal write failed; reopen before writing again")]
    Poisoned,
    /// The endpoint could not rotate. Reported before a signature is
    /// exported over such a state, and again if a rotation is attempted.
    #[error("a checkpoint of {len} bytes exceeds the {MAX_CHECKPOINT_BYTES}-byte maximum")]
    CheckpointTooLarge { len: usize },
    /// The generation is full, reserve included. Nothing was written, so
    /// the journal is not poisoned; only a rotation moves it on.
    #[error("the journal holds {frames} records in {bytes} bytes and admits no more")]
    Full { frames: u64, bytes: u64 },
}

impl JournalError {
    fn from_sqlx(error: sqlx::Error, path: &Path) -> Self {
        let code = error
            .as_database_error()
            .and_then(|error| error.code()?.parse::<i32>().ok());
        match code.map(|code| code & 0xff) {
            Some(SQLITE_BUSY | SQLITE_LOCKED) => Self::Locked { path: path.into() },
            Some(SQLITE_NOTADB) => Self::NotAJournal { path: path.into() },
            _ => Self::Sqlx(error),
        }
    }
}

/// What opening a journal found.
#[derive(Debug)]
pub struct Replay {
    /// The state the last rotation checkpointed, absent until the first.
    pub checkpoint: Option<Vec<u8>>,
    /// Every record appended after the checkpoint, in append order.
    pub records: Vec<Vec<u8>>,
}

/// How long an open waits on another connection's lock before reporting
/// [`JournalError::Locked`].
const OPEN_BUSY_TIMEOUT: Duration = Duration::from_millis(250);

/// One append-only durable journal, exclusively held by its host.
#[derive(Debug)]
pub struct Journal {
    /// Taken only by `Drop`.
    connection: Option<SqliteConnection>,
    id: JournalId,
    generation: u64,
    records: u64,
    bytes: u64,
    poisoned: bool,
}

impl Drop for Journal {
    /// Closes the database before returning, so ownership ends with the
    /// handle: sqlx would close it later on its worker thread, and this
    /// process reopening the journal would find it still held.
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            // The worker is a plain thread, so this wait needs no runtime.
            let _ = futures::executor::block_on(connection.close());
        }
    }
}

impl Journal {
    /// Returns where the journal named `stem` lives under `directory`.
    #[must_use]
    pub fn path(directory: &Path, stem: &str) -> PathBuf {
        directory
            .join(PARTITION)
            .join(format!("{stem}.{EXTENSION}"))
    }

    /// Lists the stems of the journals under `directory`, sorted, so two
    /// machines holding the same journals list them in the same order.
    pub fn stems(directory: &Path) -> Result<Vec<String>, JournalError> {
        let entries = match std::fs::read_dir(directory.join(PARTITION)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            entries => entries?,
        };
        let mut stems = Vec::new();
        for entry in entries {
            let name = entry?.file_name();
            let stem = name
                .to_str()
                .and_then(|name| name.strip_suffix(EXTENSION)?.strip_suffix('.'));
            stems.extend(stem.filter(|stem| valid_stem(stem)).map(str::to_owned));
        }
        stems.sort_unstable();
        Ok(stems)
    }

    /// Opens the journal, creating it empty when it does not exist yet.
    pub async fn open_latest(
        directory: &Path,
        stem: &str,
        id: JournalId,
    ) -> Result<(Self, Replay), JournalError> {
        Self::open_owned(directory, stem, id, true).await
    }

    /// Recovers an initialized journal without creating an empty replacement.
    pub async fn open_existing(
        directory: &Path,
        stem: &str,
        id: JournalId,
    ) -> Result<(Self, Replay), JournalError> {
        Self::open_owned(directory, stem, id, false).await
    }

    async fn open_owned(
        directory: &Path,
        stem: &str,
        id: JournalId,
        create: bool,
    ) -> Result<(Self, Replay), JournalError> {
        if !valid_stem(stem) {
            let invalid = std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid stem");
            return Err(invalid.into());
        }
        let path = Self::path(directory, stem);
        let missing = || JournalError::Missing {
            directory: directory.into(),
        };
        if create {
            hellas_private::create_dir_all_durable(&directory.join(PARTITION))?;
        } else if !path.try_exists()? {
            return Err(missing());
        }
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(create)
            .locking_mode(SqliteLockingMode::Exclusive)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            // A rotation deletes records a channel journal may hold payloads
            // in; zero them rather than leave them in free pages.
            .pragma("secure_delete", "ON")
            // Long enough to wait out a racing opener's transient lock, short
            // enough that a journal held by its owner is reported promptly.
            .busy_timeout(OPEN_BUSY_TIMEOUT);
        let sqlx_error = |error| JournalError::from_sqlx(error, &path);
        // sqlx's migrator only takes a connection source whose futures are
        // `Send` for every lifetime, which a borrowed connection is not. A
        // one-connection pool is; its connection is then kept, not shared.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            // EXCLUSIVE mode keeps the lock of the first write until the
            // connection closes, so a second opener is refused at connect.
            .after_connect(|connection, _| {
                let lock = sqlx::raw_sql("BEGIN IMMEDIATE; COMMIT");
                Box::pin(async move { lock.execute(connection).await.map(drop) })
            })
            .connect_with(options)
            .await
            .map_err(sqlx_error)?;
        // A new database's directory entry must outlive a power cut too.
        hellas_private::sync_directory(&directory.join(PARTITION))?;
        MIGRATOR.run(&pool).await.map_err(|error| match error {
            MigrateError::Execute(error) => sqlx_error(error),
            error => error.into(),
        })?;
        let mut connection = pool.acquire().await.map_err(sqlx_error)?.leak();
        let (found, generation, checkpoint) = match read_head(&mut connection, &path).await? {
            Some(head) => head,
            None if create => {
                let (key, kind, role) = (&id.key[..], id.kind as i64, id.role as i64);
                sqlx::query!(
                    "INSERT INTO journal (key, kind, role, generation) VALUES (?, ?, ?, 0)",
                    key,
                    kind,
                    role,
                )
                .execute(&mut connection)
                .await
                .map_err(sqlx_error)?;
                (id, 0, None)
            }
            None => return Err(missing()),
        };
        if found != id {
            return Err(JournalError::HeaderMismatch {
                path,
                kind: id.kind,
            });
        }
        let records = read_records(&mut connection, &path).await?;
        let bytes = checkpoint
            .iter()
            .chain(&records)
            .map(|r| r.len() as u64)
            .sum();
        let (connection, records_len) = (Some(connection), records.len() as u64);
        let journal = Self {
            connection,
            id,
            generation,
            records: records_len,
            bytes,
            poisoned: false,
        };
        Ok((
            journal,
            Replay {
                checkpoint,
                records,
            },
        ))
    }

    /// Reads a journal without writing to it or taking its owner's lock. A
    /// journal open elsewhere is [`JournalError::Locked`]: its owner holds
    /// the database exclusively.
    pub async fn inspect(
        directory: &Path,
        stem: &str,
    ) -> Result<(JournalId, Replay), JournalError> {
        let path = Self::path(directory, stem);
        if !path.try_exists()? {
            return Err(JournalError::Missing {
                directory: directory.into(),
            });
        }
        let options = SqliteConnectOptions::new().filename(&path).read_only(true);
        let sqlx_error = |error| JournalError::from_sqlx(error, &path);
        let mut connection = SqliteConnection::connect_with(&options)
            .await
            .map_err(sqlx_error)?;
        let Some((id, _, checkpoint)) = read_head(&mut connection, &path).await? else {
            return Err(JournalError::NotAJournal { path });
        };
        let records = read_records(&mut connection, &path).await?;
        connection.close().await.map_err(sqlx_error)?;
        Ok((
            id,
            Replay {
                checkpoint,
                records,
            },
        ))
    }

    /// Returns how many rotations this journal has been through.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Emits `restart_replay_ms_at_cap` for the open that produced this
    /// handle and the replay its caller then ran. The store calls it,
    /// because §4 measures a process reaching the state it left: the read
    /// plus the caller's decode, signature checks and transitions.
    pub fn observe_replay(&self, timing: Timing, records: usize) {
        if let Some(ms) = timing.ms() {
            tracing::event!(
                name: "restart_replay_ms_at_cap", target: TARGET, LEVEL,
                kind = ?self.id.kind, role = ?self.id.role, key = %hex(self.id.key),
                generation = self.generation, frames = self.records,
                bytes = self.bytes, records, ms,
            );
        }
    }

    /// Authority checks cannot use cached state after an ambiguous append
    /// or rotation, including cancellation before an error could be returned.
    pub fn check_authority(&self) -> Result<(), JournalError> {
        if self.poisoned || self.connection.is_none() {
            return Err(JournalError::Poisoned);
        }
        Ok(())
    }

    /// Closes the database and ends ownership, so the host can reopen and
    /// replay it. Every later call is refused like a poisoned handle.
    pub async fn close(&mut self) {
        if let Some(connection) = self.connection.take() {
            let _ = connection.close().await;
        }
    }

    /// Returns whether this generation has reached the hard limit less the
    /// duty reserve. Past it the journal still takes records — that is what
    /// the reserve is — but new work admitted past it runs out of room in
    /// the middle of a duty.
    #[must_use]
    pub const fn at_soft_limit(&self) -> bool {
        self.at_soft_limit_with_frames(DUTY_RESERVE_FRAMES)
    }

    /// A shared journal may owe more transitions than a single channel. Its
    /// writer reserves enough records for every duty it admits; the byte
    /// reserve and hard bounds remain common to all journals.
    #[must_use]
    pub const fn at_soft_limit_with_frames(&self, duty_frames: u64) -> bool {
        self.records >= MAX_ACTIVE_FRAMES.saturating_sub(duty_frames)
            || self.bytes >= MAX_ACTIVE_JOURNAL_BYTES.saturating_sub(DUTY_RESERVE_BYTES)
    }

    /// Replaces every record with `checkpoint` and starts the next
    /// generation, in one transaction. A failure, or a cancellation,
    /// poisons the handle like a failed append.
    pub async fn rotate(&mut self, checkpoint: &[u8]) -> Result<(), JournalError> {
        self.check_authority()?;
        if checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(JournalError::CheckpointTooLarge {
                len: checkpoint.len(),
            });
        }
        let generation = self.generation.checked_add(1);
        let stored = generation.and_then(|generation| i64::try_from(generation).ok());
        let (Some(generation), Some(stored)) = (generation, stored) else {
            return Err(JournalError::GenerationExhausted);
        };
        let Some(connection) = self.connection.as_mut() else {
            return Err(JournalError::Poisoned);
        };
        let (rotation, frames, bytes) = (Timing::start(), self.records, self.bytes);
        self.poisoned = true;
        let mut transaction = connection.begin().await?;
        let update = sqlx::query!(
            "UPDATE journal SET checkpoint = ?, generation = ?",
            checkpoint,
            stored,
        );
        update.execute(&mut *transaction).await?;
        sqlx::query!("DELETE FROM record")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        (self.generation, self.records, self.bytes) = (generation, 0, checkpoint.len() as u64);
        self.poisoned = false;
        // `secure_delete` zeroes the database pages, but the WAL still holds the
        // frames the deleted records were written in until it is truncated. The
        // rotation is already committed, so a failure here is reported, not fatal.
        if let Err(error) = sqlx::raw_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&mut *connection)
            .await
        {
            tracing::warn!(target: TARGET, kind = ?self.id.kind, %error, "journal WAL was not truncated after rotation");
        }
        if let Some(ms) = rotation.ms() {
            tracing::event!(
                name: "rotation_tail_ms", target: TARGET, LEVEL,
                kind = ?self.id.kind, role = ?self.id.role, key = %hex(self.id.key),
                generation, frames, bytes, checkpoint_bytes = checkpoint.len(), ms,
            );
        }
        Ok(())
    }

    /// Appends one record and returns only once it is committed and synced.
    ///
    /// A write that fails poisons this handle: whether it committed is not
    /// something this process can tell, so every later call is refused
    /// until the journal is reopened and read again. A record refused for
    /// its size, or because the generation is [`JournalError::Full`], is
    /// not one of those: nothing was written, so nothing is unknown.
    pub async fn append(&mut self, payload: &[u8]) -> Result<(), JournalError> {
        self.check_authority()?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(JournalError::RecordTooLarge { len: payload.len() });
        }
        let len = payload.len() as u64;
        let (frames, bytes) = (self.records, self.bytes);
        if frames >= MAX_ACTIVE_FRAMES || bytes.saturating_add(len) > MAX_ACTIVE_JOURNAL_BYTES {
            return Err(JournalError::Full { frames, bytes });
        }
        let Some(connection) = self.connection.as_mut() else {
            return Err(JournalError::Poisoned);
        };
        let fsync = Timing::start();
        // Cancellation is an ambiguous append too: the statement runs on
        // sqlx's worker whether or not this future is still polled.
        self.poisoned = true;
        let insert = sqlx::query!("INSERT INTO record (payload) VALUES (?)", payload);
        insert.execute(connection).await?;
        if let Some(ms) = fsync.ms() {
            tracing::event!(
                name: "fsync_tail_ms", target: TARGET, LEVEL,
                kind = ?self.id.kind, role = ?self.id.role, key = %hex(self.id.key),
                generation = self.generation, seq = frames, bytes = len, ms,
            );
        }
        (self.records, self.bytes, self.poisoned) = (frames + 1, bytes + len, false);
        Ok(())
    }

    /// Returns how many records were appended since the checkpoint.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.records
    }

    /// Returns whether no record was appended since the checkpoint.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records == 0
    }
}

/// Stems name files, so one that could leave the journal directory is
/// refused before anything is created.
fn valid_stem(stem: &str) -> bool {
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_');
    !stem.is_empty() && stem.bytes().all(allowed)
}

/// What the journal is about, its generation and its checkpoint.
type Head = (JournalId, u64, Option<Vec<u8>>);

/// Reads the journal's one row. A code this binary does not write is not a
/// journal it can describe, so it is refused rather than mapped to a
/// nearby value.
async fn read_head(
    connection: &mut SqliteConnection,
    path: &Path,
) -> Result<Option<Head>, JournalError> {
    let not_a_journal = || JournalError::NotAJournal { path: path.into() };
    let row = sqlx::query!("SELECT key, kind, role, generation, checkpoint FROM journal")
        .fetch_optional(connection)
        .await
        .map_err(|error| match JournalError::from_sqlx(error, path) {
            // A database without our tables is somebody else's database.
            JournalError::Sqlx(sqlx::Error::Database(_)) => not_a_journal(),
            error => error,
        })?;
    let Some(row) = row else {
        return Ok(None);
    };
    use {JournalKind::*, Role::*};
    let kind = [Setup, Channel, MetadataChannel, Grant]
        .into_iter()
        .find(|k| *k as i64 == row.kind);
    let role = [Client, Provider]
        .into_iter()
        .find(|r| *r as i64 == row.role);
    let key = <[u8; 32]>::try_from(row.key).ok();
    let generation = u64::try_from(row.generation).ok();
    let (Some(kind), Some(role), Some(key), Some(generation)) = (kind, role, key, generation)
    else {
        return Err(not_a_journal());
    };
    Ok(Some((
        JournalId { kind, role, key },
        generation,
        row.checkpoint,
    )))
}

async fn read_records(
    connection: &mut SqliteConnection,
    path: &Path,
) -> Result<Vec<Vec<u8>>, JournalError> {
    sqlx::query_scalar!("SELECT payload FROM record ORDER BY seq")
        .fetch_all(connection)
        .await
        .map_err(|error| JournalError::from_sqlx(error, path))
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test_support;
