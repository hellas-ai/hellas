//! File backing and SQLite pin persistence for the shared content core.
use super::{
    core::{Core, Stored},
    reservation::Reservation,
    storage::{Data, charged},
    *,
};
use crate::{
    Entry, Indexed,
    fastresume::{FileIdentity, Records},
};
use bytes::Bytes;
use hellas_rpc::{ContentId, ContentRef};
use prost::Message;
use sqlx::{
    Row,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqlitePoolOptions,
        SqliteSynchronous,
    },
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexMode {
    #[default]
    Resume,
    Require,
}
#[derive(Clone)]
pub struct DiskStore {
    pub(crate) core: Core,
}
pub(crate) struct Disk {
    pub root: PathBuf,
    pub ram: Reservations,
    pub quota: Reservations,
    records: Arc<Records>,
    db: sqlx::SqlitePool,
    recovered: AtomicBool,
    work_owned: AtomicBool,
    durability: Durability,
}
pub(crate) struct FileObject {
    pub object: ContentRef,
    disk: Arc<Disk>,
    entries: Mutex<Vec<Entry>>,
    staged: Mutex<Option<(tempfile::NamedTempFile, Arc<Reservation>)>>,
    private: Mutex<Option<PathBuf>>,
}
#[derive(thiserror::Error)]
#[error("backing chunk changed")]
pub(crate) struct BadBacking {
    pub file: Arc<FileObject>,
    pub entry: Entry,
    pub binding: Option<(Core, Scope)>,
}
impl std::fmt::Debug for BadBacking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.entry.fmt(f)
    }
}
impl BadBacking {
    pub fn from_error(error: &Error) -> Option<Arc<Self>> {
        let Error::Io(error) = error else {
            return None;
        };
        error.get_ref()?.downcast_ref::<Arc<Self>>().cloned()
    }
}
fn database(error: sqlx::Error) -> Error {
    let code = error
        .as_database_error()
        .and_then(|error| error.code()?.parse::<i32>().ok());
    if code.is_some_and(|code| matches!(code & 0xff, 5 | 6)) {
        Error::Locked
    } else {
        Error::Invalid("content database")
    }
}
impl Disk {
    async fn open(
        root: PathBuf,
        capacity: Option<u64>,
        ram: Reservations,
        owner_only: bool,
        durability: Durability,
    ) -> Result<Arc<Self>> {
        let directory = root.clone();
        tokio::task::spawn_blocking(move || {
            durability.create_dir_all(&directory)?;
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Invalid("content startup worker"))??;
        let options = SqliteConnectOptions::new()
            .filename(root.join("content.sqlite"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(match durability {
                Durability::Crash => SqliteSynchronous::Normal,
                Durability::Power => SqliteSynchronous::Full,
            })
            .pragma(
                "fullfsync",
                if cfg!(target_os = "macos") && durability == Durability::Power {
                    "ON"
                } else {
                    "OFF"
                },
            )
            .locking_mode(SqliteLockingMode::Exclusive)
            .busy_timeout(std::time::Duration::ZERO);
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .connect_with(options)
            .await
            .map_err(database)?;
        let opened = async {
            // Ownership is checked outside after_connect, whose failures SQLx retries.
            // Keep this one connection until close so its EXCLUSIVE lock stays live.
            let mut connection = db.acquire().await.map_err(database)?;
            if let Err(error) = sqlx::raw_sql("BEGIN IMMEDIATE; COMMIT")
                .execute(&mut *connection)
                .await
            {
                drop(connection);
                db.close().await;
                return Err(database(error));
            }
            drop(connection);
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&db)
                .await
                .map_err(database)?;
            if version != 0 && version != 1 {
                return Err(Error::Invalid("unsupported content database version"));
            }
            sqlx::raw_sql("CREATE TABLE IF NOT EXISTS pins (name TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY CHECK(id=1), generation BLOB NOT NULL); INSERT OR IGNORE INTO head VALUES(1, x'0000000000000000'); CREATE TABLE IF NOT EXISTS work_owned (id INTEGER PRIMARY KEY CHECK(id=1)); PRAGMA user_version=1;").execute(&db).await.map_err(database)?;
            sqlx::query("CREATE TABLE IF NOT EXISTS declarations (name TEXT PRIMARY KEY NOT NULL, digest BLOB NOT NULL)").execute(&db).await.map_err(database)?;
            let work_owned: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM work_owned WHERE id=1)")
                    .fetch_one(&db)
                    .await
                    .map_err(database)?;
            if owner_only && work_owned {
                db.close().await;
                return Err(Error::WorkOwned);
            }
            durability.sync_directory(&root)?;
            let records = Arc::new(Records::default());
            let _ = records.load(&root.join("fastresume.bin"));
            let cleanup = root.clone();
            tokio::task::spawn_blocking(move || {
                durability.create_dir_all(&cleanup.join("objects"))?;
                durability.create_dir_all(&cleanup.join("staging"))?;
                for entry in fs::read_dir(cleanup.join("staging"))? {
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        fs::remove_file(entry.path())?;
                    }
                }
                durability.sync_directory(&cleanup.join("staging"))?;
                Ok::<_, Error>(())
            })
            .await
            .map_err(|_| Error::Invalid("incomplete staging cleanup worker"))??;
            Ok(Arc::new(Self {
                quota: Reservations::disk(root.clone(), capacity, 0),
                root,
                ram,
                records,
                db: db.clone(),
                recovered: AtomicBool::new(false),
                work_owned: AtomicBool::new(work_owned),
                durability,
            }))

        }
        .await;
        if opened.is_err() {
            db.close().await;
        }
        opened
    }
    pub(crate) fn ready(&self) -> bool {
        self.recovered.load(Ordering::Acquire)
    }
    pub(crate) async fn pins(
        &self,
    ) -> Result<(u64, BTreeMap<PinName, PinValue>, BTreeMap<PinName, Digest>)> {
        let generation: Vec<u8> = sqlx::query_scalar("SELECT generation FROM head WHERE id=1")
            .fetch_one(&self.db)
            .await
            .map_err(database)?;
        let generation = u64::from_be_bytes(
            generation
                .try_into()
                .map_err(|_| Error::Invalid("content generation"))?,
        );
        let mut pins = BTreeMap::new();
        for row in sqlx::query("SELECT name,value FROM pins")
            .fetch_all(&self.db)
            .await
            .map_err(database)?
        {
            let name: String = row.try_get(0).map_err(database)?;
            let bytes: Vec<u8> = row.try_get(1).map_err(database)?;
            let value = hellas_rpc::pb::content::PinValue::decode(bytes.as_slice())
                .map_err(|_| Error::Invalid("stored pin"))?;
            pins.insert(PinName::new(name)?, super::wire::value_from(value)?);
        }
        let mut declarations = BTreeMap::new();
        for row in sqlx::query("SELECT name,digest FROM declarations")
            .fetch_all(&self.db)
            .await
            .map_err(database)?
        {
            let name: String = row.try_get(0).map_err(database)?;
            let digest: Vec<u8> = row.try_get(1).map_err(database)?;
            declarations.insert(
                PinName::new(name)?,
                Digest::from_bytes(
                    digest
                        .try_into()
                        .map_err(|_| Error::Invalid("stored declaration digest"))?,
                ),
            );
        }
        Ok((generation, pins, declarations))
    }
    pub(crate) async fn persist(
        &self,
        generation: u64,
        changes: Vec<(PinName, Option<PinValue>)>,
        declarations: Vec<(PinName, Option<Digest>)>,
    ) -> Result<()> {
        let mut tx = self.db.begin().await.map_err(database)?;
        for (name, value) in changes {
            if let Some(value) = value {
                sqlx::query("INSERT INTO pins(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value")
                    .bind(name.as_str())
                    .bind(super::wire::pin_value(&value).encode_to_vec())
                    .execute(&mut *tx)
                    .await
                    .map_err(database)?;
            } else {
                sqlx::query("DELETE FROM pins WHERE name=?")
                    .bind(name.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(database)?;
            }
        }
        for (name, digest) in declarations {
            if let Some(digest) = digest {
                sqlx::query("INSERT INTO declarations(name,digest) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET digest=excluded.digest").bind(name.as_str()).bind(digest.as_bytes().as_slice()).execute(&mut *tx).await.map_err(database)?;
            } else {
                sqlx::query("DELETE FROM declarations WHERE name=?")
                    .bind(name.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(database)?;
            }
        }
        sqlx::query("UPDATE head SET generation=? WHERE id=1")
            .bind(generation.to_be_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(database)?;
        tx.commit().await.map_err(database)
    }
    fn index(&self, path: &FsPath, mode: IndexMode) -> Result<(Indexed, Entry)> {
        self.records.index_entry(path, mode, &self.ram, false)
    }
    fn discard_corrupt_upper(&self, path: &FsPath) -> Result<bool> {
        if path.parent() != Some(self.root.join("objects").as_path()) {
            return Err(Error::Invalid("conflicting owned backing"));
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let name = path
            .file_name()
            .ok_or(Error::Invalid("upper object path"))?;
        #[cfg(unix)]
        let shared = {
            use std::os::unix::fs::MetadataExt as _;
            metadata.nlink() > 1
        };
        // Stable Windows metadata does not expose the link count.
        #[cfg(not(unix))]
        let shared = {
            let mut shared = false;
            for entry in fs::read_dir(self.root.join("staging"))? {
                let entry = entry?;
                if entry.file_type()?.is_dir() && Self::same_file(path, &entry.path().join(name)) {
                    shared = true;
                    break;
                }
            }
            shared
        };
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
        tracing::error!(id = %name.to_string_lossy(), path = %path.display(), "discarded corrupt upper object");
        self.records.forget(FileIdentity::of(&metadata));
        Ok(!shared)
    }
    pub(crate) fn scan(
        self: &Arc<Self>,
        lowers: &[PathBuf],
        mode: IndexMode,
    ) -> Result<BTreeMap<ContentId, Arc<Stored>>> {
        // Load local index changes only at the explicit rescan boundary.
        let _ = self.records.load(&self.root.join("fastresume.bin"));
        let mut objects: BTreeMap<ContentId, Arc<Stored>> = BTreeMap::new();
        for entry in fs::read_dir(self.root.join("objects"))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                self.scan_file(&entry.path(), false, mode, &mut objects)?;
            }
        }
        crate::fastresume::walk_lower(lowers, |path| {
            self.scan_file(path, true, mode, &mut objects)
        })?;
        self.records.save(&self.root.join("fastresume.bin"))?;
        Ok(objects)
    }
    fn scan_file(
        self: &Arc<Self>,
        path: &FsPath,
        lower: bool,
        mode: IndexMode,
        objects: &mut BTreeMap<ContentId, Arc<Stored>>,
    ) -> Result<()> {
        if crate::fastresume::is_cache_debris(path) {
            return Ok(());
        }
        let (indexed, location) = self.index(path, if lower { mode } else { IndexMode::Resume })?;
        let id = ContentId::from_bytes(indexed.id.into_bytes());
        if !lower
            && path.file_name().and_then(|name| name.to_str()) != Some(id.to_string().as_str())
        {
            self.records.forget(location.identity);
            self.discard_corrupt_upper(path)?;
            return Ok(());
        }
        if let Some(stored) = objects.get(&id) {
            if let Data::File(file) = &stored.data {
                file.entries.lock().unwrap().push(location);
            }
        } else {
            objects.insert(
                id,
                Arc::new(Stored::new(
                    Data::File(Arc::new(FileObject {
                        object: ContentRef::new(id, indexed.len),
                        disk: self.clone(),
                        entries: Mutex::new(vec![location]),
                        staged: Mutex::new(None),
                        private: Mutex::new(None),
                    })),
                    indexed.chunks,
                )),
            );
        }
        Ok(())
    }
}
impl FileObject {
    pub(crate) fn staged(
        disk: Arc<Disk>,
        file: tempfile::NamedTempFile,
        object: ContentRef,
        chunks: Vec<hellas_xet::Chunk>,
        charge: Arc<Reservation>,
    ) -> Result<Self> {
        disk.durability.sync_file(file.as_file())?;
        let entry = Entry {
            path: file.path().to_owned(),
            identity: FileIdentity::of(&file.as_file().metadata()?),
            chunks,
        };
        Ok(Self {
            object,
            disk,
            entries: Mutex::new(vec![entry]),
            staged: Mutex::new(Some((file, charge))),
            private: Mutex::new(None),
        })
    }
    pub(crate) fn merge(&self, older: &Self) {
        if std::ptr::eq(self, older) {
            return;
        }
        let older = older.entries.lock().unwrap().clone();
        let mut entries = self.entries.lock().unwrap();
        for entry in older {
            if !entries
                .iter()
                .any(|old| old.path == entry.path && old.identity == entry.identity)
            {
                entries.push(entry);
            }
        }
    }
    pub(crate) fn open(&self) -> Result<crate::VerifiedFile> {
        self.open_location().map(|(file, _)| file)
    }
    pub(crate) fn open_location(&self) -> Result<(crate::VerifiedFile, Entry)> {
        let upper = self
            .disk
            .root
            .join("objects")
            .join(self.object.id().to_string());
        let (before, tracked) = {
            let entries = self
                .entries
                .lock()
                .map_err(|_| Error::Invalid("file index lock"))?;
            (
                entries.len(),
                entries.iter().any(|entry| entry.path == upper),
            )
        };
        if tracked {
            let refreshed = self.verify_upper(&upper)?;
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|entry| entry.path != upper);
            if let Some(refreshed) = refreshed {
                entries.insert(0, refreshed);
            }
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::Invalid("file index lock"))?;
        let mut chosen = None;
        let mut failure = None;
        entries.retain(|entry| {
            match crate::open_indexed_file(self.object.id().digest(), self.object.bytes(), entry) {
                Ok(Some(file)) => {
                    if chosen.is_none() {
                        chosen = Some((file, entry.clone()));
                    }
                    true
                }
                Err(error) if entry.path == upper => {
                    failure = Some(std::io::Error::other(error).into());
                    true
                }
                Ok(None) if entry.path == upper => true,
                _ => {
                    self.disk.records.forget(entry.identity);
                    false
                }
            }
        });
        if entries.len() != before {
            self.disk
                .records
                .save(&self.disk.root.join("fastresume.bin"))?;
        }
        if let Some(error) = failure {
            return Err(error);
        }
        chosen.ok_or(Error::Missing)
    }
    pub(crate) fn stream(
        self: &Arc<Self>,
        chunks: &[hellas_xet::Chunk],
        range: std::ops::Range<u64>,
    ) -> Result<std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<Bytes>> + Send>>> {
        let (file, entry) = self.open_location()?;
        let file = file.into_file();
        let mut selected = Vec::new();
        let mut offset = 0;
        let descriptors = self
            .disk
            .ram
            .reserve((chunks.len() * std::mem::size_of::<(u64, hellas_xet::Chunk)>()) as u64)?;
        for chunk in chunks {
            let end = offset + chunk.data_len;
            if offset < range.end && end > range.start {
                selected.push((offset, *chunk));
            }
            offset = end;
        }
        let ram = self.disk.ram.clone();
        let backing = Arc::new(BadBacking {
            file: self.clone(),
            entry: Entry {
                chunks: Vec::new(),
                ..entry
            },
            binding: None,
        });
        Ok(Box::pin(futures::stream::try_unfold(
            (file, selected.into_iter(), ram, range, descriptors, backing),
            |(mut file, mut chunks, ram, range, descriptors, backing)| async move {
                let Some((offset, chunk)) = chunks.next() else {
                    return Ok(None);
                };
                let charge = ram.reserve(chunk.data_len)?;
                let reader = backing.clone();
                let (file, bytes) = tokio::task::spawn_blocking(move || {
                    let _reader = reader;
                    file.seek(std::io::SeekFrom::Start(offset))?;
                    let mut bytes = vec![0; chunk.data_len as usize];
                    let changed = match file.read_exact(&mut bytes) {
                        Ok(()) => hellas_xet::chunk(&bytes).as_slice() != [chunk],
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => true,
                        Err(error) => return Err(error.into()),
                    };
                    if changed {
                        return Err(
                            std::io::Error::new(std::io::ErrorKind::InvalidData, _reader).into(),
                        );
                    }
                    Ok::<_, Error>((file, charged(Bytes::from(bytes), charge)))
                })
                .await
                .map_err(|_| Error::Invalid("file read worker"))??;
                let start = range.start.saturating_sub(offset) as usize;
                let end = (range.end - offset).min(chunk.data_len) as usize;
                Ok(Some((
                    bytes.slice(start..end),
                    (file, chunks, ram, range, descriptors, backing),
                )))
            },
        )))
    }
    pub(crate) fn load(&self) -> Result<Bytes> {
        if self.object.bytes() > MAX_TREE_BYTES as u64 {
            return Err(Error::Invalid("tree byte limit"));
        }
        let charge = self.disk.ram.reserve(self.object.bytes())?;
        let (file, entry) = self.open_location()?;
        self.load_opened(file, entry, charge)
    }
    pub(crate) fn invalidate(&self, entry: &Entry) -> Result<()> {
        // Revoke the proven-bad identity even if its former name was replaced.
        self.disk.records.forget(entry.identity);
        let upper = entry.path.parent() == Some(self.disk.root.join("objects").as_path());
        let same = if upper {
            match fs::metadata(&entry.path) {
                Ok(metadata) => FileIdentity::of(&metadata) == entry.identity,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            }
        } else {
            false
        };
        let refreshed = if same {
            self.verify_upper(&entry.path)?
        } else {
            None
        };
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|other| other.path != entry.path || other.identity != entry.identity);
        if let Some(refreshed) = refreshed {
            entries.push(refreshed);
        }
        self.disk
            .records
            .save(&self.disk.root.join("fastresume.bin"))?;
        Ok(())
    }
    fn load_opened(
        &self,
        file: crate::VerifiedFile,
        entry: Entry,
        charge: Arc<Reservation>,
    ) -> Result<Bytes> {
        let mut file = file.into_file();
        let mut bytes = vec![0; self.object.bytes() as usize];
        if file.read_exact(&mut bytes).is_err() || ContentRef::for_bytes(&bytes) != self.object {
            self.invalidate(&entry)?;
            return Err(Error::Invalid("tree backing changed"));
        }
        Ok(charged(Bytes::from(bytes), charge))
    }
    pub(crate) fn publish(&self) -> Result<()> {
        let destination = self
            .disk
            .root
            .join("objects")
            .join(self.object.id().to_string());
        let private = self.private.lock().unwrap().clone();
        if let Some(path) = private {
            let entry = if let Some(entry) = self.verify_upper(&destination)? {
                entry
            } else {
                fs::hard_link(&path, &destination)?;
                let chunks = self.entries.lock().unwrap()[0].chunks.clone();
                Entry {
                    path: destination.clone(),
                    identity: FileIdentity::of(
                        &crate::open_regular_file(&destination)?.metadata()?,
                    ),
                    chunks,
                }
            };
            self.disk
                .durability
                .sync_directory(destination.parent().unwrap())?;
            let private_entry = Entry {
                path: path.clone(),
                identity: FileIdentity::of(&crate::open_regular_file(&path)?.metadata()?),
                chunks: entry.chunks.clone(),
            };
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|old| old.path != path && old.path != destination);
            entries.extend([private_entry, entry]);
            // Keep the verified private name through SQLite commit and scope end.
            return Ok(());
        }
        self.link_temp(destination.parent().unwrap())
    }
    fn verify_upper(&self, path: &FsPath) -> Result<Option<Entry>> {
        let released = match self.disk.index(path, IndexMode::Resume) {
            Ok((indexed, entry))
                if indexed.id == self.object.id().digest()
                    && indexed.len == self.object.bytes() =>
            {
                return Ok(Some(entry));
            }
            Ok(_) => self.disk.discard_corrupt_upper(path)?,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let mut entries = self.entries.lock().unwrap();
        if released && entries.iter().any(|entry| entry.path == path) {
            self.disk.quota.remove_owned(self.object.bytes());
        }
        entries.retain(|entry| {
            if entry.path != path {
                return true;
            }
            self.disk.records.forget(entry.identity);
            false
        });
        Ok(None)
    }
    fn link_temp(&self, directory: &FsPath) -> Result<()> {
        self.disk.durability.create_dir_all(directory)?;
        let path = directory.join(self.object.id().to_string());
        let mut staged = self
            .staged
            .lock()
            .map_err(|_| Error::Invalid("staging lock"))?;
        let Some((file, charge)) = staged.as_ref() else {
            return Ok(());
        };
        let existing = self.verify_upper(&path)?;
        let chunks = self.entries.lock().unwrap()[0].chunks.clone();
        if existing.is_none() {
            fs::hard_link(file.path(), &path)?;
        }
        let temp_path = file.path().to_owned();
        let charge = charge.clone();
        let (file, _) = staged.take().unwrap();
        drop(file);
        if existing.is_some() {
            charge.discarded(self.object.bytes());
        } else {
            charge.published(self.object.bytes());
        }
        let entry = existing.unwrap_or(Entry {
            path: path.clone(),
            identity: FileIdentity::of(&crate::open_regular_file(&path)?.metadata()?),
            chunks,
        });
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|old| old.path != temp_path && old.path != entry.path);
        entries.push(entry);
        drop(entries);
        self.disk.durability.sync_directory(directory)?;
        self.disk
            .durability
            .sync_directory(&self.disk.root.join("staging"))?;
        Ok(())
    }
    pub(crate) fn owned(&self) -> bool {
        self.staged.lock().unwrap().is_some()
            || (self.private.lock().unwrap().is_none()
                && self
                    .disk
                    .root
                    .join("objects")
                    .join(self.object.id().to_string())
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_file()))
    }
    pub(crate) fn collect(&self) -> Result<u64> {
        if let Some((file, charge)) = self.staged.lock().unwrap().take() {
            drop(file);
            charge.rewind(self.object.bytes());
            return Ok(self.object.bytes());
        }
        if self.private.lock().unwrap().is_some() {
            return Ok(0);
        }
        let path = self
            .disk
            .root
            .join("objects")
            .join(self.object.id().to_string());
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        }
        self.entries
            .lock()
            .unwrap()
            .retain(|entry| entry.path != path);
        self.disk.quota.remove_owned(self.object.bytes());
        self.disk
            .durability
            .sync_directory(path.parent().unwrap())?;
        Ok(self.object.bytes())
    }
}
impl DiskStore {
    pub fn durability(&self) -> Durability {
        self.core.disk.as_ref().unwrap().durability
    }
    pub async fn open(
        upper: PathBuf,
        lower: Vec<PathBuf>,
        mode: IndexMode,
        capacity: Option<u64>,
        ram: Reservations,
        durability: Durability,
    ) -> Result<Self> {
        Self::open_inner(upper, lower, mode, capacity, ram, false, durability).await
    }
    /// In-process owner commands have no authoritative work-journal census.
    /// Check the durable monotone ownership fact before scanning or cleanup.
    pub async fn open_owner(
        upper: PathBuf,
        lower: Vec<PathBuf>,
        mode: IndexMode,
        capacity: Option<u64>,
        ram: Reservations,
        durability: Durability,
    ) -> Result<Self> {
        Self::open_inner(upper, lower, mode, capacity, ram, true, durability).await
    }
    async fn open_inner(
        upper: PathBuf,
        lower: Vec<PathBuf>,
        mode: IndexMode,
        capacity: Option<u64>,
        ram: Reservations,
        owner_only: bool,
        durability: Durability,
    ) -> Result<Self> {
        let disk = Disk::open(upper, capacity, ram.clone(), owner_only, durability).await?;
        let opened = async {
            let core = Core::new(ram);
            let (generation, pins, declarations) = disk.pins().await?;
            let scanning = disk.clone();
            let objects = tokio::task::spawn_blocking(move || {
                let objects = scanning.scan(&lower, mode)?;
                // No store or staging writer is exposed until this constructor returns.
                scanning
                    .quota
                    .reconcile_used(Disk::owned_bytes(&scanning.root)?);
                Ok::<_, Error>(objects)
            })
            .await
            .map_err(|_| Error::Invalid("lower scan worker"))??;
            {
                let mut state = core.state.lock().unwrap();
                state.objects = objects;
                state.pins = pins;
                state.declarations = declarations;
                state.generation = generation;
            }
            let mut core = core;
            core.disk = Some(disk.clone());
            Ok(Self { core })
        }
        .await;
        if opened.is_err() {
            disk.db.close().await;
        }
        opened
    }
    /// A channel claims the upper before any of its content scopes or bytes.
    /// The only row is monotone; pin changes and collection never clear it.
    pub async fn claim_work(&self) -> Result<()> {
        let core = self.core.clone();
        tokio::spawn(async move {
            let _gate = core.effect_gate(&Scope::Owner).await?;
            let disk = core.disk.as_ref().unwrap();
            if !disk.work_owned.load(Ordering::Acquire) {
                sqlx::query("INSERT OR IGNORE INTO work_owned(id) VALUES(1)")
                    .execute(&disk.db)
                    .await
                    .map_err(database)?;
                disk.work_owned.store(true, Ordering::Release);
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Invalid("work ownership task"))?
    }
    /// The host calls this only after every channel has restored retained roots
    /// and outstanding output reservations. Admission and collection share it.
    pub async fn finish_recovery(&self) -> Result<()> {
        if !self.core.disk.as_ref().unwrap().ready() {
            self.core
                .effect(&Scope::Owner, |core| core.clear_orphan_acquired())
                .await?;
        }
        let disk = self.core.disk.as_ref().unwrap().clone();
        let gate = self.core.gate.clone().lock_owned().await;
        let live = self.core.live_jobs()?;
        let core = self.core.clone();
        tokio::task::spawn_blocking(move || {
            let _gate = gate;
            if disk.ready() {
                return Ok(());
            }
            // Root-level temporaries are incomplete. Keep only job directories
            // restored by the host; journaled roots are protected before this gate.
            for entry in fs::read_dir(disk.root.join("staging"))? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                } else if entry.file_type()?.is_dir()
                    && !live
                        .iter()
                        .any(|job| Disk::job_name(*job) == entry.file_name())
                {
                    disk.discard_directory(&entry.path(), false)?;
                }
            }
            disk.durability.sync_directory(&disk.root.join("staging"))?;
            disk.quota.reconcile_used(Disk::owned_bytes(&disk.root)?);
            // All journal roots and obligations now exist. Keep admission behind
            // this held gate while reclaiming only the cache needed to fit them.
            let result = (|| {
                core.collect_unpinned(&Scope::Owner, Some(0))?;
                disk.quota.check()?;
                Ok(())
            })();
            if result.is_ok() {
                disk.recovered.store(true, Ordering::Release);
            }
            result
        })
        .await
        .map_err(|_| Error::Invalid("staging cleanup worker"))?
    }
    pub fn ram_pool(&self) -> Reservations {
        self.core.pool.clone()
    }
    pub fn stats(&self) -> Result<StoreStats> {
        self.core.disk.as_ref().unwrap().quota.stats()
    }
    /// Both closure completion and local executor preflight consult this policy.
    pub fn set_on_miss(&self, policy: Arc<dyn OnMiss>) -> Result<()> {
        self.core
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?
            .on_miss = policy;
        Ok(())
    }
    pub fn with_peers(self, peers: hellas_wire::iroh::Pool) -> Self {
        self.core.state.lock().expect("content state").peers = Some(peers);
        self
    }
}

impl Drop for FileObject {
    fn drop(&mut self) {
        if let Some((file, charge)) = self.staged.get_mut().unwrap().take() {
            drop(file);
            charge.rewind(self.object.bytes());
        }
    }
}
impl DiskStore {
    pub async fn rescan(&self, lower: Vec<PathBuf>, mode: IndexMode) -> Result<()> {
        self.core
            .access(&Scope::Owner, move |core| {
                let mut state = core.state.lock().unwrap();
                for stored in state.objects.values() {
                    if let Data::File(file) = &stored.data {
                        file.verify_upper(
                            &file
                                .disk
                                .root
                                .join("objects")
                                .join(file.object.id().to_string()),
                        )?;
                    }
                }
                let objects = core.disk.as_ref().unwrap().scan(&lower, mode)?;
                state.reload(objects);
                Ok(())
            })
            .await
    }
    pub async fn open_work(
        &self,
        job: JobId,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Scope> {
        self.claim_work().await?;
        self.core
            .admit(&Scope::Owner, move |core| {
                core.open_work(job, closure.clone(), max_upload_bytes)
            })
            .await
    }
    pub async fn widen_work(
        &self,
        scope: &Scope,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Scope> {
        let scope = scope.clone();
        self.core
            .admit(&scope.clone(), move |core| {
                core.widen_work(&scope, closure.clone(), max_upload_bytes)
            })
            .await
    }
    pub async fn end_work(&self, scope: &Scope) -> Result<()> {
        let scope = scope.clone();
        self.core
            .effect(&Scope::Owner, move |core| core.end_work(&scope))
            .await
    }
    /// Restore journal-derived output accounting. Before recovery completes this
    /// restores the obligation; on a running node it uses ordinary admission.
    /// `consumed` counts authoritative generated metadata already owned on disk.
    /// An existing allowance is preserved, including any bytes spent since then.
    pub async fn restore_output(&self, scope: &Scope, total: u64, consumed: u64) -> Result<()> {
        let scope = scope.clone();
        self.core
            .admit(&scope.clone(), move |core| {
                core.restore_output(&scope, total, consumed)
            })
            .await
    }
    /// Set the job's total output allowance. A retry does not replenish bytes
    /// already consumed by staged trees or a transcript.
    pub async fn reserve_output(&self, scope: &Scope, bytes: u64) -> Result<()> {
        let scope = scope.clone();
        self.core
            .admit(&scope.clone(), move |core| {
                core.reserve_output(&scope, bytes)
            })
            .await
    }
    pub async fn resolve_hf(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, ContentRef)> {
        self.core.resolve_hf(scope, repo).await
    }
}

impl DiskStore {
    pub async fn stage_output(&self, scope: &Scope, object: ContentRef) -> Result<UploadSession> {
        let scope = scope.clone();
        self.core
            .effect(&scope.clone(), move |core| {
                core.stage_output(&scope, object)
            })
            .await
    }
}

impl Disk {
    fn job_name(job: JobId) -> std::ffi::OsString {
        format!("{}-{}", job.channel, job.id).into()
    }
    fn same_file(a: &FsPath, b: &FsPath) -> bool {
        match (fs::symlink_metadata(a), fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => FileIdentity::of(&a) == FileIdentity::of(&b),
            _ => false,
        }
    }
    fn owned_bytes(root: &FsPath) -> Result<u64> {
        let mut pending = if root.join("objects").is_dir() {
            vec![root.join("objects"), root.join("staging")]
        } else {
            vec![root.to_owned()]
        };
        let mut seen = std::collections::HashSet::new();
        let mut total = 0u64;
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    pending.push(entry.path());
                } else if kind.is_file() {
                    let metadata = entry.metadata()?;
                    if seen.insert(FileIdentity::of(&metadata)) {
                        total = total.checked_add(metadata.len()).ok_or(Error::Capacity)?;
                    }
                }
            }
        }
        Ok(total)
    }
    fn discard_directory(&self, directory: &FsPath, account: bool) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let shared = Self::same_file(
                &entry.path(),
                &self.root.join("objects").join(entry.file_name()),
            );
            let len = entry.metadata()?.len();
            fs::remove_file(entry.path())?;
            if account && !shared {
                self.quota.remove_owned(len);
            }
        }
        fs::remove_dir(directory)?;
        Ok(())
    }
    pub(crate) fn discard_job(&self, job: JobId) -> Result<()> {
        let directory = self.root.join("staging").join(Self::job_name(job));
        if directory.exists() {
            self.discard_directory(&directory, true)?;
            self.durability.sync_directory(&self.root.join("staging"))?;
        }
        Ok(())
    }
    pub(crate) fn recover_staged(
        self: &Arc<Self>,
        job: JobId,
    ) -> Result<BTreeMap<ContentId, Arc<Stored>>> {
        let directory = self.root.join("staging").join(Self::job_name(job));
        let mut staged = BTreeMap::new();
        if !directory.exists() {
            return Ok(staged);
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let (indexed, location) = self.index(&entry.path(), IndexMode::Resume)?;
            let id = ContentId::from_bytes(indexed.id.into_bytes());
            if entry.file_name().to_str() != Some(id.to_string().as_str()) {
                let path = entry.path();
                let shared =
                    Self::same_file(&path, &self.root.join("objects").join(entry.file_name()));
                fs::remove_file(&path)?;
                if !shared {
                    self.quota.remove_owned(indexed.len);
                }
                self.records.forget(location.identity);
                tracing::error!(id = %entry.file_name().to_string_lossy(), path = %path.display(), "discarded corrupt private staged object");
                continue;
            }
            staged.insert(
                id,
                Arc::new(Stored::new(
                    Data::File(Arc::new(FileObject {
                        object: ContentRef::new(id, indexed.len),
                        disk: self.clone(),
                        entries: Mutex::new(vec![location]),
                        staged: Mutex::new(None),
                        private: Mutex::new(Some(entry.path())),
                    })),
                    indexed.chunks,
                )),
            );
        }
        Ok(staged)
    }
}
impl FileObject {
    pub(crate) fn stage(&self, job: JobId) -> Result<()> {
        let directory = self.disk.root.join("staging").join(Disk::job_name(job));
        self.link_temp(&directory)?;
        *self.private.lock().unwrap() = Some(directory.join(self.object.id().to_string()));
        Ok(())
    }
    pub(crate) fn discard_private(&self) -> Result<()> {
        let private = self.private.lock().unwrap().clone();
        if let Some(path) = private {
            let global = self
                .disk
                .root
                .join("objects")
                .join(self.object.id().to_string());
            let shared = Disk::same_file(&path, &global);
            fs::remove_file(&path)?;
            *self.private.lock().unwrap() = None;
            if !shared {
                self.disk.quota.remove_owned(self.object.bytes());
            }
            let mut entries = self.entries.lock().unwrap();
            entries.retain(|entry| entry.path != path);
            if shared {
                for entry in entries.iter_mut().filter(|entry| entry.path == global) {
                    entry.identity =
                        FileIdentity::of(&crate::open_regular_file(&global)?.metadata()?);
                }
            }
            self.disk
                .durability
                .sync_directory(path.parent().unwrap())?;
        }
        Ok(())
    }
}
impl DiskStore {
    /// Reconcile a journal root and optional previous pin name under one effect.
    /// Recovery scopes protect files through persistence and cannot be adopted
    /// by ordinary open_work callers, including after a failed pin commit.
    pub async fn restore_root(
        &self,
        job: JobId,
        target: Target,
        pin: PinTarget,
        previous: Option<PinName>,
    ) -> Result<()> {
        self.claim_work().await?;
        let core = self.core.clone();
        tokio::spawn(async move {
            let temporary = core
                .effect(&Scope::Owner, move |core| {
                    core.restore_root(job, target, pin, previous)
                })
                .await?;
            if let Some(scope) = temporary {
                core.effect(&Scope::Owner, move |core| core.end_work(&scope))
                    .await?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Invalid("root recovery task"))?
    }
}

#[cfg(test)]
mod tests;

impl DiskStore {
    /// Wait for in-flight effects and release SQLite's exclusive writer lock.
    pub async fn close(&self) {
        let _gate = self.core.gate.lock().await;
        self.core.disk.as_ref().unwrap().db.close().await;
    }
}

impl DiskStore {
    /// Bootstrap a signed Work root before the application has validated its
    /// closure. Executor disk reads still require their policy-checked pin.
    pub async fn open_staged(
        &self,
        scope: &Scope,
        object: ContentRef,
    ) -> Result<Option<super::local::VerifiedReader>> {
        let scope = scope.clone();
        self.core
            .access(&scope.clone(), move |core| {
                core.verified(&scope, object, None, true)
            })
            .await
    }
}

impl std::fmt::Debug for DiskStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DiskStore")
    }
}
