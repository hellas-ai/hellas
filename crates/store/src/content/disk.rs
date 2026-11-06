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

#[derive(Clone, Copy, Debug, Default)]
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
}
pub(crate) struct FileObject {
    pub object: ContentRef,
    disk: Arc<Disk>,
    entries: Mutex<Vec<Entry>>,
    staged: Mutex<Option<(tempfile::NamedTempFile, Arc<Reservation>)>>,
    private: Mutex<Option<PathBuf>>,
}
fn database(_: sqlx::Error) -> Error {
    Error::Invalid("content database")
}
impl Disk {
    async fn open(root: PathBuf, capacity: Option<u64>, ram: Reservations) -> Result<Arc<Self>> {
        let directory = root.clone();
        tokio::task::spawn_blocking(move || {
            hellas_private::create_dir_all_durable(&directory.join("objects"))?;
            hellas_private::create_dir_all_durable(&directory.join("staging"))?;
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Invalid("content startup worker"))??;
        let options = SqliteConnectOptions::new()
            .filename(root.join("content.sqlite"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .locking_mode(SqliteLockingMode::Exclusive)
            .busy_timeout(std::time::Duration::from_millis(250));
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::raw_sql("BEGIN IMMEDIATE; COMMIT")
                        .execute(connection)
                        .await
                        .map(drop)
                })
            })
            .connect_with(options)
            .await
            .map_err(database)?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&db)
            .await
            .map_err(database)?;
        if version != 0 && version != 1 {
            return Err(Error::Invalid("unsupported content database version"));
        }
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS pins (name TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS head (id INTEGER PRIMARY KEY CHECK(id=1), generation BLOB NOT NULL); INSERT OR IGNORE INTO head VALUES(1, x'0000000000000000'); PRAGMA user_version=1;").execute(&db).await.map_err(database)?;
        hellas_private::sync_directory(&root)?;
        let records = Arc::new(Records::default());
        let _ = records.load(&root.join("fastresume.bin"));
        let cleanup = root.clone();
        tokio::task::spawn_blocking(move || {
            for entry in fs::read_dir(cleanup.join("staging"))? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                }
            }
            hellas_private::sync_directory(&cleanup.join("staging"))?;
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Invalid("incomplete staging cleanup worker"))??;
        let used = Self::owned_bytes(&root)?;
        Ok(Arc::new(Self {
            quota: Reservations::disk(root.clone(), capacity, used),
            root,
            ram,
            records,
            db,
            recovered: AtomicBool::new(false),
        }))
    }
    pub(crate) fn ready(&self) -> bool {
        self.recovered.load(Ordering::Acquire)
    }
    pub(crate) async fn pins(&self) -> Result<(u64, BTreeMap<PinName, PinValue>)> {
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
        Ok((generation, pins))
    }
    pub(crate) async fn persist(
        &self,
        generation: u64,
        pins: BTreeMap<PinName, PinValue>,
    ) -> Result<()> {
        let mut tx = self.db.begin().await.map_err(database)?;
        sqlx::query("DELETE FROM pins")
            .execute(&mut *tx)
            .await
            .map_err(database)?;
        for (name, value) in pins {
            sqlx::query("INSERT INTO pins(name,value) VALUES(?,?)")
                .bind(name.as_str())
                .bind(super::wire::pin_value(&value).encode_to_vec())
                .execute(&mut *tx)
                .await
                .map_err(database)?;
        }
        sqlx::query("UPDATE head SET generation=? WHERE id=1")
            .bind(generation.to_be_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(database)?;
        tx.commit().await.map_err(database)
    }
    fn index(&self, path: &FsPath, mode: IndexMode) -> Result<(Indexed, Entry)> {
        let mut file = crate::open_regular_file(path)?;
        let metadata = file.metadata()?;
        let identity = FileIdentity::of(&metadata);
        let indexed = match self.records.get(&metadata) {
            Some(indexed) => indexed,
            None if matches!(mode, IndexMode::Require) => {
                return Err(Error::Invalid("lower file requires an index record"));
            }
            None => {
                let _scratch = self.ram.reserve(crate::STREAM_BUFFER as u64)?;
                crate::hash_exact_length(&mut file, metadata.len())?
                    .ok_or(Error::Invalid("file changed during indexing"))?
            }
        };
        crate::still_the_file_that_was_read(path, identity, &file)
            .map_err(|_| Error::Invalid("file replaced during indexing"))?;
        self.records.put(&metadata, &indexed);
        Ok((
            indexed.clone(),
            Entry {
                path: path.to_owned(),
                identity,
                chunks: indexed.chunks,
            },
        ))
    }
    pub(crate) fn scan(
        self: &Arc<Self>,
        lowers: &[PathBuf],
        mode: IndexMode,
    ) -> Result<BTreeMap<ContentId, Arc<Stored>>> {
        // Load local index changes only at the explicit rescan boundary.
        let _ = self.records.load(&self.root.join("fastresume.bin"));
        let mut objects: BTreeMap<ContentId, Arc<Stored>> = BTreeMap::new();
        let mut directories = vec![(self.root.join("objects"), false)];
        directories.extend(lowers.iter().cloned().map(|path| (path, true)));
        while let Some((directory, lower)) = directories.pop() {
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                let path = entry.path();
                if kind.is_dir() && lower {
                    directories.push((path, true));
                    continue;
                }
                if !kind.is_file() || crate::fastresume::is_cache_debris(&path) {
                    continue;
                }
                let (indexed, location) =
                    self.index(&path, if lower { mode } else { IndexMode::Resume })?;
                let id = ContentId::from_bytes(indexed.id.into_bytes());
                if !lower
                    && path.file_name().and_then(|name| name.to_str())
                        != Some(id.to_string().as_str())
                {
                    return Err(Error::Invalid("corrupt upper object"));
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
            }
        }
        self.records.save(&self.root.join("fastresume.bin"))?;
        Ok(objects)
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
        file.as_file().sync_all()?;
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
    fn open_location(&self) -> Result<(crate::VerifiedFile, Entry)> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::Invalid("file index lock"))?;
        let mut chosen = None;
        let before = entries.len();
        entries.retain_mut(|entry| {
            let mut opened = crate::open_indexed_file(
                self.object.id().digest(),
                crate::LengthContract::Exact(self.object.bytes()),
                entry,
            );
            // Store-owned hard-link publication/removal changes ctime. Reverify
            // that upper backing before refreshing its identity; changed lowers
            // are still marked bad and require an explicit rescan.
            if !matches!(opened, Ok(Some(_)))
                && entry.path.parent() == Some(self.disk.root.join("objects").as_path())
                && let Ok((indexed, refreshed)) = self.disk.index(&entry.path, IndexMode::Resume)
                && indexed.id == self.object.id().digest()
                && indexed.len == self.object.bytes()
            {
                *entry = refreshed;
                opened = crate::open_indexed_file(
                    self.object.id().digest(),
                    crate::LengthContract::Exact(self.object.bytes()),
                    entry,
                );
            }
            match opened {
                Ok(Some(file)) => {
                    if chosen.is_none() {
                        chosen = Some((file, entry.clone()));
                    }
                    true
                }
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
        let backing = self.clone();
        Ok(Box::pin(futures::stream::try_unfold(
            (
                file,
                selected.into_iter(),
                ram,
                range,
                descriptors,
                backing,
                entry,
            ),
            |(mut file, mut chunks, ram, range, descriptors, backing, entry)| async move {
                let Some((offset, chunk)) = chunks.next() else {
                    return Ok(None);
                };
                let charge = ram.reserve(chunk.data_len)?;
                let invalidator = backing.clone();
                let read_entry = entry.clone();
                let (file, bytes) = tokio::task::spawn_blocking(move || {
                    file.seek(std::io::SeekFrom::Start(offset))?;
                    let mut bytes = vec![0; chunk.data_len as usize];
                    if file.read_exact(&mut bytes).is_err()
                        || hellas_xet::chunk(&bytes).as_slice() != [chunk]
                    {
                        invalidator.invalidate(&read_entry)?;
                        return Err(Error::Invalid("backing chunk changed"));
                    }
                    Ok::<_, Error>((file, charged(Bytes::from(bytes), charge)))
                })
                .await
                .map_err(|_| Error::Invalid("file read worker"))??;
                let start = range.start.saturating_sub(offset) as usize;
                let end = (range.end - offset).min(chunk.data_len) as usize;
                Ok(Some((
                    bytes.slice(start..end),
                    (file, chunks, ram, range, descriptors, backing, entry),
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
    fn invalidate(&self, entry: &Entry) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .retain(|other| other.path != entry.path || other.identity != entry.identity);
        self.disk.records.forget(entry.identity);
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
            let entry = if let Some(entry) = self.existing(&destination)? {
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
            hellas_private::sync_directory(destination.parent().unwrap())?;
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
    fn existing(&self, path: &FsPath) -> Result<Option<Entry>> {
        if path.symlink_metadata().is_err() {
            return Ok(None);
        }
        let (indexed, entry) = self.disk.index(path, IndexMode::Resume)?;
        if indexed.id != self.object.id().digest() || indexed.len != self.object.bytes() {
            return Err(Error::Invalid("conflicting owned backing"));
        }
        Ok(Some(entry))
    }
    fn link_temp(&self, directory: &FsPath) -> Result<()> {
        hellas_private::create_dir_all_durable(directory)?;
        let path = directory.join(self.object.id().to_string());
        let mut staged = self
            .staged
            .lock()
            .map_err(|_| Error::Invalid("staging lock"))?;
        let Some((file, charge)) = staged.as_ref() else {
            return Ok(());
        };
        let existing = self.existing(&path)?;
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
        hellas_private::sync_directory(directory)?;
        hellas_private::sync_directory(&self.disk.root.join("staging"))?;
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
        hellas_private::sync_directory(path.parent().unwrap())?;
        Ok(self.object.bytes())
    }
}
impl DiskStore {
    pub async fn open(
        upper: PathBuf,
        lower: Vec<PathBuf>,
        mode: IndexMode,
        capacity: Option<u64>,
        ram: Reservations,
    ) -> Result<Self> {
        let disk = Disk::open(upper, capacity, ram.clone()).await?;
        let core = Core::new(ram);
        let (generation, pins) = disk.pins().await?;
        let scanning = disk.clone();
        let objects = tokio::task::spawn_blocking(move || scanning.scan(&lower, mode))
            .await
            .map_err(|_| Error::Invalid("lower scan worker"))??;
        {
            let mut state = core.state.lock().unwrap();
            state.objects = objects;
            state.pins = pins;
            state.generation = generation;
        }
        let mut core = core;
        core.disk = Some(disk);
        Ok(Self { core })
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
            hellas_private::sync_directory(&disk.root.join("staging"))?;
            disk.quota.reconcile_used(Disk::owned_bytes(&disk.root)?);
            // All journal roots and obligations now exist. Keep admission behind
            // this held gate while reclaiming only the cache needed to fit them.
            let result = (|| {
                while disk.quota.check().is_err() {
                    if core.collect_unpinned(&Scope::Owner, true)?.objects == 0 {
                        return Err(Error::Capacity);
                    }
                }
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
    pub fn with_peers(mut self, peers: hellas_wire::iroh::Pool) -> Self {
        self.core.peers = Some(peers);
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
                let objects = core.disk.as_ref().unwrap().scan(&lower, mode)?;
                core.state.lock().unwrap().reload(objects);
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
            hellas_private::sync_directory(&self.root.join("staging"))?;
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
                return Err(Error::Invalid("corrupt private staged object"));
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
            hellas_private::sync_directory(path.parent().unwrap())?;
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
    pub async fn promote_work(&self, scope: &Scope, target: Target, pin: PinTarget) -> Result<()> {
        let scope = scope.clone();
        self.core
            .effect(&scope.clone(), move |core| {
                core.promote_work(&scope, target, pin)
            })
            .await
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
