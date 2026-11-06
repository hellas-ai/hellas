//! Executor-local verified handles; remote stores never enter this enum.
use super::{
    core::{Core, canonical_closure},
    storage::Data,
    *,
};
use hellas_rpc::{ContentId, ContentRef};
use std::io::{Cursor, Read, Seek};

pub enum VerifiedReader {
    File(crate::VerifiedFile),
    Memory(Cursor<bytes::Bytes>),
}
impl VerifiedReader {
    /// Return a bounded, immutable body whose accounting follows its ownership.
    pub async fn read_all(self, object: ContentRef, pool: &Reservations) -> Result<bytes::Bytes> {
        match self {
            Self::Memory(reader) => {
                let bytes = reader.into_inner();
                if ContentRef::for_bytes(&bytes) != object {
                    return Err(Error::Invalid("application content changed"));
                }
                Ok(bytes)
            }
            Self::File(reader) => {
                let charge = pool.reserve(object.bytes())?;
                tokio::task::spawn_blocking(move || {
                    let mut reader = reader.into_file();
                    let mut bytes =
                        vec![0; usize::try_from(object.bytes()).map_err(|_| Error::Capacity)?];
                    reader.read_exact(&mut bytes)?;
                    if reader.read(&mut [0])? != 0 || ContentRef::for_bytes(&bytes) != object {
                        return Err(Error::Invalid("application content changed"));
                    }
                    Ok(super::storage::charged(bytes.into(), charge))
                })
                .await
                .map_err(|_| Error::Invalid("application content reader"))?
            }
        }
    }
}
impl Read for VerifiedReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.file.read(bytes),
            Self::Memory(cursor) => cursor.read(bytes),
        }
    }
}
impl Seek for VerifiedReader {
    fn seek(&mut self, at: std::io::SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::File(file) => file.file.seek(at),
            Self::Memory(cursor) => cursor.seek(at),
        }
    }
}
pub(crate) fn reader(data: &Data, object: ContentRef) -> Result<VerifiedReader> {
    if data.len() != object.bytes() {
        return Err(Error::Invalid("content length contract"));
    }
    Ok(match data {
        Data::Ram(bytes) => VerifiedReader::Memory(Cursor::new(bytes.clone())),
        Data::File(file) => VerifiedReader::File(file.open()?),
    })
}
#[derive(Clone)]
pub struct JobContent {
    upper: MemoryStore,
    scope: Scope,
}
impl JobContent {
    pub async fn new(
        node: &DiskStore,
        job: JobId,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Self> {
        if !node.core.disk.as_ref().unwrap().ready() {
            return Err(Error::Denied);
        }
        let mut core = Core::new(node.core.pool.clone());
        core.lower = Some(Box::new(node.core.clone()));
        let scope = core
            .clone()
            .access(&Scope::Owner, move |core| {
                core.require_ready()?;
                core.open_work(job, closure, max_upload_bytes)
            })
            .await?;
        Ok(Self {
            upper: MemoryStore { core },
            scope,
        })
    }
    pub async fn widen(&self, closure: Closure, max_upload_bytes: u64) -> Result<Self> {
        let scope = self
            .upper
            .widen_work(&self.scope, closure, max_upload_bytes)
            .await?;
        Ok(Self {
            upper: self.upper.clone(),
            scope,
        })
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn store(&self) -> &MemoryStore {
        &self.upper
    }
    pub async fn end(&self) -> Result<()> {
        let scope = self.scope.clone();
        let upper = self.upper.core.clone();
        tokio::spawn(async move {
            let ScopeKind::Work { reservation, .. } = scope.kind else {
                return Err(Error::Denied);
            };
            let owner = (std::sync::Arc::downgrade(&upper.state), reservation);
            upper
                .access(&Scope::Owner, move |core| core.end_work(&scope))
                .await?;
            if let Some(node) = &upper.lower {
                node.effect(&Scope::Owner, move |core| core.clear_acquired(owner))
                    .await?;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Invalid("job content cleanup task"))?
    }
}
#[derive(Clone)]
pub enum LocalStore {
    Disk(DiskStore),
    Memory(MemoryStore),
    Job(JobContent),
}
impl LocalStore {
    pub fn ram_pool(&self) -> Reservations {
        self.core().pool.clone()
    }
    pub(crate) fn core(&self) -> &Core {
        match self {
            Self::Disk(store) => &store.core,
            Self::Memory(store) => &store.core,
            Self::Job(job) => &job.upper.core,
        }
    }
    pub const fn retention(&self) -> hellas_rpc::Retention {
        match self {
            Self::Disk(_) => hellas_rpc::Retention::Retain,
            Self::Memory(_) | Self::Job(_) => hellas_rpc::Retention::Ephemeral,
        }
    }
    pub async fn ephemeral_bytes(&self, scope: &Scope) -> Result<u64> {
        if matches!(self, Self::Disk(_)) {
            return Ok(0);
        }
        let scope = scope.clone();
        self.core()
            .access(&scope.clone(), move |core| core.work_bytes(&scope))
            .await
    }
    /// The application has parsed the signed root. Fetch approved misses before
    /// widening reserves RAM for client uploads; Refuse leaves them to the client.
    pub async fn acquire_missing(
        &self,
        scope: &Scope,
        closure: Closure,
    ) -> Result<std::collections::BTreeSet<ContentId>> {
        let core = self.core();
        let checking = scope.clone();
        let requested = canonical_closure(closure)?;
        let missing = core
            .access(scope, move |core| core.missing_refs(&checking, &requested))
            .await?;
        let destination = match self {
            Self::Disk(store) => &store.core,
            Self::Job(job) => job.upper.core.lower.as_deref().ok_or(Error::Denied)?,
            Self::Memory(_) => return Ok(Default::default()),
        };
        let ScopeKind::Work { job, .. } = &scope.kind else {
            return Err(Error::Denied);
        };
        let mut acquired = std::collections::BTreeSet::new();
        for object in missing {
            let policy = destination
                .state
                .lock()
                .map_err(|_| Error::Invalid("store lock"))?
                .on_miss
                .clone();
            let decision = policy.decide(
                &Miss {
                    scope: scope.clone(),
                    object,
                },
                &destination.data_pool().stats()?,
            );
            if let MissDecision::Acquire { source } = decision {
                let mut owner = scope.clone();
                owner.kind = ScopeKind::Owner;
                destination
                    .acquire_scoped(
                        &owner,
                        source,
                        Some(object),
                        PinTarget {
                            name: PinName::new(format!(
                                "work/{}/acquired/{}",
                                job.id,
                                object.id()
                            ))?,
                            policy: PinPolicy::Jobs,
                        },
                        Some((core.clone(), scope.clone())),
                    )
                    .await?;
                acquired.insert(object.id());
            }
        }
        Ok(acquired)
    }

    pub async fn open_verified(
        &self,
        scope: &Scope,
        object: ContentRef,
        at: Option<&Path>,
    ) -> Result<Option<VerifiedReader>> {
        let (core, job) = match self {
            Self::Disk(store) => (store.core.clone(), false),
            Self::Memory(store) => (store.core.clone(), false),
            Self::Job(job) => {
                if let (
                    ScopeKind::Work {
                        job: a,
                        reservation: ar,
                        ..
                    },
                    ScopeKind::Work {
                        job: b,
                        reservation: br,
                        ..
                    },
                ) = (&scope.kind, &job.scope.kind)
                {
                    if a != b || ar != br {
                        return Err(Error::Denied);
                    }
                } else {
                    return Err(Error::Denied);
                }
                (job.upper.core.clone(), true)
            }
        };
        let (scope, at) = (scope.clone(), at.cloned());
        core.access(&scope.clone(), move |core| {
            core.verified(&scope, object, at.as_ref(), job)
        })
        .await
    }

    /// Executor preflight may acquire after a missing or invalid lower backing.
    /// The caller must not hold its authority writer while staging the source.
    pub async fn preflight(
        &self,
        scope: &Scope,
        object: ContentRef,
    ) -> Result<Option<VerifiedReader>> {
        let result = self.open_verified(scope, object, None).await;
        if !matches!(&result, Ok(Some(_)))
            && let ScopeKind::Work { closure, .. } = &scope.kind
            && closure.contains(&object)
            && self
                .acquire_missing(scope, closure.clone())
                .await?
                .contains(&object.id())
        {
            return self.open_verified(scope, object, None).await;
        }
        result
    }
}

impl std::fmt::Debug for LocalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disk(_) => "DiskStore",
            Self::Memory(_) => "MemoryStore",
            Self::Job(_) => "JobContent",
        })
    }
}
