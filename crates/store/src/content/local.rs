//! Executor-local verified handles; remote stores never enter this enum.
use super::{core::Core, storage::Data, *};
use hellas_rpc::ContentRef;
use std::io::{Cursor, Read, Seek};

pub enum VerifiedReader {
    File(crate::VerifiedFile),
    Memory(Cursor<bytes::Bytes>),
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
        self.upper
            .core
            .access(&Scope::Owner, move |core| core.end_work(&scope))
            .await
    }
}
#[derive(Clone)]
pub enum LocalStore {
    Disk(DiskStore),
    Job(JobContent),
}
impl LocalStore {
    pub async fn open_verified(
        &self,
        scope: &Scope,
        object: ContentRef,
        at: Option<&Path>,
    ) -> Result<Option<VerifiedReader>> {
        let (core, job) = match self {
            Self::Disk(store) => (store.core.clone(), false),
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
}
