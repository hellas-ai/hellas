use super::{core::Core, *};

/// RAM-only upper storage; shares pin, scope and session semantics with DiskStore.
#[derive(Clone)]
pub struct MemoryStore {
    pub(crate) core: Core,
}
impl MemoryStore {
    pub fn new(pool: Reservations) -> Self {
        Self {
            core: Core::new(pool),
        }
    }
    pub fn with_peers(mut self, peers: hellas_wire::iroh::Pool) -> Self {
        self.core.peers = Some(peers);
        self
    }
    pub async fn open_work(
        &self,
        job: JobId,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Scope> {
        self.core
            .admit(move |core| core.open_work(job, closure.clone(), max_upload_bytes))
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
            .admit(move |core| core.widen_work(&scope, closure.clone(), max_upload_bytes))
            .await
    }
    pub fn accept_work(&self, scope: &Scope) -> Result<()> {
        self.core.accept_work(scope)
    }
    pub fn end_work(&self, scope: &Scope) -> Result<()> {
        self.core.end_work(scope)
    }
    pub fn own_bytes(
        &self,
        scope: &Scope,
        object: hellas_rpc::ContentRef,
    ) -> Result<Option<bytes::Bytes>> {
        self.core.own_bytes(scope, object)
    }
    pub async fn resolve_hf(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, hellas_rpc::ContentRef)> {
        self.core.resolve_hf(scope, repo).await
    }
}
