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
    pub async fn accept_work(&self, scope: &Scope) -> Result<()> {
        let scope = scope.clone();
        self.core
            .access(&scope.clone(), move |core| core.accept_work(&scope))
            .await
    }
    pub async fn end_work(&self, scope: &Scope) -> Result<()> {
        let scope = scope.clone();
        self.core
            .access(&Scope::Owner, move |core| core.end_work(&scope))
            .await
    }
    pub async fn own_bytes(
        &self,
        scope: &Scope,
        object: hellas_rpc::ContentRef,
    ) -> Result<Option<bytes::Bytes>> {
        let scope = scope.clone();
        self.core
            .access(&scope.clone(), move |core| core.own_bytes(&scope, object))
            .await
    }
    pub async fn resolve_hf(
        &self,
        scope: &Scope,
        repo: crate::hf::Repo,
    ) -> Result<(String, hellas_rpc::ContentRef)> {
        self.core.resolve_hf(scope, repo).await
    }
}
