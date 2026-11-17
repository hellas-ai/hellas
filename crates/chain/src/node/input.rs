//! Certified history enters execution through the same boundary for every source.
use super::*;

#[derive(Clone)]
pub(super) struct FinalizedInput {
    archive: ChainIndexer,
    readiness: Arc<Readiness>,
    trust: Trust,
}

impl FinalizedInput {
    pub(super) fn new(archive: ChainIndexer, readiness: Arc<Readiness>, trust: Trust) -> Self {
        Self {
            archive,
            readiness,
            trust,
        }
    }

    pub(super) async fn accept(&self, incoming: &FinalizedBlock) -> Result<(), Error> {
        self.readiness.running()?;
        let block = self.readiness.observe(&self.trust, incoming)?;
        let proof = crate::finality_proof::FinalityProof::decode(&incoming.snapshot.finalization)
            .map_err(invalid)?;
        self.archive.accept_verified_proof(block, proof).await?;
        Ok(())
    }
}
