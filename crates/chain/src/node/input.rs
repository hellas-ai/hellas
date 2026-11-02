//! Certified history enters execution through the same boundary for every source.
use super::*;
use commonware_consensus::{Reporter as _, simplex::types::Activity};

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
        for candidate in std::iter::once(block).chain(proof.descendants) {
            if !self
                .archive
                .marshal
                .verified(candidate.context().round, candidate)
                .await
            {
                return Err(storage("marshal closed"));
            }
        }
        if !self
            .archive
            .marshal
            .clone()
            .report(Activity::Finalization(proof.certificate))
            .accepted()
        {
            return Err(storage("marshal closed"));
        }
        Ok(())
    }
}
