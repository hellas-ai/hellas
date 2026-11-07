//! Proves a store's next checkpoint still fits without encoding its whole
//! state on every commit. Each store maps its own changes to growth.
use super::NodeStoreError;
use crate::model::grant::records::GrantError;
use hellas_channel::work_store::journal::MAX_CHECKPOINT_BYTES;

/// At least the checkpoint cost of a store's committed state: exact when last
/// measured, plus the growth of every frame since.
#[derive(Clone, Copy, Debug)]
pub(super) struct CheckpointBound(usize);
/// A frame's bound, held until the frame is durable.
#[must_use]
pub(super) struct Admitted {
    bound: CheckpointBound,
    growth: usize,
}
impl CheckpointBound {
    pub(super) const UNMEASURED: Self = Self(usize::MAX);

    /// Adopt an exact cost: at a rotation, or when the bound cannot decide.
    pub(super) fn measured(&mut self, cost: usize) {
        debug_assert!(
            cost <= self.0,
            "checkpoint growth bound: {cost} > {}",
            self.0
        );
        self.0 = cost;
    }
    /// Admit a frame adding at most `growth` while `reserve` stays free. Only
    /// a failing bound runs `measure`, so a refusal always rests on the exact cost.
    pub(super) fn admit(
        &self,
        growth: usize,
        reserve: usize,
        measure: impl FnOnce() -> Result<usize, NodeStoreError>,
    ) -> Result<Admitted, NodeStoreError> {
        let mut bound = Self(self.0.saturating_add(growth));
        if bound.0.saturating_add(reserve) > MAX_CHECKPOINT_BYTES {
            bound.measured(measure()?);
            if bound.0.saturating_add(reserve) > MAX_CHECKPOINT_BYTES {
                return Err(GrantError::StateCapacity.into());
            }
        }
        Ok(Admitted { bound, growth })
    }
    /// Call once the admitted frame is durable. A rotation in between can only
    /// have tightened `self`, so keep whichever bound is lower.
    pub(super) fn commit(&mut self, admitted: Admitted) {
        self.0 = admitted.bound.0.min(self.0.saturating_add(admitted.growth));
    }
    #[cfg(test)]
    pub(super) fn get(self) -> usize {
        self.0
    }
}
