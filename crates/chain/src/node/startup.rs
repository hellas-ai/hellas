//! Keep index reconciliation outside concurrent execution. Marshal may have
//! persisted backlog even while the live replication feed is stopped.
use super::*;
use commonware_actor::Feedback;
use commonware_consensus::{Heightable as _, Reporter, marshal::Update};

type UpdateBlock = Update<HellasBlock>;

#[derive(Clone)]
pub(super) struct Delivery(Arc<std::sync::Mutex<State>>);
struct State {
    mailbox: crate::execution::pipeline::Mailbox,
    through: Option<u64>,
    tip: Option<UpdateBlock>,
    block: Option<UpdateBlock>,
}
impl Delivery {
    pub(super) fn new(mailbox: crate::execution::pipeline::Mailbox, through: u64) -> Self {
        Self(Arc::new(std::sync::Mutex::new(State {
            mailbox,
            through: Some(through),
            tip: None,
            block: None,
        })))
    }
    pub(super) fn resume(&self) -> Result<(), Error> {
        let mut state = self.0.lock().expect("startup delivery lock poisoned");
        state.through = None;
        let tip = state.tip.take();
        let block = state.block.take();
        for update in tip.into_iter().chain(block) {
            if !state.mailbox.report(update).accepted() {
                return Err(storage("execution closed during startup"));
            }
        }
        Ok(())
    }
}
impl Reporter for Delivery {
    type Activity = UpdateBlock;
    fn report(&mut self, update: UpdateBlock) -> Feedback {
        let mut state = self.0.lock().expect("startup delivery lock poisoned");
        let height = match &update {
            Update::Tip(_, height, _) => height.get(),
            Update::Block(block, _) => block.height().get(),
        };
        if state.through.is_some_and(|through| height > through) {
            match update {
                Update::Tip(..) => state.tip = Some(update),
                Update::Block(..) => {
                    // The archive is configured with max_pending_acks=1. Holding
                    // this acknowledgment bounds delivery without dropping work.
                    assert!(
                        state.block.is_none(),
                        "multiple pending archive acknowledgments"
                    );
                    state.block = Some(update);
                }
            }
            Feedback::Ok
        } else {
            state.mailbox.report(update)
        }
    }
}
