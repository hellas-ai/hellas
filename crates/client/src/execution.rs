//! Presentation events for a funded text application.
pub use hellas_rpc::cache::{
    TextEvent as ExecutionEvent, TextOutcome as Outcome, TextStop as StopReason,
};
impl crate::cache::CacheEvent for ExecutionEvent {
    fn terminal(&self) -> Option<bool> {
        ExecutionEvent::terminal(self)
    }
}
