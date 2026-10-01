//! Internal worker events. These are Rust values, not an execution RPC.
//! Signed transcript envelopes retain their canonical wire representation.
use crate::pb::execute::{AssuranceEvidence, OutputEventEnvelope};

#[derive(Clone, Debug, PartialEq)]
pub struct WorkEvent {
    pub kind: Option<work_event::Kind>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct WorkChunk {
    pub output_event: Option<OutputEventEnvelope>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct WorkFinished {
    pub terminal_output_event: Option<OutputEventEnvelope>,
    pub assurance_evidence: Vec<AssuranceEvidence>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct WorkFailed {
    pub position: u64,
    pub error: String,
}
pub mod work_event {
    #[derive(Clone, Debug, PartialEq)]
    pub enum Kind {
        Chunk(super::WorkChunk),
        Finished(super::WorkFinished),
        Failed(super::WorkFailed),
    }
}
