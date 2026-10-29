//! Authenticated prefixes and durable completion of one Compute job.
use crate::protocol::invocation::output::{ArtifactChunk, InvocationOutput};
use hellas_auth::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputeEvent {
    /// An emitted value or caller-declared output, preserving its identity and
    /// byte offset. Step emissions use `emitted` and `catena.u64le.v1`.
    Output(ArtifactChunk),
    /// Complete verified artifacts and the provider whose signature bound them.
    Done {
        output: InvocationOutput,
        provider: PublicKey,
    },
}
