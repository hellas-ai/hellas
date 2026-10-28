//! Adaptors between LLM provider wire formats and the canonical
//! execution vocabulary.
//!
//! # Ownership boundary with `hellas-rpc`
//!
//! This crate owns **provider-shape conversion**: parsing OpenAI /
//! Anthropic request and response JSON, SSE framing, and rendering
//! between those formats and the canonical [`OutputEvent`] vocabulary.
//!
//! It does **not** own **transcript payload encoding**. The signed
//! dag-cbor codecs that turn `OutputEvent`s into the bytes a producer
//! commits to live in `hellas_rpc::{evaluate, fetch}` — because those
//! bytes are signed, their shape is protocol surface, not a provider
//! detail. This crate re-exports the vocabulary it renders (from
//! `hellas_rpc::output`) and nothing more; it never re-exports or
//! reimplements the codecs. The dependency flows one way — adaptors →
//! rpc — so rpc stays free of any provider knowledge.
//!
//! Rule of thumb: if the bytes get signed, the codec belongs in rpc; if
//! the bytes match a vendor's HTTP API, the conversion belongs here.

pub mod adaptor;
pub mod anthropic;
pub mod backend;
pub mod error;
pub mod execution;
mod json;
pub mod openai;
pub mod request;
pub mod wire;

pub use adaptor::{WireAdaptor, WireIngress};
pub use backend::{
    BackendError, BackendEvent, BackendEventStream, BackendFuture, BackendRequest, BackendResult,
    BackendStream, ExecutionBackend,
};
pub use error::{AdaptorError, AdaptorResult};
pub use execution::{
    CanonicalExecution, ContentPart, ExecutionErrorInfo, ExecutionRequest, ExecutionResult, Input,
    InputItem, Message, ModelRef, OutputItem, Provenance, ReasoningOptions, ResponseFormat,
    SamplingOptions, ToolChoice, ToolKind, ToolSpec,
};
// The streaming vocabulary the adaptors produce and consume is protocol
// surface owned by hellas-rpc (it is committed inside signed fetch
// transcripts); re-exported here because it appears throughout this
// crate's own API.
pub use hellas_rpc::output::{
    AdaptorEvent, CodexCompleted, CodexInputTokenDetails, CodexItemStatus, CodexMessageContent,
    CodexMessagePhase, CodexOutputTokenDetails, CodexReasoningContent, CodexReasoningSummary,
    CodexResponseItem, CodexResponsesEvent, CodexToolSearchArguments, CodexUsage,
    CodexUsageMetadata, OutputEvent, StopReason, StructuredDelta, TextChannel,
    ToolCallArgumentsDelta, ToolCallEnd, ToolCallStart, Usage,
};
pub use request::RawRequest;
pub use wire::{
    MAX_SSE_RESPONSE_BYTES, RenderContext, SseDecoder, WireBody, WireEventData, WireHeaders,
    WireResponse, WireStreamEvent,
};
