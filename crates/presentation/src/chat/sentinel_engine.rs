// Adapted from catgrad-llm ac0e432 (MIT); model-independent chat parsing.
//! Reusable sentinel-bounded tool-call parser engine.
//!
//! Survey of the 13 in-tree protocols showed that 8 of them re-implemented
//! the same Outside→Inside→Terminated state machine + 64 KiB payload
//! buffer + PartialThenFatal accumulator + per-call validation loop, just
//! with different bytes-to-calls codecs slotted in. This module factors
//! that out:
//!
//! - [`SentinelKind`] — describes how the wire frames each call:
//!   - `Pair { open, close }`: payload bounded by both sentinels (most
//!     dialects).
//!   - `Prefix { open }`: only an opening sentinel; payload drains at
//!     `finish()` (Granite, Mistral, Phi-4-mini).
//!
//! - [`PayloadCodec`] — bytes-between-sentinels → list of candidate
//!   `(name, args)` pairs, with optional [`ParserError`] for partial /
//!   fatal cases. Codec doesn't know about [`ToolDirectory`] — it only
//!   knows wire shape.
//!
//! - [`SentinelEngine`] — drives the state machine, owns the directory,
//!   validates each candidate, emits the [`DecodeEvent`] triples, and
//!   handles the partial-then-fatal poison transition. Implements
//!   [`IncrementalToolCallParser`] so per-protocol modules collapse to
//!   "construct an engine with the right codec and sentinel."
//!
//! Protocols whose wire shape doesn't fit this mould (gpt-oss harmony
//! channels, llama-3 bare-JSON streaming) implement
//! [`IncrementalToolCallParser`] directly and don't go through here.

use std::sync::Arc;

use serde_json::Value as JsonValue;

use super::event::{DecodeEvent, ParserError, StopReason};
use super::parser::{IncrementalToolCallParser, SentinelMatcher};
use super::tool_spec::ToolDirectory;

/// Per-engine cap on bytes buffered inside an open block. Same limit
/// every retrofitted protocol used independently — large enough for any
/// plausible structured call, small enough to bound a runaway generation.
pub const MAX_TOOL_CALL_PAYLOAD_BYTES: usize = 64 * 1024;

/// One candidate call extracted from a payload by a [`PayloadCodec`].
/// The engine still has to validate it against the bound directory.
#[derive(Debug, Clone)]
pub struct DecodedCall {
    pub name: String,
    pub args: JsonValue,
}

/// Result of parsing one payload. The codec is responsible for shape-
/// level errors (malformed JSON, missing `name`, bad XML); the engine
/// is responsible for directory lookup, schema validation, and the
/// poison transition.
#[derive(Debug)]
pub enum CodecOutcome {
    /// All candidates parsed cleanly. Engine then validates each.
    Calls(Vec<DecodedCall>),
    /// Codec parsed `calls` cleanly, then encountered a parse error
    /// that stops further progress. Engine validates the prefix, then
    /// — if validation didn't already terminate the parser — emits the
    /// codec's `error` as a fatal `ParseError`.
    PartialThenError {
        calls: Vec<DecodedCall>,
        error: ParserError,
    },
    /// Codec couldn't extract anything. Always fatal.
    Error(ParserError),
}

/// Bytes-between-sentinels → candidate call list. Codecs are stateless
/// and `Send`-able; one instance per engine.
pub trait PayloadCodec: Send {
    fn parse(&self, payload: &str) -> CodecOutcome;
}

/// How the wire frames each tool-call block.
#[derive(Debug, Clone, Copy)]
pub enum SentinelKind {
    /// `<open>...payload...<close>` — payload boundary is mid-stream.
    Pair {
        open: &'static str,
        close: &'static str,
    },
    /// `<open>...payload...EOS` — payload drains on `finish()`. No
    /// closing marker; everything after `open` belongs to the payload.
    Prefix { open: &'static str },
}

impl SentinelKind {
    fn open(&self) -> &'static str {
        match self {
            Self::Pair { open, .. } => open,
            Self::Prefix { open } => open,
        }
    }
    fn close(&self) -> Option<&'static str> {
        match self {
            Self::Pair { close, .. } => Some(close),
            Self::Prefix { .. } => None,
        }
    }
}

enum State {
    /// Watching for the opening sentinel.
    Outside { matcher: SentinelMatcher },
    /// Inside an open block. `close` is `Some` for Pair (still scanning
    /// for the close sentinel) and `None` for Prefix (draining at
    /// `finish()`).
    Inside {
        close: Option<SentinelMatcher>,
        payload: String,
    },
    /// A fatal error has been emitted; subsequent calls return empty.
    Terminated,
}

pub struct SentinelEngine {
    directory: Arc<ToolDirectory>,
    codec: Box<dyn PayloadCodec>,
    sentinel: SentinelKind,
    state: State,
    next_index: usize,
}

impl SentinelEngine {
    pub fn new(
        directory: Arc<ToolDirectory>,
        codec: Box<dyn PayloadCodec>,
        sentinel: SentinelKind,
    ) -> Self {
        let matcher = SentinelMatcher::new(sentinel.open());
        Self {
            directory,
            codec,
            sentinel,
            state: State::Outside { matcher },
            next_index: 0,
        }
    }

    /// Convenience: paired-sentinel engine. `open` and `close` are
    /// independent strings (Gemma-4's `<|tool_call>` / `<tool_call|>`
    /// pair is asymmetric and intentional).
    pub fn new_pair(
        directory: Arc<ToolDirectory>,
        codec: Box<dyn PayloadCodec>,
        open: &'static str,
        close: &'static str,
    ) -> Self {
        Self::new(directory, codec, SentinelKind::Pair { open, close })
    }

    /// Convenience: prefix-only-sentinel engine. Payload drains on
    /// `finish()` because the wire has no closing marker.
    pub fn new_prefix(
        directory: Arc<ToolDirectory>,
        codec: Box<dyn PayloadCodec>,
        open: &'static str,
    ) -> Self {
        Self::new(directory, codec, SentinelKind::Prefix { open })
    }

    /// Construct the post-fatal events: the supplied error event, then
    /// `Stop { ProtocolError }`. Transitions to `Terminated`.
    fn fatal(&mut self, error_event: DecodeEvent) -> Vec<DecodeEvent> {
        self.state = State::Terminated;
        vec![
            error_event,
            DecodeEvent::Stop {
                reason: StopReason::ProtocolError,
            },
        ]
    }

    /// Validate one batch of candidate calls. Each unvalidated call
    /// becomes a Start / ArgsDelta / End triple; the first lookup-miss
    /// or schema-failure terminates the engine and returns a partial
    /// event list ending with the appropriate fatal event + Stop.
    fn validate_and_emit(&mut self, calls: Vec<DecodedCall>) -> Vec<DecodeEvent> {
        let mut events = Vec::new();
        for call in calls {
            if self.directory.lookup(&call.name).is_none() {
                events.extend(self.fatal(DecodeEvent::UnknownTool {
                    name: call.name,
                    raw_args: call.args,
                }));
                return events;
            }
            let errors = self.directory.validate_args(&call.name, &call.args);
            if !errors.is_empty() {
                events.extend(self.fatal(DecodeEvent::InvalidArgs {
                    name: call.name,
                    args: call.args,
                    errors,
                }));
                return events;
            }
            let index = self.next_index;
            self.next_index += 1;
            let args_text = serde_json::to_string(&call.args).unwrap_or_else(|_| "{}".into());
            events.push(DecodeEvent::ToolCallStart {
                index,
                name: call.name.clone(),
            });
            events.push(DecodeEvent::ToolCallArgsDelta {
                index,
                delta: args_text,
            });
            events.push(DecodeEvent::ToolCallEnd {
                index,
                args: call.args,
            });
        }
        events
    }

    /// Drain a complete payload through the codec + validator. Called
    /// when a close sentinel commits (Pair) or at `finish()` (Prefix).
    fn drain_payload(&mut self, payload: String) -> Vec<DecodeEvent> {
        let outcome = self.codec.parse(&payload);
        let sentinel_label = self.sentinel.open();
        match outcome {
            CodecOutcome::Calls(calls) => self.validate_and_emit(calls),
            CodecOutcome::PartialThenError { calls, error } => {
                let mut events = self.validate_and_emit(calls);
                // If validation already terminated us, don't tack on
                // the codec's downstream error too — first-fatal wins.
                if !matches!(self.state, State::Terminated) {
                    events.extend(self.fatal(DecodeEvent::ParseError {
                        sentinel: sentinel_label,
                        source: error,
                    }));
                }
                events
            }
            CodecOutcome::Error(err) => self.fatal(DecodeEvent::ParseError {
                sentinel: sentinel_label,
                source: err,
            }),
        }
    }

    /// Push input into Inside state's payload buffer / close matcher,
    /// emit any completed-block events, and return what's left to be
    /// processed (the post-close-sentinel tail, if any).
    fn process_inside(&mut self, mut input: String, events: &mut Vec<DecodeEvent>) -> InsideStep {
        let State::Inside { close, payload } = &mut self.state else {
            return InsideStep::StateChanged(input);
        };
        match close {
            Some(close_matcher) => {
                close_matcher.push(&input);
                input.clear();
                if let Some((before, after)) = close_matcher.try_match() {
                    payload.push_str(&before);
                    if payload.len() > MAX_TOOL_CALL_PAYLOAD_BYTES {
                        events.extend(self.fatal(DecodeEvent::ParseError {
                            sentinel: self.sentinel.open(),
                            source: ParserError::PayloadTooLarge {
                                limit_bytes: MAX_TOOL_CALL_PAYLOAD_BYTES,
                            },
                        }));
                        return InsideStep::Done;
                    }
                    let payload_owned = std::mem::take(payload);
                    // Reset to Outside before draining so any
                    // fatal transition during drain leaves us
                    // Terminated, not Inside.
                    self.state = State::Outside {
                        matcher: SentinelMatcher::new(self.sentinel.open()),
                    };
                    events.extend(self.drain_payload(payload_owned));
                    if matches!(self.state, State::Terminated) {
                        return InsideStep::Done;
                    }
                    InsideStep::StateChanged(after)
                } else {
                    let safe = close_matcher.flush_safe_text();
                    payload.push_str(&safe);
                    if payload.len() > MAX_TOOL_CALL_PAYLOAD_BYTES {
                        events.extend(self.fatal(DecodeEvent::ParseError {
                            sentinel: self.sentinel.open(),
                            source: ParserError::PayloadTooLarge {
                                limit_bytes: MAX_TOOL_CALL_PAYLOAD_BYTES,
                            },
                        }));
                        return InsideStep::Done;
                    }
                    InsideStep::Done
                }
            }
            None => {
                payload.push_str(&input);
                input.clear();
                if payload.len() > MAX_TOOL_CALL_PAYLOAD_BYTES {
                    events.extend(self.fatal(DecodeEvent::ParseError {
                        sentinel: self.sentinel.open(),
                        source: ParserError::PayloadTooLarge {
                            limit_bytes: MAX_TOOL_CALL_PAYLOAD_BYTES,
                        },
                    }));
                    return InsideStep::Done;
                }
                InsideStep::Done
            }
        }
    }
}

/// Result of one Inside-state pump: either we've fully consumed input
/// (Done) or we transitioned back to Outside with `tail` left to feed.
enum InsideStep {
    Done,
    StateChanged(String),
}

impl IncrementalToolCallParser for SentinelEngine {
    fn feed(&mut self, text: &str) -> Vec<DecodeEvent> {
        if matches!(self.state, State::Terminated) {
            return Vec::new();
        }
        let mut events = Vec::new();
        let mut remaining = text.to_string();
        loop {
            match &mut self.state {
                State::Outside { matcher } => {
                    matcher.push(&remaining);
                    remaining.clear();
                    if let Some((before, after)) = matcher.try_match() {
                        if !before.is_empty() {
                            events.push(DecodeEvent::TextDelta(before));
                        }
                        // Transition to Inside with an empty buffer +
                        // a fresh close matcher (Pair only).
                        let close = self.sentinel.close().map(SentinelMatcher::new);
                        self.state = State::Inside {
                            close,
                            payload: String::new(),
                        };
                        // Eagerly process `after` — it might contain the
                        // close sentinel in the same feed.
                        match self.process_inside(after, &mut events) {
                            InsideStep::Done => return events,
                            InsideStep::StateChanged(tail) => {
                                remaining = tail;
                                continue;
                            }
                        }
                    } else {
                        let safe = matcher.flush_safe_text();
                        if !safe.is_empty() {
                            events.push(DecodeEvent::TextDelta(safe));
                        }
                        return events;
                    }
                }
                State::Inside { .. } => match self.process_inside(remaining, &mut events) {
                    InsideStep::Done => return events,
                    InsideStep::StateChanged(tail) => {
                        remaining = tail;
                        continue;
                    }
                },
                State::Terminated => return events,
            }
        }
    }

    fn finish(&mut self, reason: StopReason) -> Vec<DecodeEvent> {
        if matches!(self.state, State::Terminated) {
            return Vec::new();
        }
        let mut events = Vec::new();
        match &mut self.state {
            State::Outside { matcher } => {
                let leftover = matcher.finish();
                if !leftover.is_empty() {
                    events.push(DecodeEvent::TextDelta(leftover));
                }
                events.push(DecodeEvent::Stop { reason });
            }
            State::Inside { close, payload } => {
                let payload_owned = std::mem::take(payload);
                match close {
                    Some(_) => {
                        // Pair shape: open seen but close never arrived.
                        // Per protocol contract this is a fatal
                        // Unterminated error, not "drain whatever's
                        // there as a payload."
                        events.extend(self.fatal(DecodeEvent::ParseError {
                            sentinel: self.sentinel.open(),
                            source: ParserError::Unterminated,
                        }));
                    }
                    None => {
                        // Prefix shape: drain the buffered payload
                        // through the codec.
                        events.extend(self.drain_payload(payload_owned));
                        if !matches!(self.state, State::Terminated) {
                            events.push(DecodeEvent::Stop { reason });
                        }
                    }
                }
            }
            State::Terminated => unreachable!("checked above"),
        }
        events
    }
}
