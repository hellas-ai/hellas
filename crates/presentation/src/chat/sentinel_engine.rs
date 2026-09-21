// Adapted from catgrad-llm ac0e432 (MIT).
//! Paired-sentinel parsing shared by Qwen3 JSON and Qwen3.5 XML tool calls.
//! A complete call is validated before any of its events leave the parser.

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

enum State {
    /// Watching for the opening sentinel.
    Outside { matcher: SentinelMatcher },
    /// Buffer a call until its closing sentinel arrives.
    Inside {
        close: SentinelMatcher,
        payload: String,
    },
    /// A fatal error has been emitted; subsequent calls return empty.
    Terminated,
}

pub struct SentinelEngine {
    directory: Arc<ToolDirectory>,
    codec: Box<dyn PayloadCodec>,
    open: &'static str,
    close: &'static str,
    state: State,
    next_index: usize,
}

impl SentinelEngine {
    pub fn new_pair(
        directory: Arc<ToolDirectory>,
        codec: Box<dyn PayloadCodec>,
        open: &'static str,
        close: &'static str,
    ) -> Self {
        Self {
            directory,
            codec,
            open,
            close,
            state: State::Outside {
                matcher: SentinelMatcher::new(open),
            },
            next_index: 0,
        }
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
                events.extend(self.fatal(DecodeEvent::UnknownTool { name: call.name }));
                return events;
            }
            let errors = self.directory.validate_args(&call.name, &call.args);
            if !errors.is_empty() {
                events.extend(self.fatal(DecodeEvent::InvalidArgs {
                    name: call.name,
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

    /// Decode and validate a complete payload.
    fn drain_payload(&mut self, payload: String) -> Vec<DecodeEvent> {
        let outcome = self.codec.parse(&payload);
        let sentinel_label = self.open;
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
        close.push(&input);
        input.clear();
        if let Some((before, after)) = close.try_match() {
            payload.push_str(&before);
            if payload.len() > MAX_TOOL_CALL_PAYLOAD_BYTES {
                events.extend(self.fatal(DecodeEvent::ParseError {
                    sentinel: self.open,
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
                matcher: SentinelMatcher::new(self.open),
            };
            events.extend(self.drain_payload(payload_owned));
            if matches!(self.state, State::Terminated) {
                return InsideStep::Done;
            }
            InsideStep::StateChanged(after)
        } else {
            let safe = close.flush_safe_text();
            payload.push_str(&safe);
            if payload.len() > MAX_TOOL_CALL_PAYLOAD_BYTES {
                events.extend(self.fatal(DecodeEvent::ParseError {
                    sentinel: self.open,
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
                        // a fresh close matcher.
                        let close = SentinelMatcher::new(self.close);
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
            State::Inside { .. } => {
                events.extend(self.fatal(DecodeEvent::ParseError {
                    sentinel: self.open,
                    source: ParserError::Unterminated,
                }));
            }
            State::Terminated => unreachable!("checked above"),
        }
        events
    }
}
