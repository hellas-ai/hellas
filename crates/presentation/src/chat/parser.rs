// Adapted from catgrad-llm ac0e432 (MIT); model-independent chat parsing.
//! Streaming tool-call parser contract and shared helpers.
//!
//! Each model architecture that supports tool calling provides one
//! [`IncrementalToolCallParser`] implementation. The trait deliberately
//! exposes only `feed` and `finish` — the parser is the sole owner of
//! its state machine and of any held-back lookahead buffer.
//!
//! A trivial [`PassthroughParser`] handles the no-tools case so the
//! gateway loop has a uniform shape regardless of whether tools were
//! bound.

use super::event::{DecodeEvent, StopReason};

/// Streaming state machine that turns detokenized model output into
/// structured [`DecodeEvent`]s.
///
/// Implementations MUST hold partial sentinel matches in an internal
/// lookahead buffer rather than emitting them as `TextDelta` — see
/// [`SentinelMatcher`] for the standard helper. Once a chunk is
/// disambiguated as plain text, emit `TextDelta`; once a sentinel
/// commits, emit the corresponding `ToolCall*` events.
pub trait IncrementalToolCallParser: Send {
    /// Consume a chunk of detokenized text and return any events that
    /// became available.
    fn feed(&mut self, text: &str) -> Vec<DecodeEvent>;

    /// The model has stopped producing tokens. Flush any held lookahead
    /// (typically as a final `TextDelta`) and emit a terminal
    /// [`DecodeEvent::Stop`].
    fn finish(&mut self, reason: StopReason) -> Vec<DecodeEvent>;
}

/// Pass plain text through when no tools were offered.
pub struct PassthroughParser;

impl IncrementalToolCallParser for PassthroughParser {
    fn feed(&mut self, text: &str) -> Vec<DecodeEvent> {
        if text.is_empty() {
            Vec::new()
        } else {
            vec![DecodeEvent::TextDelta(text.to_string())]
        }
    }

    fn finish(&mut self, reason: StopReason) -> Vec<DecodeEvent> {
        vec![DecodeEvent::Stop { reason }]
    }
}

/// Streaming-safe matcher for a single literal sentinel string.
///
/// The matcher buffers incoming text and exposes two operations:
///
/// - [`Self::try_match`] — advance the buffer past the first occurrence
///   of the sentinel if present, returning the text that preceded it.
/// - [`Self::flush_safe_text`] — return the longest prefix of the buffer
///   that cannot possibly extend into a sentinel match, leaving any
///   ambiguous tail in the buffer for the next feed.
///
/// The held-back tail is bounded by `sentinel.len() - 1` bytes, so
/// memory is constant per matcher.
///
/// UTF-8 safety: prefix-emit boundaries always land on character
/// boundaries. For ASCII sentinels (the common case), this is automatic
/// because any sentinel-prefix tail is itself ASCII; for sentinels that
/// contain multi-byte characters, the matcher walks the buffer to a
/// safe character boundary before emitting.
pub struct SentinelMatcher {
    sentinel: &'static str,
    buffer: String,
}

impl SentinelMatcher {
    pub fn new(sentinel: &'static str) -> Self {
        Self {
            sentinel,
            buffer: String::new(),
        }
    }

    pub fn push(&mut self, chunk: &str) {
        self.buffer.push_str(chunk);
    }

    /// If the sentinel appears in the buffer, splits the buffer at the
    /// match and returns `(text_before, text_after_sentinel)`. The
    /// matcher's internal buffer is cleared.
    pub fn try_match(&mut self) -> Option<(String, String)> {
        let pos = self.buffer.find(self.sentinel)?;
        let before = self.buffer[..pos].to_string();
        let after = self.buffer[pos + self.sentinel.len()..].to_string();
        self.buffer.clear();
        Some((before, after))
    }

    /// Drain and return all text that cannot become part of a sentinel
    /// match. The remaining buffer holds at most `sentinel.len() - 1`
    /// bytes — the longest prefix of the sentinel that the buffer's
    /// suffix could still grow into.
    pub fn flush_safe_text(&mut self) -> String {
        let safe_end = safe_emit_boundary(&self.buffer, self.sentinel);
        self.buffer.drain(..safe_end).collect()
    }

    /// Drain everything in the buffer (used on stream close).
    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.buffer)
    }
}

/// Largest byte index `i ≤ buf.len()` such that `buf[..i]` is safe to
/// emit (i.e. cannot be the start of a future sentinel match) and is on
/// a UTF-8 character boundary.
fn safe_emit_boundary(buf: &str, sentinel: &str) -> usize {
    if buf.is_empty() {
        return 0;
    }
    let max_take = buf.len().min(sentinel.len().saturating_sub(1));
    for take in (1..=max_take).rev() {
        let cut = buf.len() - take;
        if !buf.is_char_boundary(cut) {
            continue;
        }
        if sentinel.starts_with(&buf[cut..]) {
            return cut;
        }
    }
    buf.len()
}
