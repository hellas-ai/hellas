use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{AdaptorError, AdaptorResult};

pub type WireHeaders = BTreeMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderContext {
    pub response_id: String,
    pub message_id: String,
    pub created_at: i64,
}

impl RenderContext {
    pub fn new(
        response_id: impl Into<String>,
        message_id: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            response_id: response_id.into(),
            message_id: message_id.into(),
            created_at,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireResponse {
    pub status: u16,
    pub headers: WireHeaders,
    pub body: WireBody,
}

impl WireResponse {
    pub fn json(status: u16, body: JsonValue) -> Self {
        let mut headers = WireHeaders::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        Self {
            status,
            headers,
            body: WireBody::Json(body),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WireBody {
    Json(JsonValue),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WireStreamEvent {
    pub name: Option<String>,
    pub data: WireEventData,
}

impl WireStreamEvent {
    pub fn json(name: impl Into<Option<String>>, data: JsonValue) -> Self {
        Self {
            name: name.into(),
            data: WireEventData::Json(data),
        }
    }

    pub fn text(name: impl Into<Option<String>>, data: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: WireEventData::Text(data.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum WireEventData {
    Json(JsonValue),
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    scanned: usize,
    received_bytes: usize,
    frames: u64,
    events: u64,
    ignored_lines: u64,
    noncanonical_lines: u64,
}

/// Maximum raw bytes in a complete SSE response accepted by the built-in
/// Fetch HTTP drivers.
///
/// This is part of the built-in Fetch driver contract: changing it requires a
/// new driver identity in the Fetch environment manifest.
pub const MAX_SSE_RESPONSE_BYTES: usize = 3 * 1024 * 1024;

const MAX_SSE_DELIMITER_BYTES: usize = 4;

/// Maximum raw bytes in one SSE frame, excluding its blank-line delimiter.
///
/// Responses lifecycle terminals may repeat the complete generated output in
/// one frame. Reserving only the longest delimiter keeps a complete maximum
/// frame inside the response-wide byte bound. The semantic projector still
/// applies Hellas's smaller signed-payload bound.
pub const MAX_SSE_FRAME_BYTES: usize = MAX_SSE_RESPONSE_BYTES - MAX_SSE_DELIMITER_BYTES;

/// Maximum semantic data events in one SSE response. Comment keepalives and
/// empty frames do not consume this budget; the response-wide byte ceiling
/// bounds those raw frames instead. This is deliberately above the number of
/// ordinary provider events that can fit in the byte ceiling while retaining
/// a separate allocation/dispatch guard for unusually tiny data events.
pub const MAX_SSE_EVENTS: u64 = 65_536;

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of raw SSE frames consumed, including comment-only frames.
    /// Strict adaptors use this to reject semantically invisible framing.
    pub const fn frame_count(&self) -> u64 {
        self.frames
    }

    /// Number of comment, unknown, malformed, or duplicate `event` lines
    /// discarded while applying ordinary SSE semantics. Sealed adaptors use
    /// this to require a closed framing grammar without changing permissive
    /// presentation adaptors.
    pub const fn ignored_line_count(&self) -> u64 {
        self.ignored_lines
    }

    /// Number of lines which are meaningful under the permissive SSE grammar
    /// but not in the sealed one-event/one-data framing used by strict
    /// adaptors. Presentation adaptors retain ordinary SSE compatibility;
    /// sealed adaptors reject this counter instead of accepting and silently
    /// normalizing an alternative wire representation.
    pub const fn noncanonical_line_count(&self) -> u64 {
        self.noncanonical_lines
    }

    /// Bytes retained after the last complete frame delimiter.
    pub fn pending_bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub fn push(&mut self, mut bytes: &[u8]) -> AdaptorResult<Vec<WireStreamEvent>> {
        self.received_bytes = self
            .received_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= MAX_SSE_RESPONSE_BYTES)
            .ok_or_else(sse_response_limit_error)?;
        let mut events = Vec::new();

        while !bytes.is_empty() {
            let buffer_limit = MAX_SSE_FRAME_BYTES
                .checked_add(MAX_SSE_DELIMITER_BYTES)
                .expect("SSE buffer limit fits usize");
            let available = buffer_limit
                .checked_sub(self.buffer.len())
                .ok_or_else(sse_frame_limit_error)?;
            if available == 0 {
                return Err(sse_frame_limit_error());
            }

            let appended = available.min(bytes.len());
            let buffered = self
                .buffer
                .len()
                .checked_add(appended)
                .ok_or_else(sse_frame_limit_error)?;
            if buffered > buffer_limit {
                return Err(sse_frame_limit_error());
            }
            if buffered > self.buffer.capacity() {
                let capacity = self
                    .buffer
                    .capacity()
                    .saturating_mul(2)
                    .max(buffered)
                    .min(buffer_limit);
                self.buffer
                    .try_reserve_exact(capacity - self.buffer.len())
                    .map_err(|_| {
                        AdaptorError::invalid_response("SSE frame buffer allocation failed")
                    })?;
            }
            self.buffer.extend_from_slice(&bytes[..appended]);
            bytes = &bytes[appended..];

            self.drain_complete_frames(&mut events)?;
            self.ensure_pending_frame_within_limit()?;
        }

        Ok(events)
    }

    pub fn finish(&mut self) -> AdaptorResult<Vec<WireStreamEvent>> {
        self.scanned = 0;
        if self.buffer.len() > MAX_SSE_FRAME_BYTES {
            return Err(sse_frame_limit_error());
        }
        if self.buffer.iter().all(u8::is_ascii_whitespace) {
            self.buffer.clear();
            return Ok(Vec::new());
        }
        self.record_frame()?;
        let frame = std::mem::take(&mut self.buffer);
        let (event, ignored_lines, noncanonical_lines) = parse_sse_frame(&frame)?;
        self.ignored_lines = self.ignored_lines.saturating_add(ignored_lines);
        self.noncanonical_lines = self.noncanonical_lines.saturating_add(noncanonical_lines);
        if event.is_some() {
            self.record_event()?;
        }
        Ok(event.into_iter().collect())
    }

    fn drain_complete_frames(&mut self, events: &mut Vec<WireStreamEvent>) -> AdaptorResult<()> {
        let mut consumed = 0;
        let mut scan = self.scanned;
        while let Some((offset, delimiter_len)) = find_sse_delimiter(&self.buffer[scan..]) {
            let frame_end = scan + offset;
            if frame_end - consumed > MAX_SSE_FRAME_BYTES {
                return Err(sse_frame_limit_error());
            }
            self.record_frame()?;
            let (event, ignored_lines, noncanonical_lines) =
                parse_sse_frame(&self.buffer[consumed..frame_end])?;
            self.ignored_lines = self.ignored_lines.saturating_add(ignored_lines);
            self.noncanonical_lines = self.noncanonical_lines.saturating_add(noncanonical_lines);
            if let Some(event) = event {
                self.record_event()?;
                events.push(event);
            }
            consumed = frame_end + delimiter_len;
            scan = consumed;
        }
        // A delimiter may straddle the next push. Revisit only its possible
        // three-byte prefix, never the already scanned frame contents.
        self.scanned = self
            .buffer
            .len()
            .saturating_sub(MAX_SSE_DELIMITER_BYTES - 1)
            .max(consumed)
            - consumed;
        self.buffer.drain(..consumed);
        Ok(())
    }

    fn record_frame(&mut self) -> AdaptorResult<()> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or_else(|| AdaptorError::invalid_response("SSE raw frame count overflowed"))?;
        Ok(())
    }

    fn record_event(&mut self) -> AdaptorResult<()> {
        let events = self
            .events
            .checked_add(1)
            .ok_or_else(sse_event_count_limit_error)?;
        if events > MAX_SSE_EVENTS {
            return Err(sse_event_count_limit_error());
        }
        self.events = events;
        Ok(())
    }

    fn ensure_pending_frame_within_limit(&self) -> AdaptorResult<()> {
        if self.buffer.len() <= MAX_SSE_FRAME_BYTES
            || has_incomplete_delimiter_at_frame_limit(&self.buffer)
        {
            return Ok(());
        }
        Err(sse_frame_limit_error())
    }
}

fn has_incomplete_delimiter_at_frame_limit(buffer: &[u8]) -> bool {
    [b"\n\n".as_slice(), b"\r\n\r\n".as_slice()]
        .into_iter()
        .any(|delimiter| {
            (1..delimiter.len()).any(|prefix_len| {
                buffer.len().checked_sub(prefix_len).is_some_and(|start| {
                    start <= MAX_SSE_FRAME_BYTES && buffer[start..] == delimiter[..prefix_len]
                })
            })
        })
}

fn sse_frame_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE frame exceeds the {MAX_SSE_FRAME_BYTES}-byte limit"
    ))
}

fn sse_response_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE response exceeds the {MAX_SSE_RESPONSE_BYTES}-byte limit"
    ))
}

fn sse_event_count_limit_error() -> AdaptorError {
    AdaptorError::invalid_response(format!(
        "SSE response exceeds the {MAX_SSE_EVENTS}-event limit"
    ))
}

fn find_sse_delimiter(buffer: &[u8]) -> Option<(usize, usize)> {
    for index in 0..buffer.len().saturating_sub(1) {
        if buffer[index..].starts_with(b"\n\n") {
            return Some((index, 2));
        }
        if buffer[index..].starts_with(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

fn parse_sse_frame(frame: &[u8]) -> AdaptorResult<(Option<WireStreamEvent>, u64, u64)> {
    let text = std::str::from_utf8(frame).map_err(|source| {
        AdaptorError::invalid_response(format!("invalid UTF-8 in SSE stream: {source}"))
    })?;
    let mut name = None;
    let mut data = Vec::new();
    let mut ignored_lines = 0_u64;
    let mut noncanonical_lines = 0_u64;

    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            noncanonical_lines = noncanonical_lines.saturating_add(1);
            continue;
        }
        if line.starts_with(':') {
            ignored_lines = ignored_lines.saturating_add(1);
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            ignored_lines = ignored_lines.saturating_add(1);
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if name.is_none() => {
                if !data.is_empty() {
                    noncanonical_lines = noncanonical_lines.saturating_add(1);
                }
                name = Some(value.to_string());
            }
            "data" => {
                if name.is_none() || !data.is_empty() {
                    noncanonical_lines = noncanonical_lines.saturating_add(1);
                }
                data.push(value.to_string());
            }
            _ => ignored_lines = ignored_lines.saturating_add(1),
        }
    }

    if data.is_empty() {
        return Ok((None, ignored_lines, noncanonical_lines));
    }
    Ok((
        Some(WireStreamEvent::text(name, data.join("\n"))),
        ignored_lines,
        noncanonical_lines,
    ))
}

#[cfg(test)]
mod tests;
