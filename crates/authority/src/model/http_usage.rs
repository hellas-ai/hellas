//! Bounded extraction shared by telemetry and quota settlement. Parsing never
//! changes forwarded bytes. Strict accounting requires a complete profile;
//! telemetry keeps cumulative maxima from partial, imperfect vendor streams.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{self, Write},
    sync::Arc,
};

pub const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;
const MAX_PENDING_BYTES: usize = 512 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountingProfile {
    None,
    OpenaiChat,
    OpenaiResponses,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Telemetry,
    Strict(AccountingProfile),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsageFault {
    #[error("usage is missing or incomplete")]
    Missing,
    #[error("usage is malformed")]
    Malformed,
    #[error("usage decode bound exceeded")]
    Bounds,
    #[error("unsupported content encoding")]
    Encoding,
    #[error("invalid compressed response")]
    Compression,
}
type Observer = Arc<dyn Fn(&Value) + Send + Sync>;
#[derive(Default)]
pub struct Usage {
    pub sse: bool,
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cached: Option<u64>,
    pub cache_write: Option<u64>,
    pub overflow: bool,
    mode: Mode,
    pending: Vec<u8>,
    frame: Vec<u8>,
    decoded_bytes: usize,
    usage_chunks: usize,
    sentinel: bool,
    finished: bool,
    fault: Option<UsageFault>,
    observer: Option<Observer>,
}
impl Usage {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            ..Default::default()
        }
    }
    pub fn observe(&mut self, observer: Option<Observer>) {
        self.observer = observer;
    }
    fn fail(&mut self, fault: UsageFault) {
        self.fault.get_or_insert(fault);
        self.overflow |= fault == UsageFault::Bounds;
        self.input = None;
        self.output = None;
        self.cached = None;
        self.cache_write = None;
        self.pending.clear();
        self.frame.clear();
    }
    pub fn push(&mut self, bytes: &[u8]) {
        if self.fault.is_some() {
            return;
        }
        if self.finished {
            self.fail(UsageFault::Malformed);
            return;
        }
        self.decoded_bytes = self.decoded_bytes.saturating_add(bytes.len());
        if self.decoded_bytes > MAX_DECODED_BYTES {
            self.fail(UsageFault::Bounds);
            return;
        }
        // Append in bounded pieces: a single hostile chunk must not transiently
        // allocate a second unbounded pending buffer before its limit is checked.
        for part in bytes.chunks(16 * 1024) {
            self.pending.extend_from_slice(part);
            self.sse |= self.pending.starts_with(b"event:")
                || self.pending.starts_with(b"data:")
                || self.pending.starts_with(b":");
            while self.sse {
                let Some(end) = self.pending.iter().position(|b| *b == b'\n') else {
                    break;
                };
                let line: Vec<_> = self.pending.drain(..=end).collect();
                let line = line.strip_suffix(b"\n").unwrap_or(&line);
                self.line(line.strip_suffix(b"\r").unwrap_or(line));
                if self.fault.is_some() {
                    return;
                }
            }
            // JSON responses can use the full decode allowance; only an SSE
            // line/frame has the stricter 512 KiB bound.
            if self.sse
                && (self.pending.len() > MAX_PENDING_BYTES || self.frame.len() > MAX_PENDING_BYTES)
            {
                self.fail(UsageFault::Bounds);
                return;
            }
        }
    }
    fn line(&mut self, line: &[u8]) {
        if line.is_empty() {
            if !self.frame.is_empty() {
                let data = std::mem::take(&mut self.frame);
                self.parse(&data);
            }
        } else if let Some(data) = line.strip_prefix(b"data:") {
            if !self.frame.is_empty() {
                self.frame.push(b'\n');
            }
            self.frame
                .extend_from_slice(data.strip_prefix(b" ").unwrap_or(data));
        } else if !line.starts_with(b"event:")
            && !line.starts_with(b":")
            && matches!(self.mode, Mode::Strict(_))
        {
            self.fail(UsageFault::Malformed);
        }
    }
    pub fn finish(&mut self) {
        if self.finished {
            return;
        }
        if self.fault.is_none() {
            let pending = std::mem::take(&mut self.pending);
            if self.sse {
                // Accept the final data frame without a trailing empty line,
                // but never infer a missing profile sentinel from EOF.
                if !pending.is_empty() {
                    self.line(pending.strip_suffix(b"\r").unwrap_or(&pending));
                }
                self.line(b"");
            } else {
                self.parse(&pending);
            }
        }
        self.finished = true;
    }
    pub fn strict_usage(&self) -> Result<(u64, u64), UsageFault> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if !self.finished || self.usage_chunks != 1 || (self.sse && !self.sentinel) {
            return Err(UsageFault::Missing);
        }
        Ok((
            self.input.ok_or(UsageFault::Missing)?,
            self.output.ok_or(UsageFault::Missing)?,
        ))
    }
    fn parse(&mut self, bytes: &[u8]) {
        let strict = matches!(self.mode, Mode::Strict(_));
        let bytes = bytes.trim_ascii();
        if bytes == b"[DONE]" {
            if matches!(
                self.mode,
                Mode::Strict(AccountingProfile::OpenaiResponses | AccountingProfile::None)
            ) {
                self.fail(UsageFault::Malformed);
                return;
            }
            if self.sentinel && strict {
                self.fail(UsageFault::Malformed);
            }
            self.sentinel = true;
            return;
        }
        if self.sentinel && strict {
            self.fail(UsageFault::Malformed);
            return;
        }
        let value = if strict {
            unique_json(bytes)
        } else {
            serde_json::from_slice::<Value>(bytes)
        };
        let Ok(value) = value else {
            if strict {
                self.fail(UsageFault::Malformed);
            }
            return;
        };
        if !value.is_object() {
            if strict {
                self.fail(UsageFault::Malformed);
            }
            return;
        }
        if let Some(observer) = &self.observer {
            observer(&value);
        }
        let usage = match self.mode {
            Mode::Telemetry => value
                .get("usage")
                .or_else(|| value.pointer("/message/usage"))
                .or_else(|| value.pointer("/response/usage")),
            Mode::Strict(AccountingProfile::OpenaiChat) => value.get("usage"),
            Mode::Strict(AccountingProfile::OpenaiResponses) => {
                if self.sse {
                    if matches!(
                        value.get("type").and_then(Value::as_str),
                        Some("response.completed" | "response.incomplete" | "response.failed")
                    ) {
                        self.sentinel = true;
                    }
                    value.pointer("/response/usage")
                } else {
                    value.get("usage")
                }
            }
            Mode::Strict(AccountingProfile::None) => None,
        };
        let Some(usage) = usage.filter(|u| !u.is_null()) else {
            return;
        };
        if !usage.is_object() {
            if strict {
                self.fail(UsageFault::Malformed);
            }
            return;
        }
        self.usage_chunks += 1;
        if strict && self.usage_chunks > 1 {
            self.fail(UsageFault::Malformed);
            return;
        }
        let (input, output) = match self.mode {
            Mode::Strict(AccountingProfile::OpenaiChat) => {
                (usage.get("prompt_tokens"), usage.get("completion_tokens"))
            }
            Mode::Strict(AccountingProfile::OpenaiResponses) => {
                (usage.get("input_tokens"), usage.get("output_tokens"))
            }
            _ => (
                usage
                    .get("prompt_tokens")
                    .or_else(|| usage.get("input_tokens")),
                usage
                    .get("completion_tokens")
                    .or_else(|| usage.get("output_tokens")),
            ),
        };
        let values = [
            input,
            output,
            usage
                .get("cache_read_input_tokens")
                .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
                .or_else(|| usage.pointer("/input_tokens_details/cached_tokens")),
            usage
                .get("cache_creation_input_tokens")
                .or_else(|| usage.pointer("/input_tokens_details/cache_write_tokens"))
                .or_else(|| usage.pointer("/prompt_tokens_details/cache_write_tokens")),
        ];
        let mut bad = false;
        for (target, value) in [
            &mut self.input,
            &mut self.output,
            &mut self.cached,
            &mut self.cache_write,
        ]
        .into_iter()
        .zip(values)
        {
            if let Some(value) = value {
                if let Some(n) = value.as_u64() {
                    bad |= strict && target.is_some_and(|held| n < held);
                    *target = Some(target.unwrap_or_default().max(n));
                } else {
                    bad |= strict;
                }
            }
        }
        if strict && (values[0].is_none() || values[1].is_none()) {
            bad = true;
        }
        if bad {
            self.fail(UsageFault::Malformed);
        }
    }
}
impl Write for Usage {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.push(bytes);
        if self.fault.is_some() {
            Err(io::Error::other("usage decode failed"))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Every decompressor writes through the same bounded parser, so compressed
/// output cannot bypass the decoded-byte or SSE-frame allowance.
pub enum UsageDecoder {
    Identity(Usage),
    Gzip(flate2::write::GzDecoder<Usage>),
    Deflate(flate2::write::ZlibDecoder<Usage>),
    Brotli(Box<brotli::DecompressorWriter<Usage>>),
}
impl Default for UsageDecoder {
    fn default() -> Self {
        Self::Identity(Usage::default())
    }
}
impl std::ops::Deref for UsageDecoder {
    type Target = Usage;
    fn deref(&self) -> &Usage {
        match self {
            Self::Identity(u) => u,
            Self::Gzip(d) => d.get_ref(),
            Self::Deflate(d) => d.get_ref(),
            Self::Brotli(d) => d.get_ref(),
        }
    }
}
impl UsageDecoder {
    pub fn new(mode: Mode, content_type: Option<&str>, encoding: Option<&str>) -> Self {
        let mut usage = Usage::new(mode);
        usage.sse = content_type.is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
        });
        Self::wrap(usage, encoding)
    }
    fn wrap(mut usage: Usage, encoding: Option<&str>) -> Self {
        match encoding
            .unwrap_or("identity")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "" | "identity" => Self::Identity(usage),
            "gzip" => Self::Gzip(flate2::write::GzDecoder::new(usage)),
            "deflate" => Self::Deflate(flate2::write::ZlibDecoder::new(usage)),
            "br" => Self::Brotli(Box::new(brotli::DecompressorWriter::new(usage, 4096))),
            _ => {
                usage.fail(UsageFault::Encoding);
                Self::Identity(usage)
            }
        }
    }
    pub fn observe(&mut self, observer: Option<Observer>) {
        match self {
            Self::Identity(u) => u.observe(observer),
            Self::Gzip(d) => d.get_mut().observe(observer),
            Self::Deflate(d) => d.get_mut().observe(observer),
            Self::Brotli(d) => d.get_mut().observe(observer),
        }
    }
    pub fn content(&mut self, value: Option<&str>, encoding: Option<&str>) {
        let Self::Identity(mut usage) = std::mem::take(self) else {
            let mut usage = Usage::default();
            usage.fail(UsageFault::Malformed);
            *self = Self::Identity(usage);
            return;
        };
        usage.sse = value.is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
        });
        *self = Self::wrap(usage, encoding);
    }
    pub fn push(&mut self, bytes: &[u8]) {
        if self.fault.is_some() {
            return;
        }
        let result = match self {
            Self::Identity(u) => u.write_all(bytes),
            Self::Gzip(d) => d.write_all(bytes),
            Self::Deflate(d) => d.write_all(bytes),
            Self::Brotli(d) => d.write_all(bytes),
        };
        if result.is_err() {
            self.invalidate(UsageFault::Compression);
        }
    }
    fn invalidate(&mut self, fault: UsageFault) {
        // Do not attempt to finish a malformed compression stream. Preserve a
        // prior bounds failure rather than downgrading it to malformed usage.
        let fault = self.fault.unwrap_or(fault);
        let mut usage = Usage::default();
        usage.fail(fault);
        *self = Self::Identity(usage);
    }
    pub fn finish(&mut self) {
        let mut usage = match std::mem::take(self) {
            Self::Identity(u) => u,
            Self::Gzip(mut d) => {
                if d.try_finish().is_err() {
                    failed(d.get_ref().fault.unwrap_or(UsageFault::Compression))
                } else {
                    d.finish()
                        .unwrap_or_else(|_| failed(UsageFault::Compression))
                }
            }
            Self::Deflate(mut d) => {
                if d.try_finish().is_err() {
                    failed(d.get_ref().fault.unwrap_or(UsageFault::Compression))
                } else {
                    d.finish()
                        .unwrap_or_else(|_| failed(UsageFault::Compression))
                }
            }
            Self::Brotli(d) => d.into_inner().unwrap_or_else(|mut u| {
                u.fail(UsageFault::Compression);
                u
            }),
        };
        usage.finish();
        *self = Self::Identity(usage);
    }
}

pub(crate) fn unique_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice::<UniqueValue>(bytes).map(|v| v.0)
}

// serde_json normally keeps the last duplicate object field. Strict accounting
// rejects that ambiguity before any usage field can be interpreted.
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::from(v)))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = vec![];
                while let Some(v) = seq.next_element::<UniqueValue>()? {
                    out.push(v.0);
                }
                Ok(UniqueValue(Value::Array(out)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if out.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueValue(Value::Object(out)))
            }
        }
        d.deserialize_any(Visitor)
    }
}

fn failed(fault: UsageFault) -> Usage {
    let mut usage = Usage::default();
    usage.fail(fault);
    usage
}
