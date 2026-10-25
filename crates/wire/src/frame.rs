//! Frame format. One `Frame` type, two wire wrappers (mux prepends
//! stream_key + gen; iroh omits both).

use bytes::Bytes;

use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

#[derive(Clone, Debug)]
pub enum Frame {
    Open(OpenFrame),
    Body(Bytes),
    End(EndFrame),
    Reset(ResetFrame),
    Credit(CreditFrame),
}

#[derive(Clone, Debug)]
pub struct OpenFrame {
    pub method_id: u32,
    pub headers: Metadata,
}

#[derive(Clone, Debug)]
pub struct EndFrame {
    pub status: WireCode,
    pub trailer: Trailer,
}

#[derive(Clone, Copy, Debug)]
pub struct ResetFrame {
    pub code: WireCode,
}

#[derive(Clone, Copy, Debug)]
pub struct CreditFrame {
    pub additional_bytes: u32,
}

// -- Frame discriminator -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Open = 0,
    Body = 1,
    End = 2,
    Reset = 3,
    Credit = 4,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Open),
            1 => Some(Self::Body),
            2 => Some(Self::End),
            3 => Some(Self::Reset),
            4 => Some(Self::Credit),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Frame {
    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Open(_) => FrameKind::Open,
            Self::Body(_) => FrameKind::Body,
            Self::End(_) => FrameKind::End,
            Self::Reset(_) => FrameKind::Reset,
            Self::Credit(_) => FrameKind::Credit,
        }
    }
}

// -- Decode error ------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short: need {needed} bytes, got {got}")]
    Short { needed: usize, got: usize },
    #[error("unknown frame kind: {0}")]
    UnknownKind(u8),
    #[error("unknown wire code: {0}")]
    UnknownCode(u8),
    #[error("frame body exceeds limit: {len} > {limit}")]
    BodyTooLarge { len: usize, limit: usize },
    #[error("metadata key not utf-8")]
    BadKeyUtf8,
    #[error("metadata value not utf-8")]
    BadValueUtf8,
    #[error("unknown metadata value tag: {0}")]
    UnknownMetadataTag(u8),
    #[error("invalid varint encoding")]
    BadVarint,
    #[error("frame has {remaining} trailing bytes")]
    TrailingBytes { remaining: usize },
    #[error("frame length {len} exceeds wire cap {cap}")]
    OversizedFrame { len: usize, cap: usize },
}

// -- Wire codec --------------------------------------------------------------
//
// Self-describing frame body layout per kind:
//
//   Open:   [method_id: u32 LE] [metadata]
//   Body:   [payload bytes (rest)]
//   End:    [status: u8] [message_len: varint] [message_bytes] [metadata]
//   Reset:  [code: u8]
//   Credit: [additional_bytes: u32 LE]
//
// Metadata layout:
//   [count: varint]
//   for each entry:
//     [key_len: varint] [key_utf8]
//     [tag: u8]  // 0 = text, 1 = bytes
//     [value_len: varint]
//     [value_bytes]
//
// Frame on the wire is `[kind: u8] [body...]`. Mux transports prepend
// `[stream_id: u16 BE] [gen: u16 BE] [length: varint]` outside this.

pub fn encode_body_bytes(payload: Bytes) -> Bytes {
    // Body's body is just the payload — kind byte + payload bytes. Caller
    // is expected to prepend the kind byte. We expose this helper for
    // zero-copy assembly at the transport layer; see encode_frame for
    // the general case.
    payload
}

pub fn encode_frame(frame: &Frame, out: &mut bytes::BytesMut) {
    out.extend_from_slice(&[frame.kind().as_u8()]);
    match frame {
        Frame::Open(open) => {
            out.extend_from_slice(&open.method_id.to_le_bytes());
            encode_metadata(&open.headers, out);
        }
        Frame::Body(payload) => {
            out.extend_from_slice(payload);
        }
        Frame::End(end) => {
            out.extend_from_slice(&[end.trailer.status.as_u8()]);
            write_varint(end.trailer.message.len() as u64, out);
            out.extend_from_slice(end.trailer.message.as_bytes());
            encode_metadata(&end.trailer.metadata, out);
            let _ = end.status; // EndFrame.status is redundant with trailer.status;
        }
        Frame::Reset(r) => {
            out.extend_from_slice(&[r.code.as_u8()]);
        }
        Frame::Credit(c) => {
            out.extend_from_slice(&c.additional_bytes.to_le_bytes());
        }
    }
}

/// Compute and validate the exact encoded size before an iroh sender allocates
/// its framing buffer. This mirrors [`encode_frame`] and applies the same
/// metadata and whole-frame bounds the decoder enforces.
#[cfg(any(feature = "iroh", test))]
pub(crate) fn encoded_frame_len(frame: &Frame) -> Result<usize, FrameError> {
    let body_len = match frame {
        Frame::Open(open) => checked_encoded_add(4, encoded_metadata_len(&open.headers)?)?,
        Frame::Body(payload) => payload.len(),
        Frame::End(end) => {
            let message_len = end.trailer.message.len();
            let len = checked_encoded_add(1, encoded_varint_len(message_len))?;
            let len = checked_encoded_add(len, message_len)?;
            checked_encoded_add(len, encoded_metadata_len(&end.trailer.metadata)?)?
        }
        Frame::Reset(_) => 1,
        Frame::Credit(_) => 4,
    };
    let len = checked_encoded_add(1, body_len)?;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::OversizedFrame {
            len,
            cap: MAX_FRAME_BYTES,
        });
    }
    Ok(len)
}

#[cfg(any(feature = "iroh", test))]
fn encoded_metadata_len(metadata: &Metadata) -> Result<usize, FrameError> {
    if metadata.len() > METADATA_MAX_ENTRIES as usize {
        return Err(FrameError::BodyTooLarge {
            len: metadata.len(),
            limit: METADATA_MAX_ENTRIES as usize,
        });
    }
    let mut len = encoded_varint_len(metadata.len());
    for (key, value) in metadata.iter() {
        if key.len() > METADATA_MAX_FIELD_LEN {
            return Err(FrameError::BodyTooLarge {
                len: key.len(),
                limit: METADATA_MAX_FIELD_LEN,
            });
        }
        let value_len = match value {
            crate::metadata::MetadataValue::Text(value) => value.len(),
            crate::metadata::MetadataValue::Bytes(value) => value.len(),
        };
        if value_len > METADATA_MAX_FIELD_LEN {
            return Err(FrameError::BodyTooLarge {
                len: value_len,
                limit: METADATA_MAX_FIELD_LEN,
            });
        }
        len = checked_encoded_add(len, encoded_varint_len(key.len()))?;
        len = checked_encoded_add(len, key.len())?;
        len = checked_encoded_add(len, 1)?;
        len = checked_encoded_add(len, encoded_varint_len(value_len))?;
        len = checked_encoded_add(len, value_len)?;
    }
    Ok(len)
}

#[cfg(any(feature = "iroh", test))]
fn encoded_varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

#[cfg(any(feature = "iroh", test))]
fn checked_encoded_add(left: usize, right: usize) -> Result<usize, FrameError> {
    left.checked_add(right).ok_or(FrameError::OversizedFrame {
        len: usize::MAX,
        cap: MAX_FRAME_BYTES,
    })
}

pub fn decode_frame(buf: &[u8]) -> Result<Frame, FrameError> {
    bounded_frame_len(buf.len() as u64)?;
    if buf.is_empty() {
        return Err(FrameError::Short { needed: 1, got: 0 });
    }
    let kind = FrameKind::from_u8(buf[0]).ok_or(FrameError::UnknownKind(buf[0]))?;
    let body = &buf[1..];
    match kind {
        FrameKind::Open => {
            if body.len() < 4 {
                return Err(FrameError::Short {
                    needed: 4,
                    got: body.len(),
                });
            }
            let method_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let metadata_bytes = &body[4..];
            let (headers, consumed) = decode_metadata(metadata_bytes)?;
            if consumed != metadata_bytes.len() {
                return Err(FrameError::TrailingBytes {
                    remaining: metadata_bytes.len() - consumed,
                });
            }
            Ok(Frame::Open(OpenFrame { method_id, headers }))
        }
        FrameKind::Body => Ok(Frame::Body(Bytes::copy_from_slice(body))),
        FrameKind::End => {
            if body.is_empty() {
                return Err(FrameError::Short { needed: 1, got: 0 });
            }
            let status = WireCode::from_u8(body[0]).ok_or(FrameError::UnknownCode(body[0]))?;
            let (msg_len, msg_consumed) = read_varint(&body[1..])?;
            let msg_len = bounded_len(msg_len, MAX_FRAME_BYTES)?;
            let msg_start = 1 + msg_consumed;
            let msg_end = msg_start
                .checked_add(msg_len)
                .ok_or(FrameError::BodyTooLarge {
                    len: usize::MAX,
                    limit: MAX_FRAME_BYTES,
                })?;
            if body.len() < msg_end {
                return Err(FrameError::Short {
                    needed: msg_end,
                    got: body.len(),
                });
            }
            let message = std::str::from_utf8(&body[msg_start..msg_end])
                .map_err(|_| FrameError::BadValueUtf8)?
                .into();
            let metadata_bytes = &body[msg_end..];
            let (metadata, consumed) = decode_metadata(metadata_bytes)?;
            if consumed != metadata_bytes.len() {
                return Err(FrameError::TrailingBytes {
                    remaining: metadata_bytes.len() - consumed,
                });
            }
            Ok(Frame::End(EndFrame {
                status,
                trailer: Trailer {
                    status,
                    message,
                    metadata,
                },
            }))
        }
        FrameKind::Reset => {
            if body.is_empty() {
                return Err(FrameError::Short { needed: 1, got: 0 });
            }
            if body.len() > 1 {
                return Err(FrameError::TrailingBytes {
                    remaining: body.len() - 1,
                });
            }
            let code = WireCode::from_u8(body[0]).ok_or(FrameError::UnknownCode(body[0]))?;
            Ok(Frame::Reset(ResetFrame { code }))
        }
        FrameKind::Credit => {
            if body.len() < 4 {
                return Err(FrameError::Short {
                    needed: 4,
                    got: body.len(),
                });
            }
            if body.len() > 4 {
                return Err(FrameError::TrailingBytes {
                    remaining: body.len() - 4,
                });
            }
            let additional_bytes = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            Ok(Frame::Credit(CreditFrame { additional_bytes }))
        }
    }
}

// -- Metadata codec ----------------------------------------------------------

fn encode_metadata(meta: &Metadata, out: &mut bytes::BytesMut) {
    write_varint(meta.len() as u64, out);
    for (key, value) in meta.iter() {
        write_varint(key.len() as u64, out);
        out.extend_from_slice(key.as_bytes());
        match value {
            crate::metadata::MetadataValue::Text(s) => {
                out.extend_from_slice(&[0]);
                write_varint(s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            crate::metadata::MetadataValue::Bytes(b) => {
                out.extend_from_slice(&[1]);
                write_varint(b.len() as u64, out);
                out.extend_from_slice(b);
            }
        }
    }
}

/// Hard cap on Metadata entries in a single frame. The plan calls for
/// 64 entries; cap at 256 to leave headroom while preventing
/// DoS-by-headers allocations.
const METADATA_MAX_ENTRIES: u64 = 256;
/// Hard cap on per-key / per-value byte length in a single frame.
/// 64 KiB is well over what any sane RPC header carries.
const METADATA_MAX_FIELD_LEN: usize = 64 * 1024;

fn decode_metadata(buf: &[u8]) -> Result<(Metadata, usize), FrameError> {
    let (count, consumed) = read_varint(buf)?;
    if count > METADATA_MAX_ENTRIES {
        return Err(FrameError::BodyTooLarge {
            len: usize::try_from(count).unwrap_or(usize::MAX),
            limit: METADATA_MAX_ENTRIES as usize,
        });
    }
    let mut pos = consumed;
    let mut meta = Metadata::with_capacity(count as usize);
    for _ in 0..count {
        let (key_len, c) = read_varint(&buf[pos..])?;
        pos += c;
        let key_len = bounded_len(key_len, METADATA_MAX_FIELD_LEN)?;
        let key_end = pos.checked_add(key_len).ok_or(FrameError::BodyTooLarge {
            len: usize::MAX,
            limit: METADATA_MAX_FIELD_LEN,
        })?;
        if buf.len() < key_end {
            return Err(FrameError::Short {
                needed: key_end,
                got: buf.len(),
            });
        }
        let key = std::str::from_utf8(&buf[pos..key_end])
            .map_err(|_| FrameError::BadKeyUtf8)?
            .to_string();
        pos = key_end;
        let tag_end = pos.checked_add(1).ok_or(FrameError::BodyTooLarge {
            len: usize::MAX,
            limit: MAX_FRAME_BYTES,
        })?;
        if buf.len() < tag_end {
            return Err(FrameError::Short {
                needed: tag_end,
                got: buf.len(),
            });
        }
        let tag = buf[pos];
        pos = tag_end;
        let (val_len, c) = read_varint(&buf[pos..])?;
        pos += c;
        let val_len = bounded_len(val_len, METADATA_MAX_FIELD_LEN)?;
        let value_end = pos.checked_add(val_len).ok_or(FrameError::BodyTooLarge {
            len: usize::MAX,
            limit: METADATA_MAX_FIELD_LEN,
        })?;
        if buf.len() < value_end {
            return Err(FrameError::Short {
                needed: value_end,
                got: buf.len(),
            });
        }
        let value = match tag {
            0 => {
                let s = std::str::from_utf8(&buf[pos..value_end])
                    .map_err(|_| FrameError::BadValueUtf8)?;
                crate::metadata::MetadataValue::Text(s.into())
            }
            1 => {
                crate::metadata::MetadataValue::Bytes(Bytes::copy_from_slice(&buf[pos..value_end]))
            }
            other => return Err(FrameError::UnknownMetadataTag(other)),
        };
        pos = value_end;
        meta.insert(key, value);
    }
    Ok((meta, pos))
}

// -- Varint ------------------------------------------------------------------

pub(crate) fn write_varint(mut v: u64, out: &mut bytes::BytesMut) {
    while v >= 0x80 {
        out.extend_from_slice(&[(v as u8) | 0x80]);
        v >>= 7;
    }
    out.extend_from_slice(&[v as u8]);
}

pub(crate) fn read_varint(buf: &[u8]) -> Result<(u64, usize), FrameError> {
    // "Must be complete" wrapper used by inner-frame decoders where the
    // full frame bytes are already buffered. A truncated varint here is
    // indistinguishable from corruption.
    match read_varint_partial(buf)? {
        Some(v) => Ok(v),
        None => Err(FrameError::BadVarint),
    }
}

/// Decode a varint while distinguishing a truncated buffer (recoverable —
/// more bytes may arrive) from a malformed varint (fatal — peer is
/// sending garbage).
///
/// Returns:
/// - `Ok(Some((value, consumed)))` — complete varint decoded
/// - `Ok(None)` — buffer ends mid-varint (≤ 9 continuation bytes seen)
/// - `Err(BadVarint)` — non-minimal, overflowing, or overlong encoding
pub(crate) fn read_varint_partial(buf: &[u8]) -> Result<Option<(u64, usize)>, FrameError> {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, byte) in buf.iter().take(10).enumerate() {
        // A u64 LEB128 has only one payload bit in its tenth byte. Accepting
        // anything larger silently discards high bits in the shift below and
        // lets multiple hostile encodings alias the same length.
        if i == 9 && byte & 0x7f > 1 {
            return Err(FrameError::BadVarint);
        }
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // Unsigned LEB128 is canonical only when a multi-byte encoding's
            // terminal group is non-zero. For example, 0x80 0x00 aliases the
            // one-byte encoding 0x00 and must not be another accepted wire
            // spelling.
            if i > 0 && byte & 0x7f == 0 {
                return Err(FrameError::BadVarint);
            }
            return Ok(Some((result, i + 1)));
        }
        shift += 7;
    }
    if buf.len() < 10 {
        Ok(None)
    } else {
        Err(FrameError::BadVarint)
    }
}

/// Wire-level upper bound on a single encoded frame, including its
/// kind byte and body. Enforced by stream parsers BEFORE allocating
/// buffer space; defends against a peer announcing `u64::MAX` as a
/// frame length and tarpitting our read loop into unbounded buffer
/// growth.
///
/// The mux applies its tighter per-stream window before constructing a Body;
/// this decoder cap is only a hard wire-allocation ceiling.
/// The mux's body-frame cap is a flow-control knob; this cap is the
/// parser's escape hatch. They differ in concern and lifecycle.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Validate an untrusted wire length before narrowing it to the host pointer
/// width. Comparing in `u64` first is essential on 32-bit targets: a direct
/// `as usize` cast can wrap a huge announced length below the frame cap.
pub(crate) fn bounded_frame_len(len: u64) -> Result<usize, FrameError> {
    if len > MAX_FRAME_BYTES as u64 {
        return Err(FrameError::OversizedFrame {
            len: usize::try_from(len).unwrap_or(usize::MAX),
            cap: MAX_FRAME_BYTES,
        });
    }
    usize::try_from(len).map_err(|_| FrameError::OversizedFrame {
        len: usize::MAX,
        cap: MAX_FRAME_BYTES,
    })
}

fn bounded_len(len: u64, limit: usize) -> Result<usize, FrameError> {
    if len > limit as u64 {
        return Err(FrameError::BodyTooLarge {
            len: usize::try_from(len).unwrap_or(usize::MAX),
            limit,
        });
    }
    usize::try_from(len).map_err(|_| FrameError::BodyTooLarge {
        len: usize::MAX,
        limit,
    })
}

#[cfg(test)]
mod tests;
