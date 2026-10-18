//! Mux wire framing — prepends `(stream_id: u16, generation: u16)` to each
//! Frame. One mux WS message carries exactly one keyed frame.

use bytes::{Bytes, BytesMut};

use crate::frame::{Frame, FrameError, decode_frame, encode_frame};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StreamKey {
    pub stream_id: u16,
    pub generation: u16,
}

impl StreamKey {
    pub const fn new(stream_id: u16, generation: u16) -> Self {
        Self {
            stream_id,
            generation,
        }
    }
}

#[derive(Clone, Debug)]
pub struct KeyedFrame {
    pub key: StreamKey,
    pub frame: Frame,
}

pub fn encode_keyed_frame(key: StreamKey, frame: &Frame) -> Bytes {
    let mut buf = BytesMut::with_capacity(64);
    buf.extend_from_slice(&key.stream_id.to_be_bytes());
    buf.extend_from_slice(&key.generation.to_be_bytes());
    encode_frame(frame, &mut buf);
    buf.freeze()
}

pub fn decode_keyed_frame(buf: &[u8]) -> Result<KeyedFrame, FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Short {
            needed: 4,
            got: buf.len(),
        });
    }
    let stream_id = u16::from_be_bytes([buf[0], buf[1]]);
    let generation = u16::from_be_bytes([buf[2], buf[3]]);
    let frame = decode_frame(&buf[4..])?;
    Ok(KeyedFrame {
        key: StreamKey {
            stream_id,
            generation,
        },
        frame,
    })
}

/// Inspect a frame produced by this mux without copying its protected body.
pub(super) fn keyed_frame_header(buf: &[u8]) -> Option<(StreamKey, crate::FrameKind)> {
    let [a, b, c, d, kind, ..] = buf else {
        return None;
    };
    Some((
        StreamKey::new(u16::from_be_bytes([*a, *b]), u16::from_be_bytes([*c, *d])),
        crate::FrameKind::from_u8(*kind)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::OpenFrame;
    use crate::metadata::Metadata;

    #[test]
    fn keyed_frame_roundtrip() {
        let frame = Frame::Open(OpenFrame {
            method_id: 0x12345678,
            headers: Metadata::new(),
        });
        let key = StreamKey::new(42, 7);
        let bytes = encode_keyed_frame(key, &frame);
        let decoded = decode_keyed_frame(&bytes).unwrap();
        assert_eq!(decoded.key, key);
        match decoded.frame {
            Frame::Open(o) => assert_eq!(o.method_id, 0x12345678),
            _ => panic!("expected Open"),
        }
    }
}
