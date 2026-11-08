//! Xorb framing: turning downloaded bytes back into chunks.
//!
//! A xorb is a bare concatenation of framed chunks. No container header,
//! no index, no trailer — you find the second chunk by decoding the
//! first. Each chunk is an 8-byte header followed by exactly
//! `compressed_size` payload bytes:
//!
//! ```text
//! 0       version (u8, currently 0)
//! 1..4    compressed_size   (u24, little endian)
//! 4       compression scheme
//! 5..8    uncompressed_size (u24, little endian)
//! 8..     payload
//! ```
//!
//! # Two traps
//!
//! **Scheme 1 is the LZ4 *frame* format, not a raw block.** The spec
//! says "LZ4"; xet-core uses `lz4_flex::frame`. Decoding with the block
//! API fails outright, which is at least loud, but it is the kind of
//! detail that costs an afternoon.
//!
//! **Scheme 2 (byte grouping) is applied after decompression, not
//! instead of it.** The payload is LZ4-frame-decompressed whole, and the
//! result is then un-grouped: it was split into four near-equal groups
//! and concatenated, so recovering the original means interleaving them
//! back. Remainder bytes go one each to the first groups.
//!
//! Decoding validates framing and expansion bounds. The acquired file is
//! canonically hashed against its advertised identity before publication.

/// Bytes of header before each chunk's payload.
pub(crate) const HEADER: usize = 8;
// LZ4 standard-frame maximum block is 4 MiB. FrameDecoder retains one input
// block, up to two output blocks and its 64-KiB linked history window.
pub(crate) const LZ4_SCRATCH_BYTES: usize = 3 * (4 * 1024 * 1024) + 64 * 1024;
/// Groups the byte-grouping scheme splits a payload into.
const BG4_GROUPS: usize = 4;

/// How a chunk's payload was compressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    /// Stored as-is.
    None,
    /// LZ4 frame format.
    Lz4,
    /// Byte-grouped, then LZ4 frame format.
    ByteGrouping4Lz4,
}

impl Scheme {
    fn from_tag(tag: u8) -> Result<Self, XorbError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Lz4),
            2 => Ok(Self::ByteGrouping4Lz4),
            tag => Err(XorbError::UnknownScheme { tag }),
        }
    }
}

/// Why a xorb could not be decoded.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum XorbError {
    #[error("chunk header runs past the end of the xorb")]
    Truncated,
    #[error("unsupported chunk framing version {version}")]
    UnknownVersion { version: u8 },
    #[error("unknown compression scheme {tag}")]
    UnknownScheme { tag: u8 },
    #[error("chunk decompression failed")]
    Decompress,
    #[error("chunk decompressed to {actual} bytes, header declared {declared}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("chunk header length exceeds canonical maximum")]
    TooLarge,
}

/// One decoded chunk and how many bytes of the xorb it occupied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    /// The chunk's uncompressed bytes.
    pub data: Vec<u8>,
    /// Bytes consumed from the xorb, header included.
    pub consumed: usize,
}

/// Decodes the chunk beginning at the start of `bytes`.
pub fn decode_chunk(bytes: &[u8]) -> Result<Decoded, XorbError> {
    let header = bytes.get(..HEADER).ok_or(XorbError::Truncated)?;
    let version = header[0];
    if version != 0 {
        return Err(XorbError::UnknownVersion { version });
    }
    let compressed_size = u24(&header[1..4]);
    let scheme = Scheme::from_tag(header[4])?;
    let uncompressed_size = u24(&header[5..8]);
    if uncompressed_size > hellas_xet::MAX_CHUNK_SIZE {
        return Err(XorbError::TooLarge);
    }
    if matches!(scheme, Scheme::None) && compressed_size != uncompressed_size {
        return Err(XorbError::LengthMismatch {
            declared: uncompressed_size,
            actual: compressed_size,
        });
    }
    let payload = bytes
        .get(HEADER..HEADER + compressed_size)
        .ok_or(XorbError::Truncated)?;

    // The header says how big this chunk decompresses to, and that is
    // the bound the decompressor is given. Without it a few kilobytes of
    // payload expand to whatever the sender chose before anything checks
    // the length — and the check that follows is only reached if the
    // allocation succeeded.
    let data = match scheme {
        Scheme::None => payload.to_vec(),
        Scheme::Lz4 => lz4_frame(payload, uncompressed_size)?,
        Scheme::ByteGrouping4Lz4 => ungroup(&lz4_frame(payload, uncompressed_size)?),
    };
    if data.len() != uncompressed_size {
        return Err(XorbError::LengthMismatch {
            declared: uncompressed_size,
            actual: data.len(),
        });
    }
    Ok(Decoded {
        data,
        consumed: HEADER + compressed_size,
    })
}

fn u24(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | usize::from(bytes[1]) << 8 | usize::from(bytes[2]) << 16
}

/// Decompresses at most `declared + 1` bytes.
///
/// One byte more than the header declared, deliberately: stopping at
/// exactly `declared` would truncate an over-long expansion into
/// agreement with the header, and the caller's length check — the thing
/// that catches a lying header — would pass.
fn lz4_frame(payload: &[u8], declared: usize) -> Result<Vec<u8>, XorbError> {
    use std::io::Read;
    // Reject legacy/nonstandard frames: the standard frame format limits blocks
    // to 4 MiB, which bounds FrameDecoder's internal scratch allocation.
    if payload.get(..4) != Some(&[0x04, 0x22, 0x4d, 0x18]) {
        return Err(XorbError::Decompress);
    }
    let mut decoder = lz4_flex::frame::FrameDecoder::new(payload).take((declared + 1) as u64);
    let mut out = vec![0; declared + 1];
    let mut filled = 0;
    while filled < out.len() {
        let read = decoder
            .read(&mut out[filled..])
            .map_err(|_| XorbError::Decompress)?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    if filled <= declared && !decoder.get_ref().get_ref().is_empty() {
        return Err(XorbError::Decompress);
    }
    out.truncate(filled);
    Ok(out)
}

/// Reverses byte grouping: the input is four concatenated groups that
/// were formed by dealing the original bytes round-robin.
///
/// Group sizes are `len / 4`, with the first `len % 4` groups taking one
/// extra byte — so for a length that is not a multiple of four the
/// groups are not all the same size, and assuming they are silently
/// corrupts the tail.
fn ungroup(grouped: &[u8]) -> Vec<u8> {
    let len = grouped.len();
    let base = len / BG4_GROUPS;
    let extra = len % BG4_GROUPS;

    let mut starts = [0_usize; BG4_GROUPS];
    let mut at = 0;
    for (index, start) in starts.iter_mut().enumerate() {
        *start = at;
        at += base + usize::from(index < extra);
    }

    let mut out = Vec::with_capacity(len);
    for position in 0..len {
        let group = position % BG4_GROUPS;
        let within = position / BG4_GROUPS;
        let size = base + usize::from(group < extra);
        if within < size {
            out.push(grouped[starts[group] + within]);
        }
    }
    out
}

#[cfg(test)]
mod tests;
