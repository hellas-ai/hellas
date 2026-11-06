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
//! # What verification this can and cannot do
//!
//! Each decoded chunk is hashed and checked against the chunk hash the
//! caller expects, so a xorb that decodes into the wrong bytes is
//! caught here. That check is only possible because *we* hold the chunk
//! list — a reconstruction response carries no chunk hashes, so a client
//! without an index cannot verify anything until it has reassembled a
//! whole file.

use hellas_xet::{Chunk, XetHash, chunk_hash};

/// Bytes of header before each chunk's payload.
pub(crate) const HEADER: usize = 8;
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
    #[error("chunk header length {declared} differs from expected {expected}")]
    UnexpectedLength { expected: u64, declared: usize },
    #[error("chunk header length exceeds canonical maximum")]
    TooLarge,
    #[error("chunk hashed to {actual}, expected {expected}")]
    HashMismatch { expected: XetHash, actual: XetHash },
    #[error("{trailing} bytes follow the {count} chunks that were asked for")]
    Trailing { count: usize, trailing: usize },
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
    decode_chunk_bounded(bytes, None)
}

pub(crate) fn decode_chunk_bounded(
    bytes: &[u8],
    expected: Option<&Chunk>,
) -> Result<Decoded, XorbError> {
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
    if let Some(expected) = expected
        && uncompressed_size as u64 != expected.data_len
    {
        return Err(XorbError::UnexpectedLength {
            expected: expected.data_len,
            declared: uncompressed_size,
        });
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
        Scheme::None => {
            if compressed_size != uncompressed_size {
                return Err(XorbError::LengthMismatch {
                    declared: uncompressed_size,
                    actual: compressed_size,
                });
            }
            payload.to_vec()
        }
        Scheme::Lz4 => lz4_frame(payload, uncompressed_size)?,
        Scheme::ByteGrouping4Lz4 => ungroup(&lz4_frame(payload, uncompressed_size)?),
    };
    if data.len() != uncompressed_size {
        return Err(XorbError::LengthMismatch {
            declared: uncompressed_size,
            actual: data.len(),
        });
    }
    if let Some(expected) = expected {
        let actual = chunk_hash(&data);
        if actual != expected.hash {
            return Err(XorbError::HashMismatch {
                expected: expected.hash,
                actual,
            });
        }
    }
    Ok(Decoded {
        data,
        consumed: HEADER + compressed_size,
    })
}

/// Decodes a xorb range into chunks, checking each against `expected`.
///
/// `expected` is the slice of our own chunk list covering this range.
/// Checking here is what makes a partial fetch safe: without it the only
/// verification available is the file hash, which needs every byte.
pub fn decode_range(bytes: &[u8], expected: &[Chunk]) -> Result<Vec<Vec<u8>>, XorbError> {
    decode_chunks(bytes, expected.len(), Some(expected))
}

/// Decodes `count` consecutive chunks, verifying each against
/// `expected` when the caller has a chunk list to check against.
///
/// `None` is not laxity for its own sake: a client fetching content it
/// has never indexed genuinely has nothing to check against, because a
/// reconstruction response carries no chunk hashes. Such a fetch is
/// verified once, whole, against the file hash.
pub fn decode_chunks(
    bytes: &[u8],
    count: usize,
    expected: Option<&[Chunk]>,
) -> Result<Vec<Vec<u8>>, XorbError> {
    let mut decoded = Vec::with_capacity(count);
    let mut offset = 0;
    for index in 0..count {
        let next = decode_chunk_bounded(
            bytes.get(offset..).ok_or(XorbError::Truncated)?,
            expected.and_then(|chunks| chunks.get(index)),
        )?;
        if let Some(chunk) = expected.and_then(|chunks| chunks.get(index)) {
            let actual = chunk_hash(&next.data);
            if actual != chunk.hash {
                return Err(XorbError::HashMismatch {
                    expected: chunk.hash,
                    actual,
                });
            }
        }
        offset += next.consumed;
        decoded.push(next.data);
    }
    // The range was requested by byte offsets covering exactly these
    // chunks, so anything after them is something we did not ask for and
    // cannot account for.
    if offset != bytes.len() {
        return Err(XorbError::Trailing {
            count,
            trailing: bytes.len() - offset,
        });
    }
    Ok(decoded)
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
    // FrameDecoder allocates its advertised block maximum (up to 4 MiB)
    // before Read::take can bound it. Decode blocks directly into the bounded
    // output instead; lz4_flex still owns the actual LZ4 decoding.
    fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], XorbError> {
        let (head, tail) = input.split_at_checked(count).ok_or(XorbError::Decompress)?;
        *input = tail;
        Ok(head)
    }
    fn word(input: &mut &[u8]) -> Result<u32, XorbError> {
        Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()))
    }
    let overflow = || XorbError::LengthMismatch {
        declared,
        actual: declared + 1,
    };
    let mut input = payload;
    if word(&mut input)? != 0x184d2204 {
        return Err(XorbError::Decompress);
    }
    let flags = take(&mut input, 1)?[0];
    let bd = take(&mut input, 1)?[0];
    // Standard v1 frame, no reserved bits or external dictionary.
    if flags & 0xc3 != 0x40 || bd & 0x8f != 0 || !(4..=7).contains(&(bd >> 4)) {
        return Err(XorbError::Decompress);
    }
    let max_block = 1usize << (8 + 2 * (bd >> 4));
    let content_size = if flags & 8 != 0 {
        Some(u64::from_le_bytes(take(&mut input, 8)?.try_into().unwrap()))
    } else {
        None
    };
    let header_end = payload.len() - input.len();
    let checksum = take(&mut input, 1)?[0];
    if (twox_hash::XxHash32::oneshot(0, &payload[4..header_end]) >> 8) as u8 != checksum {
        return Err(XorbError::Decompress);
    }
    if content_size.is_some_and(|size| size > declared as u64) {
        return Err(overflow());
    }
    let mut out = vec![0; declared + 1];
    let mut filled = 0;
    loop {
        let block = word(&mut input)?;
        if block == 0 {
            break;
        }
        let raw = block & 0x80000000 != 0;
        let count = (block & 0x7fffffff) as usize;
        if count == 0 || count > max_block {
            return Err(XorbError::Decompress);
        }
        let block = take(&mut input, count)?;
        if flags & 0x10 != 0 && word(&mut input)? != twox_hash::XxHash32::oneshot(0, block) {
            return Err(XorbError::Decompress);
        }
        let (dictionary, remaining) = out.split_at_mut(filled);
        let writable = remaining.len().min(max_block);
        let written = if raw {
            if count > writable {
                return Err(overflow());
            }
            remaining[..count].copy_from_slice(block);
            count
        } else {
            let decoded = if flags & 0x20 != 0 {
                lz4_flex::block::decompress_into(block, &mut remaining[..writable])
            } else {
                lz4_flex::block::decompress_into_with_dict(
                    block,
                    &mut remaining[..writable],
                    dictionary,
                )
            };
            decoded.map_err(|error| match error {
                lz4_flex::block::DecompressError::OutputTooSmall { .. } => overflow(),
                _ => XorbError::Decompress,
            })?
        };
        filled += written;
        if filled > declared {
            return Err(overflow());
        }
    }
    out.truncate(filled);
    if content_size.is_some_and(|size| size != filled as u64) {
        return Err(XorbError::Decompress);
    }
    if flags & 4 != 0 && word(&mut input)? != twox_hash::XxHash32::oneshot(0, &out) {
        return Err(XorbError::Decompress);
    }
    if !input.is_empty() {
        return Err(XorbError::Decompress);
    }
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
