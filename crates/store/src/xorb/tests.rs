use super::*;

/// Deals bytes into four groups — the encoder this module reverses.
fn group(bytes: &[u8]) -> Vec<u8> {
    let mut groups: [Vec<u8>; BG4_GROUPS] = Default::default();
    for (position, byte) in bytes.iter().enumerate() {
        groups[position % BG4_GROUPS].push(*byte);
    }
    groups.concat()
}

fn framed(data: &[u8], scheme: Scheme) -> Vec<u8> {
    let payload = match scheme {
        Scheme::None => data.to_vec(),
        Scheme::Lz4 => lz4_flex::frame::FrameEncoder::new(Vec::new())
            .tap_write(data)
            .expect("encode"),
        Scheme::ByteGrouping4Lz4 => lz4_flex::frame::FrameEncoder::new(Vec::new())
            .tap_write(&group(data))
            .expect("encode"),
    };
    let tag = match scheme {
        Scheme::None => 0,
        Scheme::Lz4 => 1,
        Scheme::ByteGrouping4Lz4 => 2,
    };
    let mut out = vec![0_u8];
    out.extend_from_slice(&payload.len().to_le_bytes()[..3]);
    out.push(tag);
    out.extend_from_slice(&data.len().to_le_bytes()[..3]);
    out.extend_from_slice(&payload);
    out
}

/// Helper so the test encoder reads tolerably.
trait TapWrite {
    fn tap_write(self, bytes: &[u8]) -> std::io::Result<Vec<u8>>;
}
impl TapWrite for lz4_flex::frame::FrameEncoder<Vec<u8>> {
    fn tap_write(mut self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        use std::io::Write as _;
        self.write_all(bytes)?;
        self.finish().map_err(std::io::Error::other)
    }
}

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index * 31 % 251) as u8).collect()
}

#[test]
fn a_truncated_xorb_is_refused_not_guessed() {
    let framed = framed(&sample(100), Scheme::Lz4);
    assert_eq!(decode_chunk(&framed[..4]), Err(XorbError::Truncated));
    assert_eq!(
        decode_chunk(&framed[..framed.len() - 1]),
        Err(XorbError::Truncated),
    );
}

#[test]
fn an_unknown_version_or_scheme_is_refused() {
    let mut bad = framed(&sample(10), Scheme::None);
    bad[0] = 1;
    assert_eq!(
        decode_chunk(&bad),
        Err(XorbError::UnknownVersion { version: 1 })
    );

    let mut bad = framed(&sample(10), Scheme::None);
    bad[4] = 9;
    assert_eq!(decode_chunk(&bad), Err(XorbError::UnknownScheme { tag: 9 }));
}

/// The check that makes a partial fetch safe: bytes that decode
/// cleanly but are not the bytes we asked for must be rejected.
#[test]
fn a_chunk_that_decodes_to_the_wrong_bytes_is_rejected() {
    let real = sample(5_000);
    let mut lie = real.clone();
    lie[0] ^= 1;
    let expected = [Chunk::new(chunk_hash(&real), real.len() as u64)];

    assert!(decode_range(&framed(&real, Scheme::Lz4), &expected).is_ok());
    assert!(matches!(
        decode_range(&framed(&lie, Scheme::Lz4), &expected),
        Err(XorbError::HashMismatch { .. }),
    ));
}

/// A header is a claim, and the payload is the sender's. Decoding
/// must be bounded by what the header declared, not by what the
/// payload turns out to expand to — otherwise the length check that
/// catches the lie is reached only if the allocation succeeded.
#[test]
fn a_chunk_that_expands_past_its_declared_length_is_refused_not_allocated() {
    // 16 MiB of zeros compresses to a few kilobytes, and the header
    // declares one byte. A decoder that expands first and checks
    // afterwards allocates all of it.
    let bomb = vec![0_u8; 16 * 1024 * 1024];
    let mut framed = framed(&bomb, Scheme::Lz4);
    assert!(framed.len() < 100_000, "the fixture must be a bomb");
    framed[5..8].copy_from_slice(&1_usize.to_le_bytes()[..3]);

    assert_eq!(
        decode_chunk(&framed),
        Err(XorbError::LengthMismatch {
            declared: 1,
            // One more than declared: enough to know the header lied,
            // and nothing like the 16 MiB it asked for.
            actual: 2,
        }),
    );
}

/// The same, for byte grouping — the ungrouping happens after
/// decompression, so the bound has to be on the decompression.
#[test]
fn a_byte_grouped_chunk_is_bounded_by_its_declared_length_too() {
    let bomb = vec![0_u8; 16 * 1024 * 1024];
    let mut framed = framed(&bomb, Scheme::ByteGrouping4Lz4);
    framed[5..8].copy_from_slice(&8_usize.to_le_bytes()[..3]);
    assert!(matches!(
        decode_chunk(&framed),
        Err(XorbError::LengthMismatch { declared: 8, .. }),
    ));
}

/// Bytes after the chunks that were asked for are bytes nobody
/// accounted for. The range was requested by byte offsets covering
/// exactly those chunks.
#[test]
fn bytes_after_the_requested_chunks_are_refused() {
    let data = sample(1_000);
    let expected = [Chunk::new(chunk_hash(&data), data.len() as u64)];
    let mut xorb = framed(&data, Scheme::Lz4);
    let honest = xorb.len();
    xorb.extend_from_slice(&framed(&sample(50), Scheme::None));

    assert_eq!(
        decode_range(&xorb, &expected),
        Err(XorbError::Trailing {
            count: 1,
            trailing: xorb.len() - honest,
        }),
    );
    assert!(decode_range(&xorb[..honest], &expected).is_ok());
}

#[test]
fn descriptor_lengths_and_cold_caps_are_checked_from_the_header_before_payload() {
    let mut header = [0u8; HEADER];
    header[1..4].copy_from_slice(&1000usize.to_le_bytes()[..3]);
    header[5..8].copy_from_slice(&1usize.to_le_bytes()[..3]);
    assert_eq!(
        decode_chunk(&header),
        Err(XorbError::LengthMismatch {
            declared: 1,
            actual: 1000
        })
    );
    header[4] = 1;
    assert!(matches!(
        decode_chunk_bounded(&header, Some(&Chunk::new(XetHash::ZERO, 2))),
        Err(XorbError::UnexpectedLength { .. })
    ));
    header[5..8].copy_from_slice(&(hellas_xet::MAX_CHUNK_SIZE + 1).to_le_bytes()[..3]);
    assert_eq!(decode_chunk(&header), Err(XorbError::TooLarge));
}
