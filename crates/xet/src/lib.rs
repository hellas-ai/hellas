#![cfg_attr(not(feature = "std"), no_std)]

// The kernel is `#![no_std]` and depends on this crate with default
// features off, so this crate's default-off surface must be allocation-free
// — not merely allocation-light. Everything that needs a growable buffer
// (the chunkers, and the Merkle tree, whose node count is unbounded) sits
// behind `std`, which `chunking` already implies. What the kernel calls —
// `XetHash`, `chunk_hash`, `SingleChunkHasher` — never allocates.
#[cfg(feature = "std")]
extern crate alloc;

// Proof of the paragraph above, checked by the compiler rather than by
// reading. With `std` off, `alloc` names this empty module: a re-added
// `extern crate alloc` collides with it ("defined multiple times") and any
// stray `alloc::…` path resolves in here and finds nothing. CI runs the
// proof as `check-xet-no-alloc`.
#[cfg(not(feature = "std"))]
mod alloc {}

#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{fmt, str::FromStr};
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Key used by Xet Protocol v1.1.0 for chunk (leaf) hashes.
pub const DATA_KEY: [u8; 32] = [
    102, 151, 245, 119, 91, 149, 80, 222, 49, 53, 203, 172, 165, 151, 24, 28, 157, 228, 33, 16,
    155, 235, 43, 88, 180, 208, 176, 75, 147, 173, 242, 41,
];

/// Key used by Xet Protocol v1.1.0 for Merkle internal-node hashes.
pub const INTERNAL_NODE_KEY: [u8; 32] = [
    1, 126, 197, 199, 165, 71, 41, 150, 253, 148, 102, 102, 180, 138, 2, 230, 93, 221, 83, 111, 55,
    199, 109, 210, 248, 99, 82, 230, 74, 83, 113, 63,
];

/// Target chunk size in bytes.
pub const TARGET_CHUNK_SIZE: usize = 64 * 1024;
/// Minimum non-final chunk size in bytes.
pub const MIN_CHUNK_SIZE: usize = 8 * 1024;
/// Maximum chunk size in bytes.
pub const MAX_CHUNK_SIZE: usize = 128 * 1024;
/// Boundary mask used with the Gear rolling hash.
pub const CHUNK_BOUNDARY_MASK: u64 = 0xffff_0000_0000_0000;

/// Bytes of input the GearHash window spans; after this many the rolling
/// state no longer depends on where feeding began.
#[cfg(feature = "chunking")]
const HASH_WINDOW_SIZE: usize = 64;
/// Bytes at the start of a chunk that cannot produce an accepted
/// boundary, so the rolling hash is not fed them.
#[cfg(feature = "chunking")]
const INITIAL_SKIP: usize = MIN_CHUNK_SIZE - HASH_WINDOW_SIZE - 1;

#[cfg(feature = "std")]
const TREE_BRANCHING_FACTOR: u64 = 4;
#[cfg(feature = "std")]
const MAX_GROUP_SIZE: usize = 2 * TREE_BRANCHING_FACTOR as usize + 1;
#[cfg(feature = "std")]
const MAX_ENTRY_SIZE: usize = 64 + 3 + 20 + 1;
#[cfg(feature = "std")]
const MAX_MERGE_BUFFER_SIZE: usize = MAX_GROUP_SIZE * MAX_ENTRY_SIZE;
const ZERO_KEY: [u8; 32] = [0; 32];

/// A raw 32-byte Xet hash.
///
/// The bytes are the BLAKE3 digest bytes. Its hexadecimal representation follows
/// Xet's convention: four little-endian `u64` limbs printed as 16 lowercase hex
/// digits each.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct XetHash([u8; 32]);

impl XetHash {
    /// Size of a Xet hash in bytes.
    pub const LEN: usize = 32;

    /// The all-zero hash used by Xet for an empty chunk sequence.
    pub const ZERO: Self = Self([0; Self::LEN]);

    /// Computes the Xet file hash of `bytes`.
    #[cfg(feature = "chunking")]
    #[must_use]
    pub fn hash(bytes: &[u8]) -> Self {
        file_hash(&chunk(bytes))
    }

    /// Wraps raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Wraps a 32-byte Xet hash from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, XetHashError> {
        let bytes = bytes
            .try_into()
            .map_err(|_| XetHashError::WrongLength { len: bytes.len() })?;
        Ok(Self(bytes))
    }

    /// Returns the raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Consumes the hash and returns its raw BLAKE3 digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::LEN] {
        self.0
    }

    #[cfg(feature = "std")]
    fn natural_cut_value(self) -> u64 {
        let mut limb = [0; 8];
        limb.copy_from_slice(&self.0[24..]);
        u64::from_le_bytes(limb)
    }
}

impl AsRef<[u8]> for XetHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for XetHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<XetHash> for [u8; 32] {
    fn from(hash: XetHash) -> Self {
        hash.into_bytes()
    }
}

impl fmt::LowerHex for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for limb in self.0.as_chunks::<8>().0 {
            for byte in limb.iter().rev() {
                write!(formatter, "{byte:02x}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

impl fmt::Debug for XetHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

/// Error returned for an invalid binary or textual Xet hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XetHashError {
    /// A binary hash had the wrong number of bytes.
    WrongLength { len: usize },
    /// A textual hash was not 64 hexadecimal characters.
    InvalidHex,
}

impl fmt::Display for XetHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { len } => write!(formatter, "Xet hash must be 32 bytes, got {len}"),
            Self::InvalidHex => {
                formatter.write_str("invalid Xet hash: expected 64 hexadecimal characters")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for XetHashError {}

impl FromStr for XetHash {
    type Err = XetHashError;

    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.len() != 64 {
            return Err(XetHashError::InvalidHex);
        }

        let mut raw = [0; 32];
        for (limb_index, limb) in hex.as_bytes().as_chunks::<16>().0.iter().enumerate() {
            for byte_index in 0..8 {
                let high = decode_hex(limb[byte_index * 2]).ok_or(XetHashError::InvalidHex)?;
                let low = decode_hex(limb[byte_index * 2 + 1]).ok_or(XetHashError::InvalidHex)?;
                raw[limb_index * 8 + 7 - byte_index] = (high << 4) | low;
            }
        }
        Ok(Self(raw))
    }
}

#[cfg(feature = "serde")]
impl Serialize for XetHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for XetHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct XetHashVisitor;

        impl Visitor<'_> for XetHashVisitor {
            type Value = XetHash;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 32-byte Xet hash")
            }

            // Only the borrowed form. serde's default `visit_byte_buf`
            // already forwards an owned buffer here, so restating it
            // would buy nothing but a `Vec` — and with it an allocator
            // this crate refuses to require.
            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                XetHash::from_slice(bytes).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(XetHashVisitor)
    }
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A content chunk represented by its Xet hash and uncompressed length.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Chunk {
    /// Xet DATA-keyed BLAKE3 hash of the chunk bytes.
    pub hash: XetHash,
    /// Length of the chunk data in bytes.
    pub data_len: u64,
}

impl Chunk {
    /// Creates a chunk descriptor.
    #[must_use]
    pub const fn new(hash: XetHash, data_len: u64) -> Self {
        Self { hash, data_len }
    }
}

/// Computes the Xet chunk hash for `bytes`.
#[must_use]
pub fn chunk_hash(bytes: &[u8]) -> XetHash {
    XetHash::from(*blake3::keyed_hash(&DATA_KEY, bytes).as_bytes())
}

/// Allocation-free Xet file hasher for inputs smaller than one minimum chunk.
///
/// Xet cannot cut an input below [`MIN_CHUNK_SIZE`], so such an input has one
/// DATA-keyed leaf whose hash is finalized with the zero file key. Writing
/// more bytes is a programming error; arbitrary inputs use [`XetHash::hash`].
pub struct SingleChunkHasher {
    leaf: blake3::Hasher,
    len: usize,
}

impl Default for SingleChunkHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleChunkHasher {
    /// Creates an empty single-chunk file hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaf: blake3::Hasher::new_keyed(&DATA_KEY),
            len: 0,
        }
    }

    /// Appends bytes to the single Xet chunk.
    ///
    /// # Panics
    ///
    /// Panics if the total input reaches [`MIN_CHUNK_SIZE`].
    pub fn update(&mut self, bytes: &[u8]) {
        assert!(
            self.len < MIN_CHUNK_SIZE && bytes.len() < MIN_CHUNK_SIZE - self.len,
            "single Xet chunk must be smaller than MIN_CHUNK_SIZE"
        );
        self.len += bytes.len();
        self.leaf.update(bytes);
    }

    /// Finalizes the Xet file hash.
    #[must_use]
    pub fn finalize(self) -> XetHash {
        if self.len == 0 {
            return XetHash::ZERO;
        }
        XetHash::from(*blake3::keyed_hash(&ZERO_KEY, self.leaf.finalize().as_bytes()).as_bytes())
    }
}

/// Splits `bytes` with Xet's GearHash CDC and returns its chunk descriptors.
#[cfg(feature = "chunking")]
#[must_use]
pub fn chunk(bytes: &[u8]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        let remaining = &bytes[start..];
        let search_end = remaining.len().min(MAX_CHUNK_SIZE);
        let mut cursor = INITIAL_SKIP.min(search_end);
        let mut hasher = gearhash::Hasher::default();
        let boundary = loop {
            let Some(consumed) =
                hasher.next_match(&remaining[cursor..search_end], CHUNK_BOUNDARY_MASK)
            else {
                break search_end;
            };
            cursor += consumed;
            if cursor >= MIN_CHUNK_SIZE {
                break cursor;
            }
        };

        let data = &remaining[..boundary];
        chunks.push(Chunk::new(chunk_hash(data), data.len() as u64));
        start += boundary;
    }

    chunks
}

/// Streaming Xet file hasher: the same split [`chunk`] produces, without
/// holding the input.
///
/// [`chunk`] and [`XetHash::hash`] take a whole `&[u8]`, so hashing a
/// multi-gigabyte file costs a multi-gigabyte allocation. This consumes
/// arbitrary buffers and yields the identical chunk list, so the caller
/// reads with a buffer of its own choosing.
///
/// Equivalence is exact, not approximate. `gearhash::Hasher` is a single
/// rolling `u64` and `next_match` leaves it at the matched position, so
/// splitting the input across calls cannot change where a boundary
/// falls.
///
/// Keep the chunk list, not just the id. It is the metainfo that makes a
/// later partial fetch of the same file verifiable — a Xet file hash is
/// a Merkle root over exactly these descriptors, and the reconstruction
/// protocol does not hand chunk hashes back.
#[cfg(feature = "chunking")]
pub struct XetFileHasher {
    /// Rolling boundary detector for the chunk being accumulated.
    gear: gearhash::Hasher<'static>,
    /// DATA-keyed leaf hash of the chunk being accumulated.
    leaf: blake3::Hasher,
    /// Bytes accumulated into the current chunk. The only carrier of the
    /// `INITIAL_SKIP` / `MIN_CHUNK_SIZE` / `MAX_CHUNK_SIZE` rules.
    chunk_len: usize,
    chunks: Vec<Chunk>,
}

#[cfg(feature = "chunking")]
impl Default for XetFileHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "chunking")]
impl XetFileHasher {
    /// Creates a hasher over an empty input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            gear: gearhash::Hasher::default(),
            leaf: blake3::Hasher::new_keyed(&DATA_KEY),
            chunk_len: 0,
            chunks: Vec::new(),
        }
    }

    /// Appends `input`, emitting chunks as their boundaries are found.
    ///
    /// Any split of the same byte sequence across calls yields the same
    /// chunks.
    #[allow(
        clippy::indexing_slicing,
        reason = "every index is bounded by input.len() or by MAX_CHUNK_SIZE minus chunk_len"
    )]
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // Bytes below INITIAL_SKIP are never fed to the rolling
            // hash, exactly as `chunk` skips them.
            //
            // Why that is safe, and why it is an ARGUMENT rather than a
            // tested fact: `hash = (hash << 1) + table[b]`, so after
            // HASH_WINDOW_SIZE bytes nothing fed earlier remains in the
            // bits CHUNK_BOUNDARY_MASK examines. Since
            // `INITIAL_SKIP + HASH_WINDOW_SIZE == MIN_CHUNK_SIZE - 1`,
            // the state at the first position where a boundary may be
            // *accepted* cannot depend on what came before the skip.
            //
            // The same argument is why resetting `gear` in `cut` is
            // belt-and-braces: mutation testing confirms neither the
            // skip nor the reset is observable. A test for this was
            // attempted and deleted — the forgetting horizon is nearer
            // than the first boundary in any realistic fixture, so the
            // test could not fail and would have been decoration. If
            // gearhash ever widened its window, this comment is what
            // would be wrong, and nothing would catch it.
            if self.chunk_len < INITIAL_SKIP {
                let skip = (INITIAL_SKIP - self.chunk_len).min(input.len());
                self.leaf.update(&input[..skip]);
                self.chunk_len += skip;
                input = &input[skip..];
                continue;
            }

            // A chunk is cut at MAX_CHUNK_SIZE whether or not the
            // rolling hash ever matched, so never scan past it.
            let take = input.len().min(MAX_CHUNK_SIZE - self.chunk_len);
            let window = &input[..take];

            if let Some(consumed) = self.gear.next_match(window, CHUNK_BOUNDARY_MASK) {
                self.leaf.update(&window[..consumed]);
                self.chunk_len += consumed;
                input = &input[consumed..];
                // A match below MIN_CHUNK_SIZE is discarded and the
                // search continues with the gear state it left behind.
                if self.chunk_len >= MIN_CHUNK_SIZE {
                    self.cut();
                }
            } else {
                self.leaf.update(window);
                self.chunk_len += take;
                input = &input[take..];
                if self.chunk_len == MAX_CHUNK_SIZE {
                    self.cut();
                }
            }
        }
    }

    /// Finishes the trailing partial chunk and returns the chunk list.
    #[must_use]
    pub fn finalize_chunks(mut self) -> Vec<Chunk> {
        if self.chunk_len > 0 {
            self.cut();
        }
        self.chunks
    }

    /// Finishes and returns the Xet file hash.
    #[must_use]
    pub fn finalize(self) -> XetHash {
        file_hash(&self.finalize_chunks())
    }

    /// Emits the accumulated chunk and starts the next one.
    fn cut(&mut self) {
        let hash = XetHash::from(*self.leaf.finalize().as_bytes());
        self.chunks.push(Chunk::new(hash, self.chunk_len as u64));
        self.gear = gearhash::Hasher::default();
        self.leaf = blake3::Hasher::new_keyed(&DATA_KEY);
        self.chunk_len = 0;
    }
}

/// Computes the Merkle root over ordered `(hash, length)` chunk descriptors.
///
/// At every level, Xet takes a natural cut after the third or later child whose
/// last hash limb is divisible by four. A group is capped at nine children, and
/// a final remainder of one or two children is merged as-is.
///
/// A level holds one node per group, so the working set is bounded only by
/// the input: this needs an allocator, and lives behind `std`.
#[cfg(feature = "std")]
#[must_use]
pub fn merkle_root(chunks: &[Chunk]) -> XetHash {
    if chunks.is_empty() {
        return XetHash::ZERO;
    }

    let mut nodes = Vec::from(chunks);
    while nodes.len() > 1 {
        let mut read_index = 0;
        let mut write_index = 0;

        while read_index < nodes.len() {
            let cut = read_index + next_merge_cut(&nodes[read_index..]);
            nodes[write_index] = merge(&nodes[read_index..cut]);
            read_index = cut;
            write_index += 1;
        }

        nodes.truncate(write_index);
    }

    nodes[0].hash
}

/// Computes the Xet xorb hash: the unfinalized Merkle root of its chunks.
#[cfg(feature = "std")]
#[must_use]
pub fn xorb_hash(chunks: &[Chunk]) -> XetHash {
    merkle_root(chunks)
}

/// Computes the Xet file hash (xetHash/ContentId) from its chunks.
///
/// The Merkle root is finalized with BLAKE3 keyed by 32 zero bytes. As in the
/// reference implementation, an empty chunk sequence maps directly to zero.
#[cfg(feature = "std")]
#[must_use]
pub fn file_hash(chunks: &[Chunk]) -> XetHash {
    if chunks.is_empty() {
        return XetHash::ZERO;
    }

    XetHash::from(*blake3::keyed_hash(&ZERO_KEY, merkle_root(chunks).as_bytes()).as_bytes())
}

#[cfg(feature = "std")]
fn next_merge_cut(nodes: &[Chunk]) -> usize {
    if nodes.len() <= 2 {
        return nodes.len();
    }

    let end = nodes.len().min(MAX_GROUP_SIZE);
    for (index, node) in nodes.iter().enumerate().take(end).skip(2) {
        if node.hash.natural_cut_value() % TREE_BRANCHING_FACTOR == 0 {
            return index + 1;
        }
    }
    end
}

#[cfg(feature = "std")]
fn merge(nodes: &[Chunk]) -> Chunk {
    let mut buffer = [0; MAX_MERGE_BUFFER_SIZE];
    let mut position = 0;
    let mut total_len = 0;

    for node in nodes {
        write_hash(&mut buffer, &mut position, node.hash);
        buffer[position..position + 3].copy_from_slice(b" : ");
        position += 3;
        write_decimal(&mut buffer, &mut position, node.data_len);
        buffer[position] = b'\n';
        position += 1;
        total_len += node.data_len;
    }

    let hash = blake3::keyed_hash(&INTERNAL_NODE_KEY, &buffer[..position]);
    Chunk::new(XetHash::from(*hash.as_bytes()), total_len)
}

#[cfg(feature = "std")]
fn write_hash(buffer: &mut [u8], position: &mut usize, hash: XetHash) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for limb in hash.0.as_chunks::<8>().0 {
        for byte in limb.iter().rev() {
            buffer[*position] = HEX[(byte >> 4) as usize];
            buffer[*position + 1] = HEX[(byte & 0x0f) as usize];
            *position += 2;
        }
    }
}

#[cfg(feature = "std")]
fn write_decimal(buffer: &mut [u8], position: &mut usize, value: u64) {
    if value == 0 {
        buffer[*position] = b'0';
        *position += 1;
        return;
    }

    let mut digits = [0; 20];
    let mut digit_start = digits.len();
    let mut remaining = value;
    while remaining > 0 {
        digit_start -= 1;
        digits[digit_start] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
    }

    let digits = &digits[digit_start..];
    buffer[*position..*position + digits.len()].copy_from_slice(digits);
    *position += digits.len();
}

#[cfg(all(test, feature = "chunking"))]
mod tests {
    use super::*;

    #[test]
    fn single_chunk_hasher_matches_full_file_hash() {
        for len in [0, 3, MIN_CHUNK_SIZE - 1] {
            let bytes: Vec<_> = (0..len).map(|index| index as u8).collect();
            let mut hasher = SingleChunkHasher::new();
            hasher.update(&bytes);
            if len == MIN_CHUNK_SIZE - 1 {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hasher.update(&[0])))
                        .is_err()
                );
            }
            assert_eq!(hasher.finalize(), XetHash::hash(&bytes));
        }
    }
}
