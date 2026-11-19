//! The network a signature authorizes an action *on*.
//!
//! # Namespace the authorization, never the address
//!
//! Every payload a party signs to authorize a kernel operation commits
//! to a [`NetworkId`]. Without it a signature says "I authorize this
//! open" rather than "I authorize this open *here*", and the same
//! witness is valid on every deployment that can reproduce the inputs —
//! the replay EIP-155 exists to close.
//!
//! Object identifiers deliberately do **not** carry it. A [`CoinId`] or
//! [`EdgeId`] only has meaning inside one network's state, so two
//! networks minting the same id is harmless; the ambiguity that matters
//! lives in the signature naming the id, which the rule above covers.
//! Content commitments must not carry it either — Xet ids are
//! content-addressed on purpose, and namespacing them would break dedup
//! and portability for no security gain.
//!
//! [`CoinId`]: crate::CoinId
//! [`EdgeId`]: crate::EdgeId
//!
//! # Not a validator
//!
//! [`NetworkId::new`] bounds the length and nothing else. The genesis
//! document is the single authority on what a legal network id string
//! is (`hellas_chain::genesis::Genesis::validate`); re-stating its token rule
//! here would be a second copy of a rule that must agree with the
//! first. The kernel only needs bytes to separate domains with.

use crate::canonical::{Encode, Writer};

/// Longest network id the kernel carries, in bytes.
///
/// Matches the genesis document's own bound, so any id that document
/// admits fits here without truncation.
pub const MAX_NETWORK_ID_LENGTH: usize = 63;

/// The network a kernel authorization is bound to.
///
/// `Copy` and allocation-free: it rides in [`crate::Context`] and is
/// written into every authorization hash, so it has to be as cheap to
/// pass as the block height beside it.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct NetworkId {
    bytes: [u8; MAX_NETWORK_ID_LENGTH],
    len: u8,
}

impl NetworkId {
    /// Creates a network id from `id`, or `None` if it is empty or
    /// longer than [`MAX_NETWORK_ID_LENGTH`] bytes.
    ///
    /// `const` so a deployment's network can be a `const` item beside
    /// the other consensus constants it has to agree on.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "the loop bound is source.len(), checked against the buffer above"
    )]
    pub const fn new(id: &str) -> Option<Self> {
        let source = id.as_bytes();
        if source.is_empty() || source.len() > MAX_NETWORK_ID_LENGTH {
            return None;
        }
        let mut bytes = [0_u8; MAX_NETWORK_ID_LENGTH];
        let mut index = 0;
        while index < source.len() {
            bytes[index] = source[index];
            index += 1;
        }
        #[allow(clippy::cast_possible_truncation)]
        Some(Self {
            bytes,
            len: source.len() as u8,
        })
    }

    /// Borrows the id bytes, without the trailing padding.
    #[must_use]
    #[allow(
        clippy::indexing_slicing,
        reason = "`new` is the only constructor and establishes len <= MAX_NETWORK_ID_LENGTH"
    )]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// Borrows the id as the string it was built from.
    ///
    /// The fallback is unreachable: [`Self::new`] copies whole `&str`
    /// bytes and retains a prefix it never splits, so the stored bytes
    /// are always the original UTF-8. It exists so this accessor is
    /// total rather than panicking on a state it cannot be in.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("<non-utf8 network id>")
    }
}

impl core::fmt::Debug for NetworkId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NetworkId({})", self.as_str())
    }
}

impl core::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Encode for NetworkId {
    const MAX_ENCODED_SIZE: usize = 1 + MAX_NETWORK_ID_LENGTH;

    fn encoded_size(&self) -> usize {
        1 + self.len as usize
    }

    /// Length-prefixed, so `"a" ‖ "bc"` and `"ab" ‖ "c"` can never hash
    /// alike when a variable-width id sits next to another field.
    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        writer.write(&[self.len]);
        writer.write(self.as_bytes());
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "test constants are legal ids and in-bounds"
)]
mod tests {
    use super::*;
    use crate::BufferWriter;

    /// Encodes into `buf` and returns the written prefix.
    fn encoded(network: NetworkId, buf: &mut [u8]) -> &[u8] {
        let mut writer = BufferWriter::new(buf);
        network.encode_to(&mut writer);
        let len = writer.position();
        assert_eq!(len, network.encoded_size());
        &buf[..len]
    }

    #[test]
    fn round_trips_the_id_it_was_built_from() {
        let network = NetworkId::new("test-network").expect("legal id");
        assert_eq!(network.as_str(), "test-network");
        assert_eq!(network.as_bytes(), b"test-network");
    }

    #[test]
    fn rejects_empty_and_oversized_ids() {
        let filled = [b'a'; MAX_NETWORK_ID_LENGTH + 1];
        let longest = core::str::from_utf8(&filled[..MAX_NETWORK_ID_LENGTH]).expect("ascii");
        let too_long = core::str::from_utf8(&filled).expect("ascii");

        assert_eq!(NetworkId::new(""), None);
        assert_eq!(NetworkId::new(too_long), None);
        assert!(NetworkId::new(longest).is_some());
    }

    #[test]
    fn padding_never_reaches_the_encoding() {
        let mut buf = [0_u8; NetworkId::MAX_ENCODED_SIZE];
        let short = NetworkId::new("a").expect("legal id");
        assert_eq!(encoded(short, &mut buf), &[1, b'a']);
    }

    #[test]
    fn length_prefix_separates_ids_that_would_otherwise_concatenate() {
        // Without the prefix, `"ab" ‖ "c"` and `"a" ‖ "bc"` collide.
        let mut left_buf = [0_u8; NetworkId::MAX_ENCODED_SIZE + 2];
        let mut right_buf = [0_u8; NetworkId::MAX_ENCODED_SIZE + 2];

        let left = NetworkId::new("ab").expect("legal id");
        let left_len = encoded(left, &mut left_buf).len();
        left_buf[left_len] = b'c';

        let right = NetworkId::new("a").expect("legal id");
        let right_len = encoded(right, &mut right_buf).len();
        right_buf[right_len] = b'b';
        right_buf[right_len + 1] = b'c';

        assert_ne!(left_buf[..=left_len], right_buf[..=right_len + 1]);
    }
}
