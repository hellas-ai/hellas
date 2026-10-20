//! Coin payout requested by an edge close or a reshape.
//!
//! Abstract counterpart: the per-position payout entries in
//! `models/l1.qnt::closeEdge`. The kernel materializes one coin per
//! `Payout`, with a canonical id derived from the consumed edge (or the
//! consumed reshape inputs) and the position of the payout.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    object::Coin,
    primitive::{CoinId, EdgeId, Key},
};

/// Coin payout requested by an edge close or a reshape.
///
/// It names the coin exactly as it will be issued, delegate included:
/// what a close carries is what the chain stores, so a host that indexes
/// the transaction without running the kernel reads the same coin.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Payout {
    owner: Key,
    delegate: Option<Key>,
    value: u64,
}

impl Encode for Payout {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + Key::MAX_ENCODED_SIZE
        + <Option<Key> as Encode>::MAX_ENCODED_SIZE
        + u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE + Key::MAX_ENCODED_SIZE + self.delegate.encoded_size() + u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PAYOUT);
        self.owner.encode_to(writer);
        self.delegate.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl Decode for Payout {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PAYOUT)?;
        let owner = decode_field(buf, &mut consumed)?;
        let delegate = decode_field(buf, &mut consumed)?;
        let value = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                owner,
                delegate,
                value,
            },
            consumed,
        ))
    }
}

impl Payout {
    /// Creates an undelegated payout.
    #[must_use]
    pub const fn new(owner: Key, value: u64) -> Self {
        Self::delegated(owner, None, value)
    }

    /// Creates a payout whose coin carries `delegate`.
    #[must_use]
    pub const fn delegated(owner: Key, delegate: Option<Key>, value: u64) -> Self {
        Self {
            owner,
            delegate,
            value,
        }
    }

    /// Returns the output coin owner.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the delegate the output coin carries, if any.
    #[must_use]
    pub const fn delegate(self) -> Option<Key> {
        self.delegate
    }

    /// Returns the output coin value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Derives the canonical output coin id for this close payout position.
    #[must_use]
    pub fn id(self, edge: EdgeId, index: usize) -> CoinId {
        CoinId::payout(edge, index, self.owner)
    }

    /// Returns the coin this payout issues.
    pub(crate) const fn coin(self) -> Coin {
        Coin::issue(self.owner, self.delegate, self.value)
    }

    pub(super) fn close_coin(self, edge: EdgeId, index: usize) -> (CoinId, Coin) {
        (self.id(edge, index), self.coin())
    }
}
