//! On-chain object payloads: coins, edges, and initial coin seeds.
//!
//! Abstract counterpart: `models/types.qnt` (the closed-universe `Coin` /
//! `Edge` ADTs and their canonical wiring) plus the conservation, shape,
//! and binding rules in `models/rules/invariants.qnt`.
//!
//! # Assumed of genesis
//!
//! **Genesis is operator-trusted.** [`Genesis`] accepts caller-supplied
//! coin ids and values without authentication — it is the one path that
//! creates value from nothing, and the kernel checks nobody's right to
//! use it. The models bake the same premise in by initializing
//! `MakerCoin` / `TakerCoin` to fixed values in `init`, so no model
//! action can ever exercise a hostile seeding. A deployment must control
//! the genesis-seeding path itself; nothing here does.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    context::{BlockHeight, Cost, Fees},
    error::{InsertError, InvalidCloseReason, InvalidOpenReason, KernelResult},
    list::List,
    primitive::{CoinId, Key, TermsHash},
    store::Batch,
    tx::{Authority, CloseKind, CloseKindSet, Payout},
};

/// Owned UTXO object.
///
/// `owner` is the key that controls the coin outright. `delegate`, when
/// present, is the one other key that may spend it — and only to fund a
/// work open or bond under its own signature, never to produce a coin.
/// Only the owner can set or clear it, and only by consuming the coin in
/// a [`crate::Reshape`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Coin {
    owner: Key,
    delegate: Option<Key>,
    value: u64,
}

impl Coin {
    pub(super) const ZERO: Self = Self::new(Key::from_bytes([0; Key::LENGTH]), None, 0);

    const fn new(owner: Key, delegate: Option<Key>, value: u64) -> Self {
        Self {
            owner,
            delegate,
            value,
        }
    }

    /// Issues a coin from a trusted host state transition.
    ///
    /// This is an issuance path, not a persistence reconstitution path:
    /// stored coins must still be reconstructed through [`Decode`].
    #[must_use]
    pub const fn issue(owner: Key, delegate: Option<Key>, value: u64) -> Self {
        Self::new(owner, delegate, value)
    }

    /// Returns the owner settlement key.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the key this coin is delegated to, if any.
    #[must_use]
    pub const fn delegate(self) -> Option<Key> {
        self.delegate
    }

    /// Returns the coin value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

impl Encode for Coin {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + Key::MAX_ENCODED_SIZE
        + <Option<Key> as Encode>::MAX_ENCODED_SIZE
        + u64::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE + Key::MAX_ENCODED_SIZE + self.delegate.encoded_size() + u64::MAX_ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::COIN);
        self.owner.encode_to(writer);
        self.delegate.encode_to(writer);
        self.value.encode_to(writer);
    }
}

impl Decode for Coin {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::COIN)?;
        let owner = decode_field(buf, &mut consumed)?;
        let delegate = decode_field(buf, &mut consumed)?;
        let value = decode_field(buf, &mut consumed)?;
        Ok((Self::new(owner, delegate, value), consumed))
    }
}

/// The keys one party commits to an edge.
///
/// `owner` is the principal whose coins the party spends and who receives
/// the party's payouts. `signer` is the one other key that may authorize
/// for the party — a node key acting under delegation. `payout_delegate`
/// is the delegate the party's payout coins carry. The party's committed
/// destination is therefore `{ owner, payout_delegate }`: a destination
/// can name no owner but the party's own.
#[derive(Debug, Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct PartyKeys {
    owner: Key,
    signer: Key,
    payout_delegate: Option<Key>,
}

impl PartyKeys {
    /// Creates a party's committed keys.
    #[must_use]
    pub const fn new(owner: Key, signer: Key, payout_delegate: Option<Key>) -> Self {
        Self {
            owner,
            signer,
            payout_delegate,
        }
    }

    /// A party whose owner signs for itself: `owner` and `signer` are the
    /// same key and its payouts are undelegated.
    #[must_use]
    pub const fn sole(key: Key) -> Self {
        Self::new(key, key, None)
    }

    /// Returns the owning principal.
    #[must_use]
    pub const fn owner(self) -> Key {
        self.owner
    }

    /// Returns the key that may sign for the owner.
    #[must_use]
    pub const fn signer(self) -> Key {
        self.signer
    }

    /// Returns the delegate this party's payout coins carry.
    #[must_use]
    pub const fn payout_delegate(self) -> Option<Key> {
        self.payout_delegate
    }

    /// Returns the one key a witness claiming `authority` is verified
    /// against.
    #[must_use]
    pub const fn key(self, authority: Authority) -> Key {
        match authority {
            Authority::Owner => self.owner,
            Authority::Signer => self.signer,
        }
    }

    /// Returns the payout of `value` at this party's committed
    /// destination.
    ///
    /// An owner-signed close issues it undelegated whatever the terms
    /// committed: the owner exercising its own authority is the exit
    /// from a delegation, and a payout that re-armed the delegate would
    /// hand the coin straight back to the key the owner is leaving.
    #[must_use]
    pub const fn payout(self, value: u64, owner_signed: bool) -> Payout {
        let delegate = if owner_signed {
            None
        } else {
            self.payout_delegate
        };
        Payout::delegated(self.owner, delegate, value)
    }

    /// True when `payout` lands exactly at this party's destination:
    /// owner and delegate both, as [`Self::payout`] would issue it.
    #[must_use]
    pub fn is_destination(self, payout: Payout, owner_signed: bool) -> bool {
        payout == self.payout(payout.value(), owner_signed)
    }
}

impl Encode for PartyKeys {
    const MAX_ENCODED_SIZE: usize =
        2 * Key::MAX_ENCODED_SIZE + <Option<Key> as Encode>::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        2 * Key::MAX_ENCODED_SIZE + self.payout_delegate.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        self.owner.encode_to(writer);
        self.signer.encode_to(writer);
        self.payout_delegate.encode_to(writer);
    }
}

impl Decode for PartyKeys {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = 0;
        let owner = decode_field(buf, &mut consumed)?;
        let signer = decode_field(buf, &mut consumed)?;
        let payout_delegate = decode_field(buf, &mut consumed)?;
        Ok((Self::new(owner, signer, payout_delegate), consumed))
    }
}

/// Positional party keys committed by an edge.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Parties {
    maker: PartyKeys,
    taker: PartyKeys,
}

impl Parties {
    /// Creates the positional parties for a bilateral edge.
    #[must_use]
    pub const fn new(maker: PartyKeys, taker: PartyKeys) -> Self {
        Self { maker, taker }
    }

    /// Returns the maker's committed keys.
    #[must_use]
    pub const fn maker(self) -> PartyKeys {
        self.maker
    }

    /// Returns the taker's committed keys.
    #[must_use]
    pub const fn taker(self) -> PartyKeys {
        self.taker
    }

    /// True when `payout` lands exactly at one of the two committed
    /// destinations. Which one, and how often, is free: multiplicity is
    /// not a rule, and zero-value payouts are legal.
    #[must_use]
    pub fn is_destination(self, payout: Payout, owner_signed: bool) -> bool {
        self.maker.is_destination(payout, owner_signed)
            || self.taker.is_destination(payout, owner_signed)
    }
}

impl Encode for Parties {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE + 2 * PartyKeys::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        ENVELOPE_SIZE + self.maker.encoded_size() + self.taker.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::PARTIES);
        self.maker.encode_to(writer);
        self.taker.encode_to(writer);
    }
}

impl Decode for Parties {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::PARTIES)?;
        let maker = decode_field(buf, &mut consumed)?;
        let taker = decode_field(buf, &mut consumed)?;
        Ok((Self::new(maker, taker), consumed))
    }
}

/// Locked channel object governed by open terms.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Edge {
    value: u64,
    reserve: u64,
    close_fees: Fees,
    timeout: BlockHeight,
    parties: Parties,
    terms: TermsHash,
    allowed: CloseKindSet,
}

impl Edge {
    const fn new(
        value: u64,
        reserve: u64,
        close_fees: Fees,
        timeout: BlockHeight,
        parties: Parties,
        terms: TermsHash,
        allowed: CloseKindSet,
    ) -> Self {
        Self {
            value,
            reserve,
            close_fees,
            timeout,
            parties,
            terms,
            allowed,
        }
    }

    /// Builds the edge an open leaves behind: the funding total less the
    /// three debits it is charged.
    ///
    /// Takes the total rather than the coins because the endpoint-facing
    /// projection prices an open it has not submitted, and holds funding
    /// values without holding [`Coin`]s. Summing is the caller's; what
    /// the sum buys is here.
    pub(super) fn open(
        total: u64,
        parties: Parties,
        terms: TermsHash,
        debits: (u64, u64, u64, Fees),
        timeout: BlockHeight,
        allowed: CloseKindSet,
    ) -> Result<Self, InvalidOpenReason> {
        let (open_fee, lifetime_fee, reserve, close_fees) = debits;
        let value = total
            .checked_sub(open_fee)
            .and_then(|after_open_fee| after_open_fee.checked_sub(lifetime_fee))
            .and_then(|after_fee| after_fee.checked_sub(reserve))
            .ok_or(InvalidOpenReason::FundingInsufficient)?;
        Ok(Self::new(
            value, reserve, close_fees, timeout, parties, terms, allowed,
        ))
    }

    /// Validates a close against the edge's locked principal and reserve,
    /// returning the value it distributes.
    ///
    /// Payouts must sum to the principal locked at open plus the part of the
    /// open-time close reserve not consumed by this close kind. The committed
    /// close fee is priced by the fee schedule stored on the edge at open time,
    /// so current block fees cannot make an already-open edge unclosable.
    ///
    /// The distributed total is returned rather than discarded because
    /// the work-payment proofs derive their payout split from it, and a
    /// second [`Self::close_value`] call there would be a second place
    /// for the two to disagree.
    pub(super) fn closes<const N: usize>(
        self,
        coins: &List<(CoinId, Coin), N>,
        close_cost: Cost,
    ) -> Result<u64, InvalidCloseReason> {
        let expected = self
            .close_value(close_cost)
            .ok_or(InvalidCloseReason::ReserveTooSmall)?;
        match Self::total(coins) {
            None => Err(InvalidCloseReason::PayoutOverflow),
            Some(total) if total != expected => Err(InvalidCloseReason::ValueMismatch),
            Some(_) => Ok(expected),
        }
    }

    pub(super) fn close_value(self, close_cost: Cost) -> Option<u64> {
        self.values().close_value(close_cost)
    }

    /// Returns the three numbers a close distributes from.
    ///
    /// The projection exists because the work-payment settlement
    /// arithmetic is public and an endpoint cannot hold an [`Edge`]: it
    /// reads a finalized edge's values from a light client. Keeping the
    /// formula on the values, and this type as the only way to reach it,
    /// is what stops the endpoint's copy from being a second formula.
    #[must_use]
    pub const fn values(self) -> EdgeValues {
        EdgeValues {
            value: self.value,
            reserve: self.reserve,
            close_fees: self.close_fees,
        }
    }

    fn total<const N: usize>(coins: &List<(CoinId, Coin), N>) -> Option<u64> {
        coins.checked_sum(|(_, coin)| coin.value())
    }

    /// Returns the value locked by this edge.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the close reserve locked when this edge opened.
    #[must_use]
    pub const fn reserve(self) -> u64 {
        self.reserve
    }

    /// Returns the fee schedule committed for future close execution.
    #[must_use]
    pub const fn close_fees(self) -> Fees {
        self.close_fees
    }

    /// Returns the block height at which timeout fallback becomes available.
    #[must_use]
    pub const fn timeout(self) -> BlockHeight {
        self.timeout
    }

    /// Returns the positional parties committed by this edge.
    #[must_use]
    pub const fn parties(self) -> Parties {
        self.parties
    }

    /// Returns the commitment to the terms that opened this edge.
    #[must_use]
    pub const fn terms(self) -> TermsHash {
        self.terms
    }

    /// Returns the close kinds committed by the opening terms.
    #[must_use]
    pub const fn allowed_closes(self) -> CloseKindSet {
        self.allowed
    }

    /// Returns true when the opening terms admit this close kind.
    #[must_use]
    pub const fn allows(self, kind: CloseKind) -> bool {
        self.allowed.contains(kind)
    }
}

/// The locked principal, the close reserve, and the fee schedule that
/// prices the reserve: everything a close distributes from.
///
/// Deliberately not the whole edge. An endpoint reconstructs these three
/// numbers from a finalized light-client read and asks the kernel what
/// they settle to; it has no store, no terms body, and no business
/// forming an [`Edge`].
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct EdgeValues {
    value: u64,
    reserve: u64,
    close_fees: Fees,
}

impl EdgeValues {
    /// Creates the value projection of a finalized edge.
    #[must_use]
    pub const fn new(value: u64, reserve: u64, close_fees: Fees) -> Self {
        Self {
            value,
            reserve,
            close_fees,
        }
    }

    /// Returns the principal locked by the edge.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the close reserve locked when the edge opened.
    #[must_use]
    pub const fn reserve(self) -> u64 {
        self.reserve
    }

    /// Returns the fee schedule committed for future close execution.
    #[must_use]
    pub const fn close_fees(self) -> Fees {
        self.close_fees
    }

    /// Returns what a close of this cost distributes: the principal plus
    /// the part of the open-time reserve that close does not consume.
    ///
    /// `None` when the committed reserve does not cover the committed
    /// fee, or when the sum would wrap. The fee comes from the schedule
    /// stored at open, so current block fees cannot strand an open edge.
    pub(crate) fn close_value(self, close_cost: Cost) -> Option<u64> {
        let fee = self.close_fees.charge(close_cost)?;
        let surplus = self.reserve.checked_sub(fee)?;
        self.value.checked_add(surplus)
    }
}

impl Encode for Edge {
    const MAX_ENCODED_SIZE: usize = ENVELOPE_SIZE
        + 2 * u64::MAX_ENCODED_SIZE
        + Fees::MAX_ENCODED_SIZE
        + BlockHeight::MAX_ENCODED_SIZE
        + Parties::MAX_ENCODED_SIZE
        + TermsHash::MAX_ENCODED_SIZE
        + CloseKindSet::MAX_ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::MAX_ENCODED_SIZE - Parties::MAX_ENCODED_SIZE + self.parties.encoded_size()
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::EDGE);
        self.value.encode_to(writer);
        self.reserve.encode_to(writer);
        self.close_fees.encode_to(writer);
        self.timeout.encode_to(writer);
        self.parties.encode_to(writer);
        self.terms.encode_to(writer);
        self.allowed.encode_to(writer);
    }
}

impl Decode for Edge {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::EDGE)?;
        let value = decode_field(buf, &mut consumed)?;
        let reserve = decode_field(buf, &mut consumed)?;
        let close_fees = decode_field(buf, &mut consumed)?;
        let timeout = decode_field(buf, &mut consumed)?;
        let parties = decode_field(buf, &mut consumed)?;
        let terms = decode_field(buf, &mut consumed)?;
        let allowed = decode_field(buf, &mut consumed)?;
        Ok((
            Self::new(value, reserve, close_fees, timeout, parties, terms, allowed),
            consumed,
        ))
    }
}

/// Initial coin seed.
///
/// `Genesis` values populate a [`crate::Store`] before it is wrapped in a
/// [`crate::State`]. Every other [`Coin`] and every [`Edge`] originates from a
/// [`crate::Tx`] applied against existing state.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Genesis {
    id: CoinId,
    coin: Coin,
}

impl Genesis {
    /// Creates an initial coin seed.
    ///
    /// The id is trusted chain configuration. Prefer ids derived via
    /// [`CoinId::genesis`]: a hand-picked id that collides with a future
    /// payout id (`H(payout ‖ edge ‖ index ‖ owner)`) would permanently
    /// block that close path with [`crate::ApplyError::OutputExists`].
    #[must_use]
    pub const fn coin(id: CoinId, owner: Key, value: u64) -> Self {
        Self {
            id,
            coin: Coin::new(owner, None, value),
        }
    }

    pub(super) fn insert<B: Batch>(&self, batch: &mut B) -> KernelResult<(), InsertError> {
        batch.insert_coin(self.id, self.coin)
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "codec tests intentionally inspect exact bytes and fail loudly"
)]
mod tests {
    use super::*;

    fn assert_canonical_round_trip<T>(value: T, buf: &mut [u8])
    where
        T: Copy + core::fmt::Debug + Decode + Encode + PartialEq,
    {
        let written = value.write_to(buf);
        assert_eq!(written, value.encoded_size());
        assert!(written < buf.len());
        assert_eq!(T::decode_exact(&buf[..written]), Ok(value));

        for end in 0..written {
            assert!(T::decode_exact(&buf[..end]).is_err());
        }

        buf[written] = 0xa5;
        assert_eq!(
            T::decode_exact(&buf[..=written]),
            Err(DecodeError::TrailingBytes { remaining: 1 }),
        );
    }

    #[test]
    fn private_coin_and_edge_payloads_round_trip_only_through_their_codecs() {
        let coin = Coin::new(Key::from_bytes([1; Key::LENGTH]), None, 23);
        let mut coin_buf = [0; Coin::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(coin, &mut coin_buf);
        assert_eq!(&coin_buf[..2], &[1, tag::COIN]);
        let delegated = Coin::new(
            Key::from_bytes([1; Key::LENGTH]),
            Some(Key::from_bytes([9; Key::LENGTH])),
            23,
        );
        let mut delegated_buf = [0; Coin::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(delegated, &mut delegated_buf);
        assert_eq!(delegated.encoded_size(), Coin::MAX_ENCODED_SIZE);

        let edge = Edge::new(
            100,
            10,
            Fees::new(1, 2, 3, 4),
            BlockHeight::new(99),
            Parties::new(
                PartyKeys::sole(Key::from_bytes([2; Key::LENGTH])),
                PartyKeys::new(
                    Key::from_bytes([3; Key::LENGTH]),
                    Key::from_bytes([5; Key::LENGTH]),
                    Some(Key::from_bytes([6; Key::LENGTH])),
                ),
            ),
            TermsHash::from_bytes([4; TermsHash::LENGTH]),
            CloseKindSet::BASIC,
        );
        let mut edge_buf = [0; Edge::MAX_ENCODED_SIZE + 1];
        assert_canonical_round_trip(edge, &mut edge_buf);
        assert_eq!(&edge_buf[..2], &[1, tag::EDGE]);

        assert_eq!(
            Edge::decode_exact(&coin_buf[..coin.encoded_size()]),
            Err(DecodeError::InvalidTag { tag: tag::COIN }),
        );
        assert_eq!(
            Coin::decode_exact(&edge_buf[..edge.encoded_size()]),
            Err(DecodeError::InvalidTag { tag: tag::EDGE }),
        );
    }
}
