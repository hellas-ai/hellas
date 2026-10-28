#![allow(clippy::redundant_pub_crate)]

//! The exclusive bond lease: the record a payment channel takes out
//! against the stake that insures it.
//!
//! # Why a bond needs a lease at all
//!
//! A work-stake bond is one provider's stake and one client's recourse.
//! Nothing in the bond edge itself says which channel it is currently
//! insuring, and without that the same stake could back several payment
//! channels at once — every one of them priced as if it had the whole
//! stake to slash. The lease is the record that makes the bond
//! exclusive: a payment open creates it, and a second payment open
//! naming the same bond finds the slots occupied and is refused.
//!
//! It is also what tells a bond close whether anyone still has recourse
//! against it. An unleased bond has no challenge exposure, so its
//! `Timeout` is immediate; a leased one must wait for the admission
//! horizon it committed to.
//!
//! # Two chunks, and why absence is decided by both
//!
//! The record is 139 canonical bytes, so it spans two
//! [`RegistryChunk`]s. "No lease" therefore means *both* derived slots
//! are empty, and every other shape — one present chunk, a wrong chunk
//! count, a value that does not decode, a record naming another bond —
//! is a fault rather than absence. A close that read a half-written or
//! corrupted lease as "unleased" would take the immediate exit out from
//! under a live channel's recourse.
//!
//! # What the lease does not decide
//!
//! Nothing about the money. The scalar a channel settles at, the contest
//! that establishes it, and the payouts it produces are all
//! [`crate::work`]'s and [`crate::tx::work`]'s, and none of them reads
//! this record: the lease is checked once, at payment open, because the
//! payment edge's own id already commits to the bond it names (see the
//! `bond_edge` field of [`crate::WorkPaymentTerms`]). Nothing of the
//! correctness game is here either — no live-game pointer and no
//! challenged bitmap. A field no transition writes is not state held
//! ready for later, it is 288 bits of consensus surface every node
//! stores and no rule reads, so the game slice adds its own record
//! shape with the transitions that mutate it.
//!
//! Abstract counterpart: none. Like the rest of the registry, the lease
//! has no Quint var and no ITF trace; `models/registry.md` records which
//! properties that leaves to Rust tests alone — including bond
//! exclusivity itself.

use crate::{
    canonical::{
        Decode, DecodeError, ENVELOPE_SIZE, Encode, Writer, decode_envelope, decode_field,
        encode_envelope, tag,
    },
    consts::HASH_LENGTH,
    error::BondLeaseFault,
    network::NetworkId,
    primitive::{EdgeId, TermsHash},
    registry::{
        RegistryChunk, RegistryChunkId, RegistryMutation, RegistryNamespace, RegistryRecordTag,
    },
    store::Batch,
};

/// Body version every bond-lease record carries. Decode rejects any
/// other value, so one body shape has exactly one meaning.
const BOND_LEASE_VERSION: u8 = 2;

/// Chunks one lease value occupies.
///
/// Derived from the record's fixed width by the same rule
/// [`RegistryChunk::split`] applies, and asserted below rather than
/// trusted: the count decides how many slots a reader consults, and a
/// count that disagreed with the encoding would make a complete lease
/// look partial.
pub const BOND_LEASE_CHUNKS: u8 = 2;

/// A payment open writes every chunk of the lease in one diff, and a
/// leased bond's timeout deletes every chunk of it in one diff. That
/// makes this record the widest registry write the kernel makes, and
/// [`crate::MAX_REGISTRY_MUTATIONS`] is set to it rather than beside it.
const _: () = assert!(
    BOND_LEASE_CHUNKS as usize <= crate::consts::MAX_REGISTRY_MUTATIONS,
    "a lease must fit one registry diff"
);

/// The exclusive lease one payment channel holds over one work-stake
/// bond.
///
/// Created whole by the payment open and never partially written: the
/// two chunks are one atomic registry diff, so no block can commit a
/// lease that only half exists.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct BondLease {
    bond_edge: EdgeId,
    // `payment_edge` is read: it is what separates "this bond is leased
    // by my channel" from "this bond is leased by somebody else", which
    // is a different answer and a different outcome at both endpoint
    // sites that ask — `hellas_channel::model::setup`'s readiness
    // gate and `hellas_channel::work_store::setup`'s recovery decision,
    // whose `LeasedElsewhere` fault has no other source. `bond_edge`
    // alone cannot say it: every lease on this bond names this bond.
    //
    // The three below are written by the payment open and read by no
    // production path in this crate or its hosts. The horizon a timeout
    // waits for is the bond edge's own `Terms::timeout()`, not this copy
    // of it, and the terms hash and policy commitment are read from the
    // live payment terms. They are carried, not deleted, because their
    // deletion is not separable from the record's shape: any one of them
    // gone takes the encoding under 121 bytes, which takes the lease to
    // one chunk, which makes `BondLeaseFault::Partial` and the
    // two-chunk reassembly rules unreachable. That is §2.3 of
    // `workflows/roadmap/compute-flow-plan.md`, a consensus-schema step
    // with its own recomputed goldens — not a field deletion.
    payment_edge: EdgeId,
    payment_terms_hash: TermsHash,
    private_policy_commitment: [u8; HASH_LENGTH],
    admission_horizon: u64,
}

impl BondLease {
    /// Canonical encoded length, envelope included.
    pub const ENCODED_SIZE: usize = ENVELOPE_SIZE
        + u8::MAX_ENCODED_SIZE
        + 2 * EdgeId::MAX_ENCODED_SIZE
        + TermsHash::MAX_ENCODED_SIZE
        + HASH_LENGTH
        + u64::MAX_ENCODED_SIZE;

    /// Creates the lease a payment open takes out over `bond_edge`.
    ///
    /// Every field is fixed here and never written again: the record has
    /// no mutable part, so the only transitions over a lease are the
    /// open that creates it whole and the bond timeout that deletes it
    /// whole.
    #[must_use]
    pub(crate) const fn opened(
        bond_edge: EdgeId,
        payment_edge: EdgeId,
        payment_terms_hash: TermsHash,
        private_policy_commitment: [u8; HASH_LENGTH],
        admission_horizon: u64,
    ) -> Self {
        Self {
            bond_edge,
            payment_edge,
            payment_terms_hash,
            private_policy_commitment,
            admission_horizon,
        }
    }

    /// Returns the bond this lease is held over.
    #[must_use]
    pub const fn bond_edge(&self) -> EdgeId {
        self.bond_edge
    }

    /// Returns the payment channel holding the lease.
    #[must_use]
    pub const fn payment_edge(&self) -> EdgeId {
        self.payment_edge
    }

    /// Returns the payment terms the lease is bound to.
    #[must_use]
    pub const fn payment_terms_hash(&self) -> TermsHash {
        self.payment_terms_hash
    }

    /// Returns the channel's salted private-policy commitment.
    #[must_use]
    pub const fn private_policy_commitment(&self) -> [u8; HASH_LENGTH] {
        self.private_policy_commitment
    }

    /// Returns the height at and after which no further job is admitted.
    #[must_use]
    pub const fn admission_horizon(&self) -> u64 {
        self.admission_horizon
    }

    /// Returns this record packed into its chunks, in slot order.
    ///
    /// `None` is unreachable for a record of this fixed width — the
    /// encoding is 139 bytes and two chunks carry 240 — and is kept a
    /// rejection rather than a panic because this runs on the apply
    /// path.
    #[must_use]
    pub(crate) fn to_chunks(self) -> Option<[RegistryChunk; BOND_LEASE_CHUNKS as usize]> {
        let mut buf = [0_u8; Self::ENCODED_SIZE];
        let written = self.write_to(&mut buf);
        let value = buf.get(..written)?;
        Some([
            RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                value,
                0,
            )?,
            RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                value,
                1,
            )?,
        ])
    }

    /// Reads the record the two stored chunks hold.
    ///
    /// Every way a present pair can fail to be this bond's lease is a
    /// fault, never absence: reassembly is refused unless both chunks
    /// agree on the record they belong to, occupy their own index, and
    /// carry exactly this record's width.
    fn from_chunks(
        chunks: [RegistryChunk; BOND_LEASE_CHUNKS as usize],
        bond_edge: EdgeId,
    ) -> Result<Self, BondLeaseFault> {
        let mut buf = [0_u8; Self::ENCODED_SIZE];
        let mut written = 0_usize;
        for (index, chunk) in chunks.iter().enumerate() {
            let expected_index = u8::try_from(index).map_err(|_| BondLeaseFault::Shape)?;
            if chunk.namespace() != RegistryNamespace::BondLease
                || chunk.record_tag() != RegistryRecordTag::BondLease
                || chunk.chunk_count() != BOND_LEASE_CHUNKS
                || chunk.chunk_index() != expected_index
                || usize::from(chunk.value_len()) != Self::ENCODED_SIZE
            {
                return Err(BondLeaseFault::Shape);
            }
            let data = chunk.data();
            let end = written
                .checked_add(data.len())
                .ok_or(BondLeaseFault::Shape)?;
            buf.get_mut(written..end)
                .ok_or(BondLeaseFault::Shape)?
                .copy_from_slice(data);
            written = end;
        }
        // Reassembly consumes exactly `value_len` bytes: the per-chunk
        // `data_len` rule already fixes each chunk's live width for its
        // index, so a pair that passed the checks above spans the
        // record exactly. The equality is spelled out because the
        // decoder below is handed this slice and would otherwise
        // silently accept a shorter one as "insufficient bytes".
        if written != Self::ENCODED_SIZE {
            return Err(BondLeaseFault::Shape);
        }
        let lease = buf
            .get(..written)
            .ok_or(BondLeaseFault::Shape)
            .and_then(|value| Self::decode_exact(value).map_err(|_| BondLeaseFault::Body))?;
        if lease.bond_edge != bond_edge {
            return Err(BondLeaseFault::Edge);
        }
        Ok(lease)
    }
}

/// Returns the registry slot holding chunk `chunk_index` of the lease on
/// `bond_edge`.
///
/// One derivation, used by the kernel transitions and by the host that
/// preloads the slots for them. A host that derived its own would
/// preload a slot the kernel never reads.
#[must_use]
pub fn bond_lease_slot(network: NetworkId, bond_edge: EdgeId, chunk_index: u8) -> RegistryChunkId {
    RegistryChunkId::derive(
        network,
        RegistryNamespace::BondLease,
        bond_edge.to_bytes(),
        chunk_index,
    )
}

/// Returns both registry slots the lease on `bond_edge` occupies, in
/// order.
#[must_use]
pub fn bond_lease_slots(
    network: NetworkId,
    bond_edge: EdgeId,
) -> [RegistryChunkId; BOND_LEASE_CHUNKS as usize] {
    [
        bond_lease_slot(network, bond_edge, 0),
        bond_lease_slot(network, bond_edge, 1),
    ]
}

/// What was found in the two slots that hold one bond's lease.
///
/// Three states, not two. A present pair that is not this bond's whole
/// lease is its own answer precisely because reading it as absence is
/// the mistake this type exists to make unrepresentable: absence is a
/// permission — it lets a payment open take the stake and lets a bond
/// take its immediate timeout — so anything that could be mistaken for
/// it has to be a distinct answer.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum LeaseSlots {
    /// Both derived slots are empty.
    Absent,
    /// Both derived slots together hold this bond's readable lease.
    Present(BondLease),
    /// The slots hold something that is not this bond's whole lease.
    Faulty(BondLeaseFault),
}

/// Reads the lease `bond_edge` holds out of the chunks its two derived
/// slots contain.
///
/// Pure, and public, because an endpoint deciding whether a channel is
/// usable asks exactly the question a bond timeout asks, and two answers
/// to it is one answer too many. Callers off the apply path supply the
/// slots from wherever they read them; [`bond_lease_slots`] is the one
/// derivation of which slots those are.
#[must_use]
pub fn parse_bond_lease(
    slots: [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize],
    bond_edge: EdgeId,
) -> LeaseSlots {
    match slots {
        [None, None] => LeaseSlots::Absent,
        [Some(first), Some(second)] => match BondLease::from_chunks([first, second], bond_edge) {
            Ok(lease) => LeaseSlots::Present(lease),
            Err(fault) => LeaseSlots::Faulty(fault),
        },
        // A lease is written whole or not at all, so one occupied slot
        // is not a lease being built: it is state no transition of this
        // kernel could have produced.
        [Some(_), None] | [None, Some(_)] => LeaseSlots::Faulty(BondLeaseFault::Partial),
    }
}

/// Reads the lease on `bond_edge` from the staged batch.
///
/// Both slots are consulted on every call, and both are charged: the
/// answer "unleased" is only sound when nothing is in either of them,
/// so a reader that stopped at the first empty slot would be answering
/// a different question than the one the caller asked.
pub(crate) fn read_bond_lease<B: Batch>(
    batch: &B,
    network: NetworkId,
    bond_edge: EdgeId,
) -> Result<Option<BondLease>, BondLeaseFault> {
    let stored = bond_lease_slots(network, bond_edge).map(|slot| batch.registry_chunk(slot));
    match parse_bond_lease(stored, bond_edge) {
        LeaseSlots::Absent => Ok(None),
        LeaseSlots::Present(lease) => Ok(Some(lease)),
        LeaseSlots::Faulty(fault) => Err(fault),
    }
}

/// Returns the mutations that create the lease `lease` occupies.
pub(crate) fn create_mutations(
    network: NetworkId,
    lease: BondLease,
) -> Option<[RegistryMutation; BOND_LEASE_CHUNKS as usize]> {
    let slots = bond_lease_slots(network, lease.bond_edge());
    let chunks = lease.to_chunks()?;
    Some([
        RegistryMutation::write(slots[0], chunks[0]),
        RegistryMutation::write(slots[1], chunks[1]),
    ])
}

/// Returns the mutations that delete the lease on `bond_edge`.
pub(crate) fn delete_mutations(
    network: NetworkId,
    bond_edge: EdgeId,
) -> [RegistryMutation; BOND_LEASE_CHUNKS as usize] {
    bond_lease_slots(network, bond_edge).map(RegistryMutation::delete)
}

impl Encode for BondLease {
    const MAX_ENCODED_SIZE: usize = Self::ENCODED_SIZE;

    fn encoded_size(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to<W: Writer + ?Sized>(&self, writer: &mut W) {
        encode_envelope(writer, tag::BOND_LEASE);
        BOND_LEASE_VERSION.encode_to(writer);
        self.bond_edge.encode_to(writer);
        self.payment_edge.encode_to(writer);
        self.payment_terms_hash.encode_to(writer);
        self.private_policy_commitment.encode_to(writer);
        // Raw eight bytes, not the `BlockHeight` composite: §0.1 fixes
        // every height inside a registry record as a bare `u64`.
        self.admission_horizon.encode_to(writer);
    }
}

impl Decode for BondLease {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut consumed = decode_envelope(buf, tag::BOND_LEASE)?;
        let version = decode_field::<u8>(buf, &mut consumed)?;
        if version != BOND_LEASE_VERSION {
            return Err(DecodeError::InvalidTag { tag: version });
        }
        let bond_edge = decode_field(buf, &mut consumed)?;
        let payment_edge = decode_field(buf, &mut consumed)?;
        let payment_terms_hash = decode_field(buf, &mut consumed)?;
        let private_policy_commitment = decode_field(buf, &mut consumed)?;
        let admission_horizon = decode_field(buf, &mut consumed)?;
        Ok((
            Self {
                bond_edge,
                payment_edge,
                payment_terms_hash,
                private_policy_commitment,
                admission_horizon,
            },
            consumed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::REGISTRY_CHUNK_DATA_CAPACITY;

    fn bond() -> EdgeId {
        EdgeId::from_bytes([0x11; EdgeId::LENGTH])
    }

    fn sample_lease() -> BondLease {
        BondLease::opened(
            bond(),
            EdgeId::from_bytes([0x22; EdgeId::LENGTH]),
            TermsHash::from_bytes([0x33; TermsHash::LENGTH]),
            [0x44; HASH_LENGTH],
            9_000,
        )
    }

    fn chunks_of(lease: BondLease) -> [RegistryChunk; BOND_LEASE_CHUNKS as usize] {
        let Some(chunks) = lease.to_chunks() else {
            panic!("a fixed-width lease always splits");
        };
        chunks
    }

    /// The one answer both a bond timeout and an endpoint's readiness
    /// gate take, over every shape the two slots can be in.
    ///
    /// Each case differs from the accepted one in exactly one way, so no
    /// case is satisfied by a neighbour's reason for failing.
    #[test]
    fn parse_bond_lease_separates_absence_from_every_fault() {
        let lease = sample_lease();
        let [first, second] = chunks_of(lease);

        assert_eq!(parse_bond_lease([None, None], bond()), LeaseSlots::Absent);
        assert_eq!(
            parse_bond_lease([Some(first), Some(second)], bond()),
            LeaseSlots::Present(lease),
        );

        // One occupied slot: state no transition of this kernel wrote.
        assert_eq!(
            parse_bond_lease([Some(first), None], bond()),
            LeaseSlots::Faulty(BondLeaseFault::Partial),
        );
        assert_eq!(
            parse_bond_lease([None, Some(second)], bond()),
            LeaseSlots::Faulty(BondLeaseFault::Partial),
        );

        // Both halves present, in the wrong slots.
        assert_eq!(
            parse_bond_lease([Some(second), Some(first)], bond()),
            LeaseSlots::Faulty(BondLeaseFault::Shape),
        );

        // A whole readable lease, over another bond.
        assert_eq!(
            parse_bond_lease(
                [Some(first), Some(second)],
                EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
            ),
            LeaseSlots::Faulty(BondLeaseFault::Edge),
        );

        // Right shape, right width, right slots: only the body's
        // version byte moves, which is what separates `Body` from
        // `Shape`.
        let mut value = [0_u8; BondLease::ENCODED_SIZE];
        let written = lease.write_to(&mut value);
        assert_eq!(written, BondLease::ENCODED_SIZE);
        let version = ENVELOPE_SIZE;
        let Some(byte) = value.get_mut(version) else {
            panic!("the version byte follows the envelope");
        };
        assert_eq!(*byte, BOND_LEASE_VERSION);
        *byte = BOND_LEASE_VERSION.wrapping_add(1);
        let corrupt = [0, 1].map(|index| {
            let Some(chunk) = RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                &value,
                index,
            ) else {
                panic!("a fixed-width value always splits");
            };
            Some(chunk)
        });
        assert_eq!(
            parse_bond_lease(corrupt, bond()),
            LeaseSlots::Faulty(BondLeaseFault::Body),
        );
    }

    /// The record's width decides how many slots every reader consults,
    /// so the two have to be derived from one another rather than
    /// declared side by side.
    #[test]
    fn the_lease_is_exactly_two_registry_chunks() {
        assert_eq!(BondLease::ENCODED_SIZE, 139);
        assert_eq!(
            RegistryChunk::chunk_count_for(BondLease::ENCODED_SIZE),
            Some(BOND_LEASE_CHUNKS),
        );
        const { assert!(BondLease::ENCODED_SIZE > REGISTRY_CHUNK_DATA_CAPACITY) };
    }
}
