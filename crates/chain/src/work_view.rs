//! The one coherent finalized read a paid work channel is decided from.
//!
//! # Why one read rather than several
//!
//! A work channel is four pieces of consensus state: the tag-4 bond
//! edge, the tag-2 payment edge, the bond's lease slots, and the payment
//! edge's pending-close slot. An endpoint that fetched them one at a
//! time would be answering from up to four different states, and the
//! combinations that produces are not hypothetical — a payment edge from
//! before a contest opened, beside a lease from after the bond was timed
//! out, reads as a healthy channel and is not one.
//!
//! A channel being *set up* is those four and one more: whether the
//! coins the two retained Opens spend are still there. That question
//! belongs to the same read for a sharper version of the same reason.
//! `SetupState::decide` locks a provider's stake only if the client's
//! payment funding is live, and a coin read at a later state than the
//! edges is a premise about a state the decision is not being made at.
//! Which coins those are is not derivable here, so the query carries
//! them.
//!
//! So [`WorkChannelSnapshot`] is one answer at one finalized block, read
//! under one database snapshot, and it carries the block it was read at
//! so a caller can say which state it acted on. The existing point
//! queries cannot be composed into this: `LightClient::get_edge` treats
//! its payload argument as a finalized *floor* and reads the
//! then-current database root, which is a different question.
//!
//! Local readers hold one database snapshot. Remote readers verify a complete
//! retained operation witness against the certified state root before deriving
//! current values or absence. A block certificate alone cannot authenticate
//! arbitrary object fields returned beside it.
//!
//! # What it does not decide
//!
//! Whether the channel is usable. This module reports what is there;
//! `hellas_channel::model::setup` decides what that means. The shape
//! of the two registry answers is not decided here either: the kernel's
//! own [`parse_bond_lease`] and [`parse_pending_close`] are called, so
//! an endpoint and a close cannot disagree about what a slot holds.

use std::collections::BTreeSet;

use crate::light_client::{LatestBlock, QueryError};
use hellas_kernel::{
    BOND_LEASE_CHUNKS, CoinId, Edge, EdgeId, LeaseSlots, PendingSlot, RegistryChunk,
    parse_bond_lease, parse_pending_close,
};

/// Which channel a snapshot answers for, and which coins it must answer
/// for at the same block.
///
/// Both edges, because neither alone identifies the channel: the payment
/// terms name the bond, but the lease is keyed by the bond and the
/// pending record by the payment edge, so a reader that knew only one of
/// them could not derive both slots.
///
/// And the coins, because a setup decision is made from the two edges
/// *and* the liveness of the coins the two retained Opens spend. Those
/// coins are named by the caller rather than derived here — only the
/// retained transactions say which they are — and they are asked for in
/// this query rather than in a second call, because a coin read at some
/// other state is a preflight that answers about a state it is not
/// protecting. A caller with no such question passes an empty set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkChannelQuery {
    /// The tag-4 work-stake bond insuring the channel.
    pub bond_edge: EdgeId,
    /// The tag-2 payment edge work is paid from.
    pub payment_edge: Option<EdgeId>,
    /// Coins whose liveness is to be read at the same block as the
    /// objects above.
    pub funding: BTreeSet<CoinId>,
}

impl WorkChannelQuery {
    #[cfg(feature = "client-core")]
    pub(crate) fn object_keys(
        &self,
        network: hellas_kernel::NetworkId,
    ) -> Vec<crate::domain::ObjectId> {
        use crate::domain::{coin_object_id, edge_object_id, registry_chunk_object_id};
        use hellas_kernel::{bond_lease_slots, pending_payment_close_slot};
        let mut keys = vec![edge_object_id(self.bond_edge)];
        keys.extend(bond_lease_slots(network, self.bond_edge).map(registry_chunk_object_id));
        if let Some(payment) = self.payment_edge {
            keys.push(edge_object_id(payment));
            keys.push(registry_chunk_object_id(pending_payment_close_slot(
                network, payment,
            )));
        }
        keys.extend(self.funding.iter().copied().map(coin_object_id));
        keys
    }
}

/// Everything one paid work channel is decided from, at one finalized
/// block.
///
/// The query travels with the answer, and the two registry answers are
/// only reachable through [`Self::lease`] and [`Self::pending`], which
/// parse against the edges in that query. A caller therefore cannot ask
/// what one channel's slots mean while holding another channel's
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkChannelSnapshot {
    query: WorkChannelQuery,
    block: LatestBlock,
    bond: Option<Edge>,
    payment: Option<Edge>,
    lease_slots: [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize],
    pending_slot: Option<RegistryChunk>,
    live_funding: BTreeSet<CoinId>,
}

impl WorkChannelSnapshot {
    #[cfg(feature = "client-core")]
    pub(crate) fn from_objects(
        network: hellas_kernel::NetworkId,
        query: WorkChannelQuery,
        snapshot: crate::light_client::ObjectSnapshot,
    ) -> Result<Self, QueryError> {
        if snapshot.network != network {
            return Err(QueryError::Remote("object witness network differs".into()));
        }
        use crate::domain::{
            Object, ObjectKind, coin_object_id, edge_object_id, registry_chunk_object_id,
        };
        use hellas_kernel::{bond_lease_slots, pending_payment_close_slot};
        let edge = |id| match snapshot.objects.get(&edge_object_id(id)).copied() {
            Some(Object::Edge(edge)) => Ok(Some(edge)),
            None => Ok(None),
            Some(object) => Err(QueryError::WrongObjectKind {
                expected: ObjectKind::Edge,
                actual: object.kind(),
            }),
        };
        let bond = edge(query.bond_edge)?;
        let payment = query.payment_edge.map(edge).transpose()?.flatten();
        let [first, second] = bond_lease_slots(network, query.bond_edge);
        let registry = |id| match snapshot.objects.get(&registry_chunk_object_id(id)).copied() {
            Some(Object::RegistryChunk(chunk)) => Ok(Some(chunk)),
            None => Ok(None),
            Some(object) => Err(QueryError::WrongObjectKind {
                expected: ObjectKind::RegistryChunk,
                actual: object.kind(),
            }),
        };
        let leases = [registry(first)?, registry(second)?];
        let pending = query
            .payment_edge
            .map(|id| registry(pending_payment_close_slot(network, id)))
            .transpose()?
            .flatten();
        let mut live = BTreeSet::new();
        for id in &query.funding {
            match snapshot.objects.get(&coin_object_id(*id)) {
                Some(Object::Coin(_)) => {
                    live.insert(*id);
                }
                None => {}
                Some(object) => {
                    return Err(QueryError::WrongObjectKind {
                        expected: ObjectKind::Coin,
                        actual: object.kind(),
                    });
                }
            }
        }
        Ok(Self::new(
            query,
            snapshot.block,
            bond,
            payment,
            leases,
            pending,
            live,
        ))
    }

    /// Assembles one snapshot from objects a caller has already read at
    /// one block.
    ///
    /// The caller owes the coherence: every object must come from the
    /// same database snapshot, and that snapshot's root must be
    /// `block.state_root`. Nothing in these arguments can establish
    /// that, and this constructor does not pretend to check it — the two
    /// implementations that call it are the ones that hold the reader.
    #[must_use]
    pub const fn new(
        query: WorkChannelQuery,
        block: LatestBlock,
        bond: Option<Edge>,
        payment: Option<Edge>,
        lease_slots: [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize],
        pending_slot: Option<RegistryChunk>,
        live_funding: BTreeSet<CoinId>,
    ) -> Self {
        Self {
            query,
            block,
            bond,
            payment,
            lease_slots,
            pending_slot,
            live_funding,
        }
    }

    /// Returns the channel this snapshot answers for.
    #[must_use]
    pub const fn query(&self) -> &WorkChannelQuery {
        &self.query
    }

    /// Returns the finalized block every object here was read at.
    #[must_use]
    pub const fn block(&self) -> &LatestBlock {
        &self.block
    }

    /// Returns the bond edge, or its absence.
    #[must_use]
    pub const fn bond(&self) -> Option<&Edge> {
        self.bond.as_ref()
    }

    /// Returns the payment edge, or its absence.
    #[must_use]
    pub const fn payment(&self) -> Option<&Edge> {
        self.payment.as_ref()
    }

    /// Returns the raw contents of the bond's lease slots, in slot
    /// order.
    ///
    /// Present for the wire, which has to carry them, and for tests that
    /// mutate one slot. Decisions take [`Self::lease`].
    #[must_use]
    pub const fn lease_slots(&self) -> &[Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize] {
        &self.lease_slots
    }

    /// Returns the raw contents of the payment edge's pending-close
    /// slot.
    #[must_use]
    pub const fn pending_slot(&self) -> Option<RegistryChunk> {
        self.pending_slot
    }

    /// Returns whether this bond is leased, unleased, or holding
    /// something that is neither.
    #[must_use]
    pub fn lease(&self) -> LeaseSlots {
        parse_bond_lease(self.lease_slots, self.query.bond_edge)
    }

    /// Returns whether this payment edge has a live contest, no
    /// contest, or something that is neither.
    #[must_use]
    pub fn pending(&self) -> PendingSlot {
        self.query.payment_edge.map_or(PendingSlot::Absent, |edge| {
            parse_pending_close(self.pending_slot, edge)
        })
    }

    /// Returns which of the coins the query named are still live at this
    /// block.
    ///
    /// A subset of [`WorkChannelQuery::funding`], never anything else: a
    /// coin absent from it is a coin that was asked about and is gone,
    /// and a coin that was never asked about is absent from both. That
    /// is why the two sets are read together through
    /// [`Self::live_funding_of`] rather than this being trusted on its
    /// own — an empty answer means "all spent" and "nothing asked" alike.
    #[must_use]
    pub const fn live_funding(&self) -> &BTreeSet<CoinId> {
        &self.live_funding
    }

    /// Returns which of `funding` are live, or `None` if this snapshot
    /// did not ask about exactly those coins.
    ///
    /// The one way a decision should read the coin answer. `live_funding`
    /// is a set of survivors, and survivors of *what* is the query's to
    /// say: a snapshot taken for a different transaction, or for no
    /// coins at all, would report an empty set that a caller could read
    /// as "every coin is spent" and abort a healthy setup on. Asking for
    /// the coins the caller actually cares about turns that into a
    /// refusal it cannot miss.
    #[must_use]
    pub fn live_funding_of(&self, funding: &BTreeSet<CoinId>) -> Option<&BTreeSet<CoinId>> {
        (&self.query.funding == funding).then_some(&self.live_funding)
    }
}

/// The two decisions this snapshot can be handed to.
///
/// Both are `hellas_rpc`'s, and both take a struct of `Option<&Edge>`s
/// whose coherence their own docs say is the caller's to owe. This is
/// where that debt is paid: every field of both comes out of one
/// snapshot, which came out of one database reader at one finalized
/// block. A caller that filled either struct in by hand would satisfy
/// the type and not the requirement, so these two functions exist to
/// make the coherent way the short way.
#[cfg(feature = "work-watcher")]
impl WorkChannelSnapshot {
    /// Returns this read as a readiness decision's input.
    ///
    /// The height carried is the block the objects were read at, which
    /// is the height `check_ready` measures the admission horizon
    /// against. It is not the height an endpoint has *processed* — that
    /// is the cursor, and `ReadyChannel::check_caught_up` is where the
    /// two are compared.
    #[must_use]
    pub fn observed_channel(&self) -> hellas_channel::model::setup::ObservedChannel<'_> {
        hellas_channel::model::setup::ObservedChannel {
            height: self.block.height,
            bond: self.bond(),
            payment: self.payment(),
            lease: self.lease(),
            pending: self.pending(),
        }
    }

    /// Returns this read as a setup decision's input, or `None` if this
    /// snapshot did not ask about exactly `funding`.
    ///
    /// The coin set is passed in rather than taken from the query so
    /// that the caller's own answer — the coins its retained
    /// transactions name — is what the snapshot is checked against.
    /// A snapshot read for another transaction's coins reports survivors
    /// of a question this decision is not asking, and an empty set of
    /// those reads as "every coin is spent".
    #[must_use]
    pub fn finalized_setup(
        &self,
        funding: &BTreeSet<CoinId>,
    ) -> Option<hellas_channel::work_open::FinalizedSetup> {
        Some(hellas_channel::work_open::FinalizedSetup {
            height: self.block.height,
            bond: self.bond,
            payment: self.payment,
            lease: self.lease(),
            live_funding: self.live_funding_of(funding)?.clone(),
        })
    }
}

/// A narrow finalized read of one work channel.
///
/// Separate from [`crate::LightClient`] on purpose. This is the whole of
/// what a paid endpoint needs from a chain, and a client that does paid
/// work should not have to be handed coin queries, an activity stream,
/// and a mempool to get it. It is also what lets an endpoint be tested
/// against a state it constructs rather than a validator it runs.
pub trait FinalizedWorkView: Clone + Send + Sync + 'static {
    /// Returns every object of one channel at one finalized block.
    ///
    /// `Ok(None)` means the node has no finalized state to answer from
    /// yet — not that the channel is absent. An existing channel whose
    /// objects are all missing at a real finalized block is
    /// `Ok(Some(..))` with absent objects, and those are different
    /// facts: the first says "ask again", the second says "this is not
    /// a channel".
    fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> impl Future<Output = Result<Option<WorkChannelSnapshot>, QueryError>> + Send;
}

#[cfg(feature = "client-core")]
impl FinalizedWorkView for crate::client::RemoteLightClient {
    async fn work_channel_snapshot(
        &self,
        query: WorkChannelQuery,
    ) -> Result<Option<WorkChannelSnapshot>, QueryError> {
        use crate::LightClient as _;
        let network = self.pinned_network()?;
        self.get_objects(query.object_keys(network))
            .await?
            .map(|snapshot| WorkChannelSnapshot::from_objects(network, query, snapshot))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Digest;
    use hellas_kernel::{
        BondLease, NetworkId, RegistryNamespace, RegistryRecordTag, bond_lease_slots,
        pending_payment_close_slot,
    };

    fn bond() -> EdgeId {
        EdgeId::from_bytes([0x11; EdgeId::LENGTH])
    }

    fn payment() -> EdgeId {
        EdgeId::from_bytes([0x22; EdgeId::LENGTH])
    }

    fn query() -> WorkChannelQuery {
        WorkChannelQuery {
            bond_edge: bond(),
            payment_edge: Some(payment()),
            funding: BTreeSet::new(),
        }
    }

    fn block() -> LatestBlock {
        LatestBlock {
            height: 42,
            payload: Digest::from([0x01; 32]),
            state_root: Digest::from([0x02; 32]),
            finalization: vec![0x03],
        }
    }

    fn empty(query: WorkChannelQuery) -> WorkChannelSnapshot {
        WorkChannelSnapshot::new(
            query,
            block(),
            None,
            None,
            [None, None],
            None,
            BTreeSet::new(),
        )
    }

    /// The canonical bytes of one bond lease, spelled out here rather
    /// than produced by the encoder this test is checking a reader of.
    ///
    /// An endpoint reads these bytes off a wire, not out of a kernel
    /// transition, so its side of the agreement is a byte layout and
    /// not a round trip. A round trip against `BondLease::encode` would
    /// pass with any two fields transposed; this does not.
    fn lease_value() -> Vec<u8> {
        let mut value = Vec::new();
        // envelope: canonical format version 1, type tag 31.
        value.extend_from_slice(&[1, 31]);
        // body version.
        value.push(2);
        value.extend_from_slice(&[0x11; 32]); // bond_edge
        value.extend_from_slice(&[0x22; 32]); // payment_edge
        value.extend_from_slice(&[0x33; 32]); // payment_terms_hash
        value.extend_from_slice(&[0x44; 32]); // private_policy_commitment
        value.extend_from_slice(&9_000_u64.to_be_bytes()); // admission_horizon
        assert_eq!(value.len(), BondLease::ENCODED_SIZE);
        value
    }

    fn lease_slots(value: &[u8]) -> [Option<RegistryChunk>; BOND_LEASE_CHUNKS as usize] {
        let slots = [0, 1].map(|index| {
            RegistryChunk::split(
                RegistryNamespace::BondLease,
                RegistryRecordTag::BondLease,
                value,
                index,
            )
        });
        assert!(slots.iter().all(Option::is_some), "the lease splits");
        slots
    }

    /// The two registry answers are taken against the snapshot's own
    /// query, so a snapshot of one channel cannot report another
    /// channel's lease as present.
    #[test]
    fn registry_answers_are_parsed_against_this_snapshots_own_edges() {
        let value = lease_value();
        let slots = lease_slots(&value);

        let held =
            WorkChannelSnapshot::new(query(), block(), None, None, slots, None, BTreeSet::new());
        let LeaseSlots::Present(lease) = held.lease() else {
            panic!(
                "the canonical bytes are a readable lease, got {:?}",
                held.lease()
            );
        };
        assert_eq!(lease.bond_edge(), bond());
        assert_eq!(lease.payment_edge(), payment());
        assert_eq!(lease.admission_horizon(), 9_000);
        assert_eq!(lease.private_policy_commitment(), [0x44; 32]);
        assert_eq!(held.pending(), PendingSlot::Absent);

        // The same slot contents, under a snapshot that answers for a
        // different bond. Only the query moves.
        let other = WorkChannelQuery {
            bond_edge: EdgeId::from_bytes([0x99; EdgeId::LENGTH]),
            payment_edge: Some(payment()),
            funding: BTreeSet::new(),
        };
        let elsewhere =
            WorkChannelSnapshot::new(other, block(), None, None, slots, None, BTreeSet::new());
        assert!(matches!(elsewhere.lease(), LeaseSlots::Faulty(_)));

        assert_eq!(empty(query()).lease(), LeaseSlots::Absent);
    }

    /// The slots a snapshot reports are the slots the kernel's own
    /// transitions read, keyed by the same two edges.
    #[test]
    fn the_derived_slots_are_the_kernels_own() {
        let Some(network) = NetworkId::new("hellas-test") else {
            panic!("a short ascii id is a legal network id");
        };
        let derived = bond_lease_slots(network, bond());
        assert_ne!(derived[0], derived[1]);
        assert_ne!(
            derived[0].to_bytes(),
            pending_payment_close_slot(network, payment()).to_bytes(),
        );
    }
}
