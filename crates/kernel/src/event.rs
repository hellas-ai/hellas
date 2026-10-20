//! Public events, private store effects, and the outcome one apply returns.
//!
//! Abstract counterpart: `models/types.qnt::Event` (the public events
//! `EdgeOpenedEvent` / `EdgeClosedEvent`) and the `lastEvent` recording
//! var in `models/l1.qnt`. ITF replay (`tests/itf.rs`) drives the kernel
//! and asserts each emitted [`EventKind`] against the abstract event the
//! producing action recorded. The registry half of an [`ApplyOutcome`]
//! has no abstract counterpart yet; `models/registry.md` records exactly
//! what that leaves unmodelled.

use crate::{
    consts::{MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS},
    error::{ApplyError, KernelResult},
    list::List,
    object::{Coin, Edge},
    primitive::{CoinId, EdgeId},
    registry::RegistryDiff,
    store::Batch,
};

type OpenCoins = List<(CoinId, Coin), MAX_EDGE_INPUTS>;
type CloseCoins = List<(CoinId, Coin), MAX_EDGE_OUTPUTS>;

/// Everything one applied operation produced.
///
/// Two halves, because the kernel commits more state than it announces.
/// `public_event` is the announcement, and it is optional: an operation
/// that moves only registry state has nothing public to say. `registry`
/// is the bounded set of registry slots the operation wrote, which a
/// host must persist in the same atomic batch as the coin and edge
/// effect — replaying the event alone would silently drop them.
///
/// Registry bodies deliberately never enter the public event payload.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ApplyOutcome {
    public_event: Option<Event>,
    registry: RegistryDiff,
}

impl ApplyOutcome {
    /// Returns the public event, if this operation has one.
    #[must_use]
    pub const fn public_event(&self) -> Option<&Event> {
        self.public_event.as_ref()
    }

    /// Returns the registry slots this operation wrote.
    #[must_use]
    pub const fn registry(&self) -> &RegistryDiff {
        &self.registry
    }
}

/// Deterministic diff produced by an ordered operation batch.
///
/// One [`ApplyOutcome`] per applied operation, in application order, so
/// an operation that emits no public event still occupies its index.
/// Collapsing the eventless ones would renumber every later operation.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Diff<const N: usize> {
    outcomes: [Option<ApplyOutcome>; N],
    len: usize,
}

impl<const N: usize> core::fmt::Debug for Diff<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<const N: usize> Diff<N> {
    pub(crate) const fn empty() -> Self {
        Self {
            outcomes: [const { None }; N],
            len: 0,
        }
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "one push per applied operation; the operation list is bounded by the same N"
    )]
    pub(crate) fn push(&mut self, outcome: &ApplyOutcome) {
        debug_assert!(self.len < N);
        self.outcomes[self.len] = Some(outcome.clone());
        self.len += 1;
    }

    /// Returns the number of applied operations in the diff.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the diff covers no operation.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the outcome of the operation at `index`, if any.
    #[must_use]
    pub fn outcome(&self, index: usize) -> Option<&ApplyOutcome> {
        if index >= self.len {
            return None;
        }

        self.outcomes.get(index)?.as_ref()
    }

    /// Returns the public event of the operation at `index`, if that
    /// operation emitted one.
    #[must_use]
    pub fn event(&self, index: usize) -> Option<&Event> {
        self.outcome(index)?.public_event()
    }

    /// Returns the registry writes of the operation at `index`, if any.
    #[must_use]
    pub fn registry(&self, index: usize) -> Option<&RegistryDiff> {
        Some(self.outcome(index)?.registry())
    }

    /// Iterates over the applied operations' outcomes, in order.
    pub fn iter(&self) -> impl Iterator<Item = &ApplyOutcome> + '_ {
        self.outcomes.iter().take(self.len).flatten()
    }

    /// Iterates over the public events, skipping operations that emitted
    /// none.
    pub fn events(&self) -> impl Iterator<Item = &Event> + '_ {
        self.iter().filter_map(ApplyOutcome::public_event)
    }
}

/// An externally visible kernel mutation.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Event {
    kind: EventKind,
}

impl Event {
    /// Returns the public event payload.
    #[must_use]
    pub const fn kind(&self) -> &EventKind {
        &self.kind
    }
}

/// Public event payload.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum EventKind {
    /// Bounded funding was locked into one shared edge.
    EdgeOpened {
        /// Coins consumed by the open.
        inputs: List<CoinId, MAX_EDGE_INPUTS>,
        /// Edge produced by the open.
        output: EdgeId,
    },

    /// One edge was closed into bounded coin payouts.
    EdgeClosed {
        /// Edge consumed by the close.
        input: EdgeId,
        /// Coins produced by the close.
        outputs: List<CoinId, MAX_EDGE_OUTPUTS>,
    },

    /// An owner consumed coins it owned and issued new ones.
    CoinsReshaped {
        /// Coins consumed by the reshape.
        inputs: List<CoinId, MAX_EDGE_INPUTS>,
        /// Coins issued by the reshape.
        outputs: List<CoinId, MAX_EDGE_OUTPUTS>,
    },
}

/// Internal reducer output: what one validated operation will commit.
///
/// The two arms encode the public/private split structurally rather
/// than by convention. An operation that moves a coin or an edge is
/// publicly visible and always carries the event that announces it; an
/// operation that moves only registry state carries none. There is no
/// third shape, so no transition can quietly consume an edge without
/// announcing it, and none can announce an event it did not earn.
#[allow(clippy::large_enum_variant, clippy::redundant_pub_crate)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) enum Change {
    /// A coin/edge mutation, its announcement, and any registry writes
    /// the same operation makes.
    Public {
        event: Event,
        effect: Effect,
        registry: RegistryDiff,
    },

    /// Registry-only: consensus state moves, nothing public is emitted.
    Private { registry: RegistryDiff },
}

impl Change {
    pub(super) fn open(inputs: &OpenCoins, output: &(EdgeId, Edge)) -> Self {
        let event = Event {
            kind: EventKind::EdgeOpened {
                inputs: Self::ids(inputs),
                output: output.0,
            },
        };

        Self::Public {
            event,
            effect: Effect::open(inputs.clone(), *output),
            registry: RegistryDiff::empty(),
        }
    }

    pub(super) fn close(input: &(EdgeId, Edge), outputs: &CloseCoins) -> Self {
        let event = Event {
            kind: EventKind::EdgeClosed {
                input: input.0,
                outputs: Self::ids(outputs),
            },
        };

        Self::Public {
            event,
            effect: Effect::close(*input, outputs.clone()),
            registry: RegistryDiff::empty(),
        }
    }

    pub(super) fn reshape(inputs: &OpenCoins, outputs: &CloseCoins) -> Self {
        let event = Event {
            kind: EventKind::CoinsReshaped {
                inputs: Self::ids(inputs),
                outputs: Self::ids(outputs),
            },
        };

        Self::Public {
            event,
            effect: Effect::Reshape {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
            },
            registry: RegistryDiff::empty(),
        }
    }

    /// A registry-only change: consensus state moves and nothing public
    /// is announced.
    ///
    /// The payment-close moves take this shape. They consume no coin and
    /// no edge, so there is nothing for an edge event to describe, and
    /// the amounts they stage are the channel's business until a close
    /// pays them out.
    pub(super) const fn private(registry: &RegistryDiff) -> Self {
        Self::Private {
            registry: *registry,
        }
    }

    /// Attaches `registry` to a change that carries none yet.
    ///
    /// Separate from the constructors because the registry writes of a
    /// v2 transition are decided after its coin/edge effect is: the
    /// record a close stages depends on the edge it just resolved.
    pub(super) const fn with_registry(self, diff: &RegistryDiff) -> Self {
        match self {
            Self::Public { event, effect, .. } => Self::Public {
                event,
                effect,
                registry: *diff,
            },
            Self::Private { .. } => Self::Private { registry: *diff },
        }
    }

    /// Returns what an applied change reports to its caller.
    pub(super) fn outcome(&self) -> ApplyOutcome {
        match self {
            Self::Public {
                event, registry, ..
            } => ApplyOutcome {
                public_event: Some(event.clone()),
                registry: *registry,
            },
            Self::Private { registry } => ApplyOutcome {
                public_event: None,
                registry: *registry,
            },
        }
    }

    pub(super) fn fold<B: Batch>(&self, batch: &mut B) -> KernelResult<()> {
        match self {
            Self::Public {
                effect, registry, ..
            } => {
                effect.fold(batch)?;
                registry.fold(batch)
            }
            Self::Private { registry } => registry.fold(batch),
        }
    }

    fn ids<const N: usize>(coins: &List<(CoinId, Coin), N>) -> List<CoinId, N> {
        coins.clone().map(CoinId::ZERO, |(id, _)| id)
    }
}

/// Private store mutation carried by a [`Change`].
#[allow(clippy::large_enum_variant, clippy::redundant_pub_crate)]
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) enum Effect {
    Open {
        coins: OpenCoins,
        edge: (EdgeId, Edge),
    },
    Close {
        edge: (EdgeId, Edge),
        coins: CloseCoins,
    },
    Reshape {
        inputs: OpenCoins,
        outputs: CloseCoins,
    },
}

impl Effect {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the effect owns the edge it stores"
    )]
    const fn open(coins: OpenCoins, edge: (EdgeId, Edge)) -> Self {
        Self::Open { edge, coins }
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the effect owns the edge it stores"
    )]
    const fn close(edge: (EdgeId, Edge), coins: CloseCoins) -> Self {
        Self::Close { edge, coins }
    }

    fn fold<B: Batch>(&self, batch: &mut B) -> KernelResult<()> {
        match self {
            Self::Open { coins, edge } => {
                Self::remove_coins(batch, coins)?;
                Self::insert_edge(batch, edge)
            }
            Self::Close { edge, coins } => {
                Self::remove_edge(batch, edge)?;
                Self::insert_coins(batch, coins)
            }
            Self::Reshape { inputs, outputs } => {
                Self::remove_coins(batch, inputs)?;
                Self::insert_coins(batch, outputs)
            }
        }
    }

    fn insert_coins<B: Batch, const N: usize>(
        batch: &mut B,
        coins: &List<(CoinId, Coin), N>,
    ) -> KernelResult<()> {
        for coin in coins.as_slice() {
            Self::insert_coin(batch, *coin)?;
        }
        Ok(())
    }

    fn remove_coins<B: Batch, const N: usize>(
        batch: &mut B,
        coins: &List<(CoinId, Coin), N>,
    ) -> KernelResult<()> {
        for coin in coins.as_slice() {
            Self::remove_coin(batch, *coin)?;
        }
        Ok(())
    }

    fn insert_coin<B: Batch>(batch: &mut B, coin: (CoinId, Coin)) -> KernelResult<()> {
        batch
            .insert_coin(coin.0, coin.1)
            .map_err(|reason| ApplyError::CoinInsertRejected { id: coin.0, reason })
    }

    fn remove_coin<B: Batch>(batch: &mut B, coin: (CoinId, Coin)) -> KernelResult<()> {
        match batch.remove_coin(coin.0) {
            Some(removed) if removed == coin.1 => Ok(()),
            Some(_) => Err(ApplyError::CoinChanged { id: coin.0 }),
            None => Err(ApplyError::MissingCoin { id: coin.0 }),
        }
    }

    fn insert_edge<B: Batch>(batch: &mut B, edge: &(EdgeId, Edge)) -> KernelResult<()> {
        batch
            .insert_edge(edge.0, edge.1)
            .map_err(|reason| ApplyError::EdgeInsertRejected { id: edge.0, reason })
    }

    fn remove_edge<B: Batch>(batch: &mut B, edge: &(EdgeId, Edge)) -> KernelResult<()> {
        match batch.remove_edge(edge.0) {
            Some(removed) if removed == edge.1 => Ok(()),
            Some(_) => Err(ApplyError::EdgeChanged { id: edge.0 }),
            None => Err(ApplyError::MissingEdge { id: edge.0 }),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "the coherence tests build fixed, statically bounded protocol projections"
)]
mod tests {
    use super::*;
    use crate::{
        BlockHeight, Fees, Key, MAX_REGISTRY_MUTATIONS, Parties, PartyKeys, TermsHash,
        registry::{
            RegistryChunk, RegistryChunkId, RegistryDiffError, RegistryMutation, RegistryNamespace,
            RegistryRecordTag,
        },
    };

    fn assert_coherent(event: &Event, effect: &Effect) {
        match (event.kind(), effect) {
            (EventKind::EdgeOpened { inputs, output }, Effect::Open { coins, edge }) => {
                assert_eq!(inputs, &Change::ids(coins));
                assert_eq!(*output, edge.0);
            }
            (EventKind::EdgeClosed { input, outputs }, Effect::Close { edge, coins }) => {
                assert_eq!(*input, edge.0);
                assert_eq!(outputs, &Change::ids(coins));
            }
            (
                EventKind::CoinsReshaped {
                    inputs: input_ids,
                    outputs: output_ids,
                },
                Effect::Reshape { inputs, outputs },
            ) => {
                assert_eq!(input_ids, &Change::ids(inputs));
                assert_eq!(output_ids, &Change::ids(outputs));
            }
            _ => panic!("event and effect variants diverged"),
        }
    }

    fn open_change() -> Change {
        let maker = Key::from_bytes([0x11; Key::LENGTH]);
        let taker = Key::from_bytes([0x22; Key::LENGTH]);
        let first = CoinId::from_bytes([0x31; CoinId::LENGTH]);
        let second = CoinId::from_bytes([0x32; CoinId::LENGTH]);
        let mut coin_slots = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
        coin_slots[0] = (first, Coin::issue(maker, None, 40));
        coin_slots[1] = (second, Coin::issue(taker, None, 60));
        let coins = List::take(coin_slots, 2);
        let edge = Edge::open(
            100,
            Parties::new(PartyKeys::sole(maker), PartyKeys::sole(taker)),
            TermsHash::from_bytes([0x44; TermsHash::LENGTH]),
            (0, 0, 0, Fees::ZERO),
            BlockHeight::new(10),
            crate::tx::CloseKindSet::BASIC,
        )
        .expect("coherence edge");
        Change::open(&coins, &(EdgeId::from_bytes([0x51; EdgeId::LENGTH]), edge))
    }

    fn effect_of(change: &Change) -> &Effect {
        match change {
            Change::Public { effect, .. } => effect,
            Change::Private { .. } => panic!("expected a public change"),
        }
    }

    fn event_of(change: &Change) -> Event {
        change
            .outcome()
            .public_event()
            .expect("a public change announces itself")
            .clone()
    }

    #[test]
    fn open_event_ids_equal_effect_mutation_slots() {
        let change = open_change();
        assert_coherent(&event_of(&change), effect_of(&change));
    }

    #[test]
    fn close_event_ids_equal_effect_mutation_slots() {
        let opened = open_change();
        let Change::Public {
            effect: Effect::Open { edge, .. },
            ..
        } = opened
        else {
            unreachable!("open helper produces an open effect")
        };
        let maker = Key::from_bytes([0x11; Key::LENGTH]);
        let taker = Key::from_bytes([0x22; Key::LENGTH]);
        let mut coin_slots = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
        coin_slots[0] = (
            CoinId::from_bytes([0x61; CoinId::LENGTH]),
            Coin::issue(maker, None, 40),
        );
        coin_slots[1] = (
            CoinId::from_bytes([0x62; CoinId::LENGTH]),
            Coin::issue(taker, None, 60),
        );
        let change = Change::close(&edge, &List::take(coin_slots, 2));
        assert_coherent(&event_of(&change), effect_of(&change));
    }

    #[test]
    fn reshape_event_ids_equal_effect_mutation_slots() {
        let owner = Key::from_bytes([0x11; Key::LENGTH]);
        let node = Key::from_bytes([0x12; Key::LENGTH]);
        let mut inputs = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_INPUTS];
        inputs[0] = (
            CoinId::from_bytes([0x71; CoinId::LENGTH]),
            Coin::issue(owner, None, 30),
        );
        let mut outputs = [(CoinId::ZERO, Coin::ZERO); MAX_EDGE_OUTPUTS];
        outputs[0] = (
            CoinId::from_bytes([0x72; CoinId::LENGTH]),
            Coin::issue(owner, Some(node), 30),
        );
        let change = Change::reshape(&List::take(inputs, 1), &List::take(outputs, 1));
        assert_coherent(&event_of(&change), effect_of(&change));
    }

    fn chunk(byte: u8) -> RegistryChunk {
        RegistryChunk::split(
            RegistryNamespace::PaymentClose,
            RegistryRecordTag::PaymentPending,
            &[byte; 5],
            0,
        )
        .expect("five bytes split into one chunk")
    }

    fn chunk_id(byte: u8) -> RegistryChunkId {
        RegistryChunkId::derive(
            crate::NetworkId::new("hellas-event-test").expect("legal network id"),
            RegistryNamespace::PaymentClose,
            [byte; 32],
            0,
        )
    }

    /// The outcome has to report every registry slot the fold writes,
    /// or a host replaying the outcome and a node folding the change
    /// end up with different stored state.
    #[test]
    fn outcome_reports_the_registry_slots_the_fold_writes() {
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::write(chunk_id(1), chunk(0xa1)))
            .expect("first slot");
        diff.push(RegistryMutation::delete(chunk_id(2)))
            .expect("second slot");

        let change = open_change().with_registry(&diff);
        let outcome = change.outcome();

        assert!(outcome.public_event().is_some());
        assert_eq!(
            outcome.registry().as_slice(),
            [
                RegistryMutation::write(chunk_id(1), chunk(0xa1)),
                RegistryMutation::delete(chunk_id(2)),
            ],
            "order and contents, not just the count",
        );

        // The private arm is the same diff without an announcement.
        let private = Change::Private { registry: diff }.outcome();
        assert_eq!(private.public_event(), None);
        assert_eq!(private.registry(), outcome.registry());
    }

    /// One slot, one write per operation: the host replays the diff in
    /// order, so a second write to the same slot would make the stored
    /// result depend on replay order rather than on the operation.
    #[test]
    fn a_diff_refuses_a_second_write_to_one_slot() {
        let mut diff = RegistryDiff::empty();
        diff.push(RegistryMutation::write(chunk_id(1), chunk(0xa1)))
            .expect("first slot");

        assert_eq!(
            diff.push(RegistryMutation::delete(chunk_id(1))),
            Err(RegistryDiffError::Duplicate { id: chunk_id(1) }),
            "a delete of an already-written slot is still a second write",
        );

        // Fill the rest, then overflow by one.
        for byte in 2..=u8::try_from(MAX_REGISTRY_MUTATIONS).expect("width fits u8") {
            diff.push(RegistryMutation::write(chunk_id(byte), chunk(byte)))
                .expect("a slot inside the bound");
        }
        assert_eq!(diff.len(), MAX_REGISTRY_MUTATIONS);
        assert_eq!(
            diff.push(RegistryMutation::write(chunk_id(0xff), chunk(0xff))),
            Err(RegistryDiffError::Full),
        );
        assert_eq!(diff.len(), MAX_REGISTRY_MUTATIONS);
    }
}
