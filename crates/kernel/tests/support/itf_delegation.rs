#![allow(clippy::redundant_pub_crate)]
#![allow(dead_code)] // The complete ITF schema includes model history variables.
//! Concrete replay of the delegation model. Symbolic ids are bound to the
//! actual ids emitted by each transaction; live objects are compared in full.
use crate::support::witness;
use std::collections::{BTreeMap, BTreeSet};

use crate::support::{
    FAKE_VERIFIER, NETWORK, coin_id, key,
    map_store::{MapStore, map_state},
};
use hellas_kernel::{
    Auth, Authority, BlockHash, BlockHeight, CloseKind, Coin, CoinId, Context, EdgeId, EventKind,
    Funding, Genesis, Key, List, Parties, PartyKeys, Payout, Proof, ProtocolCode, Reshape, Sig,
    State as KernelState, Terms, Tx, WorkStakeBondTerms,
};
use itf::de::{As, Integer};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum KeyTag {
    O,
    N,
    N2,
    T,
    NoKey,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum CoinTag {
    GenO,
    DelN,
    DelN2,
    Swept,
    BasicOut,
    BondOut,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Shape {
    Basic,
    Bond,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum ReshapeTag {
    DelegateToN,
    DelegateToN2,
    SweepN,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum AuthorityTag {
    Owner,
    Signer,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum ProofTag {
    Mutual,
    Timeout,
}
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CoinState {
    owner: KeyTag,
    delegate: KeyTag,
    #[serde(with = "As::<Integer>")]
    value: u64,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdgeState {
    shape: Shape,
    coin: CoinTag,
    payout_delegate: KeyTag,
    maker_auth: AuthorityTag,
    funded_delegate: KeyTag,
    #[serde(with = "As::<Integer>")]
    value: u64,
}
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReshapeInput {
    reshape: ReshapeTag,
    signer: KeyTag,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenInput {
    shape: Shape,
    coin: CoinTag,
    payout_delegate: KeyTag,
    maker_auth: AuthorityTag,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CloseInput {
    proof: ProofTag,
    maker_auth: AuthorityTag,
    pay_owner: KeyTag,
    pay_delegate: KeyTag,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Input {
    NoInput,
    TickInput,
    ReshapeInput(ReshapeInput),
    RejectedReshapeInput(ReshapeInput),
    OpenInput(OpenInput),
    RejectedOpenInput(OpenInput),
    CloseInput(CloseInput),
    RejectedCloseInput(CloseInput),
}
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub(crate) enum Event {
    NoEvent,
    CoinsReshapedEvent(ReshapeTag),
    EdgeOpenedEvent(Shape),
    EdgeClosedEvent(Shape),
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    coins: BTreeMap<CoinTag, CoinState>,
    live_coins: BTreeSet<CoinTag>,
    edge: EdgeState,
    edge_live: bool,
    opened: BTreeSet<Shape>,
    closed_edge: BTreeMap<Shape, EdgeState>,
    closed_owner_signed: BTreeMap<Shape, bool>,
    #[serde(with = "As::<Integer>")]
    height: u64,
    last_input: Input,
    last_event: Event,
}

fn one<T: Copy, const N: usize>(value: T) -> List<T, N> {
    List::take([value; N], 1)
}

fn concrete_key(tag: KeyTag) -> Key {
    key(match tag {
        KeyTag::O => 1,
        KeyTag::N => 2,
        KeyTag::N2 => 3,
        KeyTag::T => 4,
        KeyTag::NoKey => panic!("absent key"),
    })
}
fn delegate(tag: KeyTag) -> Option<Key> {
    (tag != KeyTag::NoKey).then(|| concrete_key(tag))
}
const fn authority(tag: AuthorityTag) -> Authority {
    match tag {
        AuthorityTag::Owner => Authority::Owner,
        AuthorityTag::Signer => Authority::Signer,
    }
}
const fn output(shape: Shape) -> CoinTag {
    match shape {
        Shape::Basic => CoinTag::BasicOut,
        Shape::Bond => CoinTag::BondOut,
    }
}

pub(crate) struct Actual {
    kernel: KernelState<MapStore>,
    ids: BTreeMap<CoinTag, CoinId>,
    edge: Option<(EdgeId, Terms, Shape)>,
}
pub(crate) struct Runner;
impl itf::Runner for Runner {
    type ActualState = Actual;
    type ExpectedState = State;
    type Result = Option<EventKind>;
    type Error = String;
    fn init(&mut self, _: &State) -> Result<Actual, String> {
        Ok(Actual {
            kernel: map_state([Genesis::coin(coin_id(1), concrete_key(KeyTag::O), 10)]),
            ids: BTreeMap::from([(CoinTag::GenO, coin_id(1))]),
            edge: None,
        })
    }
    #[allow(clippy::too_many_lines)] // Mirrors the three transaction variants in one replay step.
    fn step(&mut self, actual: &mut Actual, expected: &State) -> Result<Self::Result, String> {
        let mut issued = None;
        let mut opened = None;
        let mut closed = false;
        let rejected = matches!(
            expected.last_input,
            Input::RejectedReshapeInput(_)
                | Input::RejectedOpenInput(_)
                | Input::RejectedCloseInput(_)
        );
        let tx = match &expected.last_input {
            Input::NoInput | Input::TickInput => return Ok(None),
            Input::ReshapeInput(input) | Input::RejectedReshapeInput(input) => {
                let (from, to, pd) = match input.reshape {
                    ReshapeTag::DelegateToN => (CoinTag::GenO, CoinTag::DelN, KeyTag::N),
                    ReshapeTag::DelegateToN2 => (CoinTag::GenO, CoinTag::DelN2, KeyTag::N2),
                    ReshapeTag::SweepN => (CoinTag::DelN, CoinTag::Swept, KeyTag::NoKey),
                };
                let inputs = one(actual.ids[&from]);
                let outputs = one(Payout::delegated(concrete_key(KeyTag::O), delegate(pd), 10));
                let hash = Reshape::payload_hash(NETWORK, &inputs, &outputs);
                issued = Some((
                    to,
                    Reshape::output_ids(NETWORK, &inputs, &outputs).as_slice()[0],
                ));
                Tx::Owner(Reshape::new(
                    inputs,
                    outputs,
                    Auth::native(Sig::placeholder(concrete_key(input.signer), hash)),
                ))
            }
            Input::OpenInput(input) | Input::RejectedOpenInput(input) => {
                let parties = Parties::new(
                    PartyKeys::new(
                        concrete_key(KeyTag::O),
                        concrete_key(KeyTag::N),
                        delegate(input.payout_delegate),
                    ),
                    PartyKeys::sole(concrete_key(KeyTag::T)),
                );
                let timeout_outputs = one(parties.maker().payout(10, false));
                let terms = match input.shape {
                    Shape::Basic => Terms::basic(
                        ProtocolCode::new(5),
                        parties,
                        BlockHeight::new(2),
                        timeout_outputs,
                    ),
                    Shape::Bond => Terms::work_stake_bond(WorkStakeBondTerms {
                        parties,
                        timeout: BlockHeight::new(2),
                        timeout_outputs,
                        max_job_price: 1,
                    }),
                };
                let funding = Funding::new(one(actual.ids[&input.coin]), List::empty(coin_id(0)));
                let hash = Tx::open_hash(NETWORK, &funding, &terms);
                opened = Some((Tx::edge_id_of(&funding, &terms), terms.clone(), input.shape));
                Tx::open(
                    funding,
                    terms,
                    witness(parties.maker(), authority(input.maker_auth), hash),
                    witness(parties.taker(), Authority::Owner, hash),
                )
            }
            Input::CloseInput(input) | Input::RejectedCloseInput(input) => {
                let (id, terms, shape) = actual.edge.as_ref().ok_or("no edge for close")?;
                let payouts = one(Payout::delegated(
                    concrete_key(input.pay_owner),
                    delegate(input.pay_delegate),
                    10,
                ));
                let proof = match input.proof {
                    ProofTag::Timeout => Proof::Timeout {
                        terms: terms.clone(),
                        owner: if *shape == Shape::Bond && input.maker_auth == AuthorityTag::Owner {
                            let hash = Tx::payload_hash(
                                NETWORK,
                                *id,
                                CloseKind::Timeout,
                                terms.hash(),
                                &payouts,
                            );
                            Some(witness(terms.parties().maker(), Authority::Owner, hash))
                        } else {
                            None
                        },
                    },
                    ProofTag::Mutual => {
                        let hash = Tx::payload_hash(
                            NETWORK,
                            *id,
                            CloseKind::Mutual,
                            terms.hash(),
                            &payouts,
                        );
                        Proof::Mutual {
                            maker: witness(
                                terms.parties().maker(),
                                authority(input.maker_auth),
                                hash,
                            ),
                            taker: witness(terms.parties().taker(), Authority::Owner, hash),
                        }
                    }
                };
                issued = Some((
                    output(*shape),
                    Tx::close_output_ids(*id, &payouts).as_slice()[0],
                ));
                closed = true;
                Tx::close(*id, proof, payouts)
            }
        };
        let context = Context::new(
            NETWORK,
            BlockHeight::new(expected.height),
            BlockHash::from_bytes([0; 32]),
        );
        let result = actual.kernel.apply(context, &FAKE_VERIFIER, &tx);
        if rejected {
            return result.map_or(Ok(None), |outcome| {
                Err(format!("accepted {:?}: {outcome:?}", expected.last_input))
            });
        }
        let outcome = result.map_err(|e| format!("rejected {:?}: {e:?}", expected.last_input))?;
        let event = outcome.public_event().ok_or("missing public event")?.kind();
        let expected_event = match &tx {
            Tx::Owner(reshape) => EventKind::CoinsReshaped {
                inputs: reshape.inputs().clone(),
                outputs: Reshape::output_ids(NETWORK, reshape.inputs(), reshape.outputs()),
            },
            Tx::Open { funding, terms, .. } => EventKind::EdgeOpened {
                inputs: one(funding.maker().as_slice()[0]),
                output: Tx::edge_id_of(funding, terms),
            },
            Tx::Close { input, outputs, .. } => EventKind::EdgeClosed {
                input: *input,
                outputs: Tx::close_output_ids(*input, outputs),
            },
            Tx::Move { .. } => return Err("delegation model has no moves".into()),
        };
        if *event != expected_event {
            return Err(format!("event {event:?} differs from {expected_event:?}"));
        }
        let abstract_event_matches = match &expected.last_event {
            Event::CoinsReshapedEvent(tag) => {
                matches!(&expected.last_input, Input::ReshapeInput(input) if input.reshape == *tag)
            }
            Event::EdgeOpenedEvent(shape) => opened
                .as_ref()
                .is_some_and(|(_, _, actual_shape)| shape == actual_shape),
            Event::EdgeClosedEvent(shape) => {
                closed
                    && actual
                        .edge
                        .as_ref()
                        .is_some_and(|(_, _, actual_shape)| shape == actual_shape)
            }
            Event::NoEvent => false,
        };
        if !abstract_event_matches {
            return Err("abstract event disagrees with its input".into());
        }
        if let Some((tag, id)) = issued {
            actual.ids.insert(tag, id);
        }
        if let Some(edge) = opened {
            actual.edge = Some(edge);
        }
        if closed {
            actual.edge = None;
        }
        Ok(outcome.public_event().map(|event| event.kind().clone()))
    }
    fn result_invariant(&self, result: &Self::Result, expected: &State) -> Result<bool, String> {
        Ok(matches!(
            (result, &expected.last_event),
            (None, Event::NoEvent)
                | (
                    Some(EventKind::CoinsReshaped { .. }),
                    Event::CoinsReshapedEvent(_)
                )
                | (
                    Some(EventKind::EdgeOpened { .. }),
                    Event::EdgeOpenedEvent(_)
                )
                | (
                    Some(EventKind::EdgeClosed { .. }),
                    Event::EdgeClosedEvent(_)
                )
        ))
    }
    fn state_invariant(&self, actual: &Actual, expected: &State) -> Result<bool, String> {
        let want: BTreeMap<_, _> = expected
            .live_coins
            .iter()
            .map(|tag| {
                let coin = &expected.coins[tag];
                (
                    actual.ids[tag],
                    Coin::issue(
                        concrete_key(coin.owner),
                        delegate(coin.delegate),
                        coin.value,
                    ),
                )
            })
            .collect();
        let got: BTreeMap<_, _> = actual.kernel.store().coins().collect();
        if got != want {
            return Err(format!("coins differ: actual {got:?}, expected {want:?}"));
        }
        let edges: Vec<_> = actual.kernel.store().edges().collect();
        if expected.edge_live {
            let (id, terms, shape) = actual.edge.as_ref().ok_or("missing edge")?;
            if edges.len() != 1
                || edges[0].0 != *id
                || edges[0].1.terms() != terms.hash()
                || *shape != expected.edge.shape
                || edges[0].1.value() != expected.edge.value
                || terms.parties().maker().payout_delegate()
                    != delegate(expected.edge.payout_delegate)
            {
                return Err("live edge differs".into());
            }
        } else if !edges.is_empty() {
            return Err("unexpected live edge".into());
        }
        Ok(actual.kernel.store().registry_chunks().next().is_none())
    }
}
